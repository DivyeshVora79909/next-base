import { createMutation } from './stage.mjs';
import { canonical, decodeDomain, fingerprint, fail } from './values.mjs';
import { projectRecord, validateRecord } from './catalog.mjs';
import { producerId, generatedId } from './calculation-identity.mjs';
import { sourceKey, producerKey, reservationKey, potentialOwnerKey } from './keys.mjs';
import { affectedSubscribers, replaceRoutes, readRoutes } from './routes.mjs';
import { replacePotential, potentialPredecessors } from './potential.mjs';
import { resolveProducer, evaluateProducer, registrationsFor, signalsForSource, signalsForOutputs, validateFieldSelector } from './calculation-runtime.mjs';

const equal=(a,b)=>a===undefined||b===undefined?a===b:canonical(a)===canonical(b);
const check=ok=>{if(!ok)fail('CORRUPT_STATE','Missing or mismatched calculation state');};
const exact=(value,keys)=>value!==null&&typeof value==='object'&&!Array.isArray(value)&&Reflect.ownKeys(value).length===keys.length&&keys.every(k=>Object.hasOwn(value,k));
const merge=signals=>({fields:signals.flatMap(s=>s.fields),points:signals.flatMap(s=>s.points)});

/** Incrementally settle one final authored overlay inside the caller's transaction. */
export async function settle(tx,catalog,tenant,changes,options={}) {
  decodeDomain('id',tenant);
  const limits={};
  for(const name of ['maxProducers','maxEdges','maxRouteVisits','maxPotentialVisits']) {
    const value=options[name]===undefined?Infinity:options[name];
    if(value!==Infinity&&(!Number.isSafeInteger(value)||value<0))fail('CALCULATION_BUDGET','Invalid settlement budget');
    limits[name]=value;
  }
  const metrics={resolved:0,evaluated:0,routeVisits:0,potentialVisits:0,edges:0,pending:0};
  const mutation=await createMutation(tx,catalog,tenant);
  if(!Array.isArray(changes))fail('INVALID_MUTATION','Expected changes array');
  const commands=[],seen=new Set();
  for(const change of changes) {
    const id=change?.type==='put'?change.record?.id:change?.id;
    decodeDomain('id',id);
    if(seen.has(id))fail('DUPLICATE_SOURCE','Duplicate source command');seen.add(id);
    const old=await tx.get(sourceKey(tenant,id));
    if(id.startsWith('@next/derived/')||await tx.get(reservationKey(catalog,tenant,id))!==undefined||catalog.models[old?.model]?.managed||catalog.models[change?.record?.model]?.managed)fail('INVALID_CALCULATION','Client cannot mutate managed identities or models');
    commands.push({id,old});
  }
  await mutation.stage(changes);
  const changed=[];
  for(const command of commands) {
    command.next=await tx.get(sourceKey(tenant,command.id));
    if(!equal(command.old,command.next))changed.push(command);
  }
  const oldStates=new Map(),finalStates=new Map(),pending=new Set(),queue=[],resolve=new Set(),ownAnchors=new Map();
  const add=id=>{
    if(!pending.has(id)) {
      if(pending.size>=limits.maxProducers)fail('CALCULATION_BUDGET','Producer budget exceeded');
      pending.add(id);queue.push(id);
    }
  };
  async function load(id,allowMissing=false) {
    if(oldStates.has(id))return oldStates.get(id);
    const p=await tx.get(producerKey(catalog,tenant,id));
    if(p===undefined) {check(allowMissing);oldStates.set(id,undefined);return undefined;}
    check(exact(p,['id','anchorId','calculation','parameters','reads','outputs','resolveReads']));
    check(p.id===id&&producerId(tenant,p.anchorId,p.calculation)===id&&Array.isArray(p.outputs)&&Array.isArray(p.reads)&&Array.isArray(p.resolveReads));
    check(equal(await readRoutes(tx,catalog,tenant,id),registrationsFor(p)));
    for(const read of p.resolveReads)check(read.kind==='field'&&read.slot==='resolve:'+fingerprint([read.sourceId,read.selector]));
    const roles=new Set();
    for(const output of p.outputs) {
      check(exact(output,['role','record','computed'])&&typeof output.role==='string'&&!roles.has(output.role));roles.add(output.role);
      try {
        decodeDomain('id',output.role);validateRecord(catalog,output.record);
        check(output.record.tenant===tenant&&catalog.models[output.record.model]?.managed===true&&output.record.id===generatedId(tenant,p.anchorId,p.calculation,output.role));
        check(Array.isArray(output.computed)&&new Set(output.computed).size===output.computed.length&&output.computed.every(field=>typeof field==='string'&&Object.hasOwn(catalog.models[output.record.model].schema.properties,field)));
      } catch {fail('CORRUPT_STATE','Invalid stored potential output');}
      const ledger=await tx.get(reservationKey(catalog,tenant,output.record.id));
      check(equal(ledger,{tenant,anchorId:p.anchorId,calculation:p.calculation,role:output.role,outputId:output.record.id,model:output.record.model,createdAt:output.record.createdAt}));
    }
    oldStates.set(id,p);return p;
  }
  async function route(signals) {
    const result=await affectedSubscribers(tx,catalog,tenant,signals,{maxVisits:limits.maxRouteVisits-metrics.routeVisits});
    metrics.routeVisits+=result.metrics.intervalNodes+result.metrics.directEntries;
    return result;
  }
  for(const command of changed) {
    for(const record of [command.old,command.next]) if(record) for(const rule of catalog.models[record.model].calculations) {
      const id=producerId(tenant,record.id,rule.slot);add(id);resolve.add(id);
      ownAnchors.set(id,{anchorId:record.id,calculation:rule.slot,expectedOld:!!command.old});
    }
  }
  const authoredSignals=merge(changed.map(c=>signalsForSource(catalog,c.old,c.next)));
  const initial=await route(authoredSignals);
  for(const match of initial.matches) {add(match.subscriber);if(match.slot.startsWith('resolve:'))resolve.add(match.subscriber);}
  // Resolve every dirty shape before changing any routing or potential inventory.
  for(const id of [...pending].sort()) {
    const own=ownAnchors.get(id),old=await load(id,own&&!own.expectedOld);
    const anchor=await tx.get(sourceKey(tenant,old?.anchorId??own.anchorId));
    const rule=anchor&&catalog.models[anchor.model].calculations.find(r=>r.slot===(old?.calculation??own.calculation));
    if(!rule) {finalStates.set(id,undefined);continue;}
    if(resolve.has(id)) {finalStates.set(id,await resolveProducer(tx,catalog,tenant,anchor,rule));metrics.resolved++;}
    else finalStates.set(id,old);
  }
  const initialIds=[...pending];
  const potentialSignals=id=>signalsForOutputs(catalog,[...(oldStates.get(id)?.outputs??[]),...(finalStates.get(id)?.outputs??[])]);
  // Old descriptors must observe both old and newly declared output positions.
  for(const id of initialIds)for(const subscriber of (await route(potentialSignals(id))).subscribers)add(subscriber);
  for(const id of initialIds) {
    const old=oldStates.get(id),next=finalStates.get(id);
    for(const output of next?.outputs??[]) {
      const key=reservationKey(catalog,tenant,output.record.id),prior=await tx.get(key);
      const reservation={tenant,anchorId:next.anchorId,calculation:next.calculation,role:output.role,outputId:output.record.id,model:output.record.model,createdAt:output.record.createdAt};
      if(prior!==undefined&&!equal(prior,reservation))fail('INVALID_CALCULATION','Reservation metadata changed');
      if(prior===undefined) {
        check(await tx.get(sourceKey(tenant,output.record.id))===undefined);
        await tx.set(key,reservation);
      }
    }
    await replaceRoutes(tx,catalog,tenant,id,next?registrationsFor(next):[]);
    await replacePotential(tx,catalog,tenant,id,old?.outputs??[],next?.outputs??[]);
    if(next)await tx.set(producerKey(catalog,tenant,id),next);else await tx.delete(producerKey(catalog,tenant,id));
  }
  // Close all final causal descendants, including unchanged shapes and zero outputs.
  for(let cursor=0;cursor<queue.length;cursor++) {
    const id=queue[cursor];
    if(!finalStates.has(id)) {
      const old=await load(id);finalStates.set(id,old);
      await replaceRoutes(tx,catalog,tenant,id,registrationsFor(old));
      await replacePotential(tx,catalog,tenant,id,old.outputs,old.outputs);
    }
    for(const subscriber of (await route(potentialSignals(id))).subscribers)add(subscriber);
  }
  const active=[...pending].filter(id=>finalStates.get(id)).sort();
  const deps=new Map(active.map(id=>[id,new Set()])),successors=new Map(active.map(id=>[id,new Set()]));
  for(const id of active) {
    const p=finalStates.get(id);
    for(const read of p.reads)if(read.kind==='field') {
      const owner=await tx.get(potentialOwnerKey(catalog,tenant,read.sourceId));
      if(owner) {
        const producer=finalStates.get(owner.producer)??await tx.get(producerKey(catalog,tenant,owner.producer));check(producer);
        const template=producer.outputs.find(o=>o.record.id===read.sourceId);check(template);
        validateFieldSelector(catalog,read.selector,template.record);
      }
    }
    const predecessors=await potentialPredecessors(tx,catalog,tenant,p.reads,{maxVisits:limits.maxPotentialVisits-metrics.potentialVisits});
    metrics.potentialVisits+=predecessors.visits;
    const unique=new Set(predecessors.bySlot.flatMap(r=>r.producers));
    for(const from of unique) {
      if(metrics.edges>=limits.maxEdges)fail('CALCULATION_BUDGET','Edge budget exceeded');metrics.edges++;
      if(deps.has(from)) {deps.get(id).add(from);successors.get(from).add(id);}
      else check(await tx.get(producerKey(catalog,tenant,from))!==undefined);
    }
  }
  const order=[],ready=active.filter(id=>deps.get(id).size===0);
  for(let cursor=0;cursor<ready.length;cursor++) {
    const id=ready[cursor];order.push(id);
    for(const next of successors.get(id)) {deps.get(next).delete(id);if(!deps.get(next).size)ready.push(next);}
  }
  if(order.length!==active.length)fail('CALCULATION_CYCLE','Potential calculation graph contains a cycle');
  // Withdraw every old actual output first, including outputs moved outside final reads.
  for(const id of [...pending].sort())for(const output of oldStates.get(id)?.outputs??[])await mutation.stage([{type:'delete',id:output.record.id}]);
  const scopes=new Map();
  for(const id of order) {
    const p=finalStates.get(id),anchor=await tx.get(sourceKey(tenant,p.anchorId));check(anchor);
    const rule=catalog.models[anchor.model].calculations.find(r=>r.slot===p.calculation);check(rule);
    const records=await evaluateProducer(tx,catalog,tenant,p,rule.implementation);metrics.evaluated++;
    if(records.length)await mutation.stage(records.map(record=>({type:'put',record})));
    for(const output of p.outputs)for(const row of projectRecord(catalog,output.record)) {
      const scope={tenant,view:row.view,partition:row.partition};scopes.set(canonical(scope),scope);
    }
  }
  metrics.pending=pending.size;
  return {...await mutation.finish({scopes:[...scopes.values()]}),settlement:metrics};
}
