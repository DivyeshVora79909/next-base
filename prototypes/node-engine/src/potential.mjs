import { canonical, fingerprint, decodeDomain, compareDomain, fail } from './values.mjs';
import { projectRecord } from './catalog.mjs';
import { rootKey, nodeKey, occurrenceToken, potentialOwnerKey } from './keys.mjs';
import { treeGet, treePut, treeDelete } from './tree.mjs';
import { normalizeRange, belowRange, aboveRange } from './range.mjs';

const check = (ok) => { if (!ok) fail('CORRUPT_STATE', 'Missing or mismatched potential entry'); };
const equal = (a,b) => a === undefined || b === undefined ? a === b : canonical(a) === canonical(b);
export function potentialCatalog(catalog) {
  return {identity:fingerprint(['internal-potential-avl-v1',catalog.identity]),views:Object.fromEntries(Object.entries(catalog.views).map(([name,v])=>[name,{contract:{partition:v.contract.partition,order:v.contract.order,aggregates:{}}}]))};
}
function owner(value) {
  check(value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 1 && Object.hasOwn(value,'producer') && typeof value.producer === 'string');
  decodeDomain('id',value.producer);
  return value.producer;
}
function inventory(catalog,tenant,outputs) {
  if(!Array.isArray(outputs))fail('INVALID_CALCULATION','Expected potential outputs');
  const roles=new Set(), ids=new Set(), occurrences=new Map();
  for(const output of outputs) {
    decodeDomain('string',output.role);
    if(roles.has(output.role)||ids.has(output.record?.id))fail('INVALID_CALCULATION','Duplicate potential role or output');
    roles.add(output.role);ids.add(output.record.id);
    if(output.record.tenant!==tenant || !catalog.models[output.record.model]?.managed)fail('INVALID_CALCULATION','Potential output must be managed in this tenant');
    for(const projected of projectRecord(catalog,output.record)) {
      const {inputs,contributions,...o}=projected;
      o.contributions={};
      const key=canonical([o.view,o.partition,o.sourceId,o.slot]);
      check(!occurrences.has(key));occurrences.set(key,o);
    }
  }
  return {ids,occurrences};
}
export async function replacePotential(tx,catalog,tenant,producerId,oldOutputs,newOutputs) {
  decodeDomain('id',tenant);decodeDomain('id',producerId);
  const before=inventory(catalog,tenant,oldOutputs), after=inventory(catalog,tenant,newOutputs), internal=potentialCatalog(catalog);
  // All guards precede writes, including no-op guards and orphan node checks.
  for(const id of before.ids)check(owner(await tx.get(potentialOwnerKey(catalog,tenant,id)))===producerId);
  for(const id of after.ids)if(!before.ids.has(id))check(await tx.get(potentialOwnerKey(catalog,tenant,id))===undefined);
  for(const o of before.occurrences.values()) {
    const stored=await tx.get(nodeKey(internal,o,occurrenceToken(o))), reachable=await treeGet(tx,internal,o,o);
    check(stored && reachable && equal(stored.order,o.order) && equal(stored.contributions,{}));
  }
  for(const [key,o] of after.occurrences) {
    const old=before.occurrences.get(key);
    if(old && equal(old.order,o.order))continue;
    const stored=await tx.get(nodeKey(internal,o,occurrenceToken(o)));
    // A move in this very scope has the same physical token; all other rows must be absent.
    check(old ? stored && equal(stored.order,old.order) : stored===undefined);
  }
  for(const [key,o] of before.occurrences)if(!equal(o,after.occurrences.get(key)))check(await treeDelete(tx,internal,o));
  for(const id of before.ids)if(!after.ids.has(id))await tx.delete(potentialOwnerKey(catalog,tenant,id));
  for(const [key,o] of after.occurrences)if(!equal(o,before.occurrences.get(key)))await treePut(tx,internal,o);
  for(const id of after.ids)if(!before.ids.has(id))await tx.set(potentialOwnerKey(catalog,tenant,id),{producer:producerId});
}
export async function potentialPredecessors(tx,catalog,tenant,reads,{maxVisits=Infinity}={}) {
  decodeDomain('id',tenant);
  if(!Array.isArray(reads))fail('INVALID_CALCULATION','Expected reads');
  if(maxVisits!==Infinity&&(!Number.isSafeInteger(maxVisits)||maxVisits<0))fail('INVALID_CALCULATION','Invalid potential visit budget');
  let visits=0;
  const visit=()=>{if(visits>=maxVisits)fail('POTENTIAL_BUDGET','Potential visit budget exhausted');visits++;};
  const lookup=async id=>{visit();const value=await tx.get(potentialOwnerKey(catalog,tenant,id));return value===undefined?undefined:owner(value);};
  const internal=potentialCatalog(catalog), bySlot=[];
  for(const read of reads) {
    decodeDomain('string',read.slot);const producers=new Set();
    if(read.kind==='field') {
      const p=await lookup(decodeDomain('id',read.sourceId));if(p!==undefined)producers.add(p);
    } else {
      if(read.kind!=='range')fail('INVALID_CALCULATION','Invalid potential read');
      const view=Object.hasOwn(catalog.views,read.view)&&catalog.views[read.view];
      if(!view||!Object.hasOwn(view.contract.aggregates,read.aggregate))fail('INVALID_CALCULATION','Unknown view or aggregate');
      const scope={tenant,view:read.view,partition:read.partition};
      // rootKey validates and decodes partition arity/domains even for empty trees.
      const key=rootKey(internal,scope), options={};
      for(const side of ['lower','upper'])if(Object.hasOwn(read,side))options[side]=read[side];
      const range=normalizeRange(view.contract.order,options), header=await tx.get(key);
      check(header===undefined || header && typeof header.head==='string');
      const stack=header?[header.head]:[],seen=new Set();
      while(stack.length) {
        const token=stack.pop();check(typeof token==='string'&&!seen.has(token));seen.add(token);visit();
        const n=await tx.get(nodeKey(internal,scope,token));
        check(n&&occurrenceToken(n)===token&&Number.isSafeInteger(n.height)&&n.height>0&&Number.isSafeInteger(n.size)&&n.size>0&&[n.left,n.right].every(x=>x===null||typeof x==='string')&&equal(n.contributions,{})&&equal(n.aggregates,{}));
        decodeDomain(view.contract.order,n.order);decodeDomain('id',n.sourceId);decodeDomain('string',n.slot);
        const below=belowRange(view.contract.order,n,range),above=aboveRange(view.contract.order,n,range);
        if(!below&&!above){const p=await lookup(n.sourceId);check(p!==undefined);producers.add(p);}
        if(!below&&n.left!==null)stack.push(n.left);
        if(!above&&n.right!==null)stack.push(n.right);
      }
    }
    bySlot.push({slot:read.slot,producers:[...producers].sort((a,b)=>compareDomain('id',a,b))});
  }
  return {bySlot,visits};
}
