import { validateRecord, projectRecord } from './catalog.mjs';
import { generatedId, producerId } from './calculation-identity.mjs';
import { canonical, fingerprint, decodeDomain, freezeDeep, fail } from './values.mjs';
import { sourceKey } from './keys.mjs';
import { normalizeRange } from './range.mjs';
import { treeAggregate } from './tree.mjs';

const own = (o,k) => Object.hasOwn(o,k);
const bad = message => fail('INVALID_CALCULATION',message);
function detached(value) {
  canonical(value);
  const copy = v => Array.isArray(v) ? v.map(copy) : v && typeof v === 'object'
    ? Object.assign(Object.create(null),Object.fromEntries(Object.entries(v).map(([k,x])=>[k,copy(x)]))) : v;
  return freezeDeep(copy(value));
}
function fields(value,allowed,required=allowed) {
  canonical(value);
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(k=>!allowed.includes(k)) || required.some(k=>!own(value,k))) bad('Invalid calculation object keys');
}
function array(value) { if (!Array.isArray(value)) bad('Expected array'); return value; }
export function validateFieldSelector(catalog,s,record) {
  fields(s,['field','header'],[]);
  if (Object.keys(s).length!==1) bad('Expected one field selector');
  if (own(s,'field')) {
    decodeDomain('id',s.field);
    const models=record?[catalog.models[record.model]]:Object.values(catalog.models);
    if (!models.some(m=>m && own(m.schema.properties,s.field))) bad('Unknown read field');
  } else if (!['id','tenant','model','owner','createdAt'].includes(s.header)) bad('Unknown header');
  return {...s};
}
function direct(record,selector) {
  if (!record) return {exists:false,present:false};
  const object=own(selector,'field')?record.data:record, key=selector.field??selector.header;
  return own(object,key)?{exists:true,present:true,value:object[key]}:{exists:true,present:false};
}
async function readSource(tx,catalog,tenant,id) {
  const stored=await tx.get(sourceKey(tenant,id));
  if (stored===undefined) return undefined;
  const record=validateRecord(catalog,stored);
  if (record.id!==id || record.tenant!==tenant) bad('Stored source identity mismatch');
  return record;
}
async function readShape(tx,catalog,tenant,input) {
  if (input?.kind==='field') {
    fields(input,['slot','kind','sourceId','selector']);
    decodeDomain('id',input.slot); decodeDomain('id',input.sourceId);
    const record=await readSource(tx,catalog,tenant,input.sourceId);
    return {...input,selector:validateFieldSelector(catalog,input.selector,record)};
  }
  fields(input,['slot','kind','view','partition','aggregate','lower','upper'],['slot','kind','view','partition','aggregate']);
  decodeDomain('id',input.slot);
  const view=own(catalog.views,input.view)&&catalog.views[input.view].contract;
  if (input.kind!=='range'||!view||!own(view.aggregates,input.aggregate)) bad('Invalid range read');
  if (array(input.partition).length!==view.partition.length) bad('Wrong partition arity');
  const bounds={}; for (const side of ['lower','upper']) if (own(input,side)) bounds[side]=input[side];
  return {slot:input.slot,kind:'range',view:input.view,partition:input.partition.map((v,i)=>decodeDomain(view.partition[i],v)),aggregate:input.aggregate,...normalizeRange(view.order,bounds)};
}

/** Trusted pure callbacks receive detached data and an authored-only point reader. */
export async function resolveProducer(tx,catalog,tenant,anchor,rule) {
  const record=validateRecord(catalog,anchor);
  if (record.tenant!==tenant || record.id.startsWith('@next/derived/') || catalog.models[record.model].managed) bad('Invalid authored anchor');
  let open=true, firstFailure, failed=false;
  const pending=[], calls=[];
  const readField=(id,s)=>{
    // Throw synchronously after closure: ignored late calls cannot leak a rejected promise.
    if (!open) bad('Resolver read facade closed');
    const index=calls.length; calls.push([]);
    const promise=(async()=>{
      decodeDomain('id',id);
      if (id.startsWith('@next/derived/')) bad('Resolver cannot read managed topology');
      const requested=detached(s);
      const source=await readSource(tx,catalog,tenant,id);
      if (source && catalog.models[source.model]?.managed) bad('Resolver cannot read managed topology');
      const selected=validateFieldSelector(catalog,requested,source);
      calls[index]=[selected,{header:'id'}].map(selector=>({slot:'resolve:'+fingerprint([id,selector]),kind:'field',sourceId:id,selector}));
      return detached(direct(source,selected));
    })();
    // Attach immediately, including fire-and-forget reads; keep the original promise for awaiters.
    pending.push(promise.catch(error=>{if (!failed) {failed=true;firstFailure=error;}}));
    return promise;
  };
  let shape, callbackFailure, callbackFailed=false;
  try { shape=await rule.implementation.resolve(Object.freeze({record:detached(record),readField})); }
  catch (error) { callbackFailed=true;callbackFailure=error; }
  finally { open=false; }
  await Promise.all(pending);
  if (failed) throw firstFailure;
  if (callbackFailed) throw callbackFailure;
  shape=detached(shape); fields(shape,['parameters','reads','outputs']);
  const reads=[]; for (const r of array(shape.reads)) reads.push(await readShape(tx,catalog,tenant,r));
  if (new Set(reads.map(r=>r.slot)).size!==reads.length) bad('Duplicate read slots');
  const roles=new Set(),outputs=[];
  for (const output of array(shape.outputs)) {
    fields(output,['role','model','owner','createdAt','data','computed']);decodeDomain('id',output.role);
    if (roles.has(output.role)) bad('Duplicate output role');roles.add(output.role);
    if (!own(catalog.models,output.model)||!catalog.models[output.model].managed) bad('Output requires managed model');
    const computed=array(output.computed);
    if (new Set(computed).size!==computed.length||computed.some(f=>typeof f!=='string'||!own(catalog.models[output.model].schema.properties,f))) bad('Invalid computed fields');
    const template=validateRecord(catalog,{id:generatedId(tenant,record.id,rule.slot,output.role),tenant,model:output.model,owner:output.owner,createdAt:output.createdAt,data:output.data});
    projectRecord(catalog,template);
    outputs.push({role:output.role,record:template,computed:[...computed]});
  }
  const resolveReads=new Map(); for (const read of calls.flat()) resolveReads.set(read.slot,read);
  return {id:producerId(tenant,record.id,rule.slot),anchorId:record.id,calculation:rule.slot,parameters:shape.parameters,reads,outputs,resolveReads:[...resolveReads.values()]};
}
export function registrationsFor(producer) {
  return [...producer.resolveReads,...producer.reads.flatMap(read=>[
    {...read,slot:'evaluate:'+read.slot},
    ...(read.kind==='field'&&read.selector.header!=='id'?[{slot:'evaluate-existence:'+read.slot,kind:'field',sourceId:read.sourceId,selector:{header:'id'}}]:[])
  ])];
}
const topology = rows => rows.map(({inputs,contributions,...row})=>row);
export async function evaluateProducer(tx,catalog,tenant,producer,implementation) {
  const values=Object.create(null);
  for (const read of producer.reads) {
    if (read.kind==='field') {
      const record=await readSource(tx,catalog,tenant,read.sourceId);
      validateFieldSelector(catalog,read.selector,record);
      values[read.slot]=direct(record,read.selector);
    } else {
      const bounds={}; for (const side of ['lower','upper']) if (own(read,side)) bounds[side]=read[side];
      values[read.slot]=(await treeAggregate(tx,catalog,{tenant,view:read.view,partition:read.partition},bounds))[read.aggregate];
    }
  }
  const result=implementation.evaluate(detached({parameters:producer.parameters,values}));
  if (result&&typeof result.then==='function') {Promise.resolve(result).catch(()=>{});bad('Evaluation must be synchronous');}
  const evaluated=detached(result);fields(evaluated,['outputs']);fields(evaluated.outputs,producer.outputs.map(o=>o.role));
  const records=[];
  for (const output of producer.outputs) {
    const patch=evaluated.outputs[output.role];if (patch===null) continue;
    fields(patch,output.computed);
    const actual=validateRecord(catalog,{...output.record,data:{...output.record.data,...patch}});
    if (canonical(topology(projectRecord(catalog,actual)))!==canonical(topology(projectRecord(catalog,output.record)))) bad('Computed patch changes topology');
    records.push(actual);
  }
  return records;
}
function point(row,aggregate) {return {view:row.view,partition:row.partition,aggregate,order:row.order,sourceId:row.sourceId,slot:row.slot};}
const equal=(a,b)=>a===undefined||b===undefined?a===b:canonical(a)===canonical(b);
export function signalsForSource(catalog,old,next) {
  const fields=[],points=[],sourceId=(next??old)?.id;
  if (!sourceId) return {fields,points};
  for (const header of ['id','tenant','model','owner','createdAt']) if (!equal(old?.[header],next?.[header])) fields.push({sourceId,selector:{header}});
  const names=new Set([...Object.keys(old?.data??{}),...Object.keys(next?.data??{})]);
  for (const field of names) if (!equal(old && own(old.data,field)?old.data[field]:undefined,next && own(next.data,field)?next.data[field]:undefined)) fields.push({sourceId,selector:{field}});
  const before=new Map((old?projectRecord(catalog,old):[]).map(r=>[canonical([r.view,r.slot]),r]));
  const after=new Map((next?projectRecord(catalog,next):[]).map(r=>[canonical([r.view,r.slot]),r]));
  for (const key of new Set([...before.keys(),...after.keys()])) {
    const a=before.get(key),b=after.get(key);
    const moved=!a||!b||!equal([a.partition,a.order],[b.partition,b.order]);
    for (const aggregate of Object.keys(catalog.views[(a??b).view].contract.aggregates)) if (moved||!equal(a.contributions[aggregate],b.contributions[aggregate])) {
      if (a) points.push(point(a,aggregate));if (b) points.push(point(b,aggregate));
    }
  }
  return {fields,points:[...new Map(points.map(p=>[canonical(p),p])).values()]};
}
export function signalsForOutputs(catalog,outputs) {
  const fields=[],points=[];
  for (const output of outputs) {
    const record=output.record;
    for (const header of ['id','tenant','model','owner','createdAt']) fields.push({sourceId:record.id,selector:{header}});
    for (const field of Object.keys(catalog.models[record.model].schema.properties)) fields.push({sourceId:record.id,selector:{field}});
    for (const row of projectRecord(catalog,record)) for (const aggregate of Object.keys(catalog.views[row.view].contract.aggregates)) points.push(point(row,aggregate));
  }
  return {fields,points};
}
