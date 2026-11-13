import { canonical, fingerprint, decodeDomain, compareDomain, fail } from './values.mjs';
import { normalizeRange, containsRange } from './range.mjs';
import { nodeKey, occurrenceToken } from './keys.mjs';
import { treePut, treeDelete, treeGet, readRoot } from './tree.mjs';

const own = (o,k) => Object.hasOwn(o,k);
function fields(o, allowed) {
  canonical(o);
  if (!o || typeof o !== 'object' || Array.isArray(o) || Reflect.ownKeys(o).some(k=>!allowed.includes(k))) fail('INVALID_ROUTE','Invalid route fields');
}
function selector(catalog,s) {
  fields(s,['field','header']);
  if(Object.keys(s).length!==1) fail('INVALID_ROUTE','Expected one selector');
  if(own(s,'field')) {
    decodeDomain('id',s.field);
    if(!Object.values(catalog.models).some(m=>own(m.schema.properties,s.field))) fail('INVALID_ROUTE','Unknown field');
  } else if(!['owner','id','tenant','model','createdAt'].includes(s.header)) fail('INVALID_ROUTE','Unknown header');
  return {...s};
}
function scope(catalog,r) {
  const v=own(catalog.views,r.view)&&catalog.views[r.view];
  if(!v || !own(v.contract.aggregates,r.aggregate)) fail('INVALID_ROUTE','Unknown view or aggregate');
  if(!Array.isArray(r.partition)||r.partition.length!==v.contract.partition.length) fail('INVALID_ROUTE','Wrong partition');
  return {view:r.view,partition:r.partition.map((x,i)=>decodeDomain(v.contract.partition[i],x)),aggregate:r.aggregate};
}
function registration(catalog,r) {
  fields(r,r?.kind==='field'?['slot','kind','sourceId','selector']:['slot','kind','view','partition','aggregate','lower','upper']);
  const slot=decodeDomain('string',r.slot);
  if(r.kind==='field') return {slot,kind:r.kind,sourceId:decodeDomain('id',r.sourceId),selector:selector(catalog,r.selector)};
  if(r.kind!=='range') fail('INVALID_ROUTE','Unknown route kind');
  const s=scope(catalog,r), range={};
  for(const k of ['lower','upper']) if(own(r,k))range[k]=r[k];
  return {slot,kind:r.kind,...s,...normalizeRange(catalog.views[s.view].contract.order,range)};
}
const base=(c,t)=>`routes/v1/${canonical(t)}/${c.identity}/`;
const listKey=(c,t,s)=>`${base(c,t)}list/${canonical(s)}`;
const rowKey=(c,t,s,slot)=>`${base(c,t)}row/${canonical([s,slot])}`;
const directPrefix=(c,t,r)=>`${base(c,t)}direct/${canonical([r.sourceId,r.selector])}/`;
const directKey=(c,t,s,r)=>`${directPrefix(c,t,r)}${canonical([s,r.slot])}`;
const equal=(a,b)=>a===undefined||b===undefined?a===b:canonical(a)===canonical(b);
function check(ok) { if(!ok)fail('CORRUPT_STATE','Missing or mismatched route entry'); }
function forest(catalog) {
  const views=Object.create(null);
  for(const [name,v] of Object.entries(catalog.views)) for(const bounded of [false,true]) {
    const domain=v.contract.order;
    const combine=(a,b)=>a===null?b:b===null?a:a.unbounded?a:b.unbounded?b:compareDomain(domain,a.order,b.order)>=0?a:b;
    views[canonical([name,bounded])]={contract:{order:domain,partition:[...v.contract.partition,'string'],aggregates:{upper:{implementation:{identity:()=>null,combine}}}}};
  }
  return {identity:fingerprint(['internal-route-interval-avl-v1',catalog.identity]),views};
}
function occurrence(catalog,tenant,subscriber,r) {
  const domain=catalog.views[r.view].contract.order;
  const sentinel={integer:0n,string:'',id:'_',boolean:false}[domain];
  return {tenant,view:canonical([r.view,r.lower!==undefined]),partition:[...r.partition,r.aggregate],sourceId:subscriber,slot:r.slot,order:r.lower?.value??sentinel,contributions:{upper:r.upper?{order:r.upper.value}:{unbounded:true}}};
}
/** Return the normalized registration list for one subscriber (or an empty list). */
export async function readRoutes(tx,catalog,tenant,subscriber) {
  decodeDomain('id',tenant);decodeDomain('id',subscriber);
  const stored=await tx.get(listKey(catalog,tenant,subscriber));
  if(stored===undefined)return [];
  check(Array.isArray(stored));
  const result=stored.map(r=>registration(catalog,r));
  check(new Set(result.map(r=>r.slot)).size===result.length && equal(stored,result));
  return result;
}
/** Replace stable-slot field/range descriptors in the caller transaction; [] removes all. */
export async function replaceRoutes(tx,catalog,tenant,subscriber,registrations) {
  decodeDomain('id',tenant);decodeDomain('id',subscriber);canonical(registrations);
  if(!Array.isArray(registrations))fail('INVALID_ROUTE','Expected registrations');
  const next=registrations.map(r=>registration(catalog,r));
  if(new Set(next.map(r=>r.slot)).size!==next.length)fail('INVALID_ROUTE','Duplicate slot');
  const previous=await readRoutes(tx,catalog,tenant,subscriber), internal=forest(catalog);
  // Guard the complete expected old inventory before changing any entry.
  for(const r of previous) {
    check(equal(await tx.get(rowKey(catalog,tenant,subscriber,r.slot)),r));
    if(r.kind==='field')check(equal(await tx.get(directKey(catalog,tenant,subscriber,r)),{subscriber,slot:r.slot}));
    else {
      const o=occurrence(catalog,tenant,subscriber,r), n=await treeGet(tx,internal,o,o);
      check(n && equal(n.contributions,o.contributions));
    }
  }
  const beforeBySlot=new Map(previous.map(r=>[r.slot,r]));
  const afterBySlot=new Map(next.map(r=>[r.slot,r]));
  for(const r of previous) {
    if(equal(r,afterBySlot.get(r.slot)))continue;
    if(r.kind==='field')await tx.delete(directKey(catalog,tenant,subscriber,r));
    else check(await treeDelete(tx,internal,occurrence(catalog,tenant,subscriber,r)));
    await tx.delete(rowKey(catalog,tenant,subscriber,r.slot));
  }
  for(const r of next) {
    if(equal(r,beforeBySlot.get(r.slot)))continue;
    check(await tx.get(rowKey(catalog,tenant,subscriber,r.slot))===undefined);
    await tx.set(rowKey(catalog,tenant,subscriber,r.slot),r);
    if(r.kind==='field')await tx.set(directKey(catalog,tenant,subscriber,r),{subscriber,slot:r.slot});
    else await treePut(tx,internal,occurrence(catalog,tenant,subscriber,r));
  }
  if(next.length)await tx.set(listKey(catalog,tenant,subscriber),next);
  else await tx.delete(listKey(catalog,tenant,subscriber));
}

/** Report changes {fields:[{sourceId,selector}], points:[{view,partition,aggregate,order,sourceId,slot}]}.
 * Callers supply both old and new occurrence positions when a membership moves.
 * Return {subscribers, matches:[{subscriber,slot}], metrics:{intervalNodes,directEntries,matches}}.
 * Logical visits are budgeted; memory-adapter prefix scans still enumerate physical keys.
 * Max-upper pruning is conservative. Worst-case interval reporting is O(R).
 */
export async function affectedSubscribers(tx,catalog,tenant,changes,{maxVisits=Infinity}={}) {
  decodeDomain('id',tenant);fields(changes,['fields','points']);
  if(maxVisits!==Infinity&&(!Number.isSafeInteger(maxVisits)||maxVisits<0))fail('INVALID_ROUTE','Invalid visit budget');
  const {fields:rawFields=[],points:rawPoints=[]}=changes;
  if(!Array.isArray(rawFields)||!Array.isArray(rawPoints))fail('INVALID_ROUTE','Expected change arrays');
  const fieldsNormalized=rawFields.map(r=>{fields(r,['sourceId','selector']);return {sourceId:decodeDomain('id',r.sourceId),selector:selector(catalog,r.selector)};});
  const points=rawPoints.map(r=>{fields(r,['view','partition','aggregate','order','sourceId','slot']);const s=scope(catalog,r);return {...s,order:decodeDomain(catalog.views[s.view].contract.order,r.order),sourceId:decodeDomain('id',r.sourceId),slot:decodeDomain('string',r.slot)};});
  const metrics={intervalNodes:0,directEntries:0,matches:0}, matches=new Map(), internal=forest(catalog);
  const visit=kind=>{if(metrics.intervalNodes+metrics.directEntries>=maxVisits)fail('ROUTE_BUDGET','Route visit budget exhausted');metrics[kind]++;};
  const add=(subscriber,slot)=>{matches.set(canonical([subscriber,slot]),{subscriber,slot});};
  for(const r of new Map(fieldsNormalized.map(r=>[canonical(r),r])).values()) {
    const remaining=maxVisits-metrics.intervalNodes-metrics.directEntries;
    const limit=remaining===Infinity?Infinity:Math.min(Number.MAX_SAFE_INTEGER,remaining+1);
    for(const {key,value} of await tx.scan({prefix:directPrefix(catalog,tenant,r),limit})) {
      visit('directEntries');
      check(value&&typeof value.subscriber==='string'&&typeof value.slot==='string');
      const descriptor=await tx.get(rowKey(catalog,tenant,value.subscriber,value.slot));
      check(descriptor?.kind==='field'&&descriptor.slot===value.slot&&equal(descriptor.selector,r.selector)&&descriptor.sourceId===r.sourceId&&key===directKey(catalog,tenant,value.subscriber,descriptor));
      add(value.subscriber,value.slot);
    }
  }
  for(const p of new Map(points.map(p=>[canonical(p),p])).values()) for(const bounded of [false,true]) {
    const s={tenant,view:canonical([p.view,bounded]),partition:[...p.partition,p.aggregate]}, domain=catalog.views[p.view].contract.order;
    const root=await readRoot(tx,internal,s), stack=root?[root]:[],seen=new Set();
    while(stack.length) {
      const n=stack.pop(), token=occurrenceToken(n);visit('intervalNodes');check(!seen.has(token));seen.add(token);
      check(Number.isSafeInteger(n.height)&&n.height>0&&Number.isSafeInteger(n.size)&&n.size>0&&[n.left,n.right].every(x=>x===null||typeof x==='string'));
      const upper=n.aggregates?.upper;check(upper && (upper.unbounded===true||own(upper,'order')));
      if(!upper.unbounded&&compareDomain(domain,upper.order,p.order)<0)continue;
      const r=await tx.get(rowKey(catalog,tenant,n.sourceId,n.slot));
      check(r?.kind==='range'&&equal(scope(catalog,r),scope(catalog,p)));
      const expected=occurrence(catalog,tenant,n.sourceId,r);
      check(expected.slot===n.slot&&equal(expected.order,n.order)&&expected.view===s.view&&equal(expected.contributions,n.contributions));
      if(containsRange(domain,p,r))add(n.sourceId,n.slot);
      for(const side of ['left','right']) {
        if(side==='right'&&bounded&&compareDomain(domain,n.order,p.order)>0)continue;
        if(n[side]===null)continue;
        const child=await tx.get(nodeKey(internal,s,n[side]));check(child&&occurrenceToken(child)===n[side]);stack.push(child);
      }
    }
  }
  const result=[...matches.values()].sort((a,b)=>compareDomain('id',a.subscriber,b.subscriber)||compareDomain('string',a.slot,b.slot));
  metrics.matches=result.length;
  return {subscribers:[...new Set(result.map(r=>r.subscriber))],matches:result,metrics};
}
