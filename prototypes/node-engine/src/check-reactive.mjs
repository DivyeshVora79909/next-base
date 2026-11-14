import { settlementOracle } from './calculation-oracle.mjs';
import { GENERATED_PREFIX } from './calculation-identity.mjs';
import { canonical, fingerprint, compareDomain, decodeDomain, fail } from './values.mjs';
import { reactivePrefix, producerKey, reservationKey, potentialOwnerKey, rootKey, nodeKey, occurrenceToken, allRootsPrefix, allNodesPrefix } from './keys.mjs';

const ensure = (condition, message) => { if (!condition) fail('INTEGRITY', message); };
const same = (a,b) => canonical(a) === canonical(b);
function inventory(actual, expected, label) {
  ensure(actual.size === expected.size, `${label} inventory size`);
  for (const [key,value] of expected) ensure(actual.has(key) && same(actual.get(key),value), `${label} entry ${key}`);
}
const load = async (tx,prefix) => new Map((await tx.scan({prefix})).map(({key,value}) => [key,value]));

// Independently inspect the physical AVL inventory; never use writer traversals or summaries.
async function checkForest(tx,catalog,tenant,occurrences,label) {
  const groups = new Map();
  for (const occurrence of occurrences) {
    const key = rootKey(catalog,occurrence);
    if (!groups.has(key)) groups.set(key,{...occurrence,members:[]});
    groups.get(key).members.push(occurrence);
  }
  const [roots,nodes] = await Promise.all([load(tx,allRootsPrefix(catalog,tenant)),load(tx,allNodesPrefix(catalog,tenant))]);
  ensure(roots.size === groups.size,`${label} roots inventory`);
  const visited = new Set();
  for (const [key,scope] of groups) {
    const contract = catalog.views[scope.view].contract;
    const members = scope.members.sort((a,b) => compareDomain(contract.order,a.order,b.order) || compareDomain('id',a.sourceId,b.sourceId) || compareDomain('string',a.slot,b.slot));
    const byToken = new Map(members.map(m => [occurrenceToken(m),m]));
    ensure(byToken.size === members.length,`${label} duplicate occurrence`);
    const header = roots.get(key), ordered = [];
    ensure(header && Object.keys(header).length === 1 && typeof header.head === 'string',`${label} root shape`);
    const empty = () => Object.fromEntries(Object.entries(contract.aggregates).map(([name,a]) => [name,a.implementation.identity()]));
    function walk(token) {
      if (token === null) return {height:0,size:0,aggregates:empty()};
      ensure(typeof token === 'string',`${label} child token`);
      const physical = nodeKey(catalog,scope,token), node = nodes.get(physical), member = byToken.get(token);
      ensure(!visited.has(physical),`${label} cycle/shared child`); visited.add(physical);
      ensure(node && member,`${label} missing/extra member`);
      const names = ['sourceId','slot','order','contributions','left','right','height','size','aggregates'];
      ensure(Object.keys(node).length === names.length && names.every(n => Object.hasOwn(node,n)),`${label} node shape`);
      ensure(node.sourceId === member.sourceId && node.slot === member.slot && same(node.order,member.order) && same(node.contributions,member.contributions),`${label} node binding`);
      const left = walk(node.left); ordered.push(token); const right = walk(node.right);
      const height = 1 + Math.max(left.height,right.height), size = left.size + 1 + right.size;
      ensure(Math.abs(left.height-right.height) <= 1 && node.height === height && node.size === size,`${label} balance/count`);
      const aggregates = empty();
      for (const [name,a] of Object.entries(contract.aggregates)) aggregates[name] = a.implementation.combine(a.implementation.combine(left.aggregates[name],member.contributions[name]),right.aggregates[name]);
      ensure(same(node.aggregates,aggregates),`${label} aggregate`);
      return {height,size,aggregates};
    }
    const result = walk(header.head);
    ensure(result.size === members.length && same(ordered,members.map(occurrenceToken)),`${label} order/inventory`);
  }
  ensure(visited.size === nodes.size,`${label} orphan nodes`);
  return {trees:roots.size,occurrences:nodes.size};
}

// Flat declaration projection, including missing input participation, independent of projectRecord.
function potentialOccurrences(catalog,record) {
  const result = [];
  for (const binding of catalog.definition.models[record.model].memberships ?? []) {
    const declaration = catalog.definition.contracts[catalog.definition.views[binding.view].contract];
    let missing = false;
    const select = (selector,domain) => {
      if (Object.hasOwn(selector,'constant')) return decodeDomain(domain,selector.constant);
      const object = Object.hasOwn(selector,'field') ? record.data : record, key = selector.field ?? selector.header;
      if (!Object.hasOwn(object,key)) { missing = true; return undefined; }
      return decodeDomain(domain,object[key]);
    };
    const partition = binding.partition.map((s,i) => select(s,declaration.partition[i]));
    const order = select(binding.order,declaration.order);
    for (const [name,domain] of Object.entries(declaration.inputs)) select(binding.inputs[name],domain);
    if (missing) { ensure(binding.onMissing === 'skip','Potential missing projection'); continue; }
    result.push({tenant:record.tenant,view:binding.view,partition,sourceId:record.id,slot:binding.slot,order,contributions:{}});
  }
  return result;
}

/** Full independent reactive check within the caller's existing snapshot.
 * Retired reservation completeness is a historical precondition: a deleted retired
 * ledger entry cannot always be inferred from present authored facts.
 */
export async function checkReactive(tx,catalog,tenant,actualRecords) {
  const authored = [], managed = [];
  for (const record of actualRecords) {
    const model = catalog.models[record.model];
    ensure(model && record.tenant === tenant,'Reactive source model/tenant');
    const reserved = record.id.startsWith(GENERATED_PREFIX);
    ensure(Boolean(model.managed) === reserved,'Managed/reserved source identity');
    (reserved ? managed : authored).push(record);
  }
  const privateRows = await load(tx,reactivePrefix(catalog,tenant));
  const ledger = [];
  for (const [key,value] of privateRows) if (key.startsWith(`${reactivePrefix(catalog,tenant)}reservation/`)) {
    ensure(value && key === reservationKey(catalog,tenant,value.outputId),'Reservation storage identity'); ledger.push(value);
  }
  const expected = await settlementOracle(catalog,tenant,authored,{reservations:ledger});
  inventory(new Map(managed.map(r => [r.id,r])),new Map(expected.generated.map(r => [r.id,r])),'Managed sources');
  const expectedPrivate = new Map();
  for (const p of expected.producers) expectedPrivate.set(producerKey(catalog,tenant,p.id),p);
  for (const r of expected.reservations) expectedPrivate.set(reservationKey(catalog,tenant,r.outputId),r);
  const potentials = [];
  for (const p of expected.producers) for (const output of p.outputs) {
    expectedPrivate.set(potentialOwnerKey(catalog,tenant,output.record.id),{producer:p.id});
    potentials.push(...potentialOccurrences(catalog,output.record));
  }
  inventory(privateRows,expectedPrivate,'Reactive private');
  const potentialCatalog = {identity:fingerprint(['internal-potential-avl-v1',catalog.identity]),views:Object.fromEntries(Object.entries(catalog.views).map(([name,v]) => [name,{contract:{partition:v.contract.partition,order:v.contract.order,aggregates:{}}}]))};
  const potential = await checkForest(tx,potentialCatalog,tenant,potentials,'Potential');
  const routeBase = `routes/v1/${canonical(tenant)}/${catalog.identity}/`, expectedRoutes = new Map(), intervals = [];
  const intervalViews = Object.create(null);
  for (const [name,v] of Object.entries(catalog.views)) for (const bounded of [false,true]) {
    const domain = v.contract.order;
    // Independent maximum upper endpoint; null is the empty identity, infinity dominates.
    const combine = (a,b) => a === null ? b : b === null ? a : a.unbounded || b.unbounded ? {unbounded:true} : {order:compareDomain(domain,a.order,b.order) >= 0 ? a.order : b.order};
    intervalViews[canonical([name,bounded])] = {contract:{partition:[...v.contract.partition,'string'],order:domain,aggregates:{upper:{implementation:{identity:() => null,combine}}}}};
  }
  for (const {subscriber,registrations} of expected.routes) {
    if (registrations.length) expectedRoutes.set(`${routeBase}list/${canonical(subscriber)}`,registrations);
    for (const r of registrations) {
      expectedRoutes.set(`${routeBase}row/${canonical([subscriber,r.slot])}`,r);
      if (r.kind === 'field') expectedRoutes.set(`${routeBase}direct/${canonical([r.sourceId,r.selector])}/${canonical([subscriber,r.slot])}`,{subscriber,slot:r.slot});
      else intervals.push({tenant,view:canonical([r.view,r.lower !== undefined]),partition:[...r.partition,r.aggregate],sourceId:subscriber,slot:r.slot,order:r.lower?.value ?? {integer:0n,string:'',id:'_',boolean:false}[catalog.views[r.view].contract.order],contributions:{upper:r.upper ? {order:r.upper.value} : {unbounded:true}}});
    }
  }
  inventory(await load(tx,routeBase),expectedRoutes,'Routes');
  const interval = await checkForest(tx,{identity:fingerprint(['internal-route-interval-avl-v1',catalog.identity]),views:intervalViews},tenant,intervals,'Route intervals');
  return {producers:expected.producers.length,reservations:ledger.length,managed:managed.length,potential,interval};
}
