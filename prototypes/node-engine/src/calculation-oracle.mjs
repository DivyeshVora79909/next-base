import { validateRecord } from './catalog.mjs';
import { sourceOracle } from './oracle.mjs';
import { generatedId, producerId } from './calculation-identity.mjs';
export { generatedId, producerId } from './calculation-identity.mjs';
import { canonical, fingerprint, decodeDomain, compareDomain, cloneData, freezeDeep, fail } from './values.mjs';

const own = (o, k) => Object.hasOwn(o, k);
const cmp = (a, b) => compareDomain('string', a, b);
const bad = message => fail('INVALID_CALCULATION', message);
const detached = value => {
  canonical(value);
  const copy = item => {
    if (Array.isArray(item)) return item.map(copy);
    if (!item || typeof item !== 'object') return item;
    const result = Object.create(null);
    for (const [key, child] of Object.entries(item)) result[key] = copy(child);
    return result;
  };
  return freezeDeep(copy(value));
};
function fields(value, allowed, required = allowed) {
  canonical(value);
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(k => !allowed.includes(k)) || required.some(k => !own(value, k))) bad('Invalid calculation object keys');
}
const array = value => { if (!Array.isArray(value)) bad('Expected array'); return value; };
const declaration = (catalog, view) => catalog.definition.contracts[catalog.definition.views[view].contract];
function selector(catalog, s, record) {
  fields(s, ['field', 'header'], []);
  if (Object.keys(s).length !== 1) bad('Expected one field selector');
  if (own(s, 'field')) {
    decodeDomain('id', s.field);
    const models = record ? [catalog.models[record.model]] : Object.values(catalog.models);
    if (!models.some(m => own(m.schema.properties, s.field))) bad('Unknown read field');
  } else if (!['id','tenant','model','owner','createdAt'].includes(s.header)) bad('Unknown header');
  return { ...s };
}
function direct(records, read) {
  const record = records.get(read.sourceId);
  if (!record) return { exists: false, present: false };
  const object = own(read.selector, 'field') ? record.data : record;
  const key = read.selector.field ?? read.selector.header;
  return own(object, key) ? { exists: true, present: true, value: object[key] } : { exists: true, present: false };
}
function readShape(catalog, input, records) {
  if (input?.kind === 'field') {
    fields(input, ['slot','kind','sourceId','selector']);
    decodeDomain('id', input.slot); decodeDomain('id', input.sourceId);
    return { ...input, selector: selector(catalog, input.selector, records.get(input.sourceId)) };
  }
  fields(input, ['slot','kind','view','partition','aggregate','lower','upper'], ['slot','kind','view','partition','aggregate']);
  decodeDomain('id', input.slot);
  const view = own(catalog.definition.views, input.view) && declaration(catalog,input.view);
  if (input.kind !== 'range' || !view || !own(view.aggregates, input.aggregate)) bad('Invalid range read');
  if (array(input.partition).length !== view.partition.length) bad('Wrong partition arity');
  const result = { slot: input.slot, kind: 'range', view: input.view, partition: input.partition.map((v,i) => decodeDomain(view.partition[i], v)), aggregate: input.aggregate };
  for (const bound of ['lower','upper']) if (own(input, bound)) {
    const cut = input[bound]; fields(cut, ['value','sourceId','slot','inclusive'], ['value']);
    if (own(cut,'sourceId') !== own(cut,'slot')) bad('Incomplete occurrence cut');
    if (own(cut,'inclusive') && typeof cut.inclusive !== 'boolean') bad('Invalid inclusive');
    result[bound] = { value: decodeDomain(view.order, cut.value), inclusive: cut.inclusive ?? true };
    if (own(cut,'sourceId')) Object.assign(result[bound], { sourceId: decodeDomain('id',cut.sourceId), slot: decodeDomain('string',cut.slot) });
  }
  return result;
}
// Flat declarations only: templates establish positions, never settled values.
function project(catalog, record) {
  const result = [];
  for (const binding of catalog.definition.models[record.model].memberships ?? []) {
    const contract = declaration(catalog,binding.view);
    let missing = false;
    const select = (s, domain) => {
      const object = own(s,'field') ? record.data : record;
      const key = s.field ?? s.header;
      if (own(s,'constant')) return decodeDomain(domain,s.constant);
      if (!own(object,key)) { missing = true; return undefined; }
      return decodeDomain(domain,object[key]);
    };
    const partition = binding.partition.map((s,i) => select(s,contract.partition[i]));
    const order = select(binding.order,contract.order), inputs = Object.create(null);
    for (const [key,domain] of Object.entries(contract.inputs)) inputs[key] = select(binding.inputs[key],domain);
    if (missing) { if (binding.onMissing === 'skip') continue; bad('Missing projection'); }
    result.push({ tenant: record.tenant, view: binding.view, partition, order, sourceId: record.id, slot: binding.slot, inputs });
  }
  return result;
}
const topology = rows => rows.map(({inputs,...row}) => row);
function matches(catalog, read, row) {
  if (row.view !== read.view || canonical(row.partition) !== canonical(read.partition)) return false;
  for (const side of ['lower','upper']) if (read[side]) {
    const cut = read[side];
    const comparison = compareDomain(declaration(catalog,read.view).order,row.order,cut.value) || (own(cut,'sourceId') ? cmp(row.sourceId,cut.sourceId) || cmp(row.slot,cut.slot) : 0);
    if (side === 'lower' ? comparison < 0 || comparison === 0 && !cut.inclusive : comparison > 0 || comparison === 0 && !cut.inclusive) return false;
  }
  return true;
}
function rangeValue(catalog, read, records) {
  const contract = catalog.views[read.view].contract, aggregate = contract.aggregates[read.aggregate];
  const rows = [...records.values()].flatMap(record => project(catalog,record)).filter(row => matches(catalog,read,row));
  rows.sort((a,b) => compareDomain(declaration(catalog,read.view).order,a.order,b.order) || cmp(a.sourceId,b.sourceId) || cmp(a.slot,b.slot));
  return rows.reduce((value,row) => aggregate.implementation.combine(value,aggregate.implementation.lift(row.inputs[declaration(catalog,read.view).aggregates[read.aggregate].input])),aggregate.implementation.identity());
}

/** Independent batch reference. Caller supplies a COMPLETE tenant authored snapshot and
 * the complete historical reservation ledger, including retired producers/roles.
 * Trusted callbacks must be pure; this reference provides no JavaScript sandbox. */
export async function settlementOracle(catalog, tenant, authored, { reservations = [], maxProducers = Infinity, maxEdges = Infinity } = {}) {
  decodeDomain('id',tenant);
  for (const budget of [maxProducers,maxEdges]) if (budget !== Infinity && (!Number.isSafeInteger(budget) || budget < 0)) bad('Invalid budget');
  const records = new Map(), ledger = new Map(), outputIds = new Set(), producers = [], potential = [], owner = new Map();
  const identity = r => canonical([r.tenant,r.anchorId,r.calculation,r.role]);
  for (const input of array(reservations)) {
    fields(input,['tenant','anchorId','calculation','role','outputId','model','createdAt']);
    for (const key of ['tenant','anchorId','calculation','role','outputId','model']) decodeDomain('id',input[key]);
    if (typeof input.createdAt !== 'string') bad('Reservation timestamp must be a canonical integer string');
    decodeDomain('integer',input.createdAt);
    if (input.tenant !== tenant || !own(catalog.models,input.model) || !catalog.models[input.model].managed || input.outputId !== generatedId(tenant,input.anchorId,input.calculation,input.role)) bad('Invalid reservation');
    const key = identity(input);
    if (ledger.has(key) || outputIds.has(input.outputId)) bad('Duplicate reservation');
    ledger.set(key,cloneData(input)); outputIds.add(input.outputId);
  }
  for (const input of array(authored)) {
    const record = validateRecord(catalog,input);
    if (record.tenant !== tenant || record.id.startsWith('@next/derived/') || catalog.models[record.model].managed || records.has(record.id)) bad('Invalid authored snapshot');
    records.set(record.id,record);
  }
  const count = [...records.values()].reduce((n,r) => n + catalog.models[r.model].calculations.length,0);
  if (count > maxProducers) fail('CALCULATION_BUDGET','Producer budget exceeded');
  const anchors = [...records.values()].sort((a,b) => cmp(a.id,b.id));
  for (const record of anchors) for (const rule of catalog.models[record.model].calculations) {
    const resolveReads = new Map(); let open = true;
    const readField = (id,s) => {
      if (!open) bad('Resolver read facade closed');
      decodeDomain('id',id);
      if (id.startsWith('@next/derived/')) bad('Resolver cannot read managed topology');
      const selected = selector(catalog,s,records.get(id));
      for (const sel of [selected,{header:'id'}]) {
        const slot = 'resolve:' + fingerprint([id,sel]);
        resolveReads.set(slot,{ slot,kind:'field',sourceId:id,selector:sel });
      }
      return detached(direct(records,{sourceId:id,selector:selected}));
    };
    let shape;
    try { shape = await rule.implementation.resolve(Object.freeze({record:detached(record),readField})); } finally { open = false; }
    shape = detached(shape); fields(shape,['parameters','reads','outputs']);
    const reads = array(shape.reads).map(r => readShape(catalog,r,records));
    if (new Set(reads.map(r => r.slot)).size !== reads.length) bad('Duplicate read slots');
    const outputs = [], roles = new Set();
    const id = producerId(tenant,record.id,rule.slot);
    for (const output of array(shape.outputs)) {
      fields(output,['role','model','owner','createdAt','data','computed']); decodeDomain('id',output.role);
      if (roles.has(output.role)) bad('Duplicate output role'); roles.add(output.role);
      if (!own(catalog.models,output.model) || !catalog.models[output.model].managed) bad('Output requires managed model');
      const computed = array(output.computed);
      if (new Set(computed).size !== computed.length || computed.some(f => typeof f !== 'string' || !own(catalog.models[output.model].schema.properties,f))) bad('Invalid computed fields');
      const outputId = generatedId(tenant,record.id,rule.slot,output.role);
      const template = validateRecord(catalog,{id:outputId,tenant,model:output.model,owner:output.owner,createdAt:output.createdAt,data:output.data});
      const reservation = {tenant,anchorId:record.id,calculation:rule.slot,role:output.role,outputId,model:output.model,createdAt:output.createdAt};
      const key = identity(reservation), prior = ledger.get(key);
      if (prior && (prior.model !== output.model || prior.createdAt !== output.createdAt)) bad('Reservation metadata changed');
      if (!prior) { if (outputIds.has(outputId)) bad('Output identity collision'); ledger.set(key,reservation); outputIds.add(outputId); }
      outputs.push({role:output.role,record:template,computed:[...computed]}); owner.set(outputId,id);
      potential.push(...project(catalog,template).map(row => ({...row,producer:id})));
    }
    producers.push({id,anchorId:record.id,calculation:rule.slot,parameters:shape.parameters,reads,outputs,resolveReads:[...resolveReads.values()], implementation:rule.implementation});
  }
  // Validate direct selectors against declared generated models, even while absent.
  const templates = new Map(producers.flatMap(p => p.outputs.map(o => [o.record.id,o.record])));
  for (const producer of producers) for (const read of producer.reads) {
    if (read.kind === 'field' && templates.has(read.sourceId)) selector(catalog,read.selector,templates.get(read.sourceId));
  }
  producers.sort((a,b) => cmp(a.id,b.id));
  const edgeMap = new Map(); let edgeChecks = 0;
  for (const producer of producers) for (const read of producer.reads) {
    const predecessors = read.kind === 'field' ? (owner.has(read.sourceId) ? [owner.get(read.sourceId)] : []) : potential.filter(row => { edgeChecks++; return matches(catalog,read,row); }).map(row => row.producer);
    if (read.kind === 'field') edgeChecks++;
    for (const from of predecessors) {
      const key = canonical([from,producer.id]);
      if (!edgeMap.has(key)) { if (edgeMap.size >= maxEdges) fail('CALCULATION_BUDGET','Edge budget exceeded'); edgeMap.set(key,{from,to:producer.id}); }
    }
  }
  const edges = [...edgeMap.values()].sort((a,b) => cmp(a.from,b.from) || cmp(a.to,b.to));
  const pending = new Map(producers.map(p => [p.id,new Set(edges.filter(e => e.to === p.id).map(e => e.from))])), order = [];
  while (pending.size) {
    const next = [...pending.keys()].filter(id => pending.get(id).size === 0).sort(cmp)[0];
    if (next === undefined) fail('CALCULATION_CYCLE','Potential calculation graph contains a cycle');
    pending.delete(next); order.push(next); for (const deps of pending.values()) deps.delete(next);
  }
  const generated = [];
  for (const id of order) {
    const producer = producers.find(p => p.id === id), values = Object.create(null);
    for (const read of producer.reads) values[read.slot] = read.kind === 'field' ? direct(records,read) : rangeValue(catalog,read,records);
    const result = producer.implementation.evaluate(detached({parameters:producer.parameters,values}));
    if (result && typeof result.then === 'function') { Promise.resolve(result).catch(() => {}); bad('Evaluation must be synchronous'); }
    const evaluated = detached(result); fields(evaluated,['outputs']);
    fields(evaluated.outputs,producer.outputs.map(o => o.role));
    for (const output of producer.outputs) {
      const patch = evaluated.outputs[output.role]; if (patch === null) continue;
      fields(patch,output.computed);
      const actual = validateRecord(catalog,{...output.record,data:{...output.record.data,...patch}});
      if (canonical(topology(project(catalog,actual))) !== canonical(topology(project(catalog,output.record)))) bad('Computed patch changes topology');
      records.set(actual.id,actual); generated.push(actual);
    }
  }
  const all = [...records.values()].sort((a,b) => cmp(a.id,b.id)), inventory = sourceOracle(catalog,all);
  const scopes = new Map();
  for (const row of [...inventory.trees,...potential]) { const scope = {tenant,view:row.view,partition:row.partition}; scopes.set(canonical(scope),scope); }
  for (const scope of scopes.values()) {
    const contract = catalog.views[scope.view].contract;
    const tree = inventory.trees.find(t => t.view === scope.view && canonical(t.partition) === canonical(scope.partition));
    const aggregates = tree?.aggregates ?? Object.fromEntries(Object.entries(contract.aggregates).map(([name,a]) => [name,a.implementation.identity()]));
    for (const rule of contract.validators) {
      const result = rule.implementation.validate(detached(aggregates),detached({scope}));
      if (result && typeof result.then === 'function') Promise.resolve(result).catch(() => {});
      if (result !== true) fail('VALIDATION_FAILED',`Summary validator ${rule.use} rejected scope`);
    }
  }
  const routes = producers.map(p => ({subscriber:p.id,registrations:[
    ...p.resolveReads,
    ...p.reads.flatMap(read => {
      const registrations = [{...read,slot:'evaluate:'+read.slot}];
      if (read.kind === 'field' && read.selector.header !== 'id') registrations.push({
        slot:'evaluate-existence:'+read.slot,kind:'field',sourceId:read.sourceId,selector:{header:'id'}
      });
      return registrations;
    })
  ]}));
  return {records:all,generated:generated.sort((a,b) => cmp(a.id,b.id)),reservations:[...ledger.values()].sort((a,b) => cmp(identity(a),identity(b))),producers:producers.map(({implementation,...p}) => p),order,edges,routes,inventory,metrics:{producers:producers.length,potentialOccurrences:potential.length,edgeChecks,edges:edges.length,evaluations:order.length}};
}
