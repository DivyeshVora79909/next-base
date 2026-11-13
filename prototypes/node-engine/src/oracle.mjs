import { validateRecord } from './catalog.mjs';
import { canonical, decodeDomain, compareDomain } from './values.mjs';

const reject = (code, message) => { throw Object.assign(new Error(message), { code }); };
const own = (object, key) => Object.hasOwn(object, key);
const textCompare = (left, right) => compareDomain('id', left, right);
// Deliberately do not use projectRecord/selectValue or any writer/index state.
function select(record, selector) {
  if (own(selector, 'constant')) return { present: true, value: selector.constant };
  const object = own(selector, 'field') ? record.data : record;
  const key = selector.field ?? selector.header;
  return { present: own(object, key), value: object[key] };
}

/** Flat, source-derived inventory. Enumeration/sorting is intentionally unindexed. */
export function sourceOracle(prepared, records) {
  const sources = new Map(), groups = new Map(), references = [], claims = [], claimed = new Set();
  for (const input of records) {
    const record = validateRecord(prepared, input);
    const key = canonical([record.tenant, record.id]);
    if (sources.has(key)) reject('DUPLICATE_SOURCE', `Duplicate source ${record.id}`);
    sources.set(key, record);
  }
  for (const record of sources.values()) {
    const model = prepared.definition.models[record.model];
    for (const reference of model.references ?? []) {
      if (!own(record.data, reference.field)) continue;
      const value = record.data[reference.field];
      if (reference.many && !Array.isArray(value)) reject('INVALID_REFERENCE', 'Expected reference array');
      const ids = reference.many ? value : [value];
      ids.forEach((id, position) => {
        decodeDomain('id', id);
        const target = sources.get(canonical([record.tenant, id]));
        if (!target || !reference.targets.includes(target.model)) reject('INVALID_REFERENCE', `Invalid reference ${id}`);
        references.push({ tenant: record.tenant, sourceId: record.id, slot: reference.slot, position, targetId: id, targets: [...reference.targets] });
      });
    }
    for (const unique of model.uniqueness ?? []) {
      const values = unique.fields.map(selector => {
        const selected = select(record, selector);
        if (!selected.present) reject('MISSING_CLAIM', `Missing claim value ${unique.slot}`);
        return selected.value;
      });
      const key = canonical([record.tenant, record.model, unique.slot, values]);
      if (claimed.has(key)) reject('DUPLICATE_CLAIM', `Duplicate claim ${unique.slot}`);
      claimed.add(key);
      claims.push({ tenant: record.tenant, model: record.model, slot: unique.slot, values, sourceId: record.id });
    }
    for (const binding of model.memberships ?? []) {
      const contractId = prepared.definition.views[binding.view].contract;
      const declaration = prepared.definition.contracts[contractId];
      const contract = prepared.contracts[contractId];
      let missing = false;
      const read = (selector, domain) => {
        const selected = select(record, selector);
        if (!selected.present) { missing = true; return undefined; }
        return decodeDomain(domain, selected.value);
      };
      const partition = binding.partition.map((selector, index) => read(selector, declaration.partition[index]));
      const order = read(binding.order, declaration.order), inputs = Object.create(null);
      for (const [name, domain] of Object.entries(declaration.inputs)) inputs[name] = read(binding.inputs[name], domain);
      if (missing) {
        if (binding.onMissing === 'skip') continue;
        reject('MISSING_PROJECTION', `Missing membership value ${binding.slot}`);
      }
      const contributions = Object.create(null);
      for (const [name, aggregate] of Object.entries(declaration.aggregates)) contributions[name] = contract.aggregates[name].implementation.lift(inputs[aggregate.input]);
      const key = canonical([record.tenant, binding.view, partition]);
      if (!groups.has(key)) groups.set(key, { tenant: record.tenant, view: binding.view, partition, members: [] });
      groups.get(key).members.push({ sourceId: record.id, slot: binding.slot, order, inputs, contributions });
    }
  }
  const trees = [...groups.values()];
  for (const tree of trees) {
    const declaration = prepared.definition.contracts[prepared.definition.views[tree.view].contract];
    const contract = prepared.contracts[prepared.definition.views[tree.view].contract];
    tree.members.sort((a, b) => compareDomain(declaration.order, a.order, b.order) || textCompare(a.sourceId, b.sourceId) || textCompare(a.slot, b.slot));
    tree.count = tree.members.length;
    tree.aggregates = Object.create(null);
    for (const [name, aggregate] of Object.entries(contract.aggregates)) {
      tree.aggregates[name] = tree.members.reduce((summary, member) => aggregate.implementation.combine(summary, member.contributions[name]), aggregate.implementation.identity());
    }
  }
  trees.sort((a, b) => textCompare(canonical([a.tenant, a.view, a.partition]), canonical([b.tenant, b.view, b.partition])));
  references.sort((a, b) => textCompare(a.tenant, b.tenant) || textCompare(a.sourceId, b.sourceId) || textCompare(a.slot, b.slot) || a.position - b.position);
  claims.sort((a, b) => textCompare(a.tenant, b.tenant) || textCompare(a.model, b.model) || textCompare(a.slot, b.slot) || textCompare(a.sourceId, b.sourceId));
  return { trees, references, claims };
}
