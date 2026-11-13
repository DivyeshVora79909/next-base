import Ajv2020 from 'ajv/dist/2020.js';
import { cloneData, freezeDeep, fingerprint, decodeDomain, assertJson, selectValue } from './values.mjs';
import { standardMonoids } from './monoids.mjs';

const fail = (message, code = 'INVALID_CATALOG') => { throw Object.assign(new Error(message), { code }); };
const own = (o, k) => Object.hasOwn(o, k);
const object = (v, label) => { if (!v || typeof v !== 'object' || Array.isArray(v)) fail(`${label} must be an object`); return v; };
const name = (v, label) => { if (typeof v !== 'string' || !v.length) fail(`${label} must be a nonempty string`); return v; };
const keysOnly = (value, allowed, label) => { object(value, label); for (const key of Object.keys(value)) if (!allowed.includes(key)) fail(`Unknown ${label} key ${key}`); };
const asyncFunctionPrototype = Object.getPrototypeOf(async () => {});
const domains = new Set(['id', 'string', 'integer', 'boolean']);
const domain = value => { if (!domains.has(value)) fail(`Unsupported domain ${value}`); return value; };
const emptyDeferred = value => value === undefined || (Array.isArray(value) ? value.length === 0 : value && typeof value === 'object' && Object.keys(value).length === 0);
function slots(entries, label) {
  if (!Array.isArray(entries)) fail(`${label} must be an array`);
  const seen = new Set();
  for (const entry of entries) { object(entry, label); name(entry.slot, `${label} slot`); if (seen.has(entry.slot)) fail(`Duplicate ${label} slot ${entry.slot}`); seen.add(entry.slot); }
}
function selector(model, value, expected) {
  object(value, 'Selector');
  const keys = Object.keys(value);
  if (keys.length !== 1 || !['field', 'header', 'constant'].includes(keys[0])) fail('Selector requires exactly one field, header or constant');
  let schema;
  if (own(value, 'field')) {
    name(value.field, 'Selector field');
    if (!own(model.schema.properties, value.field)) fail(`Unknown binding field ${value.field}`);
    schema = model.schema.properties[value.field];
  } else if (own(value, 'header')) {
    if (!['id', 'tenant', 'owner', 'createdAt'].includes(value.header)) fail('Unsupported header selector');
    if (expected && (value.header === 'createdAt' ? expected !== 'integer' : !['id', 'string'].includes(expected))) fail('Incompatible header domain');
  } else if (expected) decodeDomain(expected, value.constant);
  if (expected && schema && typeof schema === 'object' && schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.includes(expected === 'boolean' ? 'boolean' : 'string')) fail(`Field ${value.field} is incompatible with ${expected} wire values`);
  }
}

/** Compile immutable declarations and trusted implementation references once. */
export function prepareCatalog(definition, { monoids = standardMonoids, validators = {}, calculations = {} } = {}) {
  assertJson(definition);
  const declaration = cloneData(definition);
  keysOnly(declaration, ['name','version','contracts','views','models','calculations','dependencies'], 'Catalog'); name(declaration.name, 'Catalog name'); name(declaration.version, 'Catalog version');
  for (const key of ['calculations', 'dependencies']) if (!emptyDeferred(declaration[key])) fail(`${key} are unsupported in JS-P1`);
  const contracts = Object.create(null), views = Object.create(null), models = Object.create(null), usedMonoids = Object.create(null), usedValidators = Object.create(null), usedCalculations = Object.create(null);
  const ajv = new Ajv2020({ strict: true, allErrors: true, ownProperties: true, coerceTypes: false, useDefaults: false, removeAdditional: false, validateSchema: true });
  for (const [id, spec] of Object.entries(object(declaration.contracts, 'Contracts'))) {
    keysOnly(spec, ['version','partition','order','inputs','aggregates','validators','calculations','dependencies'], 'Contract');
    for (const key of ['calculations', 'dependencies']) if (!emptyDeferred(spec[key])) fail(`${key} are unsupported in JS-P1`);
    name(spec.version, 'Contract version');
    if (!Array.isArray(spec.partition)) fail('Contract partition must be an array');
    spec.partition.forEach(domain); domain(spec.order); object(spec.inputs, 'Contract inputs'); Object.values(spec.inputs).forEach(domain);
    const aggregates = Object.create(null);
    for (const [slot, aggregate] of Object.entries(object(spec.aggregates, 'Aggregates'))) {
      keysOnly(aggregate, ['monoid','input'], 'Aggregate');
      const implementation = own(monoids, aggregate.monoid) ? { ...monoids[aggregate.monoid] } : undefined;
      if (!implementation || typeof implementation.identity !== 'function' || typeof implementation.lift !== 'function' || typeof implementation.combine !== 'function') fail(`Unknown monoid ${aggregate.monoid}`);
      name(implementation.version, 'Monoid version');
      if (!own(spec.inputs, aggregate.input) || implementation.inputDomain !== spec.inputs[aggregate.input]) fail(`Incompatible monoid input ${slot}`);
      aggregates[slot] = { ...aggregate, implementation };
      usedMonoids[aggregate.monoid] = { version: implementation.version, inputDomain: implementation.inputDomain };
    }
    const compiledValidators = (spec.validators ?? []).map(rule => {
      keysOnly(rule, ['scope','use'], 'Validator');
      if (!['root', 'allPrefixes'].includes(rule.scope)) fail('Unsupported validator scope');
      const implementation = own(validators, rule.use) ? { ...validators[rule.use] } : undefined;
      if (!implementation || typeof implementation.validate !== 'function') fail(`Unknown validator ${rule.use}`);
      name(implementation.version, 'Validator version'); usedValidators[rule.use] = { version: implementation.version };
      return { ...rule, implementation };
    });
    contracts[id] = { ...spec, aggregates, validators: compiledValidators };
  }
  for (const [id, spec] of Object.entries(object(declaration.views, 'Views'))) {
    keysOnly(spec, ['contract','calculations','dependencies'], 'View');
    for (const key of ['calculations', 'dependencies']) if (!emptyDeferred(spec[key])) fail(`${key} are unsupported in JS-P1`);
    if (!own(contracts, spec.contract)) fail(`Unknown contract ${spec.contract}`);
    views[id] = { ...spec, contract: contracts[spec.contract], contractId: spec.contract };
  }
  for (const [id, spec] of Object.entries(object(declaration.models, 'Models'))) {
    keysOnly(spec, ['schema','references','uniqueness','memberships','managed','calculations','dependencies'], 'Model');
    if (!emptyDeferred(spec.dependencies)) fail('dependencies are unsupported in JS-P3b.1');
    if (spec.managed !== undefined && typeof spec.managed !== 'boolean') fail('Model managed must be a boolean');
    const managed = spec.managed ?? false;
    const calculationDeclarations = spec.calculations ?? [];
    if (spec.calculations === null) fail('Model calculations must be an array');
    slots(calculationDeclarations, 'calculation');
    if (managed && calculationDeclarations.length) fail('Managed models cannot declare calculations');
    const compiledCalculations = calculationDeclarations.map(rule => {
      keysOnly(rule, ['slot','use'], 'Calculation');
      name(rule.use, 'Calculation use');
      const registered = own(calculations, rule.use) ? calculations[rule.use] : undefined;
      if (!registered || typeof registered.resolve !== 'function' || typeof registered.evaluate !== 'function' || Object.getPrototypeOf(registered.evaluate) === asyncFunctionPrototype) fail(`Unknown or invalid calculation ${rule.use}`);
      name(registered.version, 'Calculation version');
      const implementation = { version: registered.version, resolve: registered.resolve, evaluate: registered.evaluate };
      usedCalculations[rule.use] = { version: implementation.version };
      return { ...rule, implementation };
    });
    object(spec.schema, 'Model schema');
    if (spec.schema.type !== 'object' || spec.schema.additionalProperties !== false) fail('Model schema requires object root and additionalProperties:false');
    object(spec.schema.properties, 'Schema properties');
    const rejectAsync = value => { if (!value || typeof value !== 'object') return; if (value.$async !== undefined) fail('$async schemas are unsupported'); for (const child of Object.values(value)) rejectAsync(child); };
    rejectAsync(spec.schema);
    const validate = ajv.compile(spec.schema);
    if (validate.$async) fail('$async schemas are unsupported');
    const references = spec.references ?? [], uniqueness = spec.uniqueness ?? [], memberships = spec.memberships ?? [];
    slots(references, 'reference'); slots(uniqueness, 'uniqueness'); slots(memberships, 'membership');
    for (const reference of references) {
      keysOnly(reference, ['slot','field','targets','many','onDelete'], 'Reference');
      selector(spec, { field: reference.field });
      if (!Array.isArray(reference.targets) || !reference.targets.length || reference.targets.some(target => !own(declaration.models, target))) fail('Unknown reference target');
      if (typeof reference.many !== 'boolean' || reference.onDelete !== 'reject') fail('Unsupported reference behavior');
      const fieldSchema = spec.schema.properties[reference.field];
      if (fieldSchema?.type !== undefined) {
        const types = Array.isArray(fieldSchema.type) ? fieldSchema.type : [fieldSchema.type];
        if (!types.includes(reference.many ? 'array' : 'string')) fail('Incompatible reference field schema');
      }
    }
    for (const unique of uniqueness) { keysOnly(unique, ['slot','fields'], 'Uniqueness'); if (!Array.isArray(unique.fields) || !unique.fields.length) fail('Uniqueness requires fields'); unique.fields.forEach(value => selector(spec, value)); }
    for (const membership of memberships) {
      keysOnly(membership, ['slot','view','partition','order','inputs','onMissing'], 'Membership');
      const view = views[membership.view]; if (!view) fail(`Unknown view ${membership.view}`);
      const contract = view.contract;
      if (!Array.isArray(membership.partition) || membership.partition.length !== contract.partition.length) fail('Wrong partition arity');
      membership.partition.forEach((value, index) => selector(spec, value, contract.partition[index])); selector(spec, membership.order, contract.order);
      object(membership.inputs, 'Membership inputs');
      if (Object.keys(membership.inputs).length !== Object.keys(contract.inputs).length || Object.keys(membership.inputs).some(key => !own(contract.inputs, key))) fail('Membership input mismatch');
      for (const [key, expected] of Object.entries(contract.inputs)) selector(spec, membership.inputs[key], expected);
      if (!['reject', 'skip'].includes(membership.onMissing)) fail('Membership requires onMissing policy');
    }
    models[id] = { ...spec, managed, calculations: compiledCalculations, references, uniqueness, memberships, validate };
  }
  const identity = fingerprint({ declaration, monoids: usedMonoids, validators: usedValidators, ...(Object.keys(usedCalculations).length ? { calculations: usedCalculations } : {}) });
  for (const [id, view] of Object.entries(views)) view.identity = fingerprint({ catalog: identity, view: id });
  return freezeDeep({ identity, definition: declaration, contracts, views, models });
}

export function validateRecord(prepared, record) {
  assertJson(record); object(record, 'Record');
  const headers = ['id', 'tenant', 'owner', 'model', 'createdAt', 'data'];
  if (Object.keys(record).length !== headers.length || headers.some(key => !own(record, key))) fail('Invalid record headers', 'INVALID_RECORD');
  for (const key of ['id', 'tenant', 'owner', 'model']) decodeDomain('id', record[key]);
  decodeDomain('integer', record.createdAt);
  const model = own(prepared.models, record.model) && prepared.models[record.model]; if (!model) fail('Unknown model', 'INVALID_RECORD');
  if (!model.validate(record.data)) fail(`Invalid record data: ${JSON.stringify(model.validate.errors)}`, 'INVALID_RECORD');
  return cloneData(record);
}

export function projectRecord(prepared, input) {
  const record = validateRecord(prepared, input), result = [];
  for (const membership of prepared.models[record.model].memberships) {
    const contract = prepared.views[membership.view].contract;
    let missing = false;
    const read = (selector, expected) => { const selected = selectValue(record, selector); if (!selected.present) { missing = true; return undefined; } return decodeDomain(expected, selected.value); };
    const partition = membership.partition.map((selector, index) => read(selector, contract.partition[index]));
    const order = read(membership.order, contract.order), inputs = Object.create(null);
    for (const [key, expected] of Object.entries(contract.inputs)) inputs[key] = read(membership.inputs[key], expected);
    if (missing) { if (membership.onMissing === 'skip') continue; fail(`Missing projection value in ${membership.slot}`, 'MISSING_PROJECTION'); }
    const contributions = Object.create(null);
    for (const [key, aggregate] of Object.entries(contract.aggregates)) contributions[key] = aggregate.implementation.lift(inputs[aggregate.input]);
    result.push({ tenant: record.tenant, sourceId: record.id, view: membership.view, slot: membership.slot, partition, order, inputs, contributions });
  }
  return result;
}
