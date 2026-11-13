// A reusable model fixture, imported as ordinary data/functions; no work on import.
const integer = { type: 'string', pattern: '^(0|-?[1-9][0-9]*)$' };
const field = name => ({ field: name });
const aggregate = { total: { monoid: 'sum', input: 'delta' }, prefix: { monoid: 'prefix', input: 'delta' } };
const membership = (slot, view, partition, order, delta) => ({ slot, view, partition, order, inputs: { delta: field(delta) }, onMissing: 'reject' });
function movement(delta) {
  return {
    schema: {
      type: 'object', additionalProperties: false,
      properties: { resource: { type: 'string' }, effective: integer, [delta]: integer, label: { type: 'string' } },
      required: ['resource', 'effective', delta, 'label'],
    },
    references: [{ slot: 'resource', field: 'resource', targets: ['resource'], many: false, onDelete: 'reject' }],
    uniqueness: [{ slot: 'label', fields: [field('resource'), field('label')] }],
    memberships: [
      membership('resource', 'resourceEffective', [field('resource')], field('effective'), delta),
      membership('owner', 'ownerEffective', [field('resource'), { header: 'owner' }], field('effective'), delta),
      membership('created', 'ownerCreated', [field('resource'), { header: 'owner' }], { header: 'createdAt' }, delta),
    ],
  };
}
export const activityDefinition = {
  name: 'activity', version: '1',
  contracts: {
    resource: { version: '1', partition: ['id'], order: 'integer', inputs: { delta: 'integer' }, aggregates: aggregate },
    owner: { version: '1', partition: ['id', 'id'], order: 'integer', inputs: { delta: 'integer' }, aggregates: aggregate },
  },
  views: { resourceEffective: { contract: 'resource' }, ownerEffective: { contract: 'owner' }, ownerCreated: { contract: 'owner' } },
  models: {
    resource: { schema: { type: 'object', additionalProperties: false, properties: { name: { type: 'string' } }, required: ['name'] } },
    movement: movement('units'),
    correction: movement('delta'),
  },
};

export function activityRecords() {
  const record = (id, model, createdAt, data, owner = 'team') => ({ id, tenant: 'tenant', owner, model, createdAt, data });
  return [
    record('resource', 'resource', '0', { name: 'Shared capacity' }),
    record('add', 'movement', '2', { resource: 'resource', effective: '1', units: '10', label: 'add' }),
    record('use', 'movement', '1', { resource: 'resource', effective: '2', units: '-4', label: 'use' }),
    record('fix', 'correction', '3', { resource: 'resource', effective: '3', delta: '2', label: 'fix' }, 'other-team'),
  ];
}
