import test from 'node:test';
import assert from 'node:assert/strict';
import { prepareCatalog, projectRecord } from '../src/catalog.mjs';
import { createMemoryStore } from '../src/memory.mjs';
import { mutate } from '../src/mutate.mjs';
import { sourceKey, incomingPrefix, claimKey, catalogKey, nodeKey, occurrenceToken } from '../src/keys.mjs';
import { readRoot } from '../src/tree.mjs';
import { activityDefinition, activityRecords } from '../examples/activity.mjs';
const put = record => ({ type: 'put', record });
const del = id => ({ type: 'delete', id });
const snapshot = store => store.read(tx => tx.scan());
const setup = async (definition = activityDefinition, options) => {
  const catalog = prepareCatalog(definition, options), store = createMemoryStore(), records = activityRecords();
  await mutate(store, catalog, 'tenant', records.map(put));
  return { catalog, store, records };
};

test('activity final graph supports forward references and three independent views', async () => {
  const catalog = prepareCatalog(activityDefinition), store = createMemoryStore(), records = activityRecords();
  const result = await mutate(store, catalog, 'tenant', records.toReversed().map(put));
  assert.equal(result.changedSources, 4); assert.equal(result.changedMemberships, 9);
  assert.equal(result.trees.length, 5);
  await store.read(async tx => {
    const root = await readRoot(tx, catalog, { tenant: 'tenant', view: 'resourceEffective', partition: ['resource'] });
    assert.equal(root.size, 3); assert.equal(root.aggregates.total, 8n);
    assert.equal((await tx.scan({ prefix: incomingPrefix(catalog, 'tenant', 'resource') })).length, 3);
  });
});

test('no-op retains guards but produces no staged or physical writes', async () => {
  const { catalog, store, records } = await setup(); let writes;
  const result = await mutate(store, catalog, 'tenant', records.map(put), { beforeCommit: ({ changes }) => { writes = changes; } });
  assert.equal(result.changedSources, 0); assert.equal(result.changedMemberships, 0);
  assert.equal(result.metrics.metrics.stagedWrites, 0); assert.deepEqual(writes, []);
  assert.ok(result.metrics.guards.length > 0);
});

test('claims swap in either command order and duplicate final claims roll back', async () => {
  for (const reverse of [false, true]) {
    const { catalog, store, records } = await setup();
    const a = structuredClone(records[1]), b = structuredClone(records[2]);
    [a.data.label, b.data.label] = [b.data.label, a.data.label];
    await mutate(store, catalog, 'tenant', (reverse ? [b, a] : [a, b]).map(put));
    assert.equal((await store.read(tx => tx.get(claimKey(catalog, 'tenant', 'movement', 'label', ['resource', 'use'])))).sourceId, 'add');
    const before = await snapshot(store); b.data.label = a.data.label;
    await assert.rejects(mutate(store, catalog, 'tenant', [put(b)]), { code: 'DUPLICATE_CLAIM' });
    assert.deepEqual(await snapshot(store), before);
  }
});

test('delete restriction and joint deletes use final outgoing references', async () => {
  const { catalog, store, records } = await setup(); const before = await snapshot(store);
  await assert.rejects(mutate(store, catalog, 'tenant', [del('resource')]), { code: 'DELETE_RESTRICTED' });
  assert.deepEqual(await snapshot(store), before);
  await mutate(store, catalog, 'tenant', records.map(r => del(r.id)));
  assert.deepEqual(await snapshot(store), [{ key: catalogKey('tenant'), value: catalog.identity }]);
});

test('trusted owner transfer and parent retarget reconcile source references and scopes', async () => {
  const { catalog, store, records } = await setup();
  const resource = { ...records[0], id: 'second' }, movement = structuredClone(records[1]);
  movement.owner = 'new-owner'; movement.data.resource = 'second';
  await mutate(store, catalog, 'tenant', [put(movement), put(resource)]);
  await store.read(async tx => {
    assert.deepEqual(await tx.get(sourceKey('tenant', 'add')), movement);
    assert.equal((await tx.scan({ prefix: incomingPrefix(catalog, 'tenant', 'second') }))[0].value.sourceId, 'add');
    assert.equal((await tx.scan({ prefix: incomingPrefix(catalog, 'tenant', 'resource') })).length, 2);
    assert.equal(await readRoot(tx, catalog, { tenant: 'tenant', view: 'ownerEffective', partition: ['resource', 'team'] }).then(r => r.aggregates.total), -4n);
  });
});

test('duplicate commands, namespace, unknown commands and immutable headers reject atomically', async () => {
  const { catalog, store, records } = await setup(), before = await snapshot(store);
  for (const changes of [[put(records[1]), del('add')], [{ type: 'other' }], [put({ ...records[1], tenant: 'elsewhere' })], [put({ ...records[1], model: 'correction', data: { resource: 'resource', effective: '1', delta: '10', label: 'add' } })], [put({ ...records[1], createdAt: '9' })]]) {
    await assert.rejects(mutate(store, catalog, 'tenant', changes));
    assert.deepEqual(await snapshot(store), before);
  }
});

test('multiple memberships in the same view retain separate slots', async () => {
  const definition = structuredClone(activityDefinition);
  definition.models.movement.memberships.push({ ...structuredClone(definition.models.movement.memberships[0]), slot: 'repeat' });
  const { catalog, store, records } = await setup(definition);
  await store.read(async tx => {
    const root = await readRoot(tx, catalog, { tenant: 'tenant', view: 'resourceEffective', partition: ['resource'] });
    assert.equal(root.size, 5); assert.equal(root.aggregates.total, 14n);
  });
  await mutate(store, catalog, 'tenant', [del(records[1].id)]);
  const root = await store.read(tx => readRoot(tx, catalog, { tenant: 'tenant', view: 'resourceEffective', partition: ['resource'] }));
  assert.equal(root.size, 3); assert.equal(root.aggregates.total, -6n);
});

test('root total can pass while ordered running-prefix validator rejects, with full rollback', async () => {
  const definition = structuredClone(activityDefinition);
  definition.contracts.resource.validators = [{ scope: 'root', use: 'total' }, { scope: 'allPrefixes', use: 'prefix' }];
  let calls = 0;
  const options = { validators: {
    total: { version: '1', validate: aggregates => { calls++; return aggregates.total >= 0n; } },
    prefix: { version: '1', validate: aggregates => { calls++; return aggregates.prefix.minPrefix >= 0n; } },
  } };
  const { catalog, store, records } = await setup(definition, options), before = await snapshot(store);
  const use = structuredClone(records[2]); use.data.effective = '0';
  await assert.rejects(mutate(store, catalog, 'tenant', [put(use)]), { code: 'VALIDATION_FAILED' });
  assert.deepEqual(await snapshot(store), before); assert.equal(calls, 4);
});

test('commit fault discards sources, claims, references and tree changes', async () => {
  const { catalog, store, records } = await setup(), before = await snapshot(store);
  const edited = structuredClone(records[1]); edited.data.units = '100';
  await assert.rejects(mutate(store, catalog, 'tenant', [put(edited)], { beforeCommit: () => { throw new Error('fault'); } }), /fault/);
  assert.deepEqual(await snapshot(store), before);
});

test('missing old claim or incoming reference rejects corruption even for no-op', async () => {
  for (const kind of ['claim', 'reference']) {
    const { catalog, store, records } = await setup();
    await store.transact(async tx => {
      const key = kind === 'claim' ? claimKey(catalog, 'tenant', 'movement', 'label', ['resource', 'add']) : (await tx.scan({ prefix: incomingPrefix(catalog, 'tenant', 'resource') })).find(row => row.value.sourceId === 'add').key;
      await tx.delete(key);
    });
    const before = await snapshot(store);
    await assert.rejects(mutate(store, catalog, 'tenant', [put(records[1])]), { code: 'CORRUPT_STATE' });
    assert.deepEqual(await snapshot(store), before);
  }
});

test('array and polymorphic references preserve positions and allow final joint deletion', async () => {
  const definition = structuredClone(activityDefinition);
  definition.models.bundle = {
    schema: { type: 'object', additionalProperties: false, properties: { links: { type: 'array', items: { type: 'string' } } }, required: ['links'] },
    references: [{ slot: 'links', field: 'links', targets: ['resource', 'movement'], many: true, onDelete: 'reject' }],
  };
  const { catalog, store, records } = await setup(definition);
  const bundle = { ...records[0], id: 'bundle', model: 'bundle', data: { links: ['resource', 'add', 'add'] } };
  await mutate(store, catalog, 'tenant', [put(bundle)]);
  const refs = await store.read(tx => tx.scan({ prefix: incomingPrefix(catalog, 'tenant', 'add') }));
  assert.deepEqual(refs.map(row => row.value.position).sort(), [1, 2]);
  await assert.rejects(mutate(store, catalog, 'tenant', [del('add')]), { code: 'DELETE_RESTRICTED' });
  await mutate(store, catalog, 'tenant', [del('add'), del('bundle')]);
  bundle.data.links = ['absent'];
  await assert.rejects(mutate(store, catalog, 'tenant', [put(bundle)]), { code: 'INVALID_REFERENCE' });
});

test('catalog identity mismatch and asynchronous summary validators reject without publication', async () => {
  const { store, records } = await setup(); const before = await snapshot(store);
  const definition = structuredClone(activityDefinition); definition.version = 'different';
  await assert.rejects(mutate(store, prepareCatalog(definition), 'tenant', []), { code: 'CATALOG_MISMATCH' });
  assert.deepEqual(await snapshot(store), before);
  definition.contracts.resource.validators = [{ scope: 'root', use: 'async' }];
  const catalog = prepareCatalog(definition, { validators: { async: { version: '1', validate: async () => true } } });
  const empty = createMemoryStore();
  await assert.rejects(mutate(empty, catalog, 'tenant', records.map(put)), { code: 'VALIDATION_FAILED' });
  assert.deepEqual(await snapshot(empty), []);
});


test('missing unchanged membership is corruption rather than a silent no-op', async () => {
  const { catalog, store, records } = await setup();
  const occurrence = projectRecord(catalog, records[1])[0];
  await store.transact(tx => tx.delete(nodeKey(catalog, occurrence, occurrenceToken(occurrence))));
  const before = await snapshot(store);
  await assert.rejects(mutate(store, catalog, 'tenant', [put(records[1])]), { code: 'CORRUPT_STATE' });
  assert.deepEqual(await snapshot(store), before);
});

test('persisted false or null source is rejected rather than replaced as absent', async () => {
  for (const corrupt of [null, false]) {
    const { catalog, store, records } = await setup();
    await store.transact(tx => tx.set(sourceKey('tenant', 'add'), corrupt));
    const before = await snapshot(store);
    await assert.rejects(mutate(store, catalog, 'tenant', [put(records[1])]));
    assert.deepEqual(await snapshot(store), before);
  }
});

test('contribution-only edit upserts membership without changing tree topology', async () => {
  const { catalog, store, records } = await setup();
  const before = await snapshot(store), edited = structuredClone(records[1]);
  edited.data.units = '20';
  let physical;
  const result = await mutate(store, catalog, 'tenant', [put(edited)], { beforeCommit: ({ changes }) => { physical = changes; } });
  assert.equal(result.changedSources, 1); assert.equal(result.changedMemberships, 3);
  assert.equal(physical.filter(change => change.type === 'delete').length, 0);
  const after = new Map((await snapshot(store)).map(row => [row.key, row.value]));
  for (const { key, value } of before) {
    if (value && typeof value === 'object' && Object.hasOwn(value, 'left')) {
      const updated = after.get(key);
      for (const field of ['left', 'right', 'size', 'height', 'sourceId', 'slot', 'order']) assert.deepEqual(updated[field], value[field]);
    }
  }
  const root = await store.read(tx => readRoot(tx, catalog, { tenant: 'tenant', view: 'resourceEffective', partition: ['resource'] }));
  assert.equal(root.aggregates.total, 18n);
});
