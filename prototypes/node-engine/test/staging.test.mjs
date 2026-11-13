import test from 'node:test';
import assert from 'node:assert/strict';
import { prepareCatalog } from '../src/catalog.mjs';
import { createMemoryStore } from '../src/memory.mjs';
import { createMutation, mutate } from '../src/mutate.mjs';
import { sourceKey } from '../src/keys.mjs';
import { checkStore } from '../src/check.mjs';
import { readRoot } from '../src/tree.mjs';
import { activityDefinition, activityRecords } from '../examples/activity.mjs';
const put = record => ({ type: 'put', record });
const snapshot = store => store.read(tx => tx.scan());
async function setup(definition = activityDefinition, options) {
  const catalog = prepareCatalog(definition, options), store = createMemoryStore(), records = activityRecords();
  await mutate(store, catalog, 'tenant', records.map(put));
  return { catalog, store, records };
}

test('stage sources and trees in overlay and resolve forward references only at finish', async () => {
  const catalog = prepareCatalog(activityDefinition), store = createMemoryStore(), records = activityRecords();
  await store.transact(async tx => {
    const mutation = await createMutation(tx, catalog, 'tenant');
    await mutation.stage(records.slice(1).map(put));
    assert.deepEqual(await tx.get(sourceKey('tenant', 'add')), records[1]);
    assert.equal((await readRoot(tx, catalog, { tenant: 'tenant', view: 'resourceEffective', partition: ['resource'] })).size, 3);
    await mutation.stage([put(records[0])]);
    assert.equal((await mutation.finish()).changedSources, 4);
  });
  assert.deepEqual(await checkStore(store, catalog, 'tenant'), { sources: 4, trees: 5, occurrences: 9, references: 3, claims: 3 });
});

test('cross-stage uniqueness swaps release first-old claims before final acquisitions', async () => {
  const { catalog, store, records } = await setup();
  const a = structuredClone(records[1]), b = structuredClone(records[2]);
  [a.data.label, b.data.label] = [b.data.label, a.data.label];
  await store.transact(async tx => {
    const mutation = await createMutation(tx, catalog, 'tenant');
    await mutation.stage([put(a)]); await mutation.stage([put(b)]);
    assert.equal((await mutation.finish()).changedSources, 2);
  });
  await checkStore(store, catalog, 'tenant');
});

test('temporarily invalid ordered balances can be jointly repaired by later stages', async () => {
  const definition = structuredClone(activityDefinition);
  definition.contracts.resource.validators = [{ scope: 'allPrefixes', use: 'prefix' }];
  const { catalog, store, records } = await setup(definition, { validators: { prefix: { version: '1', validate: a => a.prefix.minPrefix >= 0n } } });
  const use = structuredClone(records[2]), add = structuredClone(records[1]);
  use.data.effective = '0'; add.data.effective = '-1';
  await store.transact(async tx => {
    const mutation = await createMutation(tx, catalog, 'tenant');
    await mutation.stage([put(use)]);
    await mutation.stage([put(add)]);
    await mutation.finish();
  });
  await checkStore(store, catalog, 'tenant');
});

test('failed stage or finish poisons workspace and propagated errors roll back all work', async () => {
  for (const boundary of ['stage', 'finish']) {
    const { catalog, store, records } = await setup(), before = await snapshot(store);
    await assert.rejects(store.transact(async tx => {
      const mutation = await createMutation(tx, catalog, 'tenant');
      const edited = structuredClone(records[1]); edited.data.units = '30';
      await mutation.stage([put(edited)]);
      if (boundary === 'stage') await assert.rejects(mutation.stage([{ type: 'unknown' }]), { code: 'INVALID_MUTATION' });
      else {
        edited.data.resource = 'absent'; await mutation.stage([put(edited)]);
        await assert.rejects(mutation.finish(), { code: 'INVALID_REFERENCE' });
      }
      await assert.rejects(mutation.stage([]), { code: 'MUTATION_CLOSED' });
      await mutation.finish();
    }), { code: 'MUTATION_CLOSED' });
    assert.deepEqual(await snapshot(store), before);
    await checkStore(store, catalog, 'tenant');
  }
});

test('reverted staged edits preserve exact snapshot and report zero final changes', async () => {
  const { catalog, store, records } = await setup(), before = await snapshot(store);
  let physical;
  const result = await store.transact(async tx => {
    const mutation = await createMutation(tx, catalog, 'tenant');
    const edited = structuredClone(records[1]); edited.data.units = '100'; edited.data.label = 'temporary';
    await mutation.stage([put(edited)]); await mutation.stage([put(records[1])]);
    return mutation.finish();
  }, { beforeCommit: ({ changes }) => { physical = changes; } });
  assert.equal(result.changedSources, 0); assert.equal(result.changedMemberships, 0);
  assert.deepEqual(physical, []); assert.deepEqual(await snapshot(store), before);
  await checkStore(store, catalog, 'tenant');
});

test('finished workspace rejects another finish or stage and preserves immutable first-old headers', async () => {
  const { catalog, store, records } = await setup();
  await store.transact(async tx => {
    const mutation = await createMutation(tx, catalog, 'tenant');
    await mutation.stage([]); await mutation.finish();
    await assert.rejects(mutation.finish(), { code: 'MUTATION_CLOSED' });
    await assert.rejects(mutation.stage([]), { code: 'MUTATION_CLOSED' });
  });
  await assert.rejects(store.transact(async tx => {
    const mutation = await createMutation(tx, catalog, 'tenant');
    await mutation.stage([{ type: 'delete', id: 'add' }]);
    await mutation.stage([put({ ...records[1], createdAt: '999' })]);
  }), { code: 'IMMUTABLE_HEADER' });
  await checkStore(store, catalog, 'tenant');
});


test('new-source immutable headers survive creation deletion and recreation within an attempt', async () => {
  const { catalog, store, records } = await setup(), before = await snapshot(store);
  const created = { ...records[0], id: 'new-resource' };
  await assert.rejects(store.transact(async tx => {
    const mutation = await createMutation(tx, catalog, 'tenant');
    await mutation.stage([put(created)]);
    await mutation.stage([{ type: 'delete', id: created.id }]);
    await mutation.stage([put({ ...created, createdAt: '99' })]);
  }), { code: 'IMMUTABLE_HEADER' });
  assert.deepEqual(await snapshot(store), before);
  await checkStore(store, catalog, 'tenant');
});

test('staged joint deletion and retargeting enforce only final incoming references', async () => {
  const { catalog, store, records } = await setup();
  const second = { ...records[0], id: 'second-resource' };
  const retargeted = structuredClone(records[1]); retargeted.data.resource = second.id;
  await store.transact(async tx => {
    const mutation = await createMutation(tx, catalog, 'tenant');
    await mutation.stage([{ type: 'delete', id: 'resource' }]);
    await mutation.stage([put(retargeted)]);
    await mutation.stage([{ type: 'delete', id: 'use' }, { type: 'delete', id: 'fix' }]);
    await mutation.stage([put(second)]);
    await mutation.finish();
  });
  assert.deepEqual(await checkStore(store, catalog, 'tenant'), { sources: 2, trees: 3, occurrences: 3, references: 1, claims: 1 });
});

test('final validation excludes transient-only scopes but validates emptied original scopes', async () => {
  const definition = structuredClone(activityDefinition);
  definition.contracts.owner.validators = [{ scope: 'root', use: 'positive' }];
  const { catalog, store, records } = await setup(definition, { validators: { positive: { version: '1', validate: a => a.total > 0n } } });
  const before = await snapshot(store), temporary = { ...records[3], owner: 'temporary-owner' };
  const result = await store.transact(async tx => {
    const mutation = await createMutation(tx, catalog, 'tenant');
    await mutation.stage([put(temporary)]);
    await mutation.stage([put(records[3])]);
    return mutation.finish();
  });
  assert.equal(result.changedSources, 0);
  assert.equal(result.changedMemberships, 0);
  assert.deepEqual(result.trees, []);
  assert.deepEqual(await snapshot(store), before);
  await checkStore(store, catalog, 'tenant');
  await assert.rejects(store.transact(async tx => {
    const mutation = await createMutation(tx, catalog, 'tenant');
    await mutation.stage([put(temporary)]);
    await mutation.finish();
  }), { code: 'VALIDATION_FAILED' });
  assert.deepEqual(await snapshot(store), before);
  await checkStore(store, catalog, 'tenant');
});
