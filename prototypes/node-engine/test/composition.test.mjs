import test from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryStore, prepareCatalog, projectRecord, sourceOracle } from '../src/index.mjs';
import { activityDefinition, activityRecords } from '../examples/activity.mjs';

test('prepared views, source oracle and transaction overlay compose with forward references', async () => {
  const catalog = prepareCatalog(activityDefinition), store = createMemoryStore();
  const records = activityRecords(), expected = sourceOracle(catalog, records);
  const result = await store.transact(async tx => {
    for (const record of [...records].reverse()) await tx.set(`source/${record.id}`, record);
    // Deliberate full-source oracle in a test, not a proposed mutation scan.
    return sourceOracle(catalog, (await tx.scan({ prefix: 'source/' })).map(row => row.value));
  });
  assert.deepEqual(result, expected);
  assert.equal(result.trees.reduce((count, tree) => count + tree.count, 0), 9);
  assert.equal(records.reduce((count, record) => count + projectRecord(catalog, record).length, 0), 9);
  const effective = result.trees.find(tree => tree.view === 'ownerEffective' && tree.partition[1] === 'team');
  const created = result.trees.find(tree => tree.view === 'ownerCreated' && tree.partition[1] === 'team');
  assert.deepEqual(effective.aggregates.prefix, { sum: 6n, minPrefix: 0n });
  assert.deepEqual(created.aggregates.prefix, { sum: 6n, minPrefix: -4n });
  const baseline = await store.read(tx => tx.scan());
  for (const fault of ['duplicate', 'dangling', 'commit']) {
    await assert.rejects(store.transact(async tx => {
      if (fault === 'dangling') await tx.delete('source/resource');
      else if (fault === 'duplicate') await tx.set('source/duplicate', { ...records[1], id: 'duplicate' });
      else await tx.set('source/add', { ...records[1], data: { ...records[1].data, units: '9007199254740993' } });
      sourceOracle(catalog, (await tx.scan({ prefix: 'source/' })).map(row => row.value));
    }, { beforeCommit: () => { if (fault === 'commit') throw new Error('injected failure'); } }));
    assert.deepEqual(await store.read(tx => tx.scan()), baseline);
  }
});

test('ambiguous missing values and mistyped scan options are rejected without publication', async () => {
  const store = createMemoryStore();
  await assert.rejects(store.transact(tx => tx.set('missing', undefined)), { code: 'INVALID_VALUE' });
  await assert.rejects(store.read(tx => tx.scan({ prefex: 'private/' })), { code: 'INVALID_RANGE' });
  assert.deepEqual(await store.read(tx => tx.scan()), []);
});
