import test from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryStore, prepareCatalog, sourceOracle, mutate, checkStore, canonical } from '../src/index.mjs';
import { activityDefinition, activityRecords } from '../examples/activity.mjs';
import { catalogKey, sourceKey, rootKey, nodeKey, occurrenceToken, allIncomingPrefix, allClaimsPrefix } from '../src/keys.mjs';

const put = record => ({ type: 'put', record });
const snapshot = store => store.read(tx => tx.scan());
async function fixture() {
  const catalog = prepareCatalog(activityDefinition), store = createMemoryStore(), records = activityRecords();
  await mutate(store, catalog, 'tenant', records.map(put));
  return { catalog, store, records };
}

test('complete checker accepts two schemas, three views, transfers and separate tenants', async () => {
  const { catalog, store, records } = await fixture();
  assert.deepEqual(await checkStore(store, catalog, 'tenant'), { sources: 4, trees: 5, occurrences: 9, references: 3, claims: 3 });
  await mutate(store, catalog, 'tenant', [put({ ...records[1], owner: 'other-team', data: { ...records[1].data, effective: '9' } })]);
  await checkStore(store, catalog, 'tenant');
  await mutate(store, catalog, 'second', records.map(record => put({ ...record, tenant: 'second' })));
  assert.equal((await checkStore(store, catalog, 'second')).occurrences, 9);
  await mutate(store, catalog, 'tenant', records.map(record => ({ type: 'delete', id: record.id })));
  assert.deepEqual(await checkStore(store, catalog, 'tenant'), { sources: 0, trees: 0, occurrences: 0, references: 0, claims: 0 });
  assert.equal((await checkStore(store, catalog, 'second')).sources, 4);
});

test('independent inventory rejects forged summaries, missing tables and orphaned nodes', async () => {
  const corruptions = [
    async (tx, catalog, tree, member) => { const key = nodeKey(catalog, tree, occurrenceToken(member)); const node = await tx.get(key); node.size++; await tx.set(key, node); },
    async (tx, catalog, tree, member) => { const key = nodeKey(catalog, tree, occurrenceToken(member)); const node = await tx.get(key); node.aggregates.total += 1n; await tx.set(key, node); },
    async (tx, catalog, tree, member) => { const key = nodeKey(catalog, tree, occurrenceToken(member)); const node = await tx.get(key); node.contributions.total += 1n; await tx.set(key, node); },
    async (tx, catalog, tree) => { await tx.delete(rootKey(catalog, tree)); },
    async (tx, catalog, tree, member) => { const node = await tx.get(nodeKey(catalog, tree, occurrenceToken(member))); await tx.set(nodeKey(catalog, tree, 'orphan'), node); },
    async (tx, catalog) => { const [{ key }] = await tx.scan({ prefix: allIncomingPrefix(catalog, 'tenant') }); await tx.delete(key); },
    async (tx, catalog) => { const [{ key }] = await tx.scan({ prefix: allClaimsPrefix(catalog, 'tenant') }); await tx.delete(key); },
    async tx => { const key = sourceKey('tenant', 'add'), source = await tx.get(key); source.data.units = '900'; await tx.set(key, source); },
    async (tx, catalog, tree, member) => { const key = nodeKey(catalog, tree, occurrenceToken(member)); const node = await tx.get(key); node.left = occurrenceToken(member); await tx.set(key, node); },
    async tx => { await tx.delete(catalogKey('tenant')); },
  ];
  for (const corrupt of corruptions) {
    const { catalog, store, records } = await fixture();
    const tree = sourceOracle(catalog, records).trees.find(tree => tree.view === 'resourceEffective');
    await store.transact(tx => corrupt(tx, catalog, tree, tree.members[0]));
    await assert.rejects(checkStore(store, catalog, 'tenant'));
  }
});

test('mixed incremental commands agree with flat final-state validation and preserve rejected state', async () => {
  const definition = structuredClone(activityDefinition);
  definition.contracts.resource.validators = [{ scope: 'allPrefixes', use: 'nonnegative' }];
  const catalog = prepareCatalog(definition, { validators: { nonnegative: { version: '1', validate: aggregate => aggregate.prefix.minPrefix >= 0n } } });
  const store = createMemoryStore();
  const seed = activityRecords();
  const secondResource = { ...seed[0], id: 'resource2', data: { name: 'Second capacity' } };
  let sources = new Map([...seed, secondResource].map(record => [record.id, record]));
  await mutate(store, catalog, 'tenant', [...sources.values()].map(put));
  let state = 167; const random = n => ((state = (Math.imul(state, 1664525) + 1013904223) >>> 0) % n);
  let rejected = 0;
  for (let step = 0; step < 120; step++) {
    const existing = [...sources.values()].filter(record => record.model !== 'resource');
    let command;
    if (!existing.length || random(3) === 0) {
      const id = `new-${step}`;
      command = put({ id, tenant: 'tenant', owner: `owner-${random(3)}`, model: 'movement', createdAt: String(step + 10), data: { resource: random(2) ? 'resource' : 'resource2', effective: String(random(25)), units: String(random(15) - 5), label: id } });
    } else {
      const chosen = existing[random(existing.length)];
      command = random(4) === 0 ? { type: 'delete', id: chosen.id } : put({ ...chosen, owner: `owner-${random(3)}`, data: { ...chosen.data, resource: random(2) ? 'resource' : 'resource2', effective: String(random(25)), [chosen.model === 'movement' ? 'units' : 'delta']: String(random(15) - 5) } });
    }
    const candidate = new Map(sources);
    if (command.type === 'put') candidate.set(command.record.id, command.record); else candidate.delete(command.id);
    const expected = sourceOracle(catalog, [...candidate.values()]);
    const valid = expected.trees.filter(tree => tree.view === 'resourceEffective').every(tree => tree.aggregates.prefix.minPrefix >= 0n);
    const before = await snapshot(store);
    if (valid) { await mutate(store, catalog, 'tenant', [command]); sources = candidate; }
    else { await assert.rejects(mutate(store, catalog, 'tenant', [command]), { code: 'VALIDATION_FAILED' }); assert.equal(canonical(await snapshot(store)), canonical(before)); rejected++; }
    const checked = await checkStore(store, catalog, 'tenant');
    assert.equal(checked.sources, sources.size);
    assert.equal(checked.occurrences, (sources.size - 2) * 3);
  }
  assert.ok(rejected > 0);
});

test('fault after full settlement preserves all source, root, node, reference and claim inventories', async () => {
  const { catalog, store, records } = await fixture();
  await mutate(store, catalog, 'tenant', [put({ ...records[0], id: 'resource2' })]);
  const before = await snapshot(store);
  const update = { ...records[1], owner: 'transferred', data: { ...records[1].data, resource: 'resource2', units: '80', effective: '-9', label: 'changed' } };
  await assert.rejects(mutate(store, catalog, 'tenant', [put(update)], { beforeCommit: ({ changes }) => {
    for (const prefix of ['source/', 'root/', 'node/', 'incoming/', 'claim/']) assert.ok(changes.some(change => change.key.startsWith(prefix)), `missing ${prefix}`);
    throw new Error('injected publication failure');
  } }), { message: 'injected publication failure' });
  assert.equal(canonical(await snapshot(store)), canonical(before));
  await checkStore(store, catalog, 'tenant');
});

test('writer and independent checker supply the same bounded validator context', async () => {
  const definition = structuredClone(activityDefinition);
  definition.contracts.resource.validators = [{ scope: 'root', use: 'scopeShape' }];
  const catalog = prepareCatalog(definition, { validators: { scopeShape: { version: '1', validate: (_, { scope }) => canonical(Object.keys(scope).sort()) === canonical(['partition', 'tenant', 'view']) } } });
  const store = createMemoryStore();
  await mutate(store, catalog, 'tenant', activityRecords().map(put));
  await checkStore(store, catalog, 'tenant');
});

test('no-op membership checks resolve the root path rather than accept orphan node data', async () => {
  const { catalog, store, records } = await fixture();
  const tree = sourceOracle(catalog, records).trees.find(tree => tree.view === 'resourceEffective');
  await store.transact(tx => tx.delete(rootKey(catalog, tree)));
  const before = await snapshot(store);
  await assert.rejects(mutate(store, catalog, 'tenant', [put(records[1])]), { code: 'CORRUPT_STATE' });
  assert.equal(canonical(await snapshot(store)), canonical(before));
});
