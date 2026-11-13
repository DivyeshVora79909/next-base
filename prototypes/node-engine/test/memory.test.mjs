import test from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryStore } from '../src/memory.mjs';

const seed = store => store.transact(async tx => {
  await tx.set('a', { n: 1n }); await tx.set('b', { n: 2n });
});

test('callback and commit-hook failures publish no partial changes and queue progresses', async () => {
  const store = createMemoryStore(); await seed(store);
  for (const failure of ['callback', 'hook']) {
    await assert.rejects(store.transact(async tx => {
      await tx.set('a', 99); await tx.delete('b'); await tx.set('c', 3);
      if (failure === 'callback') throw Error('abort');
    }, { beforeCommit: async ({ changes }) => {
      assert.equal(changes.length, 3); changes[0].value = 500;
      await Promise.resolve(); throw Error('abort');
    } }), /abort/);
    assert.deepEqual(await store.read(tx => tx.scan()), [{ key: 'a', value: { n: 1n } }, { key: 'b', value: { n: 2n } }]);
  }
  await store.transact(tx => tx.set('c', 3));
  assert.equal(await store.read(tx => tx.get('c')), 3);
});

test('overlay reads, batch snapshots, deletes, absence and no-op guards', async () => {
  const store = createMemoryStore(); await seed(store);
  let changes;
  await store.transact(async tx => {
    await tx.set('a', { n: 1n }); await tx.delete('missing');
    assert.equal(await tx.get('missing'), undefined);
    assert.deepEqual(await tx.scan({ gte: 'x', lt: 'z' }), []);
    const inspected = tx.inspect();
    assert.ok(inspected.guards.some(g => g.key === 'a' && g.exists));
    assert.ok(inspected.guards.some(g => g.key === 'missing' && !g.exists));
    assert.ok(inspected.guards.some(g => g.type === 'range' && g.gte === 'x'));
    inspected.guards.length = 0;
    assert.equal(tx.inspect().guards.length, 3);
  }, { beforeCommit: data => { changes = data.changes; } });
  assert.deepEqual(changes, []);
  await store.transact(async tx => {
    await tx.set('a', 7); await tx.delete('b'); await tx.set('c', 9);
    assert.deepEqual(await tx.getMany(['a', 'b', 'c', 'absent']), [7, undefined, 9, undefined]);
    assert.deepEqual(await tx.scan(), [{ key: 'a', value: 7 }, { key: 'c', value: 9 }]);
  });
});

test('read and write callbacks serialize across awaits on a coherent snapshot', async () => {
  const store = createMemoryStore(); await seed(store);
  let release, entered;
  const blocked = new Promise(resolve => { release = resolve; });
  const started = new Promise(resolve => { entered = resolve; });
  const order = [];
  const reader = store.read(async tx => {
    order.push('reader'); entered();
    assert.deepEqual(await tx.getMany(['a', 'b']), [{ n: 1n }, { n: 2n }]);
    await blocked;
    assert.deepEqual(await tx.getMany(['a', 'b']), [{ n: 1n }, { n: 2n }]);
  });
  await started;
  const writer = store.transact(async tx => { order.push('writer'); await tx.set('a', 10); });
  await Promise.resolve(); assert.deepEqual(order, ['reader']);
  release(); await Promise.all([reader, writer]);
  assert.deepEqual(order, ['reader', 'writer']);
  assert.equal(await store.read(tx => tx.get('a')), 10);
});

test('values and hook data are detached and noncloneable values fail before publication', async () => {
  const store = createMemoryStore(); const source = { deep: [1n] };
  await store.transact(async tx => {
    await tx.set('a', source); source.deep.push(2n);
    const read = await tx.get('a'); read.deep.push(3n);
    const rows = await tx.scan(); rows[0].value.deep.push(4n);
  }, { beforeCommit: ({ changes }) => { changes[0].value.deep.push(5n); } });
  assert.deepEqual(await store.read(tx => tx.get('a')), { deep: [1n] });
  await assert.rejects(store.transact(async tx => { await tx.set('b', 1); await tx.set('c', () => {}); }));
  assert.equal(await store.read(tx => tx.get('b')), undefined);
});

test('closed transactions, read-only writes and nested same-store work reject', async () => {
  const store = createMemoryStore(); let saved;
  await store.transact(tx => { saved = tx; });
  for (const call of [() => saved.get('a'), () => saved.getMany([]), () => saved.set('a', 1), () => saved.delete('a'), () => saved.scan()]) {
    await assert.rejects(call(), { code: 'TRANSACTION_CLOSED' });
  }
  assert.throws(() => saved.inspect(), { code: 'TRANSACTION_CLOSED' });
  await store.read(async tx => {
    await assert.rejects(tx.set('a', 1), { code: 'READ_ONLY' });
    await assert.rejects(tx.delete('a'), { code: 'READ_ONLY' });
    await assert.rejects(store.transact(() => {}), { code: 'NESTED_TRANSACTION' });
    await assert.rejects(store.read(() => {}), { code: 'NESTED_TRANSACTION' });
  });
});

test('UTF-8 byte ordering and bounded scans are deterministic', async () => {
  const store = createMemoryStore();
  const keys = ['😀', '\uE000', 'z', 'a2', 'a1'];
  await store.transact(async tx => { for (const key of keys) await tx.set(key, key); });
  assert.deepEqual((await store.read(tx => tx.scan({ prefix: '' }))).map(row => row.key), ['a1', 'a2', 'z', '\uE000', '😀']);
  assert.deepEqual((await store.read(tx => tx.scan({ prefix: 'a', gt: 'a1', lte: 'a2', limit: 1 }))).map(row => row.key), ['a2']);
  for (const key of ['', '\uD800', 1]) await assert.rejects(store.read(tx => tx.get(key)), { code: 'INVALID_KEY' });
  await assert.rejects(store.read(tx => tx.scan({ limit: -1 })), { code: 'INVALID_RANGE' });
});

test('shared memory is rejected through nested containers and clone rejection rolls back', async () => {
  const store = createMemoryStore();
  const backing = new SharedArrayBuffer(4);
  const shared = new Uint8Array(backing); shared[0] = 7;
  const cyclic = { nested: [shared] }; cyclic.self = cyclic;
  const error = new Error('nested cause', { cause: backing });
  for (const value of [backing, shared, new DataView(backing), cyclic,
    new Map([[backing, 1]]), new Map([['key', { shared }]]), new Set([shared]), error]) {
    await assert.rejects(store.transact(async tx => {
      await tx.set('staged', 'must roll back');
      await tx.set('shared', value);
    }), { code: 'INVALID_VALUE' });
    assert.equal(await store.read(tx => tx.get('staged')), undefined);
    assert.equal(await store.read(tx => tx.get('shared')), undefined);
  }
  // Ordinary byte arrays are copied both on ingress and on return.
  const original = Uint8Array.from(shared);
  await store.transact(tx => tx.set('bytes', { original }));
  shared[0] = 8; original[0] = 9;
  const returned = await store.read(tx => tx.get('bytes')); returned.original[0] = 10;
  assert.equal((await store.read(tx => tx.get('bytes'))).original[0], 7);
  const safeCycle = {}; safeCycle.self = safeCycle;
  await store.transact(tx => tx.set('cycle', safeCycle));
  const roundTrip = await store.read(tx => tx.get('cycle'));
  assert.equal(roundTrip.self, roundTrip);
});
