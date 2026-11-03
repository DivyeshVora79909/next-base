import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { connect, savePlan } from '../client.mjs';
import { resolveConfig } from '../config.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const binary = process.env.REBASE_NODE_N6_BINARY ?? process.env.REBASE_NODE_N3_BINARY
  ?? path.join(root, 'target/n2-native-default/rebase-next');
const available = existsSync(binary);
const id = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const atom = value => [{ kind: 'integer', value }];
const compare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const numericOrder = (left, right) => compare(BigInt(left.value), BigInt(right.value)) || compare(left.id, right.id);
const all = { lower: null, upper: null };

test('C3 signed RPC exposes exact declared order pages, trusted creation metadata, stable ties and fenced cursors',
  { skip: !available && `native binary not found: ${binary}` }, async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'next-base-c3-order-'));
    const tenant = randomUUID(), actor = randomUUID();
    const methods = ['service.start', 'service.stop', 'identity.issue'];
    let native, service, operator;
    try {
      native = await openNative(resolveConfig({ overrides: { native: { binary: path.resolve(binary), environment: {},
        configuration: { model: 'quantity', backend: { kind: 'redb', cluster_file: null },
          target: { mode: 'create', path: path.join(directory, 'quantity.redb'), tenant, actor }, operator_methods: methods } } } }));
      operator = openOperator(native, { scope: native.scope, methods });
      const pair = generateKeyPairSync('ed25519');
      const identity = { issuer: 'c3-order', audience: 'c3-order', max_token_seconds: 300,
        public_keys: { local: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString() } };
      service = await operator.startService({ config: { listen: '127.0.0.1:0', identity, max_inflight: 4,
        request_timeout_seconds: 15, effects: null } });
      const credential = (await operator.issueIdentity({ identity,
        request: { tenant, actor, epoch: 0, ttl: 300, key_id: 'local' },
        privateKeyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() })).token;
      const client = connect({ endpoint: service.endpoint, credential });
      const catalog = await client.call('model.describe', {});
      assert.ok(catalog.capabilities.methods.includes('records.order_page'));
      assert.ok(!catalog.capabilities.methods.includes('records.ordered_page'));
      const source = catalog.contracts.find(contract => contract.name === 'Source');
      const valueIndex = source.access_indexes.find(index => index.name === 'value');
      const createdIndex = source.access_indexes.find(index => index.name === 'created');
      assert.deepEqual(valueIndex.components, [{ source: 'field', field: 'value', kind: 'integer' }]);
      assert.deepEqual(createdIndex.components, [{ source: 'created_at' }]);
      assert.ok(!Object.hasOwn(source.input_schema.properties, 'created_at'));
      const sources = [[7, '10'], [1, '2'], [9, '-10'], [3, '2'], [5, '100'], [11, '1000000000000000000']]
        .map(([n, value]) => ({ id: id(n), value }));
      const before = BigInt(Date.now());
      const plan = await client.prepare({ model: catalog.model,
        commands: sources.map(row => ({ op: 'create', id: row.id, contract: source.code, fields: { value: row.value } })),
        returning: sources.map(row => row.id) });
      const filename = path.join(directory, 'original.plan.json');
      await savePlan(filename, plan);
      await client.execute(plan); // Discard the response and recover this exact saved operation.
      const after = BigInt(Date.now());
      const saved = JSON.parse(await readFile(filename, 'utf8'));
      const recovered = await client.status(saved);
      assert.equal(recovered.status, 'committed');
      assert.equal(recovered.result.operation_id, plan.request.operation_id);
      assert.equal(saved.request.context, plan.request.context);
      assert.equal((await client.execute(saved)).replayed, true);

      const byIdQuery = { path: 'records.by_id', contract: source.code, equals: null };
      const scan = await client.call('records.page', { model: catalog.model, query: byIdQuery,
        limit: 32, visit_budget: 128, cursor: null });
      assert.equal(scan.exhausted, true);
      assert.deepEqual(scan.records.map(row => row.id), sources.map(row => row.id).sort());
      const scanned = new Map(scan.records.map(row => [row.id, row]));
      for (const fact of sources) {
        const record = await client.call('records.get', { model: catalog.model, id: fact.id });
        assert.deepEqual(record, scanned.get(fact.id));
        assert.equal(record.input.value, fact.value);
        assert.match(record.created_at, /^(0|[1-9][0-9]*)$/);
        assert.ok(before <= BigInt(record.created_at) && BigInt(record.created_at) <= after);
        assert.ok(!Object.hasOwn(record.input, 'created_at'));
        assert.ok(!Object.hasOwn(record, 'reader') && !Object.hasOwn(record, 'read_by'));
      }
      assert.equal(new Set(scan.records.map(row => row.created_at)).size, 1, 'one trusted creation instant per atomic batch');

      const request = (index, range = all, cursor = null, limit = 2) => ({ model: catalog.model,
        query: { contract: source.code, index, range, equals: null }, limit, visit_budget: 2, cursor });
      const walk = async (index, range = all) => {
        const rows = []; let cursor = null;
        for (let page = 0; page < 16; page += 1) {
          const result = await client.call('records.order_page', request(index, range, cursor));
          assert.ok(result.visited <= 2);
          rows.push(...result.records);
          if (result.exhausted) { assert.equal(result.cursor, null); return rows; }
          assert.equal(typeof result.cursor, 'string');
          assert.notEqual(result.cursor, cursor, 'a bounded page must advance');
          cursor = result.cursor;
        }
        assert.fail('ordered continuation exceeded source-derived page bound');
      };
      const expected = [...sources].sort(numericOrder).map(row => row.id);
      assert.deepEqual((await walk(valueIndex.code)).map(row => row.id), expected);
      const scanExpected = scan.records.map(row => ({ id: row.id, value: row.input.value })).sort(numericOrder).map(row => row.id);
      assert.deepEqual(scanExpected, expected);
      assert.deepEqual((await walk(createdIndex.code)).map(row => row.id), sources.map(row => row.id).sort());
      for (const [range, lower, lowerClosed, upper, upperClosed] of [
        [{ lower: { included: atom('2') }, upper: { included: atom('2') } }, 2n, true, 2n, true],
        [{ lower: { excluded: atom('2') }, upper: { included: atom('100') } }, 2n, false, 100n, true],
        [{ lower: { included: atom('-10') }, upper: { excluded: atom('10') } }, -10n, true, 10n, false],
        [{ lower: { excluded: atom('2') }, upper: { excluded: atom('2') } }, 2n, false, 2n, false],
      ]) {
        const wanted = sources.filter(row => {
          const value = BigInt(row.value);
          return (lowerClosed ? value >= lower : value > lower) && (upperClosed ? value <= upper : value < upper);
        }).sort(numericOrder).map(row => row.id);
        assert.deepEqual((await walk(valueIndex.code, range)).map(row => row.id), wanted);
      }

      const first = await client.call('records.order_page', request(valueIndex.code, all, null, 1));
      assert.ok(first.cursor);
      const changed = scanned.get(id(5));
      const update = await client.prepare({ model: catalog.model, commands: [{ op: 'update', id: id(5),
        if_version: changed.version, set: { value: '-20' }, unset: [] }], returning: [id(5)] });
      const updated = await client.execute(update);
      assert.equal(updated.result.records[0].record.created_at, changed.created_at);
      await assert.rejects(client.call('records.order_page', request(valueIndex.code, all, first.cursor, 1)), error => error.code === 'query_changed');
      sources.find(row => row.id === id(5)).value = '-20';
      assert.deepEqual((await walk(valueIndex.code)).map(row => row.id), [...sources].sort(numericOrder).map(row => row.id));
      assert.deepEqual((await walk(createdIndex.code)).map(row => row.id), sources.map(row => row.id).sort());

      for (const invalid of [2, '2', [{ kind: 'integer', value: 2 }], [{ kind: 'text', value: '2' }],
        [{ kind: 'integer', value: '02' }], [{ kind: 'integer', value: '170141183460469231731687303715884105728' }], []]) {
        await assert.rejects(client.call('records.order_page', request(valueIndex.code, { lower: { included: invalid }, upper: null })), error => error.code === 'invalid_input');
      }
      await assert.rejects(client.call('records.order_page', request(65535)), error => error.code === 'unsupported_query');
      await assert.rejects(client.call('records.ordered_page', request(valueIndex.code)), error => error.code === 'method_not_found');
      for (const path of ['records.by_created', 'records.by_value']) {
        await assert.rejects(client.call('records.page', { model: catalog.model, query: { ...byIdQuery, path },
          limit: 2, visit_budget: 2, cursor: null }), error => error.code === 'unsupported_query');
      }
      const badCreate = await client.prepare({ model: catalog.model, commands: [{ op: 'create', id: id(50),
        contract: source.code, fields: { value: '1', created_at: '0' } }], returning: [] });
      await assert.rejects(client.execute(badCreate), error => error.code === 'invalid_input');
      const current = await client.call('records.get', { model: catalog.model, id: id(5) });
      const badUpdate = await client.prepare({ model: catalog.model, commands: [{ op: 'update', id: id(5),
        if_version: current.version, set: { created_at: '0' }, unset: [] }], returning: [] });
      await assert.rejects(client.execute(badUpdate), error => error.code === 'invalid_input');
      assert.deepEqual(await client.call('records.get', { model: catalog.model, id: id(5) }), current);
      assert.deepEqual((await walk(valueIndex.code)).map(row => row.id), [...sources].sort(numericOrder).map(row => row.id));
    } finally {
      try { if (service) await operator.stopService({ service: service.service }); }
      finally { if (native) await native.close(); await rm(directory, { recursive: true, force: true }); }
    }
  });
