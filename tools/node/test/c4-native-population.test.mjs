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
import { prepareModel } from '../model.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';
import { checkSourceBackup, evaluateSources, stageSources } from '../oracles.mjs';
import { accept, preparePopulation, propose, reject } from '../population.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const binary = process.env.REBASE_NODE_N3_BINARY ?? path.join(root, 'target/n2-native-default/rebase-next');
const available = existsSync(binary);
const methods = ['service.start', 'service.stop', 'identity.issue', 'store.backup', 'store.check'];

test('C4 real signed redb population checks atomic reference fanout, exact derived facts, original receipts and native rejection',
  { skip: !available && `native binary not found: ${binary}` }, async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'next-base-c4-population-'));
    const tenant = randomUUID(), actor = randomUUID();
    const native = await openNative(resolveConfig({ overrides: { native: { binary: path.resolve(binary), environment: {},
      configuration: { model: 'quantity', backend: { kind: 'redb', cluster_file: null },
        target: { mode: 'create', path: path.join(directory, 'quantity.redb'), tenant, actor }, operator_methods: methods } } } }));
    const operator = openOperator(native, { scope: native.scope, methods });
    let service;
    try {
      const pair = generateKeyPairSync('ed25519');
      const identity = { issuer: 'c4-population', audience: 'c4-population',
        public_keys: { test: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString() }, max_token_seconds: 300 };
      service = await operator.startService({ config: { listen: '127.0.0.1:0', identity, max_inflight: 4, request_timeout_seconds: 15, effects: null } });
      const token = (await operator.issueIdentity({ identity, request: { tenant, actor, epoch: 0, ttl: 300, key_id: 'test' },
        privateKeyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() })).token;
      const client = connect({ endpoint: service.endpoint, credential: token });
      const model = prepareModel(await native.catalog({ scope: 'developer' }), { native, selector: 'quantity' });
      const counts = { Source: 3, Scale: 6, Join: 3 };
      const options = { seed: 'c4-native-quantity', batchSize: 12, maxAttempts: 16,
        strategies: {
          Source: (_schema, _seed, cursor) => ({ value: String(12 + cursor * 2) }),
          Scale: () => ({ factor: { numerator: '1', denominator: '2' }, rounding: 'exact' }),
          Join: () => ({}),
        },
        selectContract(eligible) { return ['Source', 'Scale', 'Join'].find(name => eligible.includes(name)); },
        selectReference(_child, _field, pools, usage) {
          const parents = pools.Source;
          assert.ok(parents?.length, 'choose only source anchors to keep exact halves');
          return ['Source', parents.reduce((best, row) => {
            const weight = id => Object.entries(usage).filter(([key]) => key.endsWith(`\0${id}`)).reduce((sum, [, value]) => sum + value, 0);
            return weight(row.id) < weight(best.id) ? row : best;
          }).id];
        },
        references: { Scale: { parent: { maxFanout: 2, distribution: 'balanced' } },
          Join: { left: { maxFanout: 1 }, right: { maxFanout: 1 } } },
      };
      const state = preparePopulation(model, counts, options);
      const proposal = await propose(state, {});
      assert.equal(proposal.commands.length, 12);
      const replay = await propose(preparePopulation(model, counts, options), {});
      assert.deepEqual(replay, proposal);
      const facts = stageSources({}, proposal.commands);
      const expected = evaluateSources('quantity', facts);
      const plan = await client.prepare({ model: model.identity, commands: proposal.commands, returning: proposal.returning });
      const filename = path.join(directory, 'original.plan.json');
      await savePlan(filename, plan);
      state.pending.plan = plan;
      await client.execute(plan);
      // Deliberately discard the first response and recover the original receipt.
      const saved = JSON.parse(await readFile(filename, 'utf8'));
      const recovered = await client.status(saved);
      assert.equal(recovered.status, 'committed');
      accept(state, proposal, saved, recovered);
      assert.deepEqual(state.accepted, counts);
      const retried = await client.execute(saved);
      assert.equal(retried.status, 'committed');
      assert.equal(retried.replayed, true);
      for (const [id, derived] of Object.entries(expected.derived)) {
        const record = await client.call('records.get', { model: model.identity, id });
        assert.deepEqual(record.derived, derived);
      }
      const backup = path.join(directory, 'accepted.backup.json');
      await operator.snapshot({ destination: backup });
      const checked = checkSourceBackup({ model: 'quantity', facts, backup: await readFile(backup), catalog: model.catalog });
      assert.equal(checked.status, 'passed', JSON.stringify(checked.obligations));
      await operator.check();

      // Locally schema-valid generation cannot make an overflowing graph native-valid.
      const maximum = '1000000000000000000';
      const anchors = preparePopulation(model, { Source: 1, Scale: 1 }, { seed: 'native-reject', batchSize: 2,
        strategies: { Source: () => ({ value: maximum }), Scale: () => ({ factor: { numerator: '2', denominator: '1' }, rounding: 'exact' }) },
        selectContract(eligible) { return eligible.includes('Source') ? 'Source' : 'Scale'; } });
      const invalid = await propose(anchors, {});
      assert.throws(() => evaluateSources('quantity', stageSources({}, invalid.commands)), error => error.kind === 'overflow');
      const rejectedPlan = await client.prepare({ model: model.identity, commands: invalid.commands, returning: invalid.returning });
      anchors.pending.plan = rejectedPlan;
      let nativeError;
      await assert.rejects(client.execute(rejectedPlan), error => { nativeError = error; return ['overflow', 'invariant'].includes(error.code); });
      reject(anchors, invalid, rejectedPlan, nativeError);
      assert.deepEqual(anchors.accepted, { Source: 0, Scale: 0, Join: 0 });
      assert.equal(anchors.poolIds.Source.length, 0);
      const after = path.join(directory, 'after-rejection.backup.json');
      await operator.snapshot({ destination: after });
      assert.deepEqual(JSON.parse(await readFile(after, 'utf8')).payload, JSON.parse(await readFile(backup, 'utf8')).payload);
    } finally {
      try { if (service) await operator.stopService({ service: service.service }); }
      finally { await native.close(); await rm(directory, { recursive: true, force: true }); }
    }
  });
