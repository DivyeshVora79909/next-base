import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { connect, savePlan } from '../client.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';
import { resolveConfig } from '../config.mjs';
import { startFakeEmailProvider } from '../fake-email-provider.mjs';
import { checkBackupStructure } from '../storage-check.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const binary = process.env.REBASE_NODE_N2_BINARY ?? path.join(root, 'target/debug/rebase-next');
test('E2 real owned worker dispatches both independent adapters with bearer-free saved intent and pinned retained keys', {
  skip: !existsSync(binary) && `native binary not found: ${binary}`,
}, async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'next-base-e2-email-'));
  let native, resend, brevo, service;
  try {
    const tenant = randomUUID(), actor = randomUUID(); const account = 'independent-test-account';
    const probes = path.join(directory, 'probes'); await mkdir(probes);
    const resendKey = `PUBLIC_TEST_RESEND_KEY_${randomUUID()}`, brevoKey = `PUBLIC_TEST_BREVO_KEY_${randomUUID()}`;
    resend = await startFakeEmailProvider({ provider: 'resend', directory, accounts: [{ account, keys: [resendKey] }] });
    brevo = await startFakeEmailProvider({ provider: 'brevo', directory, accounts: [{ account, keys: [brevoKey] }] });
    const keyring = path.join(directory, 'keyring.json');
    const key = key_id => ({ key_id, key: randomBytes(32).toString('base64url') });
    await writeFile(keyring, JSON.stringify({ format: 'rebase-credential-keyring-1', active_ingress: 'ingress', ingress: [key('ingress')],
      active_at_rest: 'vault', at_rest: [key('vault')], active_grant: 'grant', grants: [key('grant')] }), { mode: 0o600 });
    const pair = generateKeyPairSync('ed25519');
    const identity = { issuer: 'e2-test', audience: 'e2-test', max_token_seconds: 300, public_keys: { local: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString() } };
    const methods = ['store.check', 'store.inspect', 'store.backup', 'store.restore', 'service.start', 'service.stop', 'identity.issue', 'credentials.verify'];
    native = await openNative(resolveConfig({ overrides: { native: { binary, environment: {}, configuration: {
      model: 'services', backend: { kind: 'redb', cluster_file: null }, target: { mode: 'create', path: path.join(directory, 'store.redb'), tenant, actor }, operator_methods: methods,
    } } } }));
    let operator = openOperator(native, { scope: native.scope, methods });
    const catalog = await native.catalog({ scope: 'developer' }); const model = catalog.model;
    const config = { listen: '127.0.0.1:0', identity, max_inflight: 4, request_timeout_seconds: 10, effects: null, credentials: { keyring, platform: [] },
      email: { resend_origin: resend.endpoint, brevo_origin: brevo.endpoint, mode: 'disabled', probe_directory: probes, policies: ['resend', 'brevo'].map(provider => ({ provider, account, purpose: 'email.send', window_ms: '1000', limit: 3 })) } };
    service = await operator.startService({ config });
    const { token } = await operator.issueIdentity({ identity, request: { tenant, actor, epoch: 0, ttl: 300, key_id: 'local' }, privateKeyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() });
    let client = connect({ endpoint: service.endpoint, credential: token });
    const graph = structuredClone(await client.call('access.describe', { model }));
    graph.graph.principals.find(principal => principal.id === actor).grants.contracts['1001'] = ['use'];
    await client.call('access.replace', { model, if_revision: graph.revision, graph: graph.graph });
    const credentials = [];
    for (const [provider, secretKey] of [['resend', resendKey], ['brevo', brevoKey]]) {
      const credential = randomUUID(); const metadata = { label: 'transport fixture', provider, account, enabled: true, scopes: ['email.send'] };
      await client.execute(await client.prepareCredential({ model, id: credential, if_version: null, metadata }, Buffer.from(JSON.stringify({ api_key: secretKey }))));
      credentials.push({ credential, provider, metadata });
    }
    const sources = [randomUUID(), randomUUID()];
    const plan = await client.prepareEmail({ model, commands: credentials.map((binding, i) => ({ op: 'create', id: sources[i], contract: 1002,
      fields: { email: { sender: ' Sender@EXAMPLE.COM ', to: [' Recipient@Example.NET '], subject: `Fixture ${binding.provider}`, text: 'body\nsecond line' },
        selection: { kind: 'byoc', credential: binding.credential }, execute_at: null, not_after: null } })), returning: sources });
    const authorizations = [];
    for (const command of plan.request.commands) {
      const { grant } = await client.call('email.authorize', { model, email: command.fields.email, selection: command.fields.selection, ttl_seconds: 60 });
      authorizations.push({ source: command.id, grant });
    }
    const destination = path.join(directory, 'email-plan.json'); await savePlan(destination, plan);
    const saved = await readFile(destination, 'utf8'); assert.equal(plan.kind, 'email-enqueue');
    for (const authorization of authorizations) assert.equal(saved.includes(authorization.grant), false);
    await assert.rejects(client.execute(plan), { code: 'invalid_plan' });
    const accepted = await client.enqueueEmail(plan, authorizations);
    assert.equal(accepted.status, 'committed'); assert.equal(accepted.result.executions.length, 2);
    // Recovery does not require valid unconsumed grants after the original commit.
    const recovered = await client.call('email.enqueue', { ...plan.request, authorizations: sources.map(source => ({ source, grant: 'expired-or-corrupt-grant' })) });
    assert.equal(recovered.replayed, true);
    for (const execution of accepted.result.executions) {
      const command = plan.request.commands.find(command => command.id === execution.source);
      const provider = credentials[sources.indexOf(execution.source)].provider === 'resend' ? resend : brevo;
      await provider.expect(execution.execution_id, { account, email: command.fields.email });
    }
    // Fake Resend accepts only the old key. Rotation must retain and use revision 1.
    const before = await client.call('records.get', { model, id: credentials[0].credential });
    const rotatedKey = `PUBLIC_TEST_NEW_KEY_${randomUUID()}`;
    await client.execute(await client.prepareCredential({ model, id: before.id ?? credentials[0].credential, if_version: before.version, metadata: credentials[0].metadata }, Buffer.from(JSON.stringify({ api_key: rotatedKey }))));
    await operator.stopService({ service: service.service }); service = null;
    service = await operator.startService({ config: { ...config, email: { ...config.email, mode: 'delivery' } } });
    client = connect({ endpoint: service.endpoint, credential: token });
    const deadline = Date.now() + 20_000;
    let statuses;
    while (Date.now() < deadline) {
      statuses = await Promise.all(accepted.result.executions.map(execution => client.call('effects.status', { model, execution_id: execution.execution_id })));
      if (statuses.every(status => status?.phase === 'succeeded')) break;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.ok(statuses.every(status => status?.phase === 'succeeded'), JSON.stringify(statuses));
    for (const [index, execution] of accepted.result.executions.entries()) {
      const provider = credentials[sources.indexOf(execution.source)].provider === 'resend' ? resend : brevo;
      assert.deepEqual(await provider.counts(execution.execution_id), { submissions: 1, observations: 0, accepted: 1 });
      assert.equal(statuses[index].application, 'not_required');
      assert.equal(JSON.stringify(statuses[index]).includes(account), false);
    }
    // Hold before start so the independent fake can register expected source
    // intent before the real worker sends, without predicting execution IDs.
    async function enqueueHeld(subject, mode = 'success') {
      await writeFile(path.join(probes, 'before_start.hold'), '');
      const source = randomUUID();
      const next = await client.prepareEmail({ model, commands: [{ op: 'create', id: source, contract: 1002, fields: {
        email: { sender: 'Sender@example.com', to: ['Recipient@example.net'], subject, text: 'recovery fixture' },
        selection: { kind: 'byoc', credential: credentials[1].credential }, execute_at: null, not_after: null,
      } }], returning: [source] });
      const command = next.request.commands[0];
      const { grant } = await client.call('email.authorize', { model, email: command.fields.email, selection: command.fields.selection, ttl_seconds: 60 });
      const receipt = await client.enqueueEmail(next, [{ source, grant }]);
      const execution = receipt.result.executions[0].execution_id;
      await brevo.expect(execution, { account, email: command.fields.email }); await brevo.setMode(execution, mode);
      return { source, execution };
    }
    async function waitPhase(execution, phase) {
      const end = Date.now() + 20_000; let status;
      while (Date.now() < end) {
        status = await client.call('effects.status', { model, execution_id: execution });
        if (status?.phase === phase) return status;
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      assert.fail(JSON.stringify(status));
    }
    const lost = await enqueueHeld('lost response remains one remote acceptance', 'lost_response');
    await rm(path.join(probes, 'before_start.hold'));
    await waitPhase(lost.execution, 'succeeded');
    const lostCounts = await brevo.counts(lost.execution);
    assert.equal(lostCounts.submissions, 1); assert.equal(lostCounts.accepted, 1); assert.ok(lostCounts.observations >= 1);
    const revoked = await enqueueHeld('revoked before start sends nothing');
    const currentGraph = structuredClone(await client.call('access.describe', { model }));
    currentGraph.graph.principals.find(principal => principal.id === actor).grants.contracts['1001'] = [];
    await client.call('access.replace', { model, if_revision: currentGraph.revision, graph: currentGraph.graph });
    await rm(path.join(probes, 'before_start.hold'));
    await waitPhase(revoked.execution, 'cancelled');
    assert.deepEqual(await brevo.counts(revoked.execution), { submissions: 0, observations: 0, accepted: 0 });
    assert.equal((await operator.check()).status, 'valid');
    const backupPath = path.join(directory, 'backup.json'); await operator.snapshot({ destination: backupPath });
    const backup = await readFile(backupPath);
    for (const secret of [resendKey, brevoKey, rotatedKey, ...authorizations.map(authorization => authorization.grant)]) assert.equal(backup.includes(Buffer.from(secret)), false);
    assert.equal(checkBackupStructure(backup, { catalog }).status, 'passed');
    await operator.stopService({ service: service.service }); service = null;
    assert.equal((await operator.verifyCredentials({ keyring })).status, 'verified');
    // Missing vault custody after a committed start must stop the owned worker
    // without a provider call or repeated observations. Repair preserves intent.
    service = await operator.startService({ config });
    client = connect({ endpoint: service.endpoint, credential: token });
    const repairedGraph = structuredClone(await client.call('access.describe', { model }));
    repairedGraph.graph.principals.find(principal => principal.id === actor).grants.contracts['1001'] = ['use'];
    await client.call('access.replace', { model, if_revision: repairedGraph.revision, graph: repairedGraph.graph });
    const missingKey = await enqueueHeld('missing custody retains charged start');
    await rm(path.join(probes, 'before_start.hold'));
    await operator.stopService({ service: service.service }); service = null;
    const originalKeys = await readFile(keyring, 'utf8'); const unavailableKeys = JSON.parse(originalKeys);
    unavailableKeys.active_at_rest = 'wrong-vault'; unavailableKeys.at_rest = [key('wrong-vault')];
    await writeFile(keyring, JSON.stringify(unavailableKeys), { mode: 0o600 });
    service = await operator.startService({ config: { ...config, email: { ...config.email, mode: 'delivery' } } });
    const health = new URL('/health', service.endpoint); let stopped = false;
    const stopDeadline = Date.now() + 10_000;
    while (Date.now() < stopDeadline) {
      try { await fetch(health, { signal: AbortSignal.timeout(1000) }); }
      catch { stopped = true; break; }
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.equal(stopped, true, 'missing custody must stop the owned worker');
    await assert.rejects(operator.stopService({ service: service.service }), { code: 'credential_crypto' });
    await assert.rejects(operator.stopService({ service: randomUUID() }), { code: 'service_not_running' });
    await assert.rejects(operator.stopService({ service: service.service }), { code: 'service_not_running' }); service = null;
    assert.deepEqual(await brevo.counts(missingKey.execution), { submissions: 0, observations: 0, accepted: 0 });
    await writeFile(keyring, originalKeys, { mode: 0o600 });
    service = await operator.startService({ config });
    client = connect({ endpoint: service.endpoint, credential: token });
    const retained = await client.call('effects.status', { model, execution_id: missingKey.execution });
    assert.equal(retained.phase, 'uncertain'); assert.equal(retained.attempts, 1); assert.equal(retained.observations, 0);
    assert.equal((await operator.check()).status, 'valid');
    await operator.stopService({ service: service.service }); service = null;
    assert.equal((await operator.verifyCredentials({ keyring })).status, 'verified');
    const retainedBackup = path.join(directory, 'retained.backup.json'); await operator.snapshot({ destination: retainedBackup });
    const retainedImage = await readFile(retainedBackup); const checkedRetained = checkBackupStructure(retainedImage, { catalog });
    assert.equal(checkedRetained.status, 'passed');
    const restoredPath = path.join(directory, 'restored.redb'); const storeId = native.scope.store;
    const restored = await operator.restore({ backup: retainedBackup, expectBackupStore: storeId,
      destination: { backend: { kind: 'redb', cluster_file: null }, target: { path: restoredPath } } });
    assert.equal(restored.status, 'restored'); assert.equal(restored.integrity.effects.quarantined, true);
    assert.equal(restored.integrity.effects.worker_mode, 'disabled');
    await native.close(); native = null;
    native = await openNative(resolveConfig({ overrides: { native: { binary, environment: {}, configuration: {
      model: 'services', backend: { kind: 'redb', cluster_file: null }, target: { mode: 'open', path: restoredPath, expect_store: storeId }, operator_methods: methods,
    } } } }));
    operator = openOperator(native, { scope: native.scope, methods });
    await writeFile(keyring, JSON.stringify(unavailableKeys), { mode: 0o600 });
    await assert.rejects(operator.verifyCredentials({ keyring }), { code: 'credential_crypto' });
    assert.equal((await operator.check()).status, 'valid');
    await writeFile(keyring, originalKeys, { mode: 0o600 });
    assert.equal((await operator.verifyCredentials({ keyring })).status, 'verified');
    const countsBeforeRestore = await Promise.all([resend.calls(), brevo.calls()]);
    service = await operator.startService({ config }); client = connect({ endpoint: service.endpoint, credential: token });
    const restoredStatus = await client.call('effects.status', { model, execution_id: missingKey.execution });
    assert.equal(restoredStatus.phase, 'uncertain'); assert.equal(restoredStatus.attempts, 1); assert.equal(restoredStatus.observations, 0);
    assert.equal(restoredStatus.worker_mode, 'disabled'); assert.equal(restoredStatus.quarantined, true);
    for (const execution of accepted.result.executions) assert.equal((await client.call('effects.status', { model, execution_id: execution.execution_id })).phase, 'succeeded');
    assert.deepEqual(await Promise.all([resend.calls(), brevo.calls()]), countsBeforeRestore);
    const restoredBackup = path.join(directory, 'restored.backup.json'); await operator.snapshot({ destination: restoredBackup });
    const checkedRestored = checkBackupStructure(await readFile(restoredBackup), { catalog });
    assert.equal(checkedRestored.credentialSecretCount, checkedRetained.credentialSecretCount);
    assert.equal(checkedRestored.emailAdmissionCount, checkedRetained.emailAdmissionCount);
    assert.equal(checkedRestored.status, 'passed');
    await operator.stopService({ service: service.service }); service = null;
    // Repaired custody permits read-only reconciliation of the same restored
    // execution. A missing remote result never permits another charged send.
    const factHold = path.join(probes, `${missingKey.execution}.after_fact.hold`);
    await writeFile(factHold, '');
    service = await operator.startService({ config: { ...config, email: { ...config.email, mode: 'reconcile' } } });
    client = connect({ endpoint: service.endpoint, credential: token });
    const reconciledDeadline = Date.now() + 20_000;
    while (!existsSync(path.join(probes, `${missingKey.execution}.after_fact.json`))) {
      assert.ok(Date.now() < reconciledDeadline, 'restored retained key must permit reconciliation');
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    const reconciledStatus = await client.call('effects.status', { model, execution_id: missingKey.execution });
    assert.equal(reconciledStatus.phase, 'uncertain'); assert.equal(reconciledStatus.attempts, 1); assert.equal(reconciledStatus.observations, 1);
    assert.equal(reconciledStatus.quarantined, true);
    assert.deepEqual(await brevo.counts(missingKey.execution), { submissions: 0, observations: 1, accepted: 0 });
    assert.deepEqual(await resend.calls(), countsBeforeRestore[0]);
    await operator.stopService({ service: service.service }); service = null;
    await rm(factHold);
    const reconciledBackup = path.join(directory, 'reconciled.backup.json'); await operator.snapshot({ destination: reconciledBackup });
    const reconciledImage = await readFile(reconciledBackup);
    const checkedReconciled = checkBackupStructure(reconciledImage, { catalog });
    assert.equal(checkedReconciled.status, 'passed');
    assert.equal(checkedReconciled.emailAdmissionCount, checkedRetained.emailAdmissionCount);
    const retainedTables = JSON.parse(retainedImage).payload.tables;
    const reconciledTables = JSON.parse(reconciledImage).payload.tables;
    for (const name of ['email_rate_scopes', 'email_rate_starts', 'email_rate_points']) {
      assert.deepEqual(reconciledTables[name], retainedTables[name], `${name} must survive restore and reconciliation unchanged`);
    }
    const privateEnvelopes = tables => tables.native_kv.filter(row => row.key.startsWith('11'));
    assert.equal(privateEnvelopes(retainedTables).length, checkedRetained.credentialSecretCount);
    assert.deepEqual(privateEnvelopes(reconciledTables), privateEnvelopes(retainedTables));
  } finally {
    const closed = await Promise.allSettled([native?.close(), resend?.close(), brevo?.close()]);
    await rm(directory, { recursive: true, force: true });
    for (const result of closed) if (result.status === 'rejected') process.stderr.write(`Fixture cleanup: ${result.reason?.code ?? 'failed'}\n`);
  }
});
