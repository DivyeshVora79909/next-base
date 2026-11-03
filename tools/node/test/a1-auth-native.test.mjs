import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { prepareAuthentication, prepareCodeProof } from '../authentication.mjs';
import { connect, savePlan } from '../client.mjs';
import { resolveConfig } from '../config.mjs';
import { startFakeAuthProvider } from '../fake-auth-provider.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';
import { checkBackupStructure } from '../storage-check.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const binary = process.env.REBASE_NODE_N2_BINARY ?? path.join(root, 'target/debug/rebase-next');
const methods = ['store.check', 'store.inspect', 'store.backup', 'store.restore', 'service.start', 'service.stop', 'identity.issue', 'credentials.verify'];
const providers = ['resend', 'brevo', 'fake_sms'];
const recipient = 'signin@example.com';
const phone = '+123456789';
const sender = 'Sender@example.com';
function decodeRow(row) { return JSON.parse(Buffer.from(row.value, 'hex').toString('utf8')); }
function wrongCode(code) { return `${code[0] === '0' ? '1' : '0'}${code.slice(1)}`; }
async function until(read, accepted, message) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const result = await read(); if (accepted(result)) return result;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.fail(message);
}
function nativeConfig(directory, target) {
  return resolveConfig({ overrides: { native: { binary, environment: {}, configuration: {
    model: 'services', backend: { kind: 'redb', cluster_file: null }, target, operator_methods: methods,
  } }, runner: { startTimeoutMs: 20_000, closeTimeoutMs: 10_000, diagnosticBytes: 4096 } } });
}

for (const emailProvider of ['resend', 'brevo']) test(`A1/A2 native ${emailProvider} and SMS prove private delivery, exact issuance recovery and restore fencing`, {
  skip: !existsSync(binary) && `native binary not found: ${binary}`,
  timeout: 180_000,
}, async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), `next-base-a1-${emailProvider}-`));
  const fake = new Map(); let native, operator, service;
  try {
    const tenant = randomUUID(), actor = randomUUID(), child = randomUUID(), disabled = randomUUID();
    const account = 'auth-native-account'; const secrets = new Set();
    const providerKeys = new Map(providers.map(provider => [provider, `PUBLIC_TEST_${provider}_${randomUUID()}`]));
    for (const provider of providers) {
      const key = providerKeys.get(provider); secrets.add(key);
      fake.set(provider, await startFakeAuthProvider({ provider, directory, account, key,
        recipient: provider === 'fake_sms' ? phone : recipient, ...(provider === 'fake_sms' ? {} : { sender }) }));
    }
    const probes = path.join(directory, 'probes'); await mkdir(probes);
    const credentialKeyring = path.join(directory, 'credential-keys.json');
    function key(key_id) { const value = randomBytes(32).toString('base64url'); secrets.add(value); return { key_id, key: value }; }
    await writeFile(credentialKeyring, JSON.stringify({ format: 'rebase-credential-keyring-1', active_ingress: 'ingress', ingress: [key('ingress')],
      active_at_rest: 'vault', at_rest: [key('vault')], active_grant: 'grant', grants: [key('grant')] }), { mode: 0o600 });
    const proofKeyring = path.join(directory, 'proof-keys.json');
    await writeFile(proofKeyring, JSON.stringify({ format: 'next-base-auth-proof-keyring-1', current: 'proof', keys: [key('proof')] }), { mode: 0o600 });
    const pair = generateKeyPairSync('ed25519');
    const privateKeyPem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(); secrets.add(privateKeyPem);
    const signingKey = path.join(directory, 'signing.pem'); await writeFile(signingKey, privateKeyPem, { mode: 0o600 });
    const identity = { issuer: 'a1-native-test', audience: 'a1-native-test', max_token_seconds: 1800,
      public_keys: { local: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString() } };
    const storePath = path.join(directory, 'store.redb');
    native = await openNative(nativeConfig(directory, { mode: 'create', path: storePath, tenant, actor }));
    operator = openOperator(native, { scope: native.scope, methods });
    const storeId = native.scope.store;
    const catalog = await native.catalog({ scope: 'developer' }); const model = catalog.model;
    const publicCatalog = await native.catalog({ scope: 'public' });
    assert.equal(publicCatalog.contracts.some(contract => contract.code === 1004), false, 'private delivery is absent from the public source catalog');
    const config = { listen: '127.0.0.1:0', identity, max_inflight: 4, request_timeout_seconds: 10, effects: null,
      credentials: { keyring: credentialKeyring, platform: [] }, authentication: null,
      email: { resend_origin: fake.get('resend').endpoint, brevo_origin: fake.get('brevo').endpoint, sms_origin: fake.get('fake_sms').endpoint,
        mode: 'disabled', probe_directory: probes, policies: providers.map(provider => ({ provider, account, purpose: provider === 'fake_sms' ? 'sms.send' : 'email.send', window_ms: '1000', limit: 4 })) } };
    service = await operator.startService({ config });
    // A stable service endpoint lets closure-owned original recovery survive an
    // actual host restart without exporting secrets into a saved plan.
    config.listen = new URL(service.endpoint).host;
    const issued = await operator.issueIdentity({ identity, request: { tenant, actor, epoch: 0, ttl: 1800, key_id: 'local' }, privateKeyPem });
    const adminToken = issued.token; secrets.add(adminToken);
    let admin = connect({ endpoint: service.endpoint, credential: adminToken });
    const graph = structuredClone(await admin.call('access.describe', { model }));
    graph.graph.principals.find(principal => principal.id === actor).grants.contracts['1001'] = ['use'];
    graph.graph.principals.push(...[[child, true], [disabled, false]].map(([id, active]) => ({
      id, kind: 'user', parents: [actor], active, login_access: true, credential_epoch: 0, grants: { admin: false, contracts: {} },
    })));
    await admin.call('access.replace', { model, if_revision: graph.revision, graph: graph.graph });
    const credentials = new Map();
    for (const provider of providers) {
      const id = randomUUID(); credentials.set(provider, id);
      await admin.execute(await admin.prepareCredential({ model, id, if_version: null, metadata: {
        label: 'private authentication fixture', provider, account, enabled: true, scopes: [provider === 'fake_sms' ? 'sms.send' : 'email.send'],
      } }, Buffer.from(JSON.stringify({ api_key: providerKeys.get(provider) }))));
    }
    const emailId = randomUUID(), phoneId = randomUUID(), disabledId = randomUUID();
    await admin.execute(await admin.prepare({ model, commands: [
      { op: 'create', id: emailId, contract: 1003, owner: child, fields: { kind: 'email', value: ' SIGNIN@EXAMPLE.COM ' } },
      { op: 'create', id: phoneId, contract: 1003, owner: child, fields: { kind: 'phone', value: ` ${phone} ` } },
      { op: 'create', id: disabledId, contract: 1003, owner: disabled, fields: { kind: 'email', value: 'disabled@example.com' } },
    ], returning: [] }));
    config.authentication = { keyring: proofKeyring, active_signing_key: 'local', signing_keys: { local: signingKey },
      policies: [emailProvider, 'fake_sms'].map(provider => ({ kind: provider === 'fake_sms' ? 'phone' : 'email', revision: randomUUID(),
        credential: credentials.get(provider), owner: actor, provider, account, sender: provider === 'fake_sms' ? null : sender })) };
    await operator.stopService({ service: service.service }); service = null;
    config.email.mode = 'delivery'; service = await operator.startService({ config });
    admin = connect({ endpoint: service.endpoint, credential: adminToken });
    const endpoint = service.endpoint;
    async function settled() { return until(() => operator.check(), result => result.effects.unresolved === 0, 'authentication effect did not settle'); }
    async function delivered(provider, count) {
      const rows = await until(() => fake.get(provider).deliveries(), rows => rows.length >= count, 'private fake did not receive authentication delivery');
      const delivery = rows[count - 1]; assert.match(delivery.code, /^[0-9]{6}$/); secrets.add(delivery.code); return delivery;
    }
    function prepareBegin(identifier) { return prepareAuthentication({ endpoint, identifier }); }
    function prepareConsume(challenge, code) { return prepareCodeProof({ endpoint, challenge, code }); }
    function rememberAccepted(result) { assert.equal(result.status, 'accepted'); secrets.add(result.challenge); return result; }

    await fake.get(emailProvider).setMode('lost_response');
    const emailBegin = prepareBegin({ kind: 'email', value: ' SIGNIN@EXAMPLE.COM ' });
    assert.throws(() => JSON.stringify(emailBegin), /cannot be saved/);
    await assert.rejects(savePlan(path.join(directory, 'forbidden-proof-plan.json'), emailBegin));
    const emailChallenge = rememberAccepted(await emailBegin.execute());
    assert.deepEqual(await emailBegin.status(), emailChallenge); assert.deepEqual(await emailBegin.execute(), emailChallenge);
    assert.deepEqual(await prepareBegin({ kind: 'email', value: recipient }).execute(), emailChallenge,
      'a distinct begin operation coalesces its current handle and expiry');
    const emailDelivery = await delivered(emailProvider, 1);
    await until(() => fake.get(emailProvider).counts(emailDelivery.execution), counts => counts.observations >= 1, 'lost response was not reconciled');
    await settled();
    const emailCounts = await fake.get(emailProvider).counts(emailDelivery.execution);
    assert.equal(emailCounts.submissions, 1); assert.equal(emailCounts.accepted, 1);
    const emailConsume = prepareConsume(emailChallenge.challenge, emailDelivery.code);
    const emailSession = await emailConsume.execute(); assert.equal(emailSession.status, 'authenticated'); secrets.add(emailSession.token);
    assert.deepEqual(await emailConsume.execute(), emailSession); assert.deepEqual(await emailConsume.status(), emailSession);
    const claims = JSON.parse(Buffer.from(emailSession.token.split('.')[1], 'base64url').toString('utf8'));
    assert.equal(claims.sub, child); assert.equal(claims.tenant, tenant); assert.equal(claims.exp - claims.iat, 900); assert.equal(claims.iat, claims.nbf);
    let user = connect({ endpoint, credential: emailSession.token });
    const userScope = await user.call('session.describe'); assert.equal(userScope.actor, child);
    assert.equal(await user.call('records.get', { model, id: emailId }), null, 'proof does not grant Identity Read');
    await assert.rejects(user.execute(await user.prepare({ model, commands: [{ op: 'create', id: randomUUID(), contract: 1003,
      fields: { kind: 'email', value: 'ungranted@example.com' } }], returning: [] })), { code: 'forbidden' });

    const phoneBegin = prepareBegin({ kind: 'phone', value: phone }); const phoneChallenge = rememberAccepted(await phoneBegin.execute());
    const phoneDelivery = await delivered('fake_sms', 1); await settled();
    for (let i = 0; i < 4; i++) {
      const wrong = prepareConsume(phoneChallenge.challenge, wrongCode(phoneDelivery.code));
      assert.deepEqual(await wrong.execute(), { status: 'invalid_proof' }); assert.deepEqual(await wrong.status(), { status: 'invalid_proof' });
    }
    const phoneConsume = prepareConsume(phoneChallenge.challenge, phoneDelivery.code);
    const phoneSession = await phoneConsume.execute(); assert.equal(phoneSession.status, 'authenticated'); secrets.add(phoneSession.token);
    assert.deepEqual(await phoneConsume.status(), phoneSession);
    assert.deepEqual(await prepareConsume(phoneChallenge.challenge, phoneDelivery.code).execute(), { status: 'invalid_proof' }, 'successful fifth proof cannot be used twice');
    const exhaustedBegin = prepareBegin({ kind: 'phone', value: phone }); const exhausted = rememberAccepted(await exhaustedBegin.execute());
    const nextPhoneDelivery = await delivered('fake_sms', 2); await settled();
    for (let i = 0; i < 5; i++) assert.deepEqual(await prepareConsume(exhausted.challenge, wrongCode(nextPhoneDelivery.code)).execute(), { status: 'invalid_proof' });
    assert.deepEqual(await prepareConsume(exhausted.challenge, nextPhoneDelivery.code).execute(), { status: 'invalid_proof' }, 'correct sixth attempt remains invalid');

    const countsBeforeSuppressed = await Promise.all(providers.map(provider => fake.get(provider).counts()));
    const absentEvidence = { operation_id: randomUUID(), recovery_secret: randomBytes(32).toString('base64url'), identifier: { kind: 'email', value: 'absent@example.com' } };
    secrets.add(absentEvidence.recovery_secret);
    const absentResponse = await fetch(new URL('/auth/begin', endpoint), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(absentEvidence) });
    assert.equal(absentResponse.headers.get('cache-control'), 'no-store');
    const absent = rememberAccepted(await absentResponse.json());
    assert.deepEqual(await prepareBegin(absentEvidence.identifier).execute(), absent,
      'absent identifiers coalesce exactly like known identifiers');
    const disabledBegin = prepareBegin({ kind: 'email', value: 'disabled@example.com' }); const disabledChallenge = rememberAccepted(await disabledBegin.execute());
    for (const challenge of [absent.challenge, disabledChallenge.challenge]) assert.deepEqual(await prepareConsume(challenge, '000042').execute(), { status: 'invalid_proof' });
    await settled(); assert.deepEqual(await Promise.all(providers.map(provider => fake.get(provider).counts())), countsBeforeSuppressed);

    // Decode only the privileged backup to locate private execution/source IDs for
    // negative public tests; neither the catalog nor a production endpoint reveals them.
    const backupPath = path.join(directory, 'verified-auth.backup.json'); await operator.snapshot({ destination: backupPath });
    const backupBytes = await readFile(backupPath); const backup = JSON.parse(backupBytes);
    const checked = checkBackupStructure(backupBytes, { catalog }); assert.equal(checked.status, 'passed');
    assert.equal(checked.identityClaimCount, 3);
    assert.equal(checked.proofChallengeCount, 5); assert.equal(checked.proofReceiptCount, 22);
    assert.equal(checked.proofAttemptCount, 11); assert.equal(checked.proofIssuanceCount, 2);
    const privateExecutions = backup.payload.tables.effect_executions.map(decodeRow);
    assert.equal(privateExecutions.length, 3);
    const publicPage = await admin.call('records.page', { model, query: { path: 'records.by_id', contract: null, equals: null }, limit: 32, visit_budget: 128, cursor: null });
    for (const execution of privateExecutions) {
      assert.equal(execution.action_version, 'auth-delivery-1'); assert.equal(execution.application, 'not_required');
      assert.equal(await admin.call('records.get', { model, id: execution.source }), null);
      assert.equal(await admin.call('effects.status', { model, execution_id: execution.id }), null);
      assert.equal(await user.call('effects.status', { model, execution_id: execution.id }), null);
      assert.equal(JSON.stringify(publicPage).includes(execution.source), false);
      await assert.rejects(admin.call('effects.cancel', { model, context: (await admin.call('session.describe')).operation_context,
        operation_id: randomUUID(), execution_id: execution.id, if_revision: execution.revision }), { code: 'forbidden' });
    }
    for (const operation_id of [emailBegin.operationId, phoneBegin.operationId]) assert.deepEqual(await admin.call('operations.status', {
      model, context: (await admin.call('session.describe')).operation_context, operation_id,
    }), { status: 'not_observed' }, 'ordinary operation receipts cannot disclose anonymous proof evidence');
    for (const rows of Object.values(backup.payload.tables)) for (const row of rows) {
      if (typeof row.value !== 'string') continue;
      const text = Buffer.from(row.value, 'hex').toString('utf8');
      for (const secret of secrets) assert.equal(text.includes(secret.length === 6 ? `"${secret}"` : secret), false, 'private native backup leaked a proof or custody secret');
    }
    const inspection = JSON.stringify(await operator.inspect());
    for (const secret of [emailChallenge.challenge, phoneChallenge.challenge, emailSession.token, phoneSession.token, absentEvidence.recovery_secret]) assert.equal(inspection.includes(secret), false);
    assert.equal((await operator.check()).status, 'valid');
    await operator.stopService({ service: service.service }); service = null;
    await native.close(); native = null;

    // Real process restart preserves generation and original issuance, including
    // exact JWT bytes and pinned times. It does not spend another attempt or send.
    native = await openNative(nativeConfig(directory, { mode: 'open', path: storePath, expect_store: storeId }));
    operator = openOperator(native, { scope: native.scope, methods });
    service = await operator.startService({ config }); assert.equal(service.endpoint, endpoint);
    assert.deepEqual(await emailConsume.status(), emailSession); assert.deepEqual(await phoneConsume.status(), phoneSession);
    user = connect({ endpoint, credential: emailSession.token }); assert.equal((await user.call('session.describe')).actor, child);
    await settled(); assert.deepEqual(await Promise.all(providers.map(provider => fake.get(provider).counts())), countsBeforeSuppressed);
    assert.equal((await operator.check()).status, 'valid');
    await operator.stopService({ service: service.service }); service = null;
    const restoredPath = path.join(directory, 'restored.redb');
    const restored = await operator.restore({ backup: backupPath, expectBackupStore: storeId,
      destination: { backend: { kind: 'redb', cluster_file: null }, target: { path: restoredPath } } });
    assert.equal(restored.status, 'restored'); assert.equal(restored.integrity.effects.quarantined, true);
    await native.close(); native = null;
    native = await openNative(nativeConfig(directory, { mode: 'open', path: restoredPath, expect_store: storeId }));
    operator = openOperator(native, { scope: native.scope, methods });
    service = await operator.startService({ config: { ...config, email: { ...config.email, mode: 'reconcile' } } });
    assert.deepEqual(await emailConsume.status(), { status: 'unavailable' }); assert.deepEqual(await phoneConsume.status(), { status: 'unavailable' });
    assert.deepEqual(await emailBegin.status(), { status: 'unavailable' });
    await assert.rejects(user.call('session.describe'), error => ['unauthenticated', 'forbidden'].includes(error.code));
    const freshAdmin = await operator.issueIdentity({ identity, request: { tenant, actor, epoch: 0, ttl: 900, key_id: 'local' }, privateKeyPem });
    const freshClaims = JSON.parse(Buffer.from(freshAdmin.token.split('.')[1], 'base64url').toString('utf8'));
    assert.notEqual(freshClaims.generation, claims.generation);
    assert.deepEqual(await prepareBegin({ kind: 'email', value: recipient }).execute(), { status: 'unavailable' }, 'restored proof remains quarantined');
    const restoredCheck = await operator.check(); assert.equal(restoredCheck.status, 'valid'); assert.equal(restoredCheck.effects.quarantined, true);
    assert.deepEqual(await Promise.all(providers.map(provider => fake.get(provider).counts())), countsBeforeSuppressed);
    const restoredBackup = path.join(directory, 'restored-auth.backup.json'); await operator.snapshot({ destination: restoredBackup });
    const restoredBytes = await readFile(restoredBackup); assert.equal(checkBackupStructure(restoredBytes, { catalog }).status, 'passed');
    assert.deepEqual(JSON.parse(restoredBytes).payload.tables.effect_facts, backup.payload.tables.effect_facts, 'supported restore preserves original remote facts');
  } finally {
    const closed = await Promise.allSettled([native?.close(), ...[...fake.values()].map(provider => provider.close())]);
    await rm(directory, { recursive: true, force: true });
    for (const result of closed) if (result.status === 'rejected') process.stderr.write(`Authentication fixture cleanup: ${result.reason?.code ?? 'failed'}\n`);
  }
});
