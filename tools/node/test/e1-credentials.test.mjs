import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { connect, savePlan } from '../client.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';
import { resolveConfig } from '../config.mjs';
import { prepareModel } from '../model.mjs';
import { checkBackupStructure } from '../storage-check.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const binary = process.env.REBASE_NODE_N2_BINARY ?? path.join(root, 'target/debug/rebase-next');

test('E1 real HTTP encrypted plan, authority, grants, rotation, atomic rejection and backup', {
  skip: !existsSync(binary) && `native binary not found: ${binary}`,
}, async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'next-base-e1-'));
  let native;
  try {
    const tenant = randomUUID(); const actor = randomUUID(); const id = randomUUID();
    const keyring = path.join(directory, 'keys.json');
    const key = key_id => ({ key_id, key: randomBytes(32).toString('base64url') });
    await writeFile(keyring, JSON.stringify({ format: 'rebase-credential-keyring-1',
      active_ingress: 'ingress', ingress: [key('ingress')], active_at_rest: 'vault', at_rest: [key('vault')],
      active_grant: 'grant', grants: [key('grant')] }), { mode: 0o600 });
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const identity = { issuer: 'e1-test', audience: 'e1-test', max_token_seconds: 300,
      public_keys: { local: publicKey.export({ type: 'spki', format: 'pem' }).toString() } };
    const methods = ['store.check', 'store.inspect', 'store.backup', 'service.start', 'service.stop', 'identity.issue',
      'credentials.plan', 'credentials.rewrap', 'credentials.verify'];
    native = await openNative(resolveConfig({ overrides: { native: { binary, environment: {}, configuration: {
      model: 'services', backend: { kind: 'redb', cluster_file: null },
      target: { mode: 'create', path: path.join(directory, 'store.redb'), tenant, actor }, operator_methods: methods,
    } } } }));
    const operator = openOperator(native, { scope: native.scope, methods });
    const catalog = await native.catalog({ scope: 'developer' });
    const model = prepareModel(catalog, { native, selector: 'services' });
    assert.ok(catalog.capabilities.methods.includes('credentials.write_secret'));
    const live = await operator.startService({ config: { listen: '127.0.0.1:0', identity, max_inflight: 4,
      request_timeout_seconds: 10, effects: null, credentials: { keyring, platform: [] } } });
    const { token } = await operator.issueIdentity({ identity, request: { tenant, actor, epoch: 0, ttl: 300, key_id: 'local' },
      privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() });
    const client = connect({ endpoint: live.endpoint, credential: token });
    const metadata = { label: 'mail', provider: 'resend', account: 'test-account', enabled: true, scopes: ['email.send'] };
    assert.equal(model.validate('Credential', metadata).valid, true);
    const marker = `PRIVATE_TEST_KEY_${randomUUID()}`;
    const secret = Buffer.from(JSON.stringify({ api_key: marker }));
    const plan = await client.prepareCredential({ model: model.identity, id, if_version: null, metadata }, secret);
    const destination = path.join(directory, 'sealed-plan.json');
    await savePlan(destination, plan);
    await assert.rejects(savePlan(destination, plan), { code: 'EEXIST' });
    const saved = await readFile(destination, 'utf8');
    assert.equal(saved.includes(marker), false);
    assert.equal(plan.kind, 'credential-write');
    for (const malformed of [
      { ...plan, method: 'arbitrary.send' }, { ...plan, kind: 'arbitrary' },
      { ...plan, request: { ...plan.request, sealed_secret: { api_key: marker } } },
      { ...plan, request: { ...plan.request, owner: null } },
    ]) await assert.rejects(client.execute(malformed), { code: 'invalid_plan' });
    const tampered = structuredClone(plan); tampered.request.metadata.label = 'changed';
    await assert.rejects(client.execute(tampered), { code: 'credential_crypto' });
    assert.equal(await client.call('records.get', { model: model.identity, id }), null);
    const committed = await client.execute(JSON.parse(saved));
    assert.equal(committed.status, 'committed');
    assert.equal((await client.execute(plan)).replayed, true);
    assert.equal((await client.status(plan)).status, 'committed');
    const first = await client.call('records.get', { model: model.identity, id });
    assert.deepEqual(first.derived, { has_secret: true, secret_revision: '1', use_epoch: '0' });
    assert.equal(JSON.stringify(committed).includes('ciphertext'), false);
    const email = { sender: 'sender@example.com', to: ['one@example.com'], subject: 'subject', text: 'body' };
    const authorize = { model: model.identity, email, selection: { kind: 'byoc', credential: id }, ttl_seconds: 60 };
    await assert.rejects(client.call('email.authorize', authorize), { code: 'forbidden' });
    const access = await client.call('access.describe', { model: model.identity });
    access.graph.principals.find(p => p.id === actor).grants.contracts['1001'] = ['use'];
    await client.call('access.replace', { model: model.identity, if_revision: access.revision, graph: access.graph });
    const grant = await client.call('email.authorize', authorize);
    assert.deepEqual(Object.keys(grant).sort(), ['expires_at', 'grant']);
    assert.equal(Buffer.from(grant.grant, 'base64url').includes(Buffer.from(id)), false);
    const rotated = await client.prepareCredential({ model: model.identity, id, if_version: first.version, metadata }, secret);
    await client.execute(rotated);
    const second = await client.call('records.get', { model: model.identity, id });
    assert.equal(second.derived.secret_revision, '2');
    assert.equal(second.derived.use_epoch, '0');
    assert.equal(second.created_at, first.created_at);
    secret.fill(0);
    assert.equal((await operator.check()).status, 'valid');
    const backupPath = path.join(directory, 'backup.json');
    await operator.snapshot({ destination: backupPath });
    const backup = await readFile(backupPath);
    assert.equal(backup.includes(Buffer.from(marker)), false);
    const checked = checkBackupStructure(backup, { catalog });
    assert.equal(checked.status, 'passed');
    await assert.rejects(operator.prepareRewrap({ ids: [id] }), { code: 'service_running' });
    await operator.stopService({ service: live.service });
    const custody = await operator.verifyCredentials({ keyring });
    assert.equal(custody.status, 'verified');
    assert.equal(custody.secret_envelopes, 1);
    const rewrap = await operator.prepareRewrap({ ids: [id] });
    const rewrapPath = path.join(directory, 'rewrap.json');
    await writeFile(rewrapPath, JSON.stringify(rewrap), { mode: 0o600, flag: 'wx' });
    const keys = JSON.parse(await readFile(keyring, 'utf8'));
    keys.at_rest.push(key('next-vault')); keys.active_at_rest = 'next-vault';
    await writeFile(keyring, JSON.stringify(keys), { mode: 0o600 });
    assert.equal((await operator.rewrapCredentials({ keyring, request: rewrap })).status, 'committed');
    assert.equal((await operator.rewrapCredentials({ keyring, request: rewrap })).replayed, true);
    assert.equal((await operator.verifyCredentials({ keyring })).status, 'verified');
    keys.at_rest = keys.at_rest.filter(k => k.key_id === 'next-vault');
    await writeFile(keyring, JSON.stringify(keys), { mode: 0o600 });
    assert.equal((await operator.verifyCredentials({ keyring })).status, 'verified');
  } finally { await native?.close(); await rm(directory, { recursive: true, force: true }); }
});
