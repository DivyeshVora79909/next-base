import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { connect, savePlan } from '../client.mjs';
import { resolveConfig } from '../config.mjs';
import { prepareModel } from '../model.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';
import { checkBackupStructure } from '../storage-check.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const binary = process.env.REBASE_NODE_N2_BINARY ?? path.join(root, 'target/debug/rebase-next');

test('A0 real signed HTTP preserves JWT recency, exact identity claims and secret-free original receipts', {
  skip: !existsSync(binary) && `native binary not found: ${binary}`,
}, async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'next-base-a0-identity-'));
  let native;
  try {
    const tenant = randomUUID(), actor = randomUUID(), child = randomUUID(), outside = randomUUID();
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const identity = { issuer: 'a0-independent-signing-fixture', audience: 'a0-test', max_token_seconds: 3600,
      public_keys: { local: publicKey.export({ type: 'spki', format: 'pem' }).toString() } };
    // Independently encode and sign exact issuance times. This must pass the real
    // HTTP verifier; a Store session or client-authored timestamp is insufficient.
    function token(subject, age = 0, epoch = 0) {
      const now = Math.floor(Date.now() / 1000), issued = now - age;
      const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT', kid: 'local' })).toString('base64url');
      const claims = Buffer.from(JSON.stringify({ iss: identity.issuer, aud: identity.audience,
        sub: subject, tenant, epoch, iat: issued, nbf: issued, exp: now + 600 })).toString('base64url');
      const input = `${header}.${claims}`;
      return `${input}.${sign(null, Buffer.from(input), privateKey).toString('base64url')}`;
    }
    const methods = ['store.check', 'store.inspect', 'store.backup', 'service.start', 'service.stop'];
    native = await openNative(resolveConfig({ overrides: { native: { binary, environment: {}, configuration: {
      model: 'services', backend: { kind: 'redb', cluster_file: null },
      target: { mode: 'create', path: path.join(directory, 'store.redb'), tenant, actor }, operator_methods: methods,
    } } } }));
    const operator = openOperator(native, { scope: native.scope, methods });
    const catalog = await native.catalog({ scope: 'developer' });
    const prepared = prepareModel(catalog, { native, selector: 'services' }); const model = prepared.identity;
    assert.equal(catalog.capabilities.identities.contract, 1003);
    const service = await operator.startService({ config: { listen: '127.0.0.1:0', identity,
      max_inflight: 4, request_timeout_seconds: 10, effects: null, credentials: null, email: null } });
    const freshToken = token(actor), staleToken = token(actor, 601);
    const fresh = connect({ endpoint: service.endpoint, credential: freshToken });
    const stale = connect({ endpoint: service.endpoint, credential: staleToken });
    const future = connect({ endpoint: service.endpoint, credential: token(actor, -60) });
    await assert.rejects(future.call('session.describe'), { code: 'unauthenticated' });
    const access = structuredClone(await fresh.call('access.describe', { model }));
    access.graph.principals.push(...[[child, actor], [outside, tenant]].map(([id, parent]) => ({
      id, kind: 'user', parents: [parent], active: true, credential_epoch: 0,
      grants: { admin: false, contracts: { 1003: ['read', 'create', 'update', 'delete'] } },
    })));
    await fresh.call('access.replace', { model, if_revision: access.revision, graph: access.graph });
    const email = randomUUID(), phone = randomUUID();
    const draft = prepared.draftFixture([
      { contract: 'Identity', id: email, fields: { kind: 'email', value: ' Alice@EXAMPLE.COM ' } },
      { contract: 'Identity', id: phone, fields: { kind: 'phone', value: ' +919876543210 ' } },
    ], { returning: [email, phone] });
    assert.equal(draft.commands[0].fields.value, 'alice@example.com');
    assert.equal(draft.commands[1].fields.value, '+919876543210');
    const plan = await fresh.prepare(draft), planPath = path.join(directory, 'identity-plan.json');
    await savePlan(planPath, plan);
    const saved = await readFile(planPath, 'utf8');
    assert.equal(saved.includes(freshToken), false); assert.equal(saved.includes('incarnation'), false);
    // A valid, unexpired JWT may read and prepare a plan but still be too old
    // for self management. Rejection publishes no source or uniqueness claim.
    await assert.rejects(stale.execute(plan), { code: 'forbidden' });
    assert.equal(await fresh.call('records.get', { model, id: email }), null);
    const receipt = await fresh.execute(JSON.parse(saved)); assert.equal(receipt.status, 'committed');
    assert.equal((await stale.execute(plan)).replayed, true);
    assert.equal((await stale.status(plan)).status, 'committed');
    const before = await fresh.call('records.get', { model, id: email });
    assert.deepEqual(before.derived, { identity_revision: '1', verified_revision: null, verified_at: null });
    assert.equal(before.input.value, 'alice@example.com');
    const create = (id, owner, value) => ({ op: 'create', id, contract: 1003, owner, fields: { kind: 'email', value } });
    const change = (record, set, extra = {}) => ({ op: 'update', id: record.id, if_version: record.version, set, unset: [], ...extra });
    const prepare = (client, commands, returning = []) => client.prepare({ model, commands, returning });
    await assert.rejects(fresh.execute(await prepare(fresh, [create(randomUUID(), actor, 'ALICE@example.com')])), { code: 'identity_duplicate' });
    await assert.rejects(stale.execute(await prepare(stale, [change(before, { value: 'new@example.com' })])), { code: 'forbidden' });
    await assert.rejects(fresh.execute(await prepare(fresh, [change(before, {}, { owner: child })])), { code: 'invalid_input' });
    const noop = await prepare(fresh, [change(before, { value: ' ALICE@EXAMPLE.COM ' })], [email]);
    await fresh.execute(noop);
    assert.deepEqual(await fresh.call('records.get', { model, id: email }), before);
    const updated = await fresh.execute(await prepare(fresh, [change(before, { value: 'new@example.com' })], [email]));
    assert.equal(updated.result.records[0].record.derived.identity_revision, '2');
    assert.equal(updated.result.records[0].record.created_at, before.created_at);
    const childIdentity = randomUUID();
    await stale.execute(await prepare(stale, [create(childIdentity, child, 'child@example.com')]));
    await assert.rejects(fresh.execute(await prepare(fresh, [create(randomUUID(), outside, 'outside@example.com')])), { code: 'forbidden' });
    const outsideClient = connect({ endpoint: service.endpoint, credential: token(outside) });
    assert.equal(await outsideClient.call('records.get', { model, id: email }), null);
    assert.equal((await operator.check()).status, 'valid');
    const backupPath = path.join(directory, 'identity.backup.json'); await operator.snapshot({ destination: backupPath });
    const backup = await readFile(backupPath); const checked = checkBackupStructure(backup, { catalog, includeObservation: true });
    assert.equal(checked.status, 'passed'); assert.equal(checked.identityClaimCount, 3); assert.equal(checked.authenticationRevisionCount, 2);
    const image = JSON.parse(backup).payload.tables.native_kv;
    const privateIncarnations = image.filter(row => row.key.startsWith('01')).map(row => JSON.parse(Buffer.from(row.value, 'hex')).data)
      .filter(source => source.contract === 1003).map(source => source.derived.incarnation);
    const inspection = await operator.inspect();
    for (const incarnation of privateIncarnations) {
      assert.equal(JSON.stringify(inspection).includes(incarnation), false);
      assert.equal(JSON.stringify(checked).includes(incarnation), false);
      assert.equal(JSON.stringify(receipt).includes(incarnation), false);
    }
    // Last-factor deletion remains ordinary authorized CRUD; no factor count
    // or verification-presence restriction is silently added by the tools.
    const current = await fresh.call('records.get', { model, id: email });
    const currentPhone = await fresh.call('records.get', { model, id: phone });
    await fresh.execute(await prepare(fresh, [current, currentPhone].map(record => ({
      op: 'delete', id: record.id, if_version: record.version,
    }))));
    assert.equal(await fresh.call('records.get', { model, id: email }), null);
    assert.equal(await fresh.call('records.get', { model, id: phone }), null);
    assert.equal((await operator.check()).status, 'valid');
    await operator.stopService({ service: service.service });
  } finally {
    await native?.close();
    await rm(directory, { recursive: true, force: true });
  }
});
