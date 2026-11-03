import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { checkProofInventory, checkRuntimeHeader } from '../private/proof-storage.mjs';
import { checkBackupStructure } from '../storage-check.mjs';
import { validateCredentialMetadata } from '../credentials.mjs';

const id = n => `00000000-0000-0000-0000-${n.toString(16).padStart(12, '0')}`;
const hex = value => Buffer.from(value).toString('hex');
const idKey = value => value.replaceAll('-', '');
const row = (key, value) => ({ key, value: hex(JSON.stringify(value)) });
const envelope = () => ({ key_id: 'proof-key', nonce: Buffer.alloc(24, 7).toString('base64url'), ciphertext: Buffer.alloc(42, 8).toString('base64url') });
const header = { format: 'rebase-store-11', store_id: id(50), session_generation: id(51), cursor_key: '12'.repeat(32), operation_epoch: '0' };
const stable = value => Array.isArray(value) ? `[${value.map(stable).join(',')}]`
  : value && typeof value === 'object' ? `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${stable(value[k])}`).join(',')}}` : JSON.stringify(value);

function fixture() {
  const policy = { kind: 'phone', revision: id(8), credential: id(30), owner: id(2), provider: 'fake_sms', account: 'test-sms', sender: null };
  const challenge = { format: 'auth-proof-1', id: id(9), generation: header.session_generation, operation: id(10), source: id(12), execution: id(11),
    created_at: '1000', expires_at: '301000', previous: null, binding: { identity: id(20), incarnation: id(21), owner: id(2), identity_revision: '1',
      authentication_revision: '1', credential_epoch: '0', policy }, key_id: 'proof-key', verifier: Buffer.alloc(32, 0xcd).toString('base64url'), nonce: id(13),
    handle_digest: Buffer.alloc(32, 0xde).toString('base64url'), identifier_digest: Buffer.alloc(32, 0x33).toString('base64url'), response: envelope(), attempts: 0, consumed: false };
  const source = { contract: 1004, tenant: id(1), owner: id(2), created_at: '1000', derived: null,
    input: { challenge: challenge.id, generation: challenge.generation, payload: envelope(), expires_at: challenge.expires_at } };
  const execution = { id: id(11), source: id(12), target: id(12), tenant: id(1), store: header.store_id, requester: id(2), operation_id: id(10), credential_epoch: 0,
    request: source.input, email_binding: { credential: id(30), incarnation: id(31), provider: 'fake_sms', account: 'test-sms', use_epoch: '0', secret_revision: '1',
      selection: null, server_policy: policy, purpose: 'sms.send' }, email_starts: [] };
  const receipts = [{ format: 'auth-proof-1', operation: id(10), generation: challenge.generation, key_id: 'proof-key', recovery: Buffer.alloc(32, 0x11).toString('base64url'), fingerprint: Buffer.alloc(32, 0x22).toString('base64url'),
    created_at: '1000', admission: [{ key: Buffer.alloc(32, 0x33).toString('base64url'), at: '1000', consume: false }, { key: Buffer.alloc(32, 0x44).toString('base64url'), at: '1000', consume: false }], outcome: { kind: 'begin', challenge: challenge.id } }];
  const records = new Map([[id(12), source]]), executions = new Map([[idKey(execution.id), execution]]);
  const runtime = { format: 'auth-proof-1', admission_key_id: 'proof-key', last_at: '1000', challenges: 1, receipts: 1, points: receipts[0].admission.slice() };
  const state = { challenge, receipts, records, executions, runtime };
  state.tables = () => ({ auth_challenges: [row(idKey(challenge.id), challenge)], auth_receipts: receipts.map(r => row(idKey(r.operation), r)),
    auth_handles: [row(hex(challenge.handle_digest), challenge.id)], auth_heads: [row(idKey(challenge.binding.incarnation), challenge.id)], auth_runtime: [row(hex('state'), runtime)] });
  return state;
}
function consume(f, { success = false, spent = true } = {}) {
  const now = String(1000 + f.receipts.length), operation = id(100 + f.receipts.length);
  const outcome = success ? { kind: 'issued', challenge: f.challenge.id, issuance: { key_id: 'signing-key', claims: {
    iss: 'test', aud: 'test', sub: id(2), tenant: id(1), epoch: 0, generation: header.session_generation, iat: 1, nbf: 1, exp: 901 } } }
    : { kind: 'invalid', challenge: spent ? f.challenge.id : null, spent };
  const admission = [{ key: Buffer.alloc(32, 0x55).toString('base64url'), at: now, consume: true }];
  f.receipts.push({ format: 'auth-proof-1', operation, generation: header.session_generation, key_id: 'proof-key', recovery: Buffer.alloc(32, 0x66).toString('base64url'), fingerprint: Buffer.alloc(32, 0x77).toString('base64url'), created_at: now, admission, outcome });
  f.runtime.last_at = now; f.runtime.receipts += 1; f.runtime.points.push(...admission);
  if (spent || success) f.challenge.attempts += 1;
  if (success) f.challenge.consumed = true;
}
function check(f, tables = f.tables()) { return checkProofInventory(tables, f.records, f.executions, { tenant: id(1) }, header); }

test('proof inventories derive attempts and one-use from immutable receipts, including correct fifth and unspent sixth', () => {
  const f = fixture();
  for (let i = 0; i < 4; i += 1) consume(f);
  consume(f, { success: true }); consume(f, { spent: false });
  assert.deepEqual(check(f), { proofInventory: 'checked', proofChallengeCount: 1, proofReceiptCount: 7, proofAttemptCount: 5,
    proofIssuanceCount: 1, proofCryptographicAuthentication: 'not_evaluated' });
  for (const change of [f => { f.challenge.attempts = 4; }, f => { f.challenge.consumed = false; },
    f => { f.receipts.pop(); f.receipts.pop(); }, f => { consume(f, { success: true }); },
    f => { f.receipts[5].outcome.issuance.claims.exp += 1; }, f => { f.receipts[5].outcome.issuance.claims.generation = id(90); }]) {
    const copy = fixture(); for (let i = 0; i < 4; i += 1) consume(copy); consume(copy, { success: true }); consume(copy, { spent: false });
    change(copy); assert.throws(() => check(copy), /Private proof inventory/);
  }
});

test('proof inventories reject missing heads, predecessor cycles, stale handle caches, source and execution mismatches', () => {
  for (const change of [f => { f.challenge.previous = f.challenge.id; }, f => { f.challenge.created_at = '999'; },
    f => { f.executions.values().next().value.requester = id(99); }, f => { f.records.get(id(12)).owner = id(99); },
    f => { f.challenge.source = id(99); }, f => { f.challenge.verifier = 'not-a-digest'; }, f => { f.challenge.response.plaintext = '000042'; }]) {
    const f = fixture(); change(f); assert.throws(() => check(f), /Private proof inventory/);
  }
  for (const table of ['auth_heads', 'auth_handles', 'auth_receipts', 'auth_runtime']) {
    const f = fixture(), tables = f.tables(); tables[table] = []; assert.throws(() => check(f, tables), /Private proof inventory/);
  }
});

test('proof verification is derived from exact factor incarnation and latest successful issuance', () => {
  const f = fixture(); consume(f, { success: true });
  const identity = { contract: 1003, derived: { incarnation: id(21), identity_revision: '1', verified_revision: '1', verified_at: '1001' } };
  f.records.set(id(20), identity); assert.equal(check(f).proofIssuanceCount, 1);
  identity.derived.verified_at = '1000'; assert.throws(() => check(f), /verification/);
  identity.derived = { incarnation: id(22), identity_revision: '1', verified_revision: null, verified_at: null };
  assert.equal(check(f).proofIssuanceCount, 1, 'historical issuance does not verify a recreated factor');
  identity.derived.verified_revision = '1'; identity.derived.verified_at = '1001'; assert.throws(() => check(f), /verification/);
});

test('proof admission checks multiplicity from receipts and cannot trust copied runtime counts', () => {
  const f = fixture();
  for (let i = 0; i < 3; i += 1) {
    const copy = structuredClone(f.receipts[0]); copy.operation = id(200 + i); f.receipts.push(copy);
    f.runtime.receipts += 1; f.runtime.points.push(...copy.admission);
  }
  assert.throws(() => check(f), /admission limit/);
  const copy = fixture(); copy.runtime.points.pop(); assert.throws(() => check(copy), /admission points/);
});

test('complete backup projection excludes private deliveries and reveals no proof metadata', () => {
  const f = fixture(), tables = f.tables(), catalog = { model: 'proof-test', capabilities: { identities: { contract: 1003 }, credentials: { contract: 1001 } },
    contracts: [1001, 1003, 1004].map(code => ({ code, access_indexes: [] })) };
  const credential = { contract: 1001, tenant: id(1), owner: id(2), created_at: '0', input: { enabled: true, provider: 'fake_sms', account: 'test-sms' },
    derived: { has_secret: true, secret_revision: '1', use_epoch: '0', incarnation: id(31) } };
  const native = (tag, identity, type, data, suffix = '') => row(`${tag}${identity ? idKey(identity) : ''}${suffix}`, { type, data });
  tables.native_kv = [native('00', null, 'meta', { model: catalog.model, tenant: id(1) }), native('01', id(12), 'record', f.records.get(id(12))),
    native('01', id(30), 'record', credential), native('11', id(30), 'credential_secret', { format: 'rebase-credential-secret-2', credential: id(30), incarnation: id(31),
      secret_revision: '1', ...envelope() }, '0000000000000001')];
  for (const name of ['effect_due', 'effect_facts', 'effect_inbox', 'effect_runtime', 'email_rate_scopes', 'email_rate_starts', 'email_rate_points', 'operations', 'public_records', 'query_epochs', 'receipt_slots']) tables[name] = [];
  tables.local_runtime = [row(hex('header'), header)]; tables.effect_executions = [...f.executions].map(([key, value]) => row(key, value));
  const payload = { format: 'rebase-authorized-observation-1', complete: true, tables };
  const backup = JSON.stringify({ format: 'rebase-backup-1', sha256: createHash('sha256').update(stable(payload)).digest('hex'), payload });
  const checked = checkBackupStructure(backup, { catalog, includeObservation: true });
  assert.equal(checked.proofChallengeCount, 1); assert.equal(checked.credentialSecretCount, 1);
  assert.deepEqual(checked.observation.records.map(row => row.id), [id(30)]);
  for (const privateValue of [id(9), id(11), id(12), f.challenge.handle_digest, f.challenge.verifier, 'proof-key', 'fingerprint', 'recovery'])
    assert.equal(JSON.stringify(checked).includes(privateValue), false, 'private proof data is absent from projection');
});

test('runtime generation is mandatory and SMS credential scope cannot authorize email', () => {
  assert.deepEqual(checkRuntimeHeader([row(hex('header'), header)]), header);
  for (const change of [h => { delete h.session_generation; }, h => { h.session_generation = id(0); }, h => { h.format = 'rebase-store-10'; }]) {
    const h = { ...header }; change(h); assert.throws(() => checkRuntimeHeader([row(hex('header'), h)]));
  }
  const metadata = { label: 'SMS', provider: 'fake_sms', account: 'sms', enabled: true, scopes: ['sms.send'] };
  assert.deepEqual(validateCredentialMetadata(metadata), metadata);
  assert.throws(() => validateCredentialMetadata({ ...metadata, scopes: ['email.send'] }));
  assert.throws(() => validateCredentialMetadata({ ...metadata, provider: 'resend' }));
});

test('authentication email policies preserve canonical sender local-part case for both email providers', () => {
  for (const provider of ['resend', 'brevo']) {
    const f = fixture(), policy = f.challenge.binding.policy;
    Object.assign(policy, { kind: 'email', provider, sender: 'Sender@example.com' });
    Object.assign(f.executions.values().next().value.email_binding, { provider, purpose: 'email.send' });
    assert.equal(check(f).proofChallengeCount, 1);
    for (const sender of ['Sender@EXAMPLE.COM', ' Sender@example.com', 'Sender@example.com ', 'Sender..alias@example.com', 'Sender@-example.com']) {
      policy.sender = sender;
      assert.throws(() => check(f), /policy channel differs/);
    }
  }
});

test('proof receipts require matching generation and the half-open challenge lifetime', () => {
  function retime(f, index, at) {
    const receipt = f.receipts[index]; receipt.created_at = at;
    for (const point of receipt.admission) point.at = at;
    if (receipt.outcome.kind === 'issued') {
      const claims = receipt.outcome.issuance.claims;
      claims.iat = claims.nbf = Number(BigInt(at) / 1000n); claims.exp = claims.iat + 900;
    }
    f.runtime.last_at = f.receipts.reduce((max, row) => BigInt(row.created_at) > BigInt(max) ? row.created_at : max, '0');
    f.runtime.points = f.receipts.flatMap(row => row.admission).filter(point => BigInt(point.at) > BigInt(f.runtime.last_at) - 300_000n);
  }
  for (const outcome of ['begin', 'invalid', 'issued']) {
    const make = () => {
      const f = fixture();
      if (outcome !== 'begin') consume(f, { success: outcome === 'issued' });
      else {
        const repeated = structuredClone(f.receipts[0]); repeated.operation = id(200); f.receipts.push(repeated);
        f.runtime.receipts += 1; f.runtime.points.push(...repeated.admission);
      }
      return f;
    };
    const index = 1;
    for (const time of ['1000', '300999']) {
      const f = make(); retime(f, index, time); assert.equal(check(f).proofChallengeCount, 1, `${outcome} at ${time}`);
    }
    for (const time of ['999', '301000', '301001']) {
      const f = make(); retime(f, index, time); assert.throws(() => check(f), /lifetime/, `${outcome} at ${time}`);
    }
    const f = make(); f.receipts[index].generation = id(99);
    assert.throws(() => check(f), /source|claims/);
  }
});

test('original begin time is exact and a later spent attempt cannot follow successful consumption', () => {
  const origin = fixture(); origin.receipts[0].created_at = '1001';
  for (const point of origin.receipts[0].admission) point.at = '1001';
  origin.runtime.last_at = '1001';
  assert.throws(() => check(origin), /original begin time differs/);
  const f = fixture(); consume(f, { success: true }); consume(f);
  assert.throws(() => check(f), /spent attempt follows successful consumption/);
  f.receipts[2].created_at = '1001'; f.receipts[2].admission[0].at = '1001'; f.runtime.last_at = '1001';
  assert.equal(check(f).proofAttemptCount, 2, 'equal timestamps alone do not establish transaction order');
});
