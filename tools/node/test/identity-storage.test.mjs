import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { checkBackupStructure } from '../storage-check.mjs';

const id = n => `00000000-0000-0000-0000-${n.toString(16).padStart(12, '0')}`;
const hex = value => Buffer.from(value).toString('hex');
const catalog = { model: 'identity-storage-test', capabilities: { identities: { contract: 1003 } },
  contracts: [{ code: 1003, access_indexes: [] }] };
const point = (tag, identity, type, data) => ({ key: `${tag}${identity.replaceAll('-', '')}`, value: hex(JSON.stringify({ type, data })) });
const claim = (kind, value, identity, incarnation) => ({ key: `12${kind === 'email' ? '01' : '02'}${hex(value)}`,
  value: hex(JSON.stringify({ type: 'identity_claim', data: { identity, incarnation } })) });
function fixture() {
  const tables = Object.fromEntries(['effect_due', 'effect_executions', 'effect_facts', 'effect_inbox', 'effect_runtime',
    'email_rate_scopes', 'email_rate_starts', 'email_rate_points', 'local_runtime', 'native_kv', 'operations',
    'public_records', 'query_epochs', 'receipt_slots', 'authority', 'owner_records'].map(name => [name, []]));
  tables.authority = [{ key: hex('graph'), value: hex(JSON.stringify({ tenant: id(1), principals: [
    { id: id(1), kind: 'tenant', parents: [], active: true, credential_epoch: 0, grants: { admin: true, contracts: {} } },
    { id: id(2), kind: 'user', parents: [id(1)], active: false, credential_epoch: 0, grants: { admin: false, contracts: {} } },
  ] })) }];
  tables.native_kv = [{ key: '00', value: hex(JSON.stringify({ type: 'meta', data: { model: catalog.model, tenant: id(1) } })) }];
  for (const [identity, incarnation, kind, value, revision, verified] of [
    [id(10), id(20), 'email', 'alice@example.com', '2', false],
    [id(11), id(21), 'phone', '+12345678', '5', true],
  ]) {
    tables.native_kv.push(point('01', identity, 'record', { contract: 1003, tenant: id(1), owner: id(2), created_at: '0',
      input: { kind, value }, derived: { incarnation, identity_revision: revision,
        verified_revision: verified ? revision : null, verified_at: verified ? '0' : null } }));
    tables.native_kv.push(claim(kind, value, identity, incarnation));
  }
  tables.native_kv.push(point('13', id(2), 'authentication_revision', { revision: '5' }));
  return { format: 'rebase-backup-1', sha256: '', payload: { format: 'rebase-authorized-observation-1', complete: true, tables } };
}
function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function check(backup, options = {}) {
  backup.sha256 = createHash('sha256').update(stable(backup.payload)).digest('hex');
  return checkBackupStructure(JSON.stringify(backup), { catalog, ...options });
}
function edit(backup, index, change) {
  const row = backup.payload.tables.native_kv[index], value = JSON.parse(Buffer.from(row.value, 'hex'));
  change(value.data); row.value = hex(JSON.stringify(value));
}

test('identity dictionary is independently derived from canonical source facts and User ownership', () => {
  const backup = fixture();
  const result = check(backup, { includeObservation: true });
  assert.equal(result.identityInventory, 'checked');
  assert.equal(result.identityClaimCount, 2);
  assert.equal(result.authenticationRevisionCount, 1);
  assert.equal(JSON.stringify(result).includes(id(20)), false, 'checked projection does not disclose private incarnation');
  assert.equal(JSON.parse(Buffer.from(backup.payload.tables.native_kv[1].value, 'hex')).data.derived.incarnation, id(20), 'raw backup remains complete');
  assert.equal(check(fixture(), { catalog: undefined }).identityInventory, 'not_evaluated');
  assert.throws(() => check(fixture(), { catalog: { ...catalog, capabilities: {} } }), /not declared/);
  const retained = fixture();
  retained.payload.tables.native_kv.splice(1, 4);
  assert.equal(check(retained).identityClaimCount, 0, 'last identity deletion retains the monotonic User revision');
  const historical = fixture(); edit(historical, 5, value => { value.revision = '18446744073709551615'; });
  assert.equal(check(historical).status, 'passed', 'current records cannot derive the exact historical revision');
});

test('identity claims reject missing rows, stale incarnations, duplicate sources and cross-tenant/User mismatches', () => {
  for (const mutate of [
    backup => backup.payload.tables.native_kv.splice(2, 1),
    backup => backup.payload.tables.native_kv.splice(1, 1),
    backup => backup.payload.tables.native_kv.splice(5, 1),
    backup => edit(backup, 2, value => { value.identity = id(11); }),
    backup => edit(backup, 2, value => { value.incarnation = id(21); }),
    backup => edit(backup, 2, value => { value.incarnation = id(0); }),
    backup => edit(backup, 2, value => { value.extra = true; }),
    backup => edit(backup, 1, value => { value.owner = id(1); }),
    backup => edit(backup, 1, value => { value.tenant = id(99); }),
    backup => edit(backup, 1, value => { value.input.value = 'Alice@example.com'; }),
    backup => edit(backup, 3, value => { value.input = { kind: 'email', value: 'alice@example.com' }; }),
    backup => { backup.payload.tables.native_kv[5].key = `13${id(1).replaceAll('-', '')}`; },
    backup => { backup.payload.tables.authority = []; },
  ]) {
    const backup = fixture(); mutate(backup);
    assert.throws(() => check(backup), /identity|authentication/);
  }
});

test('identity system state checks complete verification pairs and canonical bounded revisions', () => {
  for (const mutate of [
    state => { state.identity_revision = '0'; }, state => { state.identity_revision = '6'; },
    state => { state.identity_revision = 2; }, state => { state.identity_revision = '02'; },
    state => { state.identity_revision = '18446744073709551616'; },
    state => { state.verified_revision = '2'; }, state => { state.verified_at = '0'; },
    state => { state.verified_revision = '1'; state.verified_at = '0'; },
    state => { state.verified_revision = '2'; state.verified_at = '-1'; },
    state => { delete state.verified_at; }, state => { state.extra = true; },
    state => { state.incarnation = id(0); },
  ]) {
    const backup = fixture(); edit(backup, 1, source => mutate(source.derived));
    assert.throws(() => check(backup), /identity|canonical|time/);
  }
  for (const revision of ['0', '4', '05', 5, '18446744073709551616']) {
    const backup = fixture(); edit(backup, 5, value => { value.revision = revision; });
    assert.throws(() => check(backup), /identity|authentication/);
  }
});

test('identity private key framing rejects extra delimiters, invalid UTF8, aliases and unknown kinds', () => {
  for (const key of ['12', '1200', '1203' + hex('alice@example.com'), '1201ff',
    '1201' + hex('Alice@example.com'), '1201' + hex('alice@example.com\0'),
    '1202' + hex('+1234567'), '1202' + hex('+1234567890123456'), '1202' + hex(' +12345678')]) {
    const backup = fixture(); backup.payload.tables.native_kv[2].key = key;
    assert.throws(() => check(backup));
  }
  for (const key of ['13', `13${id(2).replaceAll('-', '')}00`]) {
    const backup = fixture(); backup.payload.tables.native_kv[5].key = key;
    assert.throws(() => check(backup), /point key/);
  }
});
