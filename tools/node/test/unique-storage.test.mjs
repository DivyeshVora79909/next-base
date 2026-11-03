import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { checkBackupStructure } from '../storage-check.mjs';

const HOLDER = '11111111-1111-4111-8111-111111111111';
const TARGET_A = '22222222-2222-4222-8222-222222222222';
const TARGET_B = '33333333-3333-4333-8333-333333333333';
const ALPHA_HOLDER = 'abcdef12-abcd-4abc-8abc-abcdef123456';

test('checks canonical native uniqueness keys and binds holders to source records', () => {
  const rows = [recordRow(HOLDER), recordRow(TARGET_A), recordRow(TARGET_B),
    uniqueRow(encodeUniqueKey(41, 3, [TARGET_B, TARGET_A]), HOLDER)];
  assert.equal(checkBackupStructure(JSON.stringify(backupWith(rows))).nativeKvRows, 4);

  const missingHolder = backupWith([recordRow(TARGET_A), uniqueRow(encodeUniqueKey(41, 3, [TARGET_A]), HOLDER)]);
  assert.throws(() => checkBackupStructure(JSON.stringify(missingHolder)), /holder has no source record/i);

  const wrongContract = backupWith([recordRow(HOLDER, 42), recordRow(TARGET_A),
    uniqueRow(encodeUniqueKey(41, 3, [TARGET_A]), HOLDER)]);
  assert.throws(() => checkBackupStructure(JSON.stringify(wrongContract)), /holder contract differs/i);

  const missingTarget = backupWith([recordRow(HOLDER),
    uniqueRow(encodeUniqueKey(41, 3, [TARGET_A]), HOLDER)]);
  assert.throws(() => checkBackupStructure(JSON.stringify(missingTarget)), /target has no source record/i);
});

test('rejects malformed uniqueness framing, invalid codes, mismatched tags, and bad holder UUIDs', () => {
  const validKey = encodeUniqueKey(41, 3, [TARGET_A]);
  const corruptions = [
    Buffer.from([14, 0, 0, 0, 3, 0, 1, ...Buffer.from(TARGET_A.replaceAll('-', ''), 'hex')]), // zero contract
    Buffer.from([14, 0, 41, 0, 3, 0, 0]), // empty target tuple
    Buffer.from([14, 0, 41, 0, 3, 0, 2, ...Buffer.from(TARGET_A.replaceAll('-', ''), 'hex')]), // short tuple
    Buffer.from(validKey).subarray(0, -1), // truncated UUID
  ];
  for (const key of corruptions) {
    assert.throws(() => checkBackupStructure(JSON.stringify(backupWith([
      recordRow(HOLDER), recordRow(TARGET_A), uniqueRow(key.toString('hex'), HOLDER),
    ]))), /key/i);
  }

  assert.throws(() => checkBackupStructure(JSON.stringify(backupWith([
    recordRow(HOLDER), recordRow(TARGET_A), { key: validKey, value: hex(JSON.stringify({ type: 'record', data: {} })) },
  ]))), /tag differs/i);
  assert.throws(() => checkBackupStructure(JSON.stringify(backupWith([
    recordRow(ALPHA_HOLDER), recordRow(TARGET_A), uniqueRow(validKey, ALPHA_HOLDER.toUpperCase()),
  ]))), /canonical UUID/i);
});

test('rejects repeated uniqueness claims and noncanonical stored holder JSON', () => {
  const key = encodeUniqueKey(41, 3, [TARGET_A]);
  const claim = uniqueRow(key, HOLDER);
  assert.throws(() => checkBackupStructure(JSON.stringify(backupWith([
    recordRow(HOLDER), recordRow(TARGET_A), claim, structuredClone(claim),
  ]))), /duplicate key/i);

  const noncanonical = { key, value: hex(`{ "type":"unique","data":"${HOLDER}"}`) };
  assert.throws(() => checkBackupStructure(JSON.stringify(backupWith([recordRow(HOLDER), recordRow(TARGET_A), noncanonical]))), /compact JSON/i);
});

function encodeUniqueKey(contract, constraint, targets) {
  const bytes = Buffer.alloc(7 + targets.length * 16);
  bytes[0] = 14;
  bytes.writeUInt16BE(contract, 1);
  bytes.writeUInt16BE(constraint, 3);
  bytes.writeUInt16BE(targets.length, 5);
  targets.forEach((target, index) => Buffer.from(target.replaceAll('-', ''), 'hex').copy(bytes, 7 + index * 16));
  return bytes.toString('hex');
}
function recordRow(id, contract = 41) {
  return { key: `01${id.replaceAll('-', '')}`, value: hex(JSON.stringify({ type: 'record', data: { contract } })) };
}
function uniqueRow(key, holder) { return { key: typeof key === 'string' ? key : key.toString('hex'), value: hex(JSON.stringify({ type: 'unique', data: holder })) }; }
function hex(text) { return Buffer.from(text, 'utf8').toString('hex'); }
function backupWith(rows) {
  const tables = { native_kv: rows };
  for (const name of ['email_rate_scopes', 'email_rate_starts', 'email_rate_points', 'effect_due', 'effect_executions', 'effect_facts', 'effect_inbox', 'effect_runtime',
    'auth_challenges', 'auth_receipts', 'auth_heads', 'auth_handles', 'auth_runtime', 'local_runtime', 'operations', 'public_records', 'query_epochs', 'receipt_slots']) tables[name] = [];
  tables.local_runtime = [{ key: Buffer.from('header').toString('hex'), value: Buffer.from(JSON.stringify({ format: 'rebase-store-11', store_id: '00000000-0000-0000-0000-0000000000f1', session_generation: '00000000-0000-0000-0000-0000000000f2', cursor_key: 'ab'.repeat(32), operation_epoch: '0' })).toString('hex') }];
  const payload = { format: 'rebase-authorized-observation-1', complete: true, tables };
  const sha256 = createHash('sha256').update(canonicalJson(payload)).digest('hex');
  return { format: 'rebase-backup-1', sha256, payload };
}
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
