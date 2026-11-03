import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { checkBackupStructure } from '../storage-check.mjs';

const id = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const model = 'a'.repeat(64), tenant = id(100), owner = id(90);
const catalog = { model, contracts: [{ code: 101, name: 'Source', access_indexes: [
  { code: 10, name: 'created', components: [{ source: 'created_at' }] },
  { code: 11, name: 'value', components: [{ source: 'field', field: 'value', kind: 'integer' }] },
  { code: 12, name: 'tuple', components: [{ source: 'field', field: 'label', kind: 'text' }, { source: 'field', field: 'enabled', kind: 'boolean' }, { source: 'field', field: 'peer', kind: 'uuid' }] },
] }] };
const facts = [
  { id: id(1), owner, created_at: '9', input: { value: '-10', label: '\u{10000}', enabled: true, peer: id(7) } },
  { id: id(2), owner, created_at: '9', input: { value: '2', label: '\ue000', enabled: false, peer: id(8) } },
  { id: id(3), owner: id(91), created_at: '10', input: { value: '100000000000000000000', label: 'same', enabled: true, peer: id(9) } },
  { id: id(4), owner, created_at: '11', input: { value: '2', label: 'same', enabled: false, peer: id(7) } },
];

test('C3 access checker derives every owner/order forest from source records and catalog', () => {
  const backup = build(facts);
  const checked = checkBackupStructure(backup, { catalog });
  assert.equal(checked.status, 'passed');
  assert.equal(checked.rootCount, 0);
  assert.equal(checked.nodeCount, 0);
  assert.equal(checked.accessRootCount, 6);
  assert.equal(checked.accessNodeCount, 12);
  assert.equal(checked.accessSourceMembership, 'checked');
  assert.equal(checkBackupStructure(backup).accessSourceMembership, 'not_evaluated');
  assert.equal(checkBackupStructure(build([]), { catalog }).accessRootCount, 0);
});

test('C3 access checker detects missing whole forests, stale transfer roots, rekeys and source mismatches', () => {
  for (const alter of [
    rows => rows.filter(row => !['0f', '10'].includes(row.key.slice(0, 2))),
    rows => edit(rows, 'record', value => { value.data.owner = id(92); }),
    rows => edit(rows, 'record', value => { value.data.created_at = '100'; }),
    rows => edit(rows, 'record', value => { value.data.input.value = '-11'; }),
    rows => edit(rows, 'record', value => { value.data.tenant = id(101); }),
    rows => edit(rows, 'access_node', value => { value.data.key.value[0].value = '-99'; }),
  ]) assert.throws(() => checkBackupStructure(rewrite(build(facts), alter), { catalog }), /access|source|tenant|span|order/i);
  const other = structuredClone(catalog); other.model = 'b'.repeat(64);
  assert.throws(() => checkBackupStructure(build(facts), { catalog: other }), /model/i);
});

test('C3 access structure rejects unit, span, balance, size, links and canonical key corruption', () => {
  for (const mutate of [
    data => { data.summary = {}; }, data => { data.leaf = {}; }, data => { data.size += 1; },
    data => { data.height += 1; }, data => { data.left = data.key && { id: data.key.id, slot: data.key.slot }; },
    data => { data.prev = { id: id(99), slot: 10 }; }, data => { data.key.slot = 99; },
    data => { data.key.value = []; }, data => { data.key.value = Array(9).fill({ kind: 'boolean', value: true }); },
    data => { data.key.value = [{ kind: 'integer', value: '-0' }]; },
    data => { data.key.value = [{ kind: 'integer', value: '170141183460469231731687303715884105728' }]; },
    data => { data.key.value = [{ kind: 'text', value: 'é'.repeat(129) }]; },
    data => { data.key.value = [{ kind: 'boolean', value: 1 }]; },
    data => { data.key.value = [{ kind: 'uuid', value: 'ABCDEF00-0000-0000-0000-000000000000' }]; },
    data => { data.key.value = [{ kind: 'integer', value: '1', extra: 0 }]; },
  ]) assert.throws(() => checkBackupStructure(rewrite(build(facts), rows => edit(rows, 'access_node', value => mutate(value.data)))));
});

test('C3 access strings use UTF-8 order and complete equal keys use UUID ties', () => {
  assert.ok(Buffer.compare(Buffer.from('\ue000'), Buffer.from('\u{10000}')) < 0);
  assert.ok('\ue000' > '\u{10000}', 'counterexample to JavaScript UTF-16 string comparison');
  const checked = checkBackupStructure(build(facts), { catalog, includeObservation: true });
  assert.equal(checked.accessSourceMembership, 'checked');
  const changed = rewrite(build(facts), rows => {
    const indexes = rows.map((row, index) => [JSON.parse(Buffer.from(row.value, 'hex')), index])
      .filter(([value]) => value.type === 'access_node' && value.data.key.slot === 11 && value.data.key.id !== id(3));
    const equal = indexes.filter(([value]) => value.data.key.value[0].value === '2');
    const first = equal[0][0].data, second = equal[1][0].data;
    [first.key.id, second.key.id] = [second.key.id, first.key.id];
    for (const [value, index] of equal) rows[index].value = hex(JSON.stringify(value));
    return rows;
  });
  assert.throws(() => checkBackupStructure(changed), /address|key/i);
});

function build(source) {
  const rows = [{ key: '00', value: hex(JSON.stringify({ type: 'meta', data: { model, codec: 'native-slice-kv-13', tenant, actor: owner } })) }];
  for (const record of source) rows.push({ key: key(1, record.id), value: hex(JSON.stringify({ type: 'record', data: {
    contract: 101, tenant, owner: record.owner, created_at: record.created_at, version: id(200), input: record.input, derived: null,
  } })) });
  for (const declaration of catalog.contracts[0].access_indexes) for (const principal of new Set(source.map(row => row.owner))) {
    const members = source.filter(row => row.owner === principal).map(row => ({ id: row.id, order: declaration.components.map(component => ({
      kind: component.source === 'created_at' ? 'integer' : component.kind,
      value: component.source === 'created_at' ? row.created_at : row.input[component.field],
    })) })).sort((a, b) => compare(a.order, b.order) || a.id.localeCompare(b.id));
    const address = { id: principal, slot: declaration.code };
    const addressAt = index => index >= 0 && index < members.length ? { id: members[index].id, slot: declaration.code } : null;
    const visit = (first, end, parent) => {
      if (first === end) return { head: null, height: 0 };
      const index = Math.floor((first + end) / 2), member = members[index], head = addressAt(index);
      const left = visit(first, index, head), right = visit(index + 1, end, head);
      const height = 1 + Math.max(left.height, right.height);
      rows.push({ key: key(16, member.id, declaration.code), value: hex(JSON.stringify({ type: 'access_node', data: {
        kind: 1, root: address, key: { value: member.order, id: member.id, slot: declaration.code }, leaf: null,
        parent, left: left.head, right: right.head, prev: addressAt(index - 1), next: addressAt(index + 1),
        height, size: end - first, span: { first: members[first].order, last: members[end - 1].order }, summary: null,
      } })) });
      return { head, height };
    };
    const tree = visit(0, members.length, null);
    rows.push({ key: key(15, principal, declaration.code), value: hex(JSON.stringify({ type: 'access_root', data: {
      kind: 1, head: tree.head, first: addressAt(0), last: addressAt(members.length - 1), height: tree.height,
      size: members.length, span: { first: members[0].order, last: members.at(-1).order }, summary: null, revision: id(201),
    } })) });
  }
  return seal(rows);
}
function compare(a, b) {
  for (let i = 0; i < a.length; i += 1) {
    const x = a[i], y = b[i];
    const order = x.kind === 'text' ? Buffer.compare(Buffer.from(x.value), Buffer.from(y.value))
      : x.kind === 'integer' ? (BigInt(x.value) < BigInt(y.value) ? -1 : BigInt(x.value) > BigInt(y.value) ? 1 : 0)
        : x.value < y.value ? -1 : x.value > y.value ? 1 : 0;
    if (order) return order;
  }
  return 0;
}
function key(tag, id, slot) { return tag.toString(16).padStart(2, '0') + id.replaceAll('-', '') + (slot === undefined ? '' : slot.toString(16).padStart(4, '0')); }
function hex(value) { return Buffer.from(value).toString('hex'); }
function edit(rows, type, fn) {
  const row = rows.find(row => JSON.parse(Buffer.from(row.value, 'hex')).type === type);
  const value = JSON.parse(Buffer.from(row.value, 'hex')); fn(value); row.value = hex(JSON.stringify(value)); return rows;
}
function rewrite(bytes, fn) { const backup = JSON.parse(bytes); return seal(fn(backup.payload.tables.native_kv)); }
function seal(rows) {
  const tables = { native_kv: rows };
  for (const name of ['email_rate_scopes', 'email_rate_starts', 'email_rate_points', 'effect_due', 'effect_executions', 'effect_facts', 'effect_inbox', 'effect_runtime', 'auth_challenges', 'auth_receipts', 'auth_heads', 'auth_handles', 'auth_runtime', 'local_runtime', 'operations', 'public_records', 'query_epochs', 'receipt_slots']) tables[name] = [];
  tables.local_runtime = [{ key: Buffer.from('header').toString('hex'), value: Buffer.from(JSON.stringify({ format: 'rebase-store-11', store_id: '00000000-0000-0000-0000-0000000000f1', session_generation: '00000000-0000-0000-0000-0000000000f2', cursor_key: 'ab'.repeat(32), operation_epoch: '0' })).toString('hex') }];
  const payload = { format: 'rebase-authorized-observation-1', complete: true, tables };
  return JSON.stringify({ format: 'rebase-backup-1', sha256: createHash('sha256').update(canonical(payload)).digest('hex'), payload });
}
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
