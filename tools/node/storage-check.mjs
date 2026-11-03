import { createHash } from 'node:crypto';
import { parseFrame } from './private/json-codec.mjs';
import { checkProofInventory, checkRuntimeHeader } from './private/proof-storage.mjs';

const MAX_BACKUP_BYTES = 64 * 1024 * 1024;
const MAX_SNAPSHOT_ROWS = 81_920;
const MAX_TREE_DEPTH = 64;
const MAX_TREE_NODES = 81_920;
const REQUIRED_TABLES = new Set(['effect_due', 'effect_executions', 'effect_facts', 'effect_inbox',
  'effect_runtime', 'email_rate_scopes', 'email_rate_starts', 'email_rate_points',
  'local_runtime', 'native_kv', 'operations', 'public_records', 'query_epochs', 'receipt_slots',
  'auth_challenges', 'auth_receipts', 'auth_heads', 'auth_handles', 'auth_runtime']);
const HEX = /^[0-9a-f]*$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DECIMAL = /^(0|-?[1-9][0-9]*)$/;

/**
 * Independently checks the physical AVL portion of a complete native backup.
 * Pass raw UTF-8 bytes/string to retain duplicate-key JSON rejection. The
 * optional expectedMembers Map is keyed by `uuid/slot` and contains
 * `{ root: {id,slot}, time, leaf }` rows from a separate source oracle.
 * expectedRoots is keyed the same way and contains `{ kind }` entries. Set
 * includeObservation to return the inspect-compatible semantic rows decoded
 * from the same validated native KV bytes. Access trees always receive full
 * structural checks, with separate accessRootCount/accessNodeCount results.
 * Supply the matching developer catalog to derive their complete source/root
 * inventory, including absence. Without it accessSourceMembership explicitly
 * remains not_evaluated; structural agreement is not source membership proof.
 */
export function checkBackupStructure(input, { expectedMembers, maxBytes = MAX_BACKUP_BYTES,
  expectedRoots, catalog, includeObservation = false, maxRows = MAX_SNAPSHOT_ROWS, maxDepth = MAX_TREE_DEPTH } = {}) {
  positiveBound(maxBytes, MAX_BACKUP_BYTES, 'maxBytes');
  positiveBound(maxRows, MAX_SNAPSHOT_ROWS, 'maxRows');
  positiveBound(maxDepth, MAX_TREE_DEPTH, 'maxDepth');
  requireThat(typeof includeObservation === 'boolean', 'includeObservation must be a boolean');
  const backupBytes = asBytes(input, maxBytes);
  const backup = parseFrame(backupBytes);
  object(backup, 'backup');
  exactKeys(backup, ['format', 'sha256', 'payload'], 'backup envelope');
  requireThat(backup.format === 'rebase-backup-1', 'unsupported backup format');
  requireThat(typeof backup.sha256 === 'string' && /^[0-9a-f]{64}$/.test(backup.sha256), 'invalid backup checksum');
  object(backup.payload, 'backup payload');
  requireThat(backup.payload.format === 'rebase-authorized-observation-1' && backup.payload.complete === true,
    'backup is not a complete authorized observation');
  const payloadBytes = Buffer.from(canonicalJson(backup.payload), 'utf8');
  requireThat(sha256(payloadBytes) === backup.sha256, 'backup checksum differs');

  object(backup.payload.tables, 'backup tables');
  const tableNames = Object.keys(backup.payload.tables).sort();
  requireThat([...REQUIRED_TABLES].every(name => tableNames.includes(name))
    && (tableNames.length === 19 || (tableNames.length === 21
      && tableNames.includes('authority') && tableNames.includes('owner_records'))), 'backup application table inventory differs');
  for (const [name, tableRows] of Object.entries(backup.payload.tables)) {
    requireThat(Array.isArray(tableRows) && tableRows.length <= maxRows, `table ${name} exceeds the bounded inventory`);
    const tableKeys = new Set();
    for (const row of tableRows) {
      object(row, `table ${name} row`);
      requireThat(typeof row.key === 'string' && !tableKeys.has(row.key), `table ${name} has a missing or duplicate key`);
      tableKeys.add(row.key);
    }
  }
  const header = checkRuntimeHeader(backup.payload.tables.local_runtime);
  const rows = backup.payload.tables.native_kv;
  const roots = new Map();
  const nodes = new Map();
  const accessRoots = new Map();
  const accessNodes = new Map();
  const observation = { records: [], roots: [], queries: [], roles: [], reserved: [] };
  const nativeKeys = new Set();
  const recordsById = new Map();
  const secrets = new Map();
  const identityClaims = new Map(), authenticationRevisions = new Map();
  const uniqueClaims = [];
  let metadata;
  for (const row of rows) {
    object(row, 'native KV row');
    exactKeys(row, ['key', 'value'], 'native KV row');
    const keyBytes = decodeHex(row.key, 'native key');
    const valueBytes = decodeHex(row.value, 'native value');
    const decodedKey = decodeKey(keyBytes);
    const keyToken = keyBytes.toString('hex');
    requireThat(!nativeKeys.has(keyToken), 'repeated native KV key');
    nativeKeys.add(keyToken);
    const value = parseFrame(valueBytes);
    const valueText = new TextDecoder('utf-8', { fatal: true }).decode(valueBytes);
    object(value, 'stored native value');
    exactKeys(value, ['type', 'data'], 'stored native value');
    requireThat(value.type === decodedKey.type, 'native key/value tag differs');
    if (decodedKey.type === 'unique') {
      requireThat(typeof value.data === 'string' && UUID.test(value.data), 'unique holder must be a canonical UUID');
    } else object(value.data, 'stored tree value');
    if (['root', 'node', 'access_root', 'access_node'].includes(decodedKey.type)) {
      requireThat(canonicalTypedValue(value) === valueText, 'root/node bytes are not canonical serde JSON');
    } else {
      requireThat(JSON.stringify(value) === valueText, 'non-tree native value bytes are not compact JSON');
    }
    if (decodedKey.type === 'record') {
      requireThat(!Object.hasOwn(value.data, 'reader'), 'obsolete source reader field');
      if (Object.hasOwn(value.data, 'created_at')) canonicalTime(value.data.created_at);
      recordsById.set(decodedKey.id, value.data);
      observation.records.push({ id: decodedKey.id, record: value.data });
    }
    else if (decodedKey.type === 'meta') metadata = value.data;
    else if (decodedKey.type === 'unique') uniqueClaims.push({ key: decodedKey, holder: value.data });
    else if (decodedKey.type === 'query') observation.queries.push({ query: decodedKey.address, descriptor: value.data });
    else if (decodedKey.type === 'role') {
      exactKeys(value.data, ['output', 'retired', 'first_created_at'], 'role binding');
      requireThat(UUID.test(value.data.output ?? '') && typeof value.data.retired === 'boolean', 'role binding identity differs');
      if (value.data.first_created_at !== null) requireThat(canonicalTime(value.data.first_created_at) >= 0n, 'role creation time is negative');
      observation.roles.push({ source_role: decodedKey.address, binding: value.data });
    }
    else if (decodedKey.type === 'reserved') observation.reserved.push({ id: decodedKey.id, source_role: value.data });
    else if (decodedKey.type === 'credential_secret') {
      validateSecretEnvelope(value.data, decodedKey.id, decodedKey.revision);
      secrets.set(`${decodedKey.id}/${decodedKey.revision}`, value.data);
    }
    else if (decodedKey.type === 'identity_claim') {
      exactKeys(value.data, ['identity', 'incarnation'], 'identity claim');
      nonnilUuid(value.data.identity, 'identity claim source');
      nonnilUuid(value.data.incarnation, 'identity claim incarnation');
      identityClaims.set(`${decodedKey.kind}/${decodedKey.value}`, value.data);
    }
    else if (decodedKey.type === 'authentication_revision') {
      exactKeys(value.data, ['revision'], 'authentication revision');
      nonnilUuid(decodedKey.id, 'authentication revision principal');
      requireThat(canonicalU64(value.data.revision, 'authentication revision') > 0n, 'authentication revision is zero');
      authenticationRevisions.set(decodedKey.id, value.data.revision);
    }
    if (decodedKey.type === 'access_root' || decodedKey.type === 'access_node') {
      const inventory = decodedKey.type === 'access_root' ? accessRoots : accessNodes;
      inventory.set(addressToken(decodedKey.address), { address: decodedKey.address, value: value.data });
      continue;
    }
    if (decodedKey.type !== 'root' && decodedKey.type !== 'node') continue;
    const token = addressToken(decodedKey.address);
    requireThat(!(decodedKey.type === 'root' ? roots : nodes).has(token), `duplicate ${decodedKey.type} address`);
    if (decodedKey.type === 'root') {
      roots.set(token, { address: decodedKey.address, value: value.data });
      observation.roots.push({ root: decodedKey.address, revision: value.data.revision, summary: value.data.summary });
    }
    else nodes.set(token, { address: decodedKey.address, value: value.data });
  }
  const executions = decodeRows(backup.payload.tables.effect_executions, 256, 'effect executions');
  const credentialSecretInventory = checkSecretInventory(catalog, recordsById, secrets, executions);
  const identityInventory = checkIdentityInventory(catalog, recordsById, identityClaims,
    authenticationRevisions, backup.payload.tables.authority, metadata);
  const emailAdmissionCount = checkEmailAdmissions(backup.payload.tables, executions);
  const proofInventory = checkProofInventory(backup.payload.tables, recordsById, executions, metadata, header, catalog);
  // Public source records define the complete owner catalog. Managed outputs
  // remain native records but are deliberately absent from both catalogs.
  const expectedOwners = new Map();
  for (const row of backup.payload.tables.public_records) {
    exactKeys(row, ['key', 'contract'], 'public index row');
    const idBytes = decodeHex(row.key, 'public index key');
    requireThat(idBytes.length === 16, 'invalid public index key');
    const record = recordsById.get(formatUuid(idBytes));
    requireThat(record !== undefined, 'public index has no source record');
    requireThat(record.contract !== 1004, 'private authentication delivery has a public index entry');
    requireThat(Number.isInteger(row.contract) && row.contract > 0 && row.contract <= 65535
      && record.contract === row.contract, 'public index contract differs');
    requireThat(typeof record.owner === 'string' && UUID.test(record.owner), 'source owner is invalid');
    const key = `${record.owner.replaceAll('-', '')}${row.contract.toString(16).padStart(4, '0')}${row.key}`;
    expectedOwners.set(key, row.contract);
  }
  if (backup.payload.tables.owner_records !== undefined) {
    const owners = backup.payload.tables.owner_records;
    requireThat(owners.length === expectedOwners.size, 'owner index inventory size differs');
    for (const row of owners) {
      exactKeys(row, ['key', 'contract'], 'owner index row');
      requireThat(expectedOwners.get(row.key) === row.contract, 'owner index differs from public source authority');
    }
  }
  for (const claim of uniqueClaims) {
    const holder = recordsById.get(claim.holder);
    requireThat(holder !== undefined, 'unique holder has no source record');
    requireThat(holder.contract === claim.key.contract, 'unique holder contract differs from key contract');
    for (const target of claim.key.targets) {
      requireThat(recordsById.has(target), 'unique target has no source record');
    }
  }
  requireThat(nodes.size + accessNodes.size <= MAX_TREE_NODES, 'tree node inventory exceeds its bound');
  requireThat(expectedMembers === undefined || expectedMembers instanceof Map, 'expectedMembers must be a Map');
  requireThat(expectedRoots === undefined || expectedRoots instanceof Map, 'expectedRoots must be a Map');
  const accessExpected = catalog === undefined ? undefined : sourceAccessInventory(catalog, recordsById, metadata);
  if (accessExpected) {
    requireThat(accessExpected.roots.size === accessRoots.size, 'source access root inventory size differs');
    for (const root of accessRoots.keys()) requireThat(accessExpected.roots.has(root), 'source access root differs');
    requireThat(accessExpected.members.size === accessNodes.size, 'source access membership inventory size differs');
  }

  const reached = new Set();
  let visited = 0;
  for (const [rootToken, rootRow, access] of [
    ...[...roots].map(([token, row]) => [token, row, false]),
    ...[...accessRoots].map(([token, row]) => [token, row, true]),
  ]) {
    const root = rootRow.value;
    const compareKey = access ? compareOrder : compareTime;
    const inventory = access ? accessNodes : nodes;
    if (access) requireThat(root.kind === 1 && root.summary === null && root.size > 0, 'access root kind, unit summary or nonempty shape differs');
    validateRoot(root, rootRow.address);
    const ordered = [];
    const stats = visit(root.head, null, rootRow.address, root, 0, ordered);
    requireThat(root.height === stats.height, 'root height differs');
    requireThat(root.size === stats.count, 'root structural size differs');
    requireThat(sameAddress(root.first, stats.firstAddress), 'root first link differs');
    requireThat(sameAddress(root.last, stats.lastAddress), 'root last link differs');
    requireThat(root.span === null ? ordered.length === 0 : ordered.length > 0, 'root span presence differs');
    if (ordered.length) {
      requireThat(compareKey(root.span.first, stats.firstTime) === 0
        && compareKey(root.span.last, stats.lastTime) === 0, 'root span differs');
    }
    requireThat(equalJson(root.summary, stats.summary), 'root summary differs');
    for (let index = 0; index < ordered.length; index += 1) {
      const row = ordered[index];
      const node = row.value;
      requireThat(sameAddress(node.prev, ordered[index - 1]?.address ?? null), 'previous link differs');
      requireThat(sameAddress(node.next, ordered[index + 1]?.address ?? null), 'next link differs');
      if (index) requireThat(compareFullKey(ordered[index - 1], row, compareKey) < 0, 'tree keys are not strictly ordered');
      if (access && accessExpected) {
        const expected = accessExpected.members.get(addressToken(row.address));
        requireThat(expected !== undefined, 'access node is absent from source membership');
        requireThat(addressToken(expected.root) === rootToken, 'source access owner/root differs');
        requireThat(compareOrder(expected.key, row.time) === 0, 'source access key differs');
      }
      if (!access && expectedMembers) {
        const expected = expectedMembers.get(addressToken(row.address));
        requireThat(expected !== undefined, 'tree node is absent from independent source membership');
        requireThat(addressToken(expected.root) === rootToken, 'source membership root differs');
        requireThat(compareTime(expected.time, row.time) === 0, 'source membership time differs');
        requireThat(equalJson(expected.leaf, node.leaf), 'source membership leaf differs');
      }
    }
    visited += ordered.length;
    requireThat(visited <= MAX_TREE_NODES, 'tree traversal exceeds its bound');

    function visit(address, parent, owner, ownerRoot, depth, inOrder) {
      if (address === null) return access ? { height: 0, count: 0, firstTime: null, lastTime: null, firstAddress: null, lastAddress: null, summary: null } : emptyStats(ownerRoot.kind);
      requireThat(depth < maxDepth, 'tree path depth limit');
      const token = addressToken(address);
      const reachedToken = `${access ? 'access' : 'domain'}:${token}`;
      requireThat(!reached.has(reachedToken), 'tree cycle or duplicate reachability');
      reached.add(reachedToken);
      const row = inventory.get(token);
      requireThat(row !== undefined, 'linked tree node is missing');
      const node = row.value;
      structuralSize(node.size, false);
      exactKeys(node, ['kind', 'root', 'key', 'leaf', 'parent', 'left', 'right', 'prev', 'next', 'height', 'size', 'span', 'summary'], 'tree node');
      exactKeys(node.key, ['value', 'id', 'slot'], 'tree node key');
      exactKeys(node.span, ['first', 'last'], 'tree node span');
      requireThat(addressToken(node.root) === addressToken(owner), 'node root owner differs');
      requireThat(addressToken(node.parent) === (parent ? addressToken(parent) : null), 'node parent differs');
      requireThat(node.kind === ownerRoot.kind, 'node index kind differs');
      requireThat(node.key?.id === address.id && node.key?.slot === address.slot, 'node address differs from key');
      requireThat(node.key && (access ? node.leaf === null && node.summary === null : node.leaf) && node.span, 'node key, leaf, or span is missing');
      const time = access ? orderKey(node.key.value) : canonicalTime(node.key.value);
      const left = visit(node.left, address, owner, ownerRoot, depth + 1, inOrder);
      const current = { ...row, address, time, leaf: node.leaf };
      inOrder.push(current);
      const right = visit(node.right, address, owner, ownerRoot, depth + 1, inOrder);
      requireThat(Math.abs(left.height - right.height) <= 1, 'AVL balance differs');
      const height = Math.max(left.height, right.height) + 1;
      requireThat(node.height === height && height < maxDepth, 'node height differs');
      const firstTime = left.count ? left.firstTime : time;
      const lastTime = right.count ? right.lastTime : time;
      requireThat(compareKey(node.span.first, firstTime) === 0
        && compareKey(node.span.last, lastTime) === 0, 'node span differs');
      requireThat(compareKey(node.span.first, time) <= 0 && compareKey(time, node.span.last) <= 0,
        'node key lies outside span');
      const singleton = access ? null : singletonSummary(node.kind, time, node.leaf);
      const summary = access ? null : combineSummaries(node.kind, combineSummaries(node.kind, left.summary, singleton), right.summary);
      requireThat(equalJson(node.summary, summary), 'tree node summary differs');
      const count = left.count + 1 + right.count;
      requireThat(node.size === count, 'node structural size differs');
      return { height, count, firstTime, lastTime,
        firstAddress: left.count ? left.firstAddress : address,
        lastAddress: right.count ? right.lastAddress : address, summary };
    }
  }
  requireThat(reached.size === nodes.size + accessNodes.size, 'tree node inventory has disconnected entries');
  if (expectedMembers) requireThat(expectedMembers.size === nodes.size, 'source membership inventory size differs');
  if (expectedRoots) {
    for (const [token, expected] of expectedRoots) {
      requireThat(typeof token === 'string' && token === addressToken(parseAddressToken(token)), 'invalid expected root address');
      object(expected, 'expected source root');
      exactKeys(expected, ['kind'], 'expected source root');
      requireThat(Number.isInteger(expected.kind), 'invalid expected root kind');
    }
    requireThat(expectedRoots.size === roots.size, 'source root inventory size differs');
    for (const [token, rootRow] of roots) {
      const expected = expectedRoots.get(token);
      requireThat(expected !== undefined, 'physical root is absent from independent source inventory');
      object(expected, 'expected source root');
      exactKeys(expected, ['kind'], 'expected source root');
      requireThat(expected.kind === rootRow.value.kind, 'source root kind differs');
    }
  }
  const result = { status: 'passed', sourceMembership: expectedMembers ? 'checked' : 'not_evaluated',
    credentialSecretInventory, credentialSecretCount: secrets.size, credentialSecretAuthentication: 'not_evaluated',
    emailAdmissionInventory: 'checked', emailAdmissionCount,
    identityInventory, identityClaimCount: identityClaims.size, authenticationRevisionCount: authenticationRevisions.size,
    ...proofInventory,
    accessSourceMembership: accessExpected ? 'checked' : 'not_evaluated', accessRootCount: accessRoots.size, accessNodeCount: accessNodes.size,
    rootCount: roots.size, nodeCount: nodes.size, nativeKvRows: rows.length, snapshotBytes: backupBytes.length };
  if (includeObservation) {
    const identityCode = catalog?.capabilities?.identities?.contract ?? 1003;
    observation.records = observation.records.filter(row => row.record.contract !== 1004).map(row => {
      if (row.record.contract !== identityCode) return row;
      const { identity_revision, verified_revision, verified_at } = row.record.derived;
      return { ...row, record: { ...row.record, derived: { identity_revision, verified_revision, verified_at } } };
    });
    result.observation = Object.freeze(Object.fromEntries(
      Object.entries(observation).map(([name, values]) => [name, Object.freeze(values.map(Object.freeze))])));
  }
  return Object.freeze(result);
}

function canonicalU64(value, label) {
  requireThat(typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value) && BigInt(value) < (1n << 64n), `${label} is not canonical u64`);
  return BigInt(value);
}

// Deliberately independent of the writer's normalizer: derive keys from canonical source facts.
function validateIdentityInput(input) {
  exactKeys(input, ['kind', 'value'], 'identity input');
  const { kind, value } = input;
  requireThat(typeof value === 'string' && /^[\x21-\x7e]+$/u.test(value), 'identity value is not canonical ASCII');
  if (kind === 'phone') {
    requireThat(/^\+[1-9][0-9]{7,14}$/u.test(value), 'identity phone is not canonical E164');
    return;
  }
  requireThat(kind === 'email' && value.length <= 254 && value === value.toLowerCase(), 'identity email is not canonical');
  const at = value.indexOf('@'), local = value.slice(0, at), domain = value.slice(at + 1);
  requireThat(at > 0 && at === value.lastIndexOf('@') && local.length <= 64
    && /^[a-z0-9!#$%&'*+\-/=?^_`{|}~]+(?:\.[a-z0-9!#$%&'*+\-/=?^_`{|}~]+)*$/u.test(local)
    && domain.length > 0 && domain.length <= 253
    && domain.split('.').every(label => label.length > 0 && label.length <= 63
      && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label)), 'identity email syntax differs');
}

function checkIdentityInventory(catalog, records, claims, revisions, authorityRows, metadata) {
  const declaration = catalog?.capabilities?.identities;
  const code = declaration?.contract ?? 1003;
  if (declaration !== undefined) requireThat(Number.isInteger(code)
    && catalog.contracts.some(contract => contract.code === code), 'identity source declaration is missing');
  const identities = [...records].filter(([, source]) => source.contract === code);
  if (catalog !== undefined && declaration === undefined) {
    requireThat(identities.length === 0 && claims.size === 0 && revisions.size === 0, 'identity state is not declared in the catalog');
    return 'checked';
  }
  let graph;
  if (identities.length || claims.size || revisions.size) {
    const row = authorityRows?.find(row => row.key === Buffer.from('graph').toString('hex'));
    requireThat(row !== undefined, 'identity principal graph is missing');
    graph = parseFrame(decodeHex(row.value, 'identity principal graph'));
    object(graph, 'identity principal graph');
    requireThat(graph.tenant === metadata?.tenant && UUID.test(graph.tenant ?? '')
      && Array.isArray(graph.principals) && graph.principals.length <= 128, 'identity principal graph tenant or inventory differs');
  }
  const principals = new Map();
  for (const principal of graph?.principals ?? []) {
    object(principal, 'identity principal');
    nonnilUuid(principal.id, 'identity principal');
    requireThat(!principals.has(principal.id) && ['tenant', 'group', 'user'].includes(principal.kind), 'identity principal inventory differs');
    requireThat(typeof principal.login_access === 'boolean' && (principal.kind === 'user' || !principal.login_access), 'identity principal login access differs');
    principals.set(principal.id, principal);
  }
  for (const owner of revisions.keys()) requireThat(principals.get(owner)?.kind === 'user', 'authentication revision owner is not a User');
  const expected = new Map();
  for (const [id, source] of identities) {
    nonnilUuid(id, 'identity source');
    requireThat(source.tenant === graph.tenant && principals.get(source.owner)?.kind === 'user', 'identity owner or tenant differs');
    validateIdentityInput(source.input);
    const state = source.derived;
    exactKeys(state, ['incarnation', 'identity_revision', 'verified_revision', 'verified_at'], 'identity system state');
    nonnilUuid(state.incarnation, 'identity incarnation');
    const revision = canonicalU64(state.identity_revision, 'identity revision');
    requireThat(revision > 0n && revisions.has(source.owner)
      && revision <= BigInt(revisions.get(source.owner)), 'identity authentication revision is missing or stale');
    requireThat((state.verified_revision === null) === (state.verified_at === null), 'identity verification pair differs');
    if (state.verified_revision !== null) requireThat(canonicalU64(state.verified_revision, 'identity verified revision') === revision
      && canonicalTime(state.verified_at) >= 0n, 'identity verified state is stale or invalid');
    const key = `${source.input.kind}/${source.input.value}`;
    requireThat(!expected.has(key), 'duplicate final identity claim');
    expected.set(key, { identity: id, incarnation: state.incarnation });
  }
  requireThat(expected.size === claims.size, 'identity claim inventory size differs');
  for (const [key, expectedClaim] of expected) requireThat(claims.get(key)?.identity === expectedClaim.identity
    && claims.get(key)?.incarnation === expectedClaim.incarnation, 'identity claim source or incarnation differs');
  return catalog === undefined ? 'not_evaluated' : 'checked';
}
function secretBase64(value, min, max) {
  requireThat(typeof value === 'string' && value.length <= Math.ceil(max / 3) * 4 && /^[A-Za-z0-9_-]+$/.test(value), 'credential secret encoding is invalid');
  const bytes = Buffer.from(value, 'base64url');
  requireThat(bytes.length >= min && bytes.length <= max && bytes.toString('base64url') === value, 'credential secret encoding length is invalid');
}
function validateSecretEnvelope(value, id, revision) {
  exactKeys(value, ['format', 'incarnation', 'credential', 'secret_revision', 'key_id', 'nonce', 'ciphertext'], 'credential secret envelope');
  requireThat(value.format === 'rebase-credential-secret-2' && value.credential === id && value.secret_revision === revision, 'credential secret identity differs');
  nonnilUuid(value.incarnation, 'credential secret incarnation');
  requireThat(canonicalU64(value.secret_revision, 'credential secret revision') > 0n, 'credential secret revision is zero');
  requireThat(typeof value.key_id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value.key_id), 'credential secret key ID is invalid');
  secretBase64(value.nonce, 24, 24);
  secretBase64(value.ciphertext, 17, 2048);
  requireThat(Buffer.byteLength(JSON.stringify(value)) <= 2048, 'credential secret envelope byte limit');
}
function checkSecretInventory(catalog, records, secrets, executions) {
  const secretIds = new Set([...secrets.values()].map(row => row.credential));
  for (const envelope of secrets.values()) {
    const source = records.get(envelope.credential);
    requireThat(source !== undefined, 'credential secret has no source');
    requireThat(source.derived?.has_secret === true && source.derived.incarnation === envelope.incarnation
      && canonicalU64(source.derived.secret_revision, 'credential source revision') >= BigInt(envelope.secret_revision),
      'credential source/private revision differs');
  }
  const declaration = catalog?.capabilities?.credentials;
  if (catalog !== undefined && declaration === undefined) {
    requireThat(secrets.size === 0, 'credential secret is not declared in the catalog');
    requireThat([...executions.values()].every(row => row.email_binding === null || row.email_binding === undefined), 'email credential binding is not declared');
    return 'checked';
  }
  const code = declaration?.contract ?? 1001;
  if (catalog) requireThat(Number.isInteger(code) && catalog.contracts.some(contract => contract.code === code), 'credential source declaration is missing');
  const expected = new Set();
  for (const [id, source] of records) {
    if (source.contract !== code) { requireThat(!secretIds.has(id), 'credential secret source contract differs'); continue; }
    const state = source.derived;
    object(state, 'credential derived metadata');
    exactKeys(state, ['has_secret', 'secret_revision', 'use_epoch', 'incarnation'], 'credential derived metadata');
    requireThat(UUID.test(state.incarnation ?? '') && state.incarnation !== '00000000-0000-0000-0000-000000000000', 'credential incarnation is invalid');
    requireThat(typeof state.has_secret === 'boolean' && state.has_secret === (state.secret_revision !== null), 'credential derived secret presence differs');
    canonicalU64(state.use_epoch, 'credential use epoch');
    requireThat(!source.input?.enabled || state.has_secret, 'enabled credential has no secret');
    if (state.has_secret) {
      requireThat(canonicalU64(state.secret_revision, 'credential source revision') > 0n, 'credential source revision is zero');
      const key = `${id}/${state.secret_revision}`;
      requireThat(secrets.get(key)?.incarnation === state.incarnation, 'credential current secret is missing or stale');
      expected.add(key);
    } else requireThat(!secretIds.has(id), 'credential unexpected secret');
  }
  for (const [key, execution] of executions) {
    if (execution.email_binding === null || execution.email_binding === undefined) continue;
    const pin = execution.email_binding;
    exactKeys(pin, ['credential', 'incarnation', 'provider', 'account', 'use_epoch', 'secret_revision', 'selection', 'server_policy', 'purpose'], 'email credential binding');
    nonnilUuid(pin.credential, 'email credential identity'); nonnilUuid(pin.incarnation, 'email credential incarnation');
    providerAccount(pin, 'email credential binding');
    canonicalU64(pin.use_epoch, 'email credential use epoch');
    requireThat(canonicalU64(pin.secret_revision, 'email credential revision') > 0n, 'email credential revision is zero');
    const source = records.get(pin.credential);
    requireThat(source?.contract === code && source.tenant === execution.tenant && source.derived?.incarnation === pin.incarnation
      && source.input.provider === pin.provider && source.input.account === pin.account, 'email credential binding differs from source');
    const anchor = records.get(execution.source);
    requireThat(UUID.test(execution.id ?? '') && execution.id.replaceAll('-', '') === key && execution.target === execution.source
      && anchor?.contract === (pin.server_policy === null ? 1002 : 1004) && anchor.tenant === execution.tenant
      && canonicalJson(anchor.input) === canonicalJson(execution.request), 'email retained source/request differs');
    if (pin.server_policy !== null) {
      requireThat(pin.selection === null && pin.server_policy.credential === pin.credential
        && pin.server_policy.provider === pin.provider && pin.server_policy.account === pin.account
        && pin.purpose === (pin.provider === 'fake_sms' ? 'sms.send' : 'email.send'), 'authentication credential policy differs');
    } else {
      requireThat(pin.purpose === 'email.send' && pin.provider !== 'fake_sms', 'ordinary email purpose differs');
      requireThat(canonicalJson(pin.selection) === canonicalJson(execution.request.selection), 'email credential selection differs');
      if (pin.selection?.kind === 'byoc') {
        exactKeys(pin.selection, ['kind', 'credential'], 'email credential selection');
        requireThat(pin.selection.credential === pin.credential, 'email BYOC credential differs');
      } else {
        exactKeys(pin.selection, ['kind', 'slot'], 'email credential selection');
        requireThat(pin.selection.kind === 'platform' && pin.selection.slot === 'transactional_email', 'email platform selection differs');
      }
    }
    const secret = `${pin.credential}/${pin.secret_revision}`;
    requireThat(secrets.get(secret)?.incarnation === pin.incarnation, 'email retained credential revision is missing');
    expected.add(secret);
  }
  requireThat(expected.size === secrets.size, 'credential secret inventory size differs');
  return catalog === undefined ? 'not_evaluated' : 'checked';
}

function nonnilUuid(value, label) { requireThat(UUID.test(value ?? '') && value !== '00000000-0000-0000-0000-000000000000', `${label} is invalid`); }
function providerAccount(value, label) {
  requireThat(['resend', 'brevo', 'fake_sms'].includes(value.provider) && typeof value.account === 'string' && /^[A-Za-z0-9._:-]{1,128}$/u.test(value.account), `${label} is invalid`);
}
function decodeRows(rows, maximum, label) {
  requireThat(rows.length <= maximum, `${label} exceeds bounded inventory`);
  const result = new Map();
  for (const row of rows) {
    exactKeys(row, ['key', 'value'], `${label} row`);
    decodeHex(row.key, `${label} key`);
    const value = parseFrame(decodeHex(row.value, `${label} value`));
    object(value, label);
    result.set(row.key, value);
  }
  return result;
}
function quotaScope(provider, account) { return { provider, account, purpose: provider === 'fake_sms' ? 'sms.send' : 'email.send' }; }
function quotaKey(scope) { return createHash('sha256').update('next-base/email-rate-scope/1\0').update(JSON.stringify(scope)).digest('hex'); }
function checkEmailAdmissions(tables, executions) {
  const headers = decodeRows(tables.email_rate_scopes, 16, 'email admission policies');
  const charges = decodeRows(tables.email_rate_starts, 768, 'email admission starts');
  const points = new Map(tables.email_rate_points.map(row => {
    exactKeys(row, ['key', 'value'], 'email admission point'); decodeHex(row.key, 'email admission point');
    requireThat(row.value === '', 'email admission point value differs'); return [row.key, row.value];
  }));
  requireThat(points.size <= 768, 'email admission point bound');
  for (const [key, header] of headers) {
    exactKeys(header, ['format', 'policy', 'last_at'], 'email admission header');
    exactKeys(header.policy, ['provider', 'account', 'purpose', 'window_ms', 'limit'], 'email admission policy');
    const p = header.policy; providerAccount(p, 'email admission policy');
    requireThat(header.format === 'email-rate-admission-1' && p.purpose === quotaScope(p.provider, p.account).purpose
      && key === quotaKey(quotaScope(p.provider, p.account)), 'email admission scope identity differs');
    requireThat(canonicalTime(p.window_ms) > 0n && BigInt(p.window_ms) <= 86_400_000n
      && Number.isInteger(p.limit) && p.limit >= 1 && p.limit <= 64, 'email admission policy bounds');
    if (header.last_at !== null) requireThat(canonicalTime(header.last_at) >= 0n, 'email admission clock is negative');
  }
  const expected = new Map(), expectedPoints = new Set(), times = new Map();
  for (const [key, execution] of executions) {
    const history = execution.email_starts ?? [];
    requireThat(Array.isArray(history) && history.length <= 3, 'email admission history bounds');
    if (execution.email_binding === null || execution.email_binding === undefined) {
      requireThat(history.length === 0, 'email starts without binding'); continue;
    }
    const scope = quotaScope(execution.email_binding.provider, execution.email_binding.account), scopeKey = quotaKey(scope);
    let previous = -1n;
    for (const [index, start] of history.entries()) {
      exactKeys(start, ['activation', 'token', 'at', 'attempt'], 'email physical start');
      nonnilUuid(start.activation, 'email start activation'); nonnilUuid(start.token, 'email start token');
      const at = canonicalTime(start.at);
      requireThat(at >= 0n && at >= previous && start.attempt === index + 1, 'email admission history time/attempt differs');
      requireThat(headers.has(scopeKey), 'email start without quota policy'); previous = at;
      const identity = `${key}${start.attempt.toString(16).padStart(2, '0')}`;
      expected.set(identity, { format: 'email-rate-admission-1', scope, execution: execution.id, start });
      expectedPoints.add(`${scopeKey}${at.toString(16).padStart(16, '0')}${identity}`);
      if (!times.has(scopeKey)) times.set(scopeKey, []); times.get(scopeKey).push(at);
    }
  }
  requireThat(expected.size <= 768 && charges.size === expected.size && points.size === expectedPoints.size, 'email admission inventory size differs');
  for (const [key, row] of charges) requireThat(expected.has(key) && canonicalJson(row) === canonicalJson(expected.get(key)), 'email admission differs from execution history');
  for (const key of points.keys()) requireThat(expectedPoints.has(key), 'email admission ordered point differs');
  for (const [key, header] of headers) {
    const values = times.get(key) ?? [];
    requireThat(header.last_at === (values.length ? values.reduce((a, b) => a > b ? a : b).toString() : null), 'email admission clock differs from history');
    const window = BigInt(header.policy.window_ms);
    for (const at of values) requireThat(values.filter(s => at - window < s && s <= at).length <= header.policy.limit, 'email quota exceeded by source starts');
  }
  return expected.size;
}

function emptyStats(kind) {
  return { height: 0, count: 0, firstTime: null, lastTime: null, firstAddress: null, lastAddress: null,
    summary: kind === 1 ? { kind: 'financial', value: { count: 0, first: null, last: null, sum: '0',
      min_prefix: '0', max_prefix: '0', boundary_min: null, boundary_max: null } }
      : kind === 2 ? { kind: 'quote', value: { count: 0, first: null, last: null } }
        : kind === 7 ? { count: 0, sum: '0', min: null, max: null, dimension: { kind: 'empty' } }
          : unsupportedKind(kind) };
}

// This projection reads source facts and declarations, never stored access keys
// or writer summaries. A developer catalog must cover every retained contract.
function sourceAccessInventory(catalog, records, metadata) {
  object(catalog, 'access catalog');
  requireThat(Array.isArray(catalog.contracts), 'access catalog contracts are missing');
  requireThat(metadata && metadata.model === catalog.model, 'access catalog model differs from stored metadata');
  requireThat(UUID.test(metadata.tenant ?? ''), 'access tenant metadata is invalid');
  const contracts = new Map();
  const indexCodes = new Set();
  for (const contract of catalog.contracts) {
    requireThat(Number.isInteger(contract.code) && contract.code > 0 && contract.code <= 65535
      && !contracts.has(contract.code), 'access catalog contract code is invalid or duplicate');
    contracts.set(contract.code, contract);
    const indexes = contract.access_indexes ?? [];
    requireThat(Array.isArray(indexes), 'access declarations must be an array');
    const names = new Set();
    for (const declaration of indexes) {
      requireThat(Number.isInteger(declaration.code) && declaration.code > 0 && declaration.code <= 65535
        && !indexCodes.has(declaration.code), 'access catalog index code is invalid or duplicate');
      indexCodes.add(declaration.code);
      requireThat(typeof declaration.name === 'string' && declaration.name.length && !names.has(declaration.name), 'access catalog index name is invalid or duplicate');
      names.add(declaration.name);
      requireThat(Array.isArray(declaration.components) && declaration.components.length > 0 && declaration.components.length <= 8, 'access declaration component bound');
      for (const component of declaration.components) {
        object(component, 'access component');
        if (component.source === 'created_at') exactKeys(component, ['source'], 'created access component');
        else {
          exactKeys(component, ['source', 'field', 'kind'], 'field access component');
          requireThat(component.source === 'field' && typeof component.field === 'string' && component.field.length
            && ['integer', 'text', 'boolean', 'uuid'].includes(component.kind), 'invalid access component');
        }
      }
    }
  }
  const roots = new Set(), members = new Map();
  for (const [id, record] of records) {
    const contract = contracts.get(record.contract);
    requireThat(contract !== undefined, 'access catalog does not cover a stored source contract');
    requireThat(record.tenant === metadata.tenant, 'source access tenant differs');
    requireThat(UUID.test(record.owner ?? ''), 'source access owner is invalid');
    for (const declaration of contract.access_indexes ?? []) {
      const key = declaration.components.map(component => {
        const kind = component.source === 'created_at' ? 'integer' : component.kind;
        let value;
        if (component.source === 'created_at') value = canonicalTime(record.created_at).toString();
        else {
          object(record.input, 'access source input');
          requireThat(Object.hasOwn(record.input, component.field), 'declared access source field is missing');
          value = record.input[component.field];
          if (kind === 'integer' && Number.isSafeInteger(value)) value = String(value);
        }
        return { kind, value };
      });
      orderKey(key);
      const root = { id: record.owner, slot: declaration.code };
      roots.add(addressToken(root));
      members.set(`${id}/${declaration.code}`, { root, key });
      requireThat(members.size <= MAX_TREE_NODES, 'source access membership inventory bound');
    }
  }
  return { roots, members };
}

function orderKey(value) {
  requireThat(Array.isArray(value) && value.length > 0 && value.length <= 8, 'access key component bound');
  for (const atom of value) {
    object(atom, 'access key atom');
    exactKeys(atom, ['kind', 'value'], 'access key atom');
    if (atom.kind === 'integer') canonicalI128(atom.value, 'access integer key');
    else if (atom.kind === 'text') requireThat(typeof atom.value === 'string' && atom.value.isWellFormed()
      && Buffer.byteLength(atom.value, 'utf8') <= 256, 'access text key UTF-8 bound');
    else if (atom.kind === 'boolean') requireThat(typeof atom.value === 'boolean', 'access boolean key differs');
    else if (atom.kind === 'uuid') requireThat(typeof atom.value === 'string' && UUID.test(atom.value), 'access UUID key is not canonical');
    else throw new TypeError('unknown access key atom kind');
  }
  requireThat(Buffer.byteLength(JSON.stringify(value)) <= 4096, 'access key encoded byte bound');
  return value;
}

function compareOrder(left, right) {
  orderKey(left); orderKey(right);
  const kinds = ['integer', 'text', 'boolean', 'uuid'];
  for (let index = 0; index < Math.min(left.length, right.length); index += 1) {
    const a = left[index], b = right[index];
    if (a.kind !== b.kind) return kinds.indexOf(a.kind) - kinds.indexOf(b.kind);
    const x = a.kind === 'integer' ? BigInt(a.value) : a.value;
    const y = b.kind === 'integer' ? BigInt(b.value) : b.value;
    const result = a.kind === 'text' ? Buffer.compare(Buffer.from(x, 'utf8'), Buffer.from(y, 'utf8'))
      : x < y ? -1 : x > y ? 1 : 0;
    if (result) return result;
  }
  return left.length - right.length;
}

function singletonSummary(kind, time, leaf) {
  if (kind === 1) {
    exactKeys(leaf, ['kind', 'value'], 'financial leaf');
    requireThat(leaf.kind === 'financial', 'financial leaf kind differs');
    const amount = canonicalI128(leaf.value, 'financial leaf value');
    const min = amount < 0n ? amount : 0n, max = amount > 0n ? amount : 0n;
    return { kind: 'financial', value: { count: 1, first: time.toString(), last: time.toString(), sum: amount.toString(),
      min_prefix: min.toString(), max_prefix: max.toString(), boundary_min: null, boundary_max: null } };
  } else if (kind === 2) {
    exactKeys(leaf, ['kind', 'value'], 'quote leaf');
    requireThat(leaf.kind === 'quote', 'quote leaf is invalid');
    canonicalU16(leaf.value, 'quote leaf value');
    return { kind: 'quote', value: { count: 1, first: time.toString(), last: time.toString() } };
  } else if (kind === 7) {
    exactKeys(leaf, ['unit', 'value'], 'Measurement leaf');
    requireThat(Number.isInteger(leaf.unit) && leaf.unit > 0 && leaf.unit <= 65535, 'Measurement unit is invalid');
    const value = canonicalI128(leaf.value, 'Measurement leaf value');
    requireThat(value >= -1_000_000_000_000n && value <= 1_000_000_000_000n, 'Measurement leaf exceeds its bound');
    return { count: 1, sum: value.toString(), min: value.toString(), max: value.toString(),
      dimension: { kind: 'unit', code: leaf.unit } };
  } else throw new TypeError(`unsupported native index kind ${String(kind)}`);
}

function combineSummaries(kind, left, right) {
  if (kind === 1) {
    const a = left.value, b = right.value;
    if (a.count === 0) return right;
    if (b.count === 0) return left;
    const aSum = BigInt(a.sum), bSum = BigInt(b.sum), total = aSum + bSum;
    checkI128(total, 'financial combined sum');
    const shiftedMin = aSum + BigInt(b.min_prefix), shiftedMax = aSum + BigInt(b.max_prefix);
    checkI128(shiftedMin, 'financial combined minimum'); checkI128(shiftedMax, 'financial combined maximum');
    const gap = BigInt(a.last) < BigInt(b.first);
    const boundaryCandidatesMin = [nullableBigInt(a.boundary_min), shiftNullable(aSum, b.boundary_min), gap ? aSum : null].filter(v => v !== null);
    const boundaryCandidatesMax = [nullableBigInt(a.boundary_max), shiftNullable(aSum, b.boundary_max), gap ? aSum : null].filter(v => v !== null);
    const boundaryMin = boundaryCandidatesMin.length ? minBigInt(boundaryCandidatesMin) : null;
    const boundaryMax = boundaryCandidatesMax.length ? maxBigInt(boundaryCandidatesMax) : null;
    for (const value of [boundaryMin, boundaryMax]) if (value !== null) checkI128(value, 'financial combined boundary');
    return { kind: 'financial', value: { count: a.count + b.count, first: a.first, last: b.last,
      sum: total.toString(), min_prefix: minBigInt([BigInt(a.min_prefix), shiftedMin]).toString(),
      max_prefix: maxBigInt([BigInt(a.max_prefix), shiftedMax]).toString(),
      boundary_min: boundaryMin?.toString() ?? null, boundary_max: boundaryMax?.toString() ?? null } };
  }
  if (kind === 2) {
    const a = left.value, b = right.value;
    if (a.count === 0) return right;
    if (b.count === 0) return left;
    requireThat(BigInt(a.last) <= BigInt(b.first), 'quote summaries are out of time order');
    return { kind: 'quote', value: { count: a.count + b.count, first: a.first, last: b.last } };
  }
  if (kind === 7) {
    if (left.count === 0) return right;
    if (right.count === 0) return left;
    const sum = BigInt(left.sum) + BigInt(right.sum);
    checkI128(sum, 'Measurement combined sum');
    const dimension = equalJson(left.dimension, right.dimension) ? left.dimension : { kind: 'mixed' };
    return { count: left.count + right.count, sum: sum.toString(),
      min: minBigInt([BigInt(left.min), BigInt(right.min)]).toString(),
      max: maxBigInt([BigInt(left.max), BigInt(right.max)]).toString(), dimension };
  }
  return unsupportedKind(kind);
}

function nullableBigInt(value) { return value === null ? null : BigInt(value); }
function shiftNullable(amount, value) { return value === null ? null : amount + BigInt(value); }
function minBigInt(values) { return values.reduce((a, b) => a < b ? a : b); }
function maxBigInt(values) { return values.reduce((a, b) => a > b ? a : b); }
function unsupportedKind(kind) { throw new TypeError(`unsupported native index kind ${String(kind)}`); }

function decodeKey(bytes) {
  if (bytes.length === 1 && bytes[0] === 0) return { type: 'meta' };
  const tag = bytes[0];
  if (tag === 14) {
    requireThat(bytes.length >= 7, 'invalid native uniqueness key');
    const contract = bytes.readUInt16BE(1);
    const constraint = bytes.readUInt16BE(3);
    const count = bytes.readUInt16BE(5);
    requireThat(contract > 0 && constraint > 0 && count > 0
      && bytes.length === 7 + count * 16, 'invalid native uniqueness key');
    const targets = [];
    for (let offset = 7; offset < bytes.length; offset += 16) {
      targets.push(formatUuid(bytes.subarray(offset, offset + 16)));
    }
    return { type: 'unique', contract, constraint, targets };
  }
  if (tag === 17) {
    requireThat(bytes.length === 25, 'invalid credential secret point key');
    const revision = bytes.readBigUInt64BE(17).toString();
    requireThat(revision !== '0', 'credential secret point revision is zero');
    return { type: 'credential_secret', id: formatUuid(bytes.subarray(1, 17)), revision };
  }
  if (tag === 18) {
    requireThat(bytes.length >= 3 && bytes.length <= 256 && [1, 2].includes(bytes[1]), 'invalid identity claim key');
    const kind = bytes[1] === 1 ? 'email' : 'phone';
    const value = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(2));
    validateIdentityInput({ kind, value });
    return { type: 'identity_claim', kind, value };
  }
  const expectedLength = new Set([1, 5, 6, 9, 19]).has(tag) ? 17
    : new Set([2, 3, 4, 7, 8, 10, 11, 12, 15, 16]).has(tag) ? 19 : 0;
  requireThat(expectedLength > 0 && bytes.length === expectedLength, 'invalid native point key');
  const id = formatUuid(bytes.subarray(1, 17));
  const slot = expectedLength === 19 ? bytes.readUInt16BE(17) : null;
  if (expectedLength === 19) requireThat(slot > 0, 'native address slot is zero');
  const type = ({ 1: 'record', 2: 'root', 3: 'node', 4: 'query', 5: 'incoming', 6: 'direct',
    7: 'subscribers', 8: 'role', 9: 'reserved', 10: 'route_node', 11: 'route_node', 12: 'route_node', 15: 'access_root', 16: 'access_node', 17: 'credential_secret', 19: 'authentication_revision' })[tag];
  requireThat(type !== undefined, 'invalid native point key tag');
  return { type, id, ...(expectedLength === 19 ? { address: { id, slot } } : {}) };
}

function decodeHex(value, label) {
  requireThat(typeof value === 'string' && value.length % 2 === 0 && HEX.test(value), `${label} is not canonical hex`);
  return Buffer.from(value, 'hex');
}
function asBytes(input, maxBytes) {
  if (typeof input === 'string') {
    const byteLength = Buffer.byteLength(input, 'utf8');
    requireThat(byteLength > 0 && byteLength <= maxBytes, 'backup byte limit');
    return Buffer.from(input, 'utf8');
  }
  requireThat(Buffer.isBuffer(input) || input instanceof Uint8Array,
    'backup must be a string, Buffer, or Uint8Array byte view');
  requireThat(input.byteLength > 0 && input.byteLength <= maxBytes, 'backup byte limit');
  return Buffer.from(input);
}
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
function canonicalTime(value) {
  requireThat(typeof value === 'string' && DECIMAL.test(value), 'native time key is not canonical decimal');
  const time = BigInt(value);
  requireThat(time >= -(1n << 63n) && time < (1n << 63n), 'native time key exceeds i64');
  return time;
}
function canonicalI128(value, label) {
  requireThat(typeof value === 'string' && DECIMAL.test(value), `${label} is not canonical decimal`);
  const parsed = BigInt(value);
  checkI128(parsed, label);
  return parsed;
}
function canonicalU16(value, label) {
  requireThat(typeof value === 'string' && /^[1-9][0-9]*$/.test(value), `${label} is not canonical positive decimal`);
  const parsed = BigInt(value);
  requireThat(parsed <= 65_535n, `${label} exceeds u16`);
  return parsed;
}
function checkI128(value, label) { requireThat(value >= -(1n << 127n) && value < (1n << 127n), `${label} exceeds i128`); }
function compareTime(left, right) { return (typeof left === 'bigint' ? left : canonicalTime(left)) < (typeof right === 'bigint' ? right : canonicalTime(right)) ? -1
  : (typeof left === 'bigint' ? left : canonicalTime(left)) > (typeof right === 'bigint' ? right : canonicalTime(right)) ? 1 : 0; }
function compareFullKey(left, right, compareKey = compareTime) {
  const at = compareKey(left.time, right.time); if (at) return at;
  const a = Buffer.from(left.address.id.replaceAll('-', ''), 'hex'), b = Buffer.from(right.address.id.replaceAll('-', ''), 'hex');
  const id = Buffer.compare(a, b); return id || left.address.slot - right.address.slot;
}
function addressToken(address) {
  if (address === null) return null;
  object(address, 'tree address');
  exactKeys(address, ['id', 'slot'], 'tree address');
  requireThat(typeof address.id === 'string' && UUID.test(address.id) && Number.isInteger(address.slot) && address.slot > 0 && address.slot <= 65535,
    'invalid tree address');
  return `${address.id}/${address.slot}`;
}
function parseAddressToken(token) {
  requireThat(typeof token === 'string', 'invalid expected root address');
  const match = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/([1-9][0-9]*)$/.exec(token);
  requireThat(match !== null, 'invalid expected root address');
  const slot = Number(match[2]);
  requireThat(Number.isInteger(slot) && slot <= 65535, 'invalid expected root address');
  return { id: match[1], slot };
}
function sameAddress(left, right) { return (left === null && right === null) || (left !== null && right !== null && addressToken(left) === addressToken(right)); }
function structuralSize(value, emptyAllowed) {
  requireThat(Number.isSafeInteger(value) && value >= (emptyAllowed ? 0 : 1) && value <= MAX_TREE_NODES,
    'invalid structural size for bounded tree inventory');
}
function validateRoot(root, address) {
  structuralSize(root.size, true);
  exactKeys(root, ['kind', 'head', 'first', 'last', 'height', 'size', 'span', 'summary', 'revision'], 'tree root');
  if (root.span !== null) { object(root.span, 'tree root span'); exactKeys(root.span, ['first', 'last'], 'tree root span'); }
  requireThat(address.slot > 0 && (root.head === null) === (root.height === 0)
    && (root.head === null) === (root.first === null) && (root.head === null) === (root.last === null)
    && (root.head === null) === (root.span === null), 'invalid root empty-state shape');
  for (const link of [root.head, root.first, root.last]) if (link !== null) addressToken(link);
  requireThat(root.revision && UUID.test(root.revision) && root.revision !== '00000000-0000-0000-0000-000000000000', 'invalid root revision');
}
function formatUuid(bytes) { const hex = bytes.toString('hex'); return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`; }
function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function object(value, label) { requireThat(value !== null && typeof value === 'object' && !Array.isArray(value), `${label} must be an object`); }
function exactKeys(value, expected, label) { requireThat(Object.keys(value).sort().join('\0') === [...expected].sort().join('\0'), `${label} fields differ`); }
function equalJson(a, b) { return canonicalJson(a) === canonicalJson(b); }
function canonicalTypedValue(value) {
  const access = value.type === 'access_root' || value.type === 'access_node';
  if (value.type === 'root' || value.type === 'access_root') {
    const data = value.data;
    const kind = data.kind;
    exactKeys(data, ['kind', 'head', 'first', 'last', 'height', 'size', 'span', 'summary', 'revision'], 'tree root');
    return JSON.stringify({ type: value.type, data: {
      kind, head: orderedAddress(data.head), first: orderedAddress(data.first), last: orderedAddress(data.last),
      height: data.height, size: data.size, span: orderedSpan(data.span, access), summary: access ? data.summary : orderedSummary(kind, data.summary), revision: data.revision,
    } });
  }
  const data = value.data;
  exactKeys(data, ['kind', 'root', 'key', 'leaf', 'parent', 'left', 'right', 'prev', 'next', 'height', 'size', 'span', 'summary'], 'tree node');
  exactKeys(data.key, ['value', 'id', 'slot'], 'tree node key');
  return JSON.stringify({ type: value.type, data: {
    kind: data.kind, root: orderedAddress(data.root),
    key: { value: access ? orderedOrderKey(data.key.value) : data.key.value, id: data.key.id, slot: data.key.slot },
    leaf: access ? data.leaf : orderedLeaf(data.kind, data.leaf), parent: orderedAddress(data.parent), left: orderedAddress(data.left),
    right: orderedAddress(data.right), prev: orderedAddress(data.prev), next: orderedAddress(data.next),
    height: data.height, size: data.size, span: orderedSpan(data.span, access), summary: access ? data.summary : orderedSummary(data.kind, data.summary),
  } });
}
function orderedAddress(address) {
  if (address === null) return null;
  object(address, 'tree address');
  exactKeys(address, ['id', 'slot'], 'tree address');
  return { id: address.id, slot: address.slot };
}
function orderedSpan(span, access = false) {
  if (span === null) return null;
  object(span, 'tree span');
  exactKeys(span, ['first', 'last'], 'tree span');
  return { first: access ? orderedOrderKey(span.first) : span.first, last: access ? orderedOrderKey(span.last) : span.last };
}
function orderedOrderKey(value) { return orderKey(value).map(atom => ({ kind: atom.kind, value: atom.value })); }
function orderedLeaf(kind, leaf) {
  object(leaf, 'tree leaf');
  if (kind === 1 || kind === 2) {
    exactKeys(leaf, ['kind', 'value'], 'standard leaf');
    return { kind: leaf.kind, value: leaf.value };
  }
  if (kind === 7) {
    exactKeys(leaf, ['unit', 'value'], 'Measurement leaf');
    return { unit: leaf.unit, value: leaf.value };
  }
  throw new TypeError(`unsupported native index kind ${String(kind)}`);
}
function orderedSummary(kind, summary) {
  object(summary, 'tree summary');
  if (kind === 1) {
    exactKeys(summary, ['kind', 'value'], 'Financial summary');
    const value = summary.value;
    exactKeys(value, ['count', 'first', 'last', 'sum', 'min_prefix', 'max_prefix', 'boundary_min', 'boundary_max'], 'Financial summary value');
    return { kind: summary.kind, value: { count: value.count, first: value.first, last: value.last, sum: value.sum,
      min_prefix: value.min_prefix, max_prefix: value.max_prefix, boundary_min: value.boundary_min, boundary_max: value.boundary_max } };
  }
  if (kind === 2) {
    exactKeys(summary, ['kind', 'value'], 'Quote summary');
    const value = summary.value;
    exactKeys(value, ['count', 'first', 'last'], 'Quote summary value');
    return { kind: summary.kind, value: { count: value.count, first: value.first, last: value.last } };
  }
  if (kind === 7) {
    exactKeys(summary, ['count', 'sum', 'min', 'max', 'dimension'], 'Measurement summary');
    const dimension = summary.dimension;
    object(dimension, 'Measurement dimension');
    if (dimension.kind === 'unit') {
      exactKeys(dimension, ['kind', 'code'], 'unit dimension');
      return { count: summary.count, sum: summary.sum, min: summary.min, max: summary.max,
        dimension: { kind: dimension.kind, code: dimension.code } };
    }
    exactKeys(dimension, ['kind'], 'empty/mixed dimension');
    return { count: summary.count, sum: summary.sum, min: summary.min, max: summary.max,
      dimension: { kind: dimension.kind } };
  }
  throw new TypeError(`unsupported native index kind ${String(kind)}`);
}
function requireThat(condition, message) { if (!condition) throw new TypeError(message); }
function positiveBound(value, ceiling, label) {
  requireThat(Number.isSafeInteger(value) && value > 0 && value <= ceiling, `${label} must be within its hard bound`);
}
