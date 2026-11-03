import { parseFrame } from './json-codec.mjs';
import { normalizeEmailAddress } from './email-address.mjs';

const NIL = '00000000-0000-0000-0000-000000000000';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const fail = message => { throw new Error(`Private proof inventory: ${message}`); };
const require = (ok, message) => { if (!ok) fail(message); };
const uuid = value => require(typeof value === 'string' && UUID.test(value) && value !== NIL, 'UUID differs');
const digest = value => {
  require(typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value), 'digest differs');
  const decoded = Buffer.from(value, 'base64url');
  require(decoded.length === 32 && decoded.toString('base64url') === value, 'digest encoding differs');
};
const keyId = value => require(typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value), 'key ID differs');
const fields = (value, names) => require(value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name)), 'fields differ');
const number = (value, max = (1n << 63n) - 1n) => {
  require(typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value) && BigInt(value) <= max, 'canonical integer differs');
  return BigInt(value);
};
const u64 = value => number(value, (1n << 64n) - 1n);
const bytes = value => {
  require(typeof value === 'string' && /^(?:[0-9a-f]{2})*$/.test(value), 'hex differs');
  return Buffer.from(value, 'hex');
};
const stable = value => Array.isArray(value) ? `[${value.map(stable).join(',')}]`
  : value && typeof value === 'object' ? `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${stable(value[k])}`).join(',')}}`
    : JSON.stringify(value);
const same = (a, b) => stable(a) === stable(b);
const textKey = value => bytes(value).toString('utf8');
const idKey = value => value.replaceAll('-', '');
function rows(input, limit) {
  require(Array.isArray(input) && input.length <= limit, 'table bound differs');
  const result = new Map();
  for (const row of input) {
    fields(row, ['key', 'value']); bytes(row.key);
    require(!result.has(row.key), 'duplicate key');
    const decoded = parseFrame(bytes(row.value));
    require(JSON.stringify(decoded) === bytes(row.value).toString('utf8'), 'row encoding differs');
    result.set(row.key, decoded);
  }
  return result;
}
function base64(value, min, max) {
  require(typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value), 'ciphertext encoding differs');
  const decoded = Buffer.from(value, 'base64url');
  require(decoded.length >= min && decoded.length <= max && decoded.toString('base64url') === value, 'ciphertext bound differs');
}
function envelope(value) {
  fields(value, ['key_id', 'nonce', 'ciphertext']); keyId(value.key_id);
  base64(value.nonce, 24, 24); base64(value.ciphertext, 16, 4112);
}
function canonicalSender(value) {
  try { return normalizeEmailAddress(value) === value; } catch { return false; }
}
function policy(value) {
  fields(value, ['kind', 'revision', 'credential', 'owner', 'provider', 'account', 'sender']);
  for (const name of ['revision', 'credential', 'owner']) uuid(value[name]);
  require(typeof value.account === 'string' && /^[A-Za-z0-9._:-]{1,128}$/.test(value.account), 'policy account differs');
  require(value.kind === 'phone' ? value.provider === 'fake_sms' && value.sender === null
    : value.kind === 'email' && ['resend', 'brevo'].includes(value.provider)
      && canonicalSender(value.sender), 'policy channel differs');
}

export function checkRuntimeHeader(input) {
  const table = rows(input, 1), header = table.get(Buffer.from('header').toString('hex'));
  fields(header, ['format', 'store_id', 'session_generation', 'cursor_key', 'operation_epoch']);
  require(header.format === 'rebase-store-11', 'runtime format differs');
  uuid(header.store_id); uuid(header.session_generation);
  require(typeof header.cursor_key === 'string' && /^[0-9a-f]{64}$/.test(header.cursor_key), 'runtime cursor key differs');
  u64(header.operation_epoch);
  return header;
}

/** Independent retained-fact checks. This never returns private rows or claims. */
export function checkProofInventory(tables, records, executions, metadata, header, catalog) {
  const challenges = rows(tables.auth_challenges, 256), receipts = rows(tables.auth_receipts, 1536);
  const handles = rows(tables.auth_handles, 256), heads = rows(tables.auth_heads, 256), runtime = rows(tables.auth_runtime, 3);
  if (catalog && !catalog.capabilities?.identities) require(challenges.size === 0 && receipts.size === 0 && runtime.size === 0,
    'proof capability is not declared');
  const expectedHandles = new Map(), lifetimes = new Map(), origins = new Set(), attempts = new Map(), consumed = new Set(), verified = new Map();
  const lastSpent = new Map(), consumedAt = new Map();
  for (const [key, c] of challenges) {
    fields(c, ['format', 'id', 'generation', 'operation', 'source', 'execution', 'created_at', 'expires_at', 'binding', 'previous',
      'key_id', 'verifier', 'nonce', 'handle_digest', 'identifier_digest', 'response', 'attempts', 'consumed']);
    require(c.format === 'auth-proof-1', 'challenge format differs');
    for (const name of ['id', 'generation', 'operation', 'nonce']) uuid(c[name]);
    keyId(c.key_id); digest(c.verifier); digest(c.handle_digest); digest(c.identifier_digest); envelope(c.response);
    require(key === idKey(c.id) && number(c.created_at) + 300_000n === number(c.expires_at)
      && Number.isInteger(c.attempts) && c.attempts >= 0 && c.attempts <= 5 && typeof c.consumed === 'boolean', 'challenge bounds differ');
    require(!expectedHandles.has(c.handle_digest), 'repeated challenge handle');
    expectedHandles.set(c.handle_digest, c.id);
    if (c.binding === null) {
      require(c.source === NIL && c.execution === NIL && c.attempts === 0 && !c.consumed && c.previous === null, 'suppressed challenge state differs');
      continue;
    }
    const b = c.binding;
    fields(b, ['identity', 'incarnation', 'owner', 'identity_revision', 'authentication_revision', 'credential_epoch', 'policy']);
    for (const name of ['identity', 'incarnation', 'owner']) uuid(b[name]);
    require(u64(b.identity_revision) > 0n && u64(b.authentication_revision) >= u64(b.identity_revision), 'bound identity revision differs');
    u64(b.credential_epoch); policy(b.policy); uuid(c.source); uuid(c.execution);
    const source = records.get(c.source), execution = executions.get(idKey(c.execution));
    require(source?.contract === 1004 && source.tenant === metadata?.tenant && source.owner === b.owner
      && source.created_at === c.created_at, 'delivery source differs');
    fields(source.input, ['challenge', 'generation', 'payload', 'expires_at']); envelope(source.input.payload);
    require(source.input.challenge === c.id && source.input.generation === c.generation && source.input.expires_at === c.expires_at,
      'delivery challenge differs');
    require(execution?.source === c.source && execution.target === c.source && execution.id === c.execution
      && execution.operation_id === c.operation && execution.requester === b.owner && execution.store === header.store_id
      && execution.tenant === metadata?.tenant && String(execution.credential_epoch) === b.credential_epoch
      && same(execution.request, source.input) && same(execution.email_binding?.server_policy, b.policy), 'delivery origin differs');
    if (!lifetimes.has(b.incarnation)) lifetimes.set(b.incarnation, []);
    lifetimes.get(b.incarnation).push(c);
  }
  require(handles.size === expectedHandles.size, 'handle inventory differs');
  for (const [key, id] of handles) require(expectedHandles.get(textKey(key)) === id, 'handle source differs');
  require(heads.size === lifetimes.size, 'head inventory differs');
  for (const [incarnation, chain] of lifetimes) {
    const successors = new Map();
    for (const c of chain) {
      require(!successors.has(c.previous), 'challenge history forks');
      if (c.previous !== null) {
        uuid(c.previous);
        const previous = challenges.get(idKey(c.previous));
        require(previous?.binding?.incarnation === incarnation && number(previous.created_at) <= number(c.created_at), 'challenge predecessor differs');
      }
      successors.set(c.previous, c);
    }
    let current = successors.get(null), last, visited = 0;
    while (current && visited <= chain.length) { visited += 1; last = current; current = successors.get(current.id); }
    require(visited === chain.length && !current && heads.get(idKey(incarnation)) === last?.id, 'head chain differs');
  }
  const admission = [], admissionByDomain = new Map();
  for (const [key, r] of receipts) {
    fields(r, ['format', 'operation', 'generation', 'key_id', 'recovery', 'fingerprint', 'created_at', 'admission', 'outcome']);
    require(r.format === 'auth-proof-1' && key === idKey(r.operation), 'receipt identity differs');
    uuid(r.operation); uuid(r.generation); keyId(r.key_id); digest(r.recovery); digest(r.fingerprint); number(r.created_at);
    const begin = r.outcome?.kind === 'begin';
    require(Array.isArray(r.admission) && r.admission.length === (begin ? 2 : 1), 'receipt admission differs');
    for (const [index, point] of r.admission.entries()) {
      fields(point, ['key', 'at', 'consume']); digest(point.key); number(point.at);
      require(point.at === r.created_at && point.consume === !begin, 'admission binding differs');
      const domain = `${begin ? index : 2}/${point.key}`;
      if (!admissionByDomain.has(domain)) admissionByDomain.set(domain, { window: begin && index === 0 ? 300_000n : 60_000n,
        limit: begin ? index === 0 ? 3 : 32 : 64, times: [] });
      admissionByDomain.get(domain).times.push(BigInt(point.at)); admission.push(point);
    }
    const outcome = r.outcome, c = typeof outcome.challenge === 'string' ? challenges.get(idKey(outcome.challenge)) : undefined;
    if (begin) {
      fields(outcome, ['kind', 'challenge']);
      require(c && c.generation === r.generation && number(c.created_at) <= number(r.created_at)
        && number(r.created_at) < number(c.expires_at), 'begin source or lifetime differs');
      require(r.admission[0].key === c.identifier_digest, 'begin identifier binding differs');
      if (c.operation === r.operation) {
        require(c.created_at === r.created_at, 'original begin time differs');
        origins.add(c.id);
      }
    } else if (outcome.kind === 'invalid') {
      fields(outcome, ['kind', 'challenge', 'spent']);
      require(typeof outcome.spent === 'boolean' && outcome.spent === (outcome.challenge !== null), 'invalid attempt differs');
      if (outcome.spent) {
        require(c && c.binding !== null && c.generation === r.generation && number(c.created_at) <= number(r.created_at)
          && number(r.created_at) < number(c.expires_at), 'spent attempt source or lifetime differs');
        attempts.set(c.id, (attempts.get(c.id) ?? 0) + 1);
        const at = number(r.created_at);
        if (!lastSpent.has(c.id) || lastSpent.get(c.id) < at) lastSpent.set(c.id, at);
      }
    } else {
      fields(outcome, ['kind', 'challenge', 'issuance']);
      require(outcome.kind === 'issued' && c?.binding && !consumed.has(c.id), 'issuance source or one-use differs');
      fields(outcome.issuance, ['claims', 'key_id']); keyId(outcome.issuance.key_id);
      const claims = outcome.issuance.claims;
      fields(claims, ['iss', 'aud', 'sub', 'tenant', 'epoch', 'generation', 'iat', 'nbf', 'exp']);
      require(typeof claims.iss === 'string' && claims.iss.length > 0 && typeof claims.aud === 'string' && claims.aud.length > 0
        && claims.sub === c.binding.owner && claims.tenant === metadata?.tenant && String(claims.epoch) === c.binding.credential_epoch
        && claims.generation === c.generation && r.generation === c.generation && Number.isSafeInteger(claims.iat)
        && BigInt(claims.iat) === number(r.created_at) / 1000n && claims.nbf === claims.iat && claims.exp === claims.iat + 900
        && number(c.created_at) <= number(r.created_at) && number(r.created_at) < number(c.expires_at), 'pinned claims or lifetime differ');
      consumed.add(c.id); attempts.set(c.id, (attempts.get(c.id) ?? 0) + 1);
      consumedAt.set(c.id, number(r.created_at));
      const bound = c.binding, verificationKey = `${bound.identity}/${bound.incarnation}/${bound.identity_revision}`;
      if (!verified.has(verificationKey) || verified.get(verificationKey) < number(r.created_at)) verified.set(verificationKey, number(r.created_at));
    }
  }
  require(origins.size === challenges.size, 'challenge origin receipt missing');
  for (const c of challenges.values()) require(c.attempts === (attempts.get(c.id) ?? 0) && c.consumed === consumed.has(c.id),
    'attempt count or consumption differs from receipts');
  for (const [id, at] of lastSpent) require(!consumedAt.has(id) || at <= consumedAt.get(id), 'spent attempt follows successful consumption');
  for (const [id, source] of records) if (source.contract === 1004)
    require(challenges.get(idKey(source.input?.challenge ?? ''))?.source === id, 'unbound private delivery source');
  for (const [id, source] of records) if (source.contract === 1003) {
    const state = source.derived, at = verified.get(`${id}/${state.incarnation}/${state.identity_revision}`);
    require(at === undefined ? state.verified_revision === null && state.verified_at === null
      : state.verified_revision === state.identity_revision && state.verified_at === at.toString(), 'identity verification differs from issuance');
  }
  for (const domain of admissionByDomain.values()) for (const at of domain.times)
    require(domain.times.filter(value => value > at - domain.window && value <= at).length <= domain.limit, 'admission limit exceeded');
  const state = runtime.get(Buffer.from('state').toString('hex'));
  if (!state) require(challenges.size === 0 && receipts.size === 0 && runtime.size === 0, 'runtime missing');
  else {
    fields(state, ['format', 'admission_key_id', 'last_at', 'challenges', 'receipts', 'points']); keyId(state.admission_key_id);
    const last = number(state.last_at);
    require(state.format === 'auth-proof-1' && state.challenges === challenges.size && state.receipts === receipts.size
      && Array.isArray(state.points) && state.points.length <= 3072 && admission.every(point => BigInt(point.at) <= last), 'runtime count or clock differs');
    const expected = admission.filter(point => BigInt(point.at) > last - 300_000n).map(stable).sort();
    require(same(state.points.map(stable).sort(), expected), 'admission points differ from original receipts');
    for (const [key, value] of runtime) if (textKey(key) !== 'state') {
      policy(value); require(key === (value.kind === 'email' ? '01' : '02'), 'runtime policy key differs');
    }
  }
  return { proofInventory: 'checked', proofChallengeCount: challenges.size, proofReceiptCount: receipts.size,
    proofAttemptCount: [...attempts.values()].reduce((sum, value) => sum + value, 0), proofIssuanceCount: consumed.size,
    proofCryptographicAuthentication: 'not_evaluated' };
}
