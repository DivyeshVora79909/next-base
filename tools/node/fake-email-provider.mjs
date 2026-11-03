import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { lstat, mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';
import { parseFrame } from './private/json-codec.mjs';

const FORMAT = 'rebase-fake-email-journal-1';
const MAX_BYTES = 8 * 1024 * 1024;
const MAX_BODY = 65_536;
const MAX_CALLS = 4096;
const MAX_EXECUTIONS = 2048;
const ACTION = 'email-send-1';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ACCOUNT = /^[A-Za-z0-9._:-]{1,128}$/;
const MODES = new Set(['success', 'waiting', 'not_accepted', 'reject_once', 'failed', 'lost_response', 'empty', 'pause_response', 'malformed']);
const fault = () => new TypeError('Invalid fake email protocol');
function keys(value, names) { if (!value || Array.isArray(value) || typeof value !== 'object' || Object.keys(value).length !== names.length || names.some(name => !Object.hasOwn(value, name))) throw fault(); }
function id(value) { if (typeof value !== 'string' || !UUID.test(value) || value === '00000000-0000-0000-0000-000000000000') throw fault(); return value; }
function account(value) { if (typeof value !== 'string' || !ACCOUNT.test(value)) throw fault(); return value; }
function address(value) {
  if (typeof value !== 'string' || !value || value.length > 254 || /[^\x20-\x7e]/.test(value)) throw fault();
  const parts = value.split('@');
  if (parts.length !== 2 || !/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$/.test(parts[0]) || parts[0].startsWith('.') || parts[0].endsWith('.') || parts[0].includes('..')
    || parts[1].length > 253 || parts[1].split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw fault();
  return value;
}
function email(value) {
  keys(value, ['sender', 'to', 'subject', 'text']);
  address(value.sender);
  if (!Array.isArray(value.to) || value.to.length < 1 || value.to.length > 16 || new Set(value.to.map(address)).size !== value.to.length
    || typeof value.subject !== 'string' || !value.subject.isWellFormed() || /[\x00-\x1f\x7f]/.test(value.subject) || Buffer.byteLength(value.subject) > 512
    || typeof value.text !== 'string' || !value.text.isWellFormed() || Buffer.byteLength(value.text) > 16_384) throw fault();
  return { sender: value.sender, to: [...value.to], subject: value.subject, text: value.text };
}
function hash(value) { return createHash('sha256').update('next-base/email-send/1\0').update(JSON.stringify(email(value))).digest('hex'); }
function same(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
function decodeResend(body) {
  keys(body, ['from', 'to', 'subject', 'text']);
  return email({ sender: body.from, to: body.to, subject: body.subject, text: body.text });
}
function decodeBrevo(body) {
  keys(body, ['sender', 'to', 'subject', 'textContent']); keys(body.sender, ['email']);
  if (!Array.isArray(body.to)) throw fault();
  return email({ sender: body.sender.email, to: body.to.map(row => { keys(row, ['email']); return row.email; }), subject: body.subject, text: body.textContent });
}
function responseFor(provider, execution, expected, disposition) {
  const receipt = disposition === 'not_accepted' ? null : `${provider}:${execution}`;
  return provider === 'resend'
    ? { id: receipt, rebase: { provider, execution_id: execution, account: expected.account, request_hash: expected.hash, status: disposition } }
    : { messageId: receipt, event: { provider, execution, account: expected.account, requestHash: expected.hash, disposition } };
}

/** Independent, single-writer fake journals. Keys stay solely in the owned handle. */
export async function startFakeEmailProvider({ provider, directory, accounts, host = '127.0.0.1' } = {}) {
  if (!['resend', 'brevo'].includes(provider) || typeof directory !== 'string' || !path.isAbsolute(directory) || host !== '127.0.0.1'
    || !Array.isArray(accounts) || !accounts.length || accounts.length > 16) throw fault();
  const credentials = new Map(); const keyOwners = new Map();
  for (const row of accounts) {
    keys(row, ['account', 'keys']); account(row.account);
    if (credentials.has(row.account) || !Array.isArray(row.keys) || !row.keys.length || row.keys.length > 16) throw fault();
    const values = row.keys.map(key => {
      if (typeof key !== 'string' || !key || !key.isWellFormed() || Buffer.byteLength(key) > 512 || /[\x00-\x1f\x7f]/.test(key) || keyOwners.has(key)) throw fault();
      keyOwners.set(key, row.account); return Buffer.from(key);
    });
    credentials.set(row.account, values);
  }
  keyOwners.clear();
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const journalPath = path.join(directory, `${provider}.journal.json`);
  let state;
  try {
    const info = await lstat(journalPath);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > MAX_BYTES || (info.mode & 0o077)) throw fault();
    state = parseFrame(await readFile(journalPath));
  } catch (error) { if (error.code !== 'ENOENT') throw error; state = { format: FORMAT, provider, expected: {}, executions: {}, calls: [], modes: {} }; }
  validateJournal(state, provider);
  let queue = Promise.resolve(); let closed = false; let uncertain = false; let closePromise;
  const holds = new Map();
  function assertOpen() { if (closed || uncertain) throw new Error('Fake email provider is unavailable'); }
  function transaction(operation) {
    const pending = queue.then(async () => {
      assertOpen(); const next = structuredClone(state); const result = operation(next); validateJournal(next, provider);
      try { await persist(journalPath, next); } catch { uncertain = true; throw new Error('Fake email journal durability is unknown'); }
      state = next; return result;
    });
    queue = pending.catch(() => {}); return pending;
  }
  const base = provider === 'resend' ? '/emails' : '/v3/smtp/email';
  const server = createServer((request, response) => { void handle(request, response).catch(() => { if (!response.headersSent) reply(response, 500, { error: 'unavailable' }); else response.destroy(); }); });
  server.requestTimeout = 10_000; server.headersTimeout = 5000; server.maxHeadersCount = 32; server.maxConnections = 64;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, host, resolve); });
  const endpoint = `http://${host}:${server.address().port}`;
  async function handle(request, response) {
    let execution; let intent; let expected; let method;
    try {
      const url = new URL(request.url, endpoint);
      if (url.search || url.hash) throw fault();
      method = request.method;
      if (method === 'POST' && url.pathname === base) {
        execution = provider === 'resend' ? request.headers['idempotency-key']?.replace(`${ACTION}/`, '') : request.headers['x-rebase-execution'];
        id(execution);
        if (provider === 'resend' && request.headers['idempotency-key'] !== `${ACTION}/${execution}`) throw fault();
        if (request.headers['content-type']?.split(';')[0].trim() !== 'application/json') throw fault();
        const body = parseFrame(await readBody(request));
        intent = provider === 'resend' ? decodeResend(body) : decodeBrevo(body);
      } else if (method === 'GET' && url.pathname.startsWith(`${base}/`)) execution = id(url.pathname.slice(base.length + 1));
      else return reply(response, 404, { error: 'unknown' });
      if (request.headers['x-rebase-action'] !== ACTION) throw fault();
      const binding = account(request.headers['x-rebase-account']);
      const key = provider === 'resend' ? request.headers.authorization : request.headers['api-key'];
      if (typeof key !== 'string' || (provider === 'resend' && !key.startsWith('Bearer '))) throw fault();
      const supplied = Buffer.from(provider === 'resend' ? key.slice(7) : key, 'latin1');
      const authorized = (credentials.get(binding) ?? []).some(value => value.length === supplied.length && timingSafeEqual(value, supplied)); supplied.fill(0);
      if (!authorized) return reply(response, 401, { error: 'unauthorized' });
      await queue; expected = state.expected[execution];
      if (!expected || expected.account !== binding || request.headers['x-rebase-request-hash'] !== expected.hash || (intent && !same(intent, expected.email))) throw fault();
    } catch { return reply(response, 400, { error: 'invalid protocol' }); }
    const result = await transaction(next => {
      if (next.calls.length >= MAX_CALLS) throw fault();
      const mode = next.modes[execution] ?? 'success';
      let accepted = next.executions[execution];
      const submits = next.calls.filter(call => call.execution === execution && call.method === 'POST').length;
      let disposition;
      if (method === 'POST') {
        if (!accepted) {
          disposition = mode === 'not_accepted' || (mode === 'reject_once' && submits === 0) ? 'not_accepted' : mode === 'waiting' ? 'waiting' : mode === 'failed' ? 'failed' : 'succeeded';
          if (disposition !== 'not_accepted') accepted = next.executions[execution] = { account: expected.account, hash: expected.hash, disposition };
        } else disposition = accepted.disposition;
      } else {
        if (accepted?.disposition === 'waiting' && ['success', 'failed'].includes(mode)) accepted.disposition = mode === 'success' ? 'succeeded' : 'failed';
        disposition = accepted?.disposition;
      }
      next.calls.push({ execution, method, account: expected.account, hash: expected.hash, disposition: disposition ?? null });
      return { mode, disposition };
    });
    if (method === 'POST' && result.mode === 'pause_response') {
      const hold = holds.get(execution);
      if (hold) { hold.paused = true; hold.arrived(); await hold.promise; }
    }
    if (method === 'POST' && result.mode === 'lost_response') { response.destroy(); return; }
    if (!result.disposition || result.mode === 'empty') return reply(response, 404, { error: 'unknown' });
    if (result.mode === 'malformed') return reply(response, 200, { unexpected: true });
    return reply(response, 200, responseFor(provider, execution, expected, result.disposition));
  }
  return Object.freeze({ provider, endpoint, directory,
    async expect(execution, value) {
      assertOpen(); id(execution); keys(value, ['account', 'email']); account(value.account); const normalized = email(value.email);
      if (!credentials.has(value.account)) throw fault();
      const expected = { account: value.account, email: normalized, hash: hash(normalized) };
      await transaction(next => { if (next.expected[execution] && !same(next.expected[execution], expected)) throw fault(); next.expected[execution] = expected; });
    },
    async setMode(execution, mode) { assertOpen(); id(execution); if (!MODES.has(mode)) throw fault(); await transaction(next => { next.modes[execution] = mode; }); },
    holdResponse(execution) {
      assertOpen(); id(execution); if (holds.has(execution) || holds.size >= 64) throw fault();
      let release; let arrived;
      let waiting = false;
      const promise = new Promise(resolve => { release = resolve; }); const arrival = new Promise(resolve => { arrived = resolve; });
      holds.set(execution, { promise, release, arrived, paused: false });
      return Object.freeze({
        async waitUntilPaused({ timeoutMs = 5000 } = {}) {
          assertOpen(); if (waiting || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) throw fault();
          waiting = true;
          let timer; try { await Promise.race([arrival, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Fake email response did not pause')), timeoutMs); })]); assertOpen(); }
          finally { clearTimeout(timer); waiting = false; }
        },
        release() { assertOpen(); const hold = holds.get(execution); if (!hold) return false; holds.delete(execution); hold.release(); return true; },
      });
    },
    async counts(execution) { assertOpen(); id(execution); await queue; const calls = state.calls.filter(call => call.execution === execution); return { submissions: calls.filter(call => call.method === 'POST').length, observations: calls.filter(call => call.method === 'GET').length, accepted: state.executions[execution] ? 1 : 0 }; },
    async calls(execution) { assertOpen(); if (execution !== undefined) id(execution); await queue; return structuredClone(state.calls.filter(call => execution === undefined || call.execution === execution)); },
    async execution(execution) { assertOpen(); id(execution); await queue; return structuredClone(state.executions[execution] ?? null); },
    close() { closePromise ??= (async () => { closed = true; for (const hold of holds.values()) { hold.arrived(); hold.release(); } holds.clear(); await queue; await new Promise(resolve => server.close(resolve)); for (const list of credentials.values()) for (const bytes of list) bytes.fill(0); credentials.clear(); })(); return closePromise; },
  });
}
function validateJournal(value, provider) {
  keys(value, ['format', 'provider', 'expected', 'executions', 'calls', 'modes']);
  if (value.format !== FORMAT || value.provider !== provider || !Array.isArray(value.calls) || value.calls.length > MAX_CALLS
    || Object.keys(value.expected).length > MAX_EXECUTIONS || Object.keys(value.executions).length > MAX_EXECUTIONS || Object.keys(value.modes).length > MAX_EXECUTIONS) throw fault();
  for (const [execution, expected] of Object.entries(value.expected)) { id(execution); keys(expected, ['account', 'email', 'hash']); account(expected.account); if (hash(expected.email) !== expected.hash) throw fault(); }
  for (const [execution, result] of Object.entries(value.executions)) {
    id(execution); keys(result, ['account', 'hash', 'disposition']); const expected = value.expected[execution];
    if (!expected || result.account !== expected.account || result.hash !== expected.hash || !['waiting', 'succeeded', 'failed'].includes(result.disposition)
      || !value.calls.some(call => call.execution === execution && call.method === 'POST' && ['waiting', 'succeeded', 'failed'].includes(call.disposition))) throw fault();
  }
  for (const [execution, mode] of Object.entries(value.modes)) { id(execution); if (!MODES.has(mode)) throw fault(); }
  for (const call of value.calls) {
    keys(call, ['execution', 'method', 'account', 'hash', 'disposition']); const expected = value.expected[id(call.execution)];
    if (!expected || call.account !== expected.account || call.hash !== expected.hash || !['GET', 'POST'].includes(call.method) || ![null, 'waiting', 'succeeded', 'failed', 'not_accepted'].includes(call.disposition)) throw fault();
  }
  if (Buffer.byteLength(JSON.stringify(value)) > MAX_BYTES) throw fault();
}
async function readBody(request) {
  const chunks = []; let size = 0;
  for await (const chunk of request) { size += chunk.length; if (size > MAX_BODY) throw fault(); chunks.push(chunk); }
  return Buffer.concat(chunks);
}
function reply(response, status, value) { response.writeHead(status, { 'content-type': 'application/json' }); response.end(JSON.stringify(value)); }
async function persist(destination, value) {
  const temporary = `${destination}.${randomUUID()}.tmp`;
  let file;
  try { file = await open(temporary, 'wx', 0o600); await file.writeFile(JSON.stringify(value)); await file.sync(); await file.close(); file = null; await rename(temporary, destination); const directory = await open(path.dirname(destination), 'r'); try { await directory.sync(); } finally { await directory.close(); } }
  finally { await file?.close(); await rm(temporary, { force: true }); }
}
