// Independent fake inbox custody for authentication acceptance. Never a service RPC.
// The opaque request hash is supplied by the encrypted intent; no code hash is made here.
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { lstat, mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';
import { parseFrame } from './private/json-codec.mjs';

const FORMAT = 'next-base-fake-auth-provider-journal-1';
const ACTION = 'auth-delivery-1';
const CODE_PREFIX = 'Your sign-in code is ';
const MAX_BYTES = 8 * 1024 * 1024;
const MAX_BODY = 4096;
const MAX_CALLS = 4096;
const MAX_EXECUTIONS = 2048;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HASH = /^[0-9a-f]{64}$/;
const MODES = new Set(['success', 'waiting', 'not_accepted', 'reject_once', 'failed', 'lost_response', 'empty', 'malformed']);
const STATES = new Set(['waiting', 'succeeded', 'failed']);
const ROUTES = Object.freeze({ resend: '/emails', brevo: '/v3/smtp/email', fake_sms: '/sms/messages' });
const fault = () => new TypeError('Invalid fake authentication protocol');
function keys(value, names) {
  if (!value || Array.isArray(value) || typeof value !== 'object' || Object.keys(value).length !== names.length || names.some(name => !Object.hasOwn(value, name))) throw fault();
}
function id(value) {
  if (typeof value !== 'string' || value.length !== 36 || !UUID.test(value) || value === '00000000-0000-0000-0000-000000000000') throw fault();
  return value;
}
function hash(value) { if (typeof value !== 'string' || value.length !== 64 || !HASH.test(value)) throw fault(); return value; }
function accountName(value) { if (typeof value !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/.test(value) || /[\r\n]/.test(value)) throw fault(); return value; }
function address(value) {
  if (typeof value !== 'string' || value.length > 254 || /[^\x20-\x7e]/.test(value)) throw fault();
  const parts = value.split('@');
  if (parts.length !== 2 || !/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$/.test(parts[0]) || parts[0].startsWith('.') || parts[0].endsWith('.') || parts[0].includes('..')
    || parts[1].split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw fault();
  return value;
}
function validateConfig({ provider, account, recipient, sender }) {
  if (!Object.hasOwn(ROUTES, provider)) throw fault();
  accountName(account);
  if (provider === 'fake_sms') {
    if (typeof recipient !== 'string' || !/^\+[1-9][0-9]{7,14}$/.test(recipient) || /[\r\n]/.test(recipient) || sender !== null) throw fault();
  } else {
    address(recipient); address(sender);
    if (recipient !== recipient.toLowerCase()) throw fault();
  }
}
function codeFromBody(provider, body, recipient, sender) {
  let text;
  if (provider === 'resend') {
    keys(body, ['from', 'to', 'subject', 'text']);
    if (body.from !== sender || !Array.isArray(body.to) || body.to.length !== 1 || body.to[0] !== recipient || body.subject !== 'Sign-in code') throw fault();
    text = body.text;
  } else if (provider === 'brevo') {
    keys(body, ['sender', 'to', 'subject', 'textContent']); keys(body.sender, ['email']);
    if (!Array.isArray(body.to) || body.to.length !== 1) throw fault();
    keys(body.to[0], ['email']);
    if (body.sender.email !== sender || body.to[0].email !== recipient || body.subject !== 'Sign-in code') throw fault();
    text = body.textContent;
  } else {
    keys(body, ['recipient', 'message']);
    if (body.recipient !== recipient) throw fault();
    text = body.message;
  }
  if (typeof text !== 'string' || text.length !== CODE_PREFIX.length + 6 || !/^Your sign-in code is [0-9]{6}$/.test(text)) throw fault();
  return text.slice(-6);
}
function responseFor(provider, execution, account, intent, disposition) {
  const receipt = disposition === 'not_accepted' ? null : `${provider}:${execution}`;
  if (provider === 'resend') return { id: receipt, rebase: { provider, execution_id: execution, account, request_hash: intent, status: disposition } };
  if (provider === 'brevo') return { messageId: receipt, event: { provider, execution, account, requestHash: intent, disposition } };
  return { provider, execution, account, intent, status: disposition, delivery_id: receipt };
}

/** Owns one loopback fake provider. Only the returned test handle exposes delivered codes. */
export async function startFakeAuthProvider({ provider, directory, account, key, recipient, sender = null } = {}) {
  const config = { provider, account, recipient, sender };
  validateConfig(config);
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || typeof key !== 'string' || !key || key.length > 512 || /[^\x20-\x7e]/.test(key)) throw fault();
  const secret = Buffer.from(key, 'ascii');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const journalPath = path.join(directory, `${provider}.auth-journal.json`);
  let state;
  try {
    const metadata = await lstat(journalPath);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || metadata.size > MAX_BYTES || (metadata.mode & 0o077)) throw fault();
    state = parseFrame(await readFile(journalPath));
  } catch (error) {
    if (error.code !== 'ENOENT') { secret.fill(0); throw error; }
    state = { format: FORMAT, ...config, mode: 'success', executions: {}, calls: [] };
  }
  try { validateJournal(state, config); } catch (error) { secret.fill(0); throw error; }
  let queue = Promise.resolve(); let closed = false; let uncertain = false; let closePromise;
  function assertOpen() { if (closed || uncertain) throw new Error('Fake authentication provider is unavailable'); }
  function transaction(operation) {
    const pending = queue.then(async () => {
      assertOpen();
      const next = structuredClone(state); const result = operation(next); validateJournal(next, config);
      try { await persist(journalPath, next); } catch { uncertain = true; throw new Error('Fake authentication journal durability is unknown'); }
      state = next; return result;
    });
    queue = pending.catch(() => {}); return pending;
  }
  const server = createServer((request, response) => {
    void handle(request, response).catch(error => {
      if (!response.headersSent) reply(response, error instanceof TypeError ? 400 : 500, { error: error instanceof TypeError ? 'invalid protocol' : 'unavailable' });
      else response.destroy();
    });
  });
  server.requestTimeout = 10_000; server.headersTimeout = 5000; server.maxHeadersCount = 32; server.maxConnections = 64;
  try { await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); }); }
  catch (error) { secret.fill(0); throw error; }
  const endpoint = `http://127.0.0.1:${server.address().port}`;
  const base = ROUTES[provider];
  async function handle(request, response) {
    const url = new URL(request.url, endpoint);
    if (url.search || url.hash) throw fault();
    const method = request.method;
    const submit = method === 'POST' && url.pathname === base;
    const lookup = method === 'GET' && url.pathname.startsWith(`${base}/`);
    if (!submit && !lookup) return reply(response, 404, { error: 'unknown' });
    const executionHeader = provider === 'resend' ? request.headers['idempotency-key']?.slice(ACTION.length + 1)
      : request.headers[provider === 'brevo' ? 'x-rebase-execution' : 'x-sms-execution'];
    const execution = id(lookup ? url.pathname.slice(base.length + 1) : executionHeader);
    if (executionHeader !== execution || (provider === 'resend' && request.headers['idempotency-key'] !== `${ACTION}/${execution}`)
      || request.headers['x-rebase-action'] !== ACTION) throw fault();
    const intent = hash(request.headers['x-rebase-request-hash']);
    if (request.headers['x-rebase-account'] !== account) return reply(response, 401, { error: 'unauthorized' });
    const keyHeader = request.headers[provider === 'resend' ? 'authorization' : provider === 'brevo' ? 'api-key' : 'x-sms-token'];
    if (typeof keyHeader !== 'string' || (provider === 'resend' && !keyHeader.startsWith('Bearer '))) return reply(response, 401, { error: 'unauthorized' });
    const supplied = Buffer.from(provider === 'resend' ? keyHeader.slice(7) : keyHeader, 'latin1');
    const authorized = secret.length === supplied.length && timingSafeEqual(secret, supplied); supplied.fill(0);
    if (!authorized) return reply(response, 401, { error: 'unauthorized' });
    let code;
    if (submit) {
      if (request.headers['content-type']?.split(';')[0].trim() !== 'application/json') throw fault();
      code = codeFromBody(provider, parseFrame(await readBody(request)), recipient, sender);
    }
    const result = await transaction(next => {
      if (next.calls.length >= MAX_CALLS) throw fault();
      let entry = next.executions[execution];
      if (entry && (entry.hash !== intent || (submit && entry.code !== code))) throw fault();
      if (submit && !entry) {
        if (Object.keys(next.executions).length >= MAX_EXECUTIONS) throw fault();
        entry = next.executions[execution] = { hash: intent, code, disposition: null };
      }
      const previousSubmits = next.calls.filter(call => call.execution === execution && call.method === 'POST').length;
      let disposition = entry?.disposition ?? null;
      if (submit && disposition === null) {
        disposition = next.mode === 'not_accepted' || (next.mode === 'reject_once' && previousSubmits === 0) ? 'not_accepted'
          : next.mode === 'waiting' ? 'waiting' : next.mode === 'failed' ? 'failed' : 'succeeded';
        if (disposition !== 'not_accepted') entry.disposition = disposition;
      }
      if (lookup && disposition === 'waiting' && ['success', 'failed'].includes(next.mode)) {
        disposition = entry.disposition = next.mode === 'success' ? 'succeeded' : 'failed';
      }
      next.calls.push({ execution, method, hash: intent, disposition });
      return { disposition, mode: next.mode };
    });
    if (submit && result.mode === 'lost_response') { response.destroy(); return; }
    if (!result.disposition || (lookup && result.mode === 'empty')) return reply(response, 404, { error: 'unknown' });
    if (result.mode === 'malformed') return reply(response, 200, { unexpected: true });
    reply(response, 200, responseFor(provider, execution, account, intent, result.disposition));
  }
  return Object.freeze({ provider, endpoint, directory,
    async deliveries() {
      assertOpen(); await queue;
      return Object.entries(state.executions).filter(([, entry]) => entry.disposition === 'succeeded').map(([execution, entry]) => ({
        provider, execution, account, requestHash: entry.hash, recipient, sender, code: entry.code,
      }));
    },
    async counts(execution) {
      assertOpen(); if (execution !== undefined) id(execution); await queue;
      const calls = state.calls.filter(call => execution === undefined || call.execution === execution);
      return { submissions: calls.filter(call => call.method === 'POST').length, observations: calls.filter(call => call.method === 'GET').length,
        accepted: Object.entries(state.executions).filter(([id, entry]) => (execution === undefined || execution === id) && entry.disposition !== null).length };
    },
    async setMode(mode) { assertOpen(); if (!MODES.has(mode)) throw fault(); await transaction(next => { next.mode = mode; }); },
    close() {
      closePromise ??= (async () => { closed = true; await queue; await new Promise(resolve => server.close(resolve)); secret.fill(0); })();
      return closePromise;
    },
  });
}

function validateJournal(value, config) {
  keys(value, ['format', 'provider', 'account', 'recipient', 'sender', 'mode', 'executions', 'calls']);
  if (value.format !== FORMAT || Object.entries(config).some(([field, expected]) => value[field] !== expected) || !MODES.has(value.mode)
    || !value.executions || Array.isArray(value.executions) || typeof value.executions !== 'object' || Object.keys(value.executions).length > MAX_EXECUTIONS
    || !Array.isArray(value.calls) || value.calls.length > MAX_CALLS) throw fault();
  const firstSubmits = new Map(); const latest = new Map();
  for (const [execution, entry] of Object.entries(value.executions)) {
    id(execution); keys(entry, ['hash', 'code', 'disposition']); hash(entry.hash);
    if (typeof entry.code !== 'string' || entry.code.length !== 6 || !/^[0-9]{6}$/.test(entry.code) || (entry.disposition !== null && !STATES.has(entry.disposition))) throw fault();
  }
  for (const call of value.calls) {
    keys(call, ['execution', 'method', 'hash', 'disposition']); id(call.execution); hash(call.hash);
    if (!['GET', 'POST'].includes(call.method) || (call.disposition !== null && call.disposition !== 'not_accepted' && !STATES.has(call.disposition))) throw fault();
    const entry = value.executions[call.execution];
    if (call.method === 'POST') {
      if (!entry || call.disposition === null) throw fault();
      firstSubmits.set(call.execution, true);
    }
    if (firstSubmits.has(call.execution)) {
      if (call.hash !== entry.hash || (call.method === 'GET' && call.disposition === 'not_accepted')) throw fault();
      const previous = latest.get(call.execution);
      if (['succeeded', 'failed'].includes(previous) && previous !== call.disposition) throw fault();
      if (previous === 'waiting' && !STATES.has(call.disposition)) throw fault();
      if (STATES.has(call.disposition)) latest.set(call.execution, call.disposition);
    } else if (call.disposition !== null) throw fault();
  }
  for (const [execution, entry] of Object.entries(value.executions)) {
    if (!firstSubmits.has(execution) || entry.disposition !== (latest.get(execution) ?? null)) throw fault();
  }
  if (Buffer.byteLength(JSON.stringify(value)) > MAX_BYTES) throw fault();
}
async function readBody(request) {
  const chunks = []; let size = 0;
  for await (const chunk of request) { size += chunk.length; if (size > MAX_BODY) throw fault(); chunks.push(chunk); }
  return Buffer.concat(chunks);
}
function reply(response, status, value) {
  response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); response.end(JSON.stringify(value));
}
async function persist(destination, value) {
  const temporary = `${destination}.${randomUUID()}.tmp`; let file;
  try {
    file = await open(temporary, 'wx', 0o600); await file.writeFile(JSON.stringify(value)); await file.sync(); await file.close(); file = null;
    await rename(temporary, destination); const directory = await open(path.dirname(destination), 'r'); try { await directory.sync(); } finally { await directory.close(); }
  } finally { await file?.close(); await rm(temporary, { force: true }); }
}
