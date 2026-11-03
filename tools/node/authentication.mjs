import { randomBytes, randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { normalizeIdentityFields } from './private/identity-fields.mjs';
import { parseFrame } from './private/json-codec.mjs';

const SECRET = /^[A-Za-z0-9_-]{43}$/;
const secret = value => typeof value === 'string' && value.length === 43 && SECRET.test(value)
  && Buffer.from(value, 'base64url').length === 32 && Buffer.from(value, 'base64url').toString('base64url') === value;
function loopback(hostname) {
  const host = hostname.toLowerCase();
  return host === 'localhost' || host === '[::1]' || (isIP(host) === 4 && Number(host.split('.')[0]) === 127);
}

function operation(endpoint, method, input, timeoutMs) {
  let url;
  try { url = new URL(endpoint); } catch { throw new TypeError('Invalid authentication endpoint or timeout'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash
    || !['/', '/rpc'].includes(url.pathname) || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) {
    throw new TypeError('Invalid authentication endpoint or timeout');
  }
  if (url.protocol === 'http:' && !loopback(url.hostname)) throw new TypeError('Authentication requires HTTPS or loopback HTTP');
  const request = { operation_id: randomUUID(), recovery_secret: randomBytes(32).toString('base64url'), ...input };
  // Closure-owned transient evidence is deliberately absent from generic plans,
  // inspect output and JSON serialization. Both calls retain this exact request.
  async function call(status) {
    const target = new URL(status ? '/auth/status' : `/auth/${method}`, url);
    const body = status ? { operation_id: request.operation_id, recovery_secret: request.recovery_secret } : request;
    let response;
    try {
      response = await fetch(target, { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs), redirect: 'error' });
      const reader = response.body.getReader(); const chunks = []; let size = 0;
      for (;;) {
        const { done, value } = await reader.read(); if (done) break;
        size += value.length; if (size > 8192) { await reader.cancel(); throw new Error('Response limit'); }
        chunks.push(Buffer.from(value));
      }
      const bytes = Buffer.concat(chunks, size);
      const result = parseFrame(bytes);
      if (!response.ok || result?.status === 'outcome_unknown') {
        if (result?.status === 'invalid_proof' && response.status === 400) return Object.freeze({ status: 'invalid_proof' });
        throw new Error('Unknown authentication outcome');
      }
      if (!['accepted', 'authenticated', 'invalid_proof', 'unavailable'].includes(result?.status)) throw new Error('Invalid response');
      if (result.status === 'accepted' && (!secret(result.challenge) || typeof result.expires_at !== 'string'
        || !/^[0-9]+$/.test(result.expires_at))) throw new Error('Invalid challenge');
      if (result.status === 'authenticated' && (typeof result.token !== 'string' || result.token.length > 4096)) throw new Error('Invalid session');
      return Object.freeze(result);
    } catch {
      const error = new Error('Authentication outcome is unknown; recover this original operation with status()');
      error.code = 'outcome_unknown';
      throw error;
    }
  }
  return Object.freeze({ operationId: request.operation_id, execute: () => call(false), status: () => call(true),
    toJSON() { throw new TypeError('Authentication evidence cannot be saved as a mutation plan'); } });
}

/** Prepare once, then execute/recover the same anonymous begin operation. */
export function prepareAuthentication({ endpoint, identifier, timeoutMs = 20_000 }) {
  return operation(endpoint, 'begin', { identifier: normalizeIdentityFields(identifier) }, timeoutMs);
}

/** A new explicit attempt spends at most one of the challenge's five attempts. */
export function prepareCodeProof({ endpoint, challenge, code, timeoutMs = 20_000 }) {
  if (!secret(challenge) || typeof code !== 'string' || code.length !== 6 || !/^[0-9]{6}$/.test(code)) throw new TypeError('A challenge and six ASCII digits are required');
  return operation(endpoint, 'consume', { challenge, code }, timeoutMs);
}
