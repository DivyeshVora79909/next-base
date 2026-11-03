import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import test from 'node:test';
import { inspect } from 'node:util';
import { prepareAuthentication, prepareCodeProof } from '../authentication.mjs';

const identifier = () => ({ kind: 'email', value: ' Alice@EXAMPLE.COM ' });
const secret = () => randomBytes(32).toString('base64url');
async function serve(handler) {
  const server = createServer((request, response) => {
    Promise.resolve(handler(request, response)).catch(() => { response.destroy(); });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { endpoint: `http://127.0.0.1:${server.address().port}`, close: () => new Promise(resolve => server.close(resolve)) };
}
async function body(request) {
  const chunks = []; for await (const chunk of request) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks));
}
function reply(response, value) { response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify(value)); }

test('authentication rejects remote plaintext endpoints before network use and has no opt-out', () => {
  for (const endpoint of ['http://example.com', 'http://192.0.2.1/rpc', 'http://10.0.0.1', 'http://[2001:db8::1]', 'http://127.0.0.1.example.com', 'http://localhost.example.com']) {
    assert.throws(() => prepareAuthentication({ endpoint, identifier: identifier(), allowRemoteHttp: true }), /HTTPS or loopback/);
    assert.throws(() => prepareCodeProof({ endpoint, challenge: secret(), code: '000042', allowRemoteHttp: true }), /HTTPS or loopback/);
  }
  for (const endpoint of ['https://example.com/rpc', 'http://localhost', 'http://127.0.0.1/rpc', 'http://127.0.0.2', 'http://[::1]']) {
    assert.doesNotThrow(() => prepareAuthentication({ endpoint, identifier: identifier() }));
    assert.doesNotThrow(() => prepareCodeProof({ endpoint, challenge: secret(), code: '000042' }));
  }
  for (const endpoint of ['not a URL', 'file:///tmp/proof', 'https://user:private@example.com', 'https://example.com?token=private', 'https://example.com#private', 'https://example.com/other']) {
    assert.throws(() => prepareAuthentication({ endpoint, identifier: identifier() }), error => !inspect(error).includes('token=private') && error.message === 'Invalid authentication endpoint or timeout');
  }
});

test('proof input accepts only canonical 32-byte handles and exact six ASCII digits', () => {
  const endpoint = 'https://example.com'; const challenge = secret();
  for (const code of [42, '42', '00042', '0000042', '000042\n', '000042 ', ' 000042', '００００４２', null]) {
    assert.throws(() => prepareCodeProof({ endpoint, challenge, code }), /six ASCII digits/);
  }
  for (const handle of ['', challenge + '=', challenge + '\n', challenge.slice(0, -1), Buffer.alloc(31).toString('base64url'), Buffer.alloc(33).toString('base64url')]) {
    assert.throws(() => prepareCodeProof({ endpoint, challenge: handle, code: '000042' }), /challenge/);
  }
  const noncanonical = 'A'.repeat(42) + 'B';
  assert.equal(Buffer.from(noncanonical, 'base64url').toString('base64url'), 'A'.repeat(43));
  assert.throws(() => prepareCodeProof({ endpoint, challenge: noncanonical, code: '000042' }), /challenge/);
  for (const code of ['000000', '000042', '999999']) assert.doesNotThrow(() => prepareCodeProof({ endpoint, challenge, code }));
});

for (const method of ['begin', 'consume']) test(`${method} keeps closure-owned original evidence after a real lost loopback response`, async () => {
  const requests = []; const receipts = new Map(); const challenge = secret(); const code = '000042';
  const expected = method === 'begin' ? { status: 'accepted', challenge: secret(), expires_at: String(Date.now() + 300_000) }
    : { status: 'authenticated', token: 'FIXTURE_COMMITTED_SESSION_TOKEN' };
  const server = await serve(async (request, response) => {
    const input = await body(request); requests.push({ path: request.url, input });
    if (request.url === `/auth/${method}`) {
      const prior = receipts.get(input.operation_id);
      if (!prior) { receipts.set(input.operation_id, { input: structuredClone(input), result: expected }); response.destroy(); return; }
      assert.deepEqual(input, prior.input); reply(response, prior.result);
    } else {
      assert.equal(request.url, '/auth/status');
      assert.deepEqual(Object.keys(input).sort(), ['operation_id', 'recovery_secret']);
      const prior = receipts.get(input.operation_id); assert.equal(input.recovery_secret, prior.input.recovery_secret);
      reply(response, prior.result);
    }
  });
  try {
    const source = identifier();
    const operation = method === 'begin' ? prepareAuthentication({ endpoint: server.endpoint, identifier: source })
      : prepareCodeProof({ endpoint: server.endpoint, challenge, code });
    source.kind = 'phone'; source.value = '+198765432';
    assert.ok(Object.isFrozen(operation));
    assert.deepEqual(Object.keys(operation).sort(), ['execute', 'operationId', 'status', 'toJSON']);
    assert.throws(() => JSON.stringify(operation), /cannot be saved/);
    assert.throws(() => operation.toJSON(), /cannot be saved/);
    let unknown;
    await assert.rejects(operation.execute(), error => { unknown = error; return error.code === 'outcome_unknown'; });
    assert.deepEqual(await operation.status(), expected);
    assert.deepEqual(await operation.execute(), expected);
    assert.equal(receipts.size, 1); assert.equal(requests.length, 3);
    assert.deepEqual(requests[0].input, requests[2].input);
    const original = requests[0].input;
    assert.equal(original.operation_id, operation.operationId);
    assert.match(original.recovery_secret, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(Buffer.from(original.recovery_secret, 'base64url').length, 32);
    assert.deepEqual(requests[1].input, { operation_id: original.operation_id, recovery_secret: original.recovery_secret });
    if (method === 'begin') assert.deepEqual(original.identifier, { kind: 'email', value: 'alice@example.com' });
    else assert.deepEqual({ challenge: original.challenge, code: original.code }, { challenge, code });
    for (const output of [inspect(operation, { depth: null, showHidden: true }), inspect(unknown, { depth: null, showHidden: true }), operation.execute.toString(), operation.status.toString()]) {
      for (const secret of [original.recovery_secret, challenge, code, 'alice@example.com']) assert.equal(output.includes(secret), false);
    }
  } finally { await server.close(); }
});

test('authentication refuses redirects without disclosing proof to the redirected endpoint', async () => {
  let calls = 0;
  const target = await serve((_request, response) => { calls++; reply(response, { status: 'invalid_proof' }); });
  const origin = await serve(async (request, response) => {
    await body(request); response.writeHead(307, { location: `${target.endpoint}/auth/consume` }); response.end();
  });
  try {
    const operation = prepareCodeProof({ endpoint: origin.endpoint, challenge: secret(), code: '000042' });
    await assert.rejects(operation.execute(), { code: 'outcome_unknown' });
    assert.equal(calls, 0);
  } finally { await origin.close(); await target.close(); }
});

test('authentication bounds response bytes and keeps malformed outcomes recoverable', async () => {
  let oversized = true;
  const server = await serve(async (request, response) => {
    await body(request);
    if (oversized) reply(response, { status: 'authenticated', token: 'x'.repeat(16_384) });
    else reply(response, { status: 'invalid_proof' });
  });
  try {
    const operation = prepareCodeProof({ endpoint: server.endpoint, challenge: secret(), code: '000042' });
    await assert.rejects(operation.execute(), { code: 'outcome_unknown' });
    oversized = false;
    assert.deepEqual(await operation.status(), { status: 'invalid_proof' });
  } finally { await server.close(); }
});
