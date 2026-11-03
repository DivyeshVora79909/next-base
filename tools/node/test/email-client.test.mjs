import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { connect, savePlan } from '../client.mjs';

const id = n => `00000000-0000-0000-0000-${n.toString(16).padStart(12, '0')}`;
const model = 'a'.repeat(64);
const session = { model, store: id(1), tenant: id(2), actor: id(3), credential_epoch: 0, operation_context: 'original-context' };
const inputSchema = { $schema: 'https://json-schema.org/draft/2020-12/schema', type: 'object', additionalProperties: false,
  required: ['email', 'selection', 'execute_at', 'not_after'], properties: {
    email: { type: 'object', additionalProperties: false, required: ['sender', 'to', 'subject', 'text'], properties: {
      sender: { type: 'string' }, to: { type: 'array', items: { type: 'string' } }, subject: { type: 'string', maxLength: 5 }, text: { type: 'string' } } },
    selection: { type: 'object' }, execute_at: { type: 'null' }, not_after: { type: 'null' } } };
const catalog = { model, contracts: [{ code: 1002, name: 'EmailSend', visibility: 'public', schema: inputSchema }] };
const draft = () => ({ model, commands: [{ op: 'create', id: id(20), contract: 1002,
  fields: { email: { sender: ' Sender@EXAMPLE.COM ', to: [' Person@Example.NET '], subject: 'Hello', text: 'body\nline' },
    selection: { kind: 'platform', slot: 'transactional_email' }, execute_at: null, not_after: null } }], returning: [id(20)] });
let server, endpoint, calls = [], behavior = 'ok';
test.before(async () => {
  server = http.createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    const envelope = JSON.parse(Buffer.concat(chunks)); calls.push(envelope);
    if (envelope.method === 'session.describe') await new Promise(resolve => setTimeout(resolve, 15));
    if (envelope.method === 'email.enqueue' && behavior === 'lost') { request.socket.destroy(); return; }
    const result = envelope.method === 'session.describe' ? session : envelope.method === 'model.describe' ? catalog
      : envelope.method === 'operations.status' ? { status: 'committed', operation_id: envelope.params.operation_id } : { status: 'committed' };
    response.writeHead(200, { 'content-type': 'application/json' });
    if (envelope.method === 'email.enqueue' && behavior === 'echo-error') {
      response.end(JSON.stringify({ jsonrpc: '2.0', id: envelope.id, error: { code: -32000,
        message: envelope.params.authorizations[0].grant, data: { kind: 'invalid_grant' } } }));
    } else response.end(JSON.stringify({ jsonrpc: '2.0', id: envelope.id, result }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  endpoint = `http://127.0.0.1:${server.address().port}/rpc`;
});
test.after(async () => { await new Promise(resolve => server.close(resolve)); });

test('email plans normalize before catalog validation, detach intent and submit separate transient grants', async () => {
  calls = []; behavior = 'ok';
  const client = connect({ endpoint, credential: 'test-token' });
  const input = draft(), preparing = client.prepareEmail(input, { operationId: id(99) });
  input.commands[0].fields.email.text = 'changed by caller';
  const plan = await preparing;
  assert.equal(plan.kind, 'email-enqueue');
  assert.deepEqual(plan.request.commands[0].fields.email, { sender: 'Sender@example.com', to: ['Person@example.net'], subject: 'Hello', text: 'body\nline' });
  assert.ok(Object.isFrozen(plan.request.commands[0].fields.email.to));
  const evidence = [{ source: id(20), grant: 'opaque_bounded_grant' }];
  const enqueueing = client.enqueueEmail(plan, evidence);
  evidence[0].grant = 'changed_after_call';
  await enqueueing;
  const sent = calls.find(call => call.method === 'email.enqueue').params;
  const { authorizations, ...request } = sent;
  assert.deepEqual(request, plan.request);
  assert.deepEqual(authorizations, [{ source: id(20), grant: 'opaque_bounded_grant' }]);
  assert.equal(JSON.stringify(plan).includes('opaque_bounded_grant'), false);
  assert.equal(calls.some(call => call.method === 'email.authorize'), false);
  await assert.rejects(client.execute(plan), error => error.code === 'invalid_plan');
  const directory = await mkdtemp(path.join(os.tmpdir(), 'email-plan-'));
  try {
    const destination = path.join(directory, 'plan.json'); await savePlan(destination, plan);
    const bytes = await readFile(destination, 'utf8');
    assert.deepEqual(JSON.parse(bytes), plan);
    assert.equal(bytes.includes('grant'), false);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('prepared catalog remains authoritative and malformed email plans never save bearer fields', async () => {
  const client = connect({ endpoint, credential: 'test-token' });
  const longer = draft(); longer.commands[0].fields.email.subject = 'longer-than-catalog';
  await assert.rejects(client.prepareEmail(longer), error => error.code === 'invalid_plan');
  const plan = await client.prepareEmail(draft());
  const directory = await mkdtemp(path.join(os.tmpdir(), 'email-plan-denied-'));
  try {
    for (const mutate of [
      value => { value.grant = 'DO_NOT_SAVE'; },
      value => { value.request.authorizations = [{ source: id(20), grant: 'DO_NOT_SAVE' }]; },
      value => { value.fixture = { grant: 'DO_NOT_SAVE' }; },
      value => { value.request.commands[0].grant = 'DO_NOT_SAVE'; },
      value => { value.request.commands[0].fields.grant = 'DO_NOT_SAVE'; },
      value => { value.request.commands[0].fields.email.grant = 'DO_NOT_SAVE'; },
      value => { value.request.commands[0].fields.selection.grant = 'DO_NOT_SAVE'; },
    ]) {
      const altered = structuredClone(plan); mutate(altered);
      await assert.rejects(savePlan(path.join(directory, 'invalid.json'), altered), error => error.code === 'invalid_plan' && !String(error).includes('DO_NOT_SAVE'));
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
  const before = calls.length;
  for (const mutate of [
    value => { value.commands[0].fields.email.to = ['x@EXAMPLE.NET', 'x@example.net']; },
    value => { value.commands[0].fields.email.sender = 'x@y\r\nHeader: z'; },
    value => { value.commands[0].fields.email.text = 'é'.repeat(8193); },
    value => { value.commands[0].fields.selection.endpoint = 'http://evil.test'; },
  ]) {
    const altered = draft(); mutate(altered);
    await assert.rejects(client.prepareEmail(altered), error => error.code === 'invalid_plan');
  }
  assert.equal(calls.length, before);
});

test('unknown enqueue and echoed remote errors keep original status recovery without grant leakage or reauthorization', async () => {
  const client = connect({ endpoint, credential: 'test-token' });
  const plan = await client.prepareEmail(draft(), { operationId: id(98) });
  const evidence = [{ source: id(20), grant: 'NEVER_EXPOSE_THIS_GRANT' }];
  for (const mode of ['lost', 'echo-error']) {
    behavior = mode; const before = calls.length;
    await assert.rejects(client.enqueueEmail(plan, evidence), error => {
      assert.equal(error.code, mode === 'lost' ? 'outcome_unknown' : 'invalid_grant');
      assert.equal(error.cause, undefined);
      assert.equal(`${String(error)}${JSON.stringify(error)}`.includes(evidence[0].grant), false);
      return true;
    });
    assert.equal(calls.slice(before).filter(call => call.method === 'email.enqueue').length, 1);
    assert.equal(calls.slice(before).some(call => call.method === 'email.authorize'), false);
    session.operation_context = 'new-context';
    await client.status(plan);
    assert.deepEqual(calls.at(-1).params, { model, context: 'original-context', operation_id: id(98) });
    session.operation_context = 'original-context';
  }
  behavior = 'ok';
  const before = calls.length;
  for (const evidence of [[], [{ source: id(21), grant: 'x' }], [{ source: id(20), grant: 'x', endpoint: 'bad' }],
    [{ source: id(20), grant: 'x'.repeat(4097) }]]) {
    await assert.rejects(client.enqueueEmail(plan, evidence), error => error.code === 'invalid_authorizations');
  }
  assert.equal(calls.length, before);
  const changed = structuredClone(plan); changed.target.actor = id(333);
  await assert.rejects(client.enqueueEmail(changed, evidence), error => error.code === 'target_mismatch');
  assert.equal(calls.at(-1).method, 'session.describe');
});

test('transient grants consume the final wire budget before any submission or session lookup', async () => {
  const client = connect({ endpoint, credential: 'test-token' });
  const input = draft();
  input.commands = Array.from({ length: 16 }, (_, index) => ({ ...structuredClone(input.commands[0]), id: id(100 + index) }));
  input.returning = [];
  const plan = await client.prepareEmail(input);
  const grants = input.commands.map(command => ({ source: command.id, grant: 's'.repeat(4096) }));
  const before = calls.length;
  await assert.rejects(client.enqueueEmail(plan, grants), error => {
    assert.ok(['request_limit', 'protocol_error'].includes(error.code));
    assert.equal(String(error).includes(grants[0].grant), false);
    return true;
  });
  assert.equal(calls.length, before);
  assert.equal(JSON.stringify(plan).includes(grants[0].grant), false);
});
