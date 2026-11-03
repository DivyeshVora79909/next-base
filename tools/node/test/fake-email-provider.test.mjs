import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { startFakeEmailProvider } from '../fake-email-provider.mjs';

const email = { sender: 'Sender@example.com', to: ['Receiver@example.net'], subject: 'Subject café', text: 'Body\nsecond line' };
const hash = createHash('sha256').update('next-base/email-send/1\0').update(JSON.stringify(email)).digest('hex');
const account = 'test-account';
const key = 'PUBLIC_TEST_PRIVATE_API_KEY';
const accounts = [{ account, keys: [key, 'PUBLIC_TEST_ROTATED_KEY'] }];
function submit(provider, execution, options = {}) {
  const resend = provider.provider === 'resend';
  const body = resend ? { from: email.sender, to: email.to, subject: email.subject, text: email.text }
    : { sender: { email: email.sender }, to: email.to.map(email => ({ email })), subject: email.subject, textContent: email.text };
  const headers = { 'content-type': 'application/json', 'x-rebase-action': 'email-send-1', 'x-rebase-account': account, 'x-rebase-request-hash': hash,
    ...(resend ? { authorization: `Bearer ${key}`, 'idempotency-key': `email-send-1/${execution}` } : { 'api-key': key, 'x-rebase-execution': execution }), ...options.headers };
  const url = `${provider.endpoint}${resend ? '/emails' : '/v3/smtp/email'}${options.lookup ? `/${execution}` : ''}`;
  return fetch(url, { method: options.lookup ? 'GET' : 'POST', headers, ...(options.lookup ? {} : { body: options.raw ?? JSON.stringify(options.body ?? body) }) });
}
for (const providerName of ['resend', 'brevo']) {
  test(`${providerName} independently checks its distinct wire shape and key/account against durable expected intent`, async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), `fake-${providerName}-`)); let provider;
    try {
      provider = await startFakeEmailProvider({ provider: providerName, directory, accounts });
      const execution = randomUUID(); await provider.expect(execution, { account, email });
      const first = await submit(provider, execution); assert.equal(first.status, 200); const result = await first.json();
      if (providerName === 'resend') assert.deepEqual(result, { id: `resend:${execution}`, rebase: { provider: 'resend', execution_id: execution, account, request_hash: hash, status: 'succeeded' } });
      else assert.deepEqual(result, { messageId: `brevo:${execution}`, event: { provider: 'brevo', execution, account, requestHash: hash, disposition: 'succeeded' } });
      const repeats = await Promise.all(Array.from({ length: 5 }, () => submit(provider, execution)));
      assert.ok(repeats.every(response => response.status === 200));
      assert.deepEqual(await provider.counts(execution), { submissions: 6, observations: 0, accepted: 1 });
      assert.equal((await submit(provider, execution, { headers: providerName === 'resend' ? { authorization: 'Bearer WRONG' } : { 'api-key': 'WRONG' } })).status, 401);
      assert.equal((await submit(provider, execution, { headers: { 'x-rebase-account': 'other' } })).status, 401);
      assert.equal((await submit(provider, execution, { headers: { 'x-rebase-request-hash': 'a'.repeat(64) } })).status, 400);
      const otherShape = providerName === 'resend' ? { sender: { email: email.sender }, to: [{ email: email.to[0] }], subject: email.subject, textContent: email.text }
        : { from: email.sender, to: email.to, subject: email.subject, text: email.text };
      assert.equal((await submit(provider, execution, { body: otherShape })).status, 400);
      assert.equal((await submit(provider, execution, { raw: '{"from":"a","from":"b"}' })).status, 400);
      await provider.close();
      const journal = await readFile(path.join(directory, `${providerName}.journal.json`), 'utf8'); assert.equal(journal.includes(key), false);
      provider = await startFakeEmailProvider({ provider: providerName, directory, accounts });
      assert.deepEqual(await (await submit(provider, execution, { lookup: true })).json(), result);
      assert.deepEqual(await provider.counts(execution), { submissions: 6, observations: 1, accepted: 1 });
      await provider.close(); provider = null;
      const tampered = JSON.parse(journal); tampered.expected[execution].email.text = 'changed';
      await writeFile(path.join(directory, `${providerName}.journal.json`), JSON.stringify(tampered), { mode: 0o600 });
      await assert.rejects(startFakeEmailProvider({ provider: providerName, directory, accounts }), /Invalid fake email protocol/);
    } finally { await provider?.close(); await rm(directory, { recursive: true, force: true }); }
  });
  test(`${providerName} separates definite rejection, lost ACK, lookup absence and owned held responses`, async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), `fake-${providerName}-recovery-`)); let provider;
    try {
      provider = await startFakeEmailProvider({ provider: providerName, directory, accounts });
      const rejected = randomUUID(); await provider.expect(rejected, { account, email }); await provider.setMode(rejected, 'reject_once');
      const first = await (await submit(provider, rejected)).json();
      assert.equal(providerName === 'resend' ? first.rebase.status : first.event.disposition, 'not_accepted');
      assert.deepEqual(await provider.counts(rejected), { submissions: 1, observations: 0, accepted: 0 });
      assert.equal((await submit(provider, rejected, { lookup: true })).status, 404);
      assert.equal((await submit(provider, rejected)).status, 200);
      assert.deepEqual(await provider.counts(rejected), { submissions: 2, observations: 1, accepted: 1 });
      const lost = randomUUID(); await provider.expect(lost, { account, email }); await provider.setMode(lost, 'lost_response');
      await assert.rejects(submit(provider, lost));
      assert.equal((await submit(provider, lost, { lookup: true })).status, 200);
      await provider.setMode(lost, 'empty'); assert.equal((await submit(provider, lost, { lookup: true })).status, 404);
      assert.deepEqual(await provider.counts(lost), { submissions: 1, observations: 2, accepted: 1 });
      const paused = randomUUID(); await provider.expect(paused, { account, email }); await provider.setMode(paused, 'pause_response');
      const hold = provider.holdResponse(paused); const response = submit(provider, paused); await hold.waitUntilPaused();
      assert.deepEqual(await provider.counts(paused), { submissions: 1, observations: 0, accepted: 1 });
      hold.release(); assert.equal((await response).status, 200);
      const malformed = randomUUID(); await provider.expect(malformed, { account, email }); await provider.setMode(malformed, 'malformed');
      assert.deepEqual(await (await submit(provider, malformed)).json(), { unexpected: true });
      assert.deepEqual(await provider.counts(malformed), { submissions: 1, observations: 0, accepted: 1 });
    } finally { await provider?.close(); await rm(directory, { recursive: true, force: true }); }
  });
}

test('fake Resend and Brevo journals keep the same execution and account independent', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'fake-email-independent-')); let resend, brevo;
  try {
    resend = await startFakeEmailProvider({ provider: 'resend', directory, accounts });
    brevo = await startFakeEmailProvider({ provider: 'brevo', directory, accounts });
    const execution = randomUUID(); await resend.expect(execution, { account, email }); await brevo.expect(execution, { account, email });
    await submit(resend, execution); assert.deepEqual(await brevo.counts(execution), { submissions: 0, observations: 0, accepted: 0 });
    await submit(brevo, execution); assert.deepEqual(await resend.counts(execution), { submissions: 1, observations: 0, accepted: 1 });
    assert.notDeepEqual(await resend.execution(execution), null); assert.notDeepEqual(await brevo.execution(execution), null);
  } finally { await resend?.close(); await brevo?.close(); await rm(directory, { recursive: true, force: true }); }
});
