import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { startFakeAuthProvider } from '../fake-auth-provider.mjs';

const account = 'auth-account';
const key = 'PUBLIC_TEST_AUTH_PROVIDER_KEY';
const sender = 'Sender@example.com';
const code = '000042';
// A literal opaque ciphertext binding, deliberately unrelated to the low-entropy code.
const intent = 'abcdef0123456789'.repeat(4);
const providerNames = ['resend', 'brevo', 'fake_sms'];
function config(provider, directory) {
  return { provider, directory, account, key, recipient: provider === 'fake_sms' ? '+123456789' : 'receiver@example.com', ...(provider === 'fake_sms' ? {} : { sender }) };
}
function body(provider, value = code) {
  const message = `Your sign-in code is ${value}`;
  if (provider === 'resend') return { from: sender, to: ['receiver@example.com'], subject: 'Sign-in code', text: message };
  if (provider === 'brevo') return { sender: { email: sender }, to: [{ email: 'receiver@example.com' }], subject: 'Sign-in code', textContent: message };
  return { recipient: '+123456789', message };
}
function call(handle, execution, options = {}) {
  const provider = handle.provider;
  const base = provider === 'resend' ? '/emails' : provider === 'brevo' ? '/v3/smtp/email' : '/sms/messages';
  const credentials = provider === 'resend' ? { authorization: `Bearer ${key}`, 'idempotency-key': `auth-delivery-1/${execution}` }
    : provider === 'brevo' ? { 'api-key': key, 'x-rebase-execution': execution } : { 'x-sms-token': key, 'x-sms-execution': execution };
  return fetch(`${handle.endpoint}${base}${options.lookup ? `/${execution}` : ''}${options.query ?? ''}`, {
    method: options.lookup ? 'GET' : 'POST', headers: { 'content-type': 'application/json', 'x-rebase-action': 'auth-delivery-1', 'x-rebase-account': account,
      'x-rebase-request-hash': intent, ...credentials, ...options.headers },
    ...(options.lookup ? {} : { body: options.raw ?? JSON.stringify(options.body ?? body(provider)) }),
  });
}
function response(provider, execution, status = 'succeeded') {
  const receipt = status === 'not_accepted' ? null : `${provider}:${execution}`;
  if (provider === 'resend') return { id: receipt, rebase: { provider, execution_id: execution, account, request_hash: intent, status } };
  if (provider === 'brevo') return { messageId: receipt, event: { provider, execution, account, requestHash: intent, disposition: status } };
  return { provider, execution, account, intent, status, delivery_id: receipt };
}
async function dispose(handle, directory) { await handle?.close(); await rm(directory, { recursive: true, force: true }); }

for (const provider of providerNames) {
  test(`${provider} independently accepts its exact authentication protocol and keeps code custody in its handle`, async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'fake-auth-wire-')); let handle;
    try {
      handle = await startFakeAuthProvider(config(provider, directory));
      const execution = randomUUID();
      const delivered = await call(handle, execution); assert.equal(delivered.status, 200);
      assert.deepEqual(await delivered.json(), response(provider, execution));
      assert.deepEqual(await handle.deliveries(), [{ provider, execution, account, requestHash: intent, recipient: config(provider, directory).recipient, sender: provider === 'fake_sms' ? null : sender, code }]);
      const repeats = await Promise.all(Array.from({ length: 4 }, () => call(handle, execution)));
      assert.ok(repeats.every(result => result.status === 200));
      assert.deepEqual(await handle.counts(), { submissions: 5, observations: 0, accepted: 1 });
      assert.equal((await handle.deliveries()).length, 1);
      const privateCopy = await handle.deliveries(); privateCopy[0].code = '999999';
      assert.equal((await handle.deliveries())[0].code, code);
      for (const endpoint of ['/deliveries', '/codes', '/debug', '/status']) {
        const unavailable = await fetch(handle.endpoint + endpoint); assert.equal(unavailable.status, 404);
        assert.equal((await unavailable.text()).includes(code), false);
      }
      const before = await handle.counts();
      assert.equal((await call(handle, execution, { headers: { 'x-rebase-request-hash': '1'.repeat(64) } })).status, 400);
      assert.equal((await call(handle, execution, { body: body(provider, '000043') })).status, 400);
      assert.equal((await call(handle, execution, { query: '?code=000042' })).status, 400);
      assert.equal((await call(handle, execution, { headers: { 'x-rebase-action': 'email-send-1' } })).status, 400);
      assert.equal((await call(handle, execution, { headers: { 'x-rebase-account': 'other' } })).status, 401);
      const credentialHeader = provider === 'resend' ? { authorization: 'Bearer WRONG' } : provider === 'brevo' ? { 'api-key': 'WRONG' } : { 'x-sms-token': 'WRONG' };
      assert.equal((await call(handle, execution, { headers: credentialHeader })).status, 401);
      assert.deepEqual(await handle.counts(), before);
    } finally { await dispose(handle, directory); }
  });

  test(`${provider} rejects crossed shapes, recipients, senders, malformed codes and duplicate fields`, async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'fake-auth-invalid-')); let handle;
    try {
      handle = await startFakeAuthProvider(config(provider, directory));
      for (const other of providerNames.filter(name => name !== provider)) assert.equal((await call(handle, randomUUID(), { body: body(other) })).status, 400);
      for (const value of ['42', '00042', '0000042', '００００４２', '000042\n', '000042 ', '000042\u0000']) assert.equal((await call(handle, randomUUID(), { body: body(provider, value) })).status, 400);
      const wrongRecipient = body(provider);
      if (provider === 'resend') wrongRecipient.to = ['other@example.com'];
      else if (provider === 'brevo') wrongRecipient.to[0].email = 'other@example.com';
      else wrongRecipient.recipient = '+198765432';
      assert.equal((await call(handle, randomUUID(), { body: wrongRecipient })).status, 400);
      const extra = body(provider); extra.code = code;
      assert.equal((await call(handle, randomUUID(), { body: extra })).status, 400);
      assert.equal((await call(handle, randomUUID(), { raw: '{"code":"000042","code":"000043"}' })).status, 400);
      assert.equal((await call(handle, randomUUID(), { raw: JSON.stringify(Object.values(body(provider))) })).status, 400);
      if (provider !== 'fake_sms') {
        const wrongSender = body(provider); if (provider === 'resend') wrongSender.from = 'forged@example.com'; else wrongSender.sender.email = 'forged@example.com';
        assert.equal((await call(handle, randomUUID(), { body: wrongSender })).status, 400);
      }
      assert.deepEqual(await handle.counts(), { submissions: 0, observations: 0, accepted: 0 });
      assert.deepEqual(await handle.deliveries(), []);
    } finally { await dispose(handle, directory); }
  });

  test(`${provider} journals rejection, lost response and observation independently across restart`, async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'fake-auth-recovery-')); let handle;
    try {
      handle = await startFakeAuthProvider(config(provider, directory));
      const rejected = randomUUID(); await handle.setMode('reject_once');
      assert.deepEqual(await (await call(handle, rejected)).json(), response(provider, rejected, 'not_accepted'));
      assert.deepEqual(await handle.counts(rejected), { submissions: 1, observations: 0, accepted: 0 });
      assert.deepEqual(await handle.deliveries(), []);
      assert.equal((await call(handle, rejected, { lookup: true })).status, 404);
      assert.deepEqual(await (await call(handle, rejected)).json(), response(provider, rejected));
      const lost = randomUUID(); await handle.setMode('lost_response');
      await assert.rejects(call(handle, lost));
      assert.deepEqual(await handle.counts(lost), { submissions: 1, observations: 0, accepted: 1 });
      await handle.close(); handle = null;
      const journal = await readFile(path.join(directory, `${provider}.auth-journal.json`), 'utf8');
      assert.equal(journal.includes(key), false, 'provider key never enters fake custody journal');
      handle = await startFakeAuthProvider(config(provider, directory));
      assert.deepEqual(await (await call(handle, lost, { lookup: true })).json(), response(provider, lost));
      await handle.setMode('empty'); assert.equal((await call(handle, lost, { lookup: true })).status, 404);
      assert.deepEqual(await handle.counts(lost), { submissions: 1, observations: 2, accepted: 1 });
      await handle.setMode('success'); assert.deepEqual(await (await call(handle, lost, { lookup: true })).json(), response(provider, lost));
      assert.equal((await handle.deliveries()).filter(delivery => delivery.execution === lost).length, 1);
      const waiting = randomUUID(); await handle.setMode('waiting');
      assert.deepEqual(await (await call(handle, waiting)).json(), response(provider, waiting, 'waiting'));
      assert.equal((await handle.deliveries()).some(delivery => delivery.execution === waiting), false);
      await handle.setMode('failed'); assert.deepEqual(await (await call(handle, waiting, { lookup: true })).json(), response(provider, waiting, 'failed'));
      await handle.setMode('success'); assert.deepEqual(await (await call(handle, waiting)).json(), response(provider, waiting, 'failed'), 'later calls cannot resurrect a terminal failed fact');
    } finally { await dispose(handle, directory); }
  });
}

test('concurrent first submissions with conflicting codes retain one exact accepted binding', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'fake-auth-race-')); let handle;
  try {
    handle = await startFakeAuthProvider(config('fake_sms', directory)); const execution = randomUUID();
    const results = await Promise.all([call(handle, execution), call(handle, execution, { body: body('fake_sms', '000043') })]);
    assert.deepEqual(results.map(result => result.status).sort(), [200, 400]);
    assert.deepEqual(await handle.counts(), { submissions: 1, observations: 0, accepted: 1 });
    assert.equal((await handle.deliveries()).length, 1);
  } finally { await dispose(handle, directory); }
});

test('fake auth journals reject changed configuration, insecure custody and inconsistent facts', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'fake-auth-journal-')); let handle;
  try {
    handle = await startFakeAuthProvider(config('fake_sms', directory)); const execution = randomUUID(); await call(handle, execution); await handle.close(); handle = null;
    const journalPath = path.join(directory, 'fake_sms.auth-journal.json'); const original = await readFile(journalPath, 'utf8');
    await assert.rejects(startFakeAuthProvider({ ...config('fake_sms', directory), recipient: '+198765432' }), /Invalid fake authentication protocol/);
    await chmod(journalPath, 0o644); await assert.rejects(startFakeAuthProvider(config('fake_sms', directory)), /Invalid fake authentication protocol/); await chmod(journalPath, 0o600);
    const forged = JSON.parse(original); forged.executions[execution].disposition = 'failed';
    await writeFile(journalPath, JSON.stringify(forged)); await assert.rejects(startFakeAuthProvider(config('fake_sms', directory)), /Invalid fake authentication protocol/);
    await writeFile(journalPath, original); handle = await startFakeAuthProvider(config('fake_sms', directory));
    assert.deepEqual(await handle.counts(), { submissions: 1, observations: 0, accepted: 1 });
  } finally { await dispose(handle, directory); }
});

test('provider configuration rejects phone/email confusion and never exposes key data in errors', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'fake-auth-config-'));
  try {
    for (const invalid of [
      { ...config('fake_sms', directory), sender },
      { ...config('fake_sms', directory), recipient: '+123456789\n' },
      { ...config('resend', directory), recipient: '+123456789' },
      { ...config('brevo', directory), sender: null },
      { ...config('resend', directory), key: key + '\n' },
      { ...config('resend', directory), directory: 'relative' },
    ]) await assert.rejects(startFakeAuthProvider(invalid), error => !error.message.includes(key) && error.message === 'Invalid fake authentication protocol');
  } finally { await rm(directory, { recursive: true, force: true }); }
});
