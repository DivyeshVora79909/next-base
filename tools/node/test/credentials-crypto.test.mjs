import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { CipherSuite, KemId, KdfId, AeadId } from 'hpke-js';
import { INGRESS_INFO, credentialIngressAad, sealCredentialIngress, validateCredentialMetadata, validateIngressEnvelope } from '../credentials.mjs';

const fixture = JSON.parse(await readFile(new URL('../fixtures/hpke-rfc9180.json', import.meta.url)));
const wire = JSON.parse(await readFile(new URL('../fixtures/credential-ingress.json', import.meta.url)));
const suite = () => new CipherSuite({ kem: KemId.DhkemX25519HkdfSha256, kdf: KdfId.HkdfSha256, aead: AeadId.Aes256Gcm });
const hex = (text) => Buffer.from(text, 'hex');
const b64 = (text) => Buffer.from(text, 'base64url');

test('HPKE library reproduces and opens the independent RFC 9180 known-answer vector', async () => {
  const hpke = suite();
  const keys = await hpke.kem.deriveKeyPair(hex(fixture.ikmR));
  assert.equal(Buffer.from(await hpke.kem.serializePublicKey(keys.publicKey)).toString('hex'), fixture.pkRm);
  const sender = await hpke.createSenderContext({ recipientPublicKey: keys.publicKey, info: hex(fixture.info), ekm: hex(fixture.ikmE) });
  assert.equal(Buffer.from(sender.enc).toString('hex'), fixture.enc);
  assert.equal(Buffer.from(await sender.seal(hex(fixture.pt), hex(fixture.aad))).toString('hex'), fixture.ct);
  const recipient = await hpke.createRecipientContext({ recipientKey: keys.privateKey, enc: hex(fixture.enc), info: hex(fixture.info) });
  assert.deepEqual(Buffer.from(await recipient.open(hex(fixture.ct), hex(fixture.aad))), hex(fixture.pt));
});

test('shared application fixture fixes Node-to-native AAD and ciphertext independently', async () => {
  const aad = credentialIngressAad(wire.context, wire.envelope.expires_at);
  assert.equal(aad.toString('utf8'), wire.aad);
  const hpke = suite();
  const recipientPublicKey = await hpke.kem.deserializePublicKey(b64(wire.descriptor.public_key));
  const sender = await hpke.createSenderContext({ recipientPublicKey, info: INGRESS_INFO, ekm: hex(fixture.ikmE) });
  assert.equal(Buffer.from(sender.enc).toString('base64url'), wire.envelope.enc);
  assert.equal(Buffer.from(await sender.seal(Buffer.from(wire.payload), aad)).toString('base64url'), wire.envelope.ciphertext);
});

test('production ingress uses randomized HPKE, preserves caller bytes, and authenticates complete intent', async () => {
  const secret = Buffer.from(wire.payload);
  const options = { descriptor: wire.descriptor, context: wire.context, secret, expiresAt: wire.envelope.expires_at, now: Number(wire.envelope.expires_at) - 60_000 };
  const [a, b] = await Promise.all([sealCredentialIngress(options), sealCredentialIngress(options)]);
  assert.notEqual(a.enc, b.enc);
  assert.notEqual(a.ciphertext, b.ciphertext);
  assert.equal(secret.toString(), wire.payload);
  const hpke = suite();
  const keys = await hpke.kem.deriveKeyPair(hex(fixture.ikmR));
  const open = async (capsule, context = wire.context) => {
    const receiver = await hpke.createRecipientContext({ recipientKey: keys.privateKey, enc: b64(capsule.enc), info: INGRESS_INFO });
    return Buffer.from(await receiver.open(b64(capsule.ciphertext), credentialIngressAad(context, capsule.expires_at)));
  };
  assert.equal((await open(a)).toString(), wire.payload);
  for (const field of ['model', 'store', 'tenant', 'actor', 'credential_epoch', 'context', 'operation_id', 'credential', 'owner', 'if_version']) {
    const context = structuredClone(wire.context);
    context[field] = field === 'model' || field === 'context' ? `${context[field]}-other`
      : field === 'credential_epoch' ? '8' : 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa';
    await assert.rejects(open(a, context));
  }
  for (const [field, value] of [['label', 'changed'], ['provider', 'brevo'], ['account', 'other'], ['enabled', false], ['scopes', []]]) {
    const context = structuredClone(wire.context); context.metadata[field] = value;
    await assert.rejects(open(a, context));
  }
  const corrupt = structuredClone(a); const bytes = b64(corrupt.ciphertext); bytes[0] ^= 1; corrupt.ciphertext = bytes.toString('base64url');
  await assert.rejects(open(corrupt));
});

test('plaintext, metadata, descriptor and expiry failures expose fixed safe errors', async () => {
  const marker = 'SECRET_SHOULD_NOT_APPEAR';
  const base = { descriptor: wire.descriptor, context: wire.context, secret: Buffer.from(wire.payload), expiresAt: wire.envelope.expires_at, now: Number(wire.envelope.expires_at) - 60_000 };
  for (const secret of [Buffer.from(marker), Buffer.from(`{"api_key":"${marker}","api_key":"again"}`), Buffer.from('{"api_key":""}'), Buffer.from('{"api_key":"\\n"}'), Buffer.from('{"api_key":"ok","extra":true}'), Buffer.from([0xff])]) {
    await assert.rejects(sealCredentialIngress({ ...base, secret }), (error) => error.message === 'Credential ingress is invalid' && !String(error.stack).includes(marker) && !error.cause);
  }
  for (const patch of [{ expiresAt: base.now }, { expiresAt: base.now + 900_001 }, { descriptor: { ...wire.descriptor, suite: 'other' } }, { descriptor: { ...wire.descriptor, public_key: `${wire.descriptor.public_key}=` } }, { descriptor: { ...wire.descriptor, public_key: Buffer.alloc(32).toString('base64url') } }]) {
    await assert.rejects(sealCredentialIngress({ ...base, ...patch }), { code: 'credential_crypto' });
  }
  for (const patch of [{ label: '😀'.repeat(33) }, { account: '../remote/path' }, { scopes: ['email.send', 'email.send'] }, { extra: 1 }, { label: '\ud800' }]) {
    assert.throws(() => validateCredentialMetadata({ ...wire.context.metadata, ...patch }));
  }
  for (const patch of [{ extra: 1 }, { enc: `${wire.envelope.enc}=` }, { expires_at: 1 }, { ciphertext: 'AA' }, { key_id: '' }]) {
    assert.throws(() => validateIngressEnvelope({ ...wire.envelope, ...patch }));
  }
});
