import { createHash } from 'node:crypto';
import { CipherSuite, KemId, KdfId, AeadId } from 'hpke-js';

export const INGRESS_FORMAT = 'rebase-secret-ingress-1';
export const INGRESS_INFO = Buffer.from('next-base/credential-ingress/1');
const SUITE = 'X25519-HKDF-SHA256-AES256GCM';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const KEY_ID = /^[A-Za-z0-9_-]{1,64}$/;
const fail = () => Object.assign(new Error('Credential ingress is invalid'), { code: 'credential_crypto' });
function object(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) throw fail();
}
function uuid(value) { if (typeof value !== 'string' || !UUID.test(value)) throw fail(); return value; }
function decimal(value, max) {
  if (Number.isSafeInteger(value) && value >= 0) value = String(value);
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value) || BigInt(value) > max) throw fail();
  return value;
}
function decode(value, min, max) {
  if (typeof value !== 'string' || value.length > Math.ceil(max / 3) * 4 || !/^[A-Za-z0-9_-]+$/.test(value)) throw fail();
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length < min || bytes.length > max || bytes.toString('base64url') !== value) throw fail();
  return bytes;
}
export function validateCredentialMetadata(value) {
  object(value, ['label', 'provider', 'account', 'enabled', 'scopes']);
  if (typeof value.label !== 'string' || Buffer.byteLength(value.label) > 128 || !value.label.isWellFormed()
    || !['resend', 'brevo'].includes(value.provider) || typeof value.account !== 'string'
    || !/^[A-Za-z0-9._:-]{1,128}$/.test(value.account) || typeof value.enabled !== 'boolean'
    || !Array.isArray(value.scopes) || value.scopes.length > 1 || value.scopes.some((s) => s !== 'email.send')) throw fail();
  return { label: value.label, provider: value.provider, account: value.account, enabled: value.enabled, scopes: [...value.scopes] };
}
export function credentialIngressAad(context, expiresAt) {
  object(context, ['model', 'store', 'tenant', 'actor', 'credential_epoch', 'context', 'operation_id', 'credential', 'owner', 'if_version', 'metadata']);
  if (typeof context.model !== 'string' || !context.model || !context.model.isWellFormed()
    || typeof context.context !== 'string' || !context.context || !context.context.isWellFormed()) throw fail();
  const metadata = validateCredentialMetadata(context.metadata);
  const fields = [INGRESS_FORMAT, context.model, uuid(context.store), uuid(context.tenant), uuid(context.actor),
    decimal(context.credential_epoch, (1n << 64n) - 1n), createHash('sha256').update(context.context).digest('hex'),
    uuid(context.operation_id), uuid(context.credential), context.owner === null ? null : uuid(context.owner),
    context.if_version === null ? null : uuid(context.if_version), metadata.provider, metadata.account, metadata,
    decimal(expiresAt, (1n << 63n) - 1n)];
  return Buffer.from(JSON.stringify(fields));
}
export function validateIngressEnvelope(value) {
  object(value, ['format', 'key_id', 'enc', 'ciphertext', 'expires_at']);
  if (value.format !== INGRESS_FORMAT || typeof value.key_id !== 'string' || !KEY_ID.test(value.key_id)) throw fail();
  decode(value.enc, 32, 32);
  decode(value.ciphertext, 17, 2048);
  if (typeof value.expires_at !== 'string') throw fail();
  decimal(value.expires_at, (1n << 63n) - 1n);
  return value;
}

/** Encrypt private JSON bytes before the caller constructs any saved operation plan. */
export async function sealCredentialIngress({ descriptor, context, secret, expiresAt, now = Date.now() } = {}) {
  let plaintext;
  try {
    if (!(secret instanceof Uint8Array) || secret.byteLength > 2048) throw fail();
    plaintext = Buffer.from(secret);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    // This deliberately accepts only one canonical field. The native strict decoder is authoritative.
    const payload = JSON.parse(text);
    object(payload, ['api_key']);
    if (typeof payload.api_key !== 'string' || !payload.api_key.isWellFormed() || !payload.api_key
      || Buffer.byteLength(payload.api_key) > 512 || /[\x00-\x1f\x7f]/.test(payload.api_key)
      || !/^\s*\{\s*"api_key"\s*:\s*"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"\s*\}\s*$/.test(text)) throw fail();
    object(descriptor, ['format', 'key_id', 'suite', 'public_key']);
    if (descriptor.format !== INGRESS_FORMAT || descriptor.suite !== SUITE || typeof descriptor.key_id !== 'string' || !KEY_ID.test(descriptor.key_id)) throw fail();
    const expires = decimal(expiresAt, (1n << 63n) - 1n);
    const capturedNow = BigInt(decimal(now, (1n << 63n) - 1n));
    if (BigInt(expires) <= capturedNow || BigInt(expires) - capturedNow > 900_000n) throw fail();
    const aad = credentialIngressAad(context, expires);
    const suite = new CipherSuite({ kem: KemId.DhkemX25519HkdfSha256, kdf: KdfId.HkdfSha256, aead: AeadId.Aes256Gcm });
    const recipientPublicKey = await suite.kem.deserializePublicKey(decode(descriptor.public_key, 32, 32));
    const sender = await suite.createSenderContext({ recipientPublicKey, info: INGRESS_INFO });
    const ciphertext = await sender.seal(plaintext, aad);
    return validateIngressEnvelope({ format: INGRESS_FORMAT, key_id: descriptor.key_id,
      enc: Buffer.from(sender.enc).toString('base64url'), ciphertext: Buffer.from(ciphertext).toString('base64url'), expires_at: expires });
  } catch {
    // No parser/library cause or caller input crosses this boundary.
    throw fail();
  } finally { plaintext?.fill(0); }
}
