//! Private credential ingress, storage envelopes and purpose-bound opaque grants.
//! Only ciphertext DTOs are serializable or printable. Keys are loaded before transactions.
use crate::native_slice::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hpke::{
    Deserializable, Kem, OpModeR, Serializable, aead::AesGcm256, kdf::HkdfSha256,
    kem::X25519HkdfSha256,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, Metadata as FileMetadata},
    io::Read,
    path::Path,
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const INGRESS_FORMAT: &str = "rebase-secret-ingress-1";
pub const SECRET_FORMAT: &str = "rebase-credential-secret-2";
pub const GRANT_FORMAT: &str = "rebase-email-use-grant-1";
pub const INGRESS_INFO: &[u8] = b"next-base/credential-ingress/1";
const GRANT_AAD: &[u8] = b"next-base/email-use-grant/1";
type K = X25519HkdfSha256;

fn invalid() -> Error {
    Error::new("credential_crypto", "credential cryptography failed")
}
fn key_error() -> Error {
    Error::new("credential_keys", "credential key configuration is invalid")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Resend,
    Brevo,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub label: String,
    pub provider: Provider,
    pub account: String,
    pub enabled: bool,
    pub scopes: Vec<String>,
}
pub fn validate_account(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
    {
        return Err(invalid());
    }
    Ok(())
}
impl Metadata {
    pub fn validate(&self) -> Result<()> {
        validate_account(&self.account)?;
        if self.label.len() > 128
            || self.scopes.len() > 1
            || self.scopes.iter().any(|s| s != "email.send")
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn schema() -> serde_json::Value {
        serde_json::json!({"type":"object","additionalProperties":false,"required":["label","provider","account","enabled","scopes"],"properties":{
            "label":{"type":"string","maxLength":128,"x-maxUtf8Bytes":128},"provider":{"enum":["resend","brevo"]},
            "account":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},
            "enabled":{"type":"boolean"},"scopes":{"type":"array","maxItems":1,"uniqueItems":true,"items":{"enum":["email.send"]}}
        }})
    }
}

#[derive(Clone, Debug)]
pub struct IngressContext {
    pub model: String,
    pub store: Uuid,
    pub tenant: Uuid,
    pub actor: Uuid,
    pub credential_epoch: u64,
    pub context: String,
    pub operation_id: Uuid,
    pub credential: Uuid,
    pub owner: Option<Uuid>,
    pub if_version: Option<Uuid>,
    pub metadata: Metadata,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressEnvelope {
    pub format: String,
    pub key_id: String,
    pub enc: String,
    pub ciphertext: String,
    #[serde(with = "crate::native_codec::decimal")]
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressDescriptor {
    pub format: String,
    pub key_id: String,
    pub suite: String,
    pub public_key: String,
}
#[derive(Clone, Debug)]
pub struct SecretContext {
    pub tenant: Uuid,
    pub credential: Uuid,
    pub incarnation: Uuid,
    pub secret_revision: u64,
    pub provider: Provider,
    pub account: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretEnvelope {
    pub format: String,
    #[serde(with = "crate::native_codec::uuid_text")]
    pub incarnation: Uuid,
    #[serde(with = "crate::native_codec::uuid_text")]
    pub credential: Uuid,
    #[serde(with = "crate::native_codec::decimal")]
    pub secret_revision: u64,
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
}
impl SecretEnvelope {
    pub fn validate(&self) -> Result<()> {
        if self.format != SECRET_FORMAT
            || self.incarnation.is_nil()
            || self.secret_revision == 0
            || !valid_key_id(&self.key_id)
        {
            return Err(invalid());
        }
        decode(&self.nonce, 24, 24)?;
        decode(&self.ciphertext, 17, 2048)?;
        if serde_json::to_vec(self).map_err(|_| invalid())?.len() > 2048 {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Secret bytes represent the strict private JSON payload, never a generic record Value.
pub struct ApiKeySecret(Zeroizing<String>);
struct SensitiveString(Zeroizing<String>);
impl<'de> Deserialize<'de> for SensitiveString {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(|text| Self(Zeroizing::new(text)))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretPayload {
    api_key: SensitiveString,
}
impl ApiKeySecret {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() > 2048 {
            return Err(invalid());
        }
        let payload: SecretPayload = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if payload.api_key.0.is_empty()
            || payload.api_key.0.len() > 512
            || payload.api_key.0.bytes().any(|b| b.is_ascii_control())
        {
            return Err(invalid());
        }
        Ok(Self(payload.api_key.0))
    }
    /// Provider adapters receive only the validated API key, not the private JSON wrapper.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    fn payload(&self) -> Result<Zeroizing<Vec<u8>>> {
        #[derive(Serialize)]
        struct Borrowed<'a> {
            api_key: &'a str,
        }
        serde_json::to_vec(&Borrowed { api_key: &self.0 })
            .map(Zeroizing::new)
            .map_err(|_| invalid())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntry {
    key_id: String,
    key: SensitiveString,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    format: String,
    active_ingress: String,
    ingress: Vec<KeyEntry>,
    active_at_rest: String,
    at_rest: Vec<KeyEntry>,
    active_grant: String,
    grants: Vec<KeyEntry>,
}
struct Keys {
    active: String,
    values: BTreeMap<String, Zeroizing<Vec<u8>>>,
}
pub struct Crypto {
    ingress: Keys,
    at_rest: Keys,
    grants: Keys,
    #[cfg(test)]
    ingress_opens: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    secret_opens: std::sync::atomic::AtomicUsize,
}
fn valid_key_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn decode(text: &str, min: usize, max: usize) -> Result<Vec<u8>> {
    if text.len() > max.div_ceil(3) * 4 {
        return Err(invalid());
    }
    let bytes = URL_SAFE_NO_PAD.decode(text).map_err(|_| invalid())?;
    if bytes.len() < min || bytes.len() > max || URL_SAFE_NO_PAD.encode(&bytes) != text {
        return Err(invalid());
    }
    Ok(bytes)
}
fn prepare_keys(
    active: String,
    entries: Vec<KeyEntry>,
    ids: &mut BTreeSet<String>,
    material: &mut Vec<Zeroizing<Vec<u8>>>,
) -> Result<Keys> {
    if entries.is_empty() || entries.len() > 16 {
        return Err(key_error());
    }
    let mut values = BTreeMap::new();
    for entry in entries {
        if entry.key.0.len() != 43 {
            return Err(key_error());
        }
        let mut bytes = Zeroizing::new(vec![0u8; 33]);
        let length = URL_SAFE_NO_PAD
            .decode_slice(entry.key.0.as_bytes(), &mut bytes)
            .map_err(|_| key_error())?;
        if length != 32 || URL_SAFE_NO_PAD.encode(&bytes[..length]) != *entry.key.0 {
            return Err(key_error());
        }
        bytes.truncate(length);
        if !valid_key_id(&entry.key_id)
            || !ids.insert(entry.key_id.clone())
            || material.iter().any(|old| **old == *bytes)
        {
            return Err(key_error());
        }
        material.push(bytes.clone());
        values.insert(entry.key_id.clone(), bytes);
    }
    if !values.contains_key(&active) {
        return Err(key_error());
    }
    Ok(Keys { active, values })
}
#[cfg(unix)]
fn private_file(meta: &FileMetadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.is_file() && meta.nlink() == 1 && meta.mode() & 0o077 == 0 && meta.len() <= 65_536
}
#[cfg(not(unix))]
fn private_file(_: &FileMetadata) -> bool {
    false
}
#[cfg(unix)]
fn same_file(a: &FileMetadata, b: &FileMetadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}
#[cfg(not(unix))]
fn same_file(_: &FileMetadata, _: &FileMetadata) -> bool {
    false
}

impl Crypto {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(key_error());
        }
        let before = std::fs::symlink_metadata(path).map_err(|_| key_error())?;
        if !private_file(&before) {
            return Err(key_error());
        }
        let file = File::open(path).map_err(|_| key_error())?;
        let opened = file.metadata().map_err(|_| key_error())?;
        if !private_file(&opened) || !same_file(&before, &opened) {
            return Err(key_error());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(65_537)
            .read_to_end(&mut bytes)
            .map_err(|_| key_error())?;
        let after = std::fs::symlink_metadata(path).map_err(|_| key_error())?;
        if bytes.len() > 65_536 || !private_file(&after) || !same_file(&opened, &after) {
            return Err(key_error());
        }
        Self::parse(&bytes)
    }
    fn parse(bytes: &[u8]) -> Result<Self> {
        let parsed: KeyFile = serde_json::from_slice(bytes).map_err(|_| key_error())?;
        if parsed.format != "rebase-credential-keyring-1" {
            return Err(key_error());
        }
        let mut ids = BTreeSet::new();
        let mut material = Vec::new();
        let crypto = Self {
            ingress: prepare_keys(
                parsed.active_ingress,
                parsed.ingress,
                &mut ids,
                &mut material,
            )?,
            at_rest: prepare_keys(
                parsed.active_at_rest,
                parsed.at_rest,
                &mut ids,
                &mut material,
            )?,
            grants: prepare_keys(parsed.active_grant, parsed.grants, &mut ids, &mut material)?,
            #[cfg(test)]
            ingress_opens: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            secret_opens: std::sync::atomic::AtomicUsize::new(0),
        };
        // Distinct raw X25519 private bytes can clamp to the same effective key.
        let mut public_keys = BTreeSet::new();
        for key in crypto.ingress.values.values() {
            let private = <K as Kem>::PrivateKey::from_bytes(key).map_err(|_| key_error())?;
            if !public_keys.insert(K::sk_to_pk(&private).to_bytes().to_vec()) {
                return Err(key_error());
            }
        }
        Ok(crypto)
    }
    pub fn ingress_descriptor(&self) -> IngressDescriptor {
        let private =
            <K as Kem>::PrivateKey::from_bytes(&self.ingress.values[&self.ingress.active])
                .expect("validated ingress key");
        IngressDescriptor {
            format: INGRESS_FORMAT.into(),
            key_id: self.ingress.active.clone(),
            suite: "X25519-HKDF-SHA256-AES256GCM".into(),
            public_key: URL_SAFE_NO_PAD.encode(K::sk_to_pk(&private).to_bytes()),
        }
    }
    pub fn open_ingress(
        &self,
        envelope: &IngressEnvelope,
        context: &IngressContext,
        now: i64,
    ) -> Result<ApiKeySecret> {
        #[cfg(test)]
        self.ingress_opens
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if envelope.format != INGRESS_FORMAT
            || envelope.expires_at <= now
            || envelope
                .expires_at
                .checked_sub(now)
                .is_none_or(|ttl| ttl > 900_000)
        {
            return Err(invalid());
        }
        let key = self
            .ingress
            .values
            .get(&envelope.key_id)
            .ok_or_else(invalid)?;
        let sk = <K as Kem>::PrivateKey::from_bytes(key).map_err(|_| invalid())?;
        let enc = <K as Kem>::EncappedKey::from_bytes(&decode(&envelope.enc, 32, 32)?)
            .map_err(|_| invalid())?;
        let ciphertext = decode(&envelope.ciphertext, 17, 2048)?;
        let aad = ingress_aad(context, envelope.expires_at)?;
        let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, K>(
            &OpModeR::Base,
            &sk,
            &enc,
            INGRESS_INFO,
        )
        .map_err(|_| invalid())?;
        ApiKeySecret::from_bytes(receiver.open(&ciphertext, &aad).map_err(|_| invalid())?)
    }
    pub fn seal_secret(
        &self,
        secret: &ApiKeySecret,
        context: &SecretContext,
    ) -> Result<SecretEnvelope> {
        let aad = secret_aad(context)?;
        let (nonce, ciphertext) = seal(
            &self.at_rest.values[&self.at_rest.active],
            &secret.payload()?,
            &aad,
        )?;
        Ok(SecretEnvelope {
            format: SECRET_FORMAT.into(),
            incarnation: context.incarnation,
            credential: context.credential,
            secret_revision: context.secret_revision,
            key_id: self.at_rest.active.clone(),
            nonce,
            ciphertext,
        })
    }
    pub fn open_secret(
        &self,
        envelope: &SecretEnvelope,
        context: &SecretContext,
    ) -> Result<ApiKeySecret> {
        #[cfg(test)]
        self.secret_opens
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        envelope.validate()?;
        if envelope.credential != context.credential
            || envelope.incarnation != context.incarnation
            || envelope.secret_revision != context.secret_revision
        {
            return Err(invalid());
        }
        let bytes = open(
            self.at_rest
                .values
                .get(&envelope.key_id)
                .ok_or_else(invalid)?,
            &envelope.nonce,
            &envelope.ciphertext,
            &secret_aad(context)?,
            2048,
        )?;
        ApiKeySecret::from_bytes(bytes)
    }
    pub fn rewrap(
        &self,
        envelope: &SecretEnvelope,
        context: &SecretContext,
    ) -> Result<SecretEnvelope> {
        self.seal_secret(&self.open_secret(envelope, context)?, context)
    }
    pub fn seal_grant(&self, claims: &[u8]) -> Result<String> {
        if claims.is_empty() || claims.len() > 2048 {
            return Err(invalid());
        }
        let (nonce, ciphertext) =
            seal(&self.grants.values[&self.grants.active], claims, GRANT_AAD)?;
        let token = GrantEnvelope {
            format: GRANT_FORMAT.into(),
            key_id: self.grants.active.clone(),
            nonce,
            ciphertext,
        };
        let token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&token).map_err(|_| invalid())?);
        if token.len() > 4096 {
            return Err(invalid());
        }
        Ok(token)
    }
    pub fn open_grant(&self, token: &str) -> Result<Zeroizing<Vec<u8>>> {
        if token.len() > 4096 {
            return Err(invalid());
        }
        let envelope: GrantEnvelope =
            serde_json::from_slice(&decode(token, 1, 3072)?).map_err(|_| invalid())?;
        if envelope.format != GRANT_FORMAT {
            return Err(invalid());
        }
        open(
            self.grants
                .values
                .get(&envelope.key_id)
                .ok_or_else(invalid)?,
            &envelope.nonce,
            &envelope.ciphertext,
            GRANT_AAD,
            2064,
        )
        .map(Zeroizing::new)
    }
    #[cfg(test)]
    pub fn test() -> Self {
        Self::test_with_seed(1)
    }
    #[cfg(test)]
    pub fn test_with_seed(seed: u8) -> Self {
        let keys = |id: &str, key: u8| Keys {
            active: id.into(),
            values: [(id.into(), Zeroizing::new(vec![key; 32]))].into(),
        };
        Self {
            ingress: keys(&format!("test-ingress-{seed}"), seed),
            at_rest: keys(&format!("test-vault-{seed}"), seed.wrapping_add(1)),
            grants: keys(&format!("test-grant-{seed}"), seed.wrapping_add(2)),
            ingress_opens: std::sync::atomic::AtomicUsize::new(0),
            secret_opens: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    #[cfg(test)]
    pub fn test_rotated(old_seed: u8, new_seed: u8) -> Self {
        let mut current = Self::test_with_seed(new_seed);
        current
            .at_rest
            .values
            .extend(Self::test_with_seed(old_seed).at_rest.values);
        current
    }
    #[cfg(test)]
    pub fn decrypt_counts(&self) -> (usize, usize) {
        (
            self.ingress_opens.load(std::sync::atomic::Ordering::SeqCst),
            self.secret_opens.load(std::sync::atomic::Ordering::SeqCst),
        )
    }
    #[cfg(test)]
    pub fn seal_ingress_for_test(
        &self,
        secret: &ApiKeySecret,
        context: &IngressContext,
        expires_at: i64,
    ) -> Result<IngressEnvelope> {
        let private =
            <K as Kem>::PrivateKey::from_bytes(&self.ingress.values[&self.ingress.active])
                .map_err(|_| invalid())?;
        let (enc, mut sender) = hpke::setup_sender::<AesGcm256, HkdfSha256, K>(
            &hpke::OpModeS::Base,
            &K::sk_to_pk(&private),
            INGRESS_INFO,
        )
        .map_err(|_| invalid())?;
        let ciphertext = sender
            .seal(&secret.payload()?, &ingress_aad(context, expires_at)?)
            .map_err(|_| invalid())?;
        Ok(IngressEnvelope {
            format: INGRESS_FORMAT.into(),
            key_id: self.ingress.active.clone(),
            enc: URL_SAFE_NO_PAD.encode(enc.to_bytes()),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            expires_at,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantEnvelope {
    format: String,
    key_id: String,
    nonce: String,
    ciphertext: String,
}
fn seal(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<(String, String)> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| invalid())?;
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| invalid())?;
    let encrypted = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| invalid())?;
    Ok((
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(encrypted),
    ))
}
fn open(key: &[u8], nonce: &str, ciphertext: &str, aad: &[u8], max: usize) -> Result<Vec<u8>> {
    let nonce: [u8; 24] = decode(nonce, 24, 24)?.try_into().map_err(|_| invalid())?;
    XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| invalid())?
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &decode(ciphertext, 17, max)?,
                aad,
            },
        )
        .map_err(|_| invalid())
}
pub fn ingress_aad(context: &IngressContext, expires_at: i64) -> Result<Vec<u8>> {
    context.metadata.validate()?;
    let hash = format!("{:x}", Sha256::digest(context.context.as_bytes()));
    serde_json::to_vec(&(
        INGRESS_FORMAT,
        &context.model,
        context.store,
        context.tenant,
        context.actor,
        context.credential_epoch.to_string(),
        hash,
        context.operation_id,
        context.credential,
        context.owner,
        context.if_version,
        context.metadata.provider,
        &context.metadata.account,
        &context.metadata,
        expires_at.to_string(),
    ))
    .map_err(|_| invalid())
}
fn secret_aad(context: &SecretContext) -> Result<Vec<u8>> {
    validate_account(&context.account)?;
    if context.incarnation.is_nil() || context.secret_revision == 0 {
        return Err(invalid());
    }
    serde_json::to_vec(&(
        SECRET_FORMAT,
        context.tenant,
        context.credential,
        context.incarnation,
        context.secret_revision.to_string(),
        context.provider,
        &context.account,
        "provider-api-key-1",
    ))
    .map_err(|_| invalid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    #[test]
    fn selected_aead_implementations_clear_key_state_on_drop() {
        fn requires_zeroizing_drop<T: zeroize::ZeroizeOnDrop>() {}
        requires_zeroizing_drop::<aes_gcm::Aes256Gcm>();
        requires_zeroizing_drop::<XChaCha20Poly1305>();
    }
    fn unhex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    fn vector() -> Value {
        serde_json::from_str(include_str!("../../tools/node/fixtures/hpke-rfc9180.json")).unwrap()
    }
    fn wire() -> Value {
        serde_json::from_str(include_str!(
            "../../tools/node/fixtures/credential-ingress.json"
        ))
        .unwrap()
    }
    fn ingress_context() -> IngressContext {
        let fixture = wire();
        let c = &fixture["context"];
        let id = |field: &str| Uuid::parse_str(c[field].as_str().unwrap()).unwrap();
        IngressContext {
            model: c["model"].as_str().unwrap().into(),
            store: id("store"),
            tenant: id("tenant"),
            actor: id("actor"),
            credential_epoch: 7,
            context: c["context"].as_str().unwrap().into(),
            operation_id: id("operation_id"),
            credential: id("credential"),
            owner: None,
            if_version: None,
            metadata: serde_json::from_value(c["metadata"].clone()).unwrap(),
        }
    }
    fn secret_context() -> SecretContext {
        let c = ingress_context();
        SecretContext {
            tenant: c.tenant,
            credential: c.credential,
            incarnation: Uuid::from_u128(99),
            secret_revision: 1,
            provider: c.metadata.provider,
            account: c.metadata.account,
        }
    }
    fn secret() -> ApiKeySecret {
        ApiKeySecret::from_bytes(wire()["payload"].as_str().unwrap().as_bytes().to_vec()).unwrap()
    }
    fn keyring() -> Value {
        json!({"format":"rebase-credential-keyring-1","active_ingress":"ingress","ingress":[{"key_id":"ingress","key":URL_SAFE_NO_PAD.encode([1u8;32])}],
            "active_at_rest":"vault","at_rest":[{"key_id":"vault","key":URL_SAFE_NO_PAD.encode([2u8;32])}],
            "active_grant":"grant","grants":[{"key_id":"grant","key":URL_SAFE_NO_PAD.encode([3u8;32])}]})
    }
    #[test]
    fn independent_rfc9180_vector_opens() {
        let v = vector();
        let hex = |key: &str| unhex(v[key].as_str().unwrap());
        let sk = <K as Kem>::PrivateKey::from_bytes(&hex("skRm")).unwrap();
        assert_eq!(K::sk_to_pk(&sk).to_bytes().as_slice(), hex("pkRm"));
        let enc = <K as Kem>::EncappedKey::from_bytes(&hex("enc")).unwrap();
        let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, K>(
            &OpModeR::Base,
            &sk,
            &enc,
            &hex("info"),
        )
        .unwrap();
        assert_eq!(receiver.open(&hex("ct"), &hex("aad")).unwrap(), hex("pt"));
    }
    #[test]
    fn node_generated_capsule_opens_with_actual_typed_aad() {
        let w = wire();
        let c = ingress_context();
        let envelope: IngressEnvelope = serde_json::from_value(w["envelope"].clone()).unwrap();
        let mut crypto = Crypto::test();
        crypto.ingress = Keys {
            active: "rfc-test-ingress".into(),
            values: [(
                "rfc-test-ingress".into(),
                Zeroizing::new(unhex(vector()["skRm"].as_str().unwrap())),
            )]
            .into(),
        };
        assert_eq!(
            String::from_utf8(ingress_aad(&c, envelope.expires_at).unwrap()).unwrap(),
            w["aad"].as_str().unwrap()
        );
        assert_eq!(
            serde_json::to_value(crypto.ingress_descriptor()).unwrap(),
            w["descriptor"]
        );
        assert_eq!(
            crypto
                .open_ingress(&envelope, &c, envelope.expires_at - 60_000)
                .unwrap()
                .as_bytes(),
            secret().as_bytes()
        );
    }
    #[test]
    fn ingress_rejects_every_changed_identity_metadata_expiry_and_encoding() {
        let crypto = Crypto::test();
        let c = ingress_context();
        let now = 1_000_000;
        let envelope = crypto
            .seal_ingress_for_test(&secret(), &c, now + 60_000)
            .unwrap();
        assert_eq!(
            crypto.open_ingress(&envelope, &c, now).unwrap().as_bytes(),
            secret().as_bytes()
        );
        let mut changes = Vec::new();
        macro_rules! change {
            ($field:ident, $value:expr) => {{
                let mut changed = c.clone();
                changed.$field = $value;
                changes.push(changed);
            }};
        }
        change!(model, "other".into());
        change!(store, Uuid::new_v4());
        change!(tenant, Uuid::new_v4());
        change!(actor, Uuid::new_v4());
        change!(credential_epoch, 8);
        change!(context, "other".into());
        change!(operation_id, Uuid::new_v4());
        change!(credential, Uuid::new_v4());
        change!(owner, Some(c.actor));
        change!(if_version, Some(Uuid::new_v4()));
        for field in 0..5 {
            let mut changed = c.clone();
            match field {
                0 => changed.metadata.label.push('!'),
                1 => changed.metadata.provider = Provider::Brevo,
                2 => changed.metadata.account.push('!'),
                3 => changed.metadata.enabled = false,
                _ => changed.metadata.scopes.clear(),
            }
            changes.push(changed);
        }
        for changed in changes {
            assert!(crypto.open_ingress(&envelope, &changed, now).is_err());
        }
        for field in 0..7 {
            let mut changed = envelope.clone();
            match field {
                0 => changed.format.push('!'),
                1 => changed.key_id.push('!'),
                2 => changed.enc.push('='),
                3 => {
                    let mut bytes = decode(&changed.ciphertext, 17, 2048).unwrap();
                    bytes[0] ^= 1;
                    changed.ciphertext = URL_SAFE_NO_PAD.encode(bytes);
                }
                4 => changed.expires_at += 1,
                5 => changed.enc = URL_SAFE_NO_PAD.encode([0u8; 32]),
                _ => changed.ciphertext = URL_SAFE_NO_PAD.encode(vec![0u8; 2049]),
            }
            assert!(crypto.open_ingress(&changed, &c, now).is_err());
        }
        assert!(
            crypto
                .open_ingress(&envelope, &c, envelope.expires_at)
                .is_err()
        );
        assert!(
            crypto
                .open_ingress(&envelope, &c, envelope.expires_at - 900_001)
                .is_err()
        );
        assert!(crypto.open_ingress(&envelope, &c, i64::MIN).is_err());
    }
    #[test]
    fn stored_secret_aad_random_nonce_rotation_and_key_loss() {
        let mut crypto = Crypto::test();
        let c = secret_context();
        let a = crypto.seal_secret(&secret(), &c).unwrap();
        let b = crypto.seal_secret(&secret(), &c).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_eq!(
            crypto.open_secret(&a, &c).unwrap().as_bytes(),
            secret().as_bytes()
        );
        for field in 0..6 {
            let mut changed = c.clone();
            match field {
                0 => changed.tenant = Uuid::new_v4(),
                1 => changed.credential = Uuid::new_v4(),
                2 => changed.secret_revision += 1,
                3 => changed.provider = Provider::Brevo,
                4 => changed.account.push('x'),
                _ => changed.incarnation = Uuid::new_v4(),
            }
            assert!(crypto.open_secret(&a, &changed).is_err());
        }
        let mut transplanted_context = c.clone();
        transplanted_context.incarnation = Uuid::new_v4();
        let mut transplanted = a.clone();
        transplanted.incarnation = transplanted_context.incarnation;
        assert!(
            crypto
                .open_secret(&transplanted, &transplanted_context)
                .is_err()
        );
        for field in 0..6 {
            let mut changed = a.clone();
            match field {
                0 => changed.format.push('!'),
                1 => changed.key_id.push('!'),
                2 => changed.nonce = "AA".into(),
                3 => {
                    let mut bytes = decode(&changed.ciphertext, 17, 2048).unwrap();
                    bytes[0] ^= 1;
                    changed.ciphertext = URL_SAFE_NO_PAD.encode(bytes);
                }
                4 => changed.secret_revision += 1,
                _ => changed.incarnation = Uuid::new_v4(),
            }
            assert!(crypto.open_secret(&changed, &c).is_err());
        }
        crypto
            .at_rest
            .values
            .insert("rotated".into(), Zeroizing::new(vec![4; 32]));
        crypto.at_rest.active = "rotated".into();
        let rotated = crypto.rewrap(&a, &c).unwrap();
        assert_eq!(rotated.key_id, "rotated");
        assert_eq!(rotated.secret_revision, a.secret_revision);
        crypto.at_rest.values.remove(&a.key_id);
        assert!(crypto.open_secret(&a, &c).is_err());
        assert_eq!(
            crypto.open_secret(&rotated, &c).unwrap().as_bytes(),
            secret().as_bytes()
        );
        assert!(!format!("{a:?}").contains("PUBLIC_TEST_API_KEY"));
        assert!(
            !serde_json::to_string(&a)
                .unwrap()
                .contains("PUBLIC_TEST_API_KEY")
        );
    }
    #[test]
    fn grants_are_opaque_bounded_and_separate_from_secret_storage() {
        let crypto = Crypto::test();
        let marker = b"PUBLIC_TEST_PRIVATE_BINDING";
        let a = crypto.seal_grant(marker).unwrap();
        let b = crypto.seal_grant(marker).unwrap();
        assert_ne!(a, b);
        assert_eq!(crypto.open_grant(&a).unwrap().as_slice(), marker);
        assert_eq!(crypto.decrypt_counts(), (0, 0));
        assert!(
            !String::from_utf8(decode(&a, 1, 3072).unwrap())
                .unwrap()
                .contains(std::str::from_utf8(marker).unwrap())
        );
        assert!(crypto.seal_grant(&vec![0; 2049]).is_err());
        assert!(crypto.open_grant(&"x".repeat(4097)).is_err());
        assert!(crypto.open_grant(&(a.clone() + "=")).is_err());
        assert!(Crypto::test_with_seed(8).open_grant(&a).is_err());
        let grant: GrantEnvelope = serde_json::from_slice(&decode(&a, 1, 3072).unwrap()).unwrap();
        assert!(
            open(
                &crypto.at_rest.values[&crypto.at_rest.active],
                &grant.nonce,
                &grant.ciphertext,
                GRANT_AAD,
                2064
            )
            .is_err()
        );
        assert!(
            open(
                &crypto.grants.values[&crypto.grants.active],
                &grant.nonce,
                &grant.ciphertext,
                b"other-domain",
                2064
            )
            .is_err()
        );
    }
    #[test]
    fn payload_and_keyring_errors_are_fixed_and_private() {
        for payload in [
            "PUBLIC_TEST_PRIVATE",
            "{\"api_key\":\"\"}",
            "{\"api_key\":\"a\",\"api_key\":\"b\"}",
            "{\"api_key\":\"a\",\"other\":0}",
            "{\"api_key\":\"\\n\"}",
        ] {
            let error = ApiKeySecret::from_bytes(payload.as_bytes().to_vec())
                .err()
                .unwrap();
            assert_eq!(error.detail, "credential cryptography failed");
        }
        let valid = keyring();
        assert!(Crypto::parse(&serde_json::to_vec(&valid).unwrap()).is_ok());
        for case in 0..8 {
            let mut value = valid.clone();
            match case {
                0 => value["format"] = json!("other"),
                1 => value["active_ingress"] = json!("absent"),
                2 => value["ingress"][0]["key"] = json!("PRIVATE_MALFORMED"),
                3 => value["ingress"][0]["key_id"] = json!("grant"),
                4 => value["ingress"][0]["key"] = value["grants"][0]["key"].clone(),
                5 => value["grants"] = json!([]),
                6 => value["extra"] = json!(1),
                _ => value["ingress"][0]["key_id"] = json!("../path"),
            }
            let error = Crypto::parse(&serde_json::to_vec(&value).unwrap())
                .err()
                .unwrap();
            assert_eq!(error.detail, "credential key configuration is invalid");
        }
        let mut aliases = valid;
        let mut alias = [1u8; 32];
        alias[0] ^= 1;
        aliases["ingress"]
            .as_array_mut()
            .unwrap()
            .push(json!({"key_id":"alias","key":URL_SAFE_NO_PAD.encode(alias)}));
        assert!(Crypto::parse(&serde_json::to_vec(&aliases).unwrap()).is_err());
        assert!(Crypto::load(Path::new("relative-private-key-file")).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn keyring_requires_private_regular_unlinked_file() {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
        let directory =
            std::env::temp_dir().join(format!("next-base-public-test-keys-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("keys.json");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&serde_json::to_vec(&keyring()).unwrap())
            .unwrap();
        drop(file);
        assert!(Crypto::load(&path).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(Crypto::load(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.join("link");
        symlink(&path, &link).unwrap();
        assert!(Crypto::load(&link).is_err());
        std::fs::remove_file(link).unwrap();
        let hard = directory.join("hard");
        std::fs::hard_link(&path, &hard).unwrap();
        assert!(Crypto::load(&path).is_err());
        std::fs::remove_file(hard).unwrap();
        assert!(Crypto::load(&directory).is_err());
        std::fs::write(&path, vec![b' '; 65_537]).unwrap();
        assert!(Crypto::load(&path).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
