//! External proof custody, purpose-separated keyed fingerprints and encrypted payloads.
//! Plaintext codes, recovery capabilities and key material have no serializable DTO.
use crate::native_slice::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    fs::{File, Metadata},
    io::Read,
    marker::PhantomData,
    path::Path,
};
use zeroize::Zeroizing;

pub const KEYRING_FORMAT: &str = "next-base-auth-proof-keyring-1";
pub const FORMAT: &str = "next-base-auth-proof-crypto-1";
pub const MAX_PLAINTEXT_BYTES: usize = 4096;
const MAX_BINDING_BYTES: usize = 16_384;
const MAX_KEYRING_BYTES: u64 = 65_536;
type HmacSha256 = Hmac<Sha256>;

fn invalid() -> Error {
    Error::new("proof_crypto", "proof cryptography failed")
}
fn key_error() -> Error {
    Error::new("proof_keys", "proof key configuration is invalid")
}

/// Struct-derived deserializers accept arrays too; persistent proof DTOs do not.
pub(crate) fn object<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<T, D::Error> {
    struct Object<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> de::Visitor<'de> for Object<T> {
        type Value = T;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a proof object")
        }
        fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> std::result::Result<T, A::Error> {
            T::deserialize(de::value::MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(Object(PhantomData))
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}
fn decode(value: &str, min: usize, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    if value.len() > max.div_ceil(3) * 4 {
        return Err(invalid());
    }
    let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(value).map_err(|_| invalid())?);
    if !(min..=max).contains(&bytes.len()) || URL_SAFE_NO_PAD.encode(&*bytes) != value {
        return Err(invalid());
    }
    Ok(bytes)
}
pub fn validate_secret(value: &str) -> Result<()> {
    decode(value, 32, 32).map(|_| ())
}
pub fn validate_code(value: &str) -> Result<()> {
    if value.len() != 6 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Envelope {
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
}
impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofEnvelope")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}
impl<'de> Deserialize<'de> for Envelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            key_id: String,
            nonce: String,
            ciphertext: String,
        }
        let fields: Fields = object(deserializer)?;
        let envelope = Self {
            key_id: fields.key_id,
            nonce: fields.nonce,
            ciphertext: fields.ciphertext,
        };
        envelope.validate().map_err(de::Error::custom)?;
        Ok(envelope)
    }
}
impl Envelope {
    pub fn validate(&self) -> Result<()> {
        if !valid_key_id(&self.key_id) {
            return Err(invalid());
        }
        decode(&self.nonce, 24, 24)?;
        decode(&self.ciphertext, 16, MAX_PLAINTEXT_BYTES + 16)?;
        Ok(())
    }
    pub fn schema() -> Value {
        json!({"type":"object","additionalProperties":false,"required":["key_id","nonce","ciphertext"],"properties":{
            "key_id":{"type":"string","pattern":"^[A-Za-z0-9_-]{1,64}$"},
            "nonce":{"type":"string","pattern":"^[A-Za-z0-9_-]{32}$"},
            "ciphertext":{"type":"string","minLength":22,"maxLength":(MAX_PLAINTEXT_BYTES+16).div_ceil(3)*4,"pattern":"^[A-Za-z0-9_-]+$"}
        }})
    }
}

struct KeyString(Zeroizing<String>);
impl<'de> Deserialize<'de> for KeyString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}
struct KeyEntry {
    key_id: String,
    key: KeyString,
}
impl<'de> Deserialize<'de> for KeyEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            key_id: String,
            key: KeyString,
        }
        let fields: Fields = object(deserializer)?;
        Ok(Self {
            key_id: fields.key_id,
            key: fields.key,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    format: String,
    current: String,
    keys: Vec<KeyEntry>,
}

pub struct Crypto {
    current: String,
    keys: BTreeMap<String, Zeroizing<Vec<u8>>>,
}
impl std::fmt::Debug for Crypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofCrypto").finish_non_exhaustive()
    }
}

#[cfg(unix)]
fn private_file(meta: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.is_file()
        && meta.nlink() == 1
        && meta.mode() & 0o077 == 0
        && meta.len() <= MAX_KEYRING_BYTES
}
#[cfg(not(unix))]
fn private_file(_: &Metadata) -> bool {
    false
}
#[cfg(unix)]
fn same_file(first: &Metadata, second: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    first.dev() == second.dev() && first.ino() == second.ino()
}
#[cfg(not(unix))]
fn same_file(_: &Metadata, _: &Metadata) -> bool {
    false
}

impl Crypto {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = read_private_file(path, MAX_KEYRING_BYTES as usize)?;
        Self::parse(&bytes)
    }
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_KEYRING_BYTES as usize {
            return Err(key_error());
        }
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let file: KeyFile = object(&mut deserializer).map_err(|_| key_error())?;
        deserializer.end().map_err(|_| key_error())?;
        if file.format != KEYRING_FORMAT || !(1..=4).contains(&file.keys.len()) {
            return Err(key_error());
        }
        let mut keys = BTreeMap::new();
        for entry in file.keys {
            let key = decode(&entry.key.0, 32, 32).map_err(|_| key_error())?;
            if !valid_key_id(&entry.key_id)
                || keys.contains_key(&entry.key_id)
                || keys.values().any(|previous| previous == &key)
            {
                return Err(key_error());
            }
            keys.insert(entry.key_id, key);
        }
        if !keys.contains_key(&file.current) {
            return Err(key_error());
        }
        Ok(Self {
            current: file.current,
            keys,
        })
    }
    pub fn current_id(&self) -> &str {
        &self.current
    }
    pub fn has_key(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }
    fn derive(&self, key_id: &str, category: &[u8], purpose: &str) -> Result<Zeroizing<Vec<u8>>> {
        if purpose.is_empty()
            || purpose.len() > 64
            || !purpose
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-/".contains(&byte))
        {
            return Err(invalid());
        }
        let key = self.keys.get(key_id).ok_or_else(invalid)?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| invalid())?;
        mac.update(b"next-base/auth-proof/kdf/1\0");
        frame(&mut mac, category);
        frame(&mut mac, purpose.as_bytes());
        Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
    }
    fn mac(
        &self,
        key_id: &str,
        purpose: &str,
        binding: &impl Serialize,
        secret: &[u8],
    ) -> Result<HmacSha256> {
        if secret.len() > MAX_PLAINTEXT_BYTES {
            return Err(invalid());
        }
        let key = self.derive(key_id, b"mac", purpose)?;
        let binding = binding_bytes(binding)?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).map_err(|_| invalid())?;
        mac.update(b"next-base/auth-proof/digest/1\0");
        frame(&mut mac, &binding);
        frame(&mut mac, secret);
        Ok(mac)
    }
    pub fn digest(&self, purpose: &str, binding: &impl Serialize, secret: &[u8]) -> Result<String> {
        self.digest_with_key(&self.current, purpose, binding, secret)
    }
    pub fn digest_with_key(
        &self,
        key_id: &str,
        purpose: &str,
        binding: &impl Serialize,
        secret: &[u8],
    ) -> Result<String> {
        Ok(URL_SAFE_NO_PAD.encode(
            self.mac(key_id, purpose, binding, secret)?
                .finalize()
                .into_bytes(),
        ))
    }
    pub fn verify_digest(
        &self,
        purpose: &str,
        binding: &impl Serialize,
        secret: &[u8],
        digest: &str,
    ) -> Result<bool> {
        self.verify_digest_with_key(&self.current, purpose, binding, secret, digest)
    }
    pub fn verify_digest_with_key(
        &self,
        key_id: &str,
        purpose: &str,
        binding: &impl Serialize,
        secret: &[u8],
        digest: &str,
    ) -> Result<bool> {
        // HMAC's verify_slice performs constant-time comparison for the fixed
        // digest length. Malformed encodings are rejected before comparison.
        let expected = decode(digest, 32, 32)?;
        Ok(self
            .mac(key_id, purpose, binding, secret)?
            .verify_slice(&expected)
            .is_ok())
    }
    pub fn seal(&self, binding: &impl Serialize, plaintext: &[u8]) -> Result<Envelope> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(invalid());
        }
        let key = self.derive(&self.current, b"encryption", "payload")?;
        let aad = aad(&self.current, binding)?;
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| invalid())?;
        let ciphertext = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| invalid())?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| invalid())?;
        Ok(Envelope {
            key_id: self.current.clone(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
    }
    pub fn open(
        &self,
        binding: &impl Serialize,
        envelope: &Envelope,
    ) -> Result<Zeroizing<Vec<u8>>> {
        envelope.validate()?;
        let key = self.derive(&envelope.key_id, b"encryption", "payload")?;
        let aad = aad(&envelope.key_id, binding)?;
        let nonce: [u8; 24] = decode(&envelope.nonce, 24, 24)?
            .as_slice()
            .try_into()
            .map_err(|_| invalid())?;
        let ciphertext = decode(&envelope.ciphertext, 16, MAX_PLAINTEXT_BYTES + 16)?;
        XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| invalid())?
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| invalid())
    }
    #[cfg(test)]
    pub(crate) fn test_key(key_id: &str, key: [u8; 32]) -> Self {
        assert!(valid_key_id(key_id));
        Self {
            current: key_id.into(),
            keys: [(key_id.into(), Zeroizing::new(key.to_vec()))].into(),
        }
    }
}

/// Shared external custody boundary for proof keyrings and signing PEMs.
/// This profile requires a private, singly linked Unix regular file.
pub fn read_private_file(path: &Path, max_bytes: usize) -> Result<Zeroizing<Vec<u8>>> {
    if !path.is_absolute() || max_bytes == 0 || max_bytes > MAX_KEYRING_BYTES as usize {
        return Err(key_error());
    }
    let before = std::fs::symlink_metadata(path).map_err(|_| key_error())?;
    if !private_file(&before) || before.len() > max_bytes as u64 {
        return Err(key_error());
    }
    let file = File::open(path).map_err(|_| key_error())?;
    let opened = file.metadata().map_err(|_| key_error())?;
    if !private_file(&opened) || !same_file(&before, &opened) {
        return Err(key_error());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| key_error())?;
    let after = std::fs::symlink_metadata(path).map_err(|_| key_error())?;
    if bytes.len() > max_bytes || !private_file(&after) || !same_file(&opened, &after) {
        return Err(key_error());
    }
    Ok(bytes)
}

fn frame(mac: &mut HmacSha256, bytes: &[u8]) {
    mac.update(&(bytes.len() as u64).to_be_bytes());
    mac.update(bytes);
}
fn binding_bytes(binding: &impl Serialize) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = Zeroizing::new(serde_json::to_vec(binding).map_err(|_| invalid())?);
    if bytes.len() > MAX_BINDING_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}
fn aad(key_id: &str, binding: &impl Serialize) -> Result<Zeroizing<Vec<u8>>> {
    let binding = binding_bytes(binding)?;
    let mut bytes = Zeroizing::new(b"next-base/auth-proof/envelope/1\0".to_vec());
    for field in [key_id.as_bytes(), binding.as_slice()] {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    Ok(bytes)
}

pub fn random_secret() -> Result<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| invalid())?;
    Ok(URL_SAFE_NO_PAD.encode(*bytes))
}
fn code_from_random(value: u32) -> Option<Zeroizing<String>> {
    // Exactly 4294 complete million-value intervals; reject the incomplete tail.
    (value < 4_294_000_000).then(|| Zeroizing::new(format!("{:06}", value % 1_000_000)))
}
pub fn random_code() -> Result<Zeroizing<String>> {
    for _ in 0..128 {
        let mut bytes = Zeroizing::new([0u8; 4]);
        getrandom::fill(bytes.as_mut()).map_err(|_| invalid())?;
        if let Some(code) = code_from_random(u32::from_be_bytes(*bytes)) {
            return Ok(code);
        }
    }
    Err(invalid())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyfile(current: &str, entries: &[(&str, u8)]) -> Value {
        json!({"format":KEYRING_FORMAT,"current":current,"keys":entries.iter().map(|(id, byte)|
            json!({"key_id":id,"key":URL_SAFE_NO_PAD.encode([*byte;32])})).collect::<Vec<_>>()})
    }
    fn ring(current: &str, entries: &[(&str, u8)]) -> Crypto {
        Crypto::parse(&serde_json::to_vec(&keyfile(current, entries)).unwrap()).unwrap()
    }

    #[test]
    fn keyed_digest_matches_independent_python_hmac_vector_and_separates_domains() {
        let crypto = ring("a", &[("a", 11)]);
        let binding = json!({"challenge":"fixture"});
        let expected = "Bzi9wBkxT9LjUKEFVUcMpiu2f9tZ0zT2daVotGpjncM";
        // Python stdlib hmac/sha256, with two length-prefixed KDF fields
        // and two length-prefixed message fields. This is not a writer oracle.
        assert_eq!(
            crypto.digest("verifier", &binding, b"000042").unwrap(),
            expected
        );
        assert!(
            crypto
                .verify_digest("verifier", &binding, b"000042", expected)
                .unwrap()
        );
        for purpose in ["recovery", "fingerprint", "payload"] {
            assert_ne!(
                crypto.digest(purpose, &binding, b"000042").unwrap(),
                expected
            );
            assert!(
                !crypto
                    .verify_digest(purpose, &binding, b"000042", expected)
                    .unwrap()
            );
        }
        assert_ne!(
            crypto.derive("a", b"encryption", "payload").unwrap(),
            crypto.derive("a", b"mac", "payload").unwrap()
        );
        assert!(
            !crypto
                .verify_digest("verifier", &binding, b"000043", expected)
                .unwrap()
        );
        assert!(
            !crypto
                .verify_digest(
                    "verifier",
                    &json!({"challenge":"other"}),
                    b"000042",
                    expected
                )
                .unwrap()
        );
        assert!(
            crypto
                .verify_digest(
                    "verifier",
                    &binding,
                    b"000042",
                    &(expected.to_owned() + "=")
                )
                .is_err()
        );
        // Length framing prevents an adjacent binding/secret boundary ambiguity.
        assert_ne!(
            crypto.digest("verifier", &"a", b"bc").unwrap(),
            crypto.digest("verifier", &"ab", b"c").unwrap()
        );
    }

    #[test]
    fn encryption_binds_context_key_id_ciphertext_and_fresh_nonce() {
        let crypto = ring("a", &[("a", 11), ("b", 12)]);
        let binding = json!({"tenant":"one","challenge":"original","format":FORMAT});
        let first = crypto.seal(&binding, b"private-code-000042").unwrap();
        let second = crypto.seal(&binding, b"private-code-000042").unwrap();
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
        assert_eq!(
            &*crypto.open(&binding, &first).unwrap(),
            b"private-code-000042"
        );
        assert!(
            crypto
                .open(
                    &json!({"tenant":"two","challenge":"original","format":FORMAT}),
                    &first
                )
                .is_err()
        );
        let mut changed = first.clone();
        changed.key_id = "b".into();
        assert!(crypto.open(&binding, &changed).is_err());
        let mut changed = first.clone();
        let mut ciphertext = URL_SAFE_NO_PAD.decode(&changed.ciphertext).unwrap();
        ciphertext[0] ^= 1;
        changed.ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
        assert!(crypto.open(&binding, &changed).is_err());
        let mut changed = first.clone();
        let mut nonce = URL_SAFE_NO_PAD.decode(&changed.nonce).unwrap();
        nonce[0] ^= 1;
        changed.nonce = URL_SAFE_NO_PAD.encode(nonce);
        assert!(crypto.open(&binding, &changed).is_err());
        assert!(
            crypto
                .seal(&binding, &vec![0; MAX_PLAINTEXT_BYTES + 1])
                .is_err()
        );
        assert!(!serde_json::to_string(&first).unwrap().contains("000042"));
        assert!(!format!("{first:?}").contains(&first.ciphertext));
    }

    #[test]
    fn rotation_keeps_explicit_old_key_verification_and_removed_keys_fail_closed() {
        let old = ring("old", &[("old", 11)]);
        let rotated = ring("new", &[("old", 11), ("new", 12)]);
        let removed = ring("new", &[("new", 12)]);
        let binding = json!(["retained", 42]);
        let digest = old
            .digest("recovery", &binding, b"fixture-capability")
            .unwrap();
        let envelope = old.seal(&binding, b"fixture-response").unwrap();
        assert_eq!(rotated.current_id(), "new");
        assert!(rotated.has_key("old"));
        assert_eq!(
            rotated
                .digest_with_key("old", "recovery", &binding, b"fixture-capability")
                .unwrap(),
            digest
        );
        assert!(
            rotated
                .verify_digest_with_key("old", "recovery", &binding, b"fixture-capability", &digest)
                .unwrap()
        );
        assert!(
            !rotated
                .verify_digest("recovery", &binding, b"fixture-capability", &digest)
                .unwrap()
        );
        assert_eq!(
            &*rotated.open(&binding, &envelope).unwrap(),
            b"fixture-response"
        );
        assert!(!removed.has_key("old"));
        assert!(
            removed
                .verify_digest_with_key("old", "recovery", &binding, b"fixture-capability", &digest)
                .is_err()
        );
        assert!(removed.open(&binding, &envelope).is_err());
    }

    #[test]
    fn secret_and_code_formats_preserve_leading_zero_and_reject_modulo_tail() {
        for (sample, expected) in [
            (0, "000000"),
            (42, "000042"),
            (999_999, "999999"),
            (1_000_000, "000000"),
            (4_293_999_999, "999999"),
        ] {
            assert_eq!(code_from_random(sample).unwrap().as_str(), expected);
            validate_code(expected).unwrap();
        }
        assert!(code_from_random(4_294_000_000).is_none());
        assert!(code_from_random(u32::MAX).is_none());
        for invalid in [
            "42",
            "00042",
            "0000042",
            " 000042",
            "000042\n",
            "００００４２",
            "000.42",
        ] {
            assert!(validate_code(invalid).is_err());
        }
        for _ in 0..32 {
            validate_code(&random_code().unwrap()).unwrap();
            validate_secret(&random_secret().unwrap()).unwrap();
        }
        let secret = URL_SAFE_NO_PAD.encode([7; 32]);
        validate_secret(&secret).unwrap();
        for invalid in [
            format!("{secret}="),
            secret[..42].into(),
            URL_SAFE_NO_PAD.encode([7; 31]),
            URL_SAFE_NO_PAD.encode([7; 33]),
        ] {
            assert!(validate_secret(&invalid).is_err());
        }
    }

    #[test]
    fn keyring_and_envelope_require_strict_objects_and_bounded_unique_keys() {
        let good = keyfile("a", &[("a", 11)]);
        let mut duplicate = keyfile("a", &[("a", 11), ("a", 12)]);
        for bad in [
            json!([KEYRING_FORMAT, "a", []]),
            keyfile("missing", &[("a", 11)]),
            keyfile("a", &[]),
            duplicate.clone(),
            keyfile("a", &[("a", 11), ("b", 11)]),
            keyfile(
                "a",
                &[("a", 11), ("b", 12), ("c", 13), ("d", 14), ("e", 15)],
            ),
        ] {
            assert!(Crypto::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        duplicate = good.clone();
        duplicate["keys"][0] = json!(["a", URL_SAFE_NO_PAD.encode([11; 32])]);
        assert!(Crypto::parse(&serde_json::to_vec(&duplicate).unwrap()).is_err());
        let crypto = ring("a", &[("a", 11)]);
        let envelope = serde_json::to_value(crypto.seal(&"context", b"code").unwrap()).unwrap();
        for field in ["key_id", "nonce", "ciphertext"] {
            let mut bad = envelope.clone();
            bad.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Envelope>(bad).is_err());
        }
        assert!(
            serde_json::from_value::<Envelope>(json!([
                envelope["key_id"],
                envelope["nonce"],
                envelope["ciphertext"]
            ]))
            .is_err()
        );
        let mut bad = envelope;
        bad["extra"] = json!(true);
        assert!(serde_json::from_value::<Envelope>(bad).is_err());
        assert!(Crypto::load(Path::new("relative-path")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_key_loading_rejects_permissions_links_and_oversized_files() {
        use std::{
            io::Write,
            os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
        };
        let directory =
            std::env::temp_dir().join(format!("proof-custody-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("keys.json");
        let bytes = serde_json::to_vec(&keyfile("a", &[("a", 11)])).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        drop(file);
        assert!(Crypto::load(&path).is_ok());
        assert!(read_private_file(&path, bytes.len() - 1).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(Crypto::load(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.join("symlink");
        symlink(&path, &link).unwrap();
        assert!(Crypto::load(&link).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::hard_link(&path, &link).unwrap();
        assert!(Crypto::load(&path).is_err());
        std::fs::remove_file(&link).unwrap();
        assert!(Crypto::load(&directory).is_err());
        std::fs::write(&path, vec![0; MAX_KEYRING_BYTES as usize + 1]).unwrap();
        assert!(Crypto::load(&path).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
