//! Narrow anonymous inputs and engine-private encrypted delivery metadata.
use super::{
    proof_crypto::{Envelope, object, validate_code, validate_secret},
    types::{Input, Kind},
};
use crate::{
    credentials::crypto::{Provider, validate_account},
    native_slice::{Error, Result},
};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const DELIVERY_FORMAT: &str = "next-base-auth-delivery-1";
pub const POLICY_FORMAT: &str = "next-base-auth-server-policy-1";

fn invalid() -> Error {
    Error::new("invalid_proof", "proof input is not valid")
}

/// Transient request secret. Deliberately has no Serialize implementation.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);
impl Secret {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
impl std::ops::Deref for Secret {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([redacted])")
    }
}
impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

#[derive(Clone)]
pub struct Begin {
    pub operation_id: Uuid,
    pub recovery_secret: Secret,
    pub identifier: Input,
}
impl std::fmt::Debug for Begin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofBegin").finish_non_exhaustive()
    }
}
impl<'de> Deserialize<'de> for Begin {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            #[serde(with = "crate::native_codec::uuid_text")]
            operation_id: Uuid,
            recovery_secret: Secret,
            identifier: Input,
        }
        let fields: Fields = object(deserializer)?;
        let request = Self {
            operation_id: fields.operation_id,
            recovery_secret: fields.recovery_secret,
            identifier: fields
                .identifier
                .normalized()
                .map_err(|_| de::Error::custom(invalid()))?,
        };
        request.validate().map_err(de::Error::custom)?;
        Ok(request)
    }
}
impl Begin {
    pub fn validate(&self) -> Result<()> {
        if self.operation_id.is_nil() {
            return Err(invalid());
        }
        validate_secret(&self.recovery_secret).map_err(|_| invalid())?;
        self.identifier.validate().map_err(|_| invalid())
    }
}

#[derive(Clone)]
pub struct Consume {
    pub operation_id: Uuid,
    pub recovery_secret: Secret,
    pub challenge: Secret,
    pub code: Secret,
}
impl std::fmt::Debug for Consume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofConsume").finish_non_exhaustive()
    }
}
impl<'de> Deserialize<'de> for Consume {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            #[serde(with = "crate::native_codec::uuid_text")]
            operation_id: Uuid,
            recovery_secret: Secret,
            challenge: Secret,
            code: Secret,
        }
        let fields: Fields = object(deserializer)?;
        let request = Self {
            operation_id: fields.operation_id,
            recovery_secret: fields.recovery_secret,
            challenge: fields.challenge,
            code: fields.code,
        };
        request.validate().map_err(de::Error::custom)?;
        Ok(request)
    }
}
impl Consume {
    pub fn validate(&self) -> Result<()> {
        if self.operation_id.is_nil() {
            return Err(invalid());
        }
        validate_secret(&self.recovery_secret).map_err(|_| invalid())?;
        validate_secret(&self.challenge).map_err(|_| invalid())?;
        validate_code(&self.code).map_err(|_| invalid())
    }
}

#[derive(Clone)]
pub struct Status {
    pub operation_id: Uuid,
    pub recovery_secret: Secret,
}
impl std::fmt::Debug for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofStatus").finish_non_exhaustive()
    }
}
impl<'de> Deserialize<'de> for Status {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            #[serde(with = "crate::native_codec::uuid_text")]
            operation_id: Uuid,
            recovery_secret: Secret,
        }
        let fields: Fields = object(deserializer)?;
        let request = Self {
            operation_id: fields.operation_id,
            recovery_secret: fields.recovery_secret,
        };
        request.validate().map_err(de::Error::custom)?;
        Ok(request)
    }
}
impl Status {
    pub fn validate(&self) -> Result<()> {
        if self.operation_id.is_nil() {
            return Err(invalid());
        }
        validate_secret(&self.recovery_secret).map_err(|_| invalid())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct AuthDelivery {
    #[serde(with = "crate::native_codec::uuid_text")]
    pub challenge: Uuid,
    #[serde(with = "crate::native_codec::uuid_text")]
    pub generation: Uuid,
    pub payload: Envelope,
    #[serde(with = "crate::native_codec::decimal")]
    pub expires_at: i64,
}
impl std::fmt::Debug for AuthDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthDelivery").finish_non_exhaustive()
    }
}
impl<'de> Deserialize<'de> for AuthDelivery {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            #[serde(with = "crate::native_codec::uuid_text")]
            challenge: Uuid,
            #[serde(with = "crate::native_codec::uuid_text")]
            generation: Uuid,
            payload: Envelope,
            #[serde(with = "crate::native_codec::decimal")]
            expires_at: i64,
        }
        let fields: Fields = object(deserializer)?;
        let delivery = Self {
            challenge: fields.challenge,
            generation: fields.generation,
            payload: fields.payload,
            expires_at: fields.expires_at,
        };
        delivery.validate().map_err(de::Error::custom)?;
        Ok(delivery)
    }
}
impl AuthDelivery {
    pub fn validate(&self) -> Result<()> {
        if self.challenge.is_nil() || self.generation.is_nil() || self.expires_at < 0 {
            return Err(invalid());
        }
        self.payload.validate()
    }
    pub fn bind(value: Value) -> Result<Self> {
        serde_json::from_value(value).map_err(|_| invalid())
    }
    pub fn schema() -> Value {
        json!({"type":"object","additionalProperties":false,"required":["challenge","generation","payload","expires_at"],"properties":{
            "challenge":{"type":"string","format":"uuid"},"generation":{"type":"string","format":"uuid"},
            "payload":Envelope::schema(),
            "expires_at":{"type":"string","pattern":"^(0|[1-9][0-9]*)$","x-rebase-range":["0","9223372036854775807"]}
        }})
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ServerPolicy {
    pub kind: Kind,
    #[serde(with = "crate::native_codec::uuid_text")]
    pub revision: Uuid,
    #[serde(with = "crate::native_codec::uuid_text")]
    pub credential: Uuid,
    #[serde(with = "crate::native_codec::uuid_text")]
    pub owner: Uuid,
    pub provider: Provider,
    pub account: String,
    pub sender: Option<String>,
}
impl std::fmt::Debug for ServerPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthServerPolicy")
            .field("kind", &self.kind)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}
impl<'de> Deserialize<'de> for ServerPolicy {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Sender(Option<String>);
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            kind: Kind,
            #[serde(with = "crate::native_codec::uuid_text")]
            revision: Uuid,
            #[serde(with = "crate::native_codec::uuid_text")]
            credential: Uuid,
            #[serde(with = "crate::native_codec::uuid_text")]
            owner: Uuid,
            provider: Provider,
            account: String,
            sender: Sender,
        }
        let fields: Fields = object(deserializer)?;
        let policy = Self {
            kind: fields.kind,
            revision: fields.revision,
            credential: fields.credential,
            owner: fields.owner,
            provider: fields.provider,
            account: fields.account,
            sender: fields.sender.0,
        };
        policy.validate().map_err(de::Error::custom)?;
        Ok(policy)
    }
}
impl ServerPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.revision.is_nil() || self.credential.is_nil() || self.owner.is_nil() {
            return Err(invalid());
        }
        validate_account(&self.account).map_err(|_| invalid())?;
        match (self.kind, self.provider, self.sender.as_deref()) {
            (Kind::Email, Provider::Resend | Provider::Brevo, Some(sender))
                if crate::email::normalize_address(sender).is_ok_and(|value| value == sender) =>
            {
                Ok(())
            }
            (Kind::Phone, Provider::FakeSms, None) => Ok(()),
            _ => Err(invalid()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::proof_crypto::Crypto;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    fn operation() -> Uuid {
        Uuid::from_u128(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)
    }
    fn recovery() -> String {
        URL_SAFE_NO_PAD.encode([7u8; 32])
    }
    fn handle() -> String {
        URL_SAFE_NO_PAD.encode([9u8; 32])
    }
    fn begin() -> Value {
        json!({"operation_id":operation(),"recovery_secret":recovery(),"identifier":{"kind":"email","value":" Alice@EXAMPLE.COM "}})
    }
    fn consume() -> Value {
        json!({"operation_id":operation(),"recovery_secret":recovery(),"challenge":handle(),"code":"000042"})
    }

    #[test]
    fn anonymous_inputs_normalize_identifiers_keep_exact_code_and_redact_debug() {
        let begin_request: Begin = serde_json::from_value(begin()).unwrap();
        assert_eq!(begin_request.identifier.value, "alice@example.com");
        let consume: Consume = serde_json::from_value(consume()).unwrap();
        assert_eq!(consume.code.as_str(), "000042");
        assert_eq!(consume.challenge.as_str(), handle());
        let status: Status = serde_json::from_value(
            json!({"operation_id":operation(),"recovery_secret":recovery()}),
        )
        .unwrap();
        for output in [
            format!("{begin_request:?}"),
            format!("{consume:?}"),
            format!("{status:?}"),
            format!("{:?}", consume.code),
        ] {
            for secret in ["000042", "alice@example.com", &recovery(), &handle()] {
                assert!(!output.contains(secret));
            }
        }
        let mut phone = begin();
        phone["identifier"] = json!({"kind":"phone","value":" +123456789 "});
        assert_eq!(
            serde_json::from_value::<Begin>(phone)
                .unwrap()
                .identifier
                .value,
            "+123456789"
        );
    }

    #[test]
    fn anonymous_inputs_reject_redirects_unknown_missing_array_and_noncanonical_fields() {
        for field in [
            "tenant",
            "identity",
            "recipient",
            "provider",
            "claims",
            "expires_at",
        ] {
            let mut bad = begin();
            bad[field] = json!("forged");
            assert!(serde_json::from_value::<Begin>(bad).is_err());
        }
        for field in ["operation_id", "recovery_secret", "identifier"] {
            let mut bad = begin();
            bad.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Begin>(bad).is_err());
        }
        for field in ["operation_id", "recovery_secret", "challenge", "code"] {
            let mut bad = consume();
            bad.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Consume>(bad).is_err());
        }
        for bad_code in [
            json!(42),
            json!("00042"),
            json!(" 000042"),
            json!("000042\n"),
            json!("００００４２"),
        ] {
            let mut bad = consume();
            bad["code"] = bad_code;
            assert!(serde_json::from_value::<Consume>(bad).is_err());
        }
        for bad_uuid in [
            Uuid::nil().to_string(),
            operation().to_string().to_ascii_uppercase(),
            operation().simple().to_string(),
        ] {
            let mut bad = begin();
            bad["operation_id"] = json!(bad_uuid);
            assert!(serde_json::from_value::<Begin>(bad).is_err());
        }
        for field in ["recovery_secret", "challenge"] {
            let mut bad = consume();
            bad[field] = json!(format!("{}=", recovery()));
            assert!(serde_json::from_value::<Consume>(bad).is_err());
        }
        assert!(
            serde_json::from_value::<Begin>(
                json!([operation(),recovery(),{"kind":"email","value":"a@example.com"}])
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<Consume>(json!([operation(), recovery(), handle(), "000042"]))
                .is_err()
        );
        assert!(serde_json::from_value::<Status>(json!([operation(), recovery()])).is_err());
        assert!(serde_json::from_value::<Status>(json!({"operation_id":operation()})).is_err());
        assert!(
            serde_json::from_value::<Status>(
                json!({"operation_id":operation(),"recovery_secret":recovery(),"code":"000042"})
            )
            .is_err()
        );
        let duplicate = format!(
            "{{\"operation_id\":\"{}\",\"recovery_secret\":\"{}\",\"recovery_secret\":\"{}\"}}",
            operation(),
            recovery(),
            recovery()
        );
        assert!(serde_json::from_str::<Status>(&duplicate).is_err());
    }

    fn delivery() -> AuthDelivery {
        AuthDelivery {
            challenge: Uuid::from_u128(1),
            generation: Uuid::from_u128(2),
            payload: Crypto::test_key("proof", [11; 32])
                .seal(&"delivery-binding", b"000042")
                .unwrap(),
            expires_at: 300,
        }
    }
    #[test]
    fn delivery_is_ciphertext_only_with_exact_stored_field_shapes() {
        let delivery = delivery();
        let value = serde_json::to_value(&delivery).unwrap();
        assert_eq!(value["expires_at"], "300");
        assert_eq!(
            serde_json::from_value::<AuthDelivery>(value.clone()).unwrap(),
            delivery
        );
        assert!(
            jsonschema::validator_for(&AuthDelivery::schema())
                .unwrap()
                .is_valid(&value)
        );
        assert!(!serde_json::to_string(&delivery).unwrap().contains("000042"));
        assert!(!format!("{delivery:?}").contains(&delivery.payload.ciphertext));
        for field in ["challenge", "generation", "payload", "expires_at"] {
            let mut bad = value.clone();
            bad.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<AuthDelivery>(bad).is_err());
        }
        for invalid in [
            json!(300),
            json!("0300"),
            json!("-1"),
            json!("9223372036854775808"),
        ] {
            let mut bad = value.clone();
            bad["expires_at"] = invalid;
            assert!(serde_json::from_value::<AuthDelivery>(bad).is_err());
        }
        let mut bad = value.clone();
        bad["code"] = json!("000042");
        assert!(serde_json::from_value::<AuthDelivery>(bad).is_err());
        assert!(
            serde_json::from_value::<AuthDelivery>(json!([
                value["challenge"],
                value["generation"],
                value["payload"],
                value["expires_at"]
            ]))
            .is_err()
        );
    }

    fn email_policy() -> Value {
        json!({"kind":"email","revision":operation(),"credential":Uuid::from_u128(2),"owner":Uuid::from_u128(3),"provider":"resend","account":"auth-test","sender":"noreply@example.com"})
    }
    #[test]
    fn server_policy_requires_exact_channel_provider_sender_and_explicit_binding() {
        let email = email_policy();
        for provider in ["resend", "brevo"] {
            let mut valid = email.clone();
            valid["provider"] = json!(provider);
            serde_json::from_value::<ServerPolicy>(valid)
                .unwrap()
                .validate()
                .unwrap();
        }
        let mut phone = email.clone();
        phone["kind"] = json!("phone");
        phone["provider"] = json!("fake_sms");
        phone["sender"] = Value::Null;
        let policy: ServerPolicy = serde_json::from_value(phone.clone()).unwrap();
        assert_eq!(serde_json::to_value(policy).unwrap(), phone);
        for field in [
            "kind",
            "revision",
            "credential",
            "owner",
            "provider",
            "account",
            "sender",
        ] {
            let mut bad = phone.clone();
            bad.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<ServerPolicy>(bad).is_err());
        }
        for (field, value) in [
            ("provider", json!("fake_sms")),
            ("sender", Value::Null),
            ("sender", json!("noreply@EXAMPLE.COM")),
            ("sender", json!("Name <noreply@example.com>")),
            ("revision", json!(1)),
            ("revision", json!(Uuid::nil())),
            ("credential", json!(Uuid::nil())),
            ("owner", json!(Uuid::nil())),
            ("account", json!("https://untrusted.example")),
        ] {
            let mut bad = email.clone();
            bad[field] = value;
            assert!(serde_json::from_value::<ServerPolicy>(bad).is_err());
        }
        phone["sender"] = json!("noreply@example.com");
        assert!(serde_json::from_value::<ServerPolicy>(phone).is_err());
        assert!(
            serde_json::from_value::<ServerPolicy>(json!([
                email["kind"],
                email["revision"],
                email["credential"],
                email["owner"],
                email["provider"],
                email["account"],
                email["sender"]
            ]))
            .is_err()
        );
    }
}
