//! Canonical identity input and protected lifetime/proof state.
use crate::native_slice::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Value, json};
use std::marker::PhantomData;
use uuid::Uuid;

pub const POLICY: &str = "identity-ascii-email-phone-user-owner-recent-self-1";

fn invalid() -> Error {
    Error::new("invalid_identity", "identity input or state is not valid")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Email,
    Phone,
}

impl<'de> Deserialize<'de> for Kind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        match String::deserialize(deserializer)?.as_str() {
            "email" => Ok(Self::Email),
            "phone" => Ok(Self::Phone),
            _ => Err(de::Error::custom("email or phone identity kind required")),
        }
    }
}

impl Kind {
    pub fn tag(self) -> u8 {
        match self {
            Self::Email => 1,
            Self::Phone => 2,
        }
    }

    pub fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Email),
            2 => Ok(Self::Phone),
            _ => Err(invalid()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Input {
    pub kind: Kind,
    pub value: String,
}

impl<'de> Deserialize<'de> for Input {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            kind: Kind,
            value: String,
        }
        let fields: Fields = object(deserializer)?;
        Ok(Self {
            kind: fields.kind,
            value: fields.value,
        })
    }
}

impl Input {
    pub fn normalized(&self) -> Result<Self> {
        let value = match self.kind {
            Kind::Email => crate::email::normalize_address(&self.value)
                .map_err(|_| invalid())?
                .to_ascii_lowercase(),
            Kind::Phone => {
                let value = self.value.trim_matches(' ');
                let digits = value.strip_prefix('+').ok_or_else(invalid)?;
                if !(8..=15).contains(&digits.len())
                    || !digits.as_bytes()[0].is_ascii_digit()
                    || digits.as_bytes()[0] == b'0'
                    || !digits.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(invalid());
                }
                value.to_owned()
            }
        };
        Ok(Self {
            kind: self.kind,
            value,
        })
    }

    /// Persisted values must already be canonical. Input binding normalizes once.
    pub fn validate(&self) -> Result<()> {
        if self.normalized()? != *self {
            return Err(invalid());
        }
        Ok(())
    }

    pub fn bind(value: Value) -> Result<Self> {
        serde_json::from_value::<Self>(value)
            .map_err(|_| invalid())?
            .normalized()
    }

    pub fn schema() -> Value {
        json!({"type":"object","additionalProperties":false,"required":["kind","value"],"properties":{
            "kind":{"enum":["email","phone"]},
            "value":{"type":"string","minLength":1,"maxLength":254,"x-maxUtf8Bytes":254}
        },"allOf":[{"if":{"properties":{"kind":{"const":"phone"}}},"then":{"properties":{
            "value":{"maxLength":16,"pattern":"^\\+[1-9][0-9]{7,14}$"}
        }}}]})
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct State {
    #[serde(with = "crate::native_codec::uuid_text")]
    pub incarnation: Uuid,
    #[serde(with = "crate::native_codec::decimal")]
    pub identity_revision: u64,
    #[serde(with = "crate::native_codec::optional_decimal")]
    pub verified_revision: Option<u64>,
    #[serde(with = "crate::native_codec::optional_decimal")]
    pub verified_at: Option<i64>,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityState")
            .field("identity_revision", &self.identity_revision)
            .field("verified_revision", &self.verified_revision)
            .field("verified_at", &self.verified_at)
            .finish_non_exhaustive()
    }
}

impl<'de> Deserialize<'de> for State {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Revision(#[serde(with = "crate::native_codec::optional_decimal")] Option<u64>);
        #[derive(Deserialize)]
        struct Time(#[serde(with = "crate::native_codec::optional_decimal")] Option<i64>);
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            #[serde(with = "crate::native_codec::uuid_text")]
            incarnation: Uuid,
            #[serde(with = "crate::native_codec::decimal")]
            identity_revision: u64,
            verified_revision: Revision,
            verified_at: Time,
        }
        let fields: Fields = object(deserializer)?;
        let state = Self {
            incarnation: fields.incarnation,
            identity_revision: fields.identity_revision,
            verified_revision: fields.verified_revision.0,
            verified_at: fields.verified_at.0,
        };
        state.validate().map_err(de::Error::custom)?;
        Ok(state)
    }
}

impl State {
    pub fn new(incarnation: Uuid) -> Result<Self> {
        let state = Self {
            incarnation,
            identity_revision: 1,
            verified_revision: None,
            verified_at: None,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> Result<()> {
        if self.incarnation.is_nil()
            || self.identity_revision == 0
            || !matches!(
                (self.verified_revision, self.verified_at),
                (None, None) | (Some(_), Some(0..))
            )
            || self
                .verified_revision
                .is_some_and(|revision| revision != self.identity_revision)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Claim {
    #[serde(with = "crate::native_codec::uuid_text")]
    pub identity: Uuid,
    #[serde(with = "crate::native_codec::uuid_text")]
    pub incarnation: Uuid,
}

impl std::fmt::Debug for Claim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityClaim").finish_non_exhaustive()
    }
}

impl<'de> Deserialize<'de> for Claim {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            #[serde(with = "crate::native_codec::uuid_text")]
            identity: Uuid,
            #[serde(with = "crate::native_codec::uuid_text")]
            incarnation: Uuid,
        }
        let fields: Fields = object(deserializer)?;
        let claim = Self {
            identity: fields.identity,
            incarnation: fields.incarnation,
        };
        claim.validate().map_err(de::Error::custom)?;
        Ok(claim)
    }
}

impl Claim {
    pub fn validate(&self) -> Result<()> {
        if self.identity.is_nil() || self.incarnation.is_nil() {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuthenticationRevision {
    #[serde(with = "crate::native_codec::decimal")]
    pub revision: u64,
}

impl<'de> Deserialize<'de> for AuthenticationRevision {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            #[serde(with = "crate::native_codec::decimal")]
            revision: u64,
        }
        let fields: Fields = object(deserializer)?;
        let revision = Self {
            revision: fields.revision,
        };
        revision.validate().map_err(de::Error::custom)?;
        Ok(revision)
    }
}

impl AuthenticationRevision {
    pub fn validate(&self) -> Result<()> {
        if self.revision == 0 {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Struct-derived deserializers also accept sequences; stored DTOs require objects.
fn object<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<T, D::Error> {
    struct Object<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> de::Visitor<'de> for Object<T> {
        type Value = T;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an identity object")
        }

        fn visit_map<A: de::MapAccess<'de>>(
            self,
            map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            T::deserialize(de::value::MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(Object(PhantomData))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bind(kind: Kind, value: &str) -> Result<Input> {
        Input::bind(json!({"kind":kind,"value":value}))
    }

    #[test]
    fn email_normalization_is_whole_address_and_idempotent() {
        for value in ["Alice+News@EXAMPLE.COM", " alice+news@example.com "] {
            let input = bind(Kind::Email, value).unwrap();
            assert_eq!(input.value, "alice+news@example.com");
            assert_eq!(input.normalized().unwrap(), input);
            input.validate().unwrap();
        }
        assert_eq!(
            crate::email::normalize_address("Alice@EXAMPLE.COM").unwrap(),
            "Alice@example.com",
            "message intent keeps its distinct local-part case contract"
        );
        assert!(
            Input {
                kind: Kind::Email,
                value: "Alice@example.com".into()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn email_boundaries_and_literal_malformed_mailboxes() {
        let address = format!(
            "{}@{}.{}.{}",
            "a".repeat(64),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(address.len(), 254);
        assert!(bind(Kind::Email, &address).is_ok());
        assert!(bind(Kind::Email, &(address + "d")).is_err());
        assert!(bind(Kind::Email, &format!("{}@example.com", "a".repeat(65))).is_err());
        for value in [
            "",
            " ",
            "Alice <alice@example.com>",
            "a@example.com,b@example.com",
            "a(comment)@example.com",
            "a..b@example.com",
            ".a@example.com",
            "a.@example.com",
            "a@example..com",
            "a@-example.com",
            "a@example-.com",
            "a@example.com@evil.test",
            " a@example.com\t",
            "\na@example.com",
            "a\0@example.com",
            "é@example.com",
            "a@éxample.com",
            "\u{a0}a@example.com",
        ] {
            assert!(bind(Kind::Email, value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn phone_exact_e164_length_boundaries_and_no_country_guess() {
        for value in ["+12345678", "+123456789012345", " +919876543210 "] {
            let input = bind(Kind::Phone, value).unwrap();
            assert_eq!(input.value, value.trim_matches(' '));
            input.validate().unwrap();
        }
        for value in [
            "+1234567",
            "+1234567890123456",
            "+012345678",
            "1234567890",
            "+1 23456789",
            "+1-23456789",
            "+123456789x1",
            "+１２３４５６７８",
            "\t+123456789",
            "+123456789\r",
            "\u{a0}+123456789",
            "",
            "+",
        ] {
            assert!(bind(Kind::Phone, value).is_err(), "{value:?}");
        }
        assert!(
            Input {
                kind: Kind::Phone,
                value: " +12345678 ".into()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn input_wire_rejects_forged_fields_duplicates_missing_values_and_sequences() {
        for text in [
            r#"["email","a@example.com"]"#,
            r#"{"kind":"email"}"#,
            r#"{"kind":"email","value":null}"#,
            r#"{"kind":"Email","value":"a@example.com"}"#,
            r#"{"kind":{"email":null},"value":"a@example.com"}"#,
            r#"{"kind":"email","value":"a@example.com","verified_revision":"1"}"#,
            r#"{"kind":"email","kind":"phone","value":"a@example.com"}"#,
            r#"{"kind":"email","value":"a@example.com","value":"b@example.com"}"#,
        ] {
            assert!(serde_json::from_str::<Input>(text).is_err(), "{text}");
        }
    }

    #[test]
    fn protected_state_requires_current_revision_and_complete_verification_pair() {
        let initial = State::new(Uuid::from_u128(1)).unwrap();
        assert_eq!(initial.identity_revision, 1);
        assert_eq!(initial.verified_revision, None);
        assert_eq!(initial.verified_at, None);
        assert!(State::new(Uuid::nil()).is_err());
        for (revision, verified, at, valid) in [
            (0, None, None, false),
            (1, None, None, true),
            (1, Some(1), Some(0), true),
            (u64::MAX, Some(u64::MAX), Some(i64::MAX), true),
            (2, Some(1), Some(0), false),
            (1, Some(2), Some(0), false),
            (1, Some(1), None, false),
            (1, None, Some(0), false),
            (1, Some(1), Some(-1), false),
        ] {
            let state = State {
                identity_revision: revision,
                verified_revision: verified,
                verified_at: at,
                ..initial.clone()
            };
            assert_eq!(state.validate().is_ok(), valid);
            assert_eq!(
                serde_json::from_value::<State>(serde_json::to_value(state).unwrap()).is_ok(),
                valid
            );
        }
        assert!(!format!("{initial:?}").contains(&initial.incarnation.to_string()));
    }

    #[test]
    fn protected_state_wire_rejects_noncanonical_or_missing_fields() {
        let initial = serde_json::to_value(State::new(Uuid::from_u128(1)).unwrap()).unwrap();
        for field in [
            "incarnation",
            "identity_revision",
            "verified_revision",
            "verified_at",
        ] {
            let mut value = initial.clone();
            value.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<State>(value).is_err(), "{field}");
        }
        for revision in [
            json!(1),
            json!("01"),
            json!("+1"),
            json!("18446744073709551616"),
        ] {
            let mut value = initial.clone();
            value["identity_revision"] = revision;
            assert!(serde_json::from_value::<State>(value).is_err());
        }
        for value in [
            json!([initial["incarnation"], "1", null, null]),
            json!({"incarnation":"00000000000000000000000000000001","identity_revision":"1","verified_revision":null,"verified_at":null}),
            json!({"incarnation":initial["incarnation"],"identity_revision":"1","verified_revision":"1","verified_at":"-0"}),
            json!({"incarnation":initial["incarnation"],"identity_revision":"1","verified_revision":null,"verified_at":null,"extra":true}),
        ] {
            assert!(serde_json::from_value::<State>(value).is_err());
        }
        let duplicate = format!(
            "{{\"incarnation\":\"{}\",\"identity_revision\":\"1\",\"identity_revision\":\"2\",\"verified_revision\":null,\"verified_at\":null}}",
            Uuid::from_u128(1)
        );
        assert!(serde_json::from_str::<State>(&duplicate).is_err());
    }

    #[test]
    fn claim_and_authentication_revision_are_strict_private_objects() {
        let claim = Claim {
            identity: Uuid::from_u128(1),
            incarnation: Uuid::from_u128(2),
        };
        assert_eq!(
            serde_json::from_value::<Claim>(serde_json::to_value(&claim).unwrap()).unwrap(),
            claim
        );
        for value in [
            json!([claim.identity, claim.incarnation]),
            json!({"identity":claim.identity}),
            json!({"identity":claim.identity,"incarnation":Uuid::nil()}),
            json!({"identity":Uuid::nil(),"incarnation":claim.incarnation}),
            json!({"identity":claim.identity,"incarnation":claim.incarnation,"owner":claim.identity}),
        ] {
            assert!(serde_json::from_value::<Claim>(value).is_err());
        }
        for value in [
            json!({"revision":"0"}),
            json!({"revision":1}),
            json!({"revision":"01"}),
            json!({"revision":"1","extra":true}),
            json!(["1"]),
            json!({}),
        ] {
            assert!(serde_json::from_value::<AuthenticationRevision>(value).is_err());
        }
        assert!(
            serde_json::from_str::<AuthenticationRevision>(r#"{"revision":"1","revision":"2"}"#)
                .is_err()
        );
        assert_eq!(
            serde_json::from_value::<AuthenticationRevision>(
                json!({"revision":u64::MAX.to_string()})
            )
            .unwrap()
            .revision,
            u64::MAX
        );
    }

    #[test]
    fn kind_key_tags_and_order_are_explicit() {
        assert!(Kind::Email < Kind::Phone);
        assert_eq!(Kind::Email.tag(), 1);
        assert_eq!(Kind::Phone.tag(), 2);
        for tag in 0..=u8::MAX {
            match tag {
                1 => assert_eq!(Kind::from_tag(tag).unwrap(), Kind::Email),
                2 => assert_eq!(Kind::from_tag(tag).unwrap(), Kind::Phone),
                _ => assert!(Kind::from_tag(tag).is_err()),
            }
        }
    }
}
