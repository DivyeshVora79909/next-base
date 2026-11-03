//! One bounded, normalized email intent shared by authorization and dispatch.
use crate::native_slice::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub use crate::credentials::crypto::Provider;
pub const EMAIL_OPERATION: &str = "email-send-1";
pub const MAX_RECIPIENTS: usize = 16;
pub const MAX_SUBJECT_BYTES: usize = 512;
pub const MAX_TEXT_BYTES: usize = 16_384;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Purpose {
    #[serde(rename = "email.send")]
    EmailSend,
}
impl Purpose {
    pub fn as_str(self) -> &'static str {
        "email.send"
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct EmailRequest {
    pub sender: String,
    pub to: Vec<String>,
    pub subject: String,
    pub text: String,
}
impl std::fmt::Debug for EmailRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EmailRequest(<redacted>)")
    }
}
impl<'de> Deserialize<'de> for EmailRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = EmailRequest;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an email request object")
            }
            fn visit_map<A: de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let (mut sender, mut to, mut subject, mut text) = (None, None, None, None);
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "sender" if sender.is_none() => sender = Some(map.next_value()?),
                        "to" if to.is_none() => to = Some(map.next_value()?),
                        "subject" if subject.is_none() => subject = Some(map.next_value()?),
                        "text" if text.is_none() => text = Some(map.next_value()?),
                        "sender" | "to" | "subject" | "text" => {
                            return Err(de::Error::custom("duplicate email request field"));
                        }
                        _ => return Err(de::Error::custom("unknown email request field")),
                    }
                }
                Ok(EmailRequest {
                    sender: sender.ok_or_else(|| de::Error::missing_field("sender"))?,
                    to: to.ok_or_else(|| de::Error::missing_field("to"))?,
                    subject: subject.ok_or_else(|| de::Error::missing_field("subject"))?,
                    text: text.ok_or_else(|| de::Error::missing_field("text"))?,
                })
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

fn invalid() -> Error {
    Error::new("invalid_email", "email request is not valid")
}

/// ASCII dot-atom mailboxes only; this is syntax, not deliverability checking.
/// Local-part case is retained. Only outer ASCII spaces and domain case normalize.
pub fn normalize_address(value: &str) -> Result<String> {
    if value.bytes().any(|b| b.is_ascii_control()) {
        return Err(invalid());
    }
    let value = value.trim_matches(' ');
    if value.is_empty() || value.len() > 254 || !value.is_ascii() {
        return Err(invalid());
    }
    let (local, domain) = value.split_once('@').ok_or_else(invalid)?;
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || local
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&b)))
        || domain.is_empty()
        || domain.len() > 253
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || label
                    .bytes()
                    .any(|b| !(b.is_ascii_alphanumeric() || b == b'-'))
        })
    {
        return Err(invalid());
    }
    Ok(format!("{local}@{}", domain.to_ascii_lowercase()))
}
impl EmailRequest {
    pub fn normalized(&self) -> Result<Self> {
        if !(1..=MAX_RECIPIENTS).contains(&self.to.len())
            || self.subject.len() > MAX_SUBJECT_BYTES
            || self.text.len() > MAX_TEXT_BYTES
            || self.subject.bytes().any(|b| b.is_ascii_control())
        {
            return Err(invalid());
        }
        let sender = normalize_address(&self.sender)?;
        let to = self
            .to
            .iter()
            .map(|value| normalize_address(value))
            .collect::<Result<Vec<_>>>()?;
        if to.iter().collect::<BTreeSet<_>>().len() != to.len() {
            return Err(invalid());
        }
        Ok(Self {
            sender,
            to,
            subject: self.subject.clone(),
            text: self.text.clone(),
        })
    }
    pub fn request_hash(&self) -> Result<String> {
        let normalized = self.normalized()?;
        let bytes = serde_json::to_vec(&normalized).map_err(|_| invalid())?;
        let mut hash = Sha256::new();
        hash.update(b"next-base/email-send/1\0");
        hash.update(bytes);
        Ok(crate::native_codec::hex(&hash.finalize()))
    }
    pub fn schema() -> Value {
        json!({"type":"object","additionalProperties":false,"required":["sender","to","subject","text"],"properties":{
            "sender":{"type":"string","maxLength":254},
            "to":{"type":"array","minItems":1,"maxItems":MAX_RECIPIENTS,"uniqueItems":true,"items":{"type":"string","maxLength":254}},
            "subject":{"type":"string","maxLength":MAX_SUBJECT_BYTES,"x-maxUtf8Bytes":MAX_SUBJECT_BYTES},
            "text":{"type":"string","maxLength":MAX_TEXT_BYTES,"x-maxUtf8Bytes":MAX_TEXT_BYTES}
        }})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> EmailRequest {
        EmailRequest {
            sender: " Sender@EXAMPLE.COM ".into(),
            to: vec![" Receiver@Example.NET ".into()],
            subject: "subject".into(),
            text: "body\nsecond line".into(),
        }
    }
    #[test]
    fn normalization_is_idempotent_and_hash_binds_exact_intent() {
        let normalized = request().normalized().unwrap();
        assert_eq!(normalized.sender, "Sender@example.com");
        assert_eq!(normalized.to, ["Receiver@example.net"]);
        assert_eq!(normalized.normalized().unwrap(), normalized);
        assert_eq!(
            request().request_hash().unwrap(),
            normalized.request_hash().unwrap()
        );
        for field in 0..4 {
            let mut changed = normalized.clone();
            match field {
                0 => changed.sender = "Other@example.com".into(),
                1 => changed.to[0] = "Other@example.net".into(),
                2 => changed.subject.push('!'),
                _ => changed.text.push('!'),
            }
            assert_ne!(
                changed.request_hash().unwrap(),
                normalized.request_hash().unwrap()
            );
        }
        assert!(!format!("{normalized:?}").contains("body"));
    }
    #[test]
    fn bounds_count_utf8_bytes_and_reject_header_syntax() {
        let mut value = request();
        value.subject = "é".repeat(256);
        assert!(value.normalized().is_ok());
        value.subject.push('é');
        assert!(value.normalized().is_err());
        value = request();
        value.text = "é".repeat(8192);
        assert!(value.normalized().is_ok());
        value.text.push('é');
        assert!(value.normalized().is_err());
        for address in [
            "a@b\r\nCc:c@d",
            "a@b\t",
            "a b@example.com",
            "A <a@example.com>",
            "a..b@example.com",
            "a@-example.com",
            "a@example..com",
            "a@example.com@evil.test",
        ] {
            assert!(normalize_address(address).is_err());
        }
        value = request();
        value.to = vec!["a@EXAMPLE.COM".into(), "a@example.com".into()];
        assert!(value.normalized().is_err());
        value.to = (0..16).map(|i| format!("u{i}@example.com")).collect();
        assert!(value.normalized().is_ok());
        value.to.push("extra@example.com".into());
        assert!(value.normalized().is_err());
        value = request();
        value.subject = "subject\r\nX-Header: value".into();
        assert!(value.normalized().is_err());
    }
    #[test]
    fn request_wire_has_no_headers_endpoints_or_sequence_alias() {
        for value in [
            json!(["a@b", ["c@d"], "s", "t"]),
            json!({"sender":"a@b","to":["c@d"],"subject":"s","text":"t","headers":{}}),
            json!({"sender":"a@b","to":["c@d"],"subject":"s","text":"t","endpoint":"https://example.com"}),
        ] {
            assert!(serde_json::from_value::<EmailRequest>(value).is_err());
        }
        assert!(
            serde_json::from_str::<EmailRequest>(
                r#"{"sender":"a@b","sender":"x@y","to":["c@d"],"subject":"s","text":"t"}"#
            )
            .is_err()
        );
    }
}
