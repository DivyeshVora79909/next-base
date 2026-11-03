//! One bounded, normalized email intent shared by authorization and dispatch.
use crate::native_slice::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use uuid::Uuid;

pub use crate::credentials::crypto::Provider;
pub const EMAIL_OPERATION: &str = "email-send-1";
pub const MAX_RECIPIENTS: usize = 16;
pub const MAX_SUBJECT_BYTES: usize = 512;
pub const MAX_TEXT_BYTES: usize = 16_384;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SendInput {
    pub email: EmailRequest,
    pub selection: crate::credentials::grants::Selection,
    #[serde(with = "crate::native_codec::optional_decimal")]
    pub execute_at: Option<i64>,
    #[serde(with = "crate::native_codec::optional_decimal")]
    pub not_after: Option<i64>,
}
impl<'de> Deserialize<'de> for SendInput {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Time(#[serde(with = "crate::native_codec::optional_decimal")] Option<i64>);
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = SendInput;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an email send object")
            }
            fn visit_map<A: de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let (mut email, mut selection, mut execute_at, mut not_after) =
                    (None, None, None, None);
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "email" if email.is_none() => email = Some(map.next_value()?),
                        "selection" if selection.is_none() => selection = Some(map.next_value()?),
                        "execute_at" if execute_at.is_none() => {
                            execute_at = Some(map.next_value::<Time>()?.0)
                        }
                        "not_after" if not_after.is_none() => {
                            not_after = Some(map.next_value::<Time>()?.0)
                        }
                        _ => {
                            return Err(de::Error::custom("duplicate or unknown email send field"));
                        }
                    }
                }
                Ok(SendInput {
                    email: email.ok_or_else(|| de::Error::missing_field("email"))?,
                    selection: selection.ok_or_else(|| de::Error::missing_field("selection"))?,
                    execute_at: execute_at.ok_or_else(|| de::Error::missing_field("execute_at"))?,
                    not_after: not_after.ok_or_else(|| de::Error::missing_field("not_after"))?,
                })
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}
impl SendInput {
    pub fn normalized(&self) -> Result<Self> {
        if self.execute_at.is_some_and(|time| time < 0)
            || self.not_after.is_some_and(|time| time < 0)
        {
            return Err(invalid());
        }
        Ok(Self {
            email: self.email.normalized()?,
            ..self.clone()
        })
    }
    pub fn validate(&self) -> Result<()> {
        if &self.normalized()? != self {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn bind(value: Value) -> Result<Self> {
        let input: Self = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
        input.validate()?;
        if serde_json::to_value(&input).map_err(|_| invalid())? != value {
            return Err(invalid());
        }
        Ok(input)
    }
    pub fn schema() -> Value {
        let time = json!({"anyOf":[{"type":"null"},{"type":"string","pattern":"^(0|[1-9][0-9]*)$","x-rebase-range":["0","9223372036854775807"]}]});
        json!({"type":"object","additionalProperties":false,"required":["email","selection","execute_at","not_after"],"properties":{
            "email":EmailRequest::schema(),"selection":crate::credentials::grants::Selection::schema(),"execute_at":time,"not_after":time
        }})
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct EmailOutcome {
    #[serde(with = "crate::native_codec::uuid_text")]
    pub execution_id: Uuid,
    pub provider: Provider,
    pub account: String,
    pub request_hash: String,
    pub disposition: crate::effects::Disposition,
    pub receipt: Option<String>,
}
impl<'de> Deserialize<'de> for EmailOutcome {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Receipt(Option<String>);
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            #[serde(with = "crate::native_codec::uuid_text")]
            execution_id: Uuid,
            provider: Provider,
            account: String,
            request_hash: String,
            disposition: crate::effects::Disposition,
            receipt: Receipt,
        }
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = EmailOutcome;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an email outcome object")
            }
            fn visit_map<A: de::MapAccess<'de>>(
                self,
                map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let fields = Fields::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(EmailOutcome {
                    execution_id: fields.execution_id,
                    provider: fields.provider,
                    account: fields.account,
                    request_hash: fields.request_hash,
                    disposition: fields.disposition,
                    receipt: fields.receipt.0,
                })
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}
impl std::fmt::Debug for EmailOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailOutcome")
            .field("execution_id", &self.execution_id)
            .field("provider", &self.provider)
            .field("disposition", &self.disposition)
            .finish_non_exhaustive()
    }
}
impl EmailOutcome {
    pub fn validate(
        &self,
        request: &EmailRequest,
        execution: Uuid,
    ) -> Result<crate::effects::Disposition> {
        use crate::effects::Disposition;
        crate::credentials::crypto::validate_account(&self.account)?;
        if execution.is_nil()
            || self.execution_id != execution
            || self.request_hash != request.request_hash()?
            || self.receipt.as_ref().is_some_and(|receipt| {
                receipt.is_empty()
                    || receipt.len() > 128
                    || !receipt
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_:-".contains(&b))
            })
            || match self.disposition {
                Disposition::NotAccepted => self.receipt.is_some(),
                _ => self.receipt.is_none(),
            }
        {
            return Err(Error::new(
                "invalid_outcome",
                "email provider result is invalid",
            ));
        }
        Ok(self.disposition)
    }
    pub fn validate_binding(&self, provider: Provider, account: &str) -> Result<()> {
        if self.provider != provider || self.account != account {
            return Err(Error::new(
                "invalid_outcome",
                "email provider binding differs",
            ));
        }
        Ok(())
    }
    pub fn schema() -> Value {
        json!({"type":"object","additionalProperties":false,"required":["execution_id","provider","account","request_hash","disposition","receipt"],"properties":{
            "execution_id":{"type":"string","format":"uuid"},"provider":{"enum":["resend","brevo"]},"account":{"type":"string","pattern":"^[A-Za-z0-9._:-]{1,128}$"},
            "request_hash":{"type":"string","pattern":"^[0-9a-f]{64}$"},"disposition":{"enum":["waiting","succeeded","not_accepted","failed"]},
            "receipt":{"anyOf":[{"type":"null"},{"type":"string","pattern":"^[A-Za-z0-9_:-]{1,128}$"}]}
        }})
    }
}

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
    #[test]
    fn send_input_requires_canonical_complete_object_and_normalized_email() {
        let input = SendInput {
            email: request().normalized().unwrap(),
            selection: crate::credentials::grants::Selection::Byoc {
                credential: Uuid::from_u128(8),
            },
            execute_at: None,
            not_after: None,
        };
        let value = serde_json::to_value(&input).unwrap();
        assert_eq!(SendInput::bind(value.clone()).unwrap(), input);
        for field in ["email", "selection", "execute_at", "not_after"] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(SendInput::bind(missing).is_err());
        }
        for time in [
            json!(0),
            json!("00"),
            json!("-1"),
            json!("9223372036854775808"),
        ] {
            let mut changed = value.clone();
            changed["execute_at"] = time;
            assert!(SendInput::bind(changed).is_err());
        }
        let sequence = json!([input.email, input.selection, null, null]);
        assert!(serde_json::from_value::<SendInput>(sequence).is_err());
        let mut changed = input.clone();
        changed.email = request();
        assert!(changed.validate().is_err());
        assert_eq!(changed.normalized().unwrap(), input);
    }
    #[test]
    fn email_outcomes_bind_provider_account_execution_and_exact_request() {
        let execution = Uuid::from_u128(9);
        let request = request().normalized().unwrap();
        let outcome = EmailOutcome {
            execution_id: execution,
            provider: Provider::Resend,
            account: "test-account".into(),
            request_hash: request.request_hash().unwrap(),
            disposition: crate::effects::Disposition::Succeeded,
            receipt: Some("resend:public-test-receipt".into()),
        };
        assert_eq!(
            outcome.validate(&request, execution).unwrap(),
            crate::effects::Disposition::Succeeded
        );
        assert!(outcome.validate(&request, Uuid::from_u128(10)).is_err());
        assert!(
            outcome
                .validate_binding(Provider::Brevo, "test-account")
                .is_err()
        );
        assert!(
            outcome
                .validate_binding(Provider::Resend, "other-account")
                .is_err()
        );
        let mut changed = request.clone();
        changed.text.push('!');
        assert!(outcome.validate(&changed, execution).is_err());
        for receipt in [None, Some("bad\nreceipt".into()), Some("x".repeat(129))] {
            let mut changed = outcome.clone();
            changed.receipt = receipt;
            assert!(changed.validate(&request, execution).is_err());
        }
        let mut rejected = outcome.clone();
        rejected.disposition = crate::effects::Disposition::NotAccepted;
        assert!(rejected.validate(&request, execution).is_err());
        rejected.receipt = None;
        assert!(rejected.validate(&request, execution).is_ok());
        let mut value = serde_json::to_value(&rejected).unwrap();
        value.as_object_mut().unwrap().remove("receipt");
        assert!(serde_json::from_value::<EmailOutcome>(value).is_err());
        assert!(!format!("{outcome:?}").contains("test-account"));
    }
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
