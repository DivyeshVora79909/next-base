//! Bounded exact tuple keys for explicitly declared owner access indexes.
//!
//! A prepared access declaration fixes the kind of every tuple component. The
//! enum order only makes native values total; it does not admit mixed kinds in
//! one declared component or define tuple-prefix request semantics.

use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    index::{IndexCode, IndexDescriptor, NativeIndex, SummaryRead},
    native_codec::{decimal, uuid_text},
    native_slice::{Error, Result},
};

pub const ORDER_MAX_COMPONENTS: usize = 8;
pub const ORDER_MAX_TEXT_BYTES: usize = 256;
pub const ORDER_MAX_ENCODED_BYTES: usize = 4096;
pub const ORDER_INDEX: IndexCode = IndexCode::new(1).expect("nonzero index code");

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderAtomKind {
    Integer,
    Text,
    Boolean,
    Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum OrderAtom {
    Integer(#[serde(with = "decimal")] i128),
    Text(String),
    Boolean(bool),
    Uuid(#[serde(with = "uuid_text")] Uuid),
}

impl OrderAtom {
    pub fn kind(&self) -> OrderAtomKind {
        match self {
            Self::Integer(_) => OrderAtomKind::Integer,
            Self::Text(_) => OrderAtomKind::Text,
            Self::Boolean(_) => OrderAtomKind::Boolean,
            Self::Uuid(_) => OrderAtomKind::Uuid,
        }
    }

    /// Project a validated native input using its declared component kind.
    /// Native bindings use both JSON integers and canonical decimal strings;
    /// neither floating numbers nor noncanonical decimal text is accepted.
    /// This projection does not loosen the tagged public key wire format.
    pub fn from_json(kind: OrderAtomKind, value: &Value) -> Result<Self> {
        match kind {
            OrderAtomKind::Integer => {
                let integer = if let Some(text) = value.as_str() {
                    let integer = text
                        .parse::<i128>()
                        .map_err(|_| invalid("integer component is outside exact i128 range"))?;
                    if integer.to_string() != text {
                        return Err(invalid("integer component must be canonical decimal text"));
                    }
                    integer
                } else if let Some(integer) = value.as_i64() {
                    i128::from(integer)
                } else if let Some(integer) = value.as_u64() {
                    i128::from(integer)
                } else {
                    return Err(invalid("integer component requires exact integer input"));
                };
                Ok(Self::Integer(integer))
            }
            OrderAtomKind::Text => {
                let text = value
                    .as_str()
                    .ok_or_else(|| invalid("text component requires string input"))?;
                if text.len() > ORDER_MAX_TEXT_BYTES {
                    return Err(invalid("text component exceeds UTF-8 byte bound"));
                }
                Ok(Self::Text(text.to_owned()))
            }
            OrderAtomKind::Boolean => value
                .as_bool()
                .map(Self::Boolean)
                .ok_or_else(|| invalid("boolean component requires boolean input")),
            OrderAtomKind::Uuid => {
                let text = value
                    .as_str()
                    .ok_or_else(|| invalid("UUID component requires canonical string input"))?;
                let uuid = Uuid::parse_str(text)
                    .map_err(|_| invalid("UUID component requires canonical string input"))?;
                if uuid.to_string() != text {
                    return Err(invalid("UUID component requires canonical string input"));
                }
                Ok(Self::Uuid(uuid))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct OrderKey(pub Vec<OrderAtom>);

impl<'de> Deserialize<'de> for OrderKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let key = Self(Vec::<OrderAtom>::deserialize(deserializer)?);
        key.validate().map_err(de::Error::custom)?;
        Ok(key)
    }
}

impl OrderKey {
    pub fn new(components: Vec<OrderAtom>) -> Result<Self> {
        let key = Self(components);
        key.validate()?;
        Ok(key)
    }

    pub fn validate(&self) -> Result<()> {
        if self.0.is_empty() || self.0.len() > ORDER_MAX_COMPONENTS {
            return Err(invalid(
                "order key requires between one and eight components",
            ));
        }
        if self.0.iter().any(
            |component| matches!(component, OrderAtom::Text(text) if text.len() > ORDER_MAX_TEXT_BYTES),
        ) {
            return Err(invalid("text component exceeds UTF-8 byte bound"));
        }
        let encoded = serde_json::to_vec(self)
            .map_err(|error| invalid(format!("cannot encode order key: {error}")))?;
        if encoded.len() > ORDER_MAX_ENCODED_BYTES {
            return Err(invalid("order key exceeds canonical JSON byte bound"));
        }
        Ok(())
    }

    pub fn schema() -> Value {
        let variants = [
            (
                "integer",
                json!({
                    "type":"string", "pattern":"^(0|-?[1-9][0-9]*)$",
                    "x-rebase-binding":"i128",
                    "x-rebase-range":[i128::MIN.to_string(),i128::MAX.to_string()]
                }),
            ),
            (
                "text",
                json!({
                    "type":"string", "maxLength":ORDER_MAX_TEXT_BYTES,
                    "x-rebase-max-utf8-bytes":ORDER_MAX_TEXT_BYTES
                }),
            ),
            ("boolean", json!({"type":"boolean"})),
            (
                "uuid",
                json!({
                    "type":"string",
                    "pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
                }),
            ),
        ]
        .into_iter()
        .map(|(kind, value)| {
            json!({
                "type":"object", "properties":{"kind":{"const":kind},"value":value},
                "required":["kind","value"], "additionalProperties":false
            })
        })
        .collect::<Vec<_>>();
        json!({
            "type":"array", "minItems":1, "maxItems":ORDER_MAX_COMPONENTS,
            "items":{"oneOf":variants},
            "x-rebase-max-encoded-bytes":ORDER_MAX_ENCODED_BYTES
        })
    }
}

fn invalid(detail: impl Into<String>) -> Error {
    Error::new("invalid_order_key", detail)
}

/// Access memberships carry no business aggregate. The tree's structural size
/// counts occurrences independently from this unit summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessOrder;

fn validate_code(code: IndexCode) -> Result<()> {
    if code == ORDER_INDEX {
        Ok(())
    } else {
        Err(Error::new(
            "corrupt_state",
            "unknown access-order index code",
        ))
    }
}

impl NativeIndex for AccessOrder {
    type Key = OrderKey;
    type Leaf = ();
    type Summary = ();
    type QueryResult = ();

    fn descriptors() -> Vec<IndexDescriptor> {
        vec![IndexDescriptor {
            code: ORDER_INDEX,
            name: "access_order",
            reads: vec!["summary"],
            key_schema: OrderKey::schema(),
            leaf_schema: json!({"type":"null"}),
            summary_schema: json!({"type":"null"}),
            result_schemas: json!({"summary":{"type":"null"}}),
            time: false,
            financial: false,
            quote: false,
        }]
    }

    fn validate_key(code: IndexCode, key: &OrderKey) -> Result<()> {
        validate_code(code)?;
        key.validate()
    }

    fn validate_leaf(code: IndexCode, _leaf: &()) -> Result<()> {
        validate_code(code)
    }

    fn validate_summary(code: IndexCode, _summary: &()) -> Result<()> {
        validate_code(code)
    }

    fn empty(code: IndexCode) -> Result<()> {
        validate_code(code)
    }

    fn singleton(code: IndexCode, key: &OrderKey, leaf: &()) -> Result<()> {
        Self::validate_key(code, key)?;
        Self::validate_leaf(code, leaf)
    }

    fn combine(code: IndexCode, left: &(), right: &()) -> Result<()> {
        Self::validate_summary(code, left)?;
        Self::validate_summary(code, right)
    }

    fn project(code: IndexCode, read: SummaryRead, summary: &()) -> Result<Value> {
        Self::validate_summary(code, summary)?;
        if read == SummaryRead::Summary {
            Ok(Value::Null)
        } else {
            Err(Error::new(
                "unsupported_query",
                "access-order summary read required",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(number: i128, text: &str) -> OrderKey {
        OrderKey::new(vec![
            OrderAtom::Integer(number),
            OrderAtom::Text(text.into()),
        ])
        .unwrap()
    }

    #[test]
    fn native_numeric_and_tuple_order_matches_source_oracle() {
        let source = [
            (10, "a"),
            (-1, "z"),
            (2, "z"),
            (2, "a"),
            (i128::MIN, ""),
            (i128::MAX, ""),
        ];
        let mut expected = source.to_vec();
        expected.sort_unstable();
        let mut actual = source.map(|(number, text)| key(number, text));
        actual.sort_unstable();
        assert_eq!(
            actual.to_vec(),
            expected
                .into_iter()
                .map(|(n, t)| key(n, t))
                .collect::<Vec<_>>()
        );
        for value in actual {
            let wire = serde_json::to_vec(&value).unwrap();
            assert_eq!(serde_json::from_slice::<OrderKey>(&wire).unwrap(), value);
        }
        assert!(key(2, "z") < key(10, "a"));
        assert!(OrderAtom::Boolean(false) < OrderAtom::Boolean(true));
        assert!(OrderAtom::Uuid(Uuid::from_u128(1)) < OrderAtom::Uuid(Uuid::from_u128(2)));
    }

    #[test]
    fn exact_declared_input_projection_is_distinct_from_wire() {
        for value in [json!(2), json!("2")] {
            assert_eq!(
                OrderAtom::from_json(OrderAtomKind::Integer, &value).unwrap(),
                OrderAtom::Integer(2)
            );
        }
        assert_eq!(
            OrderAtom::from_json(OrderAtomKind::Integer, &json!(u64::MAX)).unwrap(),
            OrderAtom::Integer(i128::from(u64::MAX))
        );
        for value in [
            json!(2.0),
            json!(2.5),
            json!("+2"),
            json!("02"),
            json!("-0"),
            json!("2.0"),
            json!(true),
            Value::Null,
        ] {
            assert!(
                OrderAtom::from_json(OrderAtomKind::Integer, &value).is_err(),
                "{value}"
            );
        }
        assert!(serde_json::from_value::<OrderAtom>(json!({"kind":"integer","value":2})).is_err());
        assert_eq!(
            OrderAtom::from_json(OrderAtomKind::Text, &json!("2")).unwrap(),
            OrderAtom::Text("2".into())
        );
        assert!(OrderAtom::from_json(OrderAtomKind::Text, &json!(2)).is_err());
        assert!(OrderAtom::from_json(OrderAtomKind::Boolean, &json!("true")).is_err());
        assert_eq!(
            OrderAtom::from_json(OrderAtomKind::Boolean, &json!(true))
                .unwrap()
                .kind(),
            OrderAtomKind::Boolean
        );
    }

    #[test]
    fn strict_wire_rejects_noncanonical_and_unknown_values() {
        for wire in [
            r#"[{"kind":"integer","value":"01"}]"#,
            r#"[{"kind":"integer","value":"-0"}]"#,
            r#"[{"kind":"integer","value":"170141183460469231731687303715884105728"}]"#,
            r#"[{"kind":"integer","value":"1","extra":0}]"#,
            r#"[{"kind":"integer","value":"1","value":"2"}]"#,
            r#"[{"kind":"number","value":"1"}]"#,
            r#"[{"kind":"uuid","value":"AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"}]"#,
            r#"[{"kind":"uuid","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]"#,
            r#"[{"kind":"text","value":null}]"#,
            r#"[]"#,
        ] {
            assert!(serde_json::from_str::<OrderKey>(wire).is_err(), "{wire}");
        }
        let text = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        assert_eq!(
            OrderAtom::from_json(OrderAtomKind::Uuid, &json!(text))
                .unwrap()
                .kind(),
            OrderAtomKind::Uuid
        );
        assert!(OrderAtom::from_json(OrderAtomKind::Uuid, &json!(text.to_uppercase())).is_err());
    }

    #[test]
    fn utf8_and_encoded_byte_bounds_are_independent() {
        assert!(OrderKey::new(vec![OrderAtom::Text("é".repeat(128))]).is_ok());
        assert!(OrderKey::new(vec![OrderAtom::Text("é".repeat(129))]).is_err());
        assert!(OrderKey::new(vec![OrderAtom::Boolean(false); ORDER_MAX_COMPONENTS]).is_ok());
        assert!(OrderKey::new(vec![OrderAtom::Boolean(false); ORDER_MAX_COMPONENTS + 1]).is_err());
        // Each NUL is one source UTF-8 byte and six escaped JSON bytes.
        let escaped = OrderKey(vec![OrderAtom::Text("\0".repeat(256)); 8]);
        assert!(escaped.validate().is_err());
        assert!(
            serde_json::from_value::<OrderKey>(serde_json::to_value(escaped).unwrap()).is_err()
        );
        let exact = OrderKey(vec![OrderAtom::Text("a".repeat(256)); 8]);
        assert!(exact.validate().is_ok());
        assert_eq!(OrderKey::schema()["maxItems"], 8);
    }

    #[test]
    fn access_family_has_only_unit_business_summary() {
        let descriptor = AccessOrder::descriptor(ORDER_INDEX).unwrap();
        assert_eq!(descriptor.key_schema, OrderKey::schema());
        assert_eq!(descriptor.reads, ["summary"]);
        assert_eq!(
            AccessOrder::project(ORDER_INDEX, SummaryRead::Summary, &()).unwrap(),
            Value::Null
        );
        assert!(AccessOrder::project(ORDER_INDEX, SummaryRead::Range, &()).is_err());
        assert!(AccessOrder::validate_key(ORDER_INDEX, &OrderKey(vec![])).is_err());
        assert!(AccessOrder::empty(IndexCode::new(2).unwrap()).is_err());
        AccessOrder::combine(ORDER_INDEX, &(), &()).unwrap();
    }
}
