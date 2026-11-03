//! One strict point-key/value codec for the bounded native experiment.

use crate::binding::{Binding, Calculation, NativeInput};
use crate::index::NativeIndex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    native_slice::{Error, Meta, ModelRecord, Query, Result},
    order_value::AccessOrder,
    tree::{Node, Root},
};

pub const CODEC: &str = "native-slice-kv-15";

pub mod decimal {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    use std::{fmt::Display, str::FromStr};

    pub fn serialize<T: Display, S: Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: FromStr + Display,
        T::Err: Display,
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        let value = text.parse::<T>().map_err(D::Error::custom)?;
        if text != value.to_string() {
            return Err(D::Error::custom("noncanonical decimal string"));
        }
        Ok(value)
    }
}

pub mod optional_decimal {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    use std::{fmt::Display, str::FromStr};

    pub fn serialize<T: Display, S: Serializer>(
        value: &Option<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.serialize_some(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        T: FromStr + Display,
        T::Err: Display,
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|text| {
                let value = text.parse::<T>().map_err(D::Error::custom)?;
                if text != value.to_string() {
                    return Err(D::Error::custom("noncanonical decimal string"));
                }
                Ok(value)
            })
            .transpose()
    }
}

pub mod uuid_text {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    use uuid::Uuid;

    pub fn serialize<S: Serializer>(value: &Uuid, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Uuid, D::Error> {
        let text = String::deserialize(deserializer)?;
        let value = Uuid::parse_str(&text).map_err(D::Error::custom)?;
        if text != value.to_string() {
            return Err(D::Error::custom("noncanonical UUID"));
        }
        Ok(value)
    }
}

pub mod optional_uuid_text {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    use uuid::Uuid;

    pub fn serialize<S: Serializer>(
        value: &Option<Uuid>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.serialize_some(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Uuid>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| {
                let value = Uuid::parse_str(&text).map_err(D::Error::custom)?;
                if text != value.to_string() {
                    return Err(D::Error::custom("noncanonical UUID"));
                }
                Ok(value)
            })
            .transpose()
    }

    /// An omitted field may default, but a present field must name a UUID.
    pub fn deserialize_present<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Uuid>, D::Error> {
        super::uuid_text::deserialize(deserializer).map(Some)
    }
}

pub mod summary {
    use super::{decimal, optional_decimal};
    use crate::algebra::Summary;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        count: u64,
        #[serde(with = "optional_decimal")]
        first: Option<i64>,
        #[serde(with = "optional_decimal")]
        last: Option<i64>,
        #[serde(with = "decimal")]
        sum: i128,
        #[serde(with = "decimal")]
        min_prefix: i128,
        #[serde(with = "decimal")]
        max_prefix: i128,
        #[serde(with = "optional_decimal")]
        boundary_min: Option<i128>,
        #[serde(with = "optional_decimal")]
        boundary_max: Option<i128>,
    }

    pub fn serialize<S: Serializer>(s: &Summary, serializer: S) -> Result<S::Ok, S::Error> {
        Wire {
            count: s.count,
            first: s.first,
            last: s.last,
            sum: s.sum,
            min_prefix: s.min_prefix,
            max_prefix: s.max_prefix,
            boundary_min: s.boundary_min,
            boundary_max: s.boundary_max,
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Summary, D::Error> {
        let w = Wire::deserialize(deserializer)?;
        Ok(Summary {
            count: w.count,
            first: w.first,
            last: w.last,
            sum: w.sum,
            min_prefix: w.min_prefix,
            max_prefix: w.max_prefix,
            boundary_min: w.boundary_min,
            boundary_max: w.boundary_max,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Address {
    #[serde(with = "uuid_text")]
    pub id: Uuid,
    pub slot: u16,
}

impl Address {
    pub fn new(id: Uuid, slot: u16) -> Self {
        Self { id, slot }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Key {
    Unique {
        contract: u16,
        constraint: u16,
        targets: Vec<Uuid>,
    },
    Meta,
    Record(Uuid),
    Root(Address),
    Node(Address),
    AccessRoot(Address),
    AccessNode(Address),
    CredentialSecret(Uuid, u64),
    Query(Address),
    Incoming(Uuid),
    Direct(Uuid),
    Subscribers(Address),
    Role(Address),
    Reserved(Uuid),
    IncomingNode(Address),
    DirectNode(Address),
    SubscriberNode(Address),
}

impl Key {
    pub fn encode(&self) -> Vec<u8> {
        let (tag, id, slot) = match self {
            Self::Unique {
                contract,
                constraint,
                targets,
            } => {
                let mut bytes = vec![14];
                bytes.extend_from_slice(&contract.to_be_bytes());
                bytes.extend_from_slice(&constraint.to_be_bytes());
                // Invalid in-memory keys are rejected by value validation.
                bytes.extend_from_slice(&(targets.len() as u16).to_be_bytes());
                for target in targets {
                    bytes.extend_from_slice(target.as_bytes());
                }
                return bytes;
            }
            Self::Meta => return vec![0],
            Self::Record(id) => (1, *id, None),
            Self::Root(a) => (2, a.id, Some(a.slot)),
            Self::Node(a) => (3, a.id, Some(a.slot)),
            Self::AccessRoot(a) => (15, a.id, Some(a.slot)),
            Self::AccessNode(a) => (16, a.id, Some(a.slot)),
            Self::CredentialSecret(id, revision) => {
                let mut bytes = vec![17];
                bytes.extend_from_slice(id.as_bytes());
                bytes.extend_from_slice(&revision.to_be_bytes());
                return bytes;
            }
            Self::Query(a) => (4, a.id, Some(a.slot)),
            Self::Incoming(id) => (5, *id, None),
            Self::Direct(id) => (6, *id, None),
            Self::Subscribers(a) => (7, a.id, Some(a.slot)),
            Self::Role(a) => (8, a.id, Some(a.slot)),
            Self::Reserved(id) => (9, *id, None),
            Self::IncomingNode(a) => (10, a.id, Some(a.slot)),
            Self::DirectNode(a) => (11, a.id, Some(a.slot)),
            Self::SubscriberNode(a) => (12, a.id, Some(a.slot)),
        };
        let mut bytes = vec![tag];
        bytes.extend_from_slice(id.as_bytes());
        if let Some(slot) = slot {
            bytes.extend_from_slice(&slot.to_be_bytes());
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let bad = || Error::new("corrupt_state", "invalid point key");
        if bytes == [0] {
            return Ok(Self::Meta);
        }
        let tag = *bytes.first().ok_or_else(bad)?;
        if tag == 14 {
            if bytes.len() < 7 {
                return Err(bad());
            }
            let contract = u16::from_be_bytes([bytes[1], bytes[2]]);
            let constraint = u16::from_be_bytes([bytes[3], bytes[4]]);
            let count = u16::from_be_bytes([bytes[5], bytes[6]]) as usize;
            if contract == 0 || constraint == 0 || count == 0 || bytes.len() != 7 + count * 16 {
                return Err(bad());
            }
            let targets = bytes[7..]
                .chunks_exact(16)
                .map(|part| Uuid::from_slice(part).map_err(|_| bad()))
                .collect::<Result<Vec<_>>>()?;
            return Ok(Self::Unique {
                contract,
                constraint,
                targets,
            });
        }
        let length = match tag {
            1 | 5 | 6 | 9 => 17,
            17 => 25,
            2..=4 | 7 | 8 | 10..=12 | 15 | 16 => 19,
            _ => return Err(bad()),
        };
        if bytes.len() != length {
            return Err(bad());
        }
        let id = Uuid::from_slice(&bytes[1..17]).map_err(|_| bad())?;
        let slot = if length == 19 {
            u16::from_be_bytes([bytes[17], bytes[18]])
        } else {
            0
        };
        if length == 19 && slot == 0 {
            return Err(bad());
        }
        let a = Address::new(id, slot);
        Ok(match tag {
            1 => Self::Record(id),
            2 => Self::Root(a),
            3 => Self::Node(a),
            15 => Self::AccessRoot(a),
            16 => Self::AccessNode(a),
            17 => {
                let revision = u64::from_be_bytes(bytes[17..25].try_into().map_err(|_| bad())?);
                if revision == 0 {
                    return Err(bad());
                }
                Self::CredentialSecret(id, revision)
            }
            4 => Self::Query(a),
            5 => Self::Incoming(id),
            6 => Self::Direct(id),
            7 => Self::Subscribers(a),
            8 => Self::Role(a),
            9 => Self::Reserved(id),
            10 => Self::IncomingNode(a),
            11 => Self::DirectNode(a),
            12 => Self::SubscriberNode(a),
            _ => return Err(bad()),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[serde(bound(
    serialize = "B::Input: Serialize, B::Derived: Serialize",
    deserialize = "B::Input: serde::de::DeserializeOwned, B::Derived: serde::de::DeserializeOwned"
))]
pub enum StoredValue<B: Binding> {
    Unique(#[serde(with = "uuid_text")] Uuid),
    Meta(Meta),
    Record(ModelRecord<B>),
    Root(Root<B::Index>),
    Node(Node<B::Index>),
    AccessRoot(Root<AccessOrder>),
    AccessNode(Node<AccessOrder>),
    CredentialSecret(crate::credentials::crypto::SecretEnvelope),
    Query(Query<B::Index>),
    Incoming(crate::routes::Header),
    Direct(crate::routes::Header),
    Subscribers(crate::routes::Header),
    RouteNode(crate::routes::Node<<B::Index as NativeIndex>::Key>),
    Role(Role),
    Reserved(Address),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Role {
    #[serde(with = "uuid_text")]
    pub output: Uuid,
    pub retired: bool,
    /// First materialization of the permanently reserved output UUID.
    #[serde(with = "optional_decimal")]
    pub first_created_at: Option<i64>,
}

pub type Stored = StoredValue<Calculation>;

pub fn encode(key: &Key, value: &Stored) -> Result<Vec<u8>> {
    encode_for::<Calculation>(key, value)
}
pub fn decode(key: &Key, bytes: &[u8]) -> Result<Stored> {
    decode_for::<Calculation>(key, bytes)
}

pub fn encode_for<B: Binding>(key: &Key, value: &StoredValue<B>) -> Result<Vec<u8>> {
    validate(key, value)?;
    serde_json::to_vec(value).map_err(|e| Error::new("codec", e.to_string()))
}

pub fn decode_for<B: Binding>(key: &Key, bytes: &[u8]) -> Result<StoredValue<B>> {
    let value =
        serde_json::from_slice(bytes).map_err(|e| Error::new("corrupt_state", e.to_string()))?;
    if encode_for::<B>(key, &value)? != bytes {
        return Err(Error::new("corrupt_state", "noncanonical value bytes"));
    }
    Ok(value)
}

fn valid_root<I: NativeIndex>(a: &Address, r: &Root<I>) -> bool {
    a.slot > 0
        && !r.revision.is_nil()
        && I::validate_summary(r.kind, &r.summary).is_ok()
        && r.height < 64
        && r.head.is_none() == (r.height == 0)
        && r.head.is_none() == (r.size == 0)
        && r.head.is_none() == r.first.is_none()
        && r.head.is_none() == r.last.is_none()
        && r.head.is_none() == r.span.is_none()
        && r.head
            .into_iter()
            .chain(r.first)
            .chain(r.last)
            .all(|a| a.slot > 0)
        && r.span.as_ref().is_none_or(|span| {
            span.first <= span.last
                && I::validate_key(r.kind, &span.first).is_ok()
                && I::validate_key(r.kind, &span.last).is_ok()
        })
        && (r.head.is_some() || I::empty(r.kind).is_ok_and(|empty| empty == r.summary))
}

fn valid_node<I: NativeIndex>(a: &Address, n: &Node<I>) -> bool {
    a.slot > 0
        && n.root.slot > 0
        && n.key.id == a.id
        && n.key.slot == a.slot
        && I::validate_key(n.kind, &n.key.value).is_ok()
        && I::validate_leaf(n.kind, &n.leaf).is_ok()
        && I::validate_summary(n.kind, &n.summary).is_ok()
        && n.size > 0
        && n.height > 0
        && n.height < 64
        && n.span.first <= n.key.value
        && n.key.value <= n.span.last
        && I::validate_key(n.kind, &n.span.first).is_ok()
        && I::validate_key(n.kind, &n.span.last).is_ok()
        && [n.parent, n.left, n.right, n.prev, n.next]
            .into_iter()
            .flatten()
            .all(|id| id.slot > 0 && id != *a)
        && (n.left.is_none() || n.left != n.right)
}

fn validate<B: Binding>(key: &Key, value: &StoredValue<B>) -> Result<()> {
    let valid = match (key, value) {
        (
            Key::Unique {
                contract,
                constraint,
                targets,
            },
            StoredValue::Unique(_),
        ) => {
            *contract > 0
                && *constraint > 0
                && !targets.is_empty()
                && targets.len() <= u16::MAX as usize
        }
        (Key::Meta, StoredValue::Meta(meta)) => !meta.codec.is_empty() && !meta.model.is_empty(),
        (Key::Record(_), StoredValue::Record(r)) => {
            r.contract > 0
                && !r.version.is_nil()
                && r.contract == r.input.contract()
                && r.input.validate().is_ok()
                && r.input.managed().is_none_or(|(_, role)| role > 0)
                && B::valid_derived(&r.input, r.derived.as_ref())
        }
        (Key::Root(a), StoredValue::Root(r)) => valid_root(a, r),
        (Key::Node(a), StoredValue::Node(n)) => valid_node(a, n),
        (Key::AccessRoot(a), StoredValue::AccessRoot(r)) => valid_root(a, r),
        (Key::AccessNode(a), StoredValue::AccessNode(n)) => valid_node(a, n),
        (Key::CredentialSecret(id, revision), StoredValue::CredentialSecret(secret)) => {
            B::credential_enabled()
                && secret.credential == *id
                && secret.secret_revision == *revision
                && secret.validate().is_ok()
        }
        (Key::Query(a), StoredValue::Query(q)) => {
            a.slot > 0 && q.source.slot > 0 && B::Index::validate_query(q).is_ok()
        }
        (Key::Incoming(_), StoredValue::Incoming(h))
        | (Key::Direct(_), StoredValue::Direct(h))
        | (Key::Subscribers(_), StoredValue::Subscribers(h)) => {
            h.head.is_none() == h.is_empty()
                && h.head.is_none_or(|a| a.slot > 0)
                && h.bounded <= h.len
                && (matches!(key, Key::Subscribers(_)) || h.bounded == 0)
        }
        (
            Key::IncomingNode(a) | Key::DirectNode(a) | Key::SubscriberNode(a),
            StoredValue::RouteNode(n),
        ) => {
            use crate::routes::{Endpoint, Route};
            a.slot > 0
                && n.key.member == *a
                && n.key.endpoint == crate::routes::endpoint(&n.range)
                && n.route.node_key(*a) == *key
                && n.height > 0
                && n.height < 64
                && n.left.is_none_or(|v| v.slot > 0 && v != *a)
                && n.right.is_none_or(|v| v.slot > 0 && v != *a)
                && (n.left.is_none() || n.left != n.right)
                && match n.route {
                    Route::Subscribers(root) => root.slot > 0,
                    _ => {
                        n.key.endpoint == Endpoint::All
                            && n.range == crate::native_range::NativeRange::ALL
                    }
                }
                && (n.range.is_empty()
                    || n.min_lower
                        .as_ref()
                        .is_some_and(|bound| bound.lower_cut() <= n.range.lower.lower_cut()))
        }
        (Key::Role(a), StoredValue::Role(role)) => {
            a.slot > 0 && role.first_created_at.is_none_or(|at| at >= 0)
        }
        (Key::Reserved(_), StoredValue::Reserved(a)) => a.slot > 0,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::new("corrupt_state", "key/value role mismatch"))
    }
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| {
            [
                char::from(DIGITS[usize::from(b >> 4)]),
                char::from(DIGITS[usize::from(b & 15)]),
            ]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_secret_keys_have_explicit_revision_bytes_and_reject_legacy_shape() {
        let credential = Uuid::from_u128(0x0102030405060708090a0b0c0d0e0f10);
        let key = Key::CredentialSecret(credential, 0x0102030405060708);
        assert_eq!(
            key.encode(),
            vec![
                17, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8
            ]
        );
        assert_eq!(Key::decode(&key.encode()).unwrap(), key);
        assert!(Key::decode(&key.encode()[..17]).is_err());
        assert!(Key::decode(&Key::CredentialSecret(credential, 0).encode()).is_err());
        assert!(
            Key::CredentialSecret(credential, 255).encode()
                < Key::CredentialSecret(credential, 256).encode()
        );
    }
    #[test]
    fn access_namespaces_are_distinct_and_enforce_native_tree_shapes() {
        use crate::order_value::{ORDER_INDEX, OrderAtom, OrderKey};
        use crate::tree::{FullKey, Span};
        let root = Address::new(Uuid::from_u128(1), 7);
        let member = Address::new(Uuid::from_u128(2), 7);
        for (key, tag) in [(Key::AccessRoot(root), 15), (Key::AccessNode(member), 16)] {
            let bytes = key.encode();
            assert_eq!(bytes[0], tag);
            assert_eq!(Key::decode(&bytes).unwrap(), key);
            let mut zero_slot = bytes;
            zero_slot[17..].fill(0);
            assert!(Key::decode(&zero_slot).is_err());
        }
        let value = OrderKey::new(vec![OrderAtom::Integer(10)]).unwrap();
        let node = Node::<AccessOrder> {
            kind: ORDER_INDEX,
            root,
            key: FullKey {
                value: value.clone(),
                id: member.id,
                slot: member.slot,
            },
            leaf: (),
            parent: None,
            left: None,
            right: None,
            prev: None,
            next: None,
            height: 1,
            size: 1,
            span: Span {
                first: value.clone(),
                last: value,
            },
            summary: (),
        };
        let stored = Stored::AccessNode(node.clone());
        let bytes = encode(&Key::AccessNode(member), &stored).unwrap();
        assert_eq!(decode(&Key::AccessNode(member), &bytes).unwrap(), stored);
        assert!(encode(&Key::Node(member), &stored).is_err());
        assert!(decode(&Key::Node(member), &bytes).is_err());
        let mut invalid = node;
        invalid.size = 0;
        assert!(encode(&Key::AccessNode(member), &Stored::AccessNode(invalid)).is_err());
        let header = Stored::AccessRoot(
            Root::<AccessOrder>::empty(ORDER_INDEX, Uuid::from_u128(3)).unwrap(),
        );
        assert!(encode(&Key::AccessRoot(root), &header).is_ok());
        assert!(encode(&Key::Root(root), &header).is_err());
    }

    #[test]
    fn removed_population_tag_is_unknown() {
        for bytes in [vec![13], vec![13; 17], vec![13; 19]] {
            assert_eq!(Key::decode(&bytes).unwrap_err().code, "corrupt_state");
        }
    }
}
