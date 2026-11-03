//! Family-native complete-key bounds shared by queries and reverse routes.
//! Bounds exclude/include entire equal-key groups, before occurrence UUID ties.
use crate::{
    index::{KeyRange, TimeKey},
    time_range::{TimeBound, TimeRange},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::ops::Bound;

/// Optional facts about gaps in a key's admitted domain. Unknown gaps remain
/// conservatively nonempty; membership is always decided by exact comparisons.
pub trait RangeKey: Ord + Clone {
    fn minimum() -> Option<Self> {
        None
    }
    fn maximum() -> Option<Self> {
        None
    }
    fn adjacent(_lower: &Self, _upper: &Self) -> bool {
        false
    }
}
impl RangeKey for String {}
impl RangeKey for crate::order_value::OrderKey {}
impl RangeKey for TimeKey {
    fn minimum() -> Option<Self> {
        Some(Self(i64::MIN))
    }
    fn maximum() -> Option<Self> {
        Some(Self(i64::MAX))
    }
    fn adjacent(lower: &Self, upper: &Self) -> bool {
        lower.0 < upper.0 && lower.0.abs_diff(upper.0) == 1
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NativeBound<K> {
    #[default]
    Unbounded,
    Included(K),
    Excluded(K),
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FiniteBound<K> {
    Included(K),
    Excluded(K),
}
impl<K: Serialize> Serialize for NativeBound<K> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Unbounded => None,
            Self::Included(key) => Some(FiniteBound::Included(key)),
            Self::Excluded(key) => Some(FiniteBound::Excluded(key)),
        }
        .serialize(serializer)
    }
}
impl<'de, K: Deserialize<'de>> Deserialize<'de> for NativeBound<K> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match Option::<FiniteBound<K>>::deserialize(deserializer)? {
            None => Self::Unbounded,
            Some(FiniteBound::Included(key)) => Self::Included(key),
            Some(FiniteBound::Excluded(key)) => Self::Excluded(key),
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Side {
    Before,
    After,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Cut<'a, K> {
    NegativeInfinity,
    Key(&'a K, Side),
    PositiveInfinity,
}
impl<K> NativeBound<K> {
    pub(crate) fn lower_cut(&self) -> Cut<'_, K> {
        match self {
            Self::Unbounded => Cut::NegativeInfinity,
            Self::Included(k) => Cut::Key(k, Side::Before),
            Self::Excluded(k) => Cut::Key(k, Side::After),
        }
    }
    pub(crate) fn upper_cut(&self) -> Cut<'_, K> {
        match self {
            Self::Unbounded => Cut::PositiveInfinity,
            Self::Included(k) => Cut::Key(k, Side::After),
            Self::Excluded(k) => Cut::Key(k, Side::Before),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct NativeRange<K> {
    pub lower: NativeBound<K>,
    pub upper: NativeBound<K>,
}
impl<'de, K: Deserialize<'de>> Deserialize<'de> for NativeRange<K> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RangeVisitor<K>(std::marker::PhantomData<fn() -> K>);
        impl<'de, K: Deserialize<'de>> de::Visitor<'de> for RangeVisitor<K> {
            type Value = NativeRange<K>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object with lower and upper native bounds")
            }

            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let (mut lower, mut upper) = (None, None);
                while let Some(key) = map.next_key::<String>()? {
                    let field = match key.as_str() {
                        "lower" => &mut lower,
                        "upper" => &mut upper,
                        _ => return Err(de::Error::unknown_field(&key, &["lower", "upper"])),
                    };
                    if field.is_some() {
                        return Err(de::Error::custom(format!("duplicate field {key}")));
                    }
                    *field = Some(map.next_value::<NativeBound<K>>()?);
                }
                Ok(NativeRange {
                    lower: lower.ok_or_else(|| de::Error::missing_field("lower"))?,
                    upper: upper.ok_or_else(|| de::Error::missing_field("upper"))?,
                })
            }
        }
        deserializer.deserialize_map(RangeVisitor(std::marker::PhantomData))
    }
}
impl<K> Default for NativeRange<K> {
    fn default() -> Self {
        Self::ALL
    }
}
impl<K> NativeRange<K> {
    pub const ALL: Self = Self {
        lower: NativeBound::Unbounded,
        upper: NativeBound::Unbounded,
    };
    pub fn before(key: K) -> Self {
        Self {
            lower: NativeBound::Unbounded,
            upper: NativeBound::Excluded(key),
        }
    }
    pub fn through(key: K) -> Self {
        Self {
            lower: NativeBound::Unbounded,
            upper: NativeBound::Included(key),
        }
    }
}
impl<K: RangeKey> NativeRange<K> {
    pub fn contains(&self, key: &K) -> bool {
        let lower = match &self.lower {
            NativeBound::Unbounded => true,
            NativeBound::Included(v) => v <= key,
            NativeBound::Excluded(v) => v < key,
        };
        let upper = match &self.upper {
            NativeBound::Unbounded => true,
            NativeBound::Included(v) => key <= v,
            NativeBound::Excluded(v) => key < v,
        };
        lower && upper
    }
    pub fn is_empty(&self) -> bool {
        use NativeBound::*;
        if let Excluded(lower) = &self.lower
            && K::maximum().as_ref() == Some(lower)
        {
            return true;
        }
        if let Excluded(upper) = &self.upper
            && K::minimum().as_ref() == Some(upper)
        {
            return true;
        }
        match (&self.lower, &self.upper) {
            (Unbounded, _) | (_, Unbounded) => false,
            (Included(a), Included(b)) => a > b,
            (Excluded(a), Excluded(b)) => a >= b || K::adjacent(a, b),
            (Included(a), Excluded(b)) | (Excluded(a), Included(b)) => a >= b,
        }
    }
    pub fn key_range(&self) -> KeyRange<K> {
        let bound = |b: &NativeBound<K>| match b {
            NativeBound::Unbounded => Bound::Unbounded,
            NativeBound::Included(v) => Bound::Included(v.clone()),
            NativeBound::Excluded(v) => Bound::Excluded(v.clone()),
        };
        KeyRange {
            lower: bound(&self.lower),
            upper: bound(&self.upper),
        }
    }
}
impl From<TimeBound> for NativeBound<TimeKey> {
    fn from(bound: TimeBound) -> Self {
        match bound {
            TimeBound::Unbounded => Self::Unbounded,
            TimeBound::Included(v) => Self::Included(TimeKey(v)),
            TimeBound::Excluded(v) => Self::Excluded(TimeKey(v)),
        }
    }
}
impl From<NativeBound<TimeKey>> for TimeBound {
    fn from(bound: NativeBound<TimeKey>) -> Self {
        match bound {
            NativeBound::Unbounded => Self::Unbounded,
            NativeBound::Included(v) => Self::Included(v.0),
            NativeBound::Excluded(v) => Self::Excluded(v.0),
        }
    }
}
impl From<NativeRange<TimeKey>> for TimeRange {
    fn from(range: NativeRange<TimeKey>) -> Self {
        Self {
            lower: range.lower.into(),
            upper: range.upper.into(),
        }
    }
}
impl From<TimeRange> for NativeRange<TimeKey> {
    fn from(range: TimeRange) -> Self {
        let bound = |b| match b {
            TimeBound::Unbounded => NativeBound::Unbounded,
            TimeBound::Included(v) => NativeBound::Included(TimeKey(v)),
            TimeBound::Excluded(v) => NativeBound::Excluded(TimeKey(v)),
        };
        Self {
            lower: bound(range.lower),
            upper: bound(range.upper),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::order_value::{OrderAtom, OrderKey};
    use serde_json::json;
    #[test]
    fn temporal_adapter_keeps_extreme_discrete_empty_and_wire_semantics() {
        let mut bounds = vec![TimeBound::Unbounded];
        for at in [i64::MIN, -1, 0, 1, i64::MAX] {
            bounds.extend([TimeBound::Included(at), TimeBound::Excluded(at)]);
        }
        for &lower in &bounds {
            for &upper in &bounds {
                let time = TimeRange { lower, upper };
                let native = NativeRange::<TimeKey>::from(time);
                assert_eq!(native.is_empty(), time.is_empty());
                assert_eq!(
                    serde_json::to_value(native).unwrap(),
                    serde_json::to_value(time).unwrap()
                );
            }
        }
    }
    #[test]
    fn string_and_tuple_windows_use_native_order_and_whole_equal_groups() {
        let words = NativeRange {
            lower: NativeBound::Excluded("alpha".to_owned()),
            upper: NativeBound::Included("gamma".to_owned()),
        };
        for (word, expected) in [
            ("alpha", false),
            ("beta", true),
            ("gamma", true),
            ("omega", false),
        ] {
            assert_eq!(words.contains(&word.to_owned()), expected);
        }
        let key = |n, s: &str| {
            OrderKey::new(vec![OrderAtom::Integer(n), OrderAtom::Text(s.into())]).unwrap()
        };
        let range = NativeRange {
            lower: NativeBound::Included(key(2, "b")),
            upper: NativeBound::Excluded(key(10, "a")),
        };
        for (n, s, expected) in [
            (2, "a", false),
            (2, "b", true),
            (2, "z", true),
            (3, "a", true),
            (10, "a", false),
        ] {
            assert_eq!(range.contains(&key(n, s)), expected);
        }
        assert!(!range.is_empty());
        let wire = serde_json::to_value(&range).unwrap();
        assert_eq!(
            serde_json::from_value::<NativeRange<OrderKey>>(wire).unwrap(),
            range
        );
    }
    #[test]
    fn strict_native_bounds_reject_sequences_missing_unknown_and_duplicate_fields() {
        for wire in [
            r#"[null,null]"#,
            r#"{}"#,
            r#"{"lower":null}"#,
            r#"{"upper":null}"#,
            r#"{"lower":null,"upper":null,"extra":0}"#,
            r#"{"lower":null,"lower":null,"upper":null}"#,
            r#"{"lower":{"included":"a","excluded":"b"},"upper":null}"#,
        ] {
            assert!(serde_json::from_str::<NativeRange<String>>(wire).is_err());
        }
        assert_eq!(
            serde_json::to_value(NativeRange::<String>::ALL).unwrap(),
            json!({"lower":null,"upper":null})
        );
        assert_eq!(
            serde_json::from_str::<NativeRange<String>>(r#"{"lower":null,"upper":null}"#).unwrap(),
            NativeRange::ALL
        );
    }
}
