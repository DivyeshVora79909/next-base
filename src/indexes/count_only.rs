//! Native ordered values whose cardinality is maintained by tree structure.

use serde_json::{Value, json};

use crate::{
    index::{IndexCode, IndexDescriptor, NativeIndex, SummaryRead},
    native_slice::{Error, Result},
};

pub const COUNT_ONLY: IndexCode = IndexCode::new(1).expect("nonzero index code");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CountOnly;

fn unknown() -> Error {
    Error::new("corrupt_state", "unknown count-only index code")
}

impl NativeIndex for CountOnly {
    type Key = String;
    type Leaf = ();
    type Summary = ();
    type QueryResult = ();

    fn descriptors() -> Vec<IndexDescriptor> {
        vec![IndexDescriptor {
            code: COUNT_ONLY,
            name: "count_only",
            reads: vec!["summary"],
            key_schema: json!({"type":"string"}),
            leaf_schema: json!({"type":"null"}),
            summary_schema: json!({"type":"null"}),
            result_schemas: json!({"summary":{"type":"null"}}),
            time: false,
            financial: false,
            quote: false,
        }]
    }

    fn validate_key(code: IndexCode, _key: &String) -> Result<()> {
        if code == COUNT_ONLY {
            Ok(())
        } else {
            Err(unknown())
        }
    }

    fn validate_leaf(code: IndexCode, _leaf: &()) -> Result<()> {
        if code == COUNT_ONLY {
            Ok(())
        } else {
            Err(unknown())
        }
    }

    fn validate_summary(code: IndexCode, _summary: &()) -> Result<()> {
        if code == COUNT_ONLY {
            Ok(())
        } else {
            Err(unknown())
        }
    }

    fn empty(code: IndexCode) -> Result<()> {
        if code == COUNT_ONLY {
            Ok(())
        } else {
            Err(unknown())
        }
    }

    fn singleton(code: IndexCode, key: &String, leaf: &()) -> Result<()> {
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
                "count-only summary read required",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_matches_unit_values_and_supported_projection() {
        let descriptor = CountOnly::descriptor(COUNT_ONLY).unwrap();
        assert_eq!(descriptor.reads, ["summary"]);
        assert_eq!(descriptor.key_schema, json!({"type":"string"}));
        assert_eq!(descriptor.leaf_schema, json!({"type":"null"}));
        assert_eq!(descriptor.summary_schema, json!({"type":"null"}));
        assert_eq!(descriptor.result_schemas["summary"], json!({"type":"null"}));
        assert!(!descriptor.time && !descriptor.financial && !descriptor.quote);
        assert_eq!(
            CountOnly::project(COUNT_ONLY, SummaryRead::Summary, &()).unwrap(),
            Value::Null
        );
        assert!(CountOnly::project(COUNT_ONLY, SummaryRead::Before, &()).is_err());
    }

    #[test]
    fn rejects_unknown_codes() {
        let invalid = IndexCode::new(99).unwrap();
        assert!(CountOnly::descriptor(invalid).is_err());
        assert!(CountOnly::validate_key(invalid, &String::new()).is_err());
        assert!(CountOnly::validate_leaf(invalid, &()).is_err());
        assert!(CountOnly::validate_summary(invalid, &()).is_err());
        assert!(CountOnly::empty(invalid).is_err());
        assert!(CountOnly::singleton(invalid, &String::new(), &()).is_err());
        assert!(CountOnly::combine(invalid, &(), &()).is_err());
        assert!(CountOnly::project(invalid, SummaryRead::Summary, &()).is_err());
    }
}
