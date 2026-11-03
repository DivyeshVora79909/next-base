//! Protected scalar-reference tuple claims, reconciled from old and final source.
use crate::{
    binding::{Binding, NativeInput},
    model::Prepared,
    native_codec::{Key, StoredValue},
    native_slice::{Attempt, Error, ModelRecord, Result},
};
use std::collections::{BTreeMap, BTreeSet};

fn claims<B: Binding>(
    model: &Prepared<B>,
    input: &B::Input,
    charge: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<BTreeSet<Key>> {
    let contract = model.contract(input.contract())?;
    let references = input.references();
    let mut claims = BTreeSet::new();
    for constraint in &contract.uniqueness {
        charge(1)?;
        let mut targets = Vec::with_capacity(constraint.reference_slots.len());
        let mut missing = false;
        for slot in &constraint.reference_slots {
            charge(1 + references.len() as u64)?;
            let mut bound = references.iter().filter(|(_, _, s)| s == slot);
            match bound.next() {
                Some((target, _, _)) => targets.push(*target),
                None => {
                    charge(contract.references.len() as u64)?;
                    let declaration = contract
                        .references
                        .iter()
                        .find(|r| r.slot == *slot)
                        .ok_or_else(|| Error::new("model", "undeclared unique reference"))?;
                    if !declaration.optional {
                        return Err(Error::new(
                            "invalid_input",
                            "missing required unique reference",
                        ));
                    }
                    missing = true;
                }
            }
            if bound.next().is_some() {
                return Err(Error::new(
                    "invalid_input",
                    "unique reference must be scalar",
                ));
            }
        }
        if !missing {
            claims.insert(Key::Unique {
                contract: contract.code,
                constraint: constraint.code,
                targets,
            });
        }
    }
    Ok(claims)
}

/// Run after model settlement, including all changed managed output records.
/// Every old claim is checked before changed claims are released; all releases
/// precede acquisition so swaps and delete/reuse depend only on the final graph.
pub fn reconcile<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
) -> Result<()> {
    reconcile_from(ws, model, &BTreeMap::new())
}

/// Reconcile against this settlement call's entry graph when an Attempt is reused.
pub(crate) fn reconcile_from<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    entry_records: &BTreeMap<uuid::Uuid, Option<ModelRecord<B>>>,
) -> Result<()> {
    if !model
        .contracts()
        .any(|contract| !contract.uniqueness.is_empty())
    {
        return Ok(());
    }
    let mut changes = Vec::new();
    let mut candidates = ws.changed_records();
    candidates.extend(entry_records.keys().copied());
    for id in candidates {
        ws.charge("dependency", 1)?;
        let original = match entry_records.get(&id) {
            Some(record) => record.clone(),
            None => match ws.original(&Key::Record(id))? {
                Some(StoredValue::Record(record)) => Some(record),
                None => None,
                _ => return Err(Error::new("corrupt_state", "unique source record type")),
            },
        };
        let old = match original {
            Some(record) => claims(model, &record.input, &mut |count| {
                ws.charge("dependency", count)
            })
            .map_err(|error| {
                if error.code == "work_limit" {
                    error
                } else {
                    Error::new("corrupt_state", "invalid original unique reference")
                }
            })?,
            None => BTreeSet::new(),
        };
        let new = ws
            .record(id)?
            .map(|r| claims(model, &r.input, &mut |count| ws.charge("dependency", count)))
            .transpose()?
            .unwrap_or_default();
        for key in &old {
            if ws.get(key)? != Some(StoredValue::Unique(id)) {
                return Err(Error::new(
                    "corrupt_state",
                    "unique claim holder differs from source",
                ));
            }
        }
        changes.push((id, old, new));
    }
    for (_, old, new) in &changes {
        for key in old.difference(new) {
            ws.put(key.clone(), None)?;
        }
    }
    for (id, old, new) in changes {
        for key in new.difference(&old) {
            if ws.get(key)?.is_some() {
                return Err(Error::new("invariant", "duplicate reference tuple"));
            }
            ws.put(key.clone(), Some(StoredValue::Unique(id)))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::ReadableTable;
    use crate::{
        indexes::standard::Standard,
        integrity::Snapshot,
        local::{KV, Mutation, Store},
        model::{Contract, Unique},
        models::quantity::{Input, JOIN, Quantity, SOURCE},
        native_codec::{self},
        native_slice::{Context, Model, ModelChange},
    };
    use serde_json::{Value, json};
    use std::{path::PathBuf, sync::Arc};
    use uuid::Uuid;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Claims;
    impl Binding for Claims {
        type Index = Standard;
        type Input = Input;
        type Derived = ();
        type Outcome = ();
        const NAME: &'static str = "unique-independent-inventory";
        const BEHAVIOR: &'static str = "unique-independent-inventory-1";
        fn engine() -> Result<Model> {
            Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
        }
        fn declarations() -> Result<Vec<Contract>> {
            let mut declarations = Quantity::declarations()?;
            for c in &mut declarations {
                c.published.clear();
                c.publication_inputs.clear();
                c.calculations.clear();
                c.calculation_order.clear();
                if c.code == JOIN {
                    c.uniqueness = vec![Unique {
                        code: 7,
                        reference_slots: vec![1, 2],
                    }];
                }
            }
            Ok(declarations)
        }
        fn valid_derived(_: &Input, derived: Option<&()>) -> bool {
            derived.is_none()
        }
        fn published_shape(_: u16) -> Value {
            Value::Null
        }
        fn settle_changes<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
            _ws: &mut Attempt<L, Self>,
            _: &Prepared<Self>,
            _: Context,
            _changes: &[ModelChange<Self>],
            _: Uuid,
            _: &mut dyn FnMut() -> Result<Uuid>,
        ) -> Result<()> {
            Ok(())
        }
        fn check(store: &Store<Self>) -> Result<Value> {
            // Deliberately scoped to Snapshot::load: includes independent source
            // claim inventory, not model-specific AVL/calculation finish checks.
            Snapshot::load(store)?;
            Ok(json!({"source_unique_inventory":true}))
        }
    }
    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }
    struct Fixture {
        store: Store<Claims>,
        directory: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let directory =
                std::env::temp_dir().join(format!("unique-snapshot-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&directory).unwrap();
            let store = Store::create(
                directory.join("store.redb"),
                Arc::new(Prepared::load().unwrap()),
                Context {
                    tenant: id(1),
                    actor: id(2),
                },
            )
            .unwrap();
            let commands = json!([
                {"op":"create","id":id(10),"contract":SOURCE,"fields":{"value":"1"}},
                {"op":"create","id":id(11),"contract":SOURCE,"fields":{"value":"2"}},
                {"op":"create","id":id(20),"contract":JOIN,"fields":{"left":id(10),"right":id(11)}},
                {"op":"create","id":id(21),"contract":JOIN,"fields":{"left":id(11),"right":id(10)}}
            ]);
            let request: Mutation = serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":Uuid::new_v4(),"commands":commands,"returning":[]})).unwrap();
            store.mutate(&request).unwrap();
            assert!(Snapshot::load(&store).is_ok());
            Self { store, directory }
        }
        fn replace(&self, key: &Key, value: Option<StoredValue<Claims>>) {
            let write = self.store.begin_write().unwrap();
            {
                let mut table = write.open_table(KV).unwrap();
                if let Some(value) = value {
                    let bytes = native_codec::encode_for(key, &value).unwrap();
                    table
                        .insert(key.encode().as_slice(), bytes.as_slice())
                        .unwrap();
                } else {
                    table.remove(key.encode().as_slice()).unwrap();
                }
            }
            write.commit().unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    #[serde(transparent)]
    struct Missing(Input);
    impl NativeInput for Missing {
        fn contract(&self) -> u16 {
            self.0.contract()
        }
        fn validate(&self) -> Result<()> {
            self.0.validate()
        }
        fn bind(code: u16, value: Value) -> Result<Self> {
            Input::bind(code, value).map(Self)
        }
        fn references(&self) -> Vec<(Uuid, u16, u16)> {
            vec![]
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct OptionalClaims;
    impl Binding for OptionalClaims {
        type Index = Standard;
        type Input = Missing;
        type Derived = ();
        type Outcome = ();
        const NAME: &'static str = "optional-claim-budget";
        const BEHAVIOR: &'static str = "optional-claim-budget-1";
        fn engine() -> Result<Model> {
            Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
        }
        fn declarations() -> Result<Vec<Contract>> {
            let mut declarations = Claims::declarations()?;
            for c in &mut declarations {
                for r in &mut c.references {
                    r.optional = true;
                }
            }
            Ok(declarations)
        }
        fn valid_derived(_: &Missing, d: Option<&()>) -> bool {
            d.is_none()
        }
        fn published_shape(_: u16) -> Value {
            Value::Null
        }
        fn settle_changes<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
            _: &mut Attempt<L, Self>,
            _: &Prepared<Self>,
            _: Context,
            _: &[ModelChange<Self>],
            _: Uuid,
            _: &mut dyn FnMut() -> Result<Uuid>,
        ) -> Result<()> {
            Ok(())
        }
        fn check(_: &Store<Self>) -> Result<Value> {
            Ok(Value::Null)
        }
    }
    #[test]
    fn absent_optional_tuple_still_consumes_bounded_work_without_publishing() {
        let model = Prepared::<OptionalClaims>::load().unwrap();
        let input = Missing(Input::Join {
            left: id(10),
            right: id(11),
        });
        let source = crate::native_slice::ModelRecord::<OptionalClaims> {
            contract: JOIN,
            tenant: id(1),
            owner: id(2),
            version: id(3),
            input,
            derived: None,
        };
        let base = std::collections::BTreeMap::<Vec<u8>, Vec<u8>>::new();
        let mut control =
            Attempt::<_, OptionalClaims>::new(|key: &[u8]| Ok(base.get(key).cloned()), 1000);
        control
            .put(
                Key::Record(id(20)),
                Some(StoredValue::Record(source.clone())),
            )
            .unwrap();
        reconcile(&mut control, &model).unwrap();
        let needed = control.work.work_units;
        assert!(
            control.work.dependency_checks >= 8,
            "record, constraint, slots and optional declaration scans are charged"
        );
        assert!(
            control
                .finish()
                .unwrap()
                .keys()
                .all(|key| !matches!(Key::decode(key).unwrap(), Key::Unique { .. }))
        );
        let mut limited =
            Attempt::<_, OptionalClaims>::new(|key: &[u8]| Ok(base.get(key).cloned()), needed - 1);
        limited
            .put(Key::Record(id(20)), Some(StoredValue::Record(source)))
            .unwrap();
        assert_eq!(
            reconcile(&mut limited, &model).unwrap_err().code,
            "work_limit"
        );
        drop(limited);
        assert!(
            base.is_empty(),
            "rejected attempt never publishes staged source or claims"
        );
    }

    #[test]
    fn snapshot_reconstructs_declared_unique_inventory_from_source() {
        let fixture = Fixture::new();
        let key = Key::Unique {
            contract: JOIN,
            constraint: 7,
            targets: vec![id(10), id(11)],
        };
        fixture.replace(&key, None);
        assert!(Snapshot::load(&fixture.store).is_err(), "missing claim");
        fixture.replace(&key, Some(StoredValue::Unique(id(21))));
        assert!(Snapshot::load(&fixture.store).is_err(), "wrong holder");
        fixture.replace(&key, Some(StoredValue::Unique(id(20))));
        assert!(Snapshot::load(&fixture.store).is_ok());
        let extra = Key::Unique {
            contract: JOIN,
            constraint: 8,
            targets: vec![id(10)],
        };
        fixture.replace(&extra, Some(StoredValue::Unique(id(20))));
        assert!(
            Snapshot::load(&fixture.store).is_err(),
            "extraneous well-formed claim"
        );
        fixture.replace(&extra, None);
        assert!(Snapshot::load(&fixture.store).is_ok());
        let original = Snapshot::load(&fixture.store).unwrap().records[&id(21)].clone();
        let mut duplicate = original.clone();
        duplicate.input = Input::Join {
            left: id(10),
            right: id(11),
        };
        fixture.replace(&Key::Record(id(21)), Some(StoredValue::Record(duplicate)));
        assert!(
            Snapshot::load(&fixture.store).is_err(),
            "duplicate source with unchanged claims"
        );
        fixture.replace(&Key::Record(id(21)), Some(StoredValue::Record(original)));
        assert!(Snapshot::load(&fixture.store).is_ok());
    }

    #[test]
    fn unique_codec_is_framed_ordered_and_canonical() {
        let key = Key::Unique {
            contract: JOIN,
            constraint: 7,
            targets: vec![id(11), id(10)],
        };
        let bytes = key.encode();
        assert_eq!(Key::decode(&bytes).unwrap(), key);
        let mut reverse = key.clone();
        if let Key::Unique { targets, .. } = &mut reverse {
            targets.reverse();
        }
        assert_ne!(reverse.encode(), bytes);
        for index in [1, 3, 5] {
            let mut invalid = bytes.clone();
            invalid[index..index + 2].fill(0);
            assert!(Key::decode(&invalid).is_err());
        }
        assert!(Key::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Key::decode(&trailing).is_err());
        let value = StoredValue::<Claims>::Unique(Uuid::from_u128(0xabcdef));
        let encoded = native_codec::encode_for(&key, &value).unwrap();
        assert_eq!(
            native_codec::decode_for::<Claims>(&key, &encoded).unwrap(),
            value
        );
        let noncanonical = String::from_utf8(encoded).unwrap().to_uppercase();
        assert!(native_codec::decode_for::<Claims>(&key, noncanonical.as_bytes()).is_err());
        let uppercase_holder = format!(
            "{{\"type\":\"unique\",\"data\":\"{}\"}}",
            Uuid::from_u128(0xabcdef).to_string().to_uppercase()
        );
        assert!(native_codec::decode_for::<Claims>(&key, uppercase_holder.as_bytes()).is_err());
    }

    /// Chunk composition at the native mutation boundary, without receipt claims.
    #[test]
    fn two_settlements_restore_original_unique_tuple_in_one_attempt() {
        let fixture = Fixture::new();
        let store = &fixture.store;
        let original = Snapshot::load(store).unwrap().records[&id(20)].clone();
        let write = store.begin_write().unwrap();
        let batch = {
            let table = write.open_table(KV).unwrap();
            let mut ws = Attempt::<_, Claims>::new(
                |key: &[u8]| {
                    Ok(table
                        .get(key)
                        .map_err(crate::local::storage)?
                        .map(|v| v.value().to_vec()))
                },
                200_000,
            );
            for left in [id(11), id(10)] {
                let current_version = ws.record(id(20)).unwrap().unwrap().version;
                let command = crate::native_slice::Command::Update {
                    owner: None,
                    id: id(20),
                    if_version: current_version,
                    set: serde_json::from_value(json!({"left":left})).unwrap(),
                    unset: vec![],
                };
                crate::mutation::settle_authorized(
                    &mut ws,
                    store.model(),
                    store.context(),
                    &[command],
                    // Preserve the original version so the final source is also
                    // absent from Attempt::changed_records, exercising its union.
                    &mut || Ok(original.version),
                    false,
                    &mut |_, _, _, _| Ok(()),
                    &mut |_, _| Ok(()),
                )
                .unwrap();
            }
            assert_eq!(ws.record(id(20)).unwrap().unwrap(), original);
            assert!(!ws.changed_records().contains(&id(20)));
            ws.finish().unwrap()
        };
        store.publish_native(&write, &batch, None).unwrap();
        write.commit().unwrap();
        let snapshot = Snapshot::load(store).unwrap();
        assert_eq!(snapshot.records[&id(20)], original);
        assert_eq!(
            snapshot.all.get(&Key::Unique {
                contract: JOIN,
                constraint: 7,
                targets: vec![id(10), id(11)],
            }),
            Some(&StoredValue::Unique(id(20)))
        );
        assert!(!snapshot.all.contains_key(&Key::Unique {
            contract: JOIN,
            constraint: 7,
            targets: vec![id(11), id(11)],
        }));
    }
}
