//! Reference-only fixture: no binding-authored Incoming or calculation routes.
use crate::storage::ReadableTable;
use crate::{
    binding::{Binding, NativeInput},
    indexes::standard::Standard,
    integrity::Snapshot,
    local::{KV, Mutation, Store},
    model::{self, Contract, InputField, Prepared, Reference, Visibility},
    native_codec::{self, Address, Key, StoredValue},
    native_slice::{Attempt, Context, Error, Model, ModelChange, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct References;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    kind: u16,
    first: Option<Uuid>,
    second: Option<Uuid>,
    action: u16,
}
impl NativeInput for Input {
    fn contract(&self) -> u16 {
        self.kind
    }
    fn validate(&self) -> Result<()> {
        Ok(())
    }
    fn bind(code: u16, fields: Value) -> Result<Self> {
        let v: Self = serde_json::from_value(fields)
            .map_err(|e| Error::new("invalid_input", e.to_string()))?;
        if v.kind != code {
            return Err(Error::new("invalid_input", "contract"));
        }
        Ok(v)
    }
    fn references(&self) -> Vec<(Uuid, u16, u16)> {
        let mut refs = Vec::new();
        if let Some(target) = self.first {
            // Deliberately wrong native hint: actual catalog types are authoritative.
            refs.push((target, 999, 1));
            refs.push((target, 999, 1)); // identical references collapse as a set
        }
        if let Some(target) = self.second {
            refs.push((target, 999, 2));
        }
        refs
    }
}
impl Binding for References {
    type Index = Standard;
    type Input = Input;
    type Derived = ();
    type Outcome = ();
    const NAME: &'static str = "automatic-incoming-reference-only";
    const BEHAVIOR: &'static str = "automatic-incoming-reference-only-1";
    fn engine() -> Result<Model> {
        Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
    }
    fn declarations() -> Result<Vec<Contract>> {
        Ok([(11,"Alpha"),(12,"Beta"),(13,"Other")].into_iter().map(|(code,name)| Contract {
            code, name, visibility: Visibility::Public,
            schema: json!({"$schema":model::SCHEMA_DIALECT,"type":"object","additionalProperties":false,
                "properties":{"kind":{"type":"integer","enum":[code]},
                "first":{"type":["string","null"],"x-rebase-binding":"uuid"},
                "second":{"type":["string","null"],"x-rebase-binding":"uuid"},"action":{"type":"integer"}},
                "required":["kind","first","second","action"]}),
            fields: ["kind","first","second","action"].into_iter().enumerate().map(|(i,name)| InputField {code:i as u16+1,name,mutable:name!="kind"}).collect(),
            references: [(1,"first"),(2,"second")].into_iter().map(|(slot,field)| Reference {
                slot,field,targets:vec![11,12],optional:true,direct_fields:vec![],validation_fields:vec![],on_delete:"reject",
            }).collect(),
            published:vec![],uniqueness:vec![],roots:vec![],memberships:vec![],queries:vec![],publication_inputs:vec![],outputs:vec![],calculations:vec![],calculation_order:vec![],rules:vec![],schema_source:"src/reference_tests.rs",behavior_source:"src/reference_tests.rs",
        }).collect())
    }
    fn valid_derived(_: &Input, v: Option<&()>) -> bool {
        v.is_none()
    }
    fn published_shape(_: u16) -> Value {
        Value::Null
    }
    fn settle_changes<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Attempt<L, Self>,
        _: &Prepared<Self>,
        _: Context,
        changes: &[ModelChange<Self>],
        _: Uuid,
        _: &mut dyn FnMut() -> Result<Uuid>,
    ) -> Result<()> {
        for change in changes {
            if let Some(new) = &change.new {
                if new.input.action == 1 {
                    // Ordinary existing source edited only by settlement.
                    let mut child = ws.record(id(20))?.unwrap();
                    child.input.first = new.input.first;
                    ws.put(Key::Record(id(20)), Some(StoredValue::Record(child)))?;
                } else if new.input.action == 2 {
                    // Restore the complete original record, including its version:
                    // changed_records excludes this explicitly proposed source.
                    if let Some(old) = &change.old {
                        ws.put(
                            Key::Record(change.id),
                            Some(StoredValue::Record(old.clone())),
                        )?;
                        assert!(!ws.changed_records().contains(&change.id));
                    }
                } else if new.input.action == 3 {
                    // Unsupported raw ordinary lifecycle mutation: the engine must
                    // reject it before it can leave record headers orphaned.
                    ws.put(Key::Record(id(20)), None)?;
                }
            }
        }
        Ok(())
    }
    fn check(store: &Store<Self>) -> Result<Value> {
        check(store)
    }
}
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn value(kind: u16, first: Option<u128>, second: Option<u128>) -> Input {
    Input {
        kind,
        first: first.map(id),
        second: second.map(id),
        action: 0,
    }
}
fn create(n: u128, v: Input) -> Value {
    json!({"op":"create","id":id(n),"contract":v.kind,"fields":v})
}
fn update(store: &Store<References>, n: u128, set: Value) -> Value {
    json!({"op":"update","id":id(n),"if_version":Snapshot::load(store).unwrap().records[&id(n)].version,"set":set,"unset":[]})
}
fn delete(store: &Store<References>, n: u128) -> Value {
    json!({"op":"delete","id":id(n),"if_version":Snapshot::load(store).unwrap().records[&id(n)].version})
}
fn request(store: &Store<References>, commands: Value) -> Mutation {
    serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":Uuid::new_v4(),"commands":commands,"returning":[]})).unwrap()
}
fn apply(store: &Store<References>, commands: Value) {
    store.mutate(&request(store, commands)).unwrap();
    check(store).unwrap();
}
fn check(store: &Store<References>) -> Result<Value> {
    let s = Snapshot::load(store)?;
    // Snapshot builds expected Incoming from typed source facts; finish compares
    // complete physical inventory, including missing and extra route rows.
    s.finish(
        s.expected_keys.clone(),
        BTreeMap::new(),
        s.routes.clone(),
        BTreeMap::new(),
    )
}
struct Fixture {
    store: Store<References>,
    directory: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!("automatic-incoming-{}", Uuid::new_v4()));
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
        Self { store, directory }
    }
}
fn incoming(store: &Store<References>, parent: u128) -> BTreeSet<Address> {
    Snapshot::load(store)
        .unwrap()
        .routes
        .get(&Key::Incoming(id(parent)))
        .cloned()
        .unwrap_or_default()
}
const PERMUTATIONS: [[usize; 3]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];

#[test]
fn automatic_incoming_all_create_delete_orders_and_reopen() {
    for order in PERMUTATIONS {
        let f = Fixture::new();
        let commands = [
            create(10, value(11, None, None)),
            create(11, value(12, None, None)),
            create(20, value(11, Some(10), Some(11))),
        ];
        apply(
            &f.store,
            Value::Array(order.map(|i| commands[i].clone()).to_vec()),
        );
        assert_eq!(
            incoming(&f.store, 10),
            BTreeSet::from([Address::new(id(20), 1)])
        );
        assert_eq!(
            incoming(&f.store, 11),
            BTreeSet::from([Address::new(id(20), 2)])
        );
        let path = f.directory.join("store.redb");
        drop(f.store);
        let store = Store::<References>::open(path, Arc::new(Prepared::load().unwrap())).unwrap();
        check(&store).unwrap();
        let commands = [delete(&store, 10), delete(&store, 11), delete(&store, 20)];
        apply(
            &store,
            Value::Array(order.map(|i| commands[i].clone()).to_vec()),
        );
        assert!(Snapshot::load(&store).unwrap().records.is_empty());
        drop(store);
        std::fs::remove_dir_all(f.directory).unwrap();
    }
}

#[test]
fn retarget_optional_duplicate_slots_cycle_and_dangling_rollback() {
    let f = Fixture::new();
    let s = &f.store;
    apply(
        s,
        json!([
            create(10, value(11, None, None)),
            create(11, value(12, None, None)),
            create(20, value(11, Some(10), Some(10)))
        ]),
    );
    assert_eq!(
        incoming(s, 10),
        BTreeSet::from([Address::new(id(20), 1), Address::new(id(20), 2)])
    );
    let before = s.observe_for_verification().unwrap();
    assert_eq!(
        s.mutate(&request(s, json!([delete(s, 10)])))
            .unwrap_err()
            .code,
        "unavailable_reference"
    );
    assert_eq!(s.observe_for_verification().unwrap(), before);
    check(s).unwrap();
    apply(
        s,
        json!([
            update(s, 20, json!({"first":id(11),"second":null})),
            delete(s, 10)
        ]),
    );
    assert!(incoming(s, 10).is_empty());
    assert_eq!(incoming(s, 11), BTreeSet::from([Address::new(id(20), 1)]));
    // A reference-only cycle has no calculation feedback or reader dependency.
    apply(s, json!([update(s, 11, json!({"first":id(20)}))]));
    apply(s, json!([delete(s, 11), delete(s, 20)]));
    drop(f.store);
    std::fs::remove_dir_all(f.directory).unwrap();
}

#[test]
fn settlement_only_edit_and_restored_explicit_proposal_reconcile_incoming() {
    let f = Fixture::new();
    let s = &f.store;
    apply(
        s,
        json!([
            create(10, value(11, None, None)),
            create(11, value(12, None, None)),
            create(20, value(11, Some(10), None)),
            create(30, value(11, None, None))
        ]),
    );
    apply(
        s,
        json!([update(s, 30, json!({"first":id(11),"action":1}))]),
    );
    assert!(incoming(s, 10).is_empty());
    assert!(incoming(s, 11).contains(&Address::new(id(20), 1)));
    let original = Snapshot::load(s).unwrap().records[&id(20)].clone();
    apply(
        s,
        json!([update(s, 20, json!({"first":id(10),"action":2}))]),
    );
    assert_eq!(Snapshot::load(s).unwrap().records[&id(20)], original);
    assert!(incoming(s, 10).is_empty());
    assert!(incoming(s, 11).contains(&Address::new(id(20), 1)));
    drop(f.store);
    std::fs::remove_dir_all(f.directory).unwrap();
}

fn raw_replace(store: &Store<References>, key: Key, value: Option<StoredValue<References>>) {
    let write = store.begin_write().unwrap();
    {
        let mut table = write.open_table(KV).unwrap();
        if let Some(value) = value {
            let bytes = native_codec::encode_for(&key, &value).unwrap();
            table
                .insert(key.encode().as_slice(), bytes.as_slice())
                .unwrap();
        } else {
            table.remove(key.encode().as_slice()).unwrap();
        }
    }
    write.commit().unwrap();
}
#[test]
fn independent_finish_rejects_missing_extra_and_stale_reference_routes() {
    let f = Fixture::new();
    let s = &f.store;
    apply(
        s,
        json!([
            create(10, value(11, None, None)),
            create(11, value(12, None, None)),
            create(20, value(11, Some(10), None))
        ]),
    );
    let snapshot = Snapshot::load(s).unwrap();
    let route_key = Key::Incoming(id(10));
    let original = snapshot.all[&route_key].clone();
    let empty = snapshot.all[&Key::Incoming(id(11))].clone();
    let child = snapshot.records[&id(20)].clone();
    drop(snapshot);
    raw_replace(s, route_key.clone(), None);
    assert_eq!(check(s).unwrap_err().code, "corrupt_state");
    raw_replace(s, route_key.clone(), Some(original.clone()));
    check(s).unwrap();
    raw_replace(s, Key::Incoming(id(11)), Some(original));
    assert_eq!(check(s).unwrap_err().code, "corrupt_state");
    raw_replace(s, Key::Incoming(id(11)), Some(empty));
    check(s).unwrap();
    let mut stale = child.clone();
    stale.input.first = Some(id(11));
    raw_replace(s, Key::Record(id(20)), Some(StoredValue::Record(stale)));
    assert_eq!(check(s).unwrap_err().code, "corrupt_state");
    raw_replace(s, Key::Record(id(20)), Some(StoredValue::Record(child)));
    check(s).unwrap();
    drop(f.store);
    std::fs::remove_dir_all(f.directory).unwrap();
}

#[test]
fn references_resolve_actual_catalog_type_and_tenant() {
    let f = Fixture::new();
    let s = &f.store;
    apply(
        s,
        json!([
            create(10, value(11, None, None)),
            create(13, value(13, None, None))
        ]),
    );
    let before = s.observe_for_verification().unwrap();
    assert_eq!(
        s.mutate(&request(s, json!([create(20, value(11, Some(13), None))])))
            .unwrap_err()
            .code,
        "unavailable_reference"
    );
    assert_eq!(s.observe_for_verification().unwrap(), before);
    let original = Snapshot::load(s).unwrap().records[&id(10)].clone();
    let mut foreign = original.clone();
    foreign.tenant = id(999);
    raw_replace(s, Key::Record(id(10)), Some(StoredValue::Record(foreign)));
    let before = s.observe_for_verification().unwrap();
    assert_eq!(
        s.mutate(&request(s, json!([create(20, value(11, Some(10), None))])))
            .unwrap_err()
            .code,
        "unavailable_reference"
    );
    assert_eq!(s.observe_for_verification().unwrap(), before);
    raw_replace(s, Key::Record(id(10)), Some(StoredValue::Record(original)));
    check(s).unwrap();
    drop(f.store);
    std::fs::remove_dir_all(f.directory).unwrap();
}

#[test]
fn settlement_raw_ordinary_delete_is_rejected_with_exact_rollback() {
    let f = Fixture::new();
    let s = &f.store;
    apply(
        s,
        json!([
            create(10, value(11, None, None)),
            create(20, value(11, Some(10), None)),
            create(30, value(11, None, None))
        ]),
    );
    let before = s.observe_for_verification().unwrap();
    assert_eq!(
        s.mutate(&request(s, json!([update(s, 30, json!({"action":3}))])))
            .unwrap_err()
            .code,
        "model"
    );
    assert_eq!(s.observe_for_verification().unwrap(), before);
    check(s).unwrap();
    drop(f.store);
    std::fs::remove_dir_all(f.directory).unwrap();
}

/// Exercise the shared mutation primitive used by chunked population: two
/// settlements share one Attempt and one redb transaction. This is not a receipt
/// or client request test; publish_native supplies normal indexes and epochs.
#[test]
fn two_settlements_in_one_attempt_use_each_calls_entry_source_graph() {
    let f = Fixture::new();
    let s = &f.store;
    apply(
        s,
        json!([
            create(10, value(11, None, None)),
            create(11, value(12, None, None)),
            create(20, value(11, Some(10), None)),
            create(30, value(11, None, None))
        ]),
    );
    let first = serde_json::from_value(update(s, 20, json!({"first":id(11)}))).unwrap();
    let second = serde_json::from_value(update(s, 30, json!({"first":id(10),"action":1}))).unwrap();
    let write = s.begin_write().unwrap();
    let batch = {
        let table = write.open_table(KV).unwrap();
        let mut ws = Attempt::<_, References>::new(
            |key: &[u8]| {
                Ok(table
                    .get(key)
                    .map_err(crate::local::storage)?
                    .map(|v| v.value().to_vec()))
            },
            200_000,
        );
        for command in [first, second] {
            crate::mutation::settle_authorized(
                &mut ws,
                s.model(),
                s.context(),
                &[command],
                &mut || Ok(Uuid::new_v4()),
                false,
                &mut |_, _, _, _| Ok(()),
                &mut |_, _| Ok(()),
            )
            .unwrap();
        }
        assert_eq!(
            ws.record(id(20)).unwrap().unwrap().input.first,
            Some(id(10))
        );
        ws.finish().unwrap()
    };
    s.publish_native(&write, &batch, None).unwrap();
    write.commit().unwrap();
    check(s).unwrap();
    assert_eq!(
        incoming(s, 10),
        BTreeSet::from([Address::new(id(20), 1), Address::new(id(30), 1)])
    );
    assert!(incoming(s, 11).is_empty());
    drop(f.store);
    std::fs::remove_dir_all(f.directory).unwrap();
}
