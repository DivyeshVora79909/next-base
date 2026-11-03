//! Pure relationship rules checked by an independent, literal source oracle.
use rebase_semantic_proof::{
    binding::{Binding, NativeInput, RelationInput},
    indexes::standard::Standard,
    local::{Mutation, Store},
    model::{self, Contract, InputField, Prepared, Reference, Visibility},
    native_codec::{self, Key, StoredValue},
    native_slice::{Attempt, Context, Error, Model, ModelChange, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Schedule;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    kind: u16,
    parent: Option<Uuid>,
    parent_kind: u16,
    at: i64,
    amount: i64,
    start: i64,
    end: i64,
    limit: i64,
    body: String,
}
impl NativeInput for Input {
    fn contract(&self) -> u16 {
        self.kind
    }
    fn validate(&self) -> Result<()> {
        Ok(())
    }
    fn bind(code: u16, fields: Value) -> Result<Self> {
        let input: Self = serde_json::from_value(fields)
            .map_err(|e| Error::new("invalid_input", e.to_string()))?;
        if input.kind != code {
            return Err(Error::new("invalid_input", "wrong contract"));
        }
        Ok(input)
    }
    fn references(&self) -> Vec<(Uuid, u16, u16)> {
        if self.kind == 21 {
            self.parent
                .map(|target| vec![(target, 11, 1)])
                .unwrap_or_default()
        } else {
            vec![]
        }
    }
}
static CALLS: AtomicUsize = AtomicUsize::new(0);
impl Binding for Schedule {
    type Index = Standard;
    type Input = Input;
    type Derived = ();
    type Outcome = ();
    const NAME: &'static str = "test-relationship-schedule";
    const BEHAVIOR: &'static str = "test-relationship-schedule-1";
    fn engine() -> Result<Model> {
        Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
    }
    fn declarations() -> Result<Vec<Contract>> {
        Ok([(11,"Window"),(12,"AlternativeWindow"),(21,"Reservation")].into_iter().map(|(code,name)| {
            Contract {code,name,visibility:Visibility::Public,
                schema:json!({"$schema":model::SCHEMA_DIALECT,"type":"object","additionalProperties":false,
                    "properties":{"kind":{"type":"integer","enum":[code]},"parent":{"type":["string","null"],"x-rebase-binding":"uuid"},"parent_kind":{"type":"integer"},"at":{"type":"integer"},"amount":{"type":"integer"},"start":{"type":"integer"},"end":{"type":"integer"},"limit":{"type":"integer"},"body":{"type":"string"}},
                    "required":["kind","parent","parent_kind","at","amount","start","end","limit","body"]}),
                fields:["kind","parent","parent_kind","at","amount","start","end","limit","body"].into_iter().enumerate().map(|(i,name)| InputField {code:i as u16+1,name,mutable:name!="kind"}).collect(),
                references:if code==21 { vec![Reference {slot:1,field:"parent",targets:vec![11,12],optional:true,direct_fields:vec![],validation_fields:vec!["start","end","limit"],on_delete:"reject",}] } else {vec![]},
                published:vec![],uniqueness:vec![],roots:vec![],memberships:vec![],queries:vec![],publication_inputs:vec![],outputs:vec![],calculations:vec![],calculation_order:vec![],rules:vec![],schema_source:"tests/relationship_predicates.rs",behavior_source:"tests/relationship_predicates.rs"}
        }).collect())
    }
    fn validate_relationships(input: &Input, parents: &[RelationInput]) -> Result<()> {
        if input.kind != 21 {
            return Ok(());
        }
        CALLS.fetch_add(1, Ordering::SeqCst);
        assert_eq!(parents.len(), usize::from(input.parent.is_some()));
        for parent in parents {
            assert_eq!(parent.slot, 1);
            assert_eq!(Some(parent.target), input.parent);
            let fields = &parent.fields;
            assert_eq!(fields.len(), 3, "no full body, unrelated or derived fields");
            assert!(
                fields.contains_key("start")
                    && fields.contains_key("end")
                    && fields.contains_key("limit")
            );
            if input.at < fields["start"].as_i64().unwrap()
                || input.at > fields["end"].as_i64().unwrap()
                || input.amount < 0
                || input.amount > fields["limit"].as_i64().unwrap()
            {
                return Err(Error::new(
                    "invariant",
                    "hidden reservation SECRET_AMOUNT_3 outside parent bounds",
                ));
            }
        }
        Ok(())
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
        oracle(store)?;
        Ok(json!({"valid":true}))
    }
}
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn input(kind: u16, parent: Option<u128>) -> Input {
    Input {
        kind,
        parent: parent.map(id),
        parent_kind: 11,
        at: 5,
        amount: 3,
        start: 0,
        end: 10,
        limit: 5,
        body: "private unprojected body".into(),
    }
}
fn create(n: u128, value: Input) -> Value {
    json!({"op":"create","id":id(n),"contract":value.kind,"fields":value})
}
fn request(store: &Store<Schedule>, commands: Value) -> Mutation {
    serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":Uuid::new_v4(),"commands":commands,"returning":[]})).unwrap()
}
fn update(store: &Store<Schedule>, n: u128, set: Value) -> Value {
    json!({"op":"update","id":id(n),"if_version":store.get(store.model().identity(),id(n)).unwrap().unwrap().version,"set":set,"unset":[]})
}
fn delete(store: &Store<Schedule>, n: u128) -> Value {
    json!({"op":"delete","id":id(n),"if_version":store.get(store.model().identity(),id(n)).unwrap().unwrap().version})
}
fn apply(store: &Store<Schedule>, commands: Value) {
    store.mutate(&request(store, commands)).unwrap();
    oracle(store).unwrap();
}
fn reject(store: &Store<Schedule>, commands: Value) {
    let before = store.observe_for_verification().unwrap();
    assert_eq!(
        store.mutate(&request(store, commands)).unwrap_err().code,
        "invariant"
    );
    assert_eq!(store.observe_for_verification().unwrap(), before);
    oracle(store).unwrap();
}
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
// Deliberately enumerate physical source rows; no incoming index, catalog field list,
// production candidate discovery, projected inputs or relationship hook is reused.
fn oracle(store: &Store<Schedule>) -> Result<()> {
    let image = store.observe_for_verification()?;
    assert_eq!(image["complete"], true);
    let mut sources = BTreeMap::new();
    for row in image["tables"]["native_kv"].as_array().unwrap() {
        let key = Key::decode(&unhex(row["key"].as_str().unwrap()))?;
        let value =
            native_codec::decode_for::<Schedule>(&key, &unhex(row["value"].as_str().unwrap()))?;
        if let (Key::Record(id), StoredValue::Record(record)) = (key, value) {
            sources.insert(id, record.input);
        }
    }
    for child in sources.values().filter(|v| v.kind == 21) {
        if let Some(target) = child.parent {
            let parent = sources
                .get(&target)
                .ok_or_else(|| Error::new("corrupt_state", "missing source parent"))?;
            if ![11, 12].contains(&parent.kind)
                || parent.kind != child.parent_kind
                || child.at < parent.start
                || child.at > parent.end
                || child.amount < 0
                || child.amount > parent.limit
            {
                return Err(Error::new(
                    "corrupt_state",
                    "literal source relationship invalid",
                ));
            }
        }
    }
    Ok(())
}
struct Fixture {
    store: Store<Schedule>,
    directory: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("relationship-predicates-{}", Uuid::new_v4()));
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

#[test]
fn final_graph_bounds_parent_invalidation_and_reopen() {
    hidden_child_still_revalidated();
    // One test keeps the diagnostic hook counter independent of parallel tests.
    for reverse in [false, true] {
        let fixture = Fixture::new();
        let store = &fixture.store;
        let mut boundary = input(21, Some(90));
        boundary.at = 10;
        boundary.amount = 5;
        let p = create(90, input(11, None));
        let c = create(190, boundary);
        apply(
            store,
            if reverse {
                json!([c, p])
            } else {
                json!([p, c])
            },
        );
        let mut bad = input(21, Some(100));
        bad.at = 11;
        apply(store, json!([create(100, input(11, None))]));
        reject(store, json!([create(200, bad)]));
        let mut bad = input(21, Some(100));
        bad.amount = 6;
        reject(store, json!([create(200, bad)]));
        apply(store, json!([create(200, input(21, Some(100)))]));
        reject(store, json!([update(store, 100, json!({"start":6}))]));
        reject(store, json!([update(store, 100, json!({"limit":2}))]));
        let parent = update(store, 100, json!({"start":6,"limit":2}));
        let child = update(store, 200, json!({"at":7,"amount":2}));
        apply(
            store,
            if reverse {
                json!([child, parent])
            } else {
                json!([parent, child])
            },
        );
        let before_calls = CALLS.load(Ordering::SeqCst);
        // Relevant source fields are unchanged: body edits must not re-run child rules.
        store
            .mutate(&request(
                store,
                json!([update(store, 100, json!({"body":"changed"}))]),
            ))
            .unwrap();
        assert_eq!(CALLS.load(Ordering::SeqCst), before_calls);
        oracle(store).unwrap();
        let mut alternative = input(12, None);
        alternative.start = 6;
        alternative.limit = 2;
        apply(store, json!([create(101, alternative)]));
        let retarget = update(store, 200, json!({"parent":id(101),"parent_kind":12}));
        let old_parent = update(store, 100, json!({"end":0,"limit":0}));
        apply(
            store,
            if reverse {
                json!([retarget, old_parent])
            } else {
                json!([old_parent, retarget])
            },
        );
        // NativeInput's historical contract hint stays 11; actual target 12
        // is admitted by the catalog union and still invalidates this child.
        reject(store, json!([update(store, 101, json!({"limit":1}))]));
        // Optional absence has no parent projection, even with otherwise failing values.
        let mut optional = input(21, None);
        optional.at = 100;
        optional.amount = -1;
        apply(store, json!([create(201, optional)]));
        let p = delete(store, 101);
        let c = delete(store, 200);
        apply(
            store,
            if reverse {
                json!([c, p])
            } else {
                json!([p, c])
            },
        );
        store.check_integrity().unwrap();
        let before = store.observe_for_verification().unwrap();
        let path = fixture.directory.join("store.redb");
        let model = Arc::new(Prepared::<Schedule>::load().unwrap());
        // Drop the only open handle before reopening the durable redb file.
        let Fixture { store, directory } = fixture;
        drop(store);
        let reopened = Store::<Schedule>::open(&path, model).unwrap();
        assert_eq!(reopened.observe_for_verification().unwrap(), before);
        reopened.check_integrity().unwrap();
        oracle(&reopened).unwrap();
        drop(reopened);
        std::fs::remove_dir_all(directory).unwrap();
    }
}

fn hidden_child_still_revalidated() {
    use rebase_semantic_proof::{
        access::{Action, Grants, Graph, Principal, PrincipalKind},
        security::ReplaceGraph,
    };
    use std::collections::BTreeSet;
    let directory = std::env::temp_dir().join(format!("relationship-hidden-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    let context = Context {
        tenant: id(1),
        actor: id(2),
    };
    let model = Arc::new(Prepared::<Schedule>::load().unwrap());
    let admin =
        Store::<Schedule>::create_secured(directory.join("store.redb"), model.clone(), context)
            .unwrap();
    let mut graph = Graph::bootstrap(context).unwrap().graph;
    for (n, parents, contracts) in [
        (3, vec![id(1)], vec![11, 12]),
        (4, vec![id(3)], vec![11, 12, 21]),
    ] {
        graph.principals.push(Principal {
            id: id(n),
            kind: if n == 3 {
                PrincipalKind::Group
            } else {
                PrincipalKind::User
            },
            parents,
            active: true,
            credential_epoch: 0,
            grants: Grants {
                admin: false,
                contracts: contracts
                    .into_iter()
                    .map(|c| {
                        (
                            c,
                            BTreeSet::from([
                                Action::Read,
                                Action::Create,
                                Action::Update,
                                Action::Delete,
                            ]),
                        )
                    })
                    .collect(),
            },
        });
    }
    let revision = admin.access_graph(model.identity()).unwrap()["revision"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    admin
        .replace_access(&ReplaceGraph {
            model: model.identity().into(),
            if_revision: revision,
            graph,
        })
        .unwrap();
    let parent_owner = admin.session(id(3), 0).unwrap();
    let child_owner = admin.session(id(4), 0).unwrap();
    apply(&parent_owner, json!([create(100, input(11, None))]));
    apply(&child_owner, json!([create(200, input(21, Some(100)))]));
    assert!(
        parent_owner
            .get(model.identity(), id(200))
            .unwrap()
            .is_none()
    );
    let before = admin.observe_for_verification().unwrap();
    let error = parent_owner
        .mutate(&request(
            &parent_owner,
            json!([update(&parent_owner, 100, json!({"limit":2}))]),
        ))
        .unwrap_err();
    assert_eq!(error.code, "invariant");
    assert_eq!(error.detail, "relationship validation failed");
    assert!(!error.detail.contains("SECRET_AMOUNT_3"));
    assert_eq!(admin.observe_for_verification().unwrap(), before);
    oracle(&admin).unwrap();
    admin.check_integrity().unwrap();
    drop(child_owner);
    drop(parent_owner);
    drop(admin);
    std::fs::remove_dir_all(directory).unwrap();
}

/// Shared mutation/rule primitive only: this isolates protected native reads
/// from Store authentication, cursor epochs, publication and receipt writes.
#[cfg(feature = "foundationdb")]
#[test]
#[ignore = "requires NEXT_BASE_FDB_CLUSTER and an explicit local FoundationDB run"]
fn foundationdb_parent_child_write_skew_conflicts_in_both_commit_orders() {
    use rebase_semantic_proof::{
        mutation,
        native_slice::Command,
        storage::{self, ReadableTable, TableDefinition, WriteTransaction},
    };
    const KV: TableDefinition<&[u8], &[u8]> = TableDefinition::new("native_kv");
    let cluster = std::env::var("NEXT_BASE_FDB_CLUSTER")
        .expect("NEXT_BASE_FDB_CLUSTER required for explicit FDB proof");
    let _network = unsafe { foundationdb::boot() };
    let context = Context {
        tenant: id(1),
        actor: id(2),
    };
    let model = Arc::new(Prepared::<Schedule>::load().unwrap());
    fn stage(
        tx: &WriteTransaction,
        model: &Prepared<Schedule>,
        context: Context,
        command: Command,
    ) {
        let mut table = tx.open_table(KV).unwrap();
        let mut ws = Attempt::<_, Schedule>::new(
            |key: &[u8]| Ok(table.get(key)?.map(|value| value.value().to_vec())),
            100_000,
        );
        mutation::settle_authorized(
            &mut ws,
            model,
            context,
            &[command],
            &mut || panic!("source-only updates must not allocate outputs"),
            false,
            &mut |_, _, _, _| Ok(()),
            &mut |_, _| Ok(()),
        )
        .unwrap();
        let batch = ws.finish().unwrap();
        // Population, receipts, epochs and other shared keys must not supply
        // accidental write/write isolation for these source-only updates.
        assert_eq!(batch.len(), 1);
        let only_key = batch.keys().next().unwrap();
        assert!(
            *only_key == Key::Record(id(100)).encode()
                || *only_key == Key::Record(id(200)).encode()
        );
        drop(ws);
        for (key, value) in batch {
            table.insert(key, value.unwrap().as_slice()).unwrap();
        }
    }
    for parent_first in [true, false] {
        let namespace = format!("next-base-relationship-primitive-{}", Uuid::new_v4());
        let db = storage::foundationdb::connect(Some(&cluster), namespace.as_bytes()).unwrap();
        let store = Store::<Schedule>::create_backend(db, model.clone(), context).unwrap();
        apply(
            &store,
            json!([
                create(100, input(11, None)),
                create(200, input(21, Some(100)))
            ]),
        );
        let parent_command: Command =
            serde_json::from_value(update(&store, 100, json!({"limit":4}))).unwrap();
        let child_command: Command =
            serde_json::from_value(update(&store, 200, json!({"amount":5}))).unwrap();
        let raw = storage::foundationdb::connect(Some(&cluster), namespace.as_bytes()).unwrap();
        {
            let read = raw.begin_read().unwrap();
            let table = read.open_table(KV).unwrap();
            assert!(table.get([13u8]).unwrap().is_none());
        }
        let parent_tx = raw.begin_write().unwrap();
        let child_tx = raw.begin_write().unwrap();
        // Both valid old-snapshot plans finish before either commit. Their
        // combination would be amount 5 > limit 4, despite disjoint writes.
        stage(&parent_tx, &model, context, parent_command);
        stage(&child_tx, &model, context, child_command);
        if parent_first {
            parent_tx.commit().unwrap();
            assert_eq!(child_tx.commit().unwrap_err().code, "transaction_conflict");
        } else {
            child_tx.commit().unwrap();
            assert_eq!(parent_tx.commit().unwrap_err().code, "transaction_conflict");
        }
        let parent = store.get(model.identity(), id(100)).unwrap().unwrap().input;
        let child = store.get(model.identity(), id(200)).unwrap().unwrap().input;
        assert!(child.amount <= parent.limit);
        assert_eq!(
            (parent.limit, child.amount),
            if parent_first { (4, 3) } else { (5, 5) }
        );
        oracle(&store).unwrap();
        let read = raw.begin_read().unwrap();
        let table = read.open_table(KV).unwrap();
        assert!(table.get([13u8]).unwrap().is_none());
    }
}
