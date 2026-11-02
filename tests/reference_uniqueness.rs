//! Scoped reference claims checked against literal source fields, never writer caches.
use rebase_semantic_proof::{
    binding::{Binding, NativeInput},
    indexes::standard::Standard,
    local::{Mutation, Store},
    model::{self, Contract, InputField, Prepared, Reference, Unique, Visibility},
    native_codec::{self, Key, StoredValue},
    native_slice::{Attempt, Context, Error, Model, ModelChange, Population, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Relations;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    kind: u16,
    #[serde(default)]
    first: Option<Uuid>,
    #[serde(default)]
    second: Option<Uuid>,
    note: String,
}
impl NativeInput for Input {
    fn contract(&self) -> u16 {
        self.kind
    }
    fn validate(&self) -> Result<()> {
        Ok(())
    }
    fn bind(code: u16, fields: Value) -> Result<Self> {
        let input: Self = serde_json::from_value(fields.clone())
            .map_err(|e| Error::new("invalid_input", e.to_string()))?;
        if input.kind != code || serde_json::to_value(&input).unwrap() != fields {
            return Err(Error::new("invalid_input", "canonical input required"));
        }
        Ok(input)
    }
    fn references(&self) -> Vec<(Uuid, u16, u16)> {
        let mut result = vec![];
        if self.kind != 11 {
            if let Some(target) = self.first {
                result.push((target, 11, 1));
            }
            if let Some(target) = self.second {
                result.push((target, 11, 2));
            }
        }
        result
    }
}
impl Binding for Relations {
    type Index = Standard;
    type Input = Input;
    type Derived = ();
    type Outcome = ();
    const NAME: &'static str = "test-reference-uniqueness";
    const BEHAVIOR: &'static str = "test-reference-uniqueness-1";
    fn engine() -> Result<Model> {
        Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
    }
    fn declarations() -> Result<Vec<Contract>> {
        let uuid = json!({"type":["string","null"],"pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$","x-rebase-binding":"uuid"});
        Ok([(11,"Target"),(21,"Single"),(22,"Pair"),(23,"OtherSingle")].into_iter().map(|(code,name)| {
            let mut properties = json!({"kind":{"type":"integer","enum":[code]},"note":{"type":"string"},"first":uuid.clone(),"second":uuid.clone()});
            let fields = vec![InputField{code:10,name:"kind",mutable:false},InputField{code:11,name:"note",mutable:true},InputField{code:1,name:"first",mutable:true},InputField{code:2,name:"second",mutable:true}];
            let mut references = vec![];
            for (slot,field) in [(1,"first"),(2,"second")] {
                if code == 11 || (slot == 2 && code != 22) {continue;}
                properties[field] = uuid.clone();
                references.push(Reference{slot,field,targets:vec![11],optional:true,direct_fields:vec![],on_delete:"reject",reader:false});
            }
            Contract {code,name,visibility:Visibility::Public,
                schema:json!({"$schema":model::SCHEMA_DIALECT,"type":"object","additionalProperties":false,"properties":properties,"required":["kind","note","first","second"]}),
                fields,published:vec![],references,
                uniqueness:if code == 11 {vec![]} else {vec![Unique{code:1,reference_slots:if code == 22 {vec![1,2]} else {vec![1]}}]},
                roots:vec![],memberships:vec![],queries:vec![],publication_inputs:vec![],outputs:vec![],calculations:vec![],calculation_order:vec![],rules:vec![],schema_source:"tests/reference_uniqueness.rs",behavior_source:"tests/reference_uniqueness.rs"}
        }).collect())
    }
    fn valid_derived(_: &Input, derived: Option<&()>) -> bool {
        derived.is_none()
    }
    fn published_shape(_: u16) -> Value {
        Value::Null
    }
    fn settle_changes<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Attempt<L, Self>,
        _: &Prepared<Self>,
        _: Context,
        changes: &[ModelChange<Self>],
        _: &mut Population,
        revision: Uuid,
        _: &mut dyn FnMut() -> Result<Uuid>,
    ) -> Result<()> {
        // Test-only derivation: a model settlement writes a second record absent
        // from client commands. Claim reconciliation must discover this write.
        if changes.iter().any(|change| {
            change
                .new
                .as_ref()
                .is_some_and(|record| record.input.note == "settle-other-link")
        }) {
            let mut output = ws
                .record(id(201))?
                .ok_or_else(|| Error::new("corrupt_state", "test settlement output missing"))?;
            output.input.first = Some(id(102));
            output.version = revision;
            ws.put(Key::Record(id(201)), Some(StoredValue::Record(output)))?;
        }
        Ok(())
    }
    fn check(store: &Store<Self>) -> Result<Value> {
        inventory(store)?;
        Ok(json!({"valid":true}))
    }
}
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
struct Fixture {
    store: Store<Relations>,
    directory: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("reference-uniqueness-{}", Uuid::new_v4()));
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
        let fixture = Self { store, directory };
        apply(
            &fixture.store,
            json!([
                create(100, 11, None, None),
                create(101, 11, None, None),
                create(102, 11, None, None),
                create(103, 11, None, None)
            ]),
        );
        fixture
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
fn create(n: u128, kind: u16, first: Option<u128>, second: Option<u128>) -> Value {
    let input = Input {
        kind,
        first: first.map(id),
        second: second.map(id),
        note: String::new(),
    };
    json!({"op":"create","id":id(n),"contract":kind,"fields":input})
}
fn request(store: &Store<Relations>, commands: Value) -> Mutation {
    serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":Uuid::new_v4(),"commands":commands,"returning":[]})).unwrap()
}
fn update(store: &Store<Relations>, n: u128, set: Value, unset: Value) -> Value {
    json!({"op":"update","id":id(n),"if_version":store.get(store.model().identity(),id(n)).unwrap().unwrap().version.to_string(),"set":set,"unset":unset})
}
fn delete(store: &Store<Relations>, n: u128) -> Value {
    json!({"op":"delete","id":id(n),"if_version":store.get(store.model().identity(),id(n)).unwrap().unwrap().version.to_string()})
}
fn apply(store: &Store<Relations>, commands: Value) {
    store.mutate(&request(store, commands)).unwrap();
    inventory(store).unwrap();
}
fn reject(store: &Store<Relations>, commands: Value) {
    let before = store.observe_for_verification().unwrap();
    let error = store.mutate(&request(store, commands)).unwrap_err();
    assert_eq!(error.code, "invariant");
    assert_eq!(store.observe_for_verification().unwrap(), before);
    inventory(store).unwrap();
}
fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
type Claims = BTreeMap<(u16, u16, Vec<Uuid>), Uuid>;
fn inventory(store: &Store<Relations>) -> Result<Claims> {
    let image = store.observe_for_verification()?;
    assert_eq!(image["complete"], true);
    let mut expected = Claims::new();
    let mut actual = Claims::new();
    for row in image["tables"]["native_kv"].as_array().unwrap() {
        let key = Key::decode(&unhex(row["key"].as_str().unwrap()))?;
        let value =
            native_codec::decode_for::<Relations>(&key, &unhex(row["value"].as_str().unwrap()))?;
        match (key, value) {
            (Key::Record(holder), StoredValue::Record(record)) => {
                let input = record.input;
                // Deliberately match test source fields, without catalog or writer claim helper.
                let targets = match (input.kind, input.first, input.second) {
                    (21 | 23, Some(first), _) => Some(vec![first]),
                    (22, Some(first), Some(second)) => Some(vec![first, second]),
                    _ => None,
                };
                if let Some(targets) = targets
                    && expected.insert((input.kind, 1, targets), holder).is_some()
                {
                    return Err(Error::new("corrupt_state", "duplicate source tuple"));
                }
            }
            (
                Key::Unique {
                    contract,
                    constraint,
                    targets,
                },
                StoredValue::Unique(holder),
            ) => {
                actual.insert((contract, constraint, targets), holder);
            }
            _ => {}
        }
    }
    if expected != actual {
        return Err(Error::new(
            "corrupt_state",
            "source-derived uniqueness inventory differs",
        ));
    }
    Ok(actual)
}

#[test]
fn scoped_scalar_optional_pairs_and_exact_rollback() {
    let f = Fixture::new();
    let s = &f.store;
    apply(
        s,
        json!([
            create(200, 21, Some(100), None),
            create(201, 21, None, None),
            create(202, 21, None, None),
            create(203, 23, Some(100), None)
        ]),
    );
    reject(s, json!([create(204, 21, Some(100), None)]));
    reject(
        s,
        json!([update(s, 201, json!({"first":id(100)}), json!([]))]),
    );
    apply(
        s,
        json!([update(s, 200, json!({"note":"payload edit"}), json!([]))]),
    );
    apply(
        s,
        json!([
            create(300, 22, Some(100), Some(101)),
            create(301, 22, Some(101), Some(100)),
            create(302, 22, Some(100), Some(102)),
            create(303, 22, Some(102), Some(101)),
            create(304, 22, Some(100), Some(100)),
            create(305, 22, Some(100), None),
            create(306, 22, Some(100), None),
            create(307, 22, None, Some(101))
        ]),
    );
    reject(s, json!([create(308, 22, Some(100), Some(101))]));
    reject(
        s,
        json!([update(s, 305, json!({"second":id(101)}), json!([]))]),
    );
    apply(
        s,
        json!([
            update(s, 300, json!({"second":null}), json!([])),
            update(s, 305, json!({"second":id(101)}), json!([]))
        ]),
    );
    assert_eq!(inventory(s).unwrap().len(), 7);
}
#[test]
fn swaps_and_three_cycles_accept_every_command_permutation() {
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let f = Fixture::new();
        let s = &f.store;
        apply(
            s,
            json!([
                create(200, 21, Some(100), None),
                create(201, 21, Some(101), None),
                create(202, 21, Some(102), None)
            ]),
        );
        let commands = [
            update(s, 200, json!({"first":id(101)}), json!([])),
            update(s, 201, json!({"first":id(102)}), json!([])),
            update(s, 202, json!({"first":id(100)}), json!([])),
        ];
        apply(
            s,
            Value::Array(order.into_iter().map(|i| commands[i].clone()).collect()),
        );
        let expected = Claims::from([
            ((21, 1, vec![id(101)]), id(200)),
            ((21, 1, vec![id(102)]), id(201)),
            ((21, 1, vec![id(100)]), id(202)),
        ]);
        assert_eq!(inventory(s).unwrap(), expected);
        let swap = [
            update(s, 200, json!({"first":id(102)}), json!([])),
            update(s, 201, json!({"first":id(101)}), json!([])),
        ];
        apply(
            s,
            Value::Array(if order[0] % 2 == 0 {
                swap.to_vec()
            } else {
                swap.into_iter().rev().collect()
            }),
        );
        assert_eq!(
            inventory(s).unwrap().get(&(21, 1, vec![id(102)])),
            Some(&id(200))
        );
    }
}
#[test]
fn delete_then_reuse_is_final_graph_order_independent() {
    for reverse in [false, true] {
        let f = Fixture::new();
        let s = &f.store;
        apply(
            s,
            json!([
                create(200, 21, Some(100), None),
                create(201, 21, Some(101), None)
            ]),
        );
        let mut commands = vec![
            delete(s, 200),
            update(s, 201, json!({"first":id(100)}), json!([])),
        ];
        if reverse {
            commands.reverse();
        }
        apply(s, Value::Array(commands));
        assert_eq!(
            inventory(s).unwrap(),
            Claims::from([((21, 1, vec![id(100)]), id(201))])
        );
    }
}

#[test]
fn prepared_catalog_rejects_ambiguous_constraints_and_binds_identity() {
    let base = Relations::declarations().unwrap();
    for malformed in [
        vec![Unique {
            code: 0,
            reference_slots: vec![1],
        }],
        vec![Unique {
            code: 1,
            reference_slots: vec![],
        }],
        vec![Unique {
            code: 1,
            reference_slots: vec![99],
        }],
        vec![Unique {
            code: 1,
            reference_slots: vec![1, 1],
        }],
        vec![
            Unique {
                code: 1,
                reference_slots: vec![1],
            },
            Unique {
                code: 1,
                reference_slots: vec![1],
            },
        ],
    ] {
        let mut declarations = base.clone();
        declarations
            .iter_mut()
            .find(|c| c.code == 21)
            .unwrap()
            .uniqueness = malformed;
        assert!(Prepared::<Relations>::prepare(declarations).is_err());
    }
    let original = Prepared::<Relations>::prepare(base.clone()).unwrap();
    let mut reversed = base.clone();
    reversed
        .iter_mut()
        .find(|c| c.code == 22)
        .unwrap()
        .uniqueness[0]
        .reference_slots
        .reverse();
    assert_ne!(
        original.identity(),
        Prepared::<Relations>::prepare(reversed).unwrap().identity()
    );
    let mut renamed = base;
    renamed
        .iter_mut()
        .find(|c| c.code == 21)
        .unwrap()
        .uniqueness[0]
        .code = 2;
    assert_ne!(
        original.identity(),
        Prepared::<Relations>::prepare(renamed).unwrap().identity()
    );
}

/// Real-adapter claim primitive proof. This deliberately excludes the full
/// mutation runner: no Population, reader/contract epoch, or authority keys exist.
#[cfg(feature = "foundationdb")]
#[test]
#[ignore = "requires explicit local FoundationDB cluster"]
fn foundationdb_claim_primitive_protects_absence_and_preserves_disjointness() {
    use rebase_semantic_proof::{
        native_slice::ModelRecord,
        storage::{self, ReadableTable, TableDefinition, WriteTransaction},
        uniqueness,
    };
    const KV: TableDefinition<&[u8], &[u8]> = TableDefinition::new("native_kv");
    let cluster = std::env::var("NEXT_BASE_FDB_CLUSTER")
        .expect("NEXT_BASE_FDB_CLUSTER required for explicit FDB proof");
    let _network = unsafe { foundationdb::boot() };
    let namespace = format!("next-base-unique-primitive-{}", Uuid::new_v4());
    let db = storage::foundationdb::connect(Some(&cluster), namespace.as_bytes()).unwrap();
    let model = Prepared::<Relations>::load().unwrap();
    let setup = db.begin_write().unwrap();
    setup.open_table(KV).unwrap();
    setup.commit().unwrap();
    fn stage(tx: &WriteTransaction, model: &Prepared<Relations>, holder: u128, target: u128) {
        let mut table = tx.open_table(KV).unwrap();
        let mut ws = Attempt::<_, Relations>::new(
            |key: &[u8]| Ok(table.get(key)?.map(|value| value.value().to_vec())),
            100_000,
        );
        let source = ModelRecord {
            contract: 21,
            tenant: id(1),
            owner: id(2),
            reader: id(2),
            version: Uuid::new_v4(),
            input: Input {
                kind: 21,
                first: Some(id(target)),
                second: None,
                note: String::new(),
            },
            derived: None,
        };
        ws.put(Key::Record(id(holder)), Some(StoredValue::Record(source)))
            .unwrap();
        uniqueness::reconcile(&mut ws, model).unwrap();
        let batch = ws.finish().unwrap();
        drop(ws);
        for (key, value) in batch {
            match value {
                Some(value) => {
                    table.insert(key, value.as_slice()).unwrap();
                }
                None => {
                    table.remove(key).unwrap();
                }
            }
        }
    }
    // Both attempts protect the same absent tuple before either commits.
    let first = db.begin_write().unwrap();
    let second = db.begin_write().unwrap();
    stage(&first, &model, 200, 100);
    stage(&second, &model, 201, 100);
    first.commit().unwrap();
    assert_eq!(second.commit().unwrap_err().code, "transaction_conflict");
    {
        let read = db.begin_read().unwrap();
        let table = read.open_table(KV).unwrap();
        let key = Key::Unique {
            contract: 21,
            constraint: 1,
            targets: vec![id(100)],
        };
        let value = table.get(key.encode()).unwrap().unwrap();
        assert_eq!(
            native_codec::decode_for::<Relations>(&key, value.value()).unwrap(),
            StoredValue::Unique(id(200))
        );
        assert!(table.get(Key::Record(id(200)).encode()).unwrap().is_some());
        assert!(table.get(Key::Record(id(201)).encode()).unwrap().is_none());
        assert_eq!(table.iter().unwrap().count(), 2);
    }
    // Disjoint holders and tuples share no mutable coordination key.
    let third = db.begin_write().unwrap();
    let fourth = db.begin_write().unwrap();
    stage(&third, &model, 202, 101);
    stage(&fourth, &model, 203, 102);
    third.commit().unwrap();
    fourth.commit().unwrap();
    let read = db.begin_read().unwrap();
    let table = read.open_table(KV).unwrap();
    assert_eq!(table.iter().unwrap().count(), 6);
    for (holder, target) in [(200, 100), (202, 101), (203, 102)] {
        let key = Key::Unique {
            contract: 21,
            constraint: 1,
            targets: vec![id(target)],
        };
        assert_eq!(
            native_codec::decode_for::<Relations>(
                &key,
                table.get(key.encode()).unwrap().unwrap().value()
            )
            .unwrap(),
            StoredValue::Unique(id(holder))
        );
        assert!(
            table
                .get(Key::Record(id(holder)).encode())
                .unwrap()
                .is_some()
        );
    }
    drop(read);
    // Each explicit run receives an isolated namespace; clean its test table.
    let cleanup = db.begin_write().unwrap();
    cleanup.delete_table(KV).unwrap();
    cleanup.commit().unwrap();
}

#[test]
fn constraint_codes_namespace_identical_target_tuples_within_one_contract() {
    use rebase_semantic_proof::{native_slice::ModelRecord, uniqueness};
    let mut declarations = Relations::declarations().unwrap();
    declarations
        .iter_mut()
        .find(|c| c.code == 22)
        .unwrap()
        .uniqueness = vec![
        Unique {
            code: 1,
            reference_slots: vec![1],
        },
        Unique {
            code: 2,
            reference_slots: vec![2],
        },
    ];
    let model = Prepared::<Relations>::prepare(declarations).unwrap();
    let mut ws = Attempt::<_, Relations>::new(|_: &[u8]| Ok(None), 100_000);
    // Each target appears in both constraint scopes, with different holders.
    // Collapsing either constraint code or tuple order loses this legal state.
    for (holder, first, second) in [(200, 100, 101), (201, 101, 100)] {
        let record = ModelRecord {
            contract: 22,
            tenant: id(1),
            owner: id(2),
            reader: id(2),
            version: Uuid::new_v4(),
            input: Input {
                kind: 22,
                first: Some(id(first)),
                second: Some(id(second)),
                note: String::new(),
            },
            derived: None,
        };
        ws.put(Key::Record(id(holder)), Some(StoredValue::Record(record)))
            .unwrap();
    }
    uniqueness::reconcile(&mut ws, &model).unwrap();
    for (constraint, target, holder) in [(1, 100, 200), (1, 101, 201), (2, 101, 200), (2, 100, 201)]
    {
        assert_eq!(
            ws.get(&Key::Unique {
                contract: 22,
                constraint,
                targets: vec![id(target)]
            })
            .unwrap(),
            Some(StoredValue::Unique(id(holder)))
        );
    }
    assert_eq!(ws.finish().unwrap().len(), 6);
}

#[test]
fn settlement_only_source_edit_moves_its_claim_and_conflicts_roll_back() {
    let f = Fixture::new();
    let s = &f.store;
    apply(
        s,
        json!([
            create(200, 21, Some(100), None),
            create(201, 21, Some(101), None)
        ]),
    );
    // Only record 200 is a command; settlement alone changes record 201.
    apply(
        s,
        json!([update(
            s,
            200,
            json!({"note":"settle-other-link"}),
            json!([])
        )]),
    );
    assert_eq!(
        inventory(s).unwrap(),
        Claims::from([
            ((21, 1, vec![id(100)]), id(200)),
            ((21, 1, vec![id(102)]), id(201)),
        ])
    );
    apply(
        s,
        json!([
            update(s, 201, json!({"first":id(101)}), json!([])),
            create(202, 21, Some(102), None)
        ]),
    );
    // Model settlement now tries to acquire record 202's claim. Full image,
    // including the otherwise valid client note edit, must remain unchanged.
    reject(
        s,
        json!([update(
            s,
            200,
            json!({"note":"settle-other-link"}),
            json!([])
        )]),
    );
}

#[test]
fn nil_uuid_is_an_ordinary_complete_target_not_an_optional_absence() {
    let f = Fixture::new();
    let s = &f.store;
    apply(
        s,
        json!([
            create(0, 11, None, None),
            create(200, 21, Some(0), None),
            create(201, 21, None, None)
        ]),
    );
    assert_eq!(
        inventory(s).unwrap(),
        Claims::from([((21, 1, vec![Uuid::nil()]), id(200))])
    );
    reject(
        s,
        json!([update(s, 201, json!({"first":Uuid::nil()}), json!([]))]),
    );
    apply(
        s,
        json!([
            update(s, 200, json!({"first":null}), json!([])),
            update(s, 201, json!({"first":Uuid::nil()}), json!([]))
        ]),
    );
    assert_eq!(
        inventory(s).unwrap(),
        Claims::from([((21, 1, vec![Uuid::nil()]), id(201))])
    );
}

#[test]
fn claim_load_failure_discards_a_partially_staged_workspace() {
    use rebase_semantic_proof::{
        native_slice::ModelRecord,
        storage::{Database, ReadableTable, TableDefinition},
        uniqueness,
    };
    const KV: TableDefinition<&[u8], &[u8]> = TableDefinition::new("native_kv");
    let directory = std::env::temp_dir().join(format!("unique-load-failure-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    let db = Database::create(directory.join("store.redb")).unwrap();
    let setup = db.begin_write().unwrap();
    setup
        .open_table(KV)
        .unwrap()
        .insert(b"baseline", b"unchanged".as_slice())
        .unwrap();
    setup.commit().unwrap();
    let model = Prepared::<Relations>::load().unwrap();
    let first_claim = Key::Unique {
        contract: 21,
        constraint: 1,
        targets: vec![id(100)],
    };
    let failing_claim = Key::Unique {
        contract: 21,
        constraint: 1,
        targets: vec![id(101)],
    }
    .encode();
    let transaction = db.begin_write().unwrap();
    {
        let table = transaction.open_table(KV).unwrap();
        let mut ws = Attempt::<_, Relations>::new(
            |key: &[u8]| {
                if key == failing_claim.as_slice() {
                    return Err(Error::new("storage", "injected claim load failure"));
                }
                Ok(table.get(key)?.map(|value| value.value().to_vec()))
            },
            100_000,
        );
        for (holder, target) in [(200, 100), (201, 101)] {
            let record = ModelRecord {
                contract: 21,
                tenant: id(1),
                owner: id(2),
                reader: id(2),
                version: Uuid::new_v4(),
                input: Input {
                    kind: 21,
                    first: Some(id(target)),
                    second: None,
                    note: String::new(),
                },
                derived: None,
            };
            ws.put(Key::Record(id(holder)), Some(StoredValue::Record(record)))
                .unwrap();
        }
        assert_eq!(
            uniqueness::reconcile(&mut ws, &model).unwrap_err().code,
            "storage"
        );
        assert_eq!(
            ws.get(&first_claim).unwrap(),
            Some(StoredValue::Unique(id(200)))
        );
        // No finish/publication after an error; partial claims remain overlay only.
    }
    drop(transaction);
    let read = db.begin_read().unwrap();
    let table = read.open_table(KV).unwrap();
    assert_eq!(table.iter().unwrap().count(), 1);
    assert_eq!(
        table.get(b"baseline").unwrap().unwrap().value(),
        b"unchanged"
    );
    assert!(table.get(first_claim.encode()).unwrap().is_none());
    assert!(table.get(Key::Record(id(200)).encode()).unwrap().is_none());
    drop(table);
    drop(read);
    drop(db);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn hidden_reference_authorization_precedes_occupied_unique_claim_disclosure() {
    use rebase_semantic_proof::{
        access::{Action, Grants, Graph, Principal, PrincipalKind},
        security::ReplaceGraph,
    };
    use std::collections::BTreeSet;
    let directory =
        std::env::temp_dir().join(format!("unique-hidden-reference-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    let model = Arc::new(Prepared::<Relations>::load().unwrap());
    let context = Context {
        tenant: id(1),
        actor: id(2),
    };
    let admin =
        Store::<Relations>::create_secured(directory.join("store.redb"), model.clone(), context)
            .unwrap();
    let mut graph = Graph::bootstrap(context).unwrap().graph;
    for actor in [3, 4] {
        graph.principals.push(Principal {
            id: id(actor),
            kind: PrincipalKind::User,
            parents: vec![id(1)],
            active: true,
            credential_epoch: 0,
            grants: Grants {
                admin: false,
                contracts: [11, 21, 22, 23]
                    .into_iter()
                    .map(|contract| {
                        (
                            contract,
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
    let owner = admin.session(id(3), 0).unwrap();
    let peer = admin.session(id(4), 0).unwrap();
    apply(
        &owner,
        json!([
            create(100, 11, None, None),
            create(200, 21, Some(100), None)
        ]),
    );
    let before = admin.observe_for_verification().unwrap();
    // The peer knows the target UUID but cannot read its owner-private record.
    // Occupied and unoccupied claim probes must both stop at reference access.
    for (holder, contract) in [(201, 21), (202, 23)] {
        let error = peer
            .mutate(&request(
                &peer,
                json!([create(holder, contract, Some(100), None)]),
            ))
            .unwrap_err();
        assert_eq!(error.code, "forbidden");
        assert_eq!(admin.observe_for_verification().unwrap(), before);
    }
    inventory(&admin).unwrap();
    drop(peer);
    drop(owner);
    drop(admin);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn persisted_claims_round_trip_through_redb_reopen() {
    let directory = std::env::temp_dir().join(format!("unique-reopen-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("store.redb");
    let model = Arc::new(Prepared::<Relations>::load().unwrap());
    let store = Store::<Relations>::create(
        &path,
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    apply(
        &store,
        json!([
            create(100, 11, None, None),
            create(200, 21, Some(100), None)
        ]),
    );
    let before = store.observe_for_verification().unwrap();
    drop(store);
    let reopened = Store::<Relations>::open(&path, model).unwrap();
    assert_eq!(reopened.observe_for_verification().unwrap(), before);
    reopened.check_integrity().unwrap();
    assert_eq!(
        inventory(&reopened).unwrap(),
        Claims::from([((21, 1, vec![id(100)]), id(200))])
    );
    reject(&reopened, json!([create(201, 21, Some(100), None)]));
    assert_eq!(reopened.observe_for_verification().unwrap(), before);
    drop(reopened);
    std::fs::remove_dir_all(directory).unwrap();
}
