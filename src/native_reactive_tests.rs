//! Source-derived non-time reactive integration: two explicitly declared roots
//! share source fields but keep distinct memberships and subscriber identities.
use crate::{
    binding::{Binding, NativeInput},
    causal::{PublicationValue, ReactiveBinding, Read, Resolved, ResolvedShape},
    index::{IndexCode, IndexDescriptor, NativeIndex, SummaryRead},
    integrity::{Snapshot, require},
    local::{Mutation, Store},
    model::{
        self, Contract, InputField, Membership, Prepared, QueryDeclaration, Reference,
        RootDeclaration, Visibility,
    },
    native_codec::{Address, Key, uuid_text},
    native_range::{NativeBound, NativeRange},
    native_slice::{Attempt, Context, Error, Model, ModelChange, ModelRecord, Query, Result},
    order_value::{OrderAtom, OrderKey},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;

const CODE: IndexCode = IndexCode::new(1).unwrap();
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ordered;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum Input {
    Root {
        label: String,
    },
    Entry {
        #[serde(with = "uuid_text")]
        root: Uuid,
        key: OrderKey,
        other: OrderKey,
        amount: i64,
    },
    Reader {
        #[serde(with = "uuid_text")]
        root: Uuid,
        range: NativeRange<OrderKey>,
    },
}
impl NativeInput for Input {
    fn contract(&self) -> u16 {
        match self {
            Self::Root { .. } => 10,
            Self::Entry { .. } => 20,
            Self::Reader { .. } => 30,
        }
    }
    fn validate(&self) -> Result<()> {
        match self {
            Self::Root { label } if label.len() > 32 => {
                return Err(Error::new("invalid_input", "root label bound"));
            }
            Self::Entry {
                key, other, amount, ..
            } => {
                key.validate()?;
                other.validate()?;
                if amount.unsigned_abs() > 1000 {
                    return Err(Error::new("invalid_input", "entry amount bound"));
                }
            }
            Self::Reader { range, .. } => {
                for b in [&range.lower, &range.upper] {
                    if let NativeBound::Included(k) | NativeBound::Excluded(k) = b {
                        k.validate()?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn bind(code: u16, fields: Value) -> Result<Self> {
        let input: Self = serde_json::from_value(fields.clone())
            .map_err(|e| Error::new("invalid_input", e.to_string()))?;
        input.validate()?;
        if input.contract() != code || serde_json::to_value(&input).unwrap() != fields {
            return Err(Error::new("invalid_input", "canonical ordered input"));
        }
        Ok(input)
    }
    fn references(&self) -> Vec<(Uuid, u16, u16)> {
        match self {
            Self::Entry { root, .. } | Self::Reader { root, .. } => vec![(*root, 10, 1)],
            _ => vec![],
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Totals {
    primary: i64,
    secondary: i64,
}
impl NativeIndex for Ordered {
    type Key = OrderKey;
    type Leaf = i64;
    type Summary = i64;
    type QueryResult = i64;
    fn descriptors() -> Vec<IndexDescriptor> {
        vec![IndexDescriptor {
            code: CODE,
            name: "test_ordered_sum",
            reads: vec!["summary", "range"],
            key_schema: OrderKey::schema(),
            leaf_schema: json!({"type":"integer"}),
            summary_schema: json!({"type":"integer"}),
            result_schemas: json!({"summary":{"type":"integer"},"range":{"type":"integer"}}),
            time: false,
            financial: false,
            quote: false,
        }]
    }
    fn validate_key(code: IndexCode, key: &OrderKey) -> Result<()> {
        Self::empty(code)?;
        key.validate()
    }
    fn validate_leaf(code: IndexCode, _leaf: &i64) -> Result<()> {
        Self::empty(code).map(|_| ())
    }
    fn validate_summary(code: IndexCode, _summary: &i64) -> Result<()> {
        Self::empty(code).map(|_| ())
    }
    fn empty(code: IndexCode) -> Result<i64> {
        if code == CODE {
            Ok(0)
        } else {
            Err(Error::new("corrupt_state", "ordered code"))
        }
    }
    fn singleton(code: IndexCode, key: &OrderKey, leaf: &i64) -> Result<i64> {
        Self::validate_key(code, key)?;
        Ok(*leaf)
    }
    fn combine(code: IndexCode, left: &i64, right: &i64) -> Result<i64> {
        Self::empty(code)?;
        left.checked_add(*right)
            .ok_or_else(|| Error::new("overflow", "ordered sum"))
    }
    fn project(code: IndexCode, read: SummaryRead, summary: &i64) -> Result<Value> {
        Self::empty(code)?;
        if !matches!(read, SummaryRead::Summary | SummaryRead::Range) {
            return Err(Error::new("unsupported_query", "ordered summary"));
        }
        Ok(json!(summary))
    }
    fn supports_query(code: IndexCode, operation: &str, phase: &str, channel: &str) -> bool {
        code == CODE && operation == "summary" && phase == "calculate" && channel == "total"
    }
    fn causal_query(operation: &str) -> bool {
        operation == "summary"
    }
    fn causal_index(code: IndexCode) -> bool {
        code == CODE
    }
    fn validate_query(query: &Query<Self>) -> Result<()> {
        if Self::supports_query(CODE, &query.operation, &query.phase, &query.channel)
            && query.selected.is_none()
        {
            Ok(())
        } else {
            Err(Error::new("corrupt_state", "ordered query"))
        }
    }
    fn query_result(code: IndexCode, operation: &str, summary: &i64) -> Result<i64> {
        if Self::supports_query(code, operation, "calculate", "total") {
            Ok(*summary)
        } else {
            Err(Error::new("corrupt_state", "ordered result"))
        }
    }
}
fn declarations() -> Vec<Contract> {
    let uuid = json!({"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$","x-rebase-binding":"uuid"});
    let key = OrderKey::schema();
    let bound = json!({"oneOf":[{"type":"null"},{"type":"object","properties":{"included":key},"required":["included"],"additionalProperties":false},{"type":"object","properties":{"excluded":key},"required":["excluded"],"additionalProperties":false}]});
    let range = json!({"type":"object","properties":{"lower":bound,"upper":bound},"required":["lower","upper"],"additionalProperties":false});
    [(10,"Root",vec!["label"],json!({"label":{"type":"string","maxLength":32}})),(20,"Entry",vec!["root","key","other","amount"],json!({"root":uuid,"key":key,"other":key,"amount":{"type":"integer","minimum":-1000,"maximum":1000}})),(30,"Reader",vec!["root","range"],json!({"root":uuid,"range":range}))].into_iter().map(|(code,name,names,properties)|{
        let mut c=Contract { access_indexes:vec![],uniqueness:vec![],code,name,visibility:Visibility::Public,schema:json!({"$schema":model::SCHEMA_DIALECT,"type":"object","properties":properties,"required":names,"additionalProperties":false}),fields:names.into_iter().enumerate().map(|(i,name)|InputField{code:i as u16+1,name,mutable:true}).collect(),published:vec![],publication_inputs:vec![],references:vec![],roots:vec![],memberships:vec![],queries:vec![],outputs:vec![],calculations:vec![],calculation_order:vec![],rules:vec![],schema_source:"src/native_reactive_tests.rs",behavior_source:"src/native_reactive_tests.rs" };
        if code==10 { for (slot,name) in [(7,"primary"),(13,"secondary")] {c.roots.push(RootDeclaration {slot,name,kind:CODE,reads:vec!["summary","range"],invariant:None});} }
        else { c.references.push(Reference {slot:1,field:"root",targets:vec![10],optional:false,direct_fields:vec![],validation_fields:vec![],on_delete:"reject"}); }
        if code==20 { for (slot,root_slot,key) in [(11,7,"key"),(17,13,"other")] {c.memberships.push(Membership {slot,through:"root",root_contract:10,root_slot,kind:CODE,key,value:"amount"});} }
        if code==30 {for (slot,root_slot) in [(31,7),(37,13)] {c.queries.push(QueryDeclaration {slot,through:"root",root_contract:10,root_slot,operation:"summary",phase:"calculate",channel:"total",bound:"authored native range",fallback:Some("0")});} c.calculations.push(model::Calculation{name:"primary",inputs:vec![],expression:"query[31]"}); c.calculations.push(model::Calculation{name:"secondary",inputs:vec![],expression:"query[37]"});}
        c
    }).collect()
}
fn member(input: &Input, slot: u16) -> Option<(Address, OrderKey, i64)> {
    if let Input::Entry {
        root,
        key,
        other,
        amount,
    } = input
    {
        Some((
            Address::new(*root, if slot == 11 { 7 } else { 13 }),
            if slot == 11 {
                key.clone()
            } else {
                other.clone()
            },
            *amount,
        ))
    } else {
        None
    }
}
impl Binding for Ordered {
    type Index = Self;
    type Input = Input;
    type Derived = Totals;
    type Outcome = ();
    const NAME: &'static str = "native-ordered-reactive-test";
    const BEHAVIOR: &'static str = "native-ordered-reactive-test-1";
    fn declarations() -> Result<Vec<Contract>> {
        Ok(declarations())
    }
    fn engine() -> Result<Model> {
        Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
    }
    fn valid_derived(input: &Input, derived: Option<&Totals>) -> bool {
        matches!(
            (input, derived),
            (Input::Reader { .. }, Some(_)) | (Input::Root { .. } | Input::Entry { .. }, None)
        )
    }
    fn published_shape(code: u16) -> Value {
        if code == 30 {
            json!({"primary":0,"secondary":0})
        } else {
            Value::Null
        }
    }
    fn settle_changes<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Attempt<L, Self>,
        model: &Prepared<Self>,
        context: Context,
        changes: &[ModelChange<Self>],
        revision: Uuid,
        allocate: &mut dyn FnMut() -> Result<Uuid>,
    ) -> Result<()> {
        for change in changes {
            for slot in [11, 17] {
                crate::mutation::reconcile_member(
                    ws,
                    Address::new(change.id, slot),
                    change.old.as_ref().and_then(|r| member(&r.input, slot)),
                    change.new.as_ref().and_then(|r| member(&r.input, slot)),
                )?;
            }
        }
        crate::causal::settle(ws, model, context, changes, revision, allocate)
    }
    fn check(store: &Store<Self>) -> Result<Value> {
        check(store)
    }
}
impl ReactiveBinding for Ordered {
    type Parameters = ();
    type Publication = ();
    fn resolve<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        _ws: &mut Attempt<L, Self>,
        _context: Context,
        _id: Uuid,
        record: &ModelRecord<Self>,
    ) -> Result<Resolved<(), OrderKey>> {
        let Input::Reader { root, range } = &record.input else {
            return Err(Error::new("model", "ordered reader"));
        };
        Ok(Resolved {
            shape: ResolvedShape {
                reads: [(31, 7), (37, 13)]
                    .into_iter()
                    .map(|(slot, root_slot)| Read {
                        slot,
                        root: Address::new(*root, root_slot),
                        range: range.clone(),
                        validate: false,
                    })
                    .collect(),
                ..Default::default()
            },
            parameters: (),
        })
    }
    fn evaluate(
        _id: Uuid,
        _record: &ModelRecord<Self>,
        _shape: &ResolvedShape<OrderKey>,
        _parameters: &(),
        _publications: &[PublicationValue<()>],
        values: &[i64],
    ) -> Result<(Totals, BTreeMap<u16, i128>)> {
        Ok((
            Totals {
                primary: values[0],
                secondary: values[1],
            },
            BTreeMap::new(),
        ))
    }
}
// Literal source comparisons, never the writer range predicate/tree or evaluator.
fn contains(range: &NativeRange<OrderKey>, key: &OrderKey) -> bool {
    let lo = match &range.lower {
        NativeBound::Unbounded => true,
        NativeBound::Included(k) => key >= k,
        NativeBound::Excluded(k) => key > k,
    };
    let hi = match &range.upper {
        NativeBound::Unbounded => true,
        NativeBound::Included(k) => key <= k,
        NativeBound::Excluded(k) => key < k,
    };
    lo && hi
}
fn check(store: &Store<Ordered>) -> Result<Value> {
    let snapshot = Snapshot::load(store)?;
    let mut members = BTreeMap::new();
    let mut routes = snapshot.routes.clone();
    let mut queries = BTreeMap::new();
    for (&id, record) in &snapshot.records {
        if let Input::Entry {
            root,
            key,
            other,
            amount,
        } = &record.input
        {
            members.insert(
                Address::new(id, 11),
                (Address::new(*root, 7), key.clone(), *amount),
            );
            members.insert(
                Address::new(id, 17),
                (Address::new(*root, 13), other.clone(), *amount),
            );
        }
    }
    for (&id, record) in &snapshot.records {
        if let Input::Reader { root, range } = &record.input {
            let mut sums = vec![];
            for (slot, root_slot) in [(31, 7), (37, 13)] {
                let source = Address::new(*root, root_slot);
                let result = members
                    .values()
                    .filter(|(r, k, _)| r == &source && contains(range, k))
                    .map(|(_, _, v)| *v)
                    .sum::<i64>();
                sums.push(result);
                routes
                    .entry(Key::Subscribers(source))
                    .or_default()
                    .insert(Address::new(id, slot));
                queries.insert(
                    Address::new(id, slot),
                    Query {
                        source,
                        operation: "summary".into(),
                        phase: "calculate".into(),
                        channel: "total".into(),
                        range: range.clone(),
                        selected: None,
                        result,
                    },
                );
            }
            require(
                record.derived
                    == Some(Totals {
                        primary: sums[0],
                        secondary: sums[1],
                    }),
                "native ordered source-derived totals",
            )?;
        }
    }
    snapshot.finish_native(
        snapshot.expected_keys.clone(),
        members,
        routes,
        queries,
        &|_code, leaves| Ok(leaves.iter().map(|(_, v)| *v).sum()),
    )
}
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn request(store: &Store<Ordered>, commands: Value) -> Mutation {
    serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":Uuid::new_v4(),"commands":commands,"returning":[]})).unwrap()
}
fn run(store: &Store<Ordered>, commands: Value) {
    store.mutate(&request(store, commands)).unwrap();
    store.check_integrity().unwrap();
}
fn update(store: &Store<Ordered>, n: u128, set: Value) -> Value {
    let record = Snapshot::load(store).unwrap().records[&id(n)].clone();
    json!({"op":"update","id":id(n),"if_version":record.version,"set":set,"unset":[]})
}
fn create(n: u128, contract: u16, fields: Value) -> Value {
    json!({"op":"create","id":id(n),"contract":contract,"fields":fields})
}
fn total(store: &Store<Ordered>) -> Totals {
    Snapshot::load(store).unwrap().records[&id(30)]
        .derived
        .clone()
        .unwrap()
}
#[test]
fn numeric_text_tuple_rekeys_queries_routes_and_rollback_use_native_keys() {
    let integer = |n| OrderKey::new(vec![OrderAtom::Integer(n)]).unwrap();
    let text = |s: &str| OrderKey::new(vec![OrderAtom::Text(s.into())]).unwrap();
    let tuple =
        |n, s: &str| OrderKey::new(vec![OrderAtom::Integer(n), OrderAtom::Text(s.into())]).unwrap();
    for [low, middle, high] in [
        [integer(2), integer(3), integer(10)],
        [text("beta"), text("gamma"), text("theta")],
        [tuple(2, "a"), tuple(2, "z"), tuple(10, "a")],
    ] {
        let directory = std::env::temp_dir().join(format!("native-reactive-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let file = directory.join("store.redb");
        let model = Arc::new(Prepared::<Ordered>::load().unwrap());
        let store = Store::create(
            &file,
            model.clone(),
            Context {
                tenant: id(100),
                actor: id(101),
            },
        )
        .unwrap();
        let range = NativeRange {
            lower: NativeBound::Included(low.clone()),
            upper: NativeBound::Excluded(high.clone()),
        };
        run(
            &store,
            json!([
                create(1, 10, json!({"label":"one"})),
                create(2, 10, json!({"label":"two"})),
                create(
                    10,
                    20,
                    json!({"root":id(1),"key":low,"other":high,"amount":10})
                ),
                create(
                    11,
                    20,
                    json!({"root":id(1),"key":middle,"other":middle,"amount":20})
                ),
                create(
                    12,
                    20,
                    json!({"root":id(1),"key":high,"other":low,"amount":30})
                ),
                create(
                    13,
                    20,
                    json!({"root":id(2),"key":middle,"other":middle,"amount":7})
                ),
                create(30, 30, json!({"root":id(1),"range":range}))
            ]),
        );
        assert_eq!(
            total(&store),
            Totals {
                primary: 30,
                secondary: 50
            }
        );
        let page = store
            .root_read(
                &serde_json::from_value(json!({
                    "model":store.model().identity(), "owner":id(1), "slot":7,
                    "read":{"kind":"range","range":range}
                }))
                .unwrap(),
            )
            .unwrap();
        assert_eq!(page["value"], 30);

        run(&store, json!([update(&store, 11, json!({"key":high}))]));
        assert_eq!(
            total(&store),
            Totals {
                primary: 10,
                secondary: 50
            }
        );
        run(
            &store,
            json!([update(
                &store,
                30,
                json!({"range":NativeRange {lower:NativeBound::Included(low.clone()),upper:NativeBound::Included(high.clone())}})
            )]),
        );
        assert_eq!(
            total(&store),
            Totals {
                primary: 60,
                secondary: 60
            }
        );
        // Both declarations retarget atomically, while a source edit hits the old roots.
        run(
            &store,
            json!([
                update(&store, 30, json!({"root":id(2)})),
                update(&store, 10, json!({"amount":9}))
            ]),
        );
        assert_eq!(
            total(&store),
            Totals {
                primary: 7,
                secondary: 7
            }
        );
        let before = store.observe_for_verification().unwrap();
        let bad = request(
            &store,
            json!([
                update(&store, 13, json!({"amount":1001})),
                update(&store, 30, json!({"root":id(1)}))
            ]),
        );
        assert!(store.mutate(&bad).is_err());
        assert_eq!(store.observe_for_verification().unwrap(), before);
        let version = Snapshot::load(&store).unwrap().records[&id(13)].version;
        run(
            &store,
            json!([{"op":"delete","id":id(13),"if_version":version}]),
        );
        assert_eq!(
            total(&store),
            Totals {
                primary: 0,
                secondary: 0
            }
        );
        // Zero-output subscriber stays registered; inserting later must wake it.
        run(
            &store,
            json!([create(
                14,
                20,
                json!({"root":id(2),"key":low,"other":high,"amount":13})
            )]),
        );
        assert_eq!(
            total(&store),
            Totals {
                primary: 13,
                secondary: 13
            }
        );
        drop(store);
        let reopened = Store::<Ordered>::open(&file, model).unwrap();
        reopened.check_integrity().unwrap();
        assert_eq!(
            total(&reopened),
            Totals {
                primary: 13,
                secondary: 13
            }
        );
        drop(reopened);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
