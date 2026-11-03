use rebase_semantic_proof::{
    access::{Action, Grants, Graph, Principal, PrincipalKind},
    access_index::{Component, Declaration, OrderQuery, PageRequest},
    binding::Binding,
    local::{Mutation, Store},
    model::{Prepared, PreparedModel},
    models::{
        invoicing::Invoicing,
        quantity::{Quantity, SOURCE},
    },
    native_codec::{self, Address, Key},
    native_range::{NativeBound, NativeRange},
    native_slice::{Context, Result},
    order_value::{OrderAtom, OrderAtomKind, OrderKey},
    query::Equality,
    security::ReplaceGraph,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};
use uuid::Uuid;

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("access-order-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn file(&self) -> PathBuf {
        self.0.join("store.redb")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn request<B: Binding>(store: &Store<B>, commands: Value) -> Mutation {
    serde_json::from_value(json!({
        "model":store.model().identity(),
        "context":store.operation_context(store.model().identity()).unwrap(),
        "operation_id":Uuid::new_v4(),"commands":commands,"returning":[],
    }))
    .unwrap()
}
fn setup<B: Binding>(directory: &Directory, model: Arc<Prepared<B>>) -> Store<B> {
    let admin = Store::create_secured(
        directory.file(),
        model,
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    let mut graph = Graph::bootstrap(Context {
        tenant: id(1),
        actor: id(2),
    })
    .unwrap()
    .graph;
    let contracts: BTreeMap<_, _> = admin
        .model()
        .contracts()
        .filter(|contract| admin.model().public_contract(contract.code).is_ok())
        .map(|contract| {
            (
                contract.code,
                BTreeSet::from([Action::Read, Action::Create, Action::Update, Action::Delete]),
            )
        })
        .collect();
    // Actor 4 reads self, child 7 and direct group 6; sibling 5 remains hidden.
    for (actor, parent, kind) in [
        (6, 2, PrincipalKind::Group),
        (4, 6, PrincipalKind::User),
        (5, 6, PrincipalKind::User),
        (7, 4, PrincipalKind::User),
        (8, 1, PrincipalKind::User),
        (9, 1, PrincipalKind::User),
    ] {
        graph.principals.push(Principal {
            id: id(actor),
            kind,
            parents: vec![id(parent)],
            active: true,
            credential_epoch: 0,
            grants: Grants {
                admin: false,
                contracts: if actor == 9 {
                    contracts
                        .keys()
                        .map(|&code| (code, BTreeSet::from([Action::Create, Action::Update])))
                        .collect()
                } else {
                    contracts.clone()
                },
            },
        });
    }
    replace(&admin, graph);
    admin
}
fn replace<B: Binding>(store: &Store<B>, graph: Graph) {
    let revision = store.access_graph(store.model().identity()).unwrap()["revision"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    store
        .replace_access(&ReplaceGraph {
            model: store.model().identity().into(),
            if_revision: revision,
            graph,
        })
        .unwrap();
}
fn page_request<B: Binding>(store: &Store<B>, contract: u16, index: u16) -> PageRequest {
    PageRequest {
        model: store.model().identity().into(),
        query: OrderQuery {
            contract,
            index,
            range: NativeRange::ALL,
            equals: None,
        },
        limit: 3,
        visit_budget: 7,
        cursor: None,
    }
}
fn ids<B: Binding>(store: &Store<B>, mut request: PageRequest) -> Vec<Uuid> {
    let mut result = vec![];
    for _ in 0..2000 {
        let page = store.order_page(&request).unwrap();
        assert!(page.visited <= request.visit_budget);
        assert!(page.records.len() <= usize::from(request.limit));
        result.extend(page.records.into_iter().map(|record| record.id));
        if page.exhausted {
            assert!(page.cursor.is_none());
            return result;
        }
        assert!(page.visited > 0, "cursor must make candidate progress");
        assert!(page.cursor.is_some());
        request.cursor = page.cursor;
    }
    panic!("access paging failed to terminate")
}
fn first_cursor<B: Binding>(store: &Store<B>, contract: u16, index: u16) -> PageRequest {
    let mut request = page_request(store, contract, index);
    request.limit = 1;
    request.cursor = store.order_page(&request).unwrap().cursor;
    assert!(request.cursor.is_some());
    request
}
fn integer(value: i128) -> OrderKey {
    OrderKey::new(vec![OrderAtom::Integer(value)]).unwrap()
}
fn native_rows(image: &Value, tags: &[&str]) -> Vec<Value> {
    image["tables"]["native_kv"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| {
            tags.iter()
                .any(|tag| row["key"].as_str().unwrap().starts_with(tag))
        })
        .cloned()
        .collect()
}
fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&text[offset..offset + 2], 16).unwrap())
        .collect()
}
fn native_value(image: &Value, key: &Key) -> Value {
    let key = native_codec::hex(&key.encode());
    let row = image["tables"]["native_kv"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["key"] == key)
        .unwrap();
    serde_json::from_slice(&unhex(row["value"].as_str().unwrap())).unwrap()
}

#[test]
fn numeric_and_creation_order_match_source_oracles_for_50_100_1000_records() {
    for population in [50usize, 100, 1000] {
        let directory = Directory::new();
        let admin = setup(&directory, Arc::new(Prepared::<Quantity>::load().unwrap()));
        let caller = admin.session(id(4), 0).unwrap();
        let source: Vec<_> = (0..population)
            .map(|n| {
                let number = 1000 + (population - 1 - n) as u128;
                let owner = [4u128, 5, 6, 7][n % 4];
                let value = (n as i128 * 17) % 23 - 11;
                (number, owner, value)
            })
            .collect();
        for chunk in source.chunks(32) {
            admin.mutate(&request(&admin,json!(chunk.iter().map(|&(number,owner,value)|json!({
                "op":"create","id":id(number),"owner":id(owner),"contract":SOURCE,"fields":{"value":value.to_string()}
            })).collect::<Vec<_>>()))).unwrap();
        }
        let mut expected: Vec<_> = source
            .iter()
            .filter(|(_, owner, _)| [4, 6, 7].contains(owner))
            .map(|&(number, _, value)| (value, id(number)))
            .collect();
        expected.sort();
        assert_eq!(
            ids(&caller, page_request(&caller, SOURCE, 102)),
            expected.iter().map(|(_, id)| *id).collect::<Vec<_>>()
        );
        let mut range = page_request(&caller, SOURCE, 102);
        range.query.range = NativeRange {
            lower: NativeBound::Included(integer(-1)),
            upper: NativeBound::Excluded(integer(10)),
        };
        assert_eq!(
            ids(&caller, range),
            expected
                .iter()
                .filter(|(value, _)| (-1..10).contains(value))
                .map(|(_, id)| *id)
                .collect::<Vec<_>>()
        );
        let mut empty = page_request(&caller, SOURCE, 102);
        empty.query.range = NativeRange {
            lower: NativeBound::Excluded(integer(2)),
            upper: NativeBound::Included(integer(2)),
        };
        let page = caller.order_page(&empty).unwrap();
        assert!(page.exhausted && page.records.is_empty() && page.visited == 0);
        // Creation order comes from immutable source metadata, independent of UUID
        // insertion order and the access writer's cached links or spans.
        let mut created = source
            .iter()
            .filter(|(_, owner, _)| [4, 6, 7].contains(owner))
            .map(|&(number, _, _)| {
                let record = caller
                    .get(caller.model().identity(), id(number))
                    .unwrap()
                    .unwrap();
                assert!(record.created_at > 0);
                (record.created_at, record.id)
            })
            .collect::<Vec<_>>();
        created.sort();
        assert_eq!(
            ids(&caller, page_request(&caller, SOURCE, 101)),
            created.iter().map(|(_, id)| *id).collect::<Vec<_>>()
        );
        let image = admin.observe_for_verification().unwrap();
        for owner in [4, 5, 6, 7] {
            let count = source
                .iter()
                .filter(|(_, candidate, _)| *candidate == owner)
                .count();
            for index in [101, 102] {
                let root = native_value(&image, &Key::AccessRoot(Address::new(id(owner), index)));
                assert_eq!(root["data"]["size"], json!(count));
            }
        }
        assert!(
            native_rows(&image, &["0d"]).is_empty(),
            "no population counter tag"
        );
        let no_read = admin.session(id(9), 0).unwrap();
        assert_eq!(
            no_read
                .order_page(&page_request(&no_read, SOURCE, 102))
                .unwrap_err()
                .code,
            "forbidden"
        );
        admin.check_integrity().unwrap();
    }
}

#[test]
fn text_and_composite_orders_use_declared_native_components_and_complete_ties() {
    let directory = Directory::new();
    let mut declarations = Invoicing::declarations().unwrap();
    let treasury = declarations
        .iter_mut()
        .find(|contract| contract.code == 601)
        .unwrap();
    treasury.access_indexes = vec![
        Declaration {
            code: 6011,
            name: "name",
            components: vec![Component::Field {
                field: "name",
                kind: OrderAtomKind::Text,
            }],
        },
        Declaration {
            code: 6012,
            name: "currency_name",
            components: vec![
                Component::Field {
                    field: "currency",
                    kind: OrderAtomKind::Integer,
                },
                Component::Field {
                    field: "name",
                    kind: OrderAtomKind::Text,
                },
            ],
        },
    ];
    let model = Arc::new(Prepared::<Invoicing>::prepare(declarations).unwrap());
    let store = Store::create(
        directory.file(),
        model,
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    let source = [
        (17, 10, "alpha"),
        (16, 2, "zeta"),
        (15, 2, "alpha"),
        (14, 2, "alpha"),
        (13, 1, "Ω"),
        (12, 1, "beta"),
    ];
    store.mutate(&request(&store,json!(source.iter().map(|&(number,currency,name)|json!({"op":"create","id":id(number),"contract":601,"fields":{"currency":currency,"name":name}})).collect::<Vec<_>>()))).unwrap();
    let mut names = source.map(|(number, _, name)| (name, id(number)));
    names.sort();
    assert_eq!(
        ids(&store, page_request(&store, 601, 6011)),
        names.map(|(_, id)| id)
    );
    let mut composite = source.map(|(number, currency, name)| (currency, name, id(number)));
    composite.sort();
    assert_eq!(
        ids(&store, page_request(&store, 601, 6012)),
        composite.map(|(_, _, id)| id)
    );
    let key = |currency, name: &str| {
        OrderKey::new(vec![
            OrderAtom::Integer(currency),
            OrderAtom::Text(name.into()),
        ])
        .unwrap()
    };
    let mut query = page_request(&store, 601, 6012);
    query.query.range = NativeRange {
        lower: NativeBound::Included(key(2, "alpha")),
        upper: NativeBound::Excluded(key(10, "alpha")),
    };
    assert_eq!(ids(&store, query.clone()), vec![id(14), id(15), id(16)]);
    query.query.range.lower = NativeBound::Included(integer(2));
    assert_eq!(store.order_page(&query).unwrap_err().code, "invalid_input");
    store.check_integrity().unwrap();
}

#[test]
fn filters_bound_candidates_and_transfers_fence_both_owner_epochs_without_payload_reindex() {
    let directory = Directory::new();
    let admin = setup(&directory, Arc::new(PreparedModel::load().unwrap()));
    let caller = admin.session(id(4), 0).unwrap();
    let sibling = admin.session(id(5), 0).unwrap();
    let other = admin.session(id(8), 0).unwrap();
    for (store, account, owner, first) in [
        (&caller, 10, 4, 40),
        (&caller, 11, 6, 50),
        (&other, 12, 8, 60),
    ] {
        store.mutate(&request(store,json!([
            {"op":"create","id":id(account),"owner":id(owner),"contract":4,"fields":{"native_unit":1}},
            {"op":"create","id":id(first),"owner":id(owner),"contract":8,"fields":{"account":id(account),"at":"2","amount":"1"}},
            {"op":"create","id":id(first+1),"owner":id(owner),"contract":8,"fields":{"account":id(account),"at":"10","amount":"2"}},
            {"op":"create","id":id(first+2),"owner":id(owner),"contract":8,"fields":{"account":id(account),"at":"2","amount":"3"}}
        ]))).unwrap();
    }
    let mut filtered = page_request(&caller, 8, 802);
    filtered.visit_budget = 1;
    filtered.query.equals = Some(Equality {
        field: "amount".into(),
        value: json!("2"),
    });
    let first = caller.order_page(&filtered).unwrap();
    assert!(first.records.is_empty() && !first.exhausted && first.visited == 1);
    assert_eq!(ids(&caller, filtered), vec![id(41), id(51)]);
    let own_cursor = first_cursor(&caller, 8, 802);
    let destination_cursor = first_cursor(&sibling, 8, 802);
    let other_cursor = first_cursor(&other, 8, 802);
    let before = admin.observe_for_verification().unwrap();
    let old = caller
        .get(caller.model().identity(), id(40))
        .unwrap()
        .unwrap();
    let transfer = request(
        &caller,
        json!([{"op":"update","id":id(40),"owner":id(6),"if_version":old.version,"set":{},"unset":[]}]),
    );
    caller.mutate(&transfer).unwrap();
    let after = admin.observe_for_verification().unwrap();
    let new = caller
        .get(caller.model().identity(), id(40))
        .unwrap()
        .unwrap();
    assert_eq!(new.created_at, old.created_at);
    assert_eq!(new.id, old.id);
    assert_eq!(
        native_rows(&before, &["02", "03"]),
        native_rows(&after, &["02", "03"])
    );
    for index in [801, 802] {
        assert_eq!(
            native_value(&after, &Key::AccessRoot(Address::new(id(4), index)))["data"]["size"],
            json!(2)
        );
        assert_eq!(
            native_value(&after, &Key::AccessRoot(Address::new(id(6), index)))["data"]["size"],
            json!(4)
        );
        assert_eq!(
            native_value(&after, &Key::AccessNode(Address::new(id(40), index)))["data"]["root"],
            json!({"id":id(6),"slot":index})
        );
    }

    for owner in [4, 6] {
        let key = format!("{}{:04x}", id(owner).simple(), 8);
        let row = |image: &Value| {
            image["tables"]["query_epochs"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["key"] == key)
                .unwrap()
                .clone()
        };
        assert_ne!(row(&before), row(&after));
    }
    assert_eq!(
        caller.order_page(&own_cursor).unwrap_err().code,
        "query_changed"
    );
    assert_eq!(
        sibling.order_page(&destination_cursor).unwrap_err().code,
        "query_changed"
    );
    assert!(other.order_page(&other_cursor).is_ok());
    assert_eq!(
        ids(&sibling, page_request(&sibling, 8, 802)),
        vec![id(40), id(50), id(52), id(51)]
    );
    // Replay retains the original accepted intent and performs no additional move.
    caller.mutate(&transfer).unwrap();
    assert_eq!(admin.observe_for_verification().unwrap(), after);
    let before_payload = admin.observe_for_verification().unwrap();
    let payload_cursor = first_cursor(&caller, 8, 802);
    caller.mutate(&request(&caller,json!([{"op":"update","id":id(40),"if_version":new.version,"set":{"amount":"4"},"unset":[]}]))).unwrap();
    let after_payload = admin.observe_for_verification().unwrap();
    assert_eq!(
        native_rows(&before_payload, &["0f", "10"]),
        native_rows(&after_payload, &["0f", "10"])
    );
    assert_eq!(
        caller.order_page(&payload_cursor).unwrap_err().code,
        "query_changed"
    );
    // A sibling destination is outside actor 4's scope, even with a stale CAS token.
    let rejected = request(
        &caller,
        json!([{"op":"update","id":id(41),"owner":id(5),"if_version":Uuid::nil(),"set":{},"unset":[]}]),
    );
    assert_eq!(caller.mutate(&rejected).unwrap_err().code, "forbidden");
    assert_eq!(admin.observe_for_verification().unwrap(), after_payload);
    let version = caller
        .get(caller.model().identity(), id(41))
        .unwrap()
        .unwrap()
        .version;
    let rollback = request(
        &caller,
        json!([{"op":"update","id":id(41),"owner":id(6),"if_version":version,"set":{"amount":"-100"},"unset":[]}]),
    );
    assert_eq!(caller.mutate(&rollback).unwrap_err().code, "invariant");
    assert_eq!(admin.observe_for_verification().unwrap(), after_payload);
    let mut altered = other_cursor;
    altered.query.index = 801;
    assert_eq!(
        other.order_page(&altered).unwrap_err().code,
        "invalid_cursor"
    );
    admin.check_integrity().unwrap();
}

#[test]
fn access_order_survives_reopen_restore_and_rejects_corrupted_cache_inventory() {
    let directory = Directory::new();
    let model = Arc::new(Prepared::<Quantity>::load().unwrap());
    let store = Store::create(
        directory.file(),
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    store
        .mutate(&request(
            &store,
            json!([
                {"op":"create","id":id(30),"contract":SOURCE,"fields":{"value":"10"}},
                {"op":"create","id":id(20),"contract":SOURCE,"fields":{"value":"2"}},
                {"op":"create","id":id(10),"contract":SOURCE,"fields":{"value":"-1"}}
            ]),
        ))
        .unwrap();
    let expected = vec![id(10), id(20), id(30)];
    assert_eq!(ids(&store, page_request(&store, SOURCE, 102)), expected);
    let image = store.observe_for_verification().unwrap();
    let backup = directory.0.join("backup.json");
    store.backup(&backup).unwrap();
    let restored_path = directory.0.join("restored.redb");
    rebase_semantic_proof::lifecycle::restore(&backup, &restored_path, model.clone()).unwrap();
    let restored = Store::open(&restored_path, model.clone()).unwrap();
    assert_eq!(restored.observe_for_verification().unwrap(), image);
    assert_eq!(
        ids(&restored, page_request(&restored, SOURCE, 102)),
        expected
    );
    restored.check_integrity().unwrap();
    drop(restored);
    drop(store);
    let reopened = Store::open(directory.file(), model.clone()).unwrap();
    assert_eq!(
        ids(&reopened, page_request(&reopened, SOURCE, 102)),
        expected
    );
    reopened.check_integrity().unwrap();
    let commands = expected
        .iter()
        .map(|&record| {
            let version = reopened
                .get(reopened.model().identity(), record)
                .unwrap()
                .unwrap()
                .version;
            json!({"op":"delete","id":record,"if_version":version})
        })
        .collect::<Vec<_>>();
    reopened
        .mutate(&request(&reopened, json!(commands)))
        .unwrap();
    assert!(native_rows(&reopened.observe_for_verification().unwrap(), &["0f", "10"]).is_empty());
    assert!(ids(&reopened, page_request(&reopened, SOURCE, 102)).is_empty());
    reopened.check_integrity().unwrap();
    drop(reopened);
    let original: Value = serde_json::from_slice(&std::fs::read(&backup).unwrap()).unwrap();
    for damage in ["root_size", "member_key", "missing_root"] {
        let mut corrupt = original.clone();
        let rows = corrupt["payload"]["tables"]["native_kv"]
            .as_array_mut()
            .unwrap();
        let index = rows
            .iter()
            .position(|row| {
                row["key"]
                    == native_codec::hex(
                        &match damage {
                            "member_key" => Key::AccessNode(Address::new(id(20), 102)),
                            _ => Key::AccessRoot(Address::new(id(2), 102)),
                        }
                        .encode(),
                    )
            })
            .unwrap();
        if damage == "missing_root" {
            rows.remove(index);
        } else {
            let mut value: Value =
                serde_json::from_slice(&unhex(rows[index]["value"].as_str().unwrap())).unwrap();
            if damage == "root_size" {
                value["data"]["size"] = json!(99);
            } else {
                value["data"]["key"]["value"][0]["value"] = json!("3");
            }
            rows[index]["value"] = json!(native_codec::hex(&serde_json::to_vec(&value).unwrap()));
        }
        corrupt["sha256"] = json!(native_codec::hex(&Sha256::digest(
            serde_json::to_vec(&corrupt["payload"]).unwrap()
        )));
        let corrupt_path = directory.0.join(format!("{damage}.json"));
        let rejected_path = directory.0.join(format!("{damage}.redb"));
        std::fs::write(&corrupt_path, serde_json::to_vec(&corrupt).unwrap()).unwrap();
        let result: Result<_> =
            rebase_semantic_proof::lifecycle::restore(&corrupt_path, &rejected_path, model.clone());
        assert_eq!(result.unwrap_err().code, "corrupt_state");
        assert!(!rejected_path.exists());
    }
}

#[test]
fn generated_access_memberships_follow_producer_without_disclosing_outputs() {
    use rebase_semantic_proof::models::equipment::Equipment;
    let directory = Directory::new();
    let mut declarations = Equipment::declarations().unwrap();
    for (contract, index) in [(410, 4101), (900, 9001)] {
        declarations
            .iter_mut()
            .find(|declaration| declaration.code == contract)
            .unwrap()
            .access_indexes = vec![Declaration::created(index)];
    }
    let model = Arc::new(Prepared::<Equipment>::prepare(declarations).unwrap());
    let admin = setup(&directory, model);
    let caller = admin.session(id(4), 0).unwrap();
    let sibling = admin.session(id(5), 0).unwrap();
    let seed = request(
        &caller,
        json!([
            {"op":"create","id":id(100),"contract":101,"fields":{"unit":1}},
            {"op":"create","id":id(101),"contract":205,"fields":{"pool":id(100),"at":"0","quantity":"10"}},
            {"op":"create","id":id(200),"contract":410,"fields":{"pool":id(100),"starts":"10","ends":"20","requested":"3","active":true}}
        ]),
    );
    let mut allocated = 899;
    caller
        .mutate_with_ids(&seed, &mut || {
            allocated += 1;
            Ok(id(allocated))
        })
        .unwrap();
    assert_eq!(allocated, 901);
    let before = admin.observe_for_verification().unwrap();
    let producer = caller
        .get(caller.model().identity(), id(200))
        .unwrap()
        .unwrap();
    caller.mutate(&request(&caller,json!([{"op":"update","id":id(200),"owner":id(6),"if_version":producer.version,"set":{},"unset":[]}]))).unwrap();
    let after = admin.observe_for_verification().unwrap();
    assert_eq!(
        native_rows(&before, &["02", "03", "08", "09"]),
        native_rows(&after, &["02", "03", "08", "09"])
    );
    for record in [900, 901] {
        let source = native_value(&after, &Key::Record(id(record)));
        assert_eq!(source["data"]["owner"], json!(id(6)));
        assert_eq!(
            source["data"]["created_at"],
            native_value(&before, &Key::Record(id(record)))["data"]["created_at"]
        );
        let member = native_value(&after, &Key::AccessNode(Address::new(id(record), 9001)));
        assert_eq!(member["data"]["root"], json!({"id":id(6),"slot":9001}));
        assert!(
            sibling
                .get(sibling.model().identity(), id(record))
                .unwrap()
                .is_none()
        );
    }
    let root = native_value(&after, &Key::AccessRoot(Address::new(id(6), 9001)));
    assert_eq!(root["data"]["size"], json!(2));
    assert!(
        !after["tables"]["native_kv"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["key"]
                == native_codec::hex(&Key::AccessRoot(Address::new(id(4), 9001)).encode()))
    );
    assert_eq!(
        ids(&sibling, page_request(&sibling, 410, 4101)),
        vec![id(200)]
    );
    assert_eq!(
        sibling
            .order_page(&page_request(&sibling, 900, 9001))
            .unwrap_err()
            .code,
        "forbidden"
    );
    admin.check_integrity().unwrap();
}

#[test]
fn access_page_resource_caps_reject_incomplete_responses_without_side_effects() {
    use rebase_semantic_proof::access_index::PagePolicy;
    let directory = Directory::new();
    let store = Store::create(
        directory.file(),
        Arc::new(Prepared::<Quantity>::load().unwrap()),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    store
        .mutate(&request(
            &store,
            json!([
                {"op":"create","id":id(10),"contract":SOURCE,"fields":{"value":"2"}},
                {"op":"create","id":id(20),"contract":SOURCE,"fields":{"value":"10"}}
            ]),
        ))
        .unwrap();
    let request = page_request(&store, SOURCE, 102);
    let before = store.observe_for_verification().unwrap();
    for field in 0..4 {
        for limit in [0, 1] {
            let mut policy = PagePolicy::default();
            match field {
                0 => policy.max_work = limit as u64,
                1 => policy.max_gets = limit,
                2 => policy.max_loaded_bytes = limit,
                _ => policy.max_output_bytes = limit,
            };
            let error = store.order_page_with_policy(&request, &policy).unwrap_err();
            assert_eq!(
                error.code,
                if limit == 0 {
                    "invalid_input"
                } else {
                    "work_limit"
                },
                "field {field}, limit {limit}"
            );
            assert_eq!(store.observe_for_verification().unwrap(), before);
        }
    }
    assert_eq!(
        store
            .order_page_with_policy(&request, &PagePolicy::default())
            .unwrap()
            .records
            .len(),
        2
    );
}
