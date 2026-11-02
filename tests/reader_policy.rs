//! C2.R expectations use original principal edges and literal source relations.
use rebase_semantic_proof::{
    access::{Action, Grants, Graph, Principal, PrincipalKind},
    binding::Binding,
    local::{LocalStore, Mutation, Store},
    model::PreparedModel,
    native_slice::Context,
    security::ReplaceGraph,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, sync::Arc};
use uuid::Uuid;
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn principal(n: u128, parents: Vec<Uuid>) -> Principal {
    Principal {
        id: id(n),
        kind: PrincipalKind::User,
        parents,
        active: true,
        credential_epoch: 0,
        grants: Grants {
            admin: false,
            contracts: (1..=10)
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
    }
}
// Independent reachability follows original parent edges, not prepared closures.
fn ancestor(g: &Graph, a: Uuid, b: Uuid) -> bool {
    let mut pending = vec![b];
    let mut seen = BTreeSet::new();
    while let Some(next) = pending.pop() {
        if next == a {
            return true;
        }
        if seen.insert(next) {
            pending.extend(
                g.principals
                    .iter()
                    .find(|p| p.id == next)
                    .unwrap()
                    .parents
                    .iter()
                    .copied(),
            );
        }
    }
    false
}
fn expected(g: &Graph, candidates: &[Uuid]) -> Uuid {
    *candidates
        .iter()
        .find(|&&a| !candidates.iter().any(|&b| a != b && ancestor(g, a, b)))
        .unwrap()
}
fn base() -> Graph {
    Graph::bootstrap(Context {
        tenant: id(1),
        actor: id(2),
    })
    .unwrap()
    .graph
}
#[test]
fn exhaustive_small_principal_dags_and_ordered_candidate_lists() {
    let edges = [(3, 4), (3, 5), (3, 6), (4, 5), (4, 6), (5, 6)];
    for mask in 0..64 {
        let mut g = base();
        for n in 3..=6 {
            let parents = std::iter::once(id(1))
                .chain(
                    edges
                        .iter()
                        .enumerate()
                        .filter(|(bit, (_, b))| *b == n && mask & (1 << bit) != 0)
                        .map(|(_, (a, _))| id(*a)),
                )
                .collect();
            g.principals.push(principal(n, parents));
        }
        let prepared = g.clone().prepare().unwrap();
        for owner in 3..=6 {
            for len in 0..=3 {
                for encoded in 0..4usize.pow(len) {
                    let mut code = encoded;
                    let refs: Vec<_> = (0..len)
                        .map(|_| {
                            let v = id(3 + (code % 4) as u128);
                            code /= 4;
                            v
                        })
                        .collect();
                    let candidates: Vec<_> = std::iter::once(id(owner))
                        .chain(refs.iter().copied())
                        .collect();
                    assert_eq!(
                        prepared.reader(&refs, id(owner)),
                        expected(&g, &candidates),
                        "mask={mask}, candidates={candidates:?}"
                    );
                }
            }
        }
    }
}
fn mutate<B: Binding>(
    store: &Store<B>,
    op: u128,
    commands: Value,
) -> Result<Value, rebase_semantic_proof::native_slice::Error> {
    let mutation: Mutation=serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":id(op),"commands":commands,"returning":[]})).unwrap();
    store.mutate(&mutation)
}
fn replace<B: Binding>(store: &Store<B>, g: Graph) {
    let revision = store.access_graph(store.model().identity()).unwrap()["revision"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    store
        .replace_access(&ReplaceGraph {
            model: store.model().identity().into(),
            if_revision: revision,
            graph: g,
        })
        .unwrap();
}
fn assert_reader<B: Binding>(store: &Store<B>, record: u128, contract: u16, reader: u128) {
    let image = store.observe_for_verification().unwrap();
    let expected = format!(
        "{}{:04x}{}",
        id(reader).simple(),
        contract,
        id(record).simple()
    );
    assert!(
        image["tables"]["reader_records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["key"] == expected)
    );
}
fn assert_private_reader(store: &LocalStore, producer: u128, reader: u128) {
    use rebase_semantic_proof::{
        native_codec::{self, Key, Stored},
        native_slice::Input,
    };
    fn bytes(value: &Value) -> Vec<u8> {
        value
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
            .collect()
    }
    let image = store.observe_for_verification().unwrap();
    let mut found = false;
    for row in image["tables"]["native_kv"].as_array().unwrap() {
        let key = Key::decode(&bytes(&row["key"])).unwrap();
        if let Stored::Record(record) = native_codec::decode(&key, &bytes(&row["value"])).unwrap()
            && matches!(record.input,Input::Output { producer: p,.. } if p==id(producer))
        {
            found = true;
            assert_eq!(record.reader, id(reader));
        }
    }
    assert!(found, "expected managed output");
}
#[test]
fn source_owner_frontier_retarget_graph_repair_and_rollback() {
    let directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/reader-policy")
        .join(Uuid::new_v4().to_string());
    std::fs::create_dir_all(&directory).unwrap();
    let model = Arc::new(PreparedModel::load().unwrap());
    let admin = LocalStore::create_secured(
        directory.join("test.redb"),
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    let mut g = base();
    g.principals.extend([
        Principal {
            kind: PrincipalKind::Group,
            ..principal(3, vec![id(2)])
        },
        principal(4, vec![id(3)]),
        principal(5, vec![id(2)]),
    ]);
    replace(&admin, g.clone());
    let manager = admin.session(id(3), 0).unwrap();
    let child = admin.session(id(4), 0).unwrap();
    let stranger = admin.session(id(5), 0).unwrap();
    for (session, n, op) in [(&manager, 10, 100), (&child, 11, 101), (&stranger, 12, 102)] {
        mutate(
            session,
            op,
            json!([{"op":"create","id":id(n),"contract":4,"fields":{"native_unit":1}}]),
        )
        .unwrap();
    }
    // Own owner is a strict descendant of the sole referenced owner.
    mutate(&child,103,json!([{"op":"create","id":id(20),"contract":8,"fields":{"account":id(10),"at":"0","amount":"1"}}])).unwrap();
    assert_reader(&admin, 20, 8, 4);
    // [admin, manager, stranger, child] removes manager globally; stranger
    // precedes child even though a greedy ancestor replacement chooses child.
    mutate(&admin,104,json!([{"op":"create","id":id(21),"contract":10,"fields":{"sources":[id(10),id(12)],"factor":"1","account":id(11),"at":"1","feedback":null}}])).unwrap();
    assert_reader(&admin, 21, 10, 5);
    assert_private_reader(&admin, 21, 5);
    let before = admin.observe_for_verification().unwrap();
    assert!(mutate(&child,105,json!([{"op":"create","id":id(22),"contract":8,"fields":{"account":id(12),"at":"2","amount":"1"}}])).is_err());
    assert_eq!(admin.observe_for_verification().unwrap(), before);
    let version = admin
        .get(model.identity(), id(21))
        .unwrap()
        .unwrap()
        .version;
    mutate(&admin,106,json!([{"op":"update","id":id(21),"if_version":version,"set":{"sources":[id(10),id(10)]},"unset":[]}])).unwrap();
    assert_reader(&admin, 21, 10, 4);
    assert_private_reader(&admin, 21, 4);
    g.principals
        .iter_mut()
        .find(|p| p.id == id(4))
        .unwrap()
        .parents = vec![id(2)];
    replace(&admin, g);
    assert_reader(&admin, 21, 10, 3);
    assert_private_reader(&admin, 21, 3);
    admin.check_integrity().unwrap();
    drop((stranger, child, manager, admin));
    std::fs::remove_dir_all(directory).unwrap();
}

fn assert_quantity_source_oracle(
    store: &Store<rebase_semantic_proof::models::quantity::Quantity>,
    graph: &Graph,
) {
    use rebase_semantic_proof::{
        models::quantity::{Input, Quantity},
        native_codec::{self, Key, StoredValue},
        native_slice::ModelRecord,
    };
    use std::collections::BTreeMap;
    let bytes = |value: &Value| {
        value
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
            .collect::<Vec<_>>()
    };
    let image = store.observe_for_verification().unwrap();
    let records: BTreeMap<_, _> = image["tables"]["native_kv"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| {
            let key = Key::decode(&bytes(&row["key"])).unwrap();
            match (
                key.clone(),
                native_codec::decode_for::<Quantity>(&key, &bytes(&row["value"])).unwrap(),
            ) {
                (Key::Record(id), StoredValue::Record(record)) => Some((id, record)),
                _ => None,
            }
        })
        .collect();
    fn expand(
        id: Uuid,
        records: &BTreeMap<Uuid, ModelRecord<Quantity>>,
        seen: &mut BTreeSet<Uuid>,
        owners: &mut Vec<Uuid>,
    ) {
        if !seen.insert(id) {
            return;
        }
        let record = &records[&id];
        owners.push(record.owner);
        match &record.input {
            Input::Source { .. } => {}
            Input::Scale { parent, .. } => expand(*parent, records, seen, owners),
            Input::Join { left, right } => {
                expand(*left, records, seen, owners);
                expand(*right, records, seen, owners);
            }
        }
    }
    for (&id, record) in &records {
        let mut owners = Vec::new();
        expand(id, &records, &mut BTreeSet::new(), &mut owners);
        assert_eq!(
            record.reader,
            expected(graph, &owners),
            "source oracle record {id}"
        );
    }
}

#[test]
fn recursive_frontier_propagates_when_parent_scalar_and_quantity_stay_equal() {
    use rebase_semantic_proof::{
        model::Prepared,
        models::quantity::{JOIN, Quantity, SOURCE},
        query::{PageRequest, RecordQuery},
    };
    let directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/reader-policy")
        .join(Uuid::new_v4().to_string());
    std::fs::create_dir_all(&directory).unwrap();
    let model = Arc::new(Prepared::<Quantity>::load().unwrap());
    let admin = Store::<Quantity>::create_secured(
        directory.join("test.redb"),
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    let mut g = base();
    for n in 3..=6 {
        let mut p = principal(n, vec![if n == 4 { id(3) } else { id(2) }]);
        p.grants.contracts = [SOURCE, JOIN]
            .into_iter()
            .map(|code| {
                (
                    code,
                    BTreeSet::from([Action::Read, Action::Create, Action::Update, Action::Delete]),
                )
            })
            .collect();
        g.principals.push(p);
    }
    replace(&admin, g.clone());
    for n in 3..=6 {
        let session = admin.session(id(n), 0).unwrap();
        mutate(
            &session,
            200 + n,
            json!([{"op":"create","id":id(100+n),"contract":SOURCE,"fields":{"value":"1"}}]),
        )
        .unwrap();
    }
    mutate(
        &admin,
        210,
        json!([
            {"op":"create","id":id(20),"contract":JOIN,"fields":{"left":id(103),"right":id(105)}},
            {"op":"create","id":id(21),"contract":JOIN,"fields":{"left":id(20),"right":id(104)}},
            {"op":"create","id":id(30),"contract":JOIN,"fields":{"left":id(105),"right":id(105)}},
            {"op":"create","id":id(31),"contract":JOIN,"fields":{"left":id(105),"right":id(105)}},
            {"op":"create","id":id(40),"contract":JOIN,"fields":{"left":id(106),"right":id(106)}},
            {"op":"create","id":id(41),"contract":JOIN,"fields":{"left":id(106),"right":id(106)}},
            {"op":"create","id":id(50),"contract":JOIN,"fields":{"left":id(104),"right":id(104)}},
            {"op":"create","id":id(51),"contract":JOIN,"fields":{"left":id(104),"right":id(104)}}
        ]),
    )
    .unwrap();
    // Literal source-edge expansion: child -> parent -> source3,source5;
    // then source4. The first surviving candidate is5, although parent reader3
    // alone would incorrectly summarize away that incomparable branch.
    assert_eq!(expected(&g, &[id(2), id(2), id(3), id(5), id(4)]), id(5));
    assert_quantity_source_oracle(&admin, &g);
    assert_reader(&admin, 20, JOIN, 3);
    assert_reader(&admin, 21, JOIN, 5);
    let child_before = admin.get(model.identity(), id(21)).unwrap().unwrap();
    let parent_before = admin.get(model.identity(), id(20)).unwrap().unwrap();
    let left = admin.session(id(5), 0).unwrap();
    let right = admin.session(id(6), 0).unwrap();
    let disjoint = admin.session(id(4), 0).unwrap();
    let cursor = |store: &Store<Quantity>| {
        let mut req = PageRequest {
            model: model.identity().into(),
            query: RecordQuery {
                contract: Some(JOIN),
                ..RecordQuery::default()
            },
            limit: 1,
            visit_budget: 64,
            cursor: None,
        };
        req.cursor = store.page(&req).unwrap().cursor;
        assert!(req.cursor.is_some());
        req
    };
    let left_cursor = cursor(&left);
    let right_cursor = cursor(&right);
    let disjoint_cursor = cursor(&disjoint);
    let disjoint_expected = disjoint.page(&disjoint_cursor).unwrap().records;
    mutate(&admin,211,json!([{"op":"update","id":id(20),"if_version":parent_before.version,"set":{"right":id(106)},"unset":[]}])).unwrap();
    assert_quantity_source_oracle(&admin, &g);
    assert_reader(&admin, 20, JOIN, 3);
    assert_reader(&admin, 21, JOIN, 6);
    let parent_after = admin.get(model.identity(), id(20)).unwrap().unwrap();
    let child_after = admin.get(model.identity(), id(21)).unwrap().unwrap();
    assert_eq!(parent_before.derived, parent_after.derived);
    assert_eq!(child_before.derived, child_after.derived);
    assert_ne!(child_before.version, child_after.version);
    assert_eq!(left.page(&left_cursor).unwrap_err().code, "query_changed");
    assert_eq!(right.page(&right_cursor).unwrap_err().code, "query_changed");
    assert_eq!(
        disjoint.page(&disjoint_cursor).unwrap().records,
        disjoint_expected
    );
    assert!(left.get(model.identity(), id(21)).unwrap().is_none());
    assert!(right.get(model.identity(), id(21)).unwrap().is_some());
    admin.check_integrity().unwrap();
    drop((left, right, disjoint, admin));
    std::fs::remove_dir_all(directory).unwrap();
}
