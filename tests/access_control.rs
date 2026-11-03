use rebase_semantic_proof::{
    access::{Action, Grants, Graph, Principal, PrincipalKind},
    local::{LocalStore, Mutation},
    model::PreparedModel,
    native_slice::{Context, Error},
    query::{PageRequest, RecordQuery},
    security::ReplaceGraph,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};
use uuid::Uuid;

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn grants() -> Grants {
    Grants {
        admin: false,
        contracts: (1..=10)
            .map(|code| {
                (
                    code,
                    BTreeSet::from([Action::Read, Action::Create, Action::Update, Action::Delete]),
                )
            })
            .collect(),
    }
}
fn person(n: u128, parents: &[u128]) -> Principal {
    Principal {
        id: id(n),
        kind: PrincipalKind::User,
        parents: parents.iter().copied().map(id).collect(),
        active: true,
        credential_epoch: 0,
        grants: grants(),
    }
}
fn graph() -> Graph {
    let mut graph = Graph::bootstrap(Context {
        tenant: id(1),
        actor: id(2),
    })
    .unwrap()
    .graph;
    graph
        .principals
        .extend([person(3, &[2]), person(4, &[3]), person(5, &[2])]);
    graph
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/access-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn file(&self) -> PathBuf {
        self.0.join("test.redb")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn replace(store: &LocalStore, graph: Graph) -> Result<Value, Error> {
    let revision = store.access_graph(store.model().identity())?["revision"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    store.replace_access(&ReplaceGraph {
        model: store.model().identity().into(),
        if_revision: revision,
        graph,
    })
}
fn mutation(store: &LocalStore, operation: u128, commands: Value, returning: Value) -> Mutation {
    serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":id(operation),"commands":commands,"returning":returning})).unwrap()
}
fn page(
    store: &LocalStore,
    cursor: Option<String>,
    budget: u16,
) -> rebase_semantic_proof::query::Page {
    store
        .page(&PageRequest {
            model: store.model().identity().into(),
            query: RecordQuery::default(),
            limit: 32,
            visit_budget: budget,
            cursor,
        })
        .unwrap()
}

#[test]
fn prepared_scopes_match_independent_path_search_and_preserve_diamonds() {
    // Exhaust all 64 subgraphs of six optional forward edges. Expected access
    // uses a literal parent walk, not prepared descendants or the engine fold.
    let edges = [(3, 4), (3, 5), (3, 6), (4, 5), (4, 6), (5, 6)];
    for mask in 0..64 {
        let mut g = Graph::bootstrap(Context {
            tenant: id(1),
            actor: id(2),
        })
        .unwrap()
        .graph;
        let mut parents: BTreeMap<u128, Vec<u128>> = (3..=6).map(|n| (n, vec![1])).collect();
        for (bit, &(a, b)) in edges.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                parents.get_mut(&b).unwrap().push(a);
            }
        }
        g.principals
            .extend((3..=6).map(|n| person(n, &parents[&n])));
        let prepared = g.prepare().unwrap();
        for actor in 3..=6 {
            let expected: BTreeSet<_> = (3..=6)
                .filter(|&target| {
                    let mut pending = vec![target];
                    let mut visited = BTreeSet::new();
                    while let Some(next) = pending.pop() {
                        if next == actor {
                            return true;
                        }
                        if visited.insert(next) {
                            pending.extend(parents.get(&next).into_iter().flatten());
                        }
                    }
                    false
                })
                .map(id)
                .collect();
            assert_eq!(
                prepared.scopes[&id(actor)].accessible,
                expected,
                "mask {mask}, actor {actor}"
            );
        }
    }
    let mut g = graph();
    g.principals.push(person(6, &[3]));
    g.principals
        .iter_mut()
        .find(|p| p.id == id(4))
        .unwrap()
        .parents
        .push(id(6));
    assert!(g.clone().prepare().unwrap().dominates(id(3), id(4)));
    g.principals
        .iter_mut()
        .find(|p| p.id == id(4))
        .unwrap()
        .parents
        .retain(|p| *p != id(3));
    assert!(g.clone().prepare().unwrap().dominates(id(3), id(4)));
    g.principals
        .iter_mut()
        .find(|p| p.id == id(6))
        .unwrap()
        .parents = vec![id(4)];
    assert_eq!(g.prepare().err().unwrap().code, "feedback");
}

#[test]
fn direct_group_access_inherits_grants_without_granting_siblings() {
    let mut g = graph();
    let group = Principal {
        kind: PrincipalKind::Group,
        ..person(6, &[2])
    };
    g.principals.push(group);
    for n in [4, 5] {
        let p = g.principals.iter_mut().find(|p| p.id == id(n)).unwrap();
        p.parents = vec![id(6)];
        p.grants = Grants::default();
    }
    let prepared = g.prepare().unwrap();
    let scope = &prepared.scopes[&id(4)];
    assert!(scope.accessible.contains(&id(6)));
    assert!(!scope.accessible.contains(&id(5)));
    assert!(scope.grants.allows(8, Action::Create));
}

#[test]
fn owner_partition_cursors_survive_disjoint_changes_and_fence_own_payload_edits() {
    let dir = Directory::new();
    let model = Arc::new(PreparedModel::load().unwrap());
    let admin = LocalStore::create_secured(
        dir.file(),
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    replace(&admin, graph()).unwrap();
    let left = admin.session(id(4), 0).unwrap();
    let right = admin.session(id(5), 0).unwrap();
    let authority_revision = admin.access_graph(model.identity()).unwrap()["revision"].clone();
    for (owner, account, operation) in [(&left, 10, 100), (&right, 20, 101)] {
        owner
            .mutate(&mutation(
                owner,
                operation,
                json!([{"op":"create","id":id(account),"contract":4,"fields":{"native_unit":1}}]),
                json!([]),
            ))
            .unwrap();
    }
    for (owner, account, first, operation) in [(&left, 10, 40, 102), (&right, 20, 50, 105)] {
        owner.mutate(&mutation(owner, operation, json!([
            {"op":"create","id":id(first),"contract":8,"fields":{"account":id(account),"at":"0","amount":"1"}},
            {"op":"create","id":id(first+1),"contract":8,"fields":{"account":id(account),"at":"1","amount":"1"}}
        ]), json!([]))).unwrap();
    }
    let cursor = |store: &LocalStore| {
        let mut request = PageRequest {
            model: model.identity().into(),
            query: RecordQuery {
                contract: Some(8),
                ..RecordQuery::default()
            },
            limit: 1,
            visit_budget: 64,
            cursor: None,
        };
        request.cursor = store.page(&request).unwrap().cursor;
        assert!(request.cursor.is_some());
        request
    };
    let left_cursor = cursor(&left);
    let expected = left.page(&left_cursor).unwrap().records;
    let right_version = admin
        .get(model.identity(), id(50))
        .unwrap()
        .unwrap()
        .version;
    admin.mutate(&mutation(&admin, 103,
        json!([{"op":"update","id":id(50),"if_version":right_version,"set":{"amount":"2"},"unset":[]}]),
        json!([]),
    )).unwrap();
    assert_eq!(left.page(&left_cursor).unwrap().records, expected);
    assert_eq!(
        admin.access_graph(model.identity()).unwrap()["revision"],
        authority_revision
    );
    let right_cursor = cursor(&right);
    let moving = admin
        .get(model.identity(), id(40))
        .unwrap()
        .unwrap()
        .version;
    admin.mutate(&mutation(&admin, 104,
        json!([{"op":"update","id":id(40),"if_version":moving,"set":{"amount":"3"},"unset":[]}]),
        json!([]),
    )).unwrap();
    assert_eq!(left.page(&left_cursor).unwrap_err().code, "query_changed");
    assert!(right.page(&right_cursor).is_ok());
    assert!(left.get(model.identity(), id(40)).unwrap().is_some());
    assert!(right.get(model.identity(), id(40)).unwrap().is_none());
    admin.check_integrity().unwrap();
}

#[test]
fn real_store_preserves_owner_indexes_revokes_credentials_and_redacts_receipts() {
    let dir = Directory::new();
    let model = Arc::new(PreparedModel::load().unwrap());
    let admin = LocalStore::create_secured(
        dir.file(),
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    replace(&admin, graph()).unwrap();
    let manager = admin.session(id(3), 0).unwrap();
    let child = admin.session(id(4), 0).unwrap();
    let stranger = admin.session(id(5), 0).unwrap();
    let account = mutation(
        &child,
        100,
        json!([{"op":"create","id":id(10),"contract":4,"fields":{"native_unit":1}}]),
        json!([id(10)]),
    );
    child.mutate(&account).unwrap();
    let entry = mutation(
        &manager,
        101,
        json!([{"op":"create","id":id(11),"contract":8,"fields":{"account":id(10),"at":"0","amount":"10"}}]),
        json!([id(11)]),
    );
    let result = manager.mutate(&entry).unwrap();
    assert!(child.get(model.identity(), id(11)).unwrap().is_none());
    assert!(stranger.get(model.identity(), id(11)).unwrap().is_none());
    let basis = mutation(
        &manager,
        104,
        json!([
            {"op":"create","id":id(20),"contract":4,"fields":{"native_unit":1}},
            {"op":"create","id":id(22),"contract":4,"fields":{"native_unit":1}},
            {"op":"create","id":id(21),"contract":10,"fields":{"sources":[id(20),id(10)],"factor":"1","account":id(22),"at":"2","feedback":null}}
        ]),
        json!([id(21)]),
    );
    manager.mutate(&basis).unwrap();
    assert!(child.get(model.identity(), id(21)).unwrap().is_none());
    let readable = page(&child, None, 128);
    assert_eq!(
        readable.records.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![id(10)]
    );
    let first = page(&manager, None, 1);
    assert_eq!(first.records[0].id, id(10));
    assert!(first.cursor.is_some());
    let before = admin.observe_for_verification().unwrap();
    let denied = mutation(
        &child,
        102,
        json!([{"op":"update","id":id(11),"if_version":id(999),"set":{"amount":"-999"},"unset":[]}]),
        json!([]),
    );
    assert_eq!(child.mutate(&denied).unwrap_err().code, "forbidden"); // authority before version/error details
    assert_eq!(admin.observe_for_verification().unwrap(), before);
    let denied = mutation(
        &stranger,
        103,
        json!([{"op":"create","id":id(12),"contract":8,"fields":{"account":id(10),"at":"1","amount":"1"}}]),
        json!([]),
    );
    assert_eq!(stranger.mutate(&denied).unwrap_err().code, "forbidden");
    assert_eq!(admin.observe_for_verification().unwrap(), before);
    // Moving the child out of the manager branch revokes descendant scope.
    let mut g = graph();
    g.principals
        .iter_mut()
        .find(|p| p.id == id(4))
        .unwrap()
        .parents = vec![id(1)];
    replace(&admin, g.clone()).unwrap();
    assert!(manager.get(model.identity(), id(11)).unwrap().is_some());
    assert!(child.get(model.identity(), id(11)).unwrap().is_none());
    assert!(child.get(model.identity(), id(21)).unwrap().is_none());
    assert!(manager.get(model.identity(), id(21)).unwrap().is_some());
    let raw = admin.observe_for_verification().unwrap();
    let entries = raw["tables"]["owner_records"].as_array().unwrap();
    assert_eq!(entries.len(), 5); // private outputs never enter public candidates
    let entry_key = format!("{}{:04x}{}", id(3).simple(), 8, id(11).simple());
    let basis_key = format!("{}{:04x}{}", id(3).simple(), 10, id(21).simple());
    assert!(entries.iter().any(|r| r["key"] == entry_key));
    assert!(entries.iter().any(|r| r["key"] == basis_key));
    // Revoke Read to test current-authority receipt redaction.
    g.principals
        .iter_mut()
        .find(|p| p.id == id(3))
        .unwrap()
        .grants
        .contracts
        .get_mut(&8)
        .unwrap()
        .remove(&Action::Read);
    replace(&admin, g.clone()).unwrap();
    assert!(manager.get(model.identity(), id(11)).unwrap().is_none());
    assert!(manager.get(model.identity(), id(21)).unwrap().is_some());
    let replay = manager.mutate(&entry).unwrap();
    assert_eq!(replay["result"]["records"][0]["record"], Value::Null);
    assert_eq!(
        manager
            .operation_status(
                model.identity(),
                &manager.operation_context(model.identity()).unwrap(),
                id(101)
            )
            .unwrap()["result"]["records"][0]["record"],
        Value::Null
    );
    assert_eq!(
        stranger
            .operation_status(
                model.identity(),
                &stranger.operation_context(model.identity()).unwrap(),
                id(101)
            )
            .unwrap()["status"],
        "not_observed"
    );
    assert_eq!(
        manager
            .page(&PageRequest {
                model: model.identity().into(),
                query: RecordQuery::default(),
                limit: 1,
                visit_budget: 1,
                cursor: first.cursor
            })
            .unwrap_err()
            .code,
        "query_changed"
    );
    g.principals
        .iter_mut()
        .find(|p| p.id == id(4))
        .unwrap()
        .credential_epoch = 1;
    replace(&admin, g).unwrap();
    assert_eq!(
        child.get(model.identity(), id(10)).unwrap_err().code,
        "forbidden"
    );
    let current = admin.session(id(4), 1).unwrap();
    assert!(current.get(model.identity(), id(10)).unwrap().is_some());
    assert_eq!(
        result["result"]["records"][0]["record"]["derived"],
        Value::Null
    );
    let snapshot = admin.observe_for_verification().unwrap();
    let mut bad = graph();
    bad.principals
        .iter_mut()
        .find(|p| p.id == id(3))
        .unwrap()
        .parents = vec![id(4)];
    assert_eq!(replace(&admin, bad).unwrap_err().code, "feedback");
    assert_eq!(admin.observe_for_verification().unwrap(), snapshot);
    drop((manager, child, stranger, current, admin));
    let reopened = LocalStore::open(dir.file(), model).unwrap();
    assert_eq!(reopened.observe_for_verification().unwrap(), snapshot);
    assert_eq!(
        page(&reopened.session(id(4), 1).unwrap(), None, 128)
            .records
            .iter()
            .map(|record| record.id)
            .collect::<Vec<_>>(),
        vec![id(10)]
    );
}

#[test]
fn explicit_group_ownership_shares_reads_and_updates_but_requires_ancestor_delete() {
    let dir = Directory::new();
    let model = Arc::new(PreparedModel::load().unwrap());
    let admin = LocalStore::create_secured(
        dir.file(),
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    let mut g = graph();
    g.principals.push(Principal {
        kind: PrincipalKind::Group,
        ..person(6, &[2])
    });
    for actor in [4, 5] {
        let p = g.principals.iter_mut().find(|p| p.id == id(actor)).unwrap();
        p.parents = vec![id(6)];
        p.grants = Grants::default();
    }
    replace(&admin, g).unwrap();
    let left = admin.session(id(4), 0).unwrap();
    let right = admin.session(id(5), 0).unwrap();
    left.mutate(&mutation(
        &left,
        200,
        json!([
            {"op":"create","id":id(59),"owner":id(6),"contract":4,"fields":{"native_unit":1}},
            {"op":"create","id":id(60),"owner":id(6),"contract":8,"fields":{"account":id(59),"at":"0","amount":"1"}},
            {"op":"create","id":id(61),"contract":4,"fields":{"native_unit":1}}
        ]),
        json!([]),
    ))
    .unwrap();
    assert!(left.get(model.identity(), id(61)).unwrap().is_some());
    assert!(right.get(model.identity(), id(61)).unwrap().is_none());
    let shared = right.get(model.identity(), id(60)).unwrap().unwrap();
    right.mutate(&mutation(&right, 201, json!([
        {"op":"update","id":id(60),"if_version":shared.version,"set":{"amount":"2"},"unset":[]}
    ]), json!([]))).unwrap();
    let shared = left.get(model.identity(), id(60)).unwrap().unwrap();
    assert_eq!(serde_json::to_value(shared.input).unwrap()["amount"], "2");
    for (caller, operation) in [(&left, 202), (&right, 203)] {
        let before = admin.observe_for_verification().unwrap();
        assert_eq!(
            caller
                .mutate(&mutation(
                    caller,
                    operation,
                    json!([
                        {"op":"delete","id":id(60),"if_version":shared.version}
                    ]),
                    json!([])
                ))
                .unwrap_err()
                .code,
            "forbidden"
        );
        assert_eq!(admin.observe_for_verification().unwrap(), before);
    }
    // Scope denial precedes duplicate/nil record identity checks. The earlier
    // valid command in each batch must also roll back.
    for (offset, owner) in [3, 1, 999].into_iter().enumerate() {
        for record in [id(60), Uuid::nil()] {
            let before = admin.observe_for_verification().unwrap();
            assert_eq!(left.mutate(&mutation(&left, 210 + offset as u128, json!([
                {"op":"create","id":id(70),"contract":4,"fields":{"native_unit":1}},
                {"op":"create","id":record,"owner":id(owner),"contract":4,"fields":{"native_unit":1}}
            ]), json!([]))).unwrap_err().code, "forbidden");
            assert_eq!(admin.observe_for_verification().unwrap(), before);
        }
    }
    admin
        .mutate(&mutation(
            &admin,
            220,
            json!([
                {"op":"delete","id":id(60),"if_version":shared.version}
            ]),
            json!([]),
        ))
        .unwrap();
    assert!(left.get(model.identity(), id(60)).unwrap().is_none());
    admin.check_integrity().unwrap();
}

#[test]
fn explicit_owner_wire_field_requires_a_canonical_uuid_string() {
    let dir = Directory::new();
    let store = LocalStore::create_secured(
        dir.file(),
        Arc::new(PreparedModel::load().unwrap()),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    let valid = serde_json::to_value(mutation(
        &store,
        300,
        json!([
            {"op":"create","id":id(301),"contract":4,"fields":{"native_unit":1}}
        ]),
        json!([]),
    ))
    .unwrap();
    assert!(serde_json::from_value::<Mutation>(valid.clone()).is_ok());
    for owner in [
        Value::Null,
        json!(123),
        json!("invalid"),
        json!("ABCDEFAB-0000-0000-0000-000000000006"),
    ] {
        let mut request = valid.clone();
        request["commands"][0]["owner"] = owner;
        assert!(serde_json::from_value::<Mutation>(request).is_err());
    }
}
