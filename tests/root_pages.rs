use rebase_semantic_proof::{
    access::{Action, Grants, Graph, Principal, PrincipalKind},
    local::{LocalStore, Mutation},
    model::PreparedModel,
    native_slice::Context,
    root_page::{RootPagePolicy, RootPageRequest},
    security::ReplaceGraph,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::PathBuf, sync::Arc};
use uuid::Uuid;
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
struct Fixture {
    store: LocalStore,
    path: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
fn mutate(store: &LocalStore, commands: Value) {
    let request:Mutation=serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":Uuid::new_v4(),"commands":commands,"returning":[]})).unwrap();
    store.mutate(&request).unwrap();
}
fn fixture() -> Fixture {
    let path = std::env::temp_dir().join(format!("public-rank-{}.redb", Uuid::new_v4()));
    let store = LocalStore::create_secured(
        &path,
        Arc::new(PreparedModel::load().unwrap()),
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
    let grants = Grants {
        admin: false,
        contracts: (1..=10)
            .map(|code| {
                (
                    code,
                    BTreeSet::from([Action::Read, Action::Create, Action::Update, Action::Delete]),
                )
            })
            .collect(),
    };
    graph.principals.extend([
        Principal {
            id: id(3),
            kind: PrincipalKind::User,
            // Store-session page checks require actual ancestor scope. User 4
            // remains on a separate branch for hidden-peer denial checks.
            parents: vec![id(2)],
            active: true,
            credential_epoch: 0,
            grants: grants.clone(),
        },
        Principal {
            id: id(4),
            kind: PrincipalKind::User,
            parents: vec![id(1)],
            active: true,
            credential_epoch: 0,
            grants,
        },
    ]);
    replace(&store, graph);
    let child = store.session(id(3), 0).unwrap();
    mutate(
        &child,
        json!([
            {"op":"create","id":id(10),"contract":4,"fields":{"native_unit":1}},
            {"op":"create","id":id(11),"contract":4,"fields":{"native_unit":1}},
            {"op":"create","id":id(20),"contract":8,"fields":{"account":id(10),"at":"0","amount":"1"}},
            {"op":"create","id":id(21),"contract":8,"fields":{"account":id(10),"at":"0","amount":"2"}},
            {"op":"create","id":id(22),"contract":8,"fields":{"account":id(10),"at":"2","amount":"3"}},
            {"op":"create","id":id(30),"contract":10,"fields":{"sources":[id(11)],"factor":"1","account":id(10),"at":"-1","feedback":null}},
            {"op":"create","id":id(40),"contract":2,"fields":{"native_unit":1,"reporting_unit":1}}
        ]),
    );
    Fixture { store, path }
}
fn replace(store: &LocalStore, graph: Graph) {
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
fn request(store: &LocalStore) -> RootPageRequest {
    RootPageRequest {
        model: store.model().identity().into(),
        owner: id(10),
        slot: 2,
        limit: 2,
        candidate_budget: 4,
        cursor: None,
    }
}
#[test]
fn independent_visible_oracle_and_private_gaps_compose() {
    let f = fixture();
    let user = f.store.session(id(3), 0).unwrap();
    let mut request = request(&user);
    request.limit = 1;
    request.candidate_budget = 1;
    let mut found = vec![];
    let mut ranks = vec![];
    let mut visited = 0;
    for turn in 0..10 {
        let page = user
            .root_page(&request, &RootPagePolicy::default())
            .unwrap();
        assert_eq!(page.total, 4);
        assert!(page.visited <= 1);
        visited += page.visited;
        if turn == 0 {
            assert!(page.occurrences.is_empty());
            assert!(page.cursor.is_some());
        }
        for item in &page.occurrences {
            assert_eq!(item.record.contract, 8);
            found.push(item.record.id);
            ranks.push(item.rank);
        }
        if page.exhausted {
            assert!(page.cursor.is_none());
            break;
        }
        assert!(page.visited > 0);
        request.cursor = page.cursor;
    }
    // Oracle is authored entry order (at, UUID, slot); the managed output at -1
    // occupies one raw position and is never a public record.
    assert_eq!(found, vec![id(20), id(21), id(22)]);
    assert_eq!(ranks, vec![1, 2, 3]);
    assert_eq!(visited, 4);
}
#[test]
fn output_target_does_not_drop_readable_tail_and_empty_root_finishes() {
    let f = fixture();
    let mut r = request(&f.store);
    r.limit = 2;
    let first = f.store.root_page(&r, &RootPagePolicy::default()).unwrap();
    assert_eq!(
        first
            .occurrences
            .iter()
            .map(|n| n.record.id)
            .collect::<Vec<_>>(),
        vec![id(20), id(21)]
    );
    assert_eq!(first.visited, 3);
    r.cursor = first.cursor;
    let last = f.store.root_page(&r, &RootPagePolicy::default()).unwrap();
    assert_eq!(last.occurrences[0].record.id, id(22));
    assert!(last.exhausted);
    let mut empty = request(&f.store);
    empty.owner = id(11);
    let empty = f
        .store
        .root_page(&empty, &RootPagePolicy::default())
        .unwrap();
    assert!(empty.exhausted);
    assert_eq!(empty.total, 0);
    assert_eq!(empty.visited, 0);
}
#[test]
fn owner_and_declaration_authority_is_required() {
    let f = fixture();
    let stranger = f.store.session(id(4), 0).unwrap();
    assert_eq!(
        stranger
            .root_page(&request(&stranger), &RootPagePolicy::default())
            .unwrap_err()
            .code,
        "not_found"
    );
    let mut r = request(&f.store);
    r.owner = id(40);
    r.slot = 1;
    assert_eq!(
        f.store
            .root_page(&r, &RootPagePolicy::default())
            .unwrap_err()
            .code,
        "unsupported_query"
    );
    r.owner = id(999);
    assert_eq!(
        f.store
            .root_page(&r, &RootPagePolicy::default())
            .unwrap_err()
            .code,
        "not_found"
    );
}
#[test]
fn cursor_is_integrity_only_contains_no_member_identity_and_rejects_substitution() {
    let f = fixture();
    let mut r = request(&f.store);
    r.limit = 1;
    r.candidate_budget = 1;
    let page = f.store.root_page(&r, &RootPagePolicy::default()).unwrap();
    let token = page.cursor.unwrap();
    let payload = token.split_once('.').unwrap().0;
    let bytes: Vec<_> = payload
        .as_bytes()
        .chunks_exact(2)
        .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
        .collect();
    let payload: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(payload["next"], 1);
    assert!(payload.get("after").is_none());
    assert!(payload.get("key").is_none());
    assert!(payload.get("limit").is_none());
    assert!(payload.get("candidate_budget").is_none());
    for hidden in [20, 21, 22, 30] {
        assert!(
            !std::str::from_utf8(&bytes)
                .unwrap()
                .contains(&id(hidden).to_string())
        );
    }
    r.cursor = Some(token.clone());
    let mut wrong = r.clone();
    wrong.owner = id(11);
    assert_eq!(
        f.store
            .root_page(&wrong, &RootPagePolicy::default())
            .unwrap_err()
            .code,
        "invalid_cursor"
    );
    let mut wrong_slot = r.clone();
    wrong_slot.slot = 3;
    assert!(
        f.store
            .root_page(&wrong_slot, &RootPagePolicy::default())
            .is_err()
    );
    let user = f.store.session(id(3), 0).unwrap();
    assert_eq!(
        user.root_page(&r, &RootPagePolicy::default())
            .unwrap_err()
            .code,
        "invalid_cursor"
    );
    let mut wrong_model = r.clone();
    wrong_model.model = "wrong-model".into();
    assert!(
        f.store
            .root_page(&wrong_model, &RootPagePolicy::default())
            .is_err()
    );
    let other = fixture();
    let mut cross = r.clone();
    cross.model = other.store.model().identity().into();
    assert_eq!(
        other
            .store
            .root_page(&cross, &RootPagePolicy::default())
            .unwrap_err()
            .code,
        "invalid_cursor"
    );
    r.cursor = Some(format!("0{}", token));
    assert_eq!(
        f.store
            .root_page(&r, &RootPagePolicy::default())
            .unwrap_err()
            .code,
        "invalid_cursor"
    );
}
#[test]
fn member_payload_and_authority_changes_fence_continuation() {
    let f = fixture();
    let mut graph: Graph = serde_json::from_value(
        f.store.access_graph(f.store.model().identity()).unwrap()["graph"].clone(),
    )
    .unwrap();
    let grants = graph
        .principals
        .iter()
        .find(|p| p.id == id(3))
        .unwrap()
        .grants
        .clone();
    for actor in [5, 6] {
        graph.principals.push(Principal {
            id: id(actor),
            kind: PrincipalKind::User,
            parents: vec![id(3)],
            active: true,
            credential_epoch: 0,
            grants: grants.clone(),
        });
    }
    replace(&f.store, graph);
    let user = f.store.session(id(3), 0).unwrap();
    let left = f.store.session(id(5), 0).unwrap();
    let right = f.store.session(id(6), 0).unwrap();
    mutate(
        &left,
        json!([{"op":"create","id":id(70),"contract":5,"fields":{"reporting_unit":1}}]),
    );
    mutate(
        &right,
        json!([{"op":"create","id":id(71),"contract":5,"fields":{"reporting_unit":1}}]),
    );
    mutate(
        &user,
        json!([
            {"op":"create","id":id(100),"contract":1,"fields":{"c":"1"}},
            {"op":"create","id":id(101),"contract":1,"fields":{"c":"1"}},
            {"op":"create","id":id(50),"contract":5,"fields":{"reporting_unit":1}},
            {"op":"create","id":id(60),"contract":6,"fields":{"units":"1","at":"3","rule":id(100),"curve":id(40),"account":id(10),"subsidiary":id(50)}},
            {"op":"create","id":id(61),"contract":6,"fields":{"units":"1","at":"4","rule":id(100),"curve":id(40),"account":id(10),"subsidiary":id(70)}}
        ]),
    );
    let root_request = rebase_semantic_proof::query::RootRequest {
        model: user.model().identity().into(),
        owner: id(10),
        slot: 2,
        read: rebase_semantic_proof::query::RootRead::Summary,
    };
    let mut r = request(&user);
    r.limit = 1;
    r.cursor = user
        .root_page(&r, &RootPagePolicy::default())
        .unwrap()
        .cursor;
    let root_before = user.root_read(&root_request).unwrap()["revision"].clone();
    let authority_before =
        f.store.access_graph(f.store.model().identity()).unwrap()["revision"].clone();
    let posting = user.get(user.model().identity(), id(60)).unwrap().unwrap();
    mutate(
        &user,
        json!([{"op":"update","id":id(60),"if_version":posting.version,"set":{"rule":id(101)},"unset":[]} ]),
    );
    let edited = user.get(user.model().identity(), id(60)).unwrap().unwrap();
    assert_ne!(edited.version, posting.version);
    assert_eq!(edited.derived, posting.derived);
    assert_eq!(
        user.root_read(&root_request).unwrap()["revision"],
        root_before
    );
    assert_eq!(
        f.store.access_graph(f.store.model().identity()).unwrap()["revision"],
        authority_before
    );
    assert_eq!(
        user.root_page(&r, &RootPagePolicy::default())
            .unwrap_err()
            .code,
        "query_changed"
    );

    r.cursor = None;
    r.cursor = user
        .root_page(&r, &RootPagePolicy::default())
        .unwrap()
        .cursor;
    assert!(left.get(left.model().identity(), id(61)).unwrap().is_none());
    assert!(
        right
            .get(right.model().identity(), id(61))
            .unwrap()
            .is_none()
    );
    let posting = user.get(user.model().identity(), id(61)).unwrap().unwrap();
    mutate(
        &user,
        json!([{"op":"update","id":id(61),"if_version":posting.version,"set":{"subsidiary":id(71)},"unset":[]} ]),
    );
    let edited = user.get(user.model().identity(), id(61)).unwrap().unwrap();
    assert_eq!(edited.derived, posting.derived);
    assert!(left.get(left.model().identity(), id(61)).unwrap().is_none());
    assert!(
        right
            .get(right.model().identity(), id(61))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        user.root_read(&root_request).unwrap()["revision"],
        root_before
    );
    assert_eq!(
        f.store.access_graph(f.store.model().identity()).unwrap()["revision"],
        authority_before
    );
    assert_eq!(
        user.root_page(&r, &RootPagePolicy::default())
            .unwrap_err()
            .code,
        "query_changed"
    );
    let mut all = request(&user);
    all.limit = 32;
    all.candidate_budget = 128;
    let all = user.root_page(&all, &RootPagePolicy::default()).unwrap();
    assert_eq!(all.total, 6);
    assert_eq!(all.occurrences.len(), 5);
    assert!(all.occurrences.iter().all(|n| n.record.contract != 12));

    r.cursor = None;
    r.cursor = user
        .root_page(&r, &RootPagePolicy::default())
        .unwrap()
        .cursor;
    let mut graph: Graph = serde_json::from_value(
        f.store.access_graph(f.store.model().identity()).unwrap()["graph"].clone(),
    )
    .unwrap();
    graph
        .principals
        .iter_mut()
        .find(|p| p.id == id(4))
        .unwrap()
        .active = false;
    replace(&f.store, graph);
    assert_eq!(
        user.root_page(&r, &RootPagePolicy::default())
            .unwrap_err()
            .code,
        "query_changed"
    );
}
#[test]
fn trusted_ceiling_and_byte_work_failures_never_return_partial_pages() {
    let f = fixture();
    let mut r = request(&f.store);
    let mut policy = RootPagePolicy {
        max_output: 1,
        ..RootPagePolicy::default()
    };
    assert_eq!(
        f.store.root_page(&r, &policy).unwrap_err().code,
        "invalid_input"
    );
    policy = RootPagePolicy::default();
    policy.max_gets = 3;
    assert!(f.store.root_page(&r, &policy).is_err());
    policy = RootPagePolicy::default();
    policy.max_bytes = 64;
    assert!(f.store.root_page(&r, &policy).is_err());
    r.candidate_budget = 0;
    assert_eq!(
        f.store
            .root_page(&r, &RootPagePolicy::default())
            .unwrap_err()
            .code,
        "invalid_input"
    );
    assert!(
        f.store
            .root_page(&request(&f.store), &RootPagePolicy::default())
            .is_ok()
    );
}

#[test]
fn readable_root_does_not_grant_member_contract_disclosure() {
    let f = fixture();
    let mut graph: Graph = serde_json::from_value(
        f.store.access_graph(f.store.model().identity()).unwrap()["graph"].clone(),
    )
    .unwrap();
    graph
        .principals
        .iter_mut()
        .find(|p| p.id == id(3))
        .unwrap()
        .grants
        .contracts
        .get_mut(&8)
        .unwrap()
        .remove(&Action::Read);
    replace(&f.store, graph);
    let user = f.store.session(id(3), 0).unwrap();
    let mut request = request(&user);
    request.limit = 2;
    request.candidate_budget = 2;
    let first = user
        .root_page(&request, &RootPagePolicy::default())
        .unwrap();
    assert!(first.occurrences.is_empty());
    assert_eq!(first.visited, 2);
    assert!(!first.exhausted);
    request.cursor = first.cursor;
    let second = user
        .root_page(&request, &RootPagePolicy::default())
        .unwrap();
    assert!(second.occurrences.is_empty());
    assert_eq!(second.visited, 2);
    assert!(second.exhausted);
}

#[test]
fn resource_limits_can_shrink_on_resume_without_dropping_or_repeating_occurrences() {
    let f = fixture();
    let policy = RootPagePolicy::default();
    let mut request = request(&f.store);
    request.limit = 1;
    request.candidate_budget = 4;
    let first = f.store.root_page(&request, &policy).unwrap();
    let mut found: Vec<_> = first
        .occurrences
        .iter()
        .map(|n| (n.rank, n.record.id))
        .collect();
    assert_eq!(first.visited, 2);
    request.cursor = first.cursor;
    request.candidate_budget = 1;
    while request.cursor.is_some() {
        let page = f.store.root_page(&request, &policy).unwrap();
        assert!(page.visited <= 1);
        assert!(page.occurrences.len() <= 1);
        found.extend(page.occurrences.iter().map(|n| (n.rank, n.record.id)));
        request.cursor = page.cursor;
    }
    assert_eq!(found, vec![(1, id(20)), (2, id(21)), (3, id(22))]);
    let mut changed = request.clone();
    changed.cursor = f
        .store
        .root_page(
            &RootPageRequest {
                model: f.store.model().identity().into(),
                owner: id(10),
                slot: 2,
                limit: 2,
                candidate_budget: 4,
                cursor: None,
            },
            &policy,
        )
        .unwrap()
        .cursor;
    changed.limit = 1;
    changed.candidate_budget = 1;
    assert_eq!(
        f.store.root_page(&changed, &policy).unwrap().occurrences[0]
            .record
            .id,
        id(22)
    );
    changed.limit = policy.max_output + 1;
    assert_eq!(
        f.store.root_page(&changed, &policy).unwrap_err().code,
        "invalid_input"
    );
}

#[test]
fn rpc_advertises_and_enforces_the_member_contract() {
    use rebase_semantic_proof::{
        binding::{Binding, Calculation},
        model::Prepared,
        rpc,
    };
    let f = fixture();
    let user = f.store.session(id(3), 0).unwrap();
    let catalog = user.model().public_catalog();
    assert!(
        catalog["capabilities"]["methods"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "roots.page")
    );
    let mut params = serde_json::to_value(request(&user)).unwrap();
    let call = |params: Value| {
        rpc::handle(
            &user,
            &serde_json::to_vec(&json!({
                "jsonrpc":"2.0","id":"members","method":"roots.page","params":params
            }))
            .unwrap(),
        )
    };
    let reply = call(params.clone());
    assert!(reply.get("error").is_none(), "{reply}");
    assert_eq!(reply["result"]["total"], "4");
    assert_eq!(reply["result"]["occurrences"].as_array().unwrap().len(), 2);
    assert!(
        reply["result"]["occurrences"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["record"]["contract"] == 8)
    );
    params["policy"] = json!({"max_output":65535});
    assert_eq!(call(params)["error"]["data"]["kind"], "invalid_input");

    let mut declarations = Calculation::declarations().unwrap();
    let root = declarations
        .iter_mut()
        .find(|c| c.code == 4)
        .unwrap()
        .roots
        .first_mut()
        .unwrap();
    root.reads.retain(|read| *read != "summary");
    assert!(Prepared::<Calculation>::prepare(declarations).is_err());
}

#[test]
fn validated_populations_of_50_100_and_1000_page_in_authored_order() {
    for count in [50_u128, 100, 1000] {
        let f = fixture();
        mutate(
            &f.store,
            json!([{"op":"create","id":id(1000),"contract":4,"fields":{"native_unit":1}}]),
        );
        let mut source: Vec<_> = (0..count)
            .map(|i| (((i * 37) % 17) as i64, id(10_000 + i)))
            .collect();
        for rows in source.chunks(32) {
            let commands: Vec<_> = rows
                .iter()
                .map(|(at, record)| {
                    json!({
                        "op":"create","id":record,"contract":8,
                        "fields":{"account":id(1000),"at":at.to_string(),"amount":"1"}
                    })
                })
                .collect();
            mutate(&f.store, Value::Array(commands));
        }
        source.sort();
        let mut request = RootPageRequest {
            model: f.store.model().identity().into(),
            owner: id(1000),
            slot: 2,
            limit: 32,
            candidate_budget: 128,
            cursor: None,
        };
        let mut actual = Vec::new();
        loop {
            let page = f
                .store
                .root_page(&request, &RootPagePolicy::default())
                .unwrap();
            assert_eq!(page.total, count as u64);
            assert!(page.occurrences.len() <= 32);
            actual.extend(page.occurrences.into_iter().map(|o| (o.rank, o.record.id)));
            request.cursor = page.cursor;
            if page.exhausted {
                assert!(request.cursor.is_none());
                break;
            }
            assert!(request.cursor.is_some());
        }
        let expected: Vec<_> = source
            .iter()
            .enumerate()
            .map(|(rank, (_, record))| (rank as u64, *record))
            .collect();
        assert_eq!(actual, expected);
        f.store.check_integrity().unwrap();
    }
}

#[test]
fn published_root_includes_hidden_owner_contributions_without_disclosing_members() {
    let f = fixture();
    // The ancestor can reference the child-owned account, but the child cannot
    // read records owned by its user parent.
    mutate(
        &f.store,
        json!([{"op":"create","id":id(90),"contract":8,
            "fields":{"account":id(10),"at":"3","amount":"7"}}]),
    );
    let user = f.store.session(id(3), 0).unwrap();
    assert!(user.get(user.model().identity(), id(90)).unwrap().is_none());
    let root = user
        .root_read(&rebase_semantic_proof::query::RootRequest {
            model: user.model().identity().into(),
            owner: id(10),
            slot: 2,
            read: rebase_semantic_proof::query::RootRead::Summary,
        })
        .unwrap();
    let ancestor_root = f
        .store
        .root_read(&rebase_semantic_proof::query::RootRequest {
            model: f.store.model().identity().into(),
            owner: id(10),
            slot: 2,
            read: rebase_semantic_proof::query::RootRead::Summary,
        })
        .unwrap();
    assert_eq!(root, ancestor_root);
    assert_eq!(root["value"]["sum"], "13");
    let mut r = request(&user);
    r.limit = 1;
    r.candidate_budget = 1;
    let mut found = Vec::new();
    loop {
        let page = user.root_page(&r, &RootPagePolicy::default()).unwrap();
        assert_eq!(page.total, 5);
        found.extend(page.occurrences.into_iter().map(|o| o.record.id));
        if page.exhausted {
            break;
        }
        r.cursor = page.cursor;
        assert!(r.cursor.is_some());
    }
    assert_eq!(found, vec![id(20), id(21), id(22)]);
    // A peer cannot read even the root summary.
    let peer = f.store.session(id(4), 0).unwrap();
    assert!(
        peer.root_read(&rebase_semantic_proof::query::RootRequest {
            model: peer.model().identity().into(),
            owner: id(10),
            slot: 2,
            read: rebase_semantic_proof::query::RootRead::Summary,
        })
        .is_err()
    );
}
