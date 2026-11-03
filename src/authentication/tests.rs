//! A0 witnesses derive exact claims from source identities, not dictionary caches.
use crate::{
    access::{Action, Grants, Graph, Principal, PrincipalKind},
    binding::Binding,
    local::{KV, Mutation, Store},
    model::Prepared,
    models::services::{IDENTITY, Services},
    native_codec::{self, Key, StoredValue},
    native_slice::{Context, ModelRecord},
    query::{PageRequest, RecordQuery},
    security::ReplaceGraph,
    storage::ReadableTable,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::SystemTime};
use uuid::Uuid;

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Fixture {
    store: Store<Services>,
    directory: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
fn fixture() -> Fixture {
    fixture_in(1)
}
fn fixture_in(tenant: u128) -> Fixture {
    let directory = std::env::temp_dir().join(format!("identity-contract-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();
    let context = Context {
        tenant: id(tenant),
        actor: id(2),
    };
    let store = Store::create_secured(
        directory.join("store.redb"),
        Arc::new(Prepared::<Services>::load().unwrap()),
        context,
    )
    .unwrap();
    let mut graph = Graph::bootstrap(context).unwrap().graph;
    // 4 owns itself and descendant 5; 6 is a sibling through group 3.
    // 7 is outside the administrator's ordinary owner scope.
    for (number, parent, kind) in [
        (3, 2, PrincipalKind::Group),
        (4, 3, PrincipalKind::User),
        (5, 4, PrincipalKind::User),
        (6, 3, PrincipalKind::User),
        (7, tenant, PrincipalKind::User),
    ] {
        graph.principals.push(Principal {
            id: id(number),
            kind,
            parents: vec![id(parent)],
            active: true,
            credential_epoch: 0,
            grants: Grants {
                admin: false,
                contracts: [(
                    IDENTITY,
                    [Action::Read, Action::Create, Action::Update, Action::Delete].into(),
                )]
                .into(),
            },
        });
    }
    replace(&store, graph);
    Fixture { store, directory }
}
fn replace(store: &Store<Services>, graph: Graph) {
    let if_revision = store.access_graph(store.model().identity()).unwrap()["revision"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    store
        .replace_access(&ReplaceGraph {
            model: store.model().identity().into(),
            if_revision,
            graph,
        })
        .unwrap();
}
fn graph(store: &Store<Services>) -> Graph {
    serde_json::from_value(store.access_graph(store.model().identity()).unwrap()["graph"].clone())
        .unwrap()
}
fn caller(store: &Store<Services>, actor: u128) -> Store<Services> {
    store.authenticated_session(id(actor), 0, now()).unwrap()
}
fn mutation(store: &Store<Services>, commands: Vec<Value>, returning: &[u128]) -> Mutation {
    serde_json::from_value(json!({"model":store.model().identity(),
        "context":store.operation_context(store.model().identity()).unwrap(), "operation_id":Uuid::new_v4(),
        "commands":commands,"returning":returning.iter().map(|value|id(*value)).collect::<Vec<_>>() })).unwrap()
}
fn create(source: u128, owner: u128, kind: &str, value: &str) -> Value {
    json!({"op":"create","id":id(source),"contract":IDENTITY,"owner":id(owner),"fields":{"kind":kind,"value":value}})
}
fn record(store: &Store<Services>, source: u128) -> ModelRecord<Services> {
    let read = store.db.begin_read().unwrap();
    let table = read.open_table(KV).unwrap();
    let bytes = table
        .get(Key::Record(id(source)).encode())
        .unwrap()
        .unwrap();
    match native_codec::decode_for::<Services>(&Key::Record(id(source)), bytes.value()).unwrap() {
        StoredValue::Record(record) => record,
        _ => panic!("record required"),
    }
}
fn update(store: &Store<Services>, source: u128, value: &str) -> Value {
    json!({"op":"update","id":id(source),"if_version":record(store,source).version,"set":{"value":value},"unset":[]})
}
fn delete(store: &Store<Services>, source: u128) -> Value {
    json!({"op":"delete","id":id(source),"if_version":record(store,source).version})
}
fn native_rows(store: &Store<Services>) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let read = store.db.begin_read().unwrap();
    let table = read.open_table(KV).unwrap();
    table
        .iter()
        .unwrap()
        .map(|row| {
            let (key, value) = row.unwrap();
            (key.value().to_vec(), value.value().to_vec())
        })
        .collect()
}
fn auth_revision(store: &Store<Services>, owner: u128) -> Option<u64> {
    native_rows(store)
        .get(&Key::AuthenticationRevision(id(owner)).encode())
        .map(|bytes| {
            let value: Value = serde_json::from_slice(bytes).unwrap();
            value["data"]["revision"].as_str().unwrap().parse().unwrap()
        })
}
fn assert_inventory(store: &Store<Services>) {
    let rows = native_rows(store);
    let mut expected = BTreeMap::new();
    for (key, bytes) in &rows {
        let Key::Record(source) = Key::decode(key).unwrap() else {
            continue;
        };
        let StoredValue::Record(record) =
            native_codec::decode_for::<Services>(&Key::decode(key).unwrap(), bytes).unwrap()
        else {
            panic!("record")
        };
        if record.contract != IDENTITY {
            continue;
        }
        let (input, state) = Services::identity_values(&record).unwrap();
        let claim_key = Key::IdentityClaim(input.kind, input.value.clone()).encode();
        assert!(
            expected
                .insert(
                    claim_key,
                    json!({"identity":source,"incarnation":state.incarnation})
                )
                .is_none(),
            "duplicate source claims"
        );
    }
    let actual: BTreeMap<_, _> = rows
        .iter()
        .filter(|(key, _)| key.first() == Some(&18))
        .map(|(key, bytes)| {
            let value: Value = serde_json::from_slice(bytes).unwrap();
            (key.clone(), value["data"].clone())
        })
        .collect();
    assert_eq!(actual, expected);
    store.check_integrity().unwrap();
}
fn rejects_unchanged(store: &Store<Services>, request: &Mutation, code: &str) {
    let before = store.observe_for_verification().unwrap();
    assert_eq!(store.mutate(request).unwrap_err().code, code);
    assert_eq!(store.observe_for_verification().unwrap(), before);
}

#[test]
fn recent_proof_has_exact_checked_ten_minute_boundary() {
    for (issued, at, expected) in [
        (None, 1000, false),
        (Some(400), 1000, true),
        (Some(399), 1000, false),
        (Some(1000), 1000, true),
        (Some(1001), 1000, false),
        (Some(0), 600, true),
        (Some(0), 601, false),
        (Some(u64::MAX), u64::MAX, true),
        (Some(u64::MAX - 600), u64::MAX, true),
        (Some(u64::MAX - 601), u64::MAX, false),
    ] {
        assert_eq!(super::recent(issued, at), expected, "{issued:?} at {at}");
    }
}

#[test]
fn canonical_claims_reject_duplicates_and_separate_tenants() {
    let a = fixture();
    let b = fixture_in(20);
    for f in [&a, &b] {
        let session = caller(&f.store, 4);
        let request = mutation(
            &session,
            vec![
                create(100, 4, "email", " Alice+News@EXAMPLE.COM "),
                create(101, 4, "phone", " +919876543210 "),
            ],
            &[100, 101],
        );
        session.mutate(&request).unwrap();
        assert_eq!(
            Services::identity_values(&record(&session, 100))
                .unwrap()
                .0
                .value,
            "alice+news@example.com"
        );
        assert_eq!(
            Services::identity_values(&record(&session, 101))
                .unwrap()
                .0
                .value,
            "+919876543210"
        );
        assert_inventory(&session);
        let duplicate = mutation(
            &session,
            vec![create(102, 4, "email", "ALICE+NEWS@example.com")],
            &[],
        );
        let error = session.mutate(&duplicate).unwrap_err();
        assert_eq!(error.code, "identity_duplicate");
        assert!(!format!("{error:?}").contains("alice"));
        assert!(!format!("{error:?}").contains(&id(100).to_string()));
        rejects_unchanged(&session, &duplicate, "identity_duplicate");
        let phone = mutation(
            &session,
            vec![create(103, 4, "phone", "+919876543210")],
            &[],
        );
        rejects_unchanged(&session, &phone, "identity_duplicate");
    }
    assert_eq!(
        native_rows(&a.store)
            .keys()
            .filter(|key| key[0] == 18)
            .collect::<Vec<_>>(),
        native_rows(&b.store)
            .keys()
            .filter(|key| key[0] == 18)
            .collect::<Vec<_>>()
    );
}

#[test]
fn two_and_three_way_claim_swaps_use_complete_final_graph_in_every_order() {
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let f = fixture();
        let session = caller(&f.store, 4);
        session
            .mutate(&mutation(
                &session,
                vec![
                    create(100, 4, "email", "a@example.com"),
                    create(101, 4, "email", "b@example.com"),
                    create(102, 4, "email", "c@example.com"),
                ],
                &[],
            ))
            .unwrap();
        let commands = [
            update(&session, 100, "b@example.com"),
            update(&session, 101, "c@example.com"),
            update(&session, 102, "a@example.com"),
        ];
        session
            .mutate(&mutation(
                &session,
                order.iter().map(|i| commands[*i].clone()).collect(),
                &[],
            ))
            .unwrap();
        for (source, value) in [
            (100, "b@example.com"),
            (101, "c@example.com"),
            (102, "a@example.com"),
        ] {
            let source = record(&session, source);
            let (input, state) = Services::identity_values(&source).unwrap();
            assert_eq!(input.value, value);
            assert_eq!(state.identity_revision, 2);
        }
        let commands = [
            update(&session, 100, "c@example.com"),
            update(&session, 101, "b@example.com"),
        ];
        let indices = if order[0] % 2 == 0 { [0, 1] } else { [1, 0] };
        session
            .mutate(&mutation(
                &session,
                indices.map(|i| commands[i].clone()).into(),
                &[],
            ))
            .unwrap();
        assert_inventory(&session);
        let duplicate = mutation(
            &session,
            vec![
                update(&session, 100, "joint@example.com"),
                update(&session, 101, "joint@example.com"),
            ],
            &[],
        );
        rejects_unchanged(&session, &duplicate, "identity_duplicate");
    }
}

#[test]
fn normalized_noop_keeps_lifetime_revision_indexes_and_cursor_while_replacement_invalidates() {
    let f = fixture();
    let session = caller(&f.store, 4);
    session
        .mutate(&mutation(
            &session,
            vec![
                create(100, 4, "email", "a@example.com"),
                create(101, 4, "email", "b@example.com"),
            ],
            &[],
        ))
        .unwrap();
    let old = record(&session, 100);
    let revision = auth_revision(&session, 4);
    let rows = native_rows(&session);
    let mut page = PageRequest {
        model: session.model().identity().into(),
        query: RecordQuery {
            contract: Some(IDENTITY),
            ..Default::default()
        },
        limit: 1,
        visit_budget: 64,
        cursor: None,
    };
    page.cursor = session.page(&page).unwrap().cursor;
    assert!(page.cursor.is_some());
    session
        .mutate(&mutation(
            &session,
            vec![update(&session, 100, " A@EXAMPLE.COM ")],
            &[100],
        ))
        .unwrap();
    assert_eq!(record(&session, 100), old);
    assert_eq!(auth_revision(&session, 4), revision);
    assert_eq!(native_rows(&session), rows);
    session.page(&page).unwrap();
    session
        .mutate(&mutation(
            &session,
            vec![update(&session, 100, "changed@example.com")],
            &[100],
        ))
        .unwrap();
    let new = record(&session, 100);
    let (_, state) = Services::identity_values(&new).unwrap();
    assert_eq!(state.identity_revision, 2);
    assert_eq!(state.verified_revision, None);
    assert_eq!(state.verified_at, None);
    assert_eq!(
        state.incarnation,
        Services::identity_values(&old).unwrap().1.incarnation
    );
    assert_eq!(new.created_at, old.created_at);
    assert_ne!(new.version, old.version);
    assert!(auth_revision(&session, 4).unwrap() > revision.unwrap());
    assert_eq!(session.page(&page).unwrap_err().code, "query_changed");
    assert_inventory(&session);
}

#[test]
fn last_identity_deletion_releases_claim_and_recreation_has_fresh_lifetime() {
    let f = fixture();
    let session = caller(&f.store, 4);
    session
        .mutate(&mutation(
            &session,
            vec![create(100, 4, "email", "a@example.com")],
            &[],
        ))
        .unwrap();
    let old = record(&session, 100);
    let revision = auth_revision(&session, 4).unwrap();
    session
        .mutate(&mutation(&session, vec![delete(&session, 100)], &[100]))
        .unwrap();
    assert!(
        session
            .get(session.model().identity(), id(100))
            .unwrap()
            .is_none()
    );
    assert!(native_rows(&session).keys().all(|key| key[0] != 18));
    assert!(auth_revision(&session, 4).unwrap() > revision);
    assert_inventory(&session);
    session
        .mutate(&mutation(
            &session,
            vec![create(100, 4, "email", "a@example.com")],
            &[],
        ))
        .unwrap();
    let new = record(&session, 100);
    let (_, state) = Services::identity_values(&new).unwrap();
    assert_eq!(state.identity_revision, 1);
    assert_ne!(
        state.incarnation,
        Services::identity_values(&old).unwrap().1.incarnation
    );
    assert_eq!(state.verified_revision, None);
    assert_inventory(&session);
}

#[test]
fn delete_and_reacquire_claim_in_one_final_graph_is_command_order_independent() {
    for reversed in [false, true] {
        let f = fixture();
        let session = caller(&f.store, 4);
        session
            .mutate(&mutation(
                &session,
                vec![create(100, 4, "email", "a@example.com")],
                &[],
            ))
            .unwrap();
        let mut commands = vec![
            delete(&session, 100),
            create(101, 4, "email", "a@example.com"),
        ];
        if reversed {
            commands.reverse();
        }
        session
            .mutate(&mutation(&session, commands, &[100, 101]))
            .unwrap();
        assert!(
            session
                .get(session.model().identity(), id(100))
                .unwrap()
                .is_none()
        );
        assert_inventory(&session);
    }
}

#[test]
fn self_requires_trusted_recent_proof_for_create_update_delete_and_noop() {
    let f = fixture();
    let fresh = caller(&f.store, 4);
    fresh
        .mutate(&mutation(
            &fresh,
            vec![create(100, 4, "email", "a@example.com")],
            &[],
        ))
        .unwrap();
    for session in [
        f.store.session(id(4), 0).unwrap(),
        f.store
            .authenticated_session(id(4), 0, now() - 601)
            .unwrap(),
        f.store.authenticated_session(id(4), 0, now() + 60).unwrap(),
    ] {
        for command in [
            create(101, 4, "email", "b@example.com"),
            update(&session, 100, "b@example.com"),
            delete(&session, 100),
            json!({"op":"update","id":id(100),"if_version":record(&session,100).version,"owner":id(4),"set":{},"unset":[]}),
        ] {
            rejects_unchanged(
                &session,
                &mutation(&session, vec![command], &[]),
                "forbidden",
            );
        }
        assert!(
            session
                .get(session.model().identity(), id(100))
                .unwrap()
                .is_some()
        );
    }
}

#[test]
fn strict_ancestor_management_needs_no_recency_but_group_owners_siblings_and_admin_widening_deny() {
    let f = fixture();
    let manager = f.store.session(id(4), 0).unwrap();
    manager
        .mutate(&mutation(
            &manager,
            vec![create(100, 5, "email", "child@example.com")],
            &[],
        ))
        .unwrap();
    manager
        .mutate(&mutation(
            &manager,
            vec![update(&manager, 100, "changed@example.com")],
            &[],
        ))
        .unwrap();
    let mut authority = graph(&f.store);
    authority
        .principals
        .iter_mut()
        .find(|p| p.id == id(5))
        .unwrap()
        .active = false;
    replace(&f.store, authority);
    manager
        .mutate(&mutation(&manager, vec![delete(&manager, 100)], &[]))
        .unwrap();
    for owner in [1, 3, 6, 7, 99] {
        rejects_unchanged(
            &manager,
            &mutation(
                &manager,
                vec![create(101, owner, "email", "invalid@example.com")],
                &[],
            ),
            "forbidden",
        );
    }
    rejects_unchanged(
        &f.store,
        &mutation(
            &f.store,
            vec![create(102, 7, "email", "outside@example.com")],
            &[],
        ),
        "forbidden",
    );
    // A visible, strictly dominated Group still cannot be an Identity owner.
    rejects_unchanged(
        &f.store,
        &mutation(
            &f.store,
            vec![create(104, 3, "email", "group-owner@example.com")],
            &[],
        ),
        "invalid_input",
    );
    let group = f.store.session(id(3), 0).unwrap();
    group
        .mutate(&mutation(
            &group,
            vec![create(103, 4, "email", "group-managed@example.com")],
            &[],
        ))
        .unwrap();
    assert_inventory(&f.store);
}

#[test]
fn immutable_owner_and_old_owner_scope_precede_stale_cas() {
    let f = fixture();
    let session = caller(&f.store, 4);
    session
        .mutate(&mutation(
            &session,
            vec![create(100, 4, "email", "a@example.com")],
            &[],
        ))
        .unwrap();
    let transfer = json!({"op":"update","id":id(100),"if_version":Uuid::nil(),"owner":id(5),"set":{},"unset":[]});
    rejects_unchanged(
        &session,
        &mutation(&session, vec![transfer.clone()], &[]),
        "invalid_input",
    );
    let sibling = caller(&f.store, 6);
    rejects_unchanged(
        &sibling,
        &mutation(&sibling, vec![transfer], &[]),
        "forbidden",
    );
    let mut unchanged = json!({"op":"update","id":id(100),"if_version":record(&session,100).version,"owner":id(4),"set":{},"unset":[]});
    session
        .mutate(&mutation(&session, vec![unchanged.clone()], &[]))
        .unwrap();
    unchanged["set"] = json!({"kind":"phone","value":"+123456789"});
    assert!(
        session
            .mutate(&mutation(&session, vec![unchanged], &[]))
            .is_err()
    );
    assert_inventory(&session);
}

#[test]
fn private_state_cannot_be_authored_and_never_enters_public_projection_or_receipt() {
    let f = fixture();
    let session = caller(&f.store, 4);
    let request = mutation(
        &session,
        vec![create(100, 4, "email", "a@example.com")],
        &[100],
    );
    let receipt = session.mutate(&request).unwrap();
    let source = record(&session, 100);
    let (_, state) = Services::identity_values(&source).unwrap();
    let public =
        serde_json::to_value(session.get(session.model().identity(), id(100)).unwrap()).unwrap();
    assert_eq!(
        public["derived"],
        json!({"identity_revision":"1","verified_revision":null,"verified_at":null})
    );
    for value in [
        public,
        receipt,
        session
            .operation_status(
                session.model().identity(),
                &request.context,
                request.operation_id,
            )
            .unwrap(),
        session.inspect().unwrap(),
    ] {
        assert!(!value.to_string().contains(&state.incarnation.to_string()));
    }
    for field in [
        "incarnation",
        "identity_revision",
        "verified_revision",
        "verified_at",
        "iat",
    ] {
        let mut command = create(101, 4, "email", "b@example.com");
        command["fields"][field] = json!("1");
        let before = session.observe_for_verification().unwrap();
        assert!(
            session
                .mutate(&mutation(&session, vec![command], &[]))
                .is_err()
        );
        assert_eq!(session.observe_for_verification().unwrap(), before);
    }
}

#[test]
fn original_unknown_receipt_recovers_after_recency_expiry_without_advancing_identity_or_auth_revision()
 {
    let f = fixture();
    let fresh = caller(&f.store, 4);
    let request = mutation(
        &fresh,
        vec![create(100, 4, "email", "a@example.com")],
        &[100],
    );
    assert_eq!(
        fresh
            .mutate_controlled(
                &request,
                &mut || Ok(Uuid::new_v4()),
                None,
                &mut || Ok(()),
                true
            )
            .unwrap_err()
            .code,
        "outcome_unknown"
    );
    let before = fresh.observe_for_verification().unwrap();
    let expired = f
        .store
        .authenticated_session(id(4), 0, now() - 601)
        .unwrap();
    assert_eq!(expired.mutate(&request).unwrap()["replayed"], true);
    assert_eq!(expired.observe_for_verification().unwrap(), before);
    let mut conflict = request;
    conflict.commands =
        serde_json::from_value(json!([create(100, 4, "email", "other@example.com")])).unwrap();
    rejects_unchanged(&expired, &conflict, "operation_conflict");
    assert_inventory(&f.store);
}

#[test]
fn every_native_identity_write_and_post_receipt_abort_leave_exact_original_store() {
    let f = fixture();
    let session = caller(&f.store, 4);
    let request = mutation(
        &session,
        vec![
            create(100, 4, "email", "a@example.com"),
            create(101, 5, "phone", "+123456789"),
        ],
        &[100, 101],
    );
    let before = session.observe_for_verification().unwrap();
    let mut failures = 0;
    assert_eq!(
        session
            .mutate_controlled(
                &request,
                &mut || Ok(Uuid::new_v4()),
                Some(usize::MAX),
                &mut || Ok(()),
                false
            )
            .unwrap_err()
            .code,
        "injected_abort"
    );
    assert_eq!(session.observe_for_verification().unwrap(), before);
    for after in 1..128 {
        match session.mutate_controlled(
            &request,
            &mut || Ok(Uuid::new_v4()),
            Some(after),
            &mut || Ok(()),
            false,
        ) {
            Err(error) => {
                assert_eq!(error.code, "injected_abort");
                failures += 1;
                assert_eq!(session.observe_for_verification().unwrap(), before);
            }
            Ok(_) => break,
        }
    }
    assert!(
        (8..127).contains(&failures),
        "actual native writes {failures}"
    );
    assert_inventory(&session);
}

#[test]
fn source_derived_checker_detects_missing_or_forged_claims_and_reopen_restore_preserve_state() {
    let f = fixture();
    let session = caller(&f.store, 4);
    session
        .mutate(&mutation(
            &session,
            vec![create(100, 4, "email", "a@example.com")],
            &[],
        ))
        .unwrap();
    let key = Key::IdentityClaim(super::types::Kind::Email, "a@example.com".into()).encode();
    let original = native_rows(&session)[&key].clone();
    let change = |value: Option<&[u8]>| {
        let write = session.begin_write().unwrap();
        {
            let mut table = write.open_table(KV).unwrap();
            if let Some(value) = value {
                table.insert(key.as_slice(), value).unwrap();
            } else {
                table.remove(key.as_slice()).unwrap();
            }
        }
        write.commit().unwrap();
    };
    change(None);
    assert!(session.check_integrity().is_err());
    let mut forged: Value = serde_json::from_slice(&original).unwrap();
    forged["data"]["incarnation"] = json!(Uuid::new_v4());
    change(Some(&serde_json::to_vec(&forged).unwrap()));
    assert!(session.check_integrity().is_err());
    change(Some(&original));
    assert_inventory(&session);
    let backup = f.directory.join("backup.json");
    let restored_path = f.directory.join("restored.redb");
    let model = Arc::new(Prepared::<Services>::load().unwrap());
    session.backup(&backup).unwrap();
    crate::lifecycle::restore(&backup, &restored_path, model.clone()).unwrap();
    let restored = Store::open(&restored_path, model.clone()).unwrap();
    assert_eq!(native_rows(&restored), native_rows(&session));
    assert_inventory(&restored);
    let before = native_rows(&session);
    drop(session);
    // A separately opened restored image exercises the same source/dictionary codec.
    drop(restored);
    let reopened = Store::open(&restored_path, model).unwrap();
    assert_eq!(native_rows(&reopened), before);
    assert_inventory(&reopened);
}

#[test]
fn current_action_grants_and_revoked_sessions_cannot_be_reused_by_saved_identity_intent() {
    let f = fixture();
    let session = caller(&f.store, 4);
    session
        .mutate(&mutation(
            &session,
            vec![create(100, 4, "email", "a@example.com")],
            &[],
        ))
        .unwrap();
    let saved = mutation(
        &session,
        vec![create(101, 4, "email", "b@example.com")],
        &[],
    );
    let authority = graph(&f.store);
    for action in [Action::Create, Action::Update, Action::Delete] {
        let mut denied = authority.clone();
        // Grants from the direct group parent also contribute to this actor.
        for principal in &mut denied.principals {
            if [id(3), id(4)].contains(&principal.id) {
                principal
                    .grants
                    .contracts
                    .get_mut(&IDENTITY)
                    .unwrap()
                    .remove(&action);
            }
        }
        replace(&f.store, denied);
        let command = match action {
            Action::Create => create(101, 4, "email", "b@example.com"),
            Action::Update => update(&session, 100, "b@example.com"),
            Action::Delete => delete(&session, 100),
            _ => unreachable!(),
        };
        rejects_unchanged(
            &session,
            &mutation(&session, vec![command], &[]),
            "forbidden",
        );
        replace(&f.store, authority.clone());
    }
    let mut revoked = authority;
    revoked
        .principals
        .iter_mut()
        .find(|principal| principal.id == id(4))
        .unwrap()
        .credential_epoch = 1;
    replace(&f.store, revoked);
    rejects_unchanged(&session, &saved, "forbidden");
    assert_inventory(&f.store);
}

#[test]
fn permitted_identity_update_does_not_require_metadata_read() {
    let f = fixture();
    let session = caller(&f.store, 4);
    session
        .mutate(&mutation(
            &session,
            vec![create(100, 4, "email", "a@example.com")],
            &[],
        ))
        .unwrap();
    let mut authority = graph(&f.store);
    for principal in &mut authority.principals {
        if [id(3), id(4)].contains(&principal.id) {
            principal
                .grants
                .contracts
                .get_mut(&IDENTITY)
                .unwrap()
                .remove(&Action::Read);
        }
    }
    replace(&f.store, authority);
    let receipt = session
        .mutate(&mutation(
            &session,
            vec![update(&session, 100, "b@example.com")],
            &[100],
        ))
        .unwrap();
    assert_eq!(receipt["result"]["records"][0]["record"], Value::Null);
    assert!(
        session
            .get(session.model().identity(), id(100))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        Services::identity_values(&record(&session, 100))
            .unwrap()
            .0
            .value,
        "b@example.com"
    );
    assert_inventory(&f.store);
}

#[test]
fn unscoped_native_writes_cannot_manufacture_recent_authentication() {
    let f = fixture();
    let unscoped = Store::<Services>::create(
        f.directory.join("unscoped.redb"),
        Arc::new(Prepared::<Services>::load().unwrap()),
        Context {
            tenant: id(1),
            actor: id(4),
        },
    )
    .unwrap();
    let request = mutation(
        &unscoped,
        vec![create(100, 4, "email", "a@example.com")],
        &[],
    );
    rejects_unchanged(&unscoped, &request, "forbidden");
}

#[test]
fn stale_operator_graph_cannot_overwrite_private_authentication_revision() {
    let f = fixture();
    let stale = graph(&f.store);
    let session = caller(&f.store, 4);
    session
        .mutate(&mutation(
            &session,
            vec![create(100, 4, "email", "a@example.com")],
            &[],
        ))
        .unwrap();
    session
        .mutate(&mutation(
            &session,
            vec![update(&session, 100, "b@example.com")],
            &[],
        ))
        .unwrap();
    let revision = auth_revision(&session, 4).unwrap();
    assert!(revision >= 2);
    replace(&f.store, stale);
    assert_eq!(auth_revision(&session, 4), Some(revision));
    assert_inventory(&session);
}

#[test]
fn missing_or_regressed_authentication_history_rejects_noop_replace_and_delete_atomically() {
    let f = fixture();
    let session = caller(&f.store, 4);
    session
        .mutate(&mutation(
            &session,
            vec![create(100, 4, "email", "a@example.com")],
            &[],
        ))
        .unwrap();
    session
        .mutate(&mutation(
            &session,
            vec![update(&session, 100, "b@example.com")],
            &[],
        ))
        .unwrap();
    assert_eq!(
        Services::identity_values(&record(&session, 100))
            .unwrap()
            .1
            .identity_revision,
        2
    );
    assert_eq!(auth_revision(&session, 4), Some(2));
    assert_inventory(&session);
    let key = Key::AuthenticationRevision(id(4));
    let original = native_rows(&session)[&key.encode()].clone();
    let change_history = |value: Option<&[u8]>| {
        let write = session.begin_write().unwrap();
        {
            let mut table = write.open_table(KV).unwrap();
            if let Some(value) = value {
                table.insert(key.encode().as_slice(), value).unwrap();
            } else {
                table.remove(key.encode().as_slice()).unwrap();
            }
        }
        write.commit().unwrap();
    };
    let regressed = native_codec::encode_for::<Services>(
        &key,
        &StoredValue::AuthenticationRevision(super::types::AuthenticationRevision { revision: 1 }),
    )
    .unwrap();
    for history in [None, Some(regressed.as_slice())] {
        change_history(history);
        assert!(session.check_integrity().is_err());
        for command in [
            update(&session, 100, " B@EXAMPLE.COM "),
            update(&session, 100, "c@example.com"),
            delete(&session, 100),
        ] {
            // Another owner's valid create is staged before the corrupted
            // source. Rejection must preserve the entire already-corrupt image,
            // including all claims, indexes, revisions and receipt absence.
            let request = mutation(
                &session,
                vec![create(101, 5, "phone", "+123456789"), command],
                &[],
            );
            rejects_unchanged(&session, &request, "corrupt_state");
            assert_eq!(
                session
                    .operation_status(
                        session.model().identity(),
                        &request.context,
                        request.operation_id,
                    )
                    .unwrap()["status"],
                "not_observed"
            );
        }
    }
    change_history(Some(&original));
    assert_inventory(&session);
    assert_eq!(auth_revision(&session, 4), Some(2));
    assert_eq!(auth_revision(&session, 5), None);
}

#[test]
fn identity_and_authentication_revision_overflow_rejects_the_whole_mutation() {
    for identity_overflow in [true, false] {
        let f = fixture();
        let session = caller(&f.store, 4);
        session
            .mutate(&mutation(
                &session,
                vec![create(100, 4, "email", "a@example.com")],
                &[],
            ))
            .unwrap();
        let key = if identity_overflow {
            Key::Record(id(100))
        } else {
            Key::AuthenticationRevision(id(4))
        };
        let mut value: Value =
            serde_json::from_slice(&native_rows(&session)[&key.encode()]).unwrap();
        if identity_overflow {
            value["data"]["derived"]["identity_revision"] = json!(u64::MAX.to_string());
        } else {
            value["data"]["revision"] = json!(u64::MAX.to_string());
        }
        let stored: StoredValue<Services> = serde_json::from_value(value).unwrap();
        let bytes = native_codec::encode_for::<Services>(&key, &stored).unwrap();
        // Store a valid maximal state; the next transition, not its decoding,
        // must reject instead of wrapping or partially publishing a new claim.
        native_codec::decode_for::<Services>(&key, &bytes).unwrap();
        let write = session.begin_write().unwrap();
        {
            write
                .open_table(KV)
                .unwrap()
                .insert(key.encode().as_slice(), bytes.as_slice())
                .unwrap();
        }
        write.commit().unwrap();
        if identity_overflow {
            let revision_key = Key::AuthenticationRevision(id(4));
            let bytes = native_codec::encode_for::<Services>(
                &revision_key,
                &StoredValue::AuthenticationRevision(super::types::AuthenticationRevision {
                    revision: u64::MAX,
                }),
            )
            .unwrap();
            let write = session.begin_write().unwrap();
            {
                write
                    .open_table(KV)
                    .unwrap()
                    .insert(revision_key.encode().as_slice(), bytes.as_slice())
                    .unwrap();
            }
            write.commit().unwrap();
        }
        assert_inventory(&session);
        let request = mutation(
            &session,
            vec![
                update(&session, 100, "b@example.com"),
                create(101, 5, "phone", "+123456789"),
            ],
            &[],
        );
        let before = session.observe_for_verification().unwrap();
        assert!(session.mutate(&request).is_err());
        assert_eq!(session.observe_for_verification().unwrap(), before);
    }
}

#[test]
fn normalized_noop_preserves_verified_state_but_value_replacement_clears_it() {
    let f = fixture();
    let session = caller(&f.store, 4);
    session
        .mutate(&mutation(
            &session,
            vec![create(100, 4, "email", "a@example.com")],
            &[],
        ))
        .unwrap();
    let key = Key::Record(id(100));
    let mut source = record(&session, 100);
    let Some(crate::models::services::System::Identity(state)) = source.derived.as_mut() else {
        panic!("identity state")
    };
    state.verified_revision = Some(1);
    state.verified_at = Some(1000);
    let original_incarnation = state.incarnation;
    let bytes = native_codec::encode_for::<Services>(&key, &StoredValue::Record(source)).unwrap();
    let write = session.begin_write().unwrap();
    {
        write
            .open_table(KV)
            .unwrap()
            .insert(key.encode().as_slice(), bytes.as_slice())
            .unwrap();
    }
    write.commit().unwrap();
    assert_inventory(&session);
    let before = record(&session, 100);
    let revision = auth_revision(&session, 4);
    session
        .mutate(&mutation(
            &session,
            vec![update(&session, 100, " A@EXAMPLE.COM ")],
            &[],
        ))
        .unwrap();
    assert_eq!(record(&session, 100), before);
    assert_eq!(auth_revision(&session, 4), revision);
    session
        .mutate(&mutation(
            &session,
            vec![update(&session, 100, "b@example.com")],
            &[],
        ))
        .unwrap();
    let source = record(&session, 100);
    let (_, state) = Services::identity_values(&source).unwrap();
    assert_eq!(state.identity_revision, 2);
    assert_eq!(state.incarnation, original_incarnation);
    assert_eq!(state.verified_revision, None);
    assert_eq!(state.verified_at, None);
    assert_inventory(&session);
}

#[test]
fn repeated_settlements_use_each_entry_graph_for_edits_deletion_and_new_identity_lifetime() {
    use crate::native_slice::{Attempt, Command, Result};

    fn chunk<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Attempt<L, Services>,
        store: &Store<Services>,
        write: &crate::storage::WriteTransaction,
        scope: &crate::access::Scope,
        command: Value,
    ) {
        let command: Command = serde_json::from_value(command).unwrap();
        crate::mutation::settle_authorized(
            ws,
            store.model(),
            store.context(),
            &[command],
            &mut || Ok(Uuid::new_v4()),
            false,
            &mut |_, command, old, new| {
                super::authorize_identity_command::<Services>(
                    write,
                    scope,
                    true,
                    Some(now()),
                    command,
                    old,
                    new,
                    &mut None,
                )
            },
            &mut |_, _| Ok(()),
        )
        .unwrap();
    }
    for preexisting in [false, true] {
        let f = fixture();
        let session = caller(&f.store, 4);
        if preexisting {
            session
                .mutate(&mutation(
                    &session,
                    vec![create(100, 4, "email", "a@example.com")],
                    &[],
                ))
                .unwrap();
        }
        let write = session.begin_write().unwrap();
        let scope = session.write_authority(&write).unwrap();
        let batch = {
            let table = write.open_table(KV).unwrap();
            let mut ws = Attempt::<_, Services>::new(
                |key: &[u8]| {
                    Ok(table
                        .get(key)
                        .map_err(crate::local::storage)?
                        .map(|value| value.value().to_vec()))
                },
                200_000,
            );
            if !preexisting {
                chunk(
                    &mut ws,
                    &session,
                    &write,
                    &scope,
                    create(100, 4, "email", "a@example.com"),
                );
            }
            let initial = ws.record(id(100)).unwrap().unwrap();
            let original_incarnation = Services::identity_values(&initial).unwrap().1.incarnation;
            for (previous, value, revision) in [
                ("a@example.com", "b@example.com", 2),
                ("b@example.com", "c@example.com", 3),
            ] {
                let version = ws.record(id(100)).unwrap().unwrap().version;
                chunk(
                    &mut ws,
                    &session,
                    &write,
                    &scope,
                    json!({"op":"update","id":id(100),"if_version":version,"set":{"value":value},"unset":[]}),
                );
                let source = ws.record(id(100)).unwrap().unwrap();
                let (input, state) = Services::identity_values(&source).unwrap();
                assert_eq!(input.value, value);
                assert_eq!(state.identity_revision, revision);
                assert_eq!(state.incarnation, original_incarnation);
                assert!(
                    ws.get(&Key::IdentityClaim(
                        super::types::Kind::Email,
                        previous.into()
                    ))
                    .unwrap()
                    .is_none()
                );
                assert_eq!(
                    ws.get(&Key::IdentityClaim(super::types::Kind::Email, value.into()))
                        .unwrap(),
                    Some(StoredValue::IdentityClaim(super::types::Claim {
                        identity: id(100),
                        incarnation: original_incarnation
                    }))
                );
                assert_eq!(
                    ws.get(&Key::AuthenticationRevision(id(4))).unwrap(),
                    Some(StoredValue::AuthenticationRevision(
                        super::types::AuthenticationRevision { revision }
                    ))
                );
            }
            let before_noop = ws.record(id(100)).unwrap().unwrap();
            chunk(
                &mut ws,
                &session,
                &write,
                &scope,
                json!({"op":"update","id":id(100),"if_version":before_noop.version,"set":{"value":" C@EXAMPLE.COM "},"unset":[]}),
            );
            assert_eq!(ws.record(id(100)).unwrap(), Some(before_noop.clone()));
            assert_eq!(
                ws.get(&Key::AuthenticationRevision(id(4))).unwrap(),
                Some(StoredValue::AuthenticationRevision(
                    super::types::AuthenticationRevision { revision: 3 }
                ))
            );
            chunk(
                &mut ws,
                &session,
                &write,
                &scope,
                json!({"op":"delete","id":id(100),"if_version":before_noop.version}),
            );
            assert!(ws.record(id(100)).unwrap().is_none());
            assert!(
                ws.get(&Key::IdentityClaim(
                    super::types::Kind::Email,
                    "c@example.com".into()
                ))
                .unwrap()
                .is_none()
            );
            assert_eq!(
                ws.get(&Key::AuthenticationRevision(id(4))).unwrap(),
                Some(StoredValue::AuthenticationRevision(
                    super::types::AuthenticationRevision { revision: 4 }
                ))
            );
            chunk(
                &mut ws,
                &session,
                &write,
                &scope,
                create(100, 4, "email", "c@example.com"),
            );
            let recreated = ws.record(id(100)).unwrap().unwrap();
            let (_, state) = Services::identity_values(&recreated).unwrap();
            assert_eq!(state.identity_revision, 1);
            assert_ne!(state.incarnation, original_incarnation);
            let reincarnation = state.incarnation;
            assert_eq!(
                ws.get(&Key::AuthenticationRevision(id(4))).unwrap(),
                Some(StoredValue::AuthenticationRevision(
                    super::types::AuthenticationRevision { revision: 5 }
                ))
            );
            chunk(
                &mut ws,
                &session,
                &write,
                &scope,
                json!({"op":"update","id":id(100),"if_version":recreated.version,"set":{"value":"d@example.com"},"unset":[]}),
            );
            let final_source = ws.record(id(100)).unwrap().unwrap();
            let (input, state) = Services::identity_values(&final_source).unwrap();
            assert_eq!(input.value, "d@example.com");
            assert_eq!(state.identity_revision, 2);
            assert_eq!(state.incarnation, reincarnation);
            assert_eq!(
                ws.get(&Key::AuthenticationRevision(id(4))).unwrap(),
                Some(StoredValue::AuthenticationRevision(
                    super::types::AuthenticationRevision { revision: 6 }
                ))
            );
            ws.finish().unwrap()
        };
        session.publish_native(&write, &batch, None).unwrap();
        write.commit().unwrap();
        assert_eq!(auth_revision(&session, 4), Some(6));
        assert_inventory(&session);
    }
}
