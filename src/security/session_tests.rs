//! Independent signed-generation and identity-revocation witnesses.
use super::*;
use crate::{
    access::Action,
    credentials::store::test_support as f,
    identity::{self, Claims, IdentityConfig, TokenRequest, Verifier},
    local::Mutation,
    models::services::{IDENTITY, Services},
};
use std::collections::BTreeMap;

fn fixture() -> f::Fixture {
    let fixture = f::fixture();
    let mut graph = f::graph();
    for principal in &mut graph.principals {
        principal.grants.contracts.insert(
            IDENTITY,
            [Action::Read, Action::Create, Action::Update, Action::Delete].into(),
        );
    }
    f::replace(&fixture.store, graph);
    fixture
}
fn epoch(store: &Store<Services>, actor: u128) -> u64 {
    read_graph(&store.db.begin_read().unwrap())
        .unwrap()
        .graph
        .principals
        .iter()
        .find(|p| p.id == f::id(actor))
        .unwrap()
        .credential_epoch
}
fn current(store: &Store<Services>, actor: u128) -> Store<Services> {
    store
        .authenticated_session(
            f::id(actor),
            epoch(store, actor),
            identity::now().unwrap(),
            store.session_generation().unwrap(),
        )
        .unwrap()
}
fn request(store: &Store<Services>, commands: Value, returning: &[u128]) -> Mutation {
    serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),
        "operation_id":Uuid::new_v4(),"commands":commands,"returning":returning.iter().copied().map(f::id).collect::<Vec<_>>()})).unwrap()
}
fn create(source: u128, value: &str) -> Value {
    json!({"op":"create","id":f::id(source),"contract":IDENTITY,"fields":{"kind":"email","value":value}})
}
fn edit(store: &Store<Services>, source: u128, value: &str) -> Value {
    json!({"op":"update","id":f::id(source),"if_version":f::record(store,f::id(source)).version,"set":{"value":value},"unset":[]})
}
fn remove(store: &Store<Services>, source: u128) -> Value {
    json!({"op":"delete","id":f::id(source),"if_version":f::record(store,f::id(source)).version})
}
fn authentication_revision(store: &Store<Services>, actor: u128) -> u64 {
    let read = store.db.begin_read().unwrap();
    let table = read.open_table(KV).unwrap();
    let key = Key::AuthenticationRevision(f::id(actor));
    match table
        .get(key.encode())
        .unwrap()
        .map(|bytes| native_codec::decode_for::<Services>(&key, bytes.value()).unwrap())
    {
        None => 0,
        Some(StoredValue::AuthenticationRevision(state)) => state.revision,
        _ => panic!("authentication revision"),
    }
}
fn config() -> IdentityConfig {
    IdentityConfig {
        issuer: "generation-test".into(),
        audience: "generation-test".into(),
        max_token_seconds: 3600,
        public_keys: BTreeMap::from([(
            "test".into(),
            include_str!("../../tests/fixtures/test-ed25519-public.pem").into(),
        )]),
    }
}
const PRIVATE: &[u8] = include_bytes!("../../tests/fixtures/test-ed25519-private.pem");
fn token(store: &Store<Services>, actor: u128) -> String {
    identity::issue(
        &config(),
        &TokenRequest {
            tenant: store.context.tenant,
            actor: f::id(actor),
            epoch: epoch(store, actor),
            ttl: 900,
            key_id: "test".into(),
        },
        PRIVATE,
        store.session_generation().unwrap(),
    )
    .unwrap()
}
fn signed_session(store: &Store<Services>, token: &str) -> Store<Services> {
    let claims = Verifier::new(config())
        .unwrap()
        .verify(token, store.context.tenant)
        .unwrap();
    store
        .authenticated_session(claims.sub, claims.epoch, claims.iat, claims.generation)
        .unwrap()
}

#[test]
fn factor_changes_revoke_prior_sessions_after_success_without_revoking_creates_or_noops() {
    let fixture = fixture();
    let store = &fixture.store;
    let first = current(store, 4);
    let graph_revision = store.access_graph(store.model().identity()).unwrap()["revision"].clone();
    first
        .mutate(&request(
            &first,
            json!([create(100, "a@example.com"), create(101, "b@example.com")]),
            &[100, 101],
        ))
        .unwrap();
    assert_eq!(epoch(store, 4), 0);
    assert_eq!(authentication_revision(store, 4), 1);
    assert_eq!(
        store.access_graph(store.model().identity()).unwrap()["revision"],
        graph_revision,
        "plain creates must not write the global graph"
    );
    first
        .mutate(&request(
            &first,
            json!([edit(store, 100, " A@EXAMPLE.COM ")]),
            &[100],
        ))
        .unwrap();
    assert_eq!(epoch(store, 4), 0);
    assert_eq!(authentication_revision(store, 4), 1);
    let changed = request(
        &first,
        json!([edit(store, 100, "replacement@example.com")]),
        &[100],
    );
    let result = first.mutate(&changed).unwrap();
    assert_eq!(
        result["result"]["records"][0]["record"]["input"]["value"],
        "replacement@example.com"
    );
    assert_eq!(epoch(store, 4), 1);
    assert_eq!(authentication_revision(store, 4), 2);
    assert_eq!(
        first
            .get(store.model().identity(), f::id(100))
            .unwrap_err()
            .code,
        "forbidden"
    );
    assert_eq!(
        first
            .operation_status(
                store.model().identity(),
                &changed.context,
                changed.operation_id
            )
            .unwrap_err()
            .code,
        "forbidden"
    );
    let next = current(store, 4);
    assert_eq!(next.mutate(&changed).unwrap()["replayed"], true);
    assert_eq!(
        epoch(store, 4),
        1,
        "original receipt replay cannot revoke twice"
    );
    next.mutate(&request(
        &next,
        json!([create(102, "additional@example.com")]),
        &[],
    ))
    .unwrap();
    assert_eq!(epoch(store, 4), 1);
    assert_eq!(authentication_revision(store, 4), 3);
    let deleted = next
        .mutate(&request(
            &next,
            json!([remove(store, 100), remove(store, 101), remove(store, 102)]),
            &[100, 101, 102],
        ))
        .unwrap();
    assert!(
        deleted["result"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["record"].is_null())
    );
    assert_eq!(
        epoch(store, 4),
        2,
        "several removals revoke once per affected User"
    );
    assert_eq!(authentication_revision(store, 4), 4);
    assert_eq!(
        next.get(store.model().identity(), f::id(100))
            .unwrap_err()
            .code,
        "forbidden"
    );
    assert!(
        current(store, 4)
            .get(store.model().identity(), f::id(100))
            .unwrap()
            .is_none()
    );
    store.check_integrity().unwrap();
}

#[test]
fn revision_failure_rolls_back_source_epoch_scope_graph_cas_and_original_receipt() {
    let fixture = fixture();
    let store = &fixture.store;
    let session = current(store, 4);
    session
        .mutate(&request(
            &session,
            json!([create(100, "a@example.com"), create(101, "b@example.com")]),
            &[],
        ))
        .unwrap();
    let before = store.observe_for_verification().unwrap();
    let rejected = request(
        &session,
        json!([
            edit(store, 100, "duplicate@example.com"),
            edit(store, 101, "duplicate@example.com")
        ]),
        &[],
    );
    assert_eq!(
        session.mutate(&rejected).unwrap_err().code,
        "identity_duplicate"
    );
    assert_eq!(store.observe_for_verification().unwrap(), before);
    let valid = request(
        &session,
        json!([edit(store, 100, "replacement@example.com")]),
        &[100],
    );
    for abort in [1, usize::MAX] {
        assert_eq!(
            session
                .mutate_controlled(
                    &valid,
                    &mut || Ok(Uuid::new_v4()),
                    Some(abort),
                    &mut || Ok(()),
                    false
                )
                .unwrap_err()
                .code,
            "injected_abort"
        );
        assert_eq!(store.observe_for_verification().unwrap(), before);
    }
    session.mutate(&valid).unwrap();
    assert_eq!(epoch(store, 4), 1);
    store.check_integrity().unwrap();
}

#[test]
fn both_login_toggles_revoke_and_fence_private_proof_history_preserving_larger_operator_epochs() {
    let fixture = fixture();
    let store = &fixture.store;
    assert_eq!(authentication_revision(store, 4), 0);
    for (enabled, supplied, expected_epoch, expected_revision) in
        [(true, 5, 5, 1), (false, 5, 6, 2), (true, 6, 7, 3)]
    {
        let before = current(store, 4);
        let mut graph = read_graph(&store.db.begin_read().unwrap()).unwrap().graph;
        let principal = graph
            .principals
            .iter_mut()
            .find(|p| p.id == f::id(4))
            .unwrap();
        principal.login_access = enabled;
        principal.credential_epoch = supplied;
        f::replace(store, graph);
        assert_eq!(epoch(store, 4), expected_epoch);
        assert_eq!(authentication_revision(store, 4), expected_revision);
        assert_eq!(
            before
                .operation_context(store.model().identity())
                .unwrap_err()
                .code,
            "forbidden"
        );
        let read = store.db.begin_read().unwrap();
        let scope = current(store, 4).authority(&read).unwrap();
        assert_eq!(scope.login_access, enabled);
    }
    let mut graph = read_graph(&store.db.begin_read().unwrap()).unwrap().graph;
    graph
        .principals
        .iter_mut()
        .find(|p| p.id == f::id(6))
        .unwrap()
        .login_access = true;
    let revision = store.access_graph(store.model().identity()).unwrap()["revision"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let before = store.observe_for_verification().unwrap();
    assert!(
        store
            .replace_access(&ReplaceGraph {
                model: store.model().identity().into(),
                if_revision: revision,
                graph
            })
            .is_err()
    );
    assert_eq!(
        store.observe_for_verification().unwrap(),
        before,
        "Groups cannot acquire login eligibility"
    );
    store.check_integrity().unwrap();
}

#[test]
fn exhausted_epoch_and_authentication_revision_reject_without_partial_authority_or_factor_changes()
{
    for exhausted in ["login_epoch", "authentication_revision", "factor_epoch"] {
        let fixture = fixture();
        let store = &fixture.store;
        if exhausted == "factor_epoch" {
            let user = current(store, 4);
            user.mutate(&request(&user, json!([create(100, "a@example.com")]), &[]))
                .unwrap();
        }
        if exhausted == "authentication_revision" {
            let write = store.db.begin_write().unwrap();
            let key = Key::AuthenticationRevision(f::id(4));
            let value = StoredValue::AuthenticationRevision(
                crate::authentication::types::AuthenticationRevision { revision: u64::MAX },
            );
            write
                .open_table(KV)
                .unwrap()
                .insert(
                    key.encode().as_slice(),
                    native_codec::encode_for::<Services>(&key, &value)
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
            write.commit().unwrap();
        } else {
            let mut graph = read_graph(&store.db.begin_read().unwrap()).unwrap().graph;
            graph
                .principals
                .iter_mut()
                .find(|p| p.id == f::id(4))
                .unwrap()
                .credential_epoch = u64::MAX;
            f::replace(store, graph);
        }
        let before = store.observe_for_verification().unwrap();
        let error = if exhausted == "factor_epoch" {
            let user = current(store, 4);
            user.mutate(&request(&user, json!([remove(store, 100)]), &[]))
                .unwrap_err()
        } else {
            let snapshot = store.access_graph(store.model().identity()).unwrap();
            let mut graph = read_graph(&store.db.begin_read().unwrap()).unwrap().graph;
            graph
                .principals
                .iter_mut()
                .find(|p| p.id == f::id(4))
                .unwrap()
                .login_access = true;
            store
                .replace_access(&ReplaceGraph {
                    model: store.model().identity().into(),
                    if_revision: snapshot["revision"].as_str().unwrap().parse().unwrap(),
                    graph,
                })
                .unwrap_err()
        };
        assert_eq!(error.code, "revision_exhausted", "{exhausted}");
        assert_eq!(
            store.observe_for_verification().unwrap(),
            before,
            "{exhausted}"
        );
        store.check_integrity().unwrap();
    }
}

#[test]
fn login_toggle_cannot_repair_missing_or_regressed_identity_history() {
    for missing in [true, false] {
        let fixture = fixture();
        let store = &fixture.store;
        let user = current(store, 4);
        user.mutate(&request(&user, json!([create(100, "a@example.com")]), &[]))
            .unwrap();
        user.mutate(&request(
            &user,
            json!([edit(store, 100, "b@example.com")]),
            &[],
        ))
        .unwrap();
        let write = store.db.begin_write().unwrap();
        let key = Key::AuthenticationRevision(f::id(4));
        if missing {
            write.open_table(KV).unwrap().remove(key.encode()).unwrap();
        } else {
            let value = StoredValue::AuthenticationRevision(
                crate::authentication::types::AuthenticationRevision { revision: 1 },
            );
            write
                .open_table(KV)
                .unwrap()
                .insert(
                    key.encode().as_slice(),
                    native_codec::encode_for::<Services>(&key, &value)
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
        }
        write.commit().unwrap();
        let before = store.observe_for_verification().unwrap();
        let snapshot = store.access_graph(store.model().identity()).unwrap();
        let mut graph = read_graph(&store.db.begin_read().unwrap()).unwrap().graph;
        graph
            .principals
            .iter_mut()
            .find(|p| p.id == f::id(4))
            .unwrap()
            .login_access = true;
        let error = store
            .replace_access(&ReplaceGraph {
                model: store.model().identity().into(),
                if_revision: snapshot["revision"].as_str().unwrap().parse().unwrap(),
                graph,
            })
            .unwrap_err();
        assert_eq!(error.code, "corrupt_state");
        assert_eq!(store.observe_for_verification().unwrap(), before);
    }
}

#[test]
fn supported_restore_rejects_pre_restore_jwt_even_when_backup_restores_its_old_epoch() {
    let fixture = fixture();
    let store = &fixture.store;
    let user = current(store, 4);
    user.mutate(&request(&user, json!([create(100, "a@example.com")]), &[]))
        .unwrap();
    let old_token = token(store, 4);
    let old_generation = store.session_generation().unwrap();
    let backup = fixture.directory.join("generation.json");
    store.backup(&backup).unwrap();
    user.mutate(&request(
        &user,
        json!([edit(store, 100, "changed@example.com")]),
        &[],
    ))
    .unwrap();
    assert_eq!(epoch(store, 4), 1);
    assert_eq!(
        signed_session(store, &old_token)
            .get(store.model().identity(), f::id(100))
            .unwrap_err()
            .code,
        "forbidden"
    );
    let restored_path = fixture.directory.join("generation-restored.redb");
    let model = Arc::new(Prepared::<Services>::load().unwrap());
    crate::lifecycle::restore(&backup, &restored_path, model.clone()).unwrap();
    let restored = Store::open(&restored_path, model.clone()).unwrap();
    assert_eq!(epoch(&restored, 4), 0);
    assert_ne!(restored.session_generation().unwrap(), old_generation);
    let old_session = signed_session(&restored, &old_token);
    assert_eq!(
        old_session
            .get(restored.model().identity(), f::id(100))
            .unwrap_err()
            .code,
        "forbidden"
    );
    let new_token = token(&restored, 4);
    let new_generation = restored.session_generation().unwrap();
    let new_session = signed_session(&restored, &new_token);
    assert!(
        new_session
            .get(restored.model().identity(), f::id(100))
            .unwrap()
            .is_some()
    );
    let header = crate::local::read_header(&restored.db.begin_read().unwrap()).unwrap();
    let archived = fixture.directory.join("generation-archive.json");
    restored.archive_receipts(&archived).unwrap();
    let after = crate::local::read_header(&restored.db.begin_read().unwrap()).unwrap();
    assert_eq!(after.session_generation, new_generation);
    assert_eq!(after.store_id, header.store_id);
    assert_eq!(after.cursor_key, header.cursor_key);
    assert_eq!(after.operation_epoch, header.operation_epoch + 1);
    drop((new_session, old_session, restored));
    let reopened = Store::open(&restored_path, model).unwrap();
    assert_eq!(reopened.session_generation().unwrap(), new_generation);
    assert!(
        signed_session(&reopened, &new_token)
            .get(reopened.model().identity(), f::id(100))
            .unwrap()
            .is_some()
    );
}

#[test]
fn pinned_signing_retains_exact_past_issuance_and_missing_or_nil_generation_is_not_a_legacy_default()
 {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let now = identity::now().unwrap();
    let claims = Claims {
        iss: config().issuer,
        aud: config().audience,
        sub: f::id(4),
        tenant: f::id(1),
        epoch: 9,
        generation: f::id(500),
        iat: now - 30,
        nbf: now - 30,
        exp: now + 870,
    };
    let first = identity::issue_pinned_claims(&config(), &claims, "test", PRIVATE).unwrap();
    assert_eq!(
        identity::issue_pinned_claims(&config(), &claims, "test", PRIVATE).unwrap(),
        first
    );
    let decoded: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(first.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(decoded["iat"], now - 30);
    assert_eq!(decoded["exp"], now + 870);
    assert_eq!(decoded["generation"], f::id(500).to_string());
    let mut missing = decoded.clone();
    missing.as_object_mut().unwrap().remove("generation");
    assert!(serde_json::from_value::<Claims>(missing).is_err());
    let mut nil = claims.clone();
    nil.generation = Uuid::nil();
    assert!(identity::issue_pinned_claims(&config(), &nil, "test", PRIVATE).is_err());
    let mut revoked = config();
    revoked.public_keys.clear();
    assert!(identity::issue_pinned_claims(&revoked, &claims, "test", PRIVATE).is_err());
    let request = json!({"tenant":f::id(1),"actor":f::id(4),"epoch":0,"ttl":300,"key_id":"test","generation":f::id(500)});
    assert!(
        serde_json::from_value::<TokenRequest>(request).is_err(),
        "operator token input cannot override the trusted store generation"
    );
}
