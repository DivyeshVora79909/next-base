//! Independent A1/A2 decisions over real redb transactions and retained source facts.
//! Only this private fixture decrypts delivery to model possession of the received code.
use super::*;
use crate::{
    access::{Action, Graph},
    authentication::proof_types::Secret,
    credentials::{crypto::Provider, store::test_support as f},
    models::services::{IDENTITY, Services},
    query::{PageRequest, RecordQuery},
};
use std::sync::Arc;

struct Fixture {
    base: f::Fixture,
    runtime: Runtime,
    identifier: Input,
}
impl Fixture {
    fn store(&self) -> &Store<Services> {
        &self.base.store
    }
}
fn setup(provider: Provider) -> Fixture {
    let base = f::fixture();
    let mut graph = f::graph();
    for principal in &mut graph.principals {
        if principal.id == f::id(2) {
            principal.grants.contracts.insert(
                IDENTITY,
                [Action::Read, Action::Create, Action::Update, Action::Delete].into(),
            );
        }
        if principal.id == f::id(4) {
            principal.login_access = true;
            // Anonymous proof cannot borrow ordinary user resource authority.
            principal.grants.contracts.clear();
        }
    }
    f::replace(&base.store, graph);
    let kind = if provider == Provider::FakeSms {
        Kind::Phone
    } else {
        Kind::Email
    };
    let mut metadata = f::metadata(true);
    metadata.provider = provider;
    if kind == Kind::Phone {
        metadata.scopes = vec!["sms.send".into()];
    }
    base.store
        .write_secret(
            &base.crypto,
            &f::sealed(
                &base.store,
                &base.crypto,
                f::id(100),
                None,
                None,
                metadata,
                "A1-fixture-provider-secret",
            ),
        )
        .unwrap();
    let identifier = Input {
        kind,
        value: if kind == Kind::Phone {
            "+123456789".into()
        } else {
            "proof@example.com".into()
        },
    };
    base.store.mutate(&f::mutation(&base.store,json!([{"op":"create","id":f::id(200),"contract":IDENTITY,"owner":f::id(4),"fields":identifier}]))).unwrap();
    let policy = ServerPolicy {
        kind,
        revision: f::id(500),
        credential: f::id(100),
        owner: f::id(2),
        provider,
        account: "test-mail".into(),
        sender: (kind == Kind::Email).then(|| "sender@example.com".into()),
    };
    let runtime = Runtime {
        crypto: Crypto::test_key("proof", [23; 32]),
        policies: [(kind, policy)].into(),
        identity: IdentityConfig {
            issuer: "proof-native".into(),
            audience: "proof-test".into(),
            max_token_seconds: 900,
            public_keys: [(
                "test".into(),
                include_str!("../../tests/fixtures/test-ed25519-public.pem").into(),
            )]
            .into(),
        },
        active_signing_key: "test".into(),
        signing: [(
            "test".into(),
            Zeroizing::new(
                include_bytes!("../../tests/fixtures/test-ed25519-private.pem").to_vec(),
            ),
        )]
        .into(),
    };
    base.store.configure_authentication(Some(&runtime)).unwrap();
    base.store.check_integrity().unwrap();
    Fixture {
        base,
        runtime,
        identifier,
    }
}
fn begin_request(f: &Fixture) -> Begin {
    Begin {
        operation_id: Uuid::new_v4(),
        recovery_secret: Secret::new(crate::authentication::proof_crypto::random_secret().unwrap()),
        identifier: f.identifier.clone(),
    }
}
fn consume_request(handle: &str, code: &str) -> Consume {
    Consume {
        operation_id: Uuid::new_v4(),
        recovery_secret: Secret::new(crate::authentication::proof_crypto::random_secret().unwrap()),
        challenge: Secret::new(handle.into()),
        code: Secret::new(code.into()),
    }
}
fn status(operation: Uuid, recovery: &Secret) -> Status {
    Status {
        operation_id: operation,
        recovery_secret: recovery.clone(),
    }
}
fn begin(f: &Fixture, request: &Begin) -> Value {
    f.store()
        .begin_proof(&f.runtime, request, "127.0.0.1")
        .unwrap()
}
fn consume(f: &Fixture, request: &Consume) -> Value {
    f.store()
        .consume_proof(&f.runtime, request, "127.0.0.1")
        .unwrap()
}
fn challenges(store: &Store<Services>) -> Vec<Challenge> {
    let read = store.db.begin_read().unwrap();
    read.open_table(CHALLENGES)
        .unwrap()
        .iter()
        .unwrap()
        .map(|row| local::decode(row.unwrap().1.value()).unwrap())
        .collect()
}
fn original_challenge(f: &Fixture, operation: Uuid) -> Challenge {
    challenges(f.store())
        .into_iter()
        .find(|c| c.operation == operation)
        .unwrap()
}
fn delivery_code(f: &Fixture, operation: Uuid) -> Zeroizing<String> {
    let c = original_challenge(f, operation);
    let source = f::record(f.store(), c.source);
    let delivery = Services::auth_delivery(&source.input).unwrap();
    let (_, _, header) = f.store().read(f.store().model().identity()).unwrap();
    let bytes = f
        .runtime
        .crypto
        .open(
            &delivery_aad(header.store_id, f.store().context.tenant, delivery),
            &delivery.payload,
        )
        .unwrap();
    let payload: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(payload["recipient"], f.identifier.value);
    assert_eq!(
        payload["kind"],
        serde_json::to_value(f.identifier.kind).unwrap()
    );
    Zeroizing::new(payload["code"].as_str().unwrap().to_owned())
}
fn wrong_code(correct: &str) -> String {
    let mut bytes = correct.as_bytes().to_vec();
    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
    String::from_utf8(bytes).unwrap()
}
fn table_len(store: &Store<Services>, definition: Definition) -> u64 {
    store
        .db
        .begin_read()
        .unwrap()
        .open_table(definition)
        .unwrap()
        .len()
        .unwrap()
}
fn full_image(store: &Store<Services>) -> Value {
    let read = store.db.begin_read().unwrap();
    let proof: Vec<_> = TABLES
        .into_iter()
        .map(|(def, _)| {
            let rows: Vec<_> = read
                .open_table(def)
                .unwrap()
                .iter()
                .unwrap()
                .map(|row| {
                    let (k, v) = row.unwrap();
                    json!([native_codec::hex(k.value()), native_codec::hex(v.value())])
                })
                .collect();
            json!({"table":def.name(),"rows":rows})
        })
        .collect();
    json!({"application":store.observe_for_verification().unwrap(),"proof":proof})
}
fn current_graph(store: &Store<Services>) -> Graph {
    serde_json::from_value(store.access_graph(store.model().identity()).unwrap()["graph"].clone())
        .unwrap()
}
fn assert_private_inventory(f: &Fixture) {
    f.store().check_integrity().unwrap();
    let rows = challenges(f.store());
    let read = f.store().db.begin_read().unwrap();
    // Count actual immutable origin rows, independently of runtime counters.
    let mut origins = BTreeSet::new();
    let mut spent = BTreeMap::<Uuid, u8>::new();
    let mut issued = BTreeSet::new();
    for row in read.open_table(RECEIPTS).unwrap().iter().unwrap() {
        let (_, value) = row.unwrap();
        let r: Receipt = local::decode(value.value()).unwrap();
        match r.outcome {
            Outcome::Begin { challenge } => {
                if rows
                    .iter()
                    .any(|c| c.id == challenge && c.operation == r.operation)
                {
                    origins.insert(challenge);
                }
            }
            Outcome::Invalid {
                challenge: Some(id),
                spent: true,
            } => {
                *spent.entry(id).or_default() += 1;
            }
            Outcome::Invalid {
                challenge: None,
                spent: false,
            } => {}
            Outcome::Issued { challenge, .. } => {
                assert!(issued.insert(challenge));
                *spent.entry(challenge).or_default() += 1;
            }
            _ => panic!("inconsistent attempt evidence"),
        }
    }
    assert_eq!(origins.len(), rows.len());
    for c in rows {
        assert_eq!(c.attempts, *spent.get(&c.id).unwrap_or(&0));
        assert_eq!(c.consumed, issued.contains(&c.id));
    }
}

#[derive(Default)]
struct Oracle {
    attempts: u8,
    consumed: bool,
}
impl Oracle {
    fn attempt(&mut self, correct: bool, current: bool) -> bool {
        if !current || self.consumed || self.attempts == 5 {
            return false;
        }
        self.attempts += 1;
        self.consumed = correct;
        correct
    }
    fn compare(&self, c: &Challenge) {
        assert_eq!((c.attempts, c.consumed), (self.attempts, self.consumed));
    }
}

#[test]
fn native_begin_coalesces_without_extra_delivery_or_refreshed_attempt_budget() {
    for provider in [Provider::Resend, Provider::Brevo, Provider::FakeSms] {
        let f = setup(provider);
        let first = begin_request(&f);
        let accepted = begin(&f, &first);
        assert_eq!(accepted["status"], "accepted");
        assert_eq!(accepted.as_object().unwrap().len(), 3);
        let code = delivery_code(&f, first.operation_id);
        let wrong = consume_request(accepted["challenge"].as_str().unwrap(), &wrong_code(&code));
        assert_eq!(consume(&f, &wrong), invalid());
        let second = begin_request(&f);
        assert_eq!(begin(&f, &second), accepted);
        assert_eq!(table_len(f.store(), CHALLENGES), 1);
        assert_eq!(table_len(f.store(), crate::effects::EXECUTIONS), 1);
        assert_eq!(original_challenge(&f, first.operation_id).attempts, 1);
        let before = full_image(f.store());
        assert_eq!(begin(&f, &first), accepted);
        assert_eq!(full_image(f.store()), before);
        assert_private_inventory(&f);
    }
}

#[test]
fn repeated_known_and_absent_begins_share_identical_coalescing_response_shapes() {
    for known in [true, false] {
        let mut f = setup(Provider::Resend);
        if !known {
            f.identifier.value = "absent@example.com".into();
        }
        let first = begin_request(&f);
        let second = begin_request(&f);
        assert_ne!(first.operation_id, second.operation_id);
        let response = begin(&f, &first);
        assert_eq!(response["status"], "accepted");
        assert_eq!(response.as_object().unwrap().len(), 3);
        assert_eq!(
            begin(&f, &second),
            response,
            "new operation retains both handle and expiry regardless of availability"
        );
        assert_eq!(table_len(f.store(), CHALLENGES), 1);
        assert_eq!(table_len(f.store(), RECEIPTS), 2);
        assert_eq!(
            table_len(f.store(), crate::effects::EXECUTIONS),
            u64::from(known)
        );
        let challenge = original_challenge(&f, first.operation_id);
        assert_eq!(challenge.attempts, 0);
        assert_eq!(challenge.binding.is_some(), known);
        let before = full_image(f.store());
        assert_eq!(begin(&f, &first), response);
        assert_eq!(begin(&f, &second), response);
        assert_eq!(full_image(f.store()), before);
        assert_private_inventory(&f);
    }
}

#[test]
fn absent_login_denied_inactive_and_missing_policy_have_suppressed_generic_results() {
    for condition in ["absent", "login_denied", "inactive", "missing_policy"] {
        let mut f = setup(Provider::Resend);
        match condition {
            "absent" => f.identifier.value = "absent@example.com".into(),
            "missing_policy" => {
                f.runtime.policies.clear();
                f.store()
                    .configure_authentication(Some(&f.runtime))
                    .unwrap();
            }
            _ => {
                let mut graph = current_graph(f.store());
                let p = graph
                    .principals
                    .iter_mut()
                    .find(|p| p.id == f::id(4))
                    .unwrap();
                if condition == "login_denied" {
                    p.login_access = false;
                } else {
                    p.active = false;
                }
                f::replace(f.store(), graph);
            }
        }
        let request = begin_request(&f);
        let accepted = begin(&f, &request);
        assert_eq!(accepted["status"], "accepted");
        assert_eq!(accepted.as_object().unwrap().len(), 3);
        crate::authentication::proof_crypto::validate_secret(
            accepted["challenge"].as_str().unwrap(),
        )
        .unwrap();
        let c = original_challenge(&f, request.operation_id);
        assert!(c.binding.is_none());
        assert_eq!(table_len(f.store(), crate::effects::EXECUTIONS), 0);
        assert_eq!(
            consume(
                &f,
                &consume_request(accepted["challenge"].as_str().unwrap(), "000042")
            ),
            invalid()
        );
        assert_eq!(original_challenge(&f, request.operation_id).attempts, 0);
        assert_private_inventory(&f);
    }
}

#[test]
fn literal_attempt_oracle_accepts_correct_fifth_rejects_sixth_and_never_reuses_success() {
    for succeed_on in [Some(1), Some(5), None] {
        let f = setup(Provider::Resend);
        let request = begin_request(&f);
        let accepted = begin(&f, &request);
        let code = delivery_code(&f, request.operation_id);
        let wrong = wrong_code(&code);
        let mut oracle = Oracle::default();
        for number in 1..=6 {
            let correct = succeed_on == Some(number) || number == 6;
            let expected = oracle.attempt(correct, true);
            let attempt = consume_request(
                accepted["challenge"].as_str().unwrap(),
                if correct { &code } else { &wrong },
            );
            let result = consume(&f, &attempt);
            assert_eq!(
                result["status"],
                if expected {
                    "authenticated"
                } else {
                    "invalid_proof"
                }
            );
            oracle.compare(&original_challenge(&f, request.operation_id));
            let before = full_image(f.store());
            assert_eq!(consume(&f, &attempt), result);
            assert_eq!(full_image(f.store()), before);
        }
        let source = f::record(f.store(), f::id(200));
        let (_, identity) = Services::identity_values(&source).unwrap();
        assert_eq!(identity.verified_revision.is_some(), succeed_on.is_some());
        assert_private_inventory(&f);
    }
}

#[test]
fn original_recovery_after_lost_ack_retains_exact_claims_token_and_fingerprints() {
    let f = setup(Provider::Resend);
    let request = begin_request(&f);
    assert_eq!(
        f.store()
            .begin_proof_controlled(
                &f.runtime,
                &request,
                "127.0.0.1",
                None,
                &mut || Ok(()),
                true
            )
            .unwrap_err()
            .code,
        "outcome_unknown"
    );
    let accepted = f
        .store()
        .proof_status(
            &f.runtime,
            &status(request.operation_id, &request.recovery_secret),
        )
        .unwrap();
    let before = full_image(f.store());
    assert_eq!(begin(&f, &request), accepted);
    assert_eq!(full_image(f.store()), before);
    let code = delivery_code(&f, request.operation_id);
    let attempt = consume_request(accepted["challenge"].as_str().unwrap(), &code);
    assert_eq!(
        f.store()
            .consume_proof_controlled(
                &f.runtime,
                &attempt,
                "127.0.0.1",
                None,
                &mut || Ok(()),
                true
            )
            .unwrap_err()
            .code,
        "outcome_unknown"
    );
    let authenticated = f
        .store()
        .proof_status(
            &f.runtime,
            &status(attempt.operation_id, &attempt.recovery_secret),
        )
        .unwrap();
    let token = authenticated["token"].as_str().unwrap();
    let claims = crate::identity::Verifier::new(f.runtime.identity.clone())
        .unwrap()
        .verify(token, f::id(1))
        .unwrap();
    assert_eq!(claims.sub, f::id(4));
    assert_eq!(claims.exp - claims.iat, 900);
    assert_eq!(claims.nbf, claims.iat);
    let before = full_image(f.store());
    assert_eq!(consume(&f, &attempt), authenticated);
    assert_eq!(full_image(f.store()), before);
    let mut changed = attempt.clone();
    changed.code = Secret::new(wrong_code(&code));
    assert!(
        f.store()
            .consume_proof(&f.runtime, &changed, "127.0.0.1")
            .is_err()
    );
    assert_eq!(full_image(f.store()), before);
    changed = attempt.clone();
    changed.recovery_secret =
        Secret::new(crate::authentication::proof_crypto::random_secret().unwrap());
    assert!(
        f.store()
            .proof_status(
                &f.runtime,
                &status(changed.operation_id, &changed.recovery_secret)
            )
            .is_err()
    );
    assert_eq!(full_image(f.store()), before);
    assert_private_inventory(&f);
}

#[test]
fn native_one_use_concurrent_requests_publish_exactly_one_issuance() {
    let f = setup(Provider::FakeSms);
    let request = begin_request(&f);
    let accepted = begin(&f, &request);
    let code = delivery_code(&f, request.operation_id);
    let a = consume_request(accepted["challenge"].as_str().unwrap(), &code);
    let b = consume_request(accepted["challenge"].as_str().unwrap(), &code);
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let left = scope.spawn(|| {
            barrier.wait();
            consume(&f, &a)
        });
        let right = scope.spawn(|| {
            barrier.wait();
            consume(&f, &b)
        });
        [left.join().unwrap(), right.join().unwrap()]
    });
    assert_eq!(
        results
            .iter()
            .filter(|r| r["status"] == "authenticated")
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| r["status"] == "invalid_proof")
            .count(),
        1
    );
    let c = original_challenge(&f, request.operation_id);
    assert!(c.consumed);
    assert_eq!(c.attempts, 1);
    assert_private_inventory(&f);
}

#[test]
fn factor_replacement_last_deletion_recreation_and_login_changes_fence_old_proofs() {
    for transition in ["replace", "delete", "recreate", "disable_login"] {
        let f = setup(Provider::Resend);
        let request = begin_request(&f);
        let accepted = begin(&f, &request);
        let code = delivery_code(&f, request.operation_id);
        match transition {
            "replace" => {
                f.store()
                    .mutate(&f::edit(
                        f.store(),
                        f::id(200),
                        None,
                        json!({"value":"changed@example.com"}),
                    ))
                    .unwrap();
            }
            "disable_login" => {
                let mut graph = current_graph(f.store());
                graph
                    .principals
                    .iter_mut()
                    .find(|p| p.id == f::id(4))
                    .unwrap()
                    .login_access = false;
                f::replace(f.store(), graph);
            }
            _ => {
                let record = f::record(f.store(), f::id(200));
                f.store()
                    .mutate(&f::mutation(
                        f.store(),
                        json!([{"op":"delete","id":f::id(200),"if_version":record.version}]),
                    ))
                    .unwrap();
                if transition == "recreate" {
                    f.store().mutate(&f::mutation(f.store(),json!([{"op":"create","id":f::id(200),"contract":IDENTITY,"owner":f::id(4),"fields":f.identifier}]))).unwrap();
                }
            }
        }
        assert_eq!(
            consume(
                &f,
                &consume_request(accepted["challenge"].as_str().unwrap(), &code)
            ),
            invalid()
        );
        assert_eq!(original_challenge(&f, request.operation_id).attempts, 0);
        assert_eq!(
            table_len(f.store(), crate::effects::EXECUTIONS),
            1,
            "historical private delivery remains retained"
        );
        assert_private_inventory(&f);
    }
}

#[test]
fn successful_verification_changes_public_version_and_invalidates_owner_cursor() {
    let f = setup(Provider::Resend);
    f.store().mutate(&f::mutation(f.store(),json!([{"op":"create","id":f::id(201),"contract":IDENTITY,"owner":f::id(4),"fields":{"kind":"email","value":"second@example.com"}}]))).unwrap();
    let mut page = PageRequest {
        model: f.store().model().identity().into(),
        query: RecordQuery {
            contract: Some(IDENTITY),
            ..Default::default()
        },
        limit: 1,
        visit_budget: 32,
        cursor: None,
    };
    page.cursor = f.store().page(&page).unwrap().cursor;
    assert!(page.cursor.is_some());
    let source = f::record(f.store(), f::id(200));
    let request = begin_request(&f);
    let accepted = begin(&f, &request);
    let code = delivery_code(&f, request.operation_id);
    assert!(
        f.store().page(&page).is_ok(),
        "private delivery does not change public owner scope"
    );
    let attempt = consume_request(accepted["challenge"].as_str().unwrap(), &code);
    let authenticated = consume(&f, &attempt);
    assert_eq!(authenticated["status"], "authenticated");
    let verified = f::record(f.store(), f::id(200));
    assert_ne!(verified.version, source.version);
    assert_eq!(verified.created_at, source.created_at);
    assert_eq!(f.store().page(&page).unwrap_err().code, "query_changed");
    assert_private_inventory(&f);

    // Retain A0's no-op/replacement obligation using actual successful proof,
    // rather than forging verification fields without a consumption receipt.
    let claims = crate::identity::Verifier::new(f.runtime.identity.clone())
        .unwrap()
        .verify(authenticated["token"].as_str().unwrap(), f::id(1))
        .unwrap();
    let issued = f
        .store()
        .authenticated_session(claims.sub, claims.epoch, claims.iat, claims.generation)
        .unwrap();
    issued.operation_context(issued.model().identity()).unwrap();
    let auth_revision = {
        let write = f.store().begin_write().unwrap();
        revision::<Services>(&write, f::id(4)).unwrap()
    };
    let verified_state = Services::identity_values(&verified).unwrap().1.clone();
    assert_eq!(
        verified_state.verified_revision,
        Some(verified_state.identity_revision)
    );
    page.cursor = None;
    page.cursor = f.store().page(&page).unwrap().cursor;
    assert!(page.cursor.is_some());
    f.store()
        .mutate(&f::edit(
            f.store(),
            f::id(200),
            None,
            json!({"value":" PROOF@EXAMPLE.COM "}),
        ))
        .unwrap();
    assert_eq!(f::record(f.store(), f::id(200)), verified);
    {
        let write = f.store().begin_write().unwrap();
        assert_eq!(
            revision::<Services>(&write, f::id(4)).unwrap(),
            auth_revision
        );
    }
    assert_eq!(
        current_graph(f.store())
            .principals
            .iter()
            .find(|p| p.id == f::id(4))
            .unwrap()
            .credential_epoch,
        claims.epoch
    );
    f.store().page(&page).unwrap();
    issued.operation_context(issued.model().identity()).unwrap();
    assert_private_inventory(&f);
    f.store()
        .mutate(&f::edit(
            f.store(),
            f::id(200),
            None,
            json!({"value":"replacement@example.com"}),
        ))
        .unwrap();
    let replaced = f::record(f.store(), f::id(200));
    let (_, state) = Services::identity_values(&replaced).unwrap();
    assert_eq!(state.incarnation, verified_state.incarnation);
    assert_eq!(
        state.identity_revision,
        verified_state.identity_revision + 1
    );
    assert_eq!((state.verified_revision, state.verified_at), (None, None));
    assert_eq!(replaced.created_at, verified.created_at);
    {
        let write = f.store().begin_write().unwrap();
        assert_eq!(
            revision::<Services>(&write, f::id(4)).unwrap(),
            auth_revision + 1
        );
    }
    assert_eq!(
        current_graph(f.store())
            .principals
            .iter()
            .find(|p| p.id == f::id(4))
            .unwrap()
            .credential_epoch,
        claims.epoch + 1
    );
    assert_eq!(
        issued
            .operation_context(issued.model().identity())
            .unwrap_err()
            .code,
        "forbidden"
    );
    assert!(
        f.store()
            .proof_status(
                &f.runtime,
                &status(attempt.operation_id, &attempt.recovery_secret)
            )
            .is_err()
    );
    assert_private_inventory(&f);
}

#[test]
fn begin_and_consume_abort_roll_back_all_source_effect_proof_receipt_tables() {
    let f = setup(Provider::Resend);
    let request = begin_request(&f);
    let before = full_image(f.store());
    for abort in [
        1,
        usize::MAX - 1,
        usize::MAX - 2,
        usize::MAX - 3,
        usize::MAX,
    ] {
        assert_eq!(
            f.store()
                .begin_proof_controlled(
                    &f.runtime,
                    &request,
                    "127.0.0.1",
                    Some(abort),
                    &mut || Ok(()),
                    false
                )
                .unwrap_err()
                .code,
            "injected_abort"
        );
        assert_eq!(full_image(f.store()), before);
        assert_private_inventory(&f);
    }
    assert_eq!(
        f.store()
            .begin_proof_controlled(
                &f.runtime,
                &request,
                "127.0.0.1",
                None,
                &mut || Err(Error::new("injected_abort", "before proof commit")),
                false
            )
            .unwrap_err()
            .code,
        "injected_abort"
    );
    assert_eq!(full_image(f.store()), before);
    let accepted = begin(&f, &request);
    let code = delivery_code(&f, request.operation_id);
    let attempt = consume_request(accepted["challenge"].as_str().unwrap(), &code);
    let before = full_image(f.store());
    for abort in [1, usize::MAX] {
        assert_eq!(
            f.store()
                .consume_proof_controlled(
                    &f.runtime,
                    &attempt,
                    "127.0.0.1",
                    Some(abort),
                    &mut || Ok(()),
                    false
                )
                .unwrap_err()
                .code,
            "injected_abort"
        );
        assert_eq!(full_image(f.store()), before);
        assert_private_inventory(&f);
    }
    assert_eq!(
        f.store()
            .consume_proof_controlled(
                &f.runtime,
                &attempt,
                "127.0.0.1",
                None,
                &mut || Err(Error::new("injected_abort", "before consume commit")),
                false
            )
            .unwrap_err()
            .code,
        "injected_abort"
    );
    assert_eq!(full_image(f.store()), before);
    assert_private_inventory(&f);
}

#[test]
fn expiry_predicate_is_strict_and_supported_restore_rejects_old_proof_recovery() {
    let f = setup(Provider::Resend);
    let request = begin_request(&f);
    let accepted = begin(&f, &request);
    let code = delivery_code(&f, request.operation_id);
    let c = original_challenge(&f, request.operation_id);
    {
        let write = f.store().begin_write().unwrap();
        let header = header(&write).unwrap();
        assert!(
            challenge_current::<Services>(&write, &header, &c, c.expires_at - 1, false).unwrap()
        );
        assert!(!challenge_current::<Services>(&write, &header, &c, c.expires_at, false).unwrap());
        assert!(
            !challenge_current::<Services>(&write, &header, &c, c.created_at - 1, false).unwrap()
        );
    }
    let attempt = consume_request(accepted["challenge"].as_str().unwrap(), &code);
    let authenticated = consume(&f, &attempt);
    assert_eq!(authenticated["status"], "authenticated");
    let backup = f.base.directory.join("proof-backup.json");
    f.store().backup(&backup).unwrap();
    let restored = f.base.directory.join("restored.redb");
    crate::lifecycle::restore(
        &backup,
        &restored,
        Arc::new(crate::model::Prepared::<Services>::load().unwrap()),
    )
    .unwrap();
    let store = Store::<Services>::open(
        &restored,
        Arc::new(crate::model::Prepared::<Services>::load().unwrap()),
    )
    .unwrap();
    let (_, _, old) = f.store().read(f.store().model().identity()).unwrap();
    let (_, _, new) = store.read(store.model().identity()).unwrap();
    assert_ne!(old.session_generation, new.session_generation);
    assert!(
        store
            .proof_status(
                &f.runtime,
                &status(request.operation_id, &request.recovery_secret)
            )
            .is_err()
    );
    assert!(
        store
            .proof_status(
                &f.runtime,
                &status(attempt.operation_id, &attempt.recovery_secret)
            )
            .is_err()
    );
    store.check_integrity().unwrap();
}

#[test]
fn backup_contains_no_plaintext_code_handle_recovery_token_or_signing_key() {
    let f = setup(Provider::Resend);
    let request = begin_request(&f);
    let accepted = begin(&f, &request);
    let code = delivery_code(&f, request.operation_id);
    let attempt = consume_request(accepted["challenge"].as_str().unwrap(), &code);
    let authenticated = consume(&f, &attempt);
    let path = f.base.directory.join("no-secrets.json");
    f.store().backup(&path).unwrap();
    let backup: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    for rows in backup["payload"]["tables"].as_object().unwrap().values() {
        for row in rows.as_array().unwrap() {
            let Some(value) = row.get("value").and_then(Value::as_str) else {
                continue;
            };
            let bytes = local::unhex(value).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            for secret in [
                accepted["challenge"].as_str().unwrap(),
                request.recovery_secret.as_str(),
                attempt.recovery_secret.as_str(),
                authenticated["token"].as_str().unwrap(),
                "PRIVATE KEY",
            ] {
                assert!(!text.contains(secret));
            }
            assert!(
                !text.contains(&format!("\"{}\"", code.as_str())),
                "raw code field must never persist"
            );
        }
    }
    assert_private_inventory(&f);
}

#[test]
fn independent_checker_rejects_forged_attempt_count_and_missing_handle_then_recovers() {
    let f = setup(Provider::Resend);
    let request = begin_request(&f);
    begin(&f, &request);
    let c = original_challenge(&f, request.operation_id);
    let write = f.store().begin_write().unwrap();
    let original = write
        .open_table(CHALLENGES)
        .unwrap()
        .get(c.id.as_bytes().as_slice())
        .unwrap()
        .unwrap()
        .value()
        .to_vec();
    let mut forged = c.clone();
    forged.attempts = 1;
    write
        .open_table(CHALLENGES)
        .unwrap()
        .insert(
            c.id.as_bytes().as_slice(),
            local::encode(&forged).unwrap().as_slice(),
        )
        .unwrap();
    write.commit().unwrap();
    assert!(f.store().check_integrity().is_err());
    let write = f.store().begin_write().unwrap();
    write
        .open_table(CHALLENGES)
        .unwrap()
        .insert(c.id.as_bytes().as_slice(), original.as_slice())
        .unwrap();
    let handle = write
        .open_table(HANDLES)
        .unwrap()
        .remove(c.handle_digest.as_bytes())
        .unwrap()
        .unwrap()
        .value()
        .to_vec();
    write.commit().unwrap();
    assert!(f.store().check_integrity().is_err());
    let write = f.store().begin_write().unwrap();
    write
        .open_table(HANDLES)
        .unwrap()
        .insert(c.handle_digest.as_bytes(), handle.as_slice())
        .unwrap();
    write.commit().unwrap();
    assert_private_inventory(&f);
}

fn retained_receipts(f: &Fixture) -> Vec<Receipt> {
    let read = f.store().db.begin_read().unwrap();
    read.open_table(RECEIPTS)
        .unwrap()
        .iter()
        .unwrap()
        .map(|row| local::decode(row.unwrap().1.value()).unwrap())
        .collect()
}

/// Corruption fixtures deliberately keep counters, retained points and public
/// verification synchronized with the forged facts. Only the independent
/// temporal/admission contract can distinguish these from valid inventories.
fn replace_retained_receipts(f: &Fixture, rows: &[Receipt]) {
    let write = f.store().begin_write().unwrap();
    let mut table = write.open_table(RECEIPTS).unwrap();
    let keys: Vec<_> = table
        .iter()
        .unwrap()
        .map(|row| row.unwrap().0.value().to_vec())
        .collect();
    for key in keys {
        table.remove(key.as_slice()).unwrap();
    }
    for row in rows {
        table
            .insert(
                row.operation.as_bytes().as_slice(),
                local::encode(row).unwrap().as_slice(),
            )
            .unwrap();
        if let Outcome::Issued { challenge, .. } = row.outcome {
            let c: Challenge = get(&write.open_table(CHALLENGES).unwrap(), challenge.as_bytes())
                .unwrap()
                .unwrap();
            let binding = c.binding.unwrap();
            let mut record = source::<Services>(&write, binding.identity)
                .unwrap()
                .unwrap();
            let Some(crate::models::services::System::Identity(identity)) = record.derived.as_mut()
            else {
                panic!("identity state");
            };
            identity.verified_at = Some(row.created_at);
            let key = Key::Record(binding.identity);
            write
                .open_table(KV)
                .unwrap()
                .insert(
                    key.encode().as_slice(),
                    native_codec::encode_for::<Services>(&key, &StoredValue::Record(record))
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
        }
    }
    drop(table);
    let mut state = state(&write).unwrap();
    state.challenges = write.open_table(CHALLENGES).unwrap().len().unwrap() as u16;
    state.receipts = rows.len() as u16;
    state.last_at = rows.iter().map(|row| row.created_at).max().unwrap_or(0);
    state.points = rows
        .iter()
        .flat_map(|row| row.admission.iter().cloned())
        .filter(|point| point.at > state.last_at.saturating_sub(PROOF_MS))
        .collect();
    store_state(&write, &state).unwrap();
    write.commit().unwrap();
}

#[test]
fn checker_rejects_receipts_outside_challenge_lifetime_and_wrong_spent_generation() {
    for success in [false, true] {
        let f = setup(Provider::Resend);
        let request = begin_request(&f);
        let accepted = begin(&f, &request);
        let c = original_challenge(&f, request.operation_id);
        let code = delivery_code(&f, request.operation_id);
        let attempt = consume_request(
            accepted["challenge"].as_str().unwrap(),
            &if success {
                code.to_string()
            } else {
                wrong_code(&code)
            },
        );
        consume(&f, &attempt);
        let originals = retained_receipts(&f);
        assert_private_inventory(&f);
        for at in [c.created_at - 1, c.expires_at] {
            let mut forged = originals.clone();
            let row = forged
                .iter_mut()
                .find(|row| row.operation == attempt.operation_id)
                .unwrap();
            row.created_at = at;
            for point in &mut row.admission {
                point.at = at;
            }
            if let Outcome::Issued { issuance, .. } = &mut row.outcome {
                issuance.claims.iat = at as u64 / 1000;
                issuance.claims.nbf = issuance.claims.iat;
                issuance.claims.exp = issuance.claims.iat + 900;
            }
            replace_retained_receipts(&f, &forged);
            assert!(
                f.store().check_integrity().is_err(),
                "accepted out-of-lifetime receipt"
            );
        }
        if !success {
            let mut forged = originals.clone();
            forged
                .iter_mut()
                .find(|row| row.operation == attempt.operation_id)
                .unwrap()
                .generation = Uuid::new_v4();
            replace_retained_receipts(&f, &forged);
            assert!(
                f.store().check_integrity().is_err(),
                "accepted another generation's spent attempt"
            );
        }
        replace_retained_receipts(&f, &originals);
        assert_private_inventory(&f);
    }
}

#[test]
fn checker_rejects_expired_coalesced_begin_and_changed_origin_time() {
    let f = setup(Provider::Resend);
    let first = begin_request(&f);
    begin(&f, &first);
    let second = begin_request(&f);
    begin(&f, &second);
    let c = original_challenge(&f, first.operation_id);
    let originals = retained_receipts(&f);
    for (operation, at) in [
        (first.operation_id, c.created_at + 1),
        (second.operation_id, c.expires_at),
    ] {
        let mut forged = originals.clone();
        let row = forged
            .iter_mut()
            .find(|row| row.operation == operation)
            .unwrap();
        row.created_at = at;
        for point in &mut row.admission {
            point.at = at;
        }
        replace_retained_receipts(&f, &forged);
        assert!(f.store().check_integrity().is_err());
    }
    replace_retained_receipts(&f, &originals);
    assert_private_inventory(&f);
}

#[test]
fn checker_derives_all_three_admission_limits_from_original_receipts() {
    // Four begins for one identifier must fail even with matching counters and
    // copied runtime admission points. Three remains a valid retained history.
    let f = setup(Provider::Resend);
    let request = begin_request(&f);
    let accepted = begin(&f, &request);
    let originals = retained_receipts(&f);
    let mut forged = originals.clone();
    for n in 0..3 {
        let mut row = originals[0].clone();
        row.operation = Uuid::new_v4();
        forged.push(row);
        replace_retained_receipts(&f, &forged);
        assert_eq!(f.store().check_integrity().is_ok(), n < 2);
    }
    replace_retained_receipts(&f, &originals);

    // Sixty-four consume receipts on the same transport peer are valid; the
    // sixty-fifth cannot become valid by forging all writer caches consistently.
    let code = delivery_code(&f, request.operation_id);
    let attempt = consume_request(accepted["challenge"].as_str().unwrap(), &wrong_code(&code));
    consume(&f, &attempt);
    let originals = retained_receipts(&f);
    let base = originals
        .iter()
        .find(|row| row.operation == attempt.operation_id)
        .unwrap();
    let mut forged = originals.clone();
    for _ in 0..63 {
        let mut row = base.clone();
        row.operation = Uuid::new_v4();
        row.outcome = Outcome::Invalid {
            challenge: None,
            spent: false,
        };
        forged.push(row);
    }
    replace_retained_receipts(&f, &forged);
    assert_private_inventory(&f);
    let mut extra = forged.last().unwrap().clone();
    extra.operation = Uuid::new_v4();
    forged.push(extra);
    replace_retained_receipts(&f, &forged);
    assert!(f.store().check_integrity().is_err());
    replace_retained_receipts(&f, &originals);
    assert_private_inventory(&f);

    // Different identifiers avoid the identifier cap and isolate the independent
    // per-peer begin limit. Suppressed challenge origins carry no delivery source.
    let f = setup(Provider::FakeSms);
    for n in 0..32 {
        let mut request = begin_request(&f);
        request.identifier.value = format!("+1202555{n:04}");
        f.store()
            .begin_proof(&f.runtime, &request, "127.0.0.2")
            .unwrap();
    }
    assert_private_inventory(&f);
    let originals = retained_receipts(&f);
    let mut receipts = originals.clone();
    let template = receipts.last().unwrap().clone();
    let Outcome::Begin { challenge } = template.outcome else {
        panic!("begin receipt");
    };
    let mut c = challenges(f.store())
        .into_iter()
        .find(|c| c.id == challenge)
        .unwrap();
    assert!(c.binding.is_none());
    c.id = Uuid::new_v4();
    c.operation = Uuid::new_v4();
    c.handle_digest = crate::authentication::proof_crypto::random_secret().unwrap();
    let mut extra = template;
    extra.operation = c.operation;
    extra.outcome = Outcome::Begin { challenge: c.id };
    let write = f.store().begin_write().unwrap();
    write
        .open_table(CHALLENGES)
        .unwrap()
        .insert(
            c.id.as_bytes().as_slice(),
            local::encode(&c).unwrap().as_slice(),
        )
        .unwrap();
    write
        .open_table(HANDLES)
        .unwrap()
        .insert(
            c.handle_digest.as_bytes(),
            local::encode(&c.id).unwrap().as_slice(),
        )
        .unwrap();
    write.commit().unwrap();
    receipts.push(extra);
    replace_retained_receipts(&f, &receipts);
    assert!(f.store().check_integrity().is_err());
    let write = f.store().begin_write().unwrap();
    write
        .open_table(CHALLENGES)
        .unwrap()
        .remove(c.id.as_bytes().as_slice())
        .unwrap();
    write
        .open_table(HANDLES)
        .unwrap()
        .remove(c.handle_digest.as_bytes())
        .unwrap();
    write.commit().unwrap();
    replace_retained_receipts(&f, &originals);
    assert_private_inventory(&f);
}

#[test]
fn signer_unavailable_after_commit_recovers_the_pinned_decision_and_removed_keys_revoke() {
    let mut f = setup(Provider::Resend);
    let request = begin_request(&f);
    let accepted = begin(&f, &request);
    let code = delivery_code(&f, request.operation_id);
    let attempt = consume_request(accepted["challenge"].as_str().unwrap(), &code);
    let pem = f.runtime.signing.remove("test").unwrap();
    assert!(
        f.store()
            .consume_proof(&f.runtime, &attempt, "127.0.0.1")
            .is_err()
    );
    let c = original_challenge(&f, request.operation_id);
    assert!(c.consumed);
    assert_eq!(c.attempts, 1);
    let before = full_image(f.store());
    assert!(
        f.store()
            .proof_status(
                &f.runtime,
                &status(attempt.operation_id, &attempt.recovery_secret)
            )
            .is_err()
    );
    assert_eq!(full_image(f.store()), before);
    f.runtime.signing.insert("test".into(), pem);
    let recovered = f
        .store()
        .proof_status(
            &f.runtime,
            &status(attempt.operation_id, &attempt.recovery_secret),
        )
        .unwrap();
    assert_eq!(recovered["status"], "authenticated");
    assert_eq!(consume(&f, &attempt), recovered);
    assert_eq!(full_image(f.store()), before);
    let proof = std::mem::replace(
        &mut f.runtime.crypto,
        Crypto::test_key("replacement", [24; 32]),
    );
    assert!(
        f.store()
            .configure_authentication(Some(&f.runtime))
            .is_err(),
        "removing admission custody cannot reset its domain"
    );
    assert!(
        f.store()
            .proof_status(
                &f.runtime,
                &status(attempt.operation_id, &attempt.recovery_secret)
            )
            .is_err()
    );
    assert_eq!(full_image(f.store()), before);
    f.runtime.crypto = proof;
    assert_eq!(consume(&f, &attempt), recovered);
    assert_private_inventory(&f);
}

#[cfg(unix)]
#[test]
fn identifier_admission_remains_stable_across_active_proof_key_rotation() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut f = setup(Provider::Resend);
    let first = begin_request(&f);
    let accepted = begin(&f, &first);
    assert_eq!(begin(&f, &begin_request(&f)), accepted);
    let path = f.base.directory.join("rotated-proof.json");
    let bytes = serde_json::to_vec(&json!({"format":crate::authentication::proof_crypto::KEYRING_FORMAT,"current":"new","keys":[
        {"key_id":"proof","key":URL_SAFE_NO_PAD.encode([23u8;32])},
        {"key_id":"new","key":URL_SAFE_NO_PAD.encode([24u8;32])}
    ]})).unwrap();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(&bytes).unwrap();
    drop(file);
    f.runtime.crypto = Crypto::load(&path).unwrap();
    f.store()
        .configure_authentication(Some(&f.runtime))
        .unwrap();
    assert_eq!(begin(&f, &begin_request(&f)), accepted);
    let fourth = begin_request(&f);
    let before = full_image(f.store());
    assert!(
        f.store()
            .begin_proof(&f.runtime, &fourth, "127.0.0.2")
            .is_err(),
        "identifier limit is independent of peer and current crypto key"
    );
    assert_eq!(full_image(f.store()), before);
    assert_eq!(
        begin(&f, &first),
        accepted,
        "original replay bypasses new admission"
    );
    assert_eq!(full_image(f.store()), before);
    let code = delivery_code(&f, first.operation_id);
    assert_eq!(
        consume(
            &f,
            &consume_request(accepted["challenge"].as_str().unwrap(), &code)
        )["status"],
        "authenticated"
    );
    assert_private_inventory(&f);
}

#[test]
fn bounded_peer_admission_charges_suppressed_begins_and_unknown_consumes() {
    let f = setup(Provider::Resend);
    let mut original = None;
    for index in 0..32 {
        let mut request = begin_request(&f);
        request.identifier.value = format!("absent-{index}@example.com");
        let result = begin(&f, &request);
        if index == 0 {
            original = Some((request, result));
        }
    }
    let mut rejected = begin_request(&f);
    rejected.identifier.value = "also-absent@example.com".into();
    let before = full_image(f.store());
    assert!(
        f.store()
            .begin_proof(&f.runtime, &rejected, "127.0.0.1")
            .is_err()
    );
    assert_eq!(full_image(f.store()), before);
    let (original, response) = original.unwrap();
    assert_eq!(begin(&f, &original), response);
    assert_eq!(full_image(f.store()), before);
    let unknown = crate::authentication::proof_crypto::random_secret().unwrap();
    for _ in 0..64 {
        assert_eq!(consume(&f, &consume_request(&unknown, "000042")), invalid());
    }
    let before = full_image(f.store());
    assert!(
        f.store()
            .consume_proof(
                &f.runtime,
                &consume_request(&unknown, "000042"),
                "127.0.0.1"
            )
            .is_err()
    );
    assert_eq!(full_image(f.store()), before);
    assert_eq!(table_len(f.store(), CHALLENGES), 32);
    assert_eq!(table_len(f.store(), crate::effects::EXECUTIONS), 0);
    assert_private_inventory(&f);
}

#[test]
fn delivery_capacity_is_checked_before_identifier_lookup_but_after_original_recovery() {
    let f = setup(Provider::Resend);
    let original = begin_request(&f);
    let response = begin(&f, &original);
    let original_runtime = {
        let write = f.store().begin_write().unwrap();
        crate::effects::runtime_write(&write).unwrap()
    };
    // Inject each valid admission boundary in isolation. These counter values
    // deliberately do not stand in for a populated effect inventory: restore
    // the original bytes before the final independent whole-store check.
    for limit in ["retained", "unresolved", "facts", "bytes"] {
        let mut capacity = original_runtime.clone();
        match limit {
            "retained" => capacity.retained = crate::effects::MAX_RETAINED,
            "unresolved" => {
                capacity.retained = crate::effects::MAX_UNRESOLVED;
                capacity.unresolved = crate::effects::MAX_UNRESOLVED;
                capacity.reserved_facts = crate::effects::MAX_UNRESOLVED;
            }
            "facts" => {
                capacity.facts = crate::effects::MAX_FACTS as u16 - capacity.reserved_facts;
            }
            "bytes" => capacity.accounted_bytes = crate::effects::MAX_BYTES,
            _ => unreachable!(),
        }
        {
            let write = f.store().begin_write().unwrap();
            write
                .open_table(crate::effects::EFFECT_RUNTIME)
                .unwrap()
                .insert(local::HEADER, local::encode(&capacity).unwrap().as_slice())
                .unwrap();
            // The injected boundary itself must satisfy runtime field rules.
            crate::effects::runtime_write(&write).unwrap();
            write.commit().unwrap();
        }
        let before = full_image(f.store());
        for exists in [true, false] {
            let mut request = begin_request(&f);
            if !exists {
                request.identifier.value = "absent-capacity@example.com".into();
            }
            let result = f.store().begin_proof(&f.runtime, &request, "127.0.0.1");
            assert_eq!(
                result.unwrap_err().code,
                "auth_unavailable",
                "{limit}, exists={exists}"
            );
            assert_eq!(
                full_image(f.store()),
                before,
                "rejected capacity must not charge admission or publish proof"
            );
        }
        assert_eq!(
            begin(&f, &original),
            response,
            "original recovery at {limit}"
        );
        assert_eq!(full_image(f.store()), before);
    }
    let write = f.store().begin_write().unwrap();
    write
        .open_table(crate::effects::EFFECT_RUNTIME)
        .unwrap()
        .insert(
            local::HEADER,
            local::encode(&original_runtime).unwrap().as_slice(),
        )
        .unwrap();
    write.commit().unwrap();
    assert_private_inventory(&f);
}

#[test]
fn admission_windows_match_event_oracle_at_exact_edges_ties_and_clock_regression() {
    struct Event {
        at: i64,
        peer: String,
        identifier: Option<Input>,
    }
    struct Oracle {
        crypto: Crypto,
        state: State,
        events: Vec<Event>,
        receipt_points: Vec<Vec<Admission>>,
    }
    impl Oracle {
        fn new() -> Self {
            Self {
                crypto: Crypto::test_key("admission-boundary", [41; 32]),
                state: State {
                    format: FORMAT.into(),
                    admission_key_id: "admission-boundary".into(),
                    last_at: 0,
                    challenges: 0,
                    receipts: 0,
                    points: vec![],
                },
                events: vec![],
                receipt_points: vec![],
            }
        }
        fn check(&mut self, at: i64, peer: &str, identifier: Option<&Input>, accepted: bool) {
            // Count authored events by elapsed age, independent of retained
            // writer points. Equal-time events are separate charged requests.
            let in_window = |event: &&Event, width| (0..width).contains(&(at - event.at));
            let peer_count = self
                .events
                .iter()
                .filter(|event| {
                    event.peer == peer
                        && event.identifier.is_some() == identifier.is_some()
                        && in_window(event, 60_000)
                })
                .count();
            let identifier_count = identifier.map_or(0, |identifier| {
                self.events
                    .iter()
                    .filter(|event| {
                        event.identifier.as_ref() == Some(identifier) && in_window(event, 300_000)
                    })
                    .count()
            });
            let predicted = at >= self.events.last().map_or(0, |event| event.at)
                && peer_count < if identifier.is_some() { 32 } else { 64 }
                && (identifier.is_none() || identifier_count < 3);
            assert_eq!(
                predicted, accepted,
                "literal scenario disagrees with event oracle"
            );

            // charge stages inside its caller's transaction; rejection drops
            // that candidate, including any tentative retention pruning.
            let mut candidate = self.state.clone();
            let result = charge(&mut candidate, &self.crypto, peer, identifier, at);
            assert_eq!(result.is_ok(), predicted, "admission at {at}, peer {peer}");
            match result {
                Ok(points) => {
                    assert_eq!(points.len(), if identifier.is_some() { 2 } else { 1 });
                    assert!(
                        points
                            .iter()
                            .all(|point| point.at == at && point.consume == identifier.is_none())
                    );
                    candidate.receipts += 1;
                    self.state = candidate;
                    self.events.push(Event {
                        at,
                        peer: peer.into(),
                        identifier: identifier.cloned(),
                    });
                    self.receipt_points.push(points);
                }
                Err(error) => assert_eq!(error.code, "auth_unavailable"),
            }
            // The checker rebuilds retained points from original receipts.
            // Additionally derive their exact keys and multiplicity from the
            // source events, so a missing or misbound charged point cannot pass.
            let mut expected = Vec::new();
            for event in self
                .events
                .iter()
                .filter(|event| self.state.last_at - event.at < 300_000)
            {
                if let Some(identifier) = &event.identifier {
                    expected.push(Admission {
                        key: self
                            .crypto
                            .digest_with_key(
                                &self.state.admission_key_id,
                                "identifier",
                                identifier,
                                b"",
                            )
                            .unwrap(),
                        at: event.at,
                        consume: false,
                    });
                }
                expected.push(Admission {
                    key: self
                        .crypto
                        .digest_with_key(&self.state.admission_key_id, "peer", &event.peer, b"")
                        .unwrap(),
                    at: event.at,
                    consume: event.identifier.is_none(),
                });
            }
            let mut from_receipts = self
                .receipt_points
                .iter()
                .flatten()
                .filter(|point| self.state.last_at - point.at < 300_000)
                .cloned()
                .collect::<Vec<_>>();
            let mut actual = self.state.points.clone();
            expected.sort();
            from_receipts.sort();
            actual.sort();
            assert_eq!(actual, expected);
            assert_eq!(actual, from_receipts);
            assert_eq!(usize::from(self.state.receipts), self.events.len());
        }
    }
    let identifier = |number| Input {
        kind: Kind::Email,
        value: format!("boundary-{number}@example.test"),
    };
    // Translating the same timeline preserves all decisions, including the
    // negative lower bound of the window at the Unix epoch.
    for start in [0, 1_000_000] {
        let mut oracle = Oracle::new();
        let email = identifier(0);
        for peer in ["peer-a", "peer-b", "peer-c"] {
            oracle.check(start, peer, Some(&email), true);
        }
        oracle.check(start, "peer-d", Some(&email), false);
        oracle.check(start + 299_999, "peer-d", Some(&email), false);
        oracle.check(start + 300_000, "peer-d", Some(&email), true);
        oracle.check(start + 300_000, "peer-a", Some(&email), true);
        oracle.check(start + 300_000, "peer-b", Some(&email), true);
        oracle.check(start + 300_000, "peer-c", Some(&email), false);
        oracle.check(start + 299_999, "fresh-peer", Some(&identifier(1)), false);
        oracle.check(start + 300_000, "fresh-peer", Some(&identifier(1)), true);

        let mut oracle = Oracle::new();
        for number in 0..32 {
            oracle.check(start, "shared-peer", Some(&identifier(number)), true);
        }
        oracle.check(start, "shared-peer", Some(&identifier(32)), false);
        oracle.check(start + 59_999, "shared-peer", Some(&identifier(32)), false);
        for number in 32..64 {
            oracle.check(
                start + 60_000,
                "shared-peer",
                Some(&identifier(number)),
                true,
            );
        }
        oracle.check(start + 60_000, "shared-peer", Some(&identifier(64)), false);
        // Begin and consume have separate peer budgets; neither gives equal
        // timestamps set semantics or admits the next over-budget request.
        for _ in 0..64 {
            oracle.check(start + 60_000, "shared-peer", None, true);
        }
        oracle.check(start + 60_000, "shared-peer", None, false);
        oracle.check(start + 119_999, "shared-peer", None, false);
        oracle.check(start + 120_000, "shared-peer", None, true);
        oracle.check(start + 119_999, "fresh-peer", None, false);
        oracle.check(start + 120_000, "fresh-peer", None, true);
    }
}
