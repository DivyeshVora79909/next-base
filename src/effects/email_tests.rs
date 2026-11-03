//! Native E2 acceptance: independent source intent and literal charged starts.
use super::*;
use crate::{
    credentials::{
        grants::{AuthorizeRequest, PlatformBindings, Runtime as Credentials, Selection},
        store::test_support as f,
    },
    email::{EmailOutcome, EmailRequest, Purpose},
    email_operations::{Authorization, Enqueue},
    models::services::{EMAIL_SEND, Services},
};
use state::{Candidate, Claim, WorkClass};

fn setup() -> (f::Fixture, Credentials) {
    let fixture = f::fixture();
    let mut graph = f::graph();
    for principal in &mut graph.principals {
        principal.grants.contracts.insert(
            EMAIL_SEND,
            [Action::Read, Action::Create, Action::Update, Action::Delete].into(),
        );
    }
    f::replace(&fixture.store, graph);
    let caller = fixture.store.session(f::id(4), 0).unwrap();
    caller
        .write_secret(
            &fixture.crypto,
            &f::sealed(
                &caller,
                &fixture.crypto,
                f::id(100),
                None,
                None,
                f::metadata(true),
                "E2-native-secret",
            ),
        )
        .unwrap();
    let runtime = Credentials::new(fixture.crypto.clone(), PlatformBindings::default());
    (fixture, runtime)
}
fn request(caller: &Store<Services>, runtime: &Credentials, source: u128) -> Enqueue {
    let email = EmailRequest {
        sender: "sender@example.com".into(),
        to: vec!["recipient@example.net".into()],
        subject: "native E2".into(),
        text: "exact source intent".into(),
    };
    let selection = Selection::Byoc {
        credential: f::id(100),
    };
    let grant = caller
        .authorize_email(
            runtime,
            &AuthorizeRequest {
                model: caller.model().identity().into(),
                email: email.clone(),
                selection: selection.clone(),
                ttl_seconds: 60,
            },
        )
        .unwrap();
    serde_json::from_value(json!({"model":caller.model().identity(),"context":caller.operation_context(caller.model().identity()).unwrap(),"operation_id":Uuid::new_v4(),"commands":[{"op":"create","id":f::id(source),"contract":EMAIL_SEND,"fields":{"email":email,"selection":selection,"execute_at":null,"not_after":null}}],"returning":[f::id(source)],"authorizations":[{"source":f::id(source),"grant":grant.grant}]})).unwrap()
}
fn enqueue(caller: &Store<Services>, runtime: &Credentials, source: u128) -> Uuid {
    caller
        .enqueue_email(runtime, &request(caller, runtime, source))
        .unwrap()["result"]["executions"][0]["execution_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}
fn row(store: &Store<Services>, id: Uuid) -> Execution<Services> {
    load_execution(&store.begin_write().unwrap(), id).unwrap()
}
fn candidate(store: &Store<Services>, id: Uuid, class: WorkClass) -> Candidate {
    let write = store.begin_write().unwrap();
    let row = load_execution::<Services>(&write, id).unwrap();
    Candidate {
        store: row.store,
        activation: runtime_write(&write).unwrap().activation,
        execution: id,
        revision: row.revision,
        class,
    }
}
fn claim(store: &Store<Services>, id: Uuid, at: i64) -> Claim {
    store
        .claim_effect_at(&candidate(store, id, WorkClass::Submit), Some(at))
        .unwrap()
        .unwrap()
}
fn policies() -> admission::Policies {
    admission::Policies::new(vec![admission::Policy {
        provider: crate::email::Provider::Resend,
        account: "test-mail".into(),
        purpose: Purpose::EmailSend,
        window_ms: 100,
        limit: 1,
    }])
    .unwrap()
}
fn outcome(store: &Store<Services>, id: Uuid, disposition: Disposition) -> EmailOutcome {
    let row = row(store, id);
    EmailOutcome {
        execution_id: id,
        provider: crate::email::Provider::Resend,
        account: "test-mail".into(),
        request_hash: row.request_hash,
        disposition,
        receipt: Some("native-provider-receipt".into()),
    }
}

#[test]
fn enqueue_is_atomic_replays_before_grant_validation_and_never_discloses_evidence() {
    let (f, runtime) = setup();
    let caller = f.store.session(f::id(4), 0).unwrap();
    let mut request = request(&caller, &runtime, 200);
    let before = f.store.observe_for_verification().unwrap();
    let decrypts = f.crypto.decrypt_counts();
    for abort in [
        1,
        usize::MAX - 1,
        usize::MAX - 2,
        usize::MAX - 3,
        usize::MAX,
    ] {
        assert_eq!(
            caller
                .enqueue_email_controlled(&runtime, &request, Some(abort), &mut || Ok(()), false)
                .unwrap_err()
                .code,
            "injected_abort"
        );
        assert_eq!(f.store.observe_for_verification().unwrap(), before);
    }
    let ordinary = crate::local::Mutation {
        model: request.model.clone(),
        context: request.context.clone(),
        operation_id: request.operation_id,
        commands: request.commands.clone(),
        returning: request.returning.clone(),
    };
    assert_eq!(caller.mutate(&ordinary).unwrap_err().code, "forbidden");
    assert_eq!(
        caller
            .enqueue_email_controlled(&runtime, &request, None, &mut || Ok(()), true)
            .unwrap_err()
            .code,
        "outcome_unknown"
    );
    let image = f.store.observe_for_verification().unwrap();
    assert!(!image.to_string().contains(&request.authorizations[0].grant));
    assert!(!image.to_string().contains("E2-native-secret"));
    request.authorizations[0].grant = "expired-and-invalid-evidence".into();
    assert_eq!(
        caller.enqueue_email(&runtime, &request).unwrap()["replayed"],
        true
    );
    assert_eq!(f.store.observe_for_verification().unwrap(), image);
    assert_eq!(f.crypto.decrypt_counts(), decrypts);
    request.commands[0]=serde_json::from_value(json!({"op":"create","id":f::id(201),"contract":EMAIL_SEND,"fields":match &request.commands[0]{Command::Create{fields,..}=>fields.clone(),_=>unreachable!()}})).unwrap();
    request.authorizations = vec![Authorization {
        source: f::id(201),
        grant: "invalid".into(),
    }];
    assert_eq!(
        caller.enqueue_email(&runtime, &request).unwrap_err().code,
        "operation_conflict"
    );
    f.store.check_integrity().unwrap();
}

#[test]
fn charges_start_once_denial_persists_wake_and_exact_expiry_releases_slot() {
    let (f, runtime) = setup();
    let caller = f.store.session(f::id(4), 0).unwrap();
    let a = enqueue(&caller, &runtime, 200);
    let b = enqueue(&caller, &runtime, 201);
    let p = policies();
    f.store.configure_email_admission(&p).unwrap();
    f.store
        .activate_effect_worker(WorkerMode::Delivery)
        .unwrap();
    let at = row(&f.store, b).created_at + 1;
    let unstarted = claim(&f.store, a, at);
    assert_eq!(row(&f.store, a).attempts, 0);
    let started = f
        .store
        .start_effect_admitted_at(&unstarted, Some(at), Some(&p))
        .unwrap()
        .unwrap();
    assert_eq!(row(&f.store, a).attempts, 1);
    let waiting = claim(&f.store, b, at);
    assert!(
        f.store
            .start_effect_admitted_at(&waiting, Some(at), Some(&p))
            .unwrap()
            .is_none()
    );
    let denied = row(&f.store, b);
    assert_eq!(denied.attempts, 0);
    assert_eq!(denied.next_at, at + 100);
    assert!(denied.lease.is_none());
    assert!(
        f.store
            .claim_effect_at(&candidate(&f.store, b, WorkClass::Submit), Some(at + 99))
            .unwrap()
            .is_none()
    );
    let second = claim(&f.store, b, at + 100);
    f.store
        .start_effect_admitted_at(&second, Some(at + 100), Some(&p))
        .unwrap()
        .unwrap();
    let before = f.store.observe_for_verification().unwrap();
    assert!(
        f.store
            .start_effect_admitted_at(&started, Some(at), Some(&p))
            .is_err()
    );
    assert_eq!(f.store.observe_for_verification().unwrap(), before);
    f.store
        .finish_effect_at(
            &started,
            Some(&outcome(&f.store, a, Disposition::Succeeded)),
            Some(at + 1),
            None,
        )
        .unwrap();
    let status = caller.effect_status(caller.model().identity(), a).unwrap();
    assert_eq!(status["phase"], "succeeded");
    assert_eq!(status["application"], "not_required");
    assert!(status["outcome"].get("account").is_none());
    assert!(!status.to_string().contains("E2-native-secret"));
    f.store.check_integrity().unwrap();
}

#[test]
fn uncertain_start_stays_charged_and_revocation_does_not_erase_reconciliation() {
    let (f, runtime) = setup();
    let caller = f.store.session(f::id(4), 0).unwrap();
    let e = enqueue(&caller, &runtime, 200);
    let p = policies();
    f.store.configure_email_admission(&p).unwrap();
    f.store
        .activate_effect_worker(WorkerMode::Delivery)
        .unwrap();
    let at = row(&f.store, e).created_at + 1;
    let claimed = claim(&f.store, e, at);
    let started = f
        .store
        .start_effect_admitted_at(&claimed, Some(at), Some(&p))
        .unwrap()
        .unwrap();
    caller
        .mutate(&f::edit(
            &caller,
            f::id(100),
            None,
            json!({"enabled":false}),
        ))
        .unwrap();
    f.store
        .finish_effect_at(&started, None, Some(at + 1), None)
        .unwrap();
    assert_eq!(row(&f.store, e).phase, Phase::Uncertain);
    let next = row(&f.store, e).next_at;
    let reconcile = f
        .store
        .claim_effect_at(&candidate(&f.store, e, WorkClass::Reconcile), Some(next))
        .unwrap()
        .unwrap();
    f.store
        .finish_effect_at(
            &reconcile,
            Some(&outcome(&f.store, e, Disposition::Succeeded)),
            Some(next + 1),
            None,
        )
        .unwrap();
    assert_eq!(row(&f.store, e).attempts, 1);
    assert_eq!(row(&f.store, e).email_starts.len(), 1);
    f.store.check_integrity().unwrap();
}

#[test]
fn stale_dispatch_confirmation_never_reuses_an_old_charge() {
    let (f, runtime) = setup();
    let caller = f.store.session(f::id(4), 0).unwrap();
    let e = enqueue(&caller, &runtime, 200);
    let p = policies();
    f.store.configure_email_admission(&p).unwrap();
    f.store
        .activate_effect_worker(WorkerMode::Delivery)
        .unwrap();
    let at = row(&f.store, e).created_at + 1;
    let claim = claim(&f.store, e, at);
    let started = f
        .store
        .start_effect_admitted_at(&claim, Some(at), Some(&p))
        .unwrap()
        .unwrap();
    let decrypts = f.crypto.decrypt_counts();
    f.store
        .confirm_effect_start_at(&started, Some(at + 1000))
        .unwrap();
    assert_eq!(
        f.store
            .confirm_effect_start_at(&started, Some(at + 1001))
            .unwrap_err()
            .code,
        "stale_version"
    );
    assert_eq!(
        f.store
            .confirm_effect_start_at(&started, Some(at - 1))
            .unwrap_err()
            .code,
        "stale_version"
    );
    assert_eq!(f.crypto.decrypt_counts(), decrypts);
    f.store
        .finish_effect_at(&started, None, Some(at + 1002), None)
        .unwrap();
    assert_eq!(row(&f.store, e).phase, Phase::Uncertain);
    assert_eq!(row(&f.store, e).email_starts.len(), 1);
    f.store.check_integrity().unwrap();
}

#[test]
fn hidden_platform_use_needs_source_create_but_never_credential_read() {
    use crate::credentials::grants::{PlatformBinding, PlatformSlot};
    let (f, _runtime) = setup();
    let caller = f.store.session(f::id(9), 0).unwrap();
    assert!(
        caller
            .get(caller.model().identity(), f::id(100))
            .unwrap()
            .is_none()
    );
    let runtime = Credentials::new(
        f.crypto.clone(),
        PlatformBindings::new(vec![PlatformBinding {
            slot: PlatformSlot::TransactionalEmail,
            credential: f::id(100),
            provider: crate::email::Provider::Resend,
            account: "test-mail".into(),
            purpose: Purpose::EmailSend,
        }])
        .unwrap(),
    );
    let email = EmailRequest {
        sender: "sender@example.com".into(),
        to: vec!["recipient@example.net".into()],
        subject: "hidden binding".into(),
        text: "public email".into(),
    };
    let selection = Selection::Platform {
        slot: PlatformSlot::TransactionalEmail,
    };
    let grant = caller
        .authorize_email(
            &runtime,
            &AuthorizeRequest {
                model: caller.model().identity().into(),
                email: email.clone(),
                selection: selection.clone(),
                ttl_seconds: 60,
            },
        )
        .unwrap();
    let request:Enqueue=serde_json::from_value(json!({"model":caller.model().identity(),"context":caller.operation_context(caller.model().identity()).unwrap(),"operation_id":Uuid::new_v4(),"commands":[{"op":"create","id":f::id(200),"contract":EMAIL_SEND,"fields":{"email":email,"selection":selection,"execute_at":null,"not_after":null}}],"returning":[f::id(200)],"authorizations":[{"source":f::id(200),"grant":grant.grant}]})).unwrap();
    let before = f.store.observe_for_verification().unwrap();
    let mut graph = f::graph();
    graph
        .principals
        .iter_mut()
        .find(|p| p.id == f::id(9))
        .unwrap()
        .grants
        .contracts
        .insert(EMAIL_SEND, [Action::Read].into());
    f::replace(&f.store, graph.clone());
    assert_eq!(
        caller.enqueue_email(&runtime, &request).unwrap_err().code,
        "forbidden"
    );
    graph
        .principals
        .iter_mut()
        .find(|p| p.id == f::id(9))
        .unwrap()
        .grants
        .contracts
        .insert(EMAIL_SEND, [Action::Read, Action::Create].into());
    f::replace(&f.store, graph);
    let result = caller.enqueue_email(&runtime, &request).unwrap();
    assert!(!result.to_string().contains("test-mail"));
    assert!(!result.to_string().contains(&f::id(100).to_string()));
    assert_ne!(f.store.observe_for_verification().unwrap(), before);
    f.store.check_integrity().unwrap();
}

#[test]
fn current_submit_nonacceptance_retries_at_most_three_charged_starts_with_exact_history() {
    // Attempt times follow the independently specified 1s/2s retry backoffs;
    // the 100ms quota window has expired before either physical retry.
    for last in [Disposition::Succeeded, Disposition::NotAccepted] {
        let (f, credentials) = setup();
        let caller = f.store.session(f::id(4), 0).unwrap();
        let execution = enqueue(&caller, &credentials, 200);
        let policies = policies();
        f.store.configure_email_admission(&policies).unwrap();
        f.store
            .activate_effect_worker(WorkerMode::Delivery)
            .unwrap();
        let base = row(&f.store, execution).created_at + 1;
        let mut expected = Vec::new();
        for (position, offset) in [0, 1001, 3002].into_iter().enumerate() {
            let at = base + offset;
            let claimed = claim(&f.store, execution, at);
            assert_eq!(row(&f.store, execution).attempts, position as u8);
            let started = f
                .store
                .start_effect_admitted_at(&claimed, Some(at), Some(&policies))
                .unwrap()
                .unwrap();
            expected.push(state::Start {
                activation: claimed.activation,
                token: claimed.token,
                at,
                attempt: position as u8 + 1,
            });
            let current = row(&f.store, execution);
            assert_eq!(current.email_starts, expected);
            assert_eq!(current.attempts, position as u8 + 1);
            let disposition = if position == 2 {
                last
            } else {
                Disposition::NotAccepted
            };
            let mut result = outcome(&f.store, execution, disposition);
            if disposition == Disposition::NotAccepted {
                result.receipt = None;
            }
            f.store
                .finish_effect_at(&started, Some(&result), Some(at + 1), None)
                .unwrap();
            let completed = row(&f.store, execution);
            assert_eq!(completed.email_starts, expected);
            if position < 2 {
                assert_eq!(completed.phase, Phase::Ready);
                assert!(completed.started.is_none());
                assert_eq!(completed.next_at, base + [1001, 3002][position]);
            }
            f.store.check_integrity().unwrap();
        }
        let final_row = row(&f.store, execution);
        assert_eq!(final_row.attempts, 3);
        assert_eq!(final_row.email_starts, expected);
        if last == Disposition::Succeeded {
            assert_eq!(final_row.phase, Phase::Succeeded);
            assert_eq!(final_row.application, Application::NotRequired);
            assert_eq!(
                caller
                    .effect_status(caller.model().identity(), execution)
                    .unwrap()["application"],
                "not_required"
            );
        } else {
            assert_eq!(final_row.phase, Phase::Failed);
            assert_eq!(final_row.application, Application::None);
            assert_eq!(
                final_row.diagnostic.as_deref(),
                Some("submission_budget_exhausted_or_expired")
            );
        }
        let before = f.store.observe_for_verification().unwrap();
        assert!(
            f.store
                .claim_effect_at(
                    &candidate(&f.store, execution, WorkClass::Submit),
                    Some(base + 10000)
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(f.store.observe_for_verification().unwrap(), before);
        let read = f.store.db.begin_read().unwrap();
        for table in [admission::STARTS, admission::POINTS] {
            assert_eq!(
                read.open_table(table)
                    .unwrap()
                    .iter()
                    .unwrap()
                    .collect::<Result<Vec<_>>>()
                    .unwrap()
                    .len(),
                3
            );
        }
        f.store.check_integrity().unwrap();
    }
}

#[test]
fn missing_and_nonacceptance_lookup_never_authorize_a_second_send() {
    let (f, credentials) = setup();
    let caller = f.store.session(f::id(4), 0).unwrap();
    let execution = enqueue(&caller, &credentials, 200);
    let policies = policies();
    f.store.configure_email_admission(&policies).unwrap();
    f.store
        .activate_effect_worker(WorkerMode::Delivery)
        .unwrap();
    let base = row(&f.store, execution).created_at + 1;
    let claimed = claim(&f.store, execution, base);
    let started = f
        .store
        .start_effect_admitted_at(&claimed, Some(base), Some(&policies))
        .unwrap()
        .unwrap();
    let expected = vec![state::Start {
        activation: claimed.activation,
        token: claimed.token,
        at: base,
        attempt: 1,
    }];
    f.store
        .finish_effect_at(&started, None, Some(base + 1), None)
        .unwrap();
    for (offset, disposition) in [(1001, None), (2002, Some(Disposition::NotAccepted))] {
        assert_eq!(row(&f.store, execution).next_at, base + offset);
        let lookup = f
            .store
            .claim_effect_at(
                &candidate(&f.store, execution, WorkClass::Reconcile),
                Some(base + offset),
            )
            .unwrap()
            .unwrap();
        let result = disposition.map(|disposition| {
            let mut result = outcome(&f.store, execution, disposition);
            result.receipt = None;
            result
        });
        f.store
            .finish_effect_at(&lookup, result.as_ref(), Some(base + offset + 1), None)
            .unwrap();
        let current = row(&f.store, execution);
        assert_eq!(current.phase, Phase::Uncertain);
        assert_eq!(current.attempts, 1);
        assert_eq!(current.email_starts, expected);
        let before = f.store.observe_for_verification().unwrap();
        assert!(
            f.store
                .claim_effect_at(
                    &candidate(&f.store, execution, WorkClass::Submit),
                    Some(current.next_at)
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(f.store.observe_for_verification().unwrap(), before);
        f.store.check_integrity().unwrap();
    }
    assert_eq!(row(&f.store, execution).next_at, base + 4003);
    let lookup = f
        .store
        .claim_effect_at(
            &candidate(&f.store, execution, WorkClass::Reconcile),
            Some(base + 4003),
        )
        .unwrap()
        .unwrap();
    f.store
        .finish_effect_at(
            &lookup,
            Some(&outcome(&f.store, execution, Disposition::Succeeded)),
            Some(base + 4004),
            None,
        )
        .unwrap();
    let completed = row(&f.store, execution);
    assert_eq!(completed.phase, Phase::Succeeded);
    assert_eq!(completed.application, Application::NotRequired);
    assert_eq!(completed.email_starts, expected);
    assert_eq!(completed.attempts, 1);
    f.store.check_integrity().unwrap();
}

#[test]
fn configured_or_charged_account_policy_prevents_reset_from_replenishing_quota() {
    let (f, credentials) = setup();
    let policies = policies();
    f.store.configure_email_admission(&policies).unwrap();
    let header = local::read_header(&f.store.db.begin_read().unwrap()).unwrap();
    let assert_rejected = || {
        let before = f.store.observe_for_verification().unwrap();
        let error = f.store.reset(header.store_id).unwrap_err();
        assert_eq!(error.code, "invariant");
        assert!(error.detail.contains("rate policy"));
        assert_eq!(f.store.observe_for_verification().unwrap(), before);
    };
    assert_rejected();
    let caller = f.store.session(f::id(4), 0).unwrap();
    let execution = enqueue(&caller, &credentials, 200);
    f.store
        .activate_effect_worker(WorkerMode::Delivery)
        .unwrap();
    let at = row(&f.store, execution).created_at + 1;
    let claimed = claim(&f.store, execution, at);
    let started = f
        .store
        .start_effect_admitted_at(&claimed, Some(at), Some(&policies))
        .unwrap()
        .unwrap();
    f.store
        .finish_effect_at(
            &started,
            Some(&outcome(&f.store, execution, Disposition::Succeeded)),
            Some(at + 1),
            None,
        )
        .unwrap();
    f.store
        .activate_effect_worker(WorkerMode::Disabled)
        .unwrap();
    assert_rejected();
    assert_eq!(row(&f.store, execution).email_starts.len(), 1);
    f.store.check_integrity().unwrap();
}
