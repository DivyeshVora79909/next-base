//! E2 controls against the actual selected adapter. The wrapper injects failures
//! after real transactional writes and drops only acknowledgements after commit;
//! it never simulates an adapter conflict or a provider response.
use super::{
    Backend, Database, Limits, ReadView, ReadableTable, Row, TableSpec, WriteView,
    coordination_checks::{Captures, Recording, capture, label, trace_value},
    credential_checks,
};
use crate::{
    access::Action,
    credentials::{
        crypto::{Crypto, Metadata, Provider},
        grants::{AuthorizeRequest, PlatformBindings, Runtime},
    },
    effects::{
        self,
        admission::{Policies, Policy},
        state::{Candidate, Claim, WorkClass},
    },
    email::{EmailRequest, Purpose, SendInput},
    email_operations::{Authorization, Enqueue},
    local::{self, Store},
    model::Prepared,
    models::services::{CREDENTIAL, EMAIL_SEND, Services},
    native_codec::Key,
    native_slice::{Command, Context, Error, Result},
};
use serde_json::{Value, json};
use std::{
    ops::Bound,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn failure(detail: &str) -> Error {
    Error::new("email_conformance", detail)
}
fn require(ok: bool, detail: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(failure(detail)) }
}
type BeforeCommit = Box<dyn FnOnce() -> Result<()> + Send>;
#[derive(Default)]
struct Plan {
    after: Option<usize>,
    lose_ack: bool,
    before_commit: Option<BeforeCommit>,
}
#[derive(Default)]
struct Control {
    next: Plan,
    last_writes: usize,
}
type Controls = Arc<Mutex<Control>>;
fn arm(controls: &Controls, plan: Plan) -> Result<()> {
    controls
        .lock()
        .map_err(|_| failure("fault control lock"))?
        .next = plan;
    Ok(())
}
struct Controlled {
    db: Database,
    controls: Controls,
}
impl Backend for Controlled {
    fn limits(&self) -> Limits {
        self.db.limits()
    }
    fn begin_read(&self) -> Result<Box<dyn ReadView>> {
        self.db.backend.begin_read()
    }
    fn begin_write(&self) -> Result<Box<dyn WriteView>> {
        let inner = self.db.backend.begin_write()?;
        let mut control = self
            .controls
            .lock()
            .map_err(|_| failure("fault control lock"))?;
        let plan = std::mem::take(&mut control.next);
        control.last_writes = 0;
        Ok(Box::new(ControlledWrite {
            inner,
            controls: self.controls.clone(),
            plan,
            writes: 0,
        }))
    }
}
struct ControlledWrite {
    inner: Box<dyn WriteView>,
    controls: Controls,
    plan: Plan,
    writes: usize,
}
impl ControlledWrite {
    fn written(&mut self) -> Result<()> {
        self.writes += 1;
        self.controls
            .lock()
            .map_err(|_| failure("fault control lock"))?
            .last_writes = self.writes;
        if self.plan.after == Some(self.writes) {
            return Err(Error::new("injected_abort", "after actual adapter write"));
        }
        Ok(())
    }
}
impl ReadView for ControlledWrite {
    fn table_exists(&self, t: &TableSpec) -> Result<bool> {
        self.inner.table_exists(t)
    }
    fn get(&self, t: &TableSpec, k: &[u8]) -> Result<Option<Vec<u8>>> {
        self.inner.get(t, k)
    }
    fn scan(
        &self,
        t: &TableSpec,
        a: Bound<Vec<u8>>,
        b: Bound<Vec<u8>>,
        n: usize,
    ) -> Result<Vec<Row>> {
        self.inner.scan(t, a, b, n)
    }
    fn list_tables(&self) -> Result<Vec<String>> {
        self.inner.list_tables()
    }
    fn has_multimap_tables(&self) -> Result<bool> {
        self.inner.has_multimap_tables()
    }
}
impl WriteView for ControlledWrite {
    fn create_table(&mut self, t: &TableSpec) -> Result<()> {
        self.inner.create_table(t)
    }
    fn delete_table(&mut self, t: &TableSpec) -> Result<bool> {
        self.inner.delete_table(t)
    }
    fn put(&mut self, t: &TableSpec, k: &[u8], v: &[u8]) -> Result<Option<Vec<u8>>> {
        let previous = self.inner.put(t, k, v)?;
        self.written()?;
        Ok(previous)
    }
    fn remove(&mut self, t: &TableSpec, k: &[u8]) -> Result<Option<Vec<u8>>> {
        let previous = self.inner.remove(t, k)?;
        self.written()?;
        Ok(previous)
    }
    fn commit(mut self: Box<Self>) -> Result<()> {
        if let Some(before) = self.plan.before_commit.take() {
            before()?;
        }
        self.inner.commit()?;
        if self.plan.lose_ack {
            Err(Error::new(
                "outcome_unknown",
                "lost actual durable commit acknowledgement",
            ))
        } else {
            Ok(())
        }
    }
}
struct Fixture {
    store: Store<Services>,
    controls: Controls,
    captures: Captures,
    runtime: Arc<Runtime>,
    policies: Arc<Policies>,
}
fn setup(db: Database, crypto: Arc<Crypto>, independent: bool) -> Result<Fixture> {
    let controls = Controls::default();
    let captures = Captures::default();
    let db = Database::new(Recording {
        db: Database::new(Controlled {
            db,
            controls: controls.clone(),
        }),
        captures: captures.clone(),
    });
    let store = Store::create_backend_secured(
        db,
        Arc::new(Prepared::load()?),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )?;
    let mut graph = credential_checks::graph()?;
    for principal in &mut graph.principals {
        if [id(3), id(4)].contains(&principal.id) {
            principal.grants.contracts.insert(
                EMAIL_SEND,
                [Action::Read, Action::Create, Action::Update, Action::Delete].into(),
            );
        }
    }
    credential_checks::replace(&store, graph)?;
    let policy = |provider| Policy {
        provider,
        account: "e2-conformance-account".into(),
        purpose: Purpose::EmailSend,
        window_ms: 86_400_000,
        limit: 1,
    };
    let policies = Arc::new(Policies::new(if independent {
        vec![policy(Provider::Resend), policy(Provider::Brevo)]
    } else {
        vec![policy(Provider::Resend)]
    })?);
    store.configure_email_admission(&policies)?;
    for (actor, credential, provider) in [
        (3, 100, Provider::Resend),
        (
            4,
            101,
            if independent {
                Provider::Brevo
            } else {
                Provider::Resend
            },
        ),
    ] {
        let caller = store.session(id(actor), 0)?;
        let metadata = Metadata {
            label: "Public fixture".into(),
            provider,
            account: "e2-conformance-account".into(),
            enabled: true,
            scopes: vec!["email.send".into()],
        };
        let request = credential_checks::sealed_metadata(
            &caller,
            &crypto,
            (id(credential), None, None, Uuid::new_v4()),
            br#"{"api_key":"public-email-conformance-key"}"#,
            metadata,
        )?;
        caller.write_secret(&crypto, &request)?;
    }
    Ok(Fixture {
        store,
        controls,
        captures,
        runtime: Arc::new(Runtime::new(crypto, PlatformBindings::default())),
        policies,
    })
}
fn request(
    store: &Store<Services>,
    runtime: &Runtime,
    source: Uuid,
    credential: Uuid,
) -> Result<Enqueue> {
    let email = EmailRequest {
        sender: "sender@example.com".into(),
        to: vec!["reader@example.net".into()],
        subject: "adapter fixture".into(),
        text: "independent literal body".into(),
    };
    let selection = crate::credentials::grants::Selection::Byoc { credential };
    let grant = store.authorize_email(
        runtime,
        &AuthorizeRequest {
            model: store.model().identity().into(),
            email: email.clone(),
            selection: selection.clone(),
            ttl_seconds: 60,
        },
    )?;
    Ok(Enqueue {
        model: store.model().identity().into(),
        context: store.operation_context(store.model().identity())?,
        operation_id: Uuid::new_v4(),
        commands: vec![Command::Create {
            id: source,
            contract: EMAIL_SEND,
            owner: None,
            fields: serde_json::to_value(SendInput {
                email,
                selection,
                execute_at: None,
                not_after: None,
            })
            .map_err(local::storage)?,
        }],
        returning: vec![source],
        authorizations: vec![Authorization {
            source,
            grant: grant.grant,
        }],
    })
}
fn execution(result: &Value) -> Result<Uuid> {
    result["result"]["executions"][0]["execution_id"]
        .as_str()
        .ok_or_else(|| failure("created execution identity"))?
        .parse()
        .map_err(local::storage)
}
fn row(store: &Store<Services>, execution: Uuid) -> Result<effects::Execution<Services>> {
    let read = store.db.begin_read()?;
    let bytes = read
        .open_table(effects::EXECUTIONS)?
        .get(execution.as_bytes())?
        .ok_or_else(|| failure("execution source missing"))?;
    local::decode(bytes.value())
}
fn candidate(store: &Store<Services>, execution: Uuid) -> Result<Candidate> {
    let row = row(store, execution)?;
    let read = store.db.begin_read()?;
    let bytes = read
        .open_table(effects::EFFECT_RUNTIME)?
        .get(local::HEADER)?
        .ok_or_else(|| failure("runtime missing"))?;
    let runtime: effects::Runtime = local::decode(bytes.value())?;
    Ok(Candidate {
        store: row.store,
        activation: runtime.activation,
        execution,
        revision: row.revision,
        class: WorkClass::Submit,
    })
}
fn claim(store: &Store<Services>, execution: Uuid, now: i64) -> Result<Claim> {
    store
        .claim_effect_at(&candidate(store, execution)?, Some(now))?
        .ok_or_else(|| failure("claim unavailable"))
}
fn receipts(store: &Store<Services>, operation: Uuid, present: bool) -> Result<()> {
    let read = store.db.begin_read()?;
    require(
        read.open_table(local::RECEIPTS)?
            .get(store.receipt_key(operation))?
            .is_some()
            == present,
        "original enqueue receipt differs",
    )
}
fn image(store: &Store<Services>) -> Result<Value> {
    let value = store.observe_for_verification()?;
    require(value["complete"] == true, "incomplete adapter observation")?;
    Ok(value)
}
fn charged(store: &Store<Services>, expected: usize) -> Result<()> {
    let read = store.db.begin_read()?;
    let executions = read.open_table(effects::EXECUTIONS)?;
    let mut starts = 0usize;
    for row in executions.iter()? {
        let (_, bytes) = row?;
        let execution: effects::Execution<Services> = local::decode(bytes.value())?;
        starts += execution.email_starts.len();
    }
    require(
        starts == expected,
        "physical starts differ from independent scenario count",
    )?;
    require(
        read.open_table(effects::admission::STARTS)?
            .iter()?
            .try_fold(0usize, |count, row| {
                row?;
                Ok::<_, Error>(count + 1)
            })?
            == expected,
        "retained original start count",
    )?;
    require(
        read.open_table(effects::admission::POINTS)?
            .iter()?
            .try_fold(0usize, |count, row| {
                row?;
                Ok::<_, Error>(count + 1)
            })?
            == expected,
        "retained original charge count",
    )?;
    store.check_integrity()?;
    Ok(())
}
fn trace_report(captures: &Captures) -> Result<Value> {
    let traces = capture(captures)?.traces.clone();
    require(
        traces.iter().all(|trace| {
            trace
                .reads
                .iter()
                .chain(&trace.writes)
                .all(|(table, key)| table != local::KV.name() || key.first() != Some(&13))
        }),
        "historical population key accessed",
    )?;
    Ok(json!(traces.iter().map(trace_value).collect::<Vec<_>>()))
}

/// Reuse each family destination for reopen; different family names must be fresh.
pub fn run(factory: impl Fn(&str) -> Result<Database>, concurrent: bool) -> Result<Value> {
    let crypto = Arc::new(credential_checks::fixture_crypto()?);
    let mut reports = vec![];
    for independent in [false, true] {
        let family = if independent {
            "e2-independent-provider-start"
        } else {
            "e2-one-account-final-slot"
        };
        let f = setup(factory(family)?, crypto.clone(), independent)?;
        let caller = f.store.session(id(3), 0)?;
        let peer = f.store.session(id(4), 0)?;
        let first = execution(
            &caller.enqueue_email(&f.runtime, &request(&caller, &f.runtime, id(200), id(100))?)?,
        )?;
        let second = execution(
            &peer.enqueue_email(&f.runtime, &request(&peer, &f.runtime, id(201), id(101))?)?,
        )?;
        f.store
            .activate_effect_worker(effects::WorkerMode::Delivery)?;
        let now = crate::mutation::creation_time()?;
        let left = claim(&f.store, first, now)?;
        let right = claim(&f.store, second, now)?;
        capture(&f.captures)?.traces.clear();
        label(&f.captures, "original-start-first")?;
        if concurrent {
            let competing = f.store.session(id(2), 0)?;
            let policies = f.policies.clone();
            let competitor = right.clone();
            let captures = f.captures.clone();
            arm(
                &f.controls,
                Plan {
                    before_commit: Some(Box::new(move || {
                        label(&captures, "original-start-second")?;
                        require(
                            competing
                                .start_effect_admitted_at(&competitor, Some(now), Some(&policies))?
                                .is_some(),
                            "second original start not admitted",
                        )
                    })),
                    ..Default::default()
                },
            )?;
            require(
                f.store
                    .start_effect_admitted_at(&left, Some(now), Some(&f.policies))
                    .is_err_and(|e| e.code == "transaction_conflict"),
                "overlapping runtime/admission starts did not conflict",
            )?;
            require(
                row(&f.store, first)?.email_starts.is_empty(),
                "losing start published a charge",
            )?;
        } else {
            label(&f.captures, "second-start-sequential-winner")?;
            require(
                f.store
                    .start_effect_admitted_at(&right, Some(now), Some(&f.policies))?
                    .is_some(),
                "sequential winner unavailable",
            )?;
        }
        label(&f.captures, "first-original-token-after-known-conflict")?;
        let retried = f
            .store
            .start_effect_admitted_at(&left, Some(now), Some(&f.policies))?;
        require(
            retried.is_some() == independent,
            "provider/account scope interfered with final-slot admission",
        )?;
        let first_row = row(&f.store, first)?;
        require(
            first_row.attempts == u8::from(independent),
            "denial consumed a physical attempt",
        )?;
        if !independent {
            require(
                first_row.lease.is_none()
                    && first_row.next_at == (now + 86_400_000).min(first_row.not_after),
                "denied start did not release lease and preserve retry boundary",
            )?;
        }
        charged(&f.store, if independent { 2 } else { 1 })?;
        let accepted = image(&f.store)?;
        reports.push(json!({"case":family,"concurrent":concurrent,"first_original_conflict":concurrent,"known_conflict_original_token_retry":concurrent,"physical_starts":if independent{2}else{1},"attempts":trace_report(&f.captures)?}));
        drop((caller, peer, f));
        let reopened =
            Store::<Services>::open_backend(factory(family)?, Arc::new(Prepared::load()?))?;
        require(
            image(&reopened)? == accepted,
            "start winner reopen changed state",
        )?;
        reopened.verify_credential_custody(&crypto)?;
    }
    fault_controls(&factory, &crypto, &mut reports)?;
    revocation_controls(&factory, &crypto, concurrent, &mut reports)?;
    Ok(
        json!({"status":"passed","case_count":reports.len(),"provider_requests":0,"concurrent_original_transactions":concurrent,"cases":reports,
        "limits":["Actual selected adapter; redb uses explicitly sequential capacity and revocation controls.","Independent quota scopes share the existing bounded service runtime guard; optimistic conflict is retried only after definite no commit with the original token.","Public dummy keys and literal email data only; no provider HTTP request occurs in this transaction suite."]}),
    )
}

fn fault_controls(
    factory: &impl Fn(&str) -> Result<Database>,
    crypto: &Arc<Crypto>,
    reports: &mut Vec<Value>,
) -> Result<()> {
    let family = "e2-enqueue-and-start-write-faults";
    let f = setup(factory(family)?, crypto.clone(), false)?;
    let caller = f.store.session(id(3), 0)?;
    let mut enqueue = request(&caller, &f.runtime, id(200), id(100))?;
    let before = image(&f.store)?;
    capture(&f.captures)?.traces.clear();
    label(&f.captures, "enqueue-all-writes-before-commit-abort")?;
    arm(
        &f.controls,
        Plan {
            before_commit: Some(Box::new(|| {
                Err(Error::new("injected_abort", "after every enqueue write"))
            })),
            ..Default::default()
        },
    )?;
    require(
        caller
            .enqueue_email(&f.runtime, &enqueue)
            .is_err_and(|e| e.code == "injected_abort"),
        "enqueue final write abort was not reached",
    )?;
    let enqueue_writes = f
        .controls
        .lock()
        .map_err(|_| failure("control lock"))?
        .last_writes;
    require(
        enqueue_writes > 0 && image(&f.store)? == before,
        "enqueue final write abort changed state",
    )?;
    let enqueue_trace = trace_report(&f.captures)?;
    for after in 1..=enqueue_writes {
        enqueue.authorizations = request(&caller, &f.runtime, id(200), id(100))?.authorizations;
        arm(
            &f.controls,
            Plan {
                after: Some(after),
                ..Default::default()
            },
        )?;
        require(
            caller
                .enqueue_email(&f.runtime, &enqueue)
                .is_err_and(|e| e.code == "injected_abort"),
            "enqueue fault did not reach actual write",
        )?;
        require(
            image(&f.store)? == before,
            "partial enqueue publication escaped rollback",
        )?;
        receipts(&caller, enqueue.operation_id, false)?;
    }
    enqueue.authorizations = request(&caller, &f.runtime, id(200), id(100))?.authorizations;
    arm(
        &f.controls,
        Plan {
            lose_ack: true,
            ..Default::default()
        },
    )?;
    require(
        caller
            .enqueue_email(&f.runtime, &enqueue)
            .is_err_and(|e| e.code == "outcome_unknown"),
        "enqueue lost durable acknowledgement did not remain unknown",
    )?;
    receipts(&caller, enqueue.operation_id, true)?;
    let committed = image(&f.store)?;
    enqueue.authorizations[0].grant = "unavailable-original-authorization-evidence".into();
    let recovered = caller.enqueue_email(&f.runtime, &enqueue)?;
    require(
        recovered["replayed"] == true && image(&f.store)? == committed,
        "original enqueue receipt recovery rewrote intent",
    )?;
    let execution = execution(&recovered)?;
    charged(&f.store, 0)?;
    reports.push(json!({"case":"e2-every-enqueue-write-rollback-and-original-receipt","actual_writes":enqueue_writes,"rollback_positions":enqueue_writes+1,"unknown_ack_recovered_without_grant":true,"write_set":enqueue_trace}));

    f.store
        .activate_effect_worker(effects::WorkerMode::Delivery)?;
    let now = crate::mutation::creation_time()?;
    let original = claim(&f.store, execution, now)?;
    let before = image(&f.store)?;
    capture(&f.captures)?.traces.clear();
    label(&f.captures, "start-all-writes-before-commit-abort")?;
    arm(
        &f.controls,
        Plan {
            before_commit: Some(Box::new(|| {
                Err(Error::new("injected_abort", "after every start write"))
            })),
            ..Default::default()
        },
    )?;
    require(
        f.store
            .start_effect_admitted_at(&original, Some(now), Some(&f.policies))
            .is_err_and(|e| e.code == "injected_abort"),
        "start final write abort was not reached",
    )?;
    let start_writes = f
        .controls
        .lock()
        .map_err(|_| failure("control lock"))?
        .last_writes;
    require(
        start_writes > 0 && image(&f.store)? == before,
        "start final write abort changed state",
    )?;
    let start_trace = trace_report(&f.captures)?;
    for after in 1..=start_writes {
        arm(
            &f.controls,
            Plan {
                after: Some(after),
                ..Default::default()
            },
        )?;
        require(
            f.store
                .start_effect_admitted_at(&original, Some(now), Some(&f.policies))
                .is_err_and(|e| e.code == "injected_abort"),
            "start fault did not reach actual write",
        )?;
        require(
            image(&f.store)? == before,
            "partial admission/start publication escaped rollback",
        )?;
        charged(&f.store, 0)?;
    }
    // All previous attempts definitely aborted. A fresh activation bounds the
    // real-clock lease before testing an actual lost commit acknowledgement.
    f.store
        .activate_effect_worker(effects::WorkerMode::Delivery)?;
    let now = crate::mutation::creation_time()?;
    let original = claim(&f.store, execution, now)?;
    arm(
        &f.controls,
        Plan {
            lose_ack: true,
            ..Default::default()
        },
    )?;
    let result = f
        .store
        .start_effect_admitted_at(&original, Some(now), Some(&f.policies));
    let recovery = match result {
        Ok(Some(_)) => "confirmed_original_charge",
        Err(error) if error.code == "outcome_unknown" => "original_charge_status_required",
        _ => return Err(failure("unexpected lost start acknowledgement result")),
    };
    let started = row(&f.store, execution)?;
    require(
        started.email_starts.len() == 1
            && started.email_starts[0].token == original.token
            && started.email_starts[0].activation == original.activation,
        "unknown start did not preserve exactly original charge",
    )?;
    let committed = image(&f.store)?;
    require(
        f.store
            .start_effect_admitted_at(&original, Some(now), Some(&f.policies))
            .is_err_and(|e| e.code == "stale_version"),
        "uncertain original start was dispatched twice",
    )?;
    require(
        image(&f.store)? == committed,
        "original start retry changed charge",
    )?;
    charged(&f.store, 1)?;
    reports.push(json!({"case":"e2-every-start-and-admission-write-rollback-and-unknown-ack","actual_writes":start_writes,"rollback_positions":start_writes+1,"unknown_ack":recovery,"physical_starts":1,"write_set":start_trace}));
    drop((caller, f));
    let reopened = Store::<Services>::open_backend(factory(family)?, Arc::new(Prepared::load()?))?;
    require(
        image(&reopened)? == committed,
        "lost start acknowledgement reopen changed state",
    )?;
    reopened.verify_credential_custody(crypto)?;
    Ok(())
}

fn revoke(store: &Store<Services>, kind: u8) -> Result<()> {
    if kind == 3 {
        let record = credential_checks::record(store, id(100))?;
        let mutation = local::Mutation {
            model: store.model().identity().into(),
            context: store.operation_context(store.model().identity())?,
            operation_id: Uuid::new_v4(),
            commands: vec![Command::Update {
                id: id(100),
                if_version: record.version,
                owner: Some(id(4)),
                set: Default::default(),
                unset: vec![],
            }],
            returning: vec![],
        };
        store.mutate(&mutation)?;
    } else {
        let mut graph = credential_checks::graph()?;
        for principal in &mut graph.principals {
            if [id(3), id(4)].contains(&principal.id) {
                principal.grants.contracts.insert(
                    EMAIL_SEND,
                    [Action::Read, Action::Create, Action::Update, Action::Delete].into(),
                );
            }
            if principal.id == id(3) {
                match kind {
                    0 => principal.credential_epoch += 1,
                    1 => {
                        principal
                            .grants
                            .contracts
                            .get_mut(&CREDENTIAL)
                            .ok_or_else(|| failure("credential grants missing"))?
                            .remove(&Action::Use);
                    }
                    _ => principal.active = false,
                }
            }
        }
        credential_checks::replace(store, graph)?;
    }
    Ok(())
}
fn revocation_controls(
    factory: &impl Fn(&str) -> Result<Database>,
    crypto: &Arc<Crypto>,
    concurrent: bool,
    reports: &mut Vec<Value>,
) -> Result<()> {
    for starting in [false, true] {
        for kind in 0..4 {
            let change = [
                "principal-epoch",
                "explicit-use",
                "principal-inactive",
                "credential-owner",
            ][kind as usize];
            let family = format!("e2-{}-{change}", if starting { "start" } else { "accept" });
            let f = setup(factory(&family)?, crypto.clone(), false)?;
            let caller = f.store.session(id(3), 0)?;
            let enqueue = request(&caller, &f.runtime, id(200), id(100))?;
            let execution = if starting {
                Some(execution(&caller.enqueue_email(&f.runtime, &enqueue)?)?)
            } else {
                None
            };
            let now = crate::mutation::creation_time()?;
            let original = if let Some(execution) = execution {
                f.store
                    .activate_effect_worker(effects::WorkerMode::Delivery)?;
                Some(claim(&f.store, execution, now)?)
            } else {
                None
            };
            capture(&f.captures)?.traces.clear();
            label(&f.captures, "original-pending-authority")?;
            let winner = Arc::new(Mutex::new(None));
            if concurrent {
                let authority = f.store.session(id(2), 0)?;
                let captures = f.captures.clone();
                let saved = winner.clone();
                arm(
                    &f.controls,
                    Plan {
                        before_commit: Some(Box::new(move || {
                            label(&captures, "current-authority-winner")?;
                            revoke(&authority, kind)?;
                            *saved.lock().map_err(|_| failure("winner lock"))? =
                                Some(image(&authority)?);
                            Ok(())
                        })),
                        ..Default::default()
                    },
                )?;
                let result = if let Some(original) = &original {
                    f.store
                        .start_effect_admitted_at(original, Some(now), Some(&f.policies))
                        .map(|_| ())
                } else {
                    caller.enqueue_email(&f.runtime, &enqueue).map(|_| ())
                };
                require(
                    result.is_err_and(|e| e.code == "transaction_conflict"),
                    "original attempt did not conflict with committed authority revocation",
                )?;
                require(
                    winner.lock().map_err(|_| failure("winner lock"))?.as_ref()
                        == Some(&image(&f.store)?),
                    "losing authorized attempt changed revocation winner",
                )?;
            } else {
                revoke(&f.store, kind)?;
            }
            if let Some(original) = &original {
                require(
                    f.store
                        .start_effect_admitted_at(original, Some(now), Some(&f.policies))?
                        .is_none(),
                    "revoked requester was physically started",
                )?;
                let row = row(
                    &f.store,
                    execution.ok_or_else(|| failure("execution missing"))?,
                )?;
                require(
                    row.cancellation == Some(effects::Cancellation::Revoked)
                        && row.attempts == 0
                        && row.email_starts.is_empty(),
                    "revoked start changed physical budget or did not cancel",
                )?;
            } else {
                require(
                    caller
                        .enqueue_email(&f.runtime, &enqueue)
                        .is_err_and(|e| e.code == "forbidden"),
                    "revoked grant accepted a new source",
                )?;
                receipts(&caller, enqueue.operation_id, false)?;
                let read = f.store.db.begin_read()?;
                require(
                    read.open_table(local::KV)?
                        .get(Key::Record(id(200)).encode())?
                        .is_none(),
                    "revoked enqueue published source",
                )?;
            }
            charged(&f.store, 0)?;
            let accepted = image(&f.store)?;
            reports.push(json!({"case":family,"concurrent":concurrent,"original_transaction_conflict":concurrent,"physical_starts":0,"attempts":trace_report(&f.captures)?}));
            drop((caller, f));
            let reopened =
                Store::<Services>::open_backend(factory(&family)?, Arc::new(Prepared::load()?))?;
            require(
                image(&reopened)? == accepted,
                "revocation winner reopen changed state",
            )?;
            reopened.verify_credential_custody(crypto)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_redb_email_transaction_controls_are_explicitly_sequential() {
        let path = std::env::temp_dir().join(format!("e2-email-adapter-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        let result = run(
            |family| {
                let file = path.join(format!("{family}.redb"));
                if file.exists() {
                    Database::open(file)
                } else {
                    Database::create(file)
                }
            },
            false,
        )
        .unwrap();
        assert_eq!(result["status"], "passed");
        assert_eq!(result["case_count"], 12);
        assert_eq!(result["provider_requests"], 0);
        std::fs::remove_dir_all(path).unwrap();
    }
}
