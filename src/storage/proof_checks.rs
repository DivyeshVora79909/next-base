//! A1/A2 controls over the actual adapter. Optimistic transactions overlap at
//! their original commit boundary; redb controls are explicitly sequential.
//! Faults occur after actual writes or after an actual durable commit.
use super::{
    Database, ReadableTable,
    coordination_checks::{Captures, Recording, capture, label, trace_value},
    credential_checks,
    email_checks::{Controlled, Controls, Plan, arm},
};
use crate::{
    access::Action,
    authentication::{
        proof::{self, Config, Runtime},
        proof_crypto,
        proof_types::{Begin, Consume, Secret, ServerPolicy, Status},
        types::{Input, Kind},
    },
    binding::Binding,
    credentials::crypto::{Metadata, Provider},
    identity::IdentityConfig,
    local::{self, Mutation, Store},
    model::{Prepared, Visibility},
    models::services::{AUTH_DELIVERY, IDENTITY, Services},
    native_codec::{self, Key, StoredValue},
    native_slice::{Context, Error, ModelRecord, Result},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;
use zeroize::Zeroizing;

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn failure(detail: &str) -> Error {
    Error::new("proof_conformance", detail)
}
fn require(ok: bool, detail: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(failure(detail)) }
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| failure("missing exact proof field"))
}
fn uuid(value: &Value, key: &str) -> Result<Uuid> {
    Uuid::parse_str(string(value, key)?).map_err(local::storage)
}
fn millis(value: &Value, key: &str) -> Result<i64> {
    string(value, key)?.parse().map_err(local::storage)
}

struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(local::storage)?;
    file.write_all(bytes).map_err(local::storage)?;
    file.sync_all().map_err(local::storage)
}
fn identity_config() -> IdentityConfig {
    IdentityConfig {
        issuer: "proof-adapter-conformance".into(),
        audience: "public-fixture".into(),
        max_token_seconds: 900,
        public_keys: [(
            "public-test".into(),
            include_str!("../../tests/fixtures/test-ed25519-public.pem").into(),
        )]
        .into(),
    }
}
fn fixture_runtime(store: &Store<Services>, provider: Provider) -> Result<Runtime> {
    let directory =
        std::env::temp_dir().join(format!("rebase-public-proof-fixture-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).map_err(local::storage)?;
    let _cleanup = Cleanup(directory.clone());
    let keyring = directory.join("proof.json");
    private_file(
        &keyring,
        &serde_json::to_vec(&json!({
            "format":proof_crypto::KEYRING_FORMAT,"current":"public-proof",
            "keys":[{"key_id":"public-proof","key":URL_SAFE_NO_PAD.encode([23u8;32])}]
        }))
        .map_err(local::storage)?,
    )?;
    let signing = directory.join("signing.pem");
    private_file(
        &signing,
        include_bytes!("../../tests/fixtures/test-ed25519-private.pem"),
    )?;
    let identity = identity_config();
    let kind = if provider == Provider::FakeSms {
        Kind::Phone
    } else {
        Kind::Email
    };
    Runtime::load(
        &Config {
            keyring,
            policies: vec![ServerPolicy {
                kind,
                revision: id(500),
                credential: id(100),
                owner: id(2),
                provider,
                account: "public-fixture-account".into(),
                sender: (kind == Kind::Email).then(|| "proof@example.test".into()),
            }],
            active_signing_key: "public-test".into(),
            signing_keys: [("public-test".into(), signing)].into(),
        },
        &identity,
        store.context().tenant,
        store.session_generation()?,
    )
}
struct Fixture {
    store: Store<Services>,
    runtime: Runtime,
    identifier: Input,
    captures: Captures,
    controls: Controls,
}
fn mutation(store: &Store<Services>, commands: Value) -> Result<Mutation> {
    serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity())?,"operation_id":Uuid::new_v4(),"commands":commands,"returning":[]})).map_err(local::storage)
}
fn setup(db: Database, provider: Provider) -> Result<Fixture> {
    let captures = Captures::default();
    let controls = Controls::default();
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
        if principal.id == id(2) {
            principal.grants.contracts.insert(
                IDENTITY,
                [Action::Read, Action::Create, Action::Update, Action::Delete].into(),
            );
        }
        if principal.id == id(4) {
            principal.login_access = true;
            principal.grants.contracts.clear();
        }
    }
    credential_checks::replace(&store, graph)?;
    let crypto = credential_checks::fixture_crypto()?;
    let kind = if provider == Provider::FakeSms {
        Kind::Phone
    } else {
        Kind::Email
    };
    let metadata = Metadata {
        label: "Public conformance fixture".into(),
        provider,
        account: "public-fixture-account".into(),
        enabled: true,
        scopes: vec![
            if kind == Kind::Phone {
                "sms.send"
            } else {
                "email.send"
            }
            .into(),
        ],
    };
    store.write_secret(
        &crypto,
        &credential_checks::sealed_metadata(
            &store,
            &crypto,
            (id(100), None, None, Uuid::new_v4()),
            br#"{"api_key":"public-proof-adapter-fixture"}"#,
            metadata,
        )?,
    )?;
    let identifier = Input {
        kind,
        value: if kind == Kind::Phone {
            "+123456789"
        } else {
            "proof@example.test"
        }
        .into(),
    };
    store.mutate(&mutation(
        &store,
        json!([{"op":"create","id":id(200),"contract":IDENTITY,"owner":id(4),"fields":identifier}]),
    )?)?;
    let runtime = fixture_runtime(&store, provider)?;
    store.configure_authentication(Some(&runtime))?;
    store.check_integrity()?;
    capture(&captures)?.traces.clear();
    Ok(Fixture {
        store,
        runtime,
        identifier,
        captures,
        controls,
    })
}
fn begin_request(f: &Fixture) -> Result<Begin> {
    Ok(Begin {
        operation_id: Uuid::new_v4(),
        recovery_secret: Secret::new(proof_crypto::random_secret()?),
        identifier: f.identifier.clone(),
    })
}
fn consume_request(handle: &str, code: &str) -> Result<Consume> {
    Ok(Consume {
        operation_id: Uuid::new_v4(),
        recovery_secret: Secret::new(proof_crypto::random_secret()?),
        challenge: Secret::new(handle.into()),
        code: Secret::new(code.into()),
    })
}
fn begin(f: &Fixture, request: &Begin) -> Result<Value> {
    f.store.begin_proof(&f.runtime, request, "127.0.0.1")
}
fn consume(f: &Fixture, request: &Consume) -> Result<Value> {
    f.store.consume_proof(&f.runtime, request, "127.0.0.1")
}
fn status(f: &Fixture, operation_id: Uuid, recovery_secret: &Secret) -> Result<Value> {
    f.store.proof_status(
        &f.runtime,
        &Status {
            operation_id,
            recovery_secret: recovery_secret.clone(),
        },
    )
}
fn image(store: &Store<Services>) -> Result<Value> {
    let image = store.observe_for_verification()?;
    require(image["complete"] == true, "incomplete proof observation")?;
    Ok(image)
}
fn receipt_present(f: &Fixture, operation: Uuid, present: bool) -> Result<()> {
    require(
        f.store
            .db
            .begin_read()?
            .open_table(proof::RECEIPTS)?
            .get(operation.as_bytes().as_slice())?
            .is_some()
            == present,
        "original proof receipt presence",
    )
}
fn rows(
    store: &Store<Services>,
    table: super::TableDefinition<'static, &'static [u8], &'static [u8]>,
) -> Result<BTreeMap<Vec<u8>, Value>> {
    store
        .db
        .begin_read()?
        .open_table(table)?
        .iter()?
        .map(|row| {
            let (key, value) = row?;
            Ok((key.value().to_vec(), local::decode(value.value())?))
        })
        .collect()
}
fn code(f: &Fixture, operation: Uuid) -> Result<Zeroizing<String>> {
    let challenges = rows(&f.store, proof::CHALLENGES)?;
    let challenge = challenges
        .values()
        .find(|c| uuid(c, "operation").ok() == Some(operation))
        .ok_or_else(|| failure("original proof challenge missing"))?;
    let source = credential_checks::record(&f.store, uuid(challenge, "source")?)?;
    let delivery = Services::auth_delivery(&source.input)
        .ok_or_else(|| failure("private delivery source role"))?;
    let (_, _, header) = f.store.read(f.store.model().identity())?;
    let bytes = f.runtime.crypto.open(
        &proof::delivery_aad(header.store_id, f.store.context().tenant, delivery),
        &delivery.payload,
    )?;
    #[derive(serde::Deserialize)]
    struct Payload {
        code: Secret,
    }
    let payload: Payload = serde_json::from_slice(&bytes).map_err(local::storage)?;
    proof_crypto::validate_code(&payload.code)?;
    Ok(Zeroizing::new(payload.code.as_str().into()))
}
fn wrong(code: &str) -> String {
    let mut bytes = code.as_bytes().to_vec();
    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
    String::from_utf8(bytes).expect("six ASCII code digits")
}

/// Literal source/receipt relations are independent of writer runtime counters,
/// ordered caches and the native checker. The native checker separately derives
/// the complete AVL forest, credential envelopes and query/owner indexes.
fn inventory(store: &Store<Services>) -> Result<()> {
    let read = store.db.begin_read()?;
    let mut records = BTreeMap::<Uuid, ModelRecord<Services>>::new();
    for row in read.open_table(local::KV)?.iter()? {
        let (k, v) = row?;
        if let Key::Record(id) = Key::decode(k.value())? {
            let StoredValue::Record(record) =
                native_codec::decode_for::<Services>(&Key::Record(id), v.value())?
            else {
                return Err(failure("source record role"));
            };
            records.insert(id, record);
        }
    }
    let mut expected_public = BTreeMap::new();
    let mut expected_owners = BTreeMap::new();
    for (&id, record) in &records {
        if store.model().contract(record.contract)?.visibility == Visibility::Public {
            expected_public.insert(id.as_bytes().to_vec(), record.contract);
            let key = [
                record.owner.as_bytes().as_slice(),
                &record.contract.to_be_bytes(),
                id.as_bytes().as_slice(),
            ]
            .concat();
            expected_owners.insert(key, record.contract);
        }
    }
    let actual_public = read
        .open_table(local::PUBLIC)?
        .iter()?
        .map(|r| {
            let (k, v) = r?;
            Ok((k.value().to_vec(), v.value()))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let actual_owners = read
        .open_table(crate::security::OWNERS)?
        .iter()?
        .map(|r| {
            let (k, v) = r?;
            Ok((k.value().to_vec(), v.value()))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    require(
        actual_public == expected_public && actual_owners == expected_owners,
        "public/owner dictionaries differ from source visibility",
    )?;
    let challenges = rows(store, proof::CHALLENGES)?;
    let receipts = rows(store, proof::RECEIPTS)?;
    let mut spent = BTreeMap::<Uuid, u64>::new();
    let mut issued = BTreeSet::new();
    let mut verified = BTreeMap::<(Uuid, Uuid, u64), i64>::new();
    for (key, r) in &receipts {
        require(
            key.as_slice() == uuid(r, "operation")?.as_bytes(),
            "receipt operation key",
        )?;
        let outcome = &r["outcome"];
        match string(outcome, "kind")? {
            "begin" => {
                let challenge = uuid(outcome, "challenge")?;
                require(
                    challenges.contains_key(challenge.as_bytes().as_slice()),
                    "receipt missing challenge",
                )?;
            }
            "invalid" if outcome["spent"] == true => {
                *spent.entry(uuid(outcome, "challenge")?).or_default() += 1;
            }
            "invalid" => {
                require(
                    outcome["challenge"].is_null(),
                    "unspent receipt disclosed challenge",
                )?;
            }
            "issued" => {
                let cid = uuid(outcome, "challenge")?;
                require(issued.insert(cid), "challenge issued twice")?;
                *spent.entry(cid).or_default() += 1;
                let c = challenges
                    .get(cid.as_bytes().as_slice())
                    .ok_or_else(|| failure("issued challenge missing"))?;
                let binding = &c["binding"];
                let revision = string(binding, "identity_revision")?
                    .parse::<u64>()
                    .map_err(local::storage)?;
                let at = millis(r, "created_at")?;
                let key = (
                    uuid(binding, "identity")?,
                    uuid(binding, "incarnation")?,
                    revision,
                );
                verified
                    .entry(key)
                    .and_modify(|old| *old = (*old).max(at))
                    .or_insert(at);
                require(
                    outcome["issuance"]["claims"]["sub"] == binding["owner"],
                    "issuance subject mismatch",
                )?;
            }
            _ => return Err(failure("unknown proof receipt outcome")),
        }
    }
    let mut expected_handles = BTreeMap::new();
    let mut expected_sources = BTreeSet::new();
    let mut candidates = BTreeMap::<Uuid, BTreeSet<Uuid>>::new();
    let mut predecessors = BTreeSet::new();
    for (key, c) in &challenges {
        let cid = uuid(c, "id")?;
        require(key.as_slice() == cid.as_bytes(), "challenge key")?;
        require(
            c["attempts"].as_u64() == Some(*spent.get(&cid).unwrap_or(&0))
                && c["consumed"] == issued.contains(&cid),
            "challenge state differs from receipt oracle",
        )?;
        let origin = receipts
            .get(uuid(c, "operation")?.as_bytes().as_slice())
            .ok_or_else(|| failure("challenge origin receipt missing"))?;
        require(
            origin["outcome"]["kind"] == "begin" && origin["outcome"]["challenge"] == c["id"],
            "challenge origin differs",
        )?;
        expected_handles.insert(string(c, "handle_digest")?.as_bytes().to_vec(), json!(cid));
        if !c["binding"].is_null() {
            let source = uuid(c, "source")?;
            require(expected_sources.insert(source), "duplicate private source")?;
            let record = records
                .get(&source)
                .ok_or_else(|| failure("private source missing"))?;
            let delivery = Services::auth_delivery(&record.input)
                .ok_or_else(|| failure("private source type"))?;
            require(
                record.contract == AUTH_DELIVERY
                    && record.owner == uuid(&c["binding"], "owner")?
                    && delivery.challenge == cid
                    && delivery.generation == uuid(c, "generation")?
                    && delivery.expires_at == millis(c, "expires_at")?,
                "private source differs from receipt origin",
            )?;
            candidates
                .entry(uuid(&c["binding"], "incarnation")?)
                .or_default()
                .insert(cid);
            if c["previous"].is_string() {
                predecessors.insert(uuid(c, "previous")?);
            }
        }
    }
    require(
        rows(store, proof::HANDLES)? == expected_handles,
        "private handle dictionary differs from challenge facts",
    )?;
    let mut expected_heads = BTreeMap::new();
    for (incarnation, ids) in candidates {
        let tips = ids.difference(&predecessors).copied().collect::<Vec<_>>();
        require(
            tips.len() == 1,
            "challenge history has no unique causal head",
        )?;
        expected_heads.insert(incarnation.as_bytes().to_vec(), json!(tips[0]));
    }
    require(
        rows(store, proof::HEADS)? == expected_heads,
        "private heads differ from challenge chains",
    )?;
    let actual_sources = records
        .iter()
        .filter(|(_, r)| r.contract == AUTH_DELIVERY)
        .map(|(&id, _)| id)
        .collect::<BTreeSet<_>>();
    require(
        actual_sources == expected_sources,
        "private delivery source inventory",
    )?;
    for (&id, record) in &records {
        if record.contract == IDENTITY {
            let (_, identity) = Services::identity_values(record)?;
            let expected = verified
                .get(&(id, identity.incarnation, identity.identity_revision))
                .copied();
            require(
                identity.verified_at == expected
                    && identity.verified_revision == expected.map(|_| identity.identity_revision),
                "identity verification differs from successful proof receipts",
            )?;
        }
    }
    store.check_integrity()?;
    Ok(())
}
fn traces(f: &Fixture) -> Result<Value> {
    let capture = capture(&f.captures)?;
    Ok(json!(
        capture
            .traces
            .iter()
            .filter(|t| !t.writes.is_empty())
            .map(trace_value)
            .collect::<Vec<_>>()
    ))
}
fn reopened(
    factory: &impl Fn(&str) -> Result<Database>,
    family: &str,
    expected: &Value,
) -> Result<()> {
    let store = Store::<Services>::open_backend(factory(family)?, Arc::new(Prepared::load()?))?;
    require(
        image(&store)? == *expected,
        "proof reopen changed accepted image",
    )?;
    inventory(&store)
}

fn begin_races(
    factory: &impl Fn(&str) -> Result<Database>,
    concurrent: bool,
    reports: &mut Vec<Value>,
) -> Result<()> {
    for provider in [Provider::Resend, Provider::FakeSms] {
        let family = format!(
            "a1-original-begin-{}",
            if provider == Provider::FakeSms {
                "phone"
            } else {
                "email"
            }
        );
        let f = setup(factory(&family)?, provider)?;
        let first = begin_request(&f)?;
        let second = begin_request(&f)?;
        let mut winner = Value::Null;
        let mut committed = Value::Null;
        label(&f.captures, "original-begin-first")?;
        if concurrent {
            let result = f.store.begin_proof_controlled(
                &f.runtime,
                &first,
                "127.0.0.1",
                None,
                &mut || {
                    label(&f.captures, "original-begin-second-winner")?;
                    winner = begin(&f, &second)?;
                    committed = image(&f.store)?;
                    Ok(())
                },
                false,
            );
            require(
                result.is_err_and(|e| e.code == "transaction_conflict"),
                "original same-identity begins did not conflict",
            )?;
            require(
                image(&f.store)? == committed,
                "begin loser changed committed winner",
            )?;
        } else {
            winner = begin(&f, &second)?;
        }
        receipt_present(&f, first.operation_id, false)?;
        receipt_present(&f, second.operation_id, true)?;
        let retried = begin(&f, &first)?;
        require(
            retried == winner,
            "known-conflict begin retry did not coalesce exact response",
        )?;
        require(
            rows(&f.store, proof::CHALLENGES)?.len() == 1
                && rows(&f.store, crate::effects::EXECUTIONS)?.len() == 1
                && rows(&f.store, proof::RECEIPTS)?.len() == 2,
            "coalesced begins created more than one delivery",
        )?;
        inventory(&f.store)?;
        reports.push(json!({"case":family,"concurrent":concurrent,"original_conflict":concurrent,"known_retry_coalesces":true,"challenges":1,"deliveries":1,"attempts":traces(&f)?}));
        let image = image(&f.store)?;
        drop(f);
        reopened(factory, &family, &image)?;
    }
    Ok(())
}

fn consume_races(
    factory: &impl Fn(&str) -> Result<Database>,
    concurrent: bool,
    reports: &mut Vec<Value>,
) -> Result<()> {
    for (first_correct, second_correct, prior_failures) in [
        (true, true, 0),
        (false, true, 0),
        (true, false, 0),
        (false, false, 4),
    ] {
        let family = format!(
            "a1-consume-race-{}-{}-{prior_failures}",
            u8::from(first_correct),
            u8::from(second_correct)
        );
        let f = setup(factory(&family)?, Provider::Resend)?;
        let request = begin_request(&f)?;
        let accepted = begin(&f, &request)?;
        let handle = string(&accepted, "challenge")?;
        let correct = code(&f, request.operation_id)?;
        let wrong = wrong(&correct);
        for _ in 0..prior_failures {
            require(
                consume(&f, &consume_request(handle, &wrong)?)?["status"] == "invalid_proof",
                "wrong pre-attempt authenticated",
            )?;
        }
        let first = consume_request(handle, if first_correct { &correct } else { &wrong })?;
        let second = consume_request(handle, if second_correct { &correct } else { &wrong })?;
        capture(&f.captures)?.traces.clear();
        label(&f.captures, "original-consume-first")?;
        let mut winner = Value::Null;
        let mut committed = Value::Null;
        if concurrent {
            let result = f.store.consume_proof_controlled(
                &f.runtime,
                &first,
                "127.0.0.1",
                None,
                &mut || {
                    label(&f.captures, "original-consume-second-winner")?;
                    winner = consume(&f, &second)?;
                    committed = image(&f.store)?;
                    Ok(())
                },
                false,
            );
            require(
                result.is_err_and(|e| e.code == "transaction_conflict"),
                "overlapping consumes did not conflict",
            )?;
            require(
                image(&f.store)? == committed,
                "consume loser changed winning decision",
            )?;
        } else {
            winner = consume(&f, &second)?;
        }
        receipt_present(&f, first.operation_id, false)?;
        let retry = consume(&f, &first)?;
        let expected_success = first_correct && !second_correct;
        require(
            retry["status"]
                == if expected_success {
                    "authenticated"
                } else {
                    "invalid_proof"
                },
            "consume retry differs from one-use oracle",
        )?;
        require(
            winner["status"]
                == if second_correct {
                    "authenticated"
                } else {
                    "invalid_proof"
                },
            "winning consume differs from input oracle",
        )?;
        let before = image(&f.store)?;
        require(
            status(&f, second.operation_id, &second.recovery_secret)? == winner,
            "winning consume recovery changed decision",
        )?;
        require(
            consume(&f, &first)? == retry && image(&f.store)? == before,
            "original consume replay changed attempts or claims",
        )?;
        let challenges = rows(&f.store, proof::CHALLENGES)?;
        let challenge = challenges
            .values()
            .next()
            .ok_or_else(|| failure("missing consumed challenge"))?;
        let expected_attempts = if second_correct {
            1
        } else if first_correct {
            2
        } else {
            5
        };
        require(
            challenge["attempts"] == expected_attempts
                && challenge["consumed"] == (first_correct || second_correct),
            "attempt count differs from independent race oracle",
        )?;
        inventory(&f.store)?;
        reports.push(json!({"case":family,"concurrent":concurrent,"original_conflict":concurrent,"prior_wrong_attempts":prior_failures,"final_attempts":expected_attempts,"at_most_one_issuance":true,"attempts":traces(&f)?}));
        let image = image(&f.store)?;
        drop(f);
        reopened(factory, &family, &image)?;
    }
    Ok(())
}

fn authority_races(
    factory: &impl Fn(&str) -> Result<Database>,
    concurrent: bool,
    reports: &mut Vec<Value>,
) -> Result<()> {
    for replace_identity in [true, false] {
        let family = if replace_identity {
            "a2-consume-identity-replacement"
        } else {
            "a2-consume-login-revocation"
        };
        let f = setup(factory(family)?, Provider::Resend)?;
        let begin_request = begin_request(&f)?;
        let accepted = begin(&f, &begin_request)?;
        let correct = code(&f, begin_request.operation_id)?;
        let request = consume_request(string(&accepted, "challenge")?, &correct)?;
        let mut winner = Value::Null;
        capture(&f.captures)?.traces.clear();
        let mut revoke = || {
            label(&f.captures, "authority-revocation-winner")?;
            if replace_identity {
                let record = credential_checks::record(&f.store, id(200))?;
                f.store.mutate(&mutation(&f.store,json!([{"op":"update","id":id(200),"if_version":record.version,"set":{"value":"changed@example.test"},"unset":[]}]))?)?;
            } else {
                let mut graph: crate::access::Graph = serde_json::from_value(
                    f.store.access_graph(f.store.model().identity())?["graph"].clone(),
                )
                .map_err(local::storage)?;
                graph
                    .principals
                    .iter_mut()
                    .find(|p| p.id == id(4))
                    .ok_or_else(|| failure("fixture proof principal"))?
                    .login_access = false;
                credential_checks::replace(&f.store, graph)?;
            }
            winner = image(&f.store)?;
            Ok(())
        };
        label(&f.captures, "original-consume-before-revocation")?;
        if concurrent {
            let result = f.store.consume_proof_controlled(
                &f.runtime,
                &request,
                "127.0.0.1",
                None,
                &mut revoke,
                false,
            );
            require(
                result.is_err_and(|e| e.code == "transaction_conflict"),
                "consume did not conflict with current identity/login revocation",
            )?;
        } else {
            revoke()?;
        }
        require(
            image(&f.store)? == winner,
            "revoked consume changed revocation winner",
        )?;
        receipt_present(&f, request.operation_id, false)?;
        require(
            consume(&f, &request)?["status"] == "invalid_proof",
            "revoked original consume authenticated",
        )?;
        let record = credential_checks::record(&f.store, id(200))?;
        require(
            Services::identity_values(&record)?
                .1
                .verified_revision
                .is_none(),
            "revoked proof marked identity verified",
        )?;
        inventory(&f.store)?;
        reports.push(json!({"case":family,"concurrent":concurrent,"original_conflict":concurrent,"known_retry_invalid":true,"attempts":traces(&f)?}));
        let image = image(&f.store)?;
        drop(f);
        reopened(factory, family, &image)?;
    }
    Ok(())
}

fn abort_plan() -> Plan {
    Plan {
        before_commit: Some(Box::new(|| {
            Err(Error::new("injected_abort", "before actual proof commit"))
        })),
        ..Default::default()
    }
}
fn last_writes(f: &Fixture) -> Result<usize> {
    Ok(f.controls
        .lock()
        .map_err(|_| failure("proof fault control lock"))?
        .last_writes)
}
fn rollback_and_recovery(
    factory: &impl Fn(&str) -> Result<Database>,
    reports: &mut Vec<Value>,
) -> Result<()> {
    for consumption in [false, true] {
        let family = if consumption {
            "a2-physical-consume-rollback-recovery"
        } else {
            "a1-physical-begin-rollback-recovery"
        };
        let f = setup(factory(family)?, Provider::Resend)?;
        let start = begin_request(&f)?;
        let accepted = if consumption {
            begin(&f, &start)?
        } else {
            Value::Null
        };
        let attempt = if consumption {
            Some(consume_request(
                string(&accepted, "challenge")?,
                &code(&f, start.operation_id)?,
            )?)
        } else {
            None
        };
        let operation = attempt
            .as_ref()
            .map_or(start.operation_id, |r| r.operation_id);
        let recovery = attempt
            .as_ref()
            .map_or(&start.recovery_secret, |r| &r.recovery_secret);
        let apply = || {
            if let Some(request) = &attempt {
                consume(&f, request)
            } else {
                begin(&f, &start)
            }
        };
        let before = image(&f.store)?;
        capture(&f.captures)?.traces.clear();
        label(&f.captures, "actual-final-proof-write-abort")?;
        arm(&f.controls, abort_plan())?;
        require(
            apply().is_err_and(|e| e.code == "injected_abort"),
            "proof final-write abort not reached",
        )?;
        let count = last_writes(&f)?;
        require(count > 0, "proof publication has no physical writes")?;
        require(
            image(&f.store)? == before,
            "proof final-write abort changed image",
        )?;
        let write_set = traces(&f)?;
        for after in 1..=count {
            arm(
                &f.controls,
                Plan {
                    after: Some(after),
                    ..Default::default()
                },
            )?;
            require(
                apply().is_err_and(|e| e.code == "injected_abort"),
                "physical proof-write abort not reached",
            )?;
            require(
                image(&f.store)? == before,
                "partial proof/source/index/receipt publication escaped rollback",
            )?;
            receipt_present(&f, operation, false)?;
            inventory(&f.store)?;
        }
        arm(
            &f.controls,
            Plan {
                lose_ack: true,
                ..Default::default()
            },
        )?;
        require(
            apply().is_err_and(|e| e.code == "outcome_unknown"),
            "durable proof acknowledgement loss not reported",
        )?;
        receipt_present(&f, operation, true)?;
        let committed = image(&f.store)?;
        let recovered = status(&f, operation, recovery)?;
        require(
            recovered["status"]
                == if consumption {
                    "authenticated"
                } else {
                    "accepted"
                },
            "recovered proof decision role",
        )?;
        require(
            apply()? == recovered && image(&f.store)? == committed,
            "unknown proof outcome refreshed decision/claims/attempts",
        )?;
        if consumption {
            let signed = crate::identity::Verifier::new(identity_config())?
                .verify(string(&recovered, "token")?, f.store.context().tenant)?;
            let receipt_rows = rows(&f.store, proof::RECEIPTS)?;
            let receipt = receipt_rows
                .get(operation.as_bytes().as_slice())
                .ok_or_else(|| failure("recovery issuance receipt missing"))?;
            require(
                serde_json::to_value(signed).map_err(local::storage)?
                    == receipt["outcome"]["issuance"]["claims"],
                "signed recovery claims differ from original durable decision",
            )?;
            let request = attempt.as_ref().ok_or_else(|| failure("consume fixture"))?;
            let another = consume_request(&request.challenge, &request.code)?;
            require(
                consume(&f, &another)?["status"] == "invalid_proof",
                "recovered consumed proof allowed second issuance",
            )?;
        }
        inventory(&f.store)?;
        reports.push(json!({"case":family,"physical_write_positions":count,"final_write_abort":true,"actual_durable_ack_loss":true,"original_receipt_and_pinned_result":true,"write_set":write_set}));
        let final_image = image(&f.store)?;
        drop(f);
        let reopened =
            Store::<Services>::open_backend(factory(family)?, Arc::new(Prepared::load()?))?;
        let runtime = fixture_runtime(&reopened, Provider::Resend)?;
        require(
            reopened.proof_status(
                &runtime,
                &Status {
                    operation_id: operation,
                    recovery_secret: recovery.clone(),
                },
            )? == recovered,
            "reopen changed original proof response or signed JWT bytes",
        )?;
        require(
            image(&reopened)? == final_image,
            "read-only original recovery changed reopened image",
        )?;
        inventory(&reopened)?;
    }
    Ok(())
}

pub fn run(factory: impl Fn(&str) -> Result<Database>, concurrent: bool) -> Result<Value> {
    let mut reports = vec![];
    begin_races(&factory, concurrent, &mut reports)?;
    consume_races(&factory, concurrent, &mut reports)?;
    authority_races(&factory, concurrent, &mut reports)?;
    rollback_and_recovery(&factory, &mut reports)?;
    Ok(
        json!({"status":"passed","case_count":reports.len(),"concurrent_original_transactions":concurrent,"cases":reports,
        "limits":["Actual selected adapter; redb race controls are sequential.","Fault wrapper does not manufacture conflicts or commits; it aborts after actual writes and drops actual durable acknowledgements.","Private fixture decryption models code possession; no provider response or external delivery is claimed.","No population counter; exact proof/private/source/owner inventories and native source-derived AVL checks run after accepted states and rollback."]}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_redb_proof_controls_are_explicitly_sequential() {
        let directory = std::env::temp_dir().join(format!("a1-proof-adapter-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let _cleanup = Cleanup(directory.clone());
        let result = run(
            |family| {
                let path = directory.join(format!("{family}.redb"));
                if path.exists() {
                    Database::open(path)
                } else {
                    Database::create(path)
                }
            },
            false,
        )
        .unwrap();
        assert_eq!(result["status"], "passed");
        assert_eq!(result["case_count"], 10);
    }
}
