//! E1 controls through actual adapters and the ordinary encrypted mutation path.
//! Known public dummy keys are disposable fixtures; no live provider is contacted.
use super::{
    Database, ReadableTable,
    coordination_checks::{Captures, Recording, capture, label, operation, trace_value},
};
use crate::{
    access::{Action, Grants, Graph, Principal, PrincipalKind},
    credentials::{
        crypto::{
            Crypto, INGRESS_FORMAT, INGRESS_INFO, IngressContext, IngressEnvelope, Metadata,
            Provider, SecretContext, ingress_aad,
        },
        store::WriteSecret,
    },
    local::{self, Store},
    model::Prepared,
    models::services::{CREDENTIAL, Services},
    native_codec::{self, Key, StoredValue},
    native_slice::{Context, Error, ModelRecord, Result},
    security::ReplaceGraph,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hpke::{
    Deserializable, Kem, Serializable, aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, io::Write, sync::Arc};
use uuid::Uuid;
const ALPHA: &[u8] = br#"{"api_key":"public-conformance-alpha"}"#;
const BETA: &[u8] = br#"{"api_key":"public-conformance-beta"}"#;
const GAMMA: &[u8] = br#"{"api_key":"public-conformance-gamma"}"#;
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn fail(detail: &str) -> Error {
    Error::new("credential_conformance", detail)
}
fn require(ok: bool, detail: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(fail(detail)) }
}
fn context() -> Context {
    Context {
        tenant: id(1),
        actor: id(2),
    }
}
fn fixture_crypto() -> Result<Crypto> {
    let path = std::env::temp_dir().join(format!(
        "rebase-public-credential-fixture-{}",
        Uuid::new_v4()
    ));
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _cleanup = Cleanup(path.clone());
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).map_err(local::storage)?;
    let keys = json!({"format":"rebase-credential-keyring-1","active_ingress":"public-ingress","ingress":[{"key_id":"public-ingress","key":URL_SAFE_NO_PAD.encode([1u8;32])}],"active_at_rest":"public-vault","at_rest":[{"key_id":"public-vault","key":URL_SAFE_NO_PAD.encode([2u8;32])}],"active_grant":"public-grant","grants":[{"key_id":"public-grant","key":URL_SAFE_NO_PAD.encode([3u8;32])}]});
    file.write_all(&serde_json::to_vec(&keys).map_err(local::storage)?)
        .map_err(local::storage)?;
    file.sync_all().map_err(local::storage)?;
    drop(file);
    Crypto::load(&path)
}
fn graph() -> Result<Graph> {
    let mut graph = Graph::bootstrap(context())?.graph;
    for (number, parent) in [(3, 2), (4, 2), (7, 3)] {
        graph.principals.push(Principal {
            id: id(number),
            kind: PrincipalKind::User,
            parents: vec![id(parent)],
            active: true,
            credential_epoch: 0,
            grants: Grants {
                admin: false,
                contracts: [(
                    CREDENTIAL,
                    BTreeSet::from([
                        Action::Read,
                        Action::Create,
                        Action::Update,
                        Action::Delete,
                        Action::Use,
                    ]),
                )]
                .into(),
            },
        });
    }
    Ok(graph)
}
fn replace(store: &Store<Services>, graph: Graph) -> Result<()> {
    let if_revision = store.access_graph(store.model().identity())?["revision"]
        .as_str()
        .ok_or_else(|| fail("graph revision"))?
        .parse()
        .map_err(local::storage)?;
    store.replace_access(&ReplaceGraph {
        model: store.model().identity().into(),
        if_revision,
        graph,
    })?;
    Ok(())
}
fn setup(db: Database) -> Result<Store<Services>> {
    let store = Store::create_backend_secured(db, Arc::new(Prepared::load()?), context())?;
    replace(&store, graph()?)?;
    Ok(store)
}
fn record(store: &Store<Services>, id: Uuid) -> Result<ModelRecord<Services>> {
    let read = store.db.begin_read()?;
    let table = read.open_table(local::KV)?;
    let bytes = table
        .get(Key::Record(id).encode())?
        .ok_or_else(|| fail("missing source"))?;
    match native_codec::decode_for::<Services>(&Key::Record(id), bytes.value())? {
        StoredValue::Record(record) => Ok(record),
        _ => Err(fail("source role")),
    }
}
fn envelope(
    store: &Store<Services>,
    id: Uuid,
) -> Result<crate::credentials::crypto::SecretEnvelope> {
    let read = store.db.begin_read()?;
    let table = read.open_table(local::KV)?;
    let bytes = table
        .get(Key::CredentialSecret(id).encode())?
        .ok_or_else(|| fail("missing secret"))?;
    match native_codec::decode_for::<Services>(&Key::CredentialSecret(id), bytes.value())? {
        StoredValue::CredentialSecret(secret) => Ok(secret),
        _ => Err(fail("secret role")),
    }
}
fn sealed(
    store: &Store<Services>,
    crypto: &Crypto,
    target: (Uuid, Option<Uuid>, Option<Uuid>, Uuid),
    payload: &[u8],
) -> Result<WriteSecret> {
    let (credential, owner, if_version, operation_id) = target;
    let metadata = Metadata {
        label: "Conformance".into(),
        provider: Provider::Resend,
        account: "public-fixture-account".into(),
        enabled: true,
        scopes: vec!["email.send".into()],
    };
    let context = store.operation_context(store.model().identity())?;
    let (read, _, header) = store.read(store.model().identity())?;
    let scope = store.authority(&read)?;
    let ingress = IngressContext {
        model: store.model().identity().into(),
        store: header.store_id,
        tenant: scope.tenant,
        actor: scope.actor,
        credential_epoch: scope.credential_epoch,
        context: context.clone(),
        operation_id,
        credential,
        owner,
        if_version,
        metadata: metadata.clone(),
    };
    let expires_at = crate::mutation::creation_time()? + 60_000;
    let descriptor = crypto.ingress_descriptor();
    let public = URL_SAFE_NO_PAD
        .decode(&descriptor.public_key)
        .map_err(|_| fail("fixture public key"))?;
    type K = X25519HkdfSha256;
    let public =
        <K as Kem>::PublicKey::from_bytes(&public).map_err(|_| fail("fixture public key"))?;
    let (enc, mut sender) =
        hpke::setup_sender::<AesGcm256, HkdfSha256, K>(&hpke::OpModeS::Base, &public, INGRESS_INFO)
            .map_err(|_| fail("fixture HPKE sender"))?;
    let ciphertext = sender
        .seal(payload, &ingress_aad(&ingress, expires_at)?)
        .map_err(|_| fail("fixture HPKE seal"))?;
    Ok(WriteSecret {
        model: store.model().identity().into(),
        context,
        operation_id,
        id: credential,
        if_version,
        owner,
        metadata,
        sealed_secret: IngressEnvelope {
            format: INGRESS_FORMAT.into(),
            key_id: descriptor.key_id,
            enc: URL_SAFE_NO_PAD.encode(enc.to_bytes()),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            expires_at,
        },
    })
}
fn receipt(store: &Store<Services>, request: &WriteSecret, present: bool) -> Result<()> {
    let read = store.db.begin_read()?;
    require(
        read.open_table(local::RECEIPTS)?
            .get(store.receipt_key(request.operation_id))?
            .is_some()
            == present,
        "original receipt presence differs",
    )
}
fn value(
    store: &Store<Services>,
    crypto: &Crypto,
    id: Uuid,
    expected: &[u8],
    revision: u64,
    incarnation: Uuid,
) -> Result<()> {
    let record = record(store, id)?;
    let state = record
        .derived
        .as_ref()
        .ok_or_else(|| fail("missing credential derived"))?;
    require(
        state.secret_revision == Some(revision)
            && state.use_epoch == 0
            && state.incarnation == incarnation,
        "source secret state differs from independent lifecycle oracle",
    )?;
    let secret = crypto.open_secret(
        &envelope(store, id)?,
        &SecretContext {
            tenant: record.tenant,
            credential: id,
            secret_revision: revision,
            provider: record.input.provider,
            account: record.input.account.clone(),
        },
    )?;
    require(
        secret.as_bytes() == expected,
        "decrypted fixture differs from literal expected key",
    )
}
fn clean_traces(captures: &Captures) -> Result<()> {
    for trace in &capture(captures)?.traces {
        require(
            trace.scanned_tables.is_empty(),
            "credential mutation scanned inventory",
        )?;
        require(
            trace
                .reads
                .iter()
                .chain(&trace.writes)
                .all(|(table, key)| table != local::KV.name() || key.first() != Some(&13)),
            "credential mutation accessed population key",
        )?;
    }
    Ok(())
}

/// Each family is a fresh actual backend. Optimistic adapters overlap two native
/// transactions; serialized redb executes explicitly labeled sequential controls.
pub fn run(factory: impl Fn(&str) -> Result<Database>, concurrent: bool) -> Result<Value> {
    let crypto = fixture_crypto()?;
    let mut cases = vec![];
    let mut reports = vec![];
    for same_credential in [false, true] {
        let family = if same_credential {
            "e1-same-credential-rotation"
        } else {
            "e1-independent-credential-rotation"
        };
        let captures = Captures::default();
        let store = setup(Database::new(Recording {
            db: factory(family)?,
            captures: captures.clone(),
        }))?;
        let left = store.session(id(3), 0)?;
        let right = store.session(id(if same_credential { 3 } else { 4 }), 0)?;
        let first_seed = sealed(&left, &crypto, (id(100), None, None, id(1001)), ALPHA)?;
        left.write_secret(&crypto, &first_seed)?;
        if !same_credential {
            let seed = sealed(&right, &crypto, (id(200), None, None, id(1002)), ALPHA)?;
            right.write_secret(&crypto, &seed)?;
        }
        let original_left = record(&store, id(100))?;
        let target = if same_credential { id(100) } else { id(200) };
        let original_right = record(&store, target)?;
        let first_op = operation(&left, 10001, None)?;
        let second_op = operation(&right, 20001, Some(&left.receipt_key(first_op)))?;
        let first = sealed(
            &left,
            &crypto,
            (id(100), None, Some(original_left.version), first_op),
            BETA,
        )?;
        let second = sealed(
            &right,
            &crypto,
            (target, None, Some(original_right.version), second_op),
            GAMMA,
        )?;
        capture(&captures)?.traces.clear();
        label(&captures, "credential-original-first")?;
        let mut barriers = 0;
        let mut winner = None;
        if concurrent {
            let result = left.write_secret_controlled(
                &crypto,
                &first,
                None,
                &mut || {
                    barriers += 1;
                    label(&captures, "credential-original-second")?;
                    right.write_secret(&crypto, &second)?;
                    winner = Some(store.observe_for_verification()?);
                    Ok(())
                },
                false,
            );
            if same_credential {
                require(
                    result.is_err_and(|error| error.code == "transaction_conflict"),
                    "same credential rotations did not conflict",
                )?;
                require(
                    winner.as_ref() == Some(&store.observe_for_verification()?),
                    "rotation loser changed winner image",
                )?;
            } else {
                result?;
            }
            require(barriers == 1, "rotation competitor count")?;
        } else if same_credential {
            label(&captures, "credential-second-sequential-winner")?;
            right.write_secret(&crypto, &second)?;
            let winner = store.observe_for_verification()?;
            label(&captures, "credential-original-first-stale-cas")?;
            require(
                left.write_secret(&crypto, &first)
                    .is_err_and(|error| error.code == "stale_version"),
                "sequential original CAS unexpectedly survived rotation",
            )?;
            require(
                store.observe_for_verification()? == winner,
                "stale sequential CAS changed winner",
            )?;
        } else {
            left.write_secret(&crypto, &first)?;
            label(&captures, "credential-original-second-sequential")?;
            right.write_secret(&crypto, &second)?;
        }
        let traces = capture(&captures)?.traces.clone();
        require(traces.len() == 2, "rotation original attempt inventory")?;
        clean_traces(&captures)?;
        let shared: Vec<_> = traces[0]
            .writes
            .intersection(&traces[1].writes)
            .map(|(table, key)| json!({"table":table,"key":native_codec::hex(key)}))
            .collect();
        if !same_credential {
            require(
                shared.is_empty()
                    && traces[0].reads.is_disjoint(&traces[1].writes)
                    && traces[1].reads.is_disjoint(&traces[0].writes),
                "independent owner credentials share protected write dependencies",
            )?;
        }
        require(
            traces.iter().all(|trace| {
                trace.writes.iter().all(|(table, key)| {
                    table != local::KV.name() || !matches!(key.first(), Some(15 | 16))
                })
            }),
            "secret rotation rewrote unchanged access memberships",
        )?;
        receipt(&left, &first, !same_credential)?;
        receipt(&right, &second, true)?;
        if !same_credential {
            value(
                &store,
                &crypto,
                id(100),
                b"public-conformance-beta",
                2,
                original_left
                    .derived
                    .as_ref()
                    .ok_or_else(|| fail("source state"))?
                    .incarnation,
            )?;
        }
        value(
            &store,
            &crypto,
            target,
            b"public-conformance-gamma",
            2,
            original_right
                .derived
                .as_ref()
                .ok_or_else(|| fail("source state"))?
                .incarnation,
        )?;
        store.check_integrity()?;
        let accepted = store.observe_for_verification()?;
        reports.push(json!({"case":family,"concurrent":concurrent,"automatic_retries":false,"barriers":barriers,"shared_writes":shared,"attempts":traces.iter().map(trace_value).collect::<Vec<_>>(),"source_secret_revisions":2,"source_incarnation_preserved":true,"access_membership_writes":0}));
        cases.push(family);
        drop((left, right, store));
        let reopened =
            Store::<Services>::open_backend(factory(family)?, Arc::new(Prepared::load()?))?;
        require(
            reopened.observe_for_verification()? == accepted,
            "credential reopen differs",
        )?;
        reopened.verify_credential_custody(&crypto)?;
    }
    for (family, change) in [
        ("e1-credential-caller-epoch", 0),
        ("e1-credential-update-grant", 1),
        ("e1-credential-owner-scope", 2),
        ("e1-credential-caller-inactive", 3),
    ] {
        let captures = Captures::default();
        let store = setup(Database::new(Recording {
            db: factory(family)?,
            captures: captures.clone(),
        }))?;
        let caller = store.session(id(3), 0)?;
        let seed = sealed(
            &caller,
            &crypto,
            (id(100), Some(id(7)), None, id(3001)),
            ALPHA,
        )?;
        caller.write_secret(&crypto, &seed)?;
        let original = record(&store, id(100))?;
        let pending = sealed(
            &caller,
            &crypto,
            (id(100), None, Some(original.version), id(4001)),
            BETA,
        )?;
        let mut revoked = graph()?;
        if change == 2 {
            revoked
                .principals
                .iter_mut()
                .find(|p| p.id == id(7))
                .ok_or_else(|| fail("owner principal"))?
                .parents = vec![id(4)];
        } else {
            let actor = revoked
                .principals
                .iter_mut()
                .find(|p| p.id == id(3))
                .ok_or_else(|| fail("caller principal"))?;
            match change {
                0 => actor.credential_epoch += 1,
                1 => {
                    actor
                        .grants
                        .contracts
                        .get_mut(&CREDENTIAL)
                        .ok_or_else(|| fail("caller grant"))?
                        .remove(&Action::Update);
                }
                _ => actor.active = false,
            }
        }
        capture(&captures)?.traces.clear();
        let mut barriers = 0;
        let mut winner = None;
        label(&captures, "credential-before-revocation")?;
        if concurrent {
            let error = caller
                .write_secret_controlled(
                    &crypto,
                    &pending,
                    None,
                    &mut || {
                        barriers += 1;
                        label(&captures, "credential-authority-winner")?;
                        replace(&store, revoked.clone())?;
                        winner = Some(store.observe_for_verification()?);
                        Ok(())
                    },
                    false,
                )
                .expect_err("protected current credential authority");
            require(
                error.code == "transaction_conflict" && barriers == 1,
                "credential revocation did not fence pending native commit",
            )?;
            require(
                winner.as_ref() == Some(&store.observe_for_verification()?),
                "revocation loser changed complete winner image",
            )?;
        } else {
            label(&captures, "credential-authority-sequential")?;
            replace(&store, revoked)?;
            let winner = store.observe_for_verification()?;
            label(&captures, "credential-rejected-current-authority")?;
            require(
                caller
                    .write_secret(&crypto, &pending)
                    .is_err_and(|error| error.code == "forbidden"),
                "revoked current authority accepted secret write",
            )?;
            require(
                store.observe_for_verification()? == winner,
                "revoked sequential write changed winner",
            )?;
        }
        receipt(&caller, &pending, false)?;
        value(
            &store,
            &crypto,
            id(100),
            b"public-conformance-alpha",
            1,
            original
                .derived
                .as_ref()
                .ok_or_else(|| fail("source state"))?
                .incarnation,
        )?;
        let traces = capture(&captures)?.traces.clone();
        require(
            traces.len() == 2,
            "authority schedule original attempt inventory",
        )?;
        store.check_integrity()?;
        let accepted = store.observe_for_verification()?;
        reports.push(json!({"case":family,"concurrent":concurrent,"automatic_retries":false,"barriers":barriers,"attempts":traces.iter().map(trace_value).collect::<Vec<_>>(),"original_receipt_absent":true,"original_secret_retained":true}));
        cases.push(family);
        drop((caller, store));
        let reopened =
            Store::<Services>::open_backend(factory(family)?, Arc::new(Prepared::load()?))?;
        require(
            reopened.observe_for_verification()? == accepted,
            "revocation reopen differs",
        )?;
        reopened.verify_credential_custody(&crypto)?;
    }
    Ok(
        json!({"status":"passed","case_count":cases.len(),"cases":cases,"concurrent_application_schedules":concurrent,"automatic_retries":false,"provider_requests":0,"schedules":reports,"limitations":["Public dummy keys and local HPKE/AEAD verify the real native encrypted-write protocol; no live provider account is contacted.","Independent credentials use separate owner/contract epochs. Same-owner metadata edits retain their documented epoch coordination.","redb revocation and stale-CAS controls are sequential; only an optimistic adapter supplies overlapping original transactions."]}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_redb_credential_controls_are_explicitly_sequential() {
        let directory =
            std::env::temp_dir().join(format!("e1-credential-adapter-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
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
        assert_eq!(result["case_count"], 6);
        assert_eq!(result["concurrent_application_schedules"], false);
        assert_eq!(result["provider_requests"], 0);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
