//! Native operator custody checks and bounded envelope rewraps. No RPC dispatch.
//! Callers stop service activity before key rotation; CAS still rejects a competing
//! metadata edit or envelope rewrite. Inspection and rewrap never authorize use.
use crate::{
    binding::Binding,
    credentials::crypto::{Crypto, SecretContext, SecretEnvelope},
    local::{
        self, CommittedValue, ReceiptKind, ReceiptResult, ReceiptValue, ReturnedValue,
        RuntimeHeader, Store,
    },
    models::services::{CREDENTIAL, Services},
    native_codec::{self, Key, StoredValue, decimal, uuid_text},
    native_slice::{Attempt, Error, ModelRecord, Result},
    storage::ReadableTable,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

const MAX_REWRAP: usize = 16;
const MAX_REWRAP_ENTRIES: usize = MAX_REWRAP + crate::effects::MAX_RETAINED as usize;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewrapEntry {
    #[serde(with = "uuid_text")]
    pub id: Uuid,
    #[serde(with = "uuid_text")]
    pub if_version: Uuid,
    #[serde(with = "decimal")]
    pub secret_revision: u64,
    pub envelope_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewrapRequest {
    pub model: String,
    pub context: String,
    #[serde(with = "uuid_text")]
    pub operation_id: Uuid,
    pub entries: Vec<RewrapEntry>,
}
fn fingerprint(envelope: &SecretEnvelope) -> Result<String> {
    Ok(native_codec::hex(&Sha256::digest(local::encode(envelope)?)))
}
fn secret_context(
    record: &ModelRecord<Services>,
    id: Uuid,
    revision: u64,
) -> Result<SecretContext> {
    let (metadata, state) = Services::credential_values(record)?;
    if revision == 0
        || state
            .secret_revision
            .is_none_or(|current| revision > current)
    {
        return Err(Error::new(
            "unavailable_reference",
            "credential secret revision unavailable",
        ));
    }
    Ok(SecretContext {
        tenant: record.tenant,
        credential: id,
        incarnation: state.incarnation,
        secret_revision: revision,
        provider: metadata.provider,
        account: metadata.account.clone(),
    })
}

fn entry_shape(entries: &[RewrapEntry]) -> Result<()> {
    if entries.is_empty()
        || entries.len() > MAX_REWRAP_ENTRIES
        || entries
            .iter()
            .map(|entry| (entry.id, entry.secret_revision))
            .collect::<BTreeSet<_>>()
            .len()
            != entries.len()
        || entries
            .iter()
            .map(|entry| entry.id)
            .collect::<BTreeSet<_>>()
            .len()
            > MAX_REWRAP
        || entries.iter().any(|entry| {
            entry.secret_revision == 0
                || entry.envelope_sha256.len() != 64
                || !entry
                    .envelope_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Err(Error::new(
            "invalid_input",
            "bounded credential rewrap entries required",
        ));
    }
    Ok(())
}
impl Store<Services> {
    /// Prepare a secret-free CAS plan for a stopped-service operator.
    pub fn credential_rewrap_plan(&self, ids: &[Uuid]) -> Result<RewrapRequest> {
        if ids.is_empty()
            || ids.len() > MAX_REWRAP
            || ids.iter().collect::<BTreeSet<_>>().len() != ids.len()
        {
            return Err(Error::new(
                "invalid_input",
                "one to sixteen unique credentials required",
            ));
        }
        let (read, _, header) = self.read(self.model().identity())?;
        let scope = self.authority(&read)?;
        if !scope.grants.admin {
            return Err(crate::access::denied());
        }
        let table = read.open_table(local::KV)?;
        let mut ws = Attempt::<_, Services>::new(
            |key: &[u8]| Ok(table.get(key)?.map(|bytes| bytes.value().to_vec())),
            local::MUTATION_WORK_LIMIT,
        );
        let pins = super::store::pinned_revisions::<Services>(
            &read.open_table(crate::effects::EXECUTIONS)?,
        )?;
        let mut entries = Vec::new();
        for &id in ids {
            let record = ws.record(id)?.ok_or_else(|| {
                Error::new("unavailable_reference", "credential source unavailable")
            })?;
            let (_, state) = Services::credential_values(&record)?;
            let current = state.secret_revision.ok_or_else(|| {
                Error::new("unavailable_reference", "credential has no current secret")
            })?;
            let mut revisions = BTreeSet::from([current]);
            revisions.extend(
                pins.keys()
                    .filter_map(|&(credential, revision)| (credential == id).then_some(revision)),
            );
            for revision in revisions {
                let context = secret_context(&record, id, revision)?;
                let Some(StoredValue::CredentialSecret(envelope)) =
                    ws.get(&Key::CredentialSecret(id, revision))?
                else {
                    return Err(local::corrupt("missing credential envelope"));
                };
                if envelope.credential != id
                    || envelope.secret_revision != revision
                    || envelope.incarnation != context.incarnation
                {
                    return Err(local::corrupt("credential envelope identity"));
                }
                entries.push(RewrapEntry {
                    id,
                    if_version: record.version,
                    secret_revision: revision,
                    envelope_sha256: fingerprint(&envelope)?,
                });
            }
        }
        entry_shape(&entries)?;
        Ok(RewrapRequest {
            model: self.model().identity().into(),
            context: crate::security::operation_context(
                &header,
                self.context,
                self.model().identity(),
            )?,
            operation_id: Uuid::new_v4(),
            entries,
        })
    }
    pub fn rewrap_credentials(&self, crypto: &Crypto, request: &RewrapRequest) -> Result<Value> {
        self.rewrap_credentials_controlled(crypto, request, None, &mut || Ok(()), false)
    }
    pub(crate) fn rewrap_credentials_controlled(
        &self,
        crypto: &Crypto,
        request: &RewrapRequest,
        abort_after: Option<usize>,
        before_commit: &mut dyn FnMut() -> Result<()>,
        lose_response: bool,
    ) -> Result<Value> {
        entry_shape(&request.entries)?;
        let request_hash = self.request_hash("credentials.rewrap", request)?;
        let write = self.begin_write()?;
        let scope = self.write_authority(&write)?;
        if !scope.grants.admin {
            return Err(crate::access::denied());
        }
        let (batch, result, disclosed) = {
            let table = write.open_table(local::KV)?;
            let mut ws = Attempt::<_, Services>::new(
                |key: &[u8]| Ok(table.get(key)?.map(|bytes| bytes.value().to_vec())),
                local::MUTATION_WORK_LIMIT,
            );
            let Some(StoredValue::Meta(meta)) = ws.get(&Key::Meta)? else {
                return Err(local::corrupt("missing model header"));
            };
            self.check_meta(&meta, &request.model)?;
            let header: RuntimeHeader = local::decode(
                write
                    .open_table(local::RUNTIME)?
                    .get(local::HEADER)?
                    .ok_or_else(|| local::corrupt("missing runtime header"))?
                    .value(),
            )?;
            local::validate_header(&header)?;
            crate::security::check_operation_context(
                &request.context,
                &header,
                self.context,
                self.model().identity(),
            )?;
            if let Some(bytes) = write
                .open_table(local::RECEIPTS)?
                .get(self.receipt_key(request.operation_id))?
            {
                let receipt: ReceiptValue<Services> = local::decode(bytes.value())?;
                self.check_receipt(&receipt, request.operation_id, &header)?;
                if receipt.kind != ReceiptKind::Records || receipt.request_hash != request_hash {
                    return Err(Error::new(
                        "operation_conflict",
                        "operation ID bound to different request",
                    ));
                }
                let result = self.disclose_result(&scope, receipt.result, &mut ws)?;
                return Ok(json!({"status":"committed","replayed":true,"result":result}));
            }
            // Validate every selected source/envelope CAS before any decryption.
            let pins = super::store::pinned_revisions::<Services>(
                &write.open_table(crate::effects::EXECUTIONS)?,
            )?;
            let secret_bytes_before = super::store::retained_secret_bytes(&mut ws, pins.values())?;
            let mut selected = Vec::new();
            for entry in &request.entries {
                let record = ws.record(entry.id)?.ok_or_else(|| {
                    Error::new("unavailable_reference", "credential source unavailable")
                })?;
                if record.version != entry.if_version {
                    return Err(Error::new(
                        "stale_version",
                        "credential rewrap source changed",
                    ));
                }
                let context = secret_context(&record, entry.id, entry.secret_revision)?;
                let (_, state) = Services::credential_values(&record)?;
                if state.secret_revision != Some(entry.secret_revision)
                    && !pins.contains_key(&(entry.id, entry.secret_revision))
                {
                    return Err(Error::new(
                        "stale_version",
                        "credential revision is no longer retained",
                    ));
                }
                let Some(StoredValue::CredentialSecret(envelope)) =
                    ws.get(&Key::CredentialSecret(entry.id, entry.secret_revision))?
                else {
                    return Err(local::corrupt("missing credential envelope"));
                };
                if record.contract != CREDENTIAL
                    || envelope.credential != entry.id
                    || envelope.secret_revision != context.secret_revision
                    || envelope.incarnation != context.incarnation
                {
                    return Err(local::corrupt("credential envelope identity"));
                }
                if record.version != entry.if_version
                    || context.secret_revision != entry.secret_revision
                    || fingerprint(&envelope)? != entry.envelope_sha256
                {
                    return Err(Error::new(
                        "stale_version",
                        "credential rewrap source or envelope changed",
                    ));
                }
                selected.push((entry.id, record, context, envelope));
            }
            let mut records = Vec::new();
            for (id, record, context, envelope) in selected {
                let rewrapped = crypto.rewrap(&envelope, &context)?;
                ws.put(
                    Key::CredentialSecret(id, context.secret_revision),
                    Some(StoredValue::CredentialSecret(rewrapped)),
                )?;
                if !records
                    .iter()
                    .any(|returned: &ReturnedValue<Services>| returned.id == id)
                {
                    records.push(ReturnedValue {
                        id,
                        record: self.project(&scope, id, Some(record)),
                    });
                }
            }
            let secret_bytes_after = super::store::retained_secret_bytes(&mut ws, pins.values())?;
            if secret_bytes_before != secret_bytes_after {
                crate::effects::refresh_retained_secret_bytes(
                    &write,
                    secret_bytes_before,
                    secret_bytes_after,
                )?;
            }
            let result = ReceiptResult::Records(CommittedValue {
                operation_id: request.operation_id,
                revision: Uuid::new_v4(),
                records,
                executions: vec![],
            });
            let disclosed = self.disclose_result(&scope, result.clone(), &mut ws)?;
            (ws.finish()?, result, disclosed)
        };
        self.publish_native(&write, &batch, abort_after)?;
        let receipt = ReceiptValue {
            slot: crate::receipts::allocate(&write, &self.receipt_key(request.operation_id))?,
            kind: ReceiptKind::Records,
            context: request.context.clone(),
            model: self.model().identity().into(),
            tenant: self.context.tenant,
            actor: self.context.actor,
            request_hash,
            result,
        };
        self.publish_receipt(&write, &receipt)?;
        if abort_after == Some(usize::MAX) {
            return Err(Error::new(
                "injected_abort",
                "adapter check after receipt write",
            ));
        }
        before_commit()?;
        write.commit()?;
        if lose_response {
            return Err(Error::new(
                "outcome_unknown",
                "original credential rewrap receipt required",
            ));
        }
        Ok(json!({"status":"committed","replayed":false,"result":disclosed}))
    }
    /// Authenticate retained current envelopes against one source snapshot. This
    /// enables no worker, provider transport, grant, or credential-use authority.
    pub fn verify_credential_custody(&self, crypto: &Crypto) -> Result<Value> {
        let (read, _, _) = self.read(self.model().identity())?;
        let scope = self.authority(&read)?;
        if !scope.grants.admin {
            return Err(crate::access::denied());
        }
        self.check_integrity()?;
        let table = read.open_table(local::KV)?;
        let mut sources = BTreeMap::new();
        let mut secrets = BTreeMap::new();
        for (position, row) in table.iter()?.enumerate() {
            if position >= crate::binding::MAX_INVENTORY_ROWS {
                return Err(Error::new(
                    "work_limit",
                    "credential custody inventory bound",
                ));
            }
            let (key, value) = row?;
            let key = Key::decode(key.value())?;
            match native_codec::decode_for::<Services>(&key, value.value())? {
                StoredValue::Record(record) => {
                    if let Key::Record(id) = key
                        && record.contract == CREDENTIAL
                    {
                        sources.insert(id, record);
                    }
                }
                StoredValue::CredentialSecret(secret) => {
                    if let Key::CredentialSecret(id, revision) = key {
                        secrets.insert((id, revision), secret);
                    }
                }
                _ => {}
            }
        }
        let mut expected = BTreeSet::new();
        for (&id, record) in &sources {
            if let Some(revision) = Services::credential_values(record)?.1.secret_revision {
                expected.insert((id, revision));
            }
        }
        let pins = super::store::pinned_revisions::<Services>(
            &read.open_table(crate::effects::EXECUTIONS)?,
        )?;
        expected.extend(pins.keys().copied());
        if expected != secrets.keys().copied().collect() {
            return Err(local::corrupt("credential custody inventory"));
        }
        for (&(id, revision), envelope) in &secrets {
            let source = sources
                .get(&id)
                .ok_or_else(|| local::corrupt("orphan credential envelope"))?;
            let context = secret_context(source, id, revision)?;
            let _secret = crypto.open_secret(envelope, &context)?;
        }
        Ok(
            json!({"status":"verified","credentials":sources.len(),"secret_envelopes":secrets.len(),"provider_requests":0,"delivery_enabled":false}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::store::test_support::*;
    use std::sync::Arc;
    #[test]
    fn accepted_jobs_retain_exact_rotations_and_operator_rewraps_every_retained_envelope() {
        use crate::{
            access::Action,
            credentials::grants::{
                AuthorizeRequest, PlatformBindings, Runtime, load_pinned_secret,
            },
            email::{EmailRequest, SendInput},
            email_operations::{Authorization, Enqueue},
            models::services::EMAIL_SEND,
        };
        let f = fixture();
        let mut access = graph();
        for principal in &mut access.principals {
            if principal.id == id(4) {
                principal.grants.contracts.insert(
                    EMAIL_SEND,
                    [Action::Read, Action::Create, Action::Update, Action::Delete].into(),
                );
            }
        }
        replace(&f.store, access);
        let caller = f.store.session(id(4), 0).unwrap();
        let runtime = Runtime::new(f.crypto.clone(), PlatformBindings::default());
        let first = sealed(
            &caller,
            &f.crypto,
            id(100),
            None,
            None,
            metadata(true),
            "retained-original-key",
        );
        caller.write_secret(&f.crypto, &first).unwrap();
        let email = EmailRequest {
            sender: "sender@example.com".into(),
            to: vec!["reader@example.net".into()],
            subject: "retention".into(),
            text: "literal fixture".into(),
        };
        let selection = crate::credentials::grants::Selection::Byoc {
            credential: id(100),
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
        // Acceptance is checked against the final transaction graph. An old
        // valid grant cannot authorize a job alongside revocation/owner transfer.
        let original_source = record(&f.store, id(100));
        for (set, owner) in [
            (json!({"enabled":false}), None),
            (json!({"scopes":[]}), None),
            (json!({}), Some(id(6))),
        ] {
            let input = SendInput {
                email: email.clone(),
                selection: selection.clone(),
                execute_at: None,
                not_after: None,
            };
            let request = Enqueue {
                model: caller.model().identity().into(),
                context: caller.operation_context(caller.model().identity()).unwrap(),
                operation_id: Uuid::new_v4(),
                commands: vec![
                    crate::native_slice::Command::Create {
                        id: id(199),
                        contract: EMAIL_SEND,
                        owner: None,
                        fields: serde_json::to_value(input).unwrap(),
                    },
                    crate::native_slice::Command::Update {
                        id: id(100),
                        if_version: original_source.version,
                        owner,
                        set: serde_json::from_value(set).unwrap(),
                        unset: vec![],
                    },
                ],
                returning: vec![],
                authorizations: vec![Authorization {
                    source: id(199),
                    grant: grant.grant.clone(),
                }],
            };
            let before = f.store.observe_for_verification().unwrap();
            let decrypts = f.crypto.decrypt_counts();
            assert_eq!(
                caller.enqueue_email(&runtime, &request).unwrap_err().code,
                "forbidden"
            );
            assert_eq!(f.store.observe_for_verification().unwrap(), before);
            assert_eq!(f.crypto.decrypt_counts(), decrypts);
        }
        let mut execution_ids = Vec::new();
        for source in [200, 201] {
            let input = SendInput {
                email: email.clone(),
                selection: selection.clone(),
                execute_at: None,
                not_after: None,
            };
            let request = Enqueue {
                model: caller.model().identity().into(),
                context: caller.operation_context(caller.model().identity()).unwrap(),
                operation_id: Uuid::new_v4(),
                commands: vec![crate::native_slice::Command::Create {
                    id: id(source),
                    contract: EMAIL_SEND,
                    owner: None,
                    fields: serde_json::to_value(input).unwrap(),
                }],
                returning: vec![],
                authorizations: vec![Authorization {
                    source: id(source),
                    grant: grant.grant.clone(),
                }],
            };
            let result = caller.enqueue_email(&runtime, &request).unwrap();
            execution_ids.push(
                result["result"]["executions"][0]["execution_id"]
                    .as_str()
                    .unwrap()
                    .parse::<Uuid>()
                    .unwrap(),
            );
        }
        let previous = record(&f.store, id(100));
        let rotation = sealed(
            &caller,
            &f.crypto,
            id(100),
            None,
            Some(previous.version),
            metadata(true),
            "rotated-current-key",
        );
        let before = f.store.observe_for_verification().unwrap();
        for abort in [1, 2, usize::MAX] {
            assert_eq!(
                caller
                    .write_secret_controlled(
                        &f.crypto,
                        &rotation,
                        Some(abort),
                        &mut || Ok(()),
                        false
                    )
                    .unwrap_err()
                    .code,
                "injected_abort"
            );
            assert_eq!(f.store.observe_for_verification().unwrap(), before);
        }
        assert_eq!(
            caller
                .write_secret_controlled(&f.crypto, &rotation, None, &mut || Ok(()), true)
                .unwrap_err()
                .code,
            "outcome_unknown"
        );
        let counts = f.crypto.decrypt_counts();
        assert_eq!(
            caller.write_secret(&f.crypto, &rotation).unwrap()["replayed"],
            true
        );
        assert_eq!(f.crypto.decrypt_counts(), counts);
        let current = record(&f.store, id(100));
        assert_eq!(
            Services::credential_values(&current)
                .unwrap()
                .1
                .secret_revision,
            Some(2)
        );
        assert_eq!(
            Services::credential_values(&current).unwrap().1.incarnation,
            Services::credential_values(&previous)
                .unwrap()
                .1
                .incarnation
        );
        let retained = |store: &Store<Services>| {
            let read = store.db.begin_read().unwrap();
            read.open_table(local::KV)
                .unwrap()
                .iter()
                .unwrap()
                .filter_map(|row| {
                    let (key, _) = row.unwrap();
                    match Key::decode(key.value()).unwrap() {
                        Key::CredentialSecret(credential, revision) => Some((credential, revision)),
                        _ => None,
                    }
                })
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(
            retained(&f.store),
            BTreeSet::from([(id(100), 1), (id(100), 2)])
        );
        let read = f.store.db.begin_read().unwrap();
        let table = read.open_table(crate::effects::EXECUTIONS).unwrap();
        let pins = execution_ids
            .iter()
            .map(|execution| {
                let bytes = table.get(execution.as_bytes()).unwrap().unwrap();
                let row: crate::effects::Execution<Services> =
                    local::decode(bytes.value()).unwrap();
                row.email_binding.unwrap()
            })
            .collect::<Vec<_>>();
        for pin in &pins {
            assert_eq!(pin.secret_revision(), 1);
            assert_eq!(
                load_pinned_secret::<Services>(&read, pin, id(1), &f.crypto)
                    .unwrap()
                    .as_bytes(),
                b"retained-original-key"
            );
        }
        drop(table);
        drop(read);
        let before_delete = f.store.observe_for_verification().unwrap();
        let delete = mutation(
            &caller,
            json!([{"op":"delete","id":id(100),"if_version":current.version}]),
        );
        assert_eq!(caller.mutate(&delete).unwrap_err().code, "invariant");
        assert_eq!(f.store.observe_for_verification().unwrap(), before_delete);
        let plan = f.store.credential_rewrap_plan(&[id(100)]).unwrap();
        assert_eq!(
            plan.entries
                .iter()
                .map(|entry| entry.secret_revision)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([1, 2])
        );
        let rotated = Crypto::test_rotated(1, 20);
        f.store.rewrap_credentials(&rotated, &plan).unwrap();
        assert_eq!(record(&f.store, id(100)), current);
        let replacement = Crypto::test_with_seed(20);
        assert_eq!(
            f.store.verify_credential_custody(&replacement).unwrap()["secret_envelopes"],
            2
        );
        assert!(f.store.verify_credential_custody(&f.crypto).is_err());
        let read = f.store.db.begin_read().unwrap();
        for pin in &pins {
            assert_eq!(
                load_pinned_secret::<Services>(&read, pin, id(1), &replacement)
                    .unwrap()
                    .as_bytes(),
                b"retained-original-key"
            );
        }
        drop(read);
        let next = sealed(
            &caller,
            &rotated,
            id(100),
            None,
            Some(current.version),
            metadata(true),
            "third-current-key",
        );
        caller.write_secret(&rotated, &next).unwrap();
        assert_eq!(
            retained(&f.store),
            BTreeSet::from([(id(100), 1), (id(100), 3)])
        );
        assert_eq!(
            f.store.verify_credential_custody(&replacement).unwrap()["secret_envelopes"],
            2
        );
        f.store.check_integrity().unwrap();
    }
    #[test]
    fn rewrap_preserves_source_epochs_and_recovers_original_receipt_after_unknown_ack() {
        let f = fixture();
        let caller = f.store.session(id(4), 0).unwrap();
        for number in [100, 101] {
            let request = sealed(
                &caller,
                &f.crypto,
                id(number),
                None,
                None,
                metadata(true),
                "rewrap-fixture-secret",
            );
            caller.write_secret(&f.crypto, &request).unwrap();
        }
        let before = f.store.observe_for_verification().unwrap();
        let original = record(&f.store, id(100));
        let original_envelope = envelope(&f.store, id(100)).unwrap();
        let plan = f.store.credential_rewrap_plan(&[id(100), id(101)]).unwrap();
        let keys = Crypto::test_rotated(1, 20);
        for abort in [1, 2, usize::MAX] {
            assert_eq!(
                f.store
                    .rewrap_credentials_controlled(&keys, &plan, Some(abort), &mut || Ok(()), false)
                    .unwrap_err()
                    .code,
                "injected_abort"
            );
            assert_eq!(f.store.observe_for_verification().unwrap(), before);
        }
        assert_eq!(
            f.store
                .rewrap_credentials_controlled(&keys, &plan, None, &mut || Ok(()), true)
                .unwrap_err()
                .code,
            "outcome_unknown"
        );
        let after = f.store.observe_for_verification().unwrap();
        assert_eq!(record(&f.store, id(100)), original);
        for table in ["public_records", "owner_records", "query_epochs"] {
            assert_eq!(after["tables"][table], before["tables"][table]);
        }
        let current = envelope(&f.store, id(100)).unwrap();
        assert_eq!(current.secret_revision, original_envelope.secret_revision);
        assert_ne!(current.key_id, original_envelope.key_id);
        assert_ne!(current.nonce, original_envelope.nonce);
        let replacement = Crypto::test_with_seed(40);
        assert_eq!(
            f.store.rewrap_credentials(&replacement, &plan).unwrap()["replayed"],
            true
        );
        assert_eq!(replacement.decrypt_counts(), (0, 0));
        assert_eq!(f.store.observe_for_verification().unwrap(), after);
        let mut stale = plan.clone();
        stale.operation_id = Uuid::new_v4();
        let counts = keys.decrypt_counts();
        assert_eq!(
            f.store.rewrap_credentials(&keys, &stale).unwrap_err().code,
            "stale_version"
        );
        assert_eq!(keys.decrypt_counts(), counts);
        let old_keys = Crypto::test();
        assert!(f.store.verify_credential_custody(&old_keys).is_err());
        let current_keys = Crypto::test_with_seed(20);
        assert_eq!(
            f.store.verify_credential_custody(&current_keys).unwrap()["secret_envelopes"],
            2
        );
        assert_eq!(current_keys.decrypt_counts(), (0, 2));
        f.store.check_integrity().unwrap();
        let backup = f.directory.join("rewrapped.json");
        f.store.backup(&backup).unwrap();
        let restored = f.directory.join("rewrapped.redb");
        crate::lifecycle::restore(
            &backup,
            &restored,
            Arc::new(crate::model::Prepared::<Services>::load().unwrap()),
        )
        .unwrap();
        let restored =
            Store::<Services>::open(&restored, Arc::new(crate::model::Prepared::load().unwrap()))
                .unwrap();
        assert_eq!(
            restored.verify_credential_custody(&current_keys).unwrap()["status"],
            "verified"
        );
        assert!(
            !serde_json::to_string(&after)
                .unwrap()
                .contains("rewrap-fixture-secret")
        );
    }
    #[test]
    fn rewrap_checks_all_cas_before_decrypt_and_requires_native_admin_authority() {
        let f = fixture();
        let caller = f.store.session(id(4), 0).unwrap();
        for number in [100, 101] {
            let request = sealed(
                &caller,
                &f.crypto,
                id(number),
                None,
                None,
                metadata(true),
                "cas-fixture-secret",
            );
            caller.write_secret(&f.crypto, &request).unwrap();
        }
        let keys = Crypto::test_rotated(1, 20);
        let plan = f.store.credential_rewrap_plan(&[id(100), id(101)]).unwrap();
        assert_eq!(
            caller.credential_rewrap_plan(&[id(100)]).unwrap_err().code,
            "forbidden"
        );
        assert_eq!(
            caller.rewrap_credentials(&keys, &plan).unwrap_err().code,
            "forbidden"
        );
        assert_eq!(
            caller.verify_credential_custody(&keys).unwrap_err().code,
            "forbidden"
        );
        assert_eq!(keys.decrypt_counts(), (0, 0));
        caller
            .mutate(&edit(&caller, id(101), None, json!({"label":"changed"})))
            .unwrap();
        let before = f.store.observe_for_verification().unwrap();
        assert_eq!(
            f.store.rewrap_credentials(&keys, &plan).unwrap_err().code,
            "stale_version"
        );
        assert_eq!(keys.decrypt_counts(), (0, 0));
        assert_eq!(f.store.observe_for_verification().unwrap(), before);
    }
    #[test]
    fn custody_authenticates_source_aad_without_modifying_or_enabling_delivery() {
        let f = fixture();
        let caller = f.store.session(id(4), 0).unwrap();
        let request = sealed(
            &caller,
            &f.crypto,
            id(100),
            None,
            None,
            metadata(true),
            "custody-fixture-secret",
        );
        caller.write_secret(&f.crypto, &request).unwrap();
        let mut changed = record(&f.store, id(100));
        changed.input.credential_mut().account = "another-account".into();
        let key = Key::Record(id(100));
        let bytes =
            native_codec::encode_for::<Services>(&key, &StoredValue::Record(changed)).unwrap();
        let write = f.store.db.begin_write().unwrap();
        write
            .open_table(local::KV)
            .unwrap()
            .insert(key.encode().as_slice(), bytes.as_slice())
            .unwrap();
        write.commit().unwrap();
        // Structural metadata inspection cannot authenticate encrypted AAD.
        f.store.check_integrity().unwrap();
        let before = f.store.observe_for_verification().unwrap();
        assert_eq!(
            f.store
                .verify_credential_custody(&f.crypto)
                .unwrap_err()
                .code,
            "credential_crypto"
        );
        assert_eq!(f.store.observe_for_verification().unwrap(), before);
    }
}
