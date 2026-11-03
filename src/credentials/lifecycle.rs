//! Native operator custody checks and bounded envelope rewraps. No RPC dispatch.
//! Callers stop service activity before key rotation; CAS still rejects a competing
//! metadata edit or envelope rewrite. Inspection and rewrap never authorize use.
use crate::{
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
fn secret_context(record: &ModelRecord<Services>, id: Uuid) -> Result<SecretContext> {
    let revision = record
        .derived
        .as_ref()
        .and_then(|state| state.secret_revision)
        .ok_or_else(|| Error::new("unavailable_reference", "credential has no current secret"))?;
    Ok(SecretContext {
        tenant: record.tenant,
        credential: id,
        secret_revision: revision,
        provider: record.input.provider,
        account: record.input.account.clone(),
    })
}
fn entry_shape(entries: &[RewrapEntry]) -> Result<()> {
    if entries.is_empty()
        || entries.len() > MAX_REWRAP
        || entries
            .iter()
            .map(|entry| entry.id)
            .collect::<BTreeSet<_>>()
            .len()
            != entries.len()
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
        let mut entries = Vec::new();
        for &id in ids {
            let record = ws.record(id)?.ok_or_else(|| {
                Error::new("unavailable_reference", "credential source unavailable")
            })?;
            let context = secret_context(&record, id)?;
            let Some(StoredValue::CredentialSecret(envelope)) =
                ws.get(&Key::CredentialSecret(id))?
            else {
                return Err(local::corrupt("missing credential envelope"));
            };
            if record.contract != CREDENTIAL
                || envelope.credential != id
                || envelope.secret_revision != context.secret_revision
            {
                return Err(local::corrupt("credential envelope identity"));
            }
            entries.push(RewrapEntry {
                id,
                if_version: record.version,
                secret_revision: context.secret_revision,
                envelope_sha256: fingerprint(&envelope)?,
            });
        }
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
            let mut selected = Vec::new();
            for entry in &request.entries {
                let record = ws.record(entry.id)?.ok_or_else(|| {
                    Error::new("unavailable_reference", "credential source unavailable")
                })?;
                let context = secret_context(&record, entry.id)?;
                let Some(StoredValue::CredentialSecret(envelope)) =
                    ws.get(&Key::CredentialSecret(entry.id))?
                else {
                    return Err(local::corrupt("missing credential envelope"));
                };
                if record.contract != CREDENTIAL
                    || envelope.credential != entry.id
                    || envelope.secret_revision != context.secret_revision
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
                    Key::CredentialSecret(id),
                    Some(StoredValue::CredentialSecret(rewrapped)),
                )?;
                records.push(ReturnedValue {
                    id,
                    record: self.project(&scope, id, Some(record)),
                });
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
                    if let Key::Record(id) = key {
                        sources.insert(id, record);
                    }
                }
                StoredValue::CredentialSecret(secret) => {
                    if let Key::CredentialSecret(id) = key {
                        secrets.insert(id, secret);
                    }
                }
                _ => {}
            }
        }
        let expected: BTreeSet<_> = sources
            .iter()
            .filter(|(_, record)| {
                record
                    .derived
                    .as_ref()
                    .is_some_and(|state| state.has_secret)
            })
            .map(|(&id, _)| id)
            .collect();
        if expected != secrets.keys().copied().collect() {
            return Err(local::corrupt("credential custody inventory"));
        }
        for (id, envelope) in &secrets {
            let source = sources
                .get(id)
                .ok_or_else(|| local::corrupt("orphan credential envelope"))?;
            let context = secret_context(source, *id)?;
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
        changed.input.account = "another-account".into();
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
