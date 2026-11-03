//! Typed encrypted ingress composes private staging into the ordinary mutation.
use crate::{
    access::{Action, Scope},
    binding::Binding,
    credentials::crypto::{Crypto, IngressContext, IngressEnvelope, Metadata, SecretContext},
    local::{Mutation, RuntimeHeader, Store},
    model::Prepared,
    models::services::{CREDENTIAL, Services},
    native_codec::{Key, StoredValue, optional_uuid_text, uuid_text},
    native_slice::{Attempt, Command, Context, Error, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteSecret {
    pub model: String,
    pub context: String,
    #[serde(with = "uuid_text")]
    pub operation_id: Uuid,
    #[serde(with = "uuid_text")]
    pub id: Uuid,
    #[serde(with = "optional_uuid_text")]
    pub if_version: Option<Uuid>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "optional_uuid_text::serialize",
        deserialize_with = "optional_uuid_text::deserialize_present"
    )]
    pub owner: Option<Uuid>,
    pub metadata: Metadata,
    pub sealed_secret: IngressEnvelope,
}
#[derive(Clone, Copy)]
pub(crate) struct SecretStage<'a> {
    pub crypto: &'a Crypto,
    pub request: &'a WriteSecret,
}

pub(crate) fn stage_secret<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    context: Context,
    scope: &Scope,
    header: &RuntimeHeader,
    stage: SecretStage<'_>,
) -> Result<()> {
    if !B::credential_enabled() {
        return Err(Error::new("unsupported_query", "model has no credentials"));
    }
    let request = stage.request;
    model.public_contract(CREDENTIAL)?;
    let old = ws.record(request.id)?;
    let action = if request.if_version.is_some() {
        Action::Update
    } else {
        Action::Create
    };
    let owner = request
        .owner
        .or_else(|| old.as_ref().map(|record| record.owner))
        .unwrap_or(context.actor);
    // Every current authority check precedes CAS and any private payload access.
    if !scope.active
        || scope.tenant != context.tenant
        || !scope.grants.allows(CREDENTIAL, action)
        || !scope.accessible.contains(&owner)
        || old
            .as_ref()
            .is_some_and(|record| !scope.can_write(record, action))
    {
        return Err(crate::access::denied());
    }
    if old
        .as_ref()
        .is_some_and(|record| record.contract != CREDENTIAL)
    {
        return Err(Error::new("invalid_input", "credential target contract"));
    }
    match (request.if_version, old.as_ref()) {
        (None, Some(_)) => return Err(Error::new("already_exists", "source UUID exists")),
        (Some(_), None) => return Err(Error::new("unavailable_reference", "source unavailable")),
        (Some(version), Some(record)) if version != record.version => {
            return Err(Error::new("stale_version", "source version"));
        }
        _ => {}
    }
    request.metadata.validate()?;
    let old_state = if let Some(record) = &old {
        let (metadata, state) = B::credential_values(record)?;
        if metadata.provider != request.metadata.provider
            || metadata.account != request.metadata.account
        {
            return Err(Error::new(
                "invalid_input",
                "credential provider and account are immutable",
            ));
        }
        Some(state.clone())
    } else {
        None
    };
    let prior_revision = old_state.as_ref().and_then(|state| state.secret_revision);
    if let Some(revision) = prior_revision {
        match ws.get(&Key::CredentialSecret(request.id, revision))? {
            Some(StoredValue::CredentialSecret(envelope))
                if envelope.credential == request.id
                    && envelope.secret_revision == revision
                    && old_state
                        .as_ref()
                        .is_some_and(|state| envelope.incarnation == state.incarnation) =>
            {
                envelope.validate()?
            }
            _ => return Err(Error::new("corrupt_state", "credential private inventory")),
        }
    }
    let secret_revision = prior_revision
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| Error::new("revision_exhausted", "credential secret revision"))?;
    if ws
        .get(&Key::CredentialSecret(request.id, secret_revision))?
        .is_some()
    {
        return Err(Error::new(
            "corrupt_state",
            "next credential revision already exists",
        ));
    }
    let incarnation = old_state
        .as_ref()
        .map_or_else(Uuid::new_v4, |state| state.incarnation);
    let ingress = IngressContext {
        model: model.identity().into(),
        store: header.store_id,
        tenant: context.tenant,
        actor: context.actor,
        credential_epoch: scope.credential_epoch,
        context: request.context.clone(),
        operation_id: request.operation_id,
        credential: request.id,
        owner: request.owner,
        if_version: request.if_version,
        metadata: request.metadata.clone(),
    };
    let secret = stage.crypto.open_ingress(
        &request.sealed_secret,
        &ingress,
        crate::mutation::creation_time()?,
    )?;
    let envelope = stage.crypto.seal_secret(
        &secret,
        &SecretContext {
            tenant: context.tenant,
            credential: request.id,
            incarnation,
            secret_revision,
            provider: request.metadata.provider,
            account: request.metadata.account.clone(),
        },
    )?;
    ws.put(
        Key::CredentialSecret(request.id, secret_revision),
        Some(StoredValue::CredentialSecret(envelope)),
    )
}

/// Derive retention from the protected execution inventory, including terminal
/// executions until their durable rows are actually swept. There is no pin cache.
pub(crate) fn pinned_revisions<B: Binding>(
    table: &crate::storage::Table<&'static [u8], &'static [u8]>,
) -> Result<std::collections::BTreeMap<(Uuid, u64), crate::credentials::grants::AcceptedBinding>> {
    let mut pins = std::collections::BTreeMap::new();
    for (position, row) in table.iter()?.enumerate() {
        if position >= crate::effects::MAX_RETAINED as usize {
            return Err(Error::new(
                "work_limit",
                "credential execution retention bound",
            ));
        }
        let (key, bytes) = row?;
        let execution: crate::effects::Execution<B> = crate::local::decode(bytes.value())?;
        if key.value() != execution.id.as_bytes() {
            return Err(Error::new("corrupt_state", "credential execution identity"));
        }
        if let Some(binding) = execution.email_binding {
            binding.validate()?;
            let pair = (binding.credential(), binding.secret_revision());
            if let Some(previous) = pins.insert(pair, binding.clone())
                && (previous.incarnation() != binding.incarnation()
                    || previous.provider() != binding.provider()
                    || previous.account() != binding.account())
            {
                return Err(Error::new(
                    "corrupt_state",
                    "inconsistent credential retention identity",
                ));
            }
        }
    }
    Ok(pins)
}

/// The effect budget counts shared encrypted revisions once, including pins to
/// older rotations. This uses actual staged encoded bytes rather than estimates.
pub(crate) fn retained_secret_bytes<'a, L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    bindings: impl IntoIterator<Item = &'a crate::credentials::grants::AcceptedBinding>,
) -> Result<u64> {
    let mut keys = std::collections::BTreeSet::new();
    let mut total = 0u64;
    for binding in bindings {
        binding.validate()?;
        let key = Key::CredentialSecret(binding.credential(), binding.secret_revision());
        if !keys.insert(key.clone()) {
            continue;
        }
        let value = ws
            .get(&key)?
            .ok_or_else(|| Error::new("corrupt_state", "retained credential envelope missing"))?;
        if !matches!(&value,StoredValue::CredentialSecret(envelope) if envelope.incarnation == binding.incarnation())
        {
            return Err(Error::new(
                "corrupt_state",
                "retained credential envelope identity",
            ));
        }
        let bytes = crate::native_codec::encode_for::<B>(&key, &value)?;
        total = total
            .checked_add((key.encode().len() + bytes.len()) as u64)
            .ok_or_else(|| Error::new("work_limit", "credential retained bytes overflow"))?;
    }
    Ok(total)
}

/// Publish only source-current and execution-pinned envelopes. Protected range
/// reads fence concurrent acceptance and deletion; all removals share source commit.
pub(crate) fn retain_revisions<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    write: &crate::storage::WriteTransaction,
    ws: &mut Attempt<L, B>,
    changed_ids: &[Uuid],
) -> Result<()> {
    if !B::credential_enabled() || changed_ids.is_empty() {
        return Ok(());
    }
    let mut credentials = std::collections::BTreeSet::new();
    for &id in changed_ids {
        let current = ws.record(id)?;
        let original = ws.original(&Key::Record(id))?;
        if current
            .as_ref()
            .is_some_and(|record| record.contract == CREDENTIAL)
            || matches!(original,Some(StoredValue::Record(record)) if record.contract == CREDENTIAL)
        {
            credentials.insert(id);
        }
    }
    if credentials.is_empty() {
        return Ok(());
    }
    let pins = pinned_revisions::<B>(&write.open_table(crate::effects::EXECUTIONS)?)?;
    let table = write.open_table(crate::local::KV)?;
    for id in credentials {
        let record = ws.record(id)?;
        let mut keep = std::collections::BTreeSet::new();
        for (&(credential, revision), binding) in &pins {
            if credential != id {
                continue;
            }
            let record = record
                .as_ref()
                .ok_or_else(|| Error::new("invariant", "credential is retained by an execution"))?;
            let (metadata, state) = B::credential_values(record)?;
            if state.incarnation != binding.incarnation()
                || metadata.provider != binding.provider()
                || metadata.account != binding.account()
            {
                return Err(Error::new("corrupt_state", "retained credential identity"));
            }
            keep.insert(revision);
        }
        if let Some(record) = &record {
            let (_, state) = B::credential_values(record)?;
            if let Some(revision) = state.secret_revision {
                keep.insert(revision);
            }
            for &revision in &keep {
                let key = Key::CredentialSecret(id, revision);
                match ws.get(&key)? {
                    Some(StoredValue::CredentialSecret(envelope))
                        if envelope.credential == id
                            && envelope.incarnation == state.incarnation
                            && envelope.secret_revision == revision
                            && state
                                .secret_revision
                                .is_some_and(|current| revision <= current) =>
                    {
                        envelope.validate()?
                    }
                    _ => {
                        return Err(Error::new(
                            "corrupt_state",
                            "retained credential envelope missing",
                        ));
                    }
                }
            }
        }
        let lower = Key::CredentialSecret(id, 0).encode();
        let upper = Key::CredentialSecret(id, u64::MAX).encode();
        for (position, row) in table
            .range(lower.as_slice()..=upper.as_slice())?
            .enumerate()
        {
            if position > crate::effects::MAX_RETAINED as usize {
                return Err(Error::new(
                    "work_limit",
                    "credential revision retention bound",
                ));
            }
            let (key, _) = row?;
            let key = Key::decode(key.value())?;
            let Key::CredentialSecret(_, revision) = key else {
                return Err(Error::new("corrupt_state", "credential revision range"));
            };
            if !keep.contains(&revision) {
                ws.put(key, None)?;
            }
        }
    }
    Ok(())
}

impl Store<Services> {
    pub fn write_secret(&self, runtime: &Crypto, request: &WriteSecret) -> Result<Value> {
        self.write_secret_controlled(runtime, request, None, &mut || Ok(()), false)
    }
    pub(crate) fn write_secret_controlled(
        &self,
        runtime: &Crypto,
        request: &WriteSecret,
        abort_after: Option<usize>,
        before_commit: &mut dyn FnMut() -> Result<()>,
        lose_response: bool,
    ) -> Result<Value> {
        let command=match request.if_version {
            None=>Command::Create{id:request.id,contract:CREDENTIAL,owner:request.owner,fields:serde_json::to_value(&request.metadata).map_err(crate::local::storage)?},
            Some(if_version)=>Command::Update{id:request.id,if_version,owner:request.owner,
                set:serde_json::from_value(json!({"label":request.metadata.label,"enabled":request.metadata.enabled,"scopes":request.metadata.scopes})).map_err(crate::local::storage)?,unset:vec![]},
        };
        let mutation = Mutation {
            model: request.model.clone(),
            context: request.context.clone(),
            operation_id: request.operation_id,
            commands: vec![command],
            returning: vec![request.id],
        };
        self.mutate_staged(
            &mutation,
            &mut || Ok(Uuid::new_v4()),
            abort_after,
            before_commit,
            lose_response,
            Some(SecretStage {
                crypto: runtime,
                request,
            }),
        )
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::{
        access::{Grants, Graph, Principal, PrincipalKind},
        credentials::crypto::{ApiKeySecret, Provider, SecretEnvelope},
        native_slice::ModelRecord,
        security::ReplaceGraph,
        storage::ReadableTable,
    };
    use std::{collections::BTreeSet, path::PathBuf, sync::Arc};
    pub fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }
    pub struct Fixture {
        pub directory: PathBuf,
        pub store: Store<Services>,
        pub crypto: Arc<Crypto>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
    pub fn graph() -> Graph {
        let mut graph = Graph::bootstrap(Context {
            tenant: id(1),
            actor: id(2),
        })
        .unwrap()
        .graph;
        let all = BTreeSet::from([
            Action::Read,
            Action::Create,
            Action::Update,
            Action::Delete,
            Action::Use,
        ]);
        graph.principals[1]
            .grants
            .contracts
            .insert(CREDENTIAL, all.clone());
        for (number, parent, kind) in [
            (6, 2, PrincipalKind::Group),
            (4, 6, PrincipalKind::User),
            (5, 6, PrincipalKind::User),
            (7, 4, PrincipalKind::User),
            (8, 1, PrincipalKind::User),
            (9, 1, PrincipalKind::User),
        ] {
            let mut actions = all.clone();
            if number == 8 {
                actions.remove(&Action::Use);
            }
            if number == 9 {
                actions.remove(&Action::Read);
            }
            graph.principals.push(Principal {
                id: id(number),
                kind,
                parents: vec![id(parent)],
                active: true,
                credential_epoch: 0,
                grants: Grants {
                    admin: false,
                    contracts: [(CREDENTIAL, actions)].into(),
                },
            });
        }
        graph
    }
    pub fn replace(store: &Store<Services>, graph: Graph) {
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
    pub fn fixture() -> Fixture {
        let directory = std::env::temp_dir().join(format!("credential-store-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let store = Store::create_secured(
            directory.join("store.redb"),
            Arc::new(Prepared::<Services>::load().unwrap()),
            Context {
                tenant: id(1),
                actor: id(2),
            },
        )
        .unwrap();
        replace(&store, graph());
        Fixture {
            directory,
            store,
            crypto: Arc::new(Crypto::test()),
        }
    }
    pub fn metadata(enabled: bool) -> Metadata {
        Metadata {
            label: "Mail".into(),
            provider: Provider::Resend,
            account: "test-mail".into(),
            enabled,
            scopes: vec!["email.send".into()],
        }
    }
    pub fn record(store: &Store<Services>, id: Uuid) -> crate::native_slice::ModelRecord<Services> {
        let read = store.db.begin_read().unwrap();
        let table = read.open_table(crate::local::KV).unwrap();
        let bytes = table.get(Key::Record(id).encode()).unwrap().unwrap();
        match crate::native_codec::decode_for::<Services>(&Key::Record(id), bytes.value()).unwrap()
        {
            StoredValue::Record(record) => record,
            _ => panic!("record role"),
        }
    }
    pub fn envelope(store: &Store<Services>, id: Uuid) -> Option<SecretEnvelope> {
        let read = store.db.begin_read().unwrap();
        let table = read.open_table(crate::local::KV).unwrap();
        let source_bytes = table.get(Key::Record(id).encode()).unwrap()?;
        let StoredValue::Record(source) =
            crate::native_codec::decode_for::<Services>(&Key::Record(id), source_bytes.value())
                .unwrap()
        else {
            panic!("source role");
        };
        let revision = source.derived.as_ref()?.secret_revision?;
        table
            .get(Key::CredentialSecret(id, revision).encode())
            .unwrap()
            .map(|bytes| {
                match crate::native_codec::decode_for::<Services>(
                    &Key::CredentialSecret(id, revision),
                    bytes.value(),
                )
                .unwrap()
                {
                    StoredValue::CredentialSecret(secret) => secret,
                    _ => panic!("private row role"),
                }
            })
    }
    pub fn sealed(
        store: &Store<Services>,
        crypto: &Crypto,
        id: Uuid,
        owner: Option<Uuid>,
        if_version: Option<Uuid>,
        metadata: Metadata,
        key: &str,
    ) -> WriteSecret {
        let context = store.operation_context(store.model().identity()).unwrap();
        let (read, _, header) = store.read(store.model().identity()).unwrap();
        let scope = store.authority(&read).unwrap();
        let operation_id = Uuid::new_v4();
        let ingress = IngressContext {
            model: store.model().identity().into(),
            store: header.store_id,
            tenant: scope.tenant,
            actor: scope.actor,
            credential_epoch: scope.credential_epoch,
            context: context.clone(),
            operation_id,
            credential: id,
            owner,
            if_version,
            metadata: metadata.clone(),
        };
        // Only test keys enter a generic JSON builder in this fixture. Production
        // secret decoding stays inside the private zeroizing crypto module.
        let secret =
            ApiKeySecret::from_bytes(serde_json::to_vec(&json!({"api_key":key})).unwrap()).unwrap();
        let sealed_secret = crypto
            .seal_ingress_for_test(
                &secret,
                &ingress,
                crate::mutation::creation_time().unwrap() + 60_000,
            )
            .unwrap();
        WriteSecret {
            model: store.model().identity().into(),
            context,
            operation_id,
            id,
            owner,
            if_version,
            metadata,
            sealed_secret,
        }
    }
    pub fn mutation(store: &Store<Services>, commands: Value) -> Mutation {
        serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":Uuid::new_v4(),"commands":commands,"returning":[]})).unwrap()
    }
    pub fn edit(
        store: &Store<Services>,
        target: Uuid,
        owner: Option<Uuid>,
        set: Value,
    ) -> Mutation {
        let previous = record(store, target);
        let mut command =
            json!({"op":"update","id":target,"if_version":previous.version,"set":set,"unset":[]});
        if let Some(owner) = owner {
            command["owner"] = json!(owner);
        }
        mutation(store, json!([command]))
    }
    pub fn secret_context(record: &ModelRecord<Services>, id: Uuid) -> SecretContext {
        SecretContext {
            tenant: record.tenant,
            credential: id,
            secret_revision: record.derived.as_ref().unwrap().secret_revision.unwrap(),
            incarnation: record.derived.as_ref().unwrap().incarnation,
            provider: record.input.credential().unwrap().provider,
            account: record.input.credential().unwrap().account.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::{credentials::crypto::Provider, models::services::Derived, storage::ReadableTable};
    use std::sync::Arc;

    #[test]
    fn metadata_secret_rotation_and_owner_epoch_follow_source_facts() {
        let f = fixture();
        let caller = f.store.session(id(4), 0).unwrap();
        let create = sealed(
            &caller,
            &f.crypto,
            id(100),
            None,
            None,
            metadata(true),
            "fixture-secret-alpha",
        );
        let result = caller.write_secret(&f.crypto, &create).unwrap();
        let first = record(&f.store, id(100));
        let first_envelope = envelope(&f.store, id(100)).unwrap();
        assert_eq!(
            first.derived,
            Some(Derived {
                incarnation: first_envelope.incarnation,
                has_secret: true,
                secret_revision: Some(1),
                use_epoch: 0
            })
        );
        for safe in [
            serde_json::to_string(&result).unwrap(),
            serde_json::to_string(&f.store.observe_for_verification().unwrap()).unwrap(),
            format!("{create:?}"),
        ] {
            assert!(!safe.contains("fixture-secret-alpha"));
        }
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("ciphertext")
        );
        let counts = f.crypto.decrypt_counts();
        caller
            .mutate(&edit(&caller, id(100), None, json!({"label":"Renamed"})))
            .unwrap();
        assert_eq!(
            record(&f.store, id(100))
                .derived
                .as_ref()
                .unwrap()
                .use_epoch,
            0
        );
        assert_eq!(envelope(&f.store, id(100)), Some(first_envelope.clone()));
        assert_eq!(f.crypto.decrypt_counts(), counts);
        caller
            .mutate(&edit(
                &caller,
                id(100),
                Some(id(6)),
                json!({"enabled":false,"scopes":[]}),
            ))
            .unwrap();
        let disabled = record(&f.store, id(100));
        assert_eq!(disabled.owner, id(6));
        assert_eq!(disabled.derived.as_ref().unwrap().use_epoch, 1);
        assert_eq!(disabled.created_at, first.created_at);
        assert_eq!(envelope(&f.store, id(100)), Some(first_envelope.clone()));
        caller
            .mutate(&edit(
                &caller,
                id(100),
                None,
                json!({"enabled":true,"scopes":["email.send"]}),
            ))
            .unwrap();
        let enabled = record(&f.store, id(100));
        assert_eq!(enabled.derived.as_ref().unwrap().use_epoch, 2);
        let rotate = sealed(
            &caller,
            &f.crypto,
            id(100),
            None,
            Some(enabled.version),
            enabled.input.credential().unwrap().clone(),
            "fixture-secret-beta",
        );
        caller.write_secret(&f.crypto, &rotate).unwrap();
        let rotated = record(&f.store, id(100));
        let second_envelope = envelope(&f.store, id(100)).unwrap();
        assert_eq!(
            rotated.derived,
            Some(Derived {
                incarnation: first_envelope.incarnation,
                has_secret: true,
                secret_revision: Some(2),
                use_epoch: 2
            })
        );
        assert_ne!(first_envelope.nonce, second_envelope.nonce);
        assert_eq!(
            f.crypto
                .open_secret(&second_envelope, &secret_context(&rotated, id(100)))
                .unwrap()
                .as_bytes(),
            b"fixture-secret-beta"
        );
        let before_noop = f.store.observe_for_verification().unwrap();
        caller
            .mutate(&edit(&caller, id(100), Some(id(6)), json!({})))
            .unwrap();
        assert_eq!(record(&f.store, id(100)), rotated);
        assert_eq!(
            f.store.observe_for_verification().unwrap()["tables"]["native_kv"],
            before_noop["tables"]["native_kv"]
        );
        let deletion = mutation(
            &caller,
            json!([{"op":"delete","id":id(100),"if_version":rotated.version}]),
        );
        assert_eq!(caller.mutate(&deletion).unwrap_err().code, "forbidden");
        caller
            .mutate(&edit(&caller, id(100), Some(id(4)), json!({})))
            .unwrap();
        let current = record(&f.store, id(100));
        assert_eq!(current.derived.as_ref().unwrap().use_epoch, 3);
        caller
            .mutate(&mutation(
                &caller,
                json!([{"op":"delete","id":id(100),"if_version":current.version}]),
            ))
            .unwrap();
        assert!(envelope(&f.store, id(100)).is_none());
        f.store.check_integrity().unwrap();
    }

    #[test]
    fn authorization_and_binding_failures_precede_every_decrypt() {
        let f = fixture();
        let caller = f.store.session(id(4), 0).unwrap();
        let sibling = f.store.session(id(5), 0).unwrap();
        let create = sealed(
            &caller,
            &f.crypto,
            id(100),
            None,
            None,
            metadata(true),
            "fixture-secret-alpha",
        );
        caller.write_secret(&f.crypto, &create).unwrap();
        let original = record(&f.store, id(100));
        let before = f.store.observe_for_verification().unwrap();
        let mut requests = vec![
            (
                sealed(
                    &sibling,
                    &f.crypto,
                    id(100),
                    Some(id(6)),
                    Some(Uuid::nil()),
                    metadata(true),
                    "x",
                ),
                "forbidden",
                false,
            ),
            (
                sealed(
                    &caller,
                    &f.crypto,
                    id(100),
                    Some(id(5)),
                    Some(Uuid::nil()),
                    metadata(true),
                    "x",
                ),
                "forbidden",
                true,
            ),
            (
                sealed(
                    &caller,
                    &f.crypto,
                    id(101),
                    Some(id(999)),
                    None,
                    metadata(true),
                    "x",
                ),
                "forbidden",
                true,
            ),
            (
                sealed(
                    &caller,
                    &f.crypto,
                    id(100),
                    None,
                    Some(Uuid::nil()),
                    metadata(true),
                    "x",
                ),
                "stale_version",
                true,
            ),
        ];
        let mut different = metadata(true);
        different.account = "different-account".into();
        requests.push((
            sealed(
                &caller,
                &f.crypto,
                id(100),
                None,
                Some(original.version),
                different,
                "x",
            ),
            "invalid_input",
            true,
        ));
        let mut different = metadata(true);
        different.provider = Provider::Brevo;
        requests.push((
            sealed(
                &caller,
                &f.crypto,
                id(100),
                None,
                Some(original.version),
                different,
                "x",
            ),
            "invalid_input",
            true,
        ));
        for (mut request, code, own) in requests {
            request.sealed_secret.ciphertext = "invalid".into();
            let counts = f.crypto.decrypt_counts();
            assert_eq!(
                if own {
                    caller.write_secret(&f.crypto, &request)
                } else {
                    sibling.write_secret(&f.crypto, &request)
                }
                .unwrap_err()
                .code,
                code
            );
            assert_eq!(f.crypto.decrypt_counts(), counts);
            assert_eq!(f.store.observe_for_verification().unwrap(), before);
        }
        let mut tampered = sealed(
            &caller,
            &f.crypto,
            id(100),
            None,
            Some(original.version),
            metadata(true),
            "tamper-secret",
        );
        tampered.sealed_secret.ciphertext = "invalid".into();
        let counts = f.crypto.decrypt_counts();
        assert_eq!(
            caller.write_secret(&f.crypto, &tampered).unwrap_err().code,
            "credential_crypto"
        );
        assert_eq!(f.crypto.decrypt_counts().0, counts.0 + 1);
        assert_eq!(f.store.observe_for_verification().unwrap(), before);
        let revoked = sealed(
            &caller,
            &f.crypto,
            id(100),
            None,
            Some(original.version),
            metadata(true),
            "x",
        );
        let mut g = graph();
        g.principals
            .iter_mut()
            .find(|p| p.id == id(4))
            .unwrap()
            .credential_epoch = 1;
        replace(&f.store, g);
        let counts = f.crypto.decrypt_counts();
        assert_eq!(
            caller.write_secret(&f.crypto, &revoked).unwrap_err().code,
            "forbidden"
        );
        assert_eq!(f.crypto.decrypt_counts(), counts);
    }

    #[test]
    fn metadata_only_creation_and_update_without_read_use_the_ordinary_contract() {
        let f = fixture();
        let caller = f.store.session(id(9), 0).unwrap();
        let disabled = metadata(false);
        caller
            .mutate(&mutation(
                &caller,
                json!([{"op":"create","id":id(100),"contract":CREDENTIAL,"fields":disabled}]),
            ))
            .unwrap();
        let incarnation = record(&f.store, id(100))
            .derived
            .as_ref()
            .unwrap()
            .incarnation;
        assert_eq!(
            record(&f.store, id(100)).derived,
            Some(Derived {
                incarnation,
                has_secret: false,
                secret_revision: None,
                use_epoch: 0
            })
        );
        assert!(
            caller
                .get(caller.model().identity(), id(100))
                .unwrap()
                .is_none()
        );
        let before = f.store.observe_for_verification().unwrap();
        assert_eq!(
            caller
                .mutate(&edit(&caller, id(100), None, json!({"enabled":true})))
                .unwrap_err()
                .code,
            "invariant"
        );
        assert_eq!(f.store.observe_for_verification().unwrap(), before);
        assert_eq!(f.crypto.decrypt_counts(), (0, 0));
        let write = sealed(
            &caller,
            &f.crypto,
            id(100),
            None,
            Some(record(&f.store, id(100)).version),
            metadata(true),
            "write-without-read",
        );
        let committed = caller.write_secret(&f.crypto, &write).unwrap();
        assert_eq!(committed["result"]["records"][0]["record"], Value::Null);
        assert_eq!(
            record(&f.store, id(100)).derived,
            Some(Derived {
                incarnation,
                has_secret: true,
                secret_revision: Some(1),
                use_epoch: 1
            })
        );
        assert_eq!(f.crypto.decrypt_counts(), (1, 0));
        f.store.check_integrity().unwrap();
        assert_eq!(f.crypto.decrypt_counts(), (1, 0));
    }

    #[test]
    fn secret_write_rolls_back_all_native_points_and_recovers_original_unknown_ack() {
        let f = fixture();
        let caller = f.store.session(id(4), 0).unwrap();
        let write = sealed(
            &caller,
            &f.crypto,
            id(100),
            None,
            None,
            metadata(true),
            "rollback-fixture-secret",
        );
        let before = f.store.observe_for_verification().unwrap();
        // Credential source, Incoming header, creation root/member, private envelope.
        for abort in [1, 2, 3, 4, 5, usize::MAX] {
            let error = caller
                .write_secret_controlled(&f.crypto, &write, Some(abort), &mut || Ok(()), false)
                .unwrap_err();
            assert_eq!(error.code, "injected_abort");
            assert_eq!(f.store.observe_for_verification().unwrap(), before);
            assert_eq!(
                caller
                    .operation_status(&write.model, &write.context, write.operation_id)
                    .unwrap()["status"],
                "not_observed"
            );
        }
        assert_eq!(
            caller
                .write_secret_controlled(&f.crypto, &write, None, &mut || Ok(()), true)
                .unwrap_err()
                .code,
            "outcome_unknown"
        );
        let committed = f.store.observe_for_verification().unwrap();
        let replacement = Crypto::test_with_seed(40);
        let recovered = caller.write_secret(&replacement, &write).unwrap();
        assert_eq!(recovered["replayed"], true);
        assert_eq!(replacement.decrypt_counts(), (0, 0));
        assert_eq!(f.store.observe_for_verification().unwrap(), committed);
        let mut different = write.clone();
        different.sealed_secret.ciphertext = "changed".into();
        assert_eq!(
            caller
                .write_secret(&replacement, &different)
                .unwrap_err()
                .code,
            "operation_conflict"
        );
        assert_eq!(replacement.decrypt_counts(), (0, 0));
        let backup = f.directory.join("backup.json");
        f.store.backup(&backup).unwrap();
        assert!(
            !String::from_utf8(std::fs::read(&backup).unwrap())
                .unwrap()
                .contains("rollback-fixture-secret")
        );
        let restored = f.directory.join("restored.redb");
        crate::lifecycle::restore(
            &backup,
            &restored,
            Arc::new(Prepared::<Services>::load().unwrap()),
        )
        .unwrap();
        let restored =
            Store::<Services>::open(&restored, Arc::new(Prepared::load().unwrap())).unwrap();
        restored.check_integrity().unwrap();
        assert_eq!(envelope(&restored, id(100)), envelope(&f.store, id(100)));
        assert_eq!(record(&restored, id(100)), record(&f.store, id(100)));
        assert!(
            replacement
                .open_secret(
                    &envelope(&restored, id(100)).unwrap(),
                    &secret_context(&record(&restored, id(100)), id(100))
                )
                .is_err()
        );
        assert_eq!(
            restored.observe_for_verification().unwrap()["tables"]["native_kv"],
            committed["tables"]["native_kv"]
        );
    }

    #[test]
    fn independent_checker_rejects_missing_and_orphan_private_rows_without_decryption() {
        let f = fixture();
        let caller = f.store.session(id(4), 0).unwrap();
        let write = sealed(
            &caller,
            &f.crypto,
            id(100),
            None,
            None,
            metadata(true),
            "inventory-fixture-secret",
        );
        caller.write_secret(&f.crypto, &write).unwrap();
        let key = Key::CredentialSecret(id(100), 1);
        let read = f.store.db.begin_read().unwrap();
        let saved = read
            .open_table(crate::local::KV)
            .unwrap()
            .get(key.encode())
            .unwrap()
            .unwrap()
            .value()
            .to_vec();
        drop(read);
        let counts = f.crypto.decrypt_counts();
        let write = f.store.db.begin_write().unwrap();
        write
            .open_table(crate::local::KV)
            .unwrap()
            .remove(key.encode().as_slice())
            .unwrap();
        write.commit().unwrap();
        assert_eq!(f.store.check_integrity().unwrap_err().code, "corrupt_state");
        let write = f.store.db.begin_write().unwrap();
        write
            .open_table(crate::local::KV)
            .unwrap()
            .insert(key.encode().as_slice(), saved.as_slice())
            .unwrap();
        write.commit().unwrap();
        f.store.check_integrity().unwrap();
        let mut orphan = envelope(&f.store, id(100)).unwrap();
        orphan.credential = id(999);
        let orphan_key = Key::CredentialSecret(id(999), 1);
        let encoded = crate::native_codec::encode_for::<Services>(
            &orphan_key,
            &StoredValue::CredentialSecret(orphan),
        )
        .unwrap();
        let write = f.store.db.begin_write().unwrap();
        write
            .open_table(crate::local::KV)
            .unwrap()
            .insert(orphan_key.encode().as_slice(), encoded.as_slice())
            .unwrap();
        write.commit().unwrap();
        assert_eq!(f.store.check_integrity().unwrap_err().code, "corrupt_state");
        let create = mutation(
            &caller,
            json!([{"op":"create","id":id(999),"contract":CREDENTIAL,"fields":metadata(true)}]),
        );
        assert_eq!(caller.mutate(&create).unwrap_err().code, "corrupt_state");
        assert_eq!(f.crypto.decrypt_counts(), counts);
    }
}
