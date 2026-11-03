//! Opaque purpose-specific grants. Provider secret rows are never read here.
use super::crypto::{Crypto, Provider};
use crate::{
    access::{Action, Scope, denied},
    email::{EMAIL_OPERATION, EmailRequest, Purpose},
    local::{self, Store},
    models::services::{CREDENTIAL, Services},
    native_codec::{self, Key, StoredValue, decimal, uuid_text},
    native_slice::{Error, ModelRecord, Result},
    storage::{ReadableTable, WriteTransaction},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;

pub const MAX_GRANT_TTL_SECONDS: u16 = 60;
pub const MAX_PLATFORM_BINDINGS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformSlot {
    TransactionalEmail,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Selection {
    Byoc {
        #[serde(with = "uuid_text")]
        credential: Uuid,
    },
    Platform {
        slot: PlatformSlot,
    },
}
impl Selection {
    pub fn schema() -> Value {
        json!({"oneOf":[
            {"type":"object","properties":{"kind":{"const":"byoc"},"credential":{"type":"string","format":"uuid"}},"required":["kind","credential"],"additionalProperties":false},
            {"type":"object","properties":{"kind":{"const":"platform"},"slot":{"const":"transactional_email"}},"required":["kind","slot"],"additionalProperties":false}
        ]})
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformBinding {
    pub slot: PlatformSlot,
    #[serde(with = "uuid_text")]
    pub credential: Uuid,
    pub provider: Provider,
    pub account: String,
    pub purpose: Purpose,
}
#[derive(Default)]
pub struct PlatformBindings(BTreeMap<PlatformSlot, PlatformBinding>);
impl PlatformBindings {
    pub fn new(bindings: Vec<PlatformBinding>) -> Result<Self> {
        if bindings.len() > MAX_PLATFORM_BINDINGS {
            return Err(configuration());
        }
        let mut result = BTreeMap::new();
        for binding in bindings {
            if binding.credential.is_nil() || result.contains_key(&binding.slot) {
                return Err(configuration());
            }
            super::crypto::validate_account(&binding.account).map_err(|_| configuration())?;
            result.insert(binding.slot, binding);
        }
        Ok(Self(result))
    }
}
fn configuration() -> Error {
    Error::new(
        "credential_configuration",
        "invalid platform credential configuration",
    )
}

/// Loaded once by the service owner. No key files or provider I/O in transactions.
pub struct Runtime {
    crypto: Arc<Crypto>,
    platform: PlatformBindings,
}
impl Runtime {
    pub fn new(crypto: Arc<Crypto>, platform: PlatformBindings) -> Self {
        Self { crypto, platform }
    }
    pub fn crypto(&self) -> &Crypto {
        &self.crypto
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeRequest {
    pub model: String,
    pub email: EmailRequest,
    pub selection: Selection,
    pub ttl_seconds: u16,
}
impl AuthorizeRequest {
    pub fn schema() -> Value {
        json!({"type":"object","additionalProperties":false,"required":["model","email","selection","ttl_seconds"],"properties":{
            "model":{"type":"string"},"email":EmailRequest::schema(),"selection":Selection::schema(),"ttl_seconds":{"type":"integer","minimum":1,"maximum":MAX_GRANT_TTL_SECONDS}
        }})
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedEmail {
    pub grant: String,
    #[serde(with = "decimal")]
    pub expires_at: i64,
}
impl std::fmt::Debug for AuthorizedEmail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthorizedEmail(<redacted>)")
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    operation: String,
    purpose: Purpose,
    model: String,
    #[serde(with = "uuid_text")]
    store: Uuid,
    #[serde(with = "uuid_text")]
    tenant: Uuid,
    #[serde(with = "uuid_text")]
    actor: Uuid,
    #[serde(with = "decimal")]
    principal_epoch: u64,
    selection: Selection,
    #[serde(with = "uuid_text")]
    credential: Uuid,
    #[serde(with = "uuid_text")]
    incarnation: Uuid,
    #[serde(with = "decimal")]
    use_epoch: u64,
    #[serde(with = "decimal")]
    secret_revision: u64,
    provider: Provider,
    account: String,
    request_hash: String,
    #[serde(with = "decimal")]
    issued_at: i64,
    #[serde(with = "decimal")]
    expires_at: i64,
    #[serde(with = "uuid_text")]
    nonce: Uuid,
}

/// Only this module can construct the accepted binding. E2 persists its safe
/// identities with durable intent; the grant token and claims are never stored.
#[allow(
    dead_code,
    reason = "E2 consumes this checked binding in the accepting write transaction"
)]
pub(crate) struct AcceptedBinding {
    credential: Uuid,
    incarnation: Uuid,
    provider: Provider,
    account: String,
    use_epoch: u64,
    secret_revision: u64,
    selection: Selection,
}
#[allow(
    dead_code,
    reason = "E2 consumes this checked binding in the accepting write transaction"
)]
impl AcceptedBinding {
    pub(crate) fn credential(&self) -> Uuid {
        self.credential
    }
    pub(crate) fn incarnation(&self) -> Uuid {
        self.incarnation
    }
    pub(crate) fn provider(&self) -> Provider {
        self.provider
    }
    pub(crate) fn account(&self) -> &str {
        &self.account
    }
    pub(crate) fn use_epoch(&self) -> u64 {
        self.use_epoch
    }
    pub(crate) fn secret_revision(&self) -> u64 {
        self.secret_revision
    }
    pub(crate) fn selection(&self) -> &Selection {
        &self.selection
    }
}

fn invalid_grant() -> Error {
    Error::new("invalid_grant", "email authorization grant is not valid")
}
fn explicit_use(scope: &Scope) -> Result<()> {
    scope.require_active()?;
    if !scope.grants.allows_explicit(CREDENTIAL, Action::Use) {
        return Err(denied());
    }
    Ok(())
}
fn resolve_selection<'a>(
    platform: &'a PlatformBindings,
    selection: &Selection,
) -> Result<(Uuid, Option<&'a PlatformBinding>)> {
    match selection {
        Selection::Byoc { credential } if !credential.is_nil() => Ok((*credential, None)),
        Selection::Platform { slot } => platform
            .0
            .get(slot)
            .map(|p| (p.credential, Some(p)))
            .ok_or_else(denied),
        _ => Err(denied()),
    }
}
fn load_record(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    id: Uuid,
) -> Result<ModelRecord<Services>> {
    let key = Key::Record(id);
    let bytes = table.get(key.encode().as_slice())?.ok_or_else(denied)?;
    match native_codec::decode_for::<Services>(&key, bytes.value())? {
        StoredValue::Record(record) if record.contract == CREDENTIAL => Ok(record),
        _ => Err(denied()),
    }
}
fn check_current(
    scope: &Scope,
    record: &ModelRecord<Services>,
    platform: Option<&PlatformBinding>,
) -> Result<(Uuid, u64, u64)> {
    explicit_use(scope)?;
    if record.tenant != scope.tenant
        || record.contract != CREDENTIAL
        || !record.input.enabled
        || !record
            .input
            .scopes
            .iter()
            .any(|p| p == Purpose::EmailSend.as_str())
        || match platform {
            None => !scope.accessible.contains(&record.owner),
            Some(binding) => {
                binding.provider != record.input.provider
                    || binding.account != record.input.account
                    || binding.purpose != Purpose::EmailSend
            }
        }
    {
        return Err(denied());
    }
    let state = record.derived.as_ref().ok_or_else(denied)?;
    let revision = state
        .secret_revision
        .filter(|r| *r > 0)
        .ok_or_else(denied)?;
    if !state.has_secret || state.incarnation.is_nil() {
        return Err(denied());
    }
    Ok((state.incarnation, state.use_epoch, revision))
}
fn validate_claims(
    claims: &Claims,
    model: &str,
    store: Uuid,
    scope: &Scope,
    request_hash: &str,
    now: i64,
) -> Result<()> {
    if claims.operation != EMAIL_OPERATION
        || claims.purpose != Purpose::EmailSend
        || claims.model != model
        || claims.store != store
        || claims.tenant != scope.tenant
        || claims.actor != scope.actor
        || claims.principal_epoch != scope.credential_epoch
        || claims.request_hash != request_hash
        || claims.nonce.is_nil()
        || claims.incarnation.is_nil()
        || claims.secret_revision == 0
        || claims.issued_at < 0
        || claims.issued_at > now
        || now >= claims.expires_at
        || claims
            .expires_at
            .checked_sub(claims.issued_at)
            .is_none_or(|ttl| !(1..=i64::from(MAX_GRANT_TTL_SECONDS) * 1000).contains(&ttl))
    {
        return Err(invalid_grant());
    }
    Ok(())
}

impl Store<Services> {
    pub fn authorize_email(
        &self,
        runtime: &Runtime,
        request: &AuthorizeRequest,
    ) -> Result<AuthorizedEmail> {
        self.authorize_email_at(runtime, request, crate::mutation::creation_time()?)
    }
    fn authorize_email_at(
        &self,
        runtime: &Runtime,
        request: &AuthorizeRequest,
        now: i64,
    ) -> Result<AuthorizedEmail> {
        if !(1..=MAX_GRANT_TTL_SECONDS).contains(&request.ttl_seconds) || now < 0 {
            return Err(invalid_grant());
        }
        let request_hash = request.email.request_hash()?;
        let (read, _, header) = self.read(&request.model)?;
        let scope = self.authority(&read)?;
        explicit_use(&scope)?;
        let (credential, platform) = resolve_selection(&runtime.platform, &request.selection)?;
        let table = read.open_table(local::KV)?;
        let record = load_record(&table, credential)?;
        let (incarnation, use_epoch, secret_revision) = check_current(&scope, &record, platform)?;
        let expires_at = now
            .checked_add(i64::from(request.ttl_seconds) * 1000)
            .ok_or_else(invalid_grant)?;
        let claims = Claims {
            operation: EMAIL_OPERATION.into(),
            purpose: Purpose::EmailSend,
            model: self.model.identity().into(),
            store: header.store_id,
            tenant: scope.tenant,
            actor: scope.actor,
            principal_epoch: scope.credential_epoch,
            selection: request.selection.clone(),
            credential,
            incarnation,
            use_epoch,
            secret_revision,
            provider: record.input.provider,
            account: record.input.account.clone(),
            request_hash,
            issued_at: now,
            expires_at,
            nonce: Uuid::new_v4(),
        };
        let bytes = serde_json::to_vec(&claims).map_err(|_| invalid_grant())?;
        let grant = runtime.crypto.seal_grant(&bytes)?;
        Ok(AuthorizedEmail { grant, expires_at })
    }

    /// Called only inside E2's transaction after original receipt recovery. A
    /// successful check is not dispatch permission and performs no secret load.
    #[allow(dead_code, reason = "E2 accepting transaction consumes the E1 grant")]
    pub(crate) fn consume_email_grant(
        &self,
        write: &WriteTransaction,
        runtime: &Runtime,
        email: &EmailRequest,
        grant: &str,
        now: i64,
    ) -> Result<AcceptedBinding> {
        let scope = self.write_authority(write)?;
        explicit_use(&scope)?;
        let request_hash = email.request_hash()?;
        let header: local::RuntimeHeader = local::decode(
            write
                .open_table(local::RUNTIME)?
                .get(local::HEADER)?
                .ok_or_else(|| local::corrupt("missing runtime header"))?
                .value(),
        )?;
        local::validate_header(&header)?;
        self.check_expected_store(header.store_id)?;
        let plaintext = runtime
            .crypto
            .open_grant(grant)
            .map_err(|_| invalid_grant())?;
        let claims: Claims = serde_json::from_slice(&plaintext).map_err(|_| invalid_grant())?;
        validate_claims(
            &claims,
            self.model.identity(),
            header.store_id,
            &scope,
            &request_hash,
            now,
        )?;
        let table = write.open_table(local::KV)?;
        let meta_key = Key::Meta;
        let meta_bytes = table
            .get(meta_key.encode().as_slice())?
            .ok_or_else(|| local::corrupt("missing model header"))?;
        let StoredValue::Meta(meta) =
            native_codec::decode_for::<Services>(&meta_key, meta_bytes.value())?
        else {
            return Err(local::corrupt("model header type"));
        };
        self.check_meta(&meta, &claims.model)?;
        let (credential, platform) = resolve_selection(&runtime.platform, &claims.selection)?;
        if credential != claims.credential {
            return Err(invalid_grant());
        }
        let record = load_record(&table, credential)?;
        let (incarnation, use_epoch, secret_revision) = check_current(&scope, &record, platform)?;
        if incarnation != claims.incarnation
            || use_epoch != claims.use_epoch
            || secret_revision != claims.secret_revision
            || record.input.provider != claims.provider
            || record.input.account != claims.account
        {
            return Err(invalid_grant());
        }
        Ok(AcceptedBinding {
            selection: claims.selection,
            credential,
            incarnation,
            provider: record.input.provider,
            account: record.input.account,
            use_epoch,
            secret_revision,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::crypto::Metadata;
    use crate::{access::Grants, models::services::Derived, native_slice::Context};
    fn scope() -> Scope {
        let mut scope = Scope::local(Context {
            tenant: Uuid::from_u128(1),
            actor: Uuid::from_u128(2),
        });
        scope.grants = Grants {
            admin: false,
            contracts: BTreeMap::from([(CREDENTIAL, [Action::Use].into())]),
        };
        scope
    }
    fn record() -> ModelRecord<Services> {
        ModelRecord {
            contract: CREDENTIAL,
            tenant: Uuid::from_u128(1),
            owner: Uuid::from_u128(2),
            created_at: 0,
            version: Uuid::from_u128(3),
            input: Metadata {
                label: "mail".into(),
                provider: Provider::Resend,
                account: "account".into(),
                enabled: true,
                scopes: vec!["email.send".into()],
            },
            derived: Some(Derived {
                incarnation: Uuid::from_u128(3),
                has_secret: true,
                secret_revision: Some(1),
                use_epoch: 0,
            }),
        }
    }
    fn platform() -> PlatformBinding {
        PlatformBinding {
            slot: PlatformSlot::TransactionalEmail,
            credential: Uuid::from_u128(5),
            provider: Provider::Resend,
            account: "account".into(),
            purpose: Purpose::EmailSend,
        }
    }
    #[test]
    fn use_is_explicit_and_independent_of_metadata_read_or_admin() {
        let mut scope = scope();
        let row = record();
        assert!(check_current(&scope, &row, None).is_ok());
        assert!(!scope.can_read(&row));
        scope.grants.contracts = BTreeMap::from([(CREDENTIAL, [Action::Read].into())]);
        assert!(check_current(&scope, &row, None).is_err());
        scope.grants.admin = true;
        assert!(check_current(&scope, &row, None).is_err());
        scope
            .grants
            .contracts
            .insert(CREDENTIAL, [Action::Use].into());
        scope.accessible.clear();
        assert!(check_current(&scope, &row, None).is_err());
    }
    #[test]
    fn platform_use_does_not_grant_read_or_bypass_fixed_binding() {
        let scope = scope();
        let mut row = record();
        row.owner = Uuid::from_u128(1);
        let binding = platform();
        assert!(check_current(&scope, &row, Some(&binding)).is_ok());
        assert!(!scope.can_read(&row));
        let mut wrong = binding.clone();
        wrong.account = "other".into();
        assert!(check_current(&scope, &row, Some(&wrong)).is_err());
        wrong = binding.clone();
        wrong.provider = Provider::Brevo;
        assert!(check_current(&scope, &row, Some(&wrong)).is_err());
        row.tenant = Uuid::from_u128(7);
        assert!(check_current(&scope, &row, Some(&binding)).is_err());
        assert!(PlatformBindings::new(vec![binding.clone(), binding]).is_err());
    }
    #[test]
    fn state_and_claim_fences_reject_revocation_expiry_and_request_changes() {
        let scope = scope();
        let row = record();
        let claims = Claims {
            operation: EMAIL_OPERATION.into(),
            purpose: Purpose::EmailSend,
            model: "model".into(),
            store: Uuid::from_u128(8),
            tenant: scope.tenant,
            actor: scope.actor,
            principal_epoch: 0,
            selection: Selection::Byoc {
                credential: Uuid::from_u128(5),
            },
            credential: Uuid::from_u128(5),
            incarnation: Uuid::from_u128(3),
            use_epoch: 0,
            secret_revision: 1,
            provider: Provider::Resend,
            account: "account".into(),
            request_hash: "request".into(),
            issued_at: 1000,
            expires_at: 2000,
            nonce: Uuid::from_u128(9),
        };
        let valid = |claims: &Claims, scope: &Scope, hash: &str, now| {
            validate_claims(claims, "model", Uuid::from_u128(8), scope, hash, now)
        };
        assert!(valid(&claims, &scope, "request", 1000).is_ok());
        assert!(valid(&claims, &scope, "request", 2000).is_err());
        assert!(valid(&claims, &scope, "request", 999).is_err());
        assert!(valid(&claims, &scope, "other", 1000).is_err());
        let mut revoked = scope.clone();
        revoked.credential_epoch = 1;
        assert!(valid(&claims, &revoked, "request", 1000).is_err());
        for state in 0..4 {
            let mut changed = row.clone();
            match state {
                0 => changed.input.enabled = false,
                1 => changed.input.scopes.clear(),
                2 => changed.derived.as_mut().unwrap().has_secret = false,
                _ => changed.derived.as_mut().unwrap().secret_revision = None,
            };
            assert!(check_current(&scope, &changed, None).is_err());
        }
    }
    #[test]
    fn opaque_grants_authenticate_claims_without_provider_secret_loading() {
        let crypto = Crypto::test();
        let scope = scope();
        let claims = Claims {
            operation: EMAIL_OPERATION.into(),
            purpose: Purpose::EmailSend,
            model: "model".into(),
            store: Uuid::from_u128(8),
            tenant: scope.tenant,
            actor: scope.actor,
            principal_epoch: 0,
            selection: Selection::Platform {
                slot: PlatformSlot::TransactionalEmail,
            },
            credential: Uuid::from_u128(5),
            incarnation: Uuid::from_u128(3),
            use_epoch: 7,
            secret_revision: 11,
            provider: Provider::Resend,
            account: "private-account".into(),
            request_hash: "request-hash".into(),
            issued_at: 1000,
            expires_at: 2000,
            nonce: Uuid::from_u128(9),
        };
        let plaintext = serde_json::to_vec(&claims).unwrap();
        let token = crypto.seal_grant(&plaintext).unwrap();
        assert!(token.len() <= 4096);
        assert!(!token.contains("private-account"));
        assert!(!token.contains("request-hash"));
        let decoded = crypto.open_grant(&token).unwrap();
        let roundtrip: Claims = serde_json::from_slice(&decoded).unwrap();
        validate_claims(
            &roundtrip,
            "model",
            Uuid::from_u128(8),
            &scope,
            "request-hash",
            1500,
        )
        .unwrap();
        assert!(
            validate_claims(
                &roundtrip,
                "other-model",
                Uuid::from_u128(8),
                &scope,
                "request-hash",
                1500
            )
            .is_err()
        );
        assert!(
            validate_claims(
                &roundtrip,
                "model",
                Uuid::from_u128(88),
                &scope,
                "request-hash",
                1500
            )
            .is_err()
        );
        let mut altered = token.into_bytes();
        let index = altered.len() / 2;
        altered[index] = if altered[index] == b'A' { b'B' } else { b'A' };
        assert!(
            crypto
                .open_grant(std::str::from_utf8(&altered).unwrap())
                .is_err()
        );
        let response = AuthorizedEmail {
            grant: "opaque-sensitive-token".into(),
            expires_at: 2000,
        };
        assert!(!format!("{response:?}").contains("opaque-sensitive-token"));
    }
    fn email() -> EmailRequest {
        EmailRequest {
            sender: "sender@example.com".into(),
            to: vec!["recipient@example.net".into()],
            subject: "subject".into(),
            text: "plain body".into(),
        }
    }
    fn consume(
        store: &Store<Services>,
        runtime: &Runtime,
        email: &EmailRequest,
        token: &str,
        now: i64,
    ) -> Result<AcceptedBinding> {
        let write = store.begin_write()?;
        store.consume_email_grant(&write, runtime, email, token, now)
    }
    #[test]
    fn real_issuance_and_accepting_transaction_recheck_rotation_revocation_and_requester_epoch() {
        use crate::credentials::store::test_support as f;
        let fixture = f::fixture();
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
                    "test-provider-key-one",
                ),
            )
            .unwrap();
        let runtime = Runtime::new(fixture.crypto.clone(), PlatformBindings::default());
        let now = crate::mutation::creation_time().unwrap();
        let request = AuthorizeRequest {
            model: caller.model.identity().into(),
            email: email(),
            selection: Selection::Byoc {
                credential: f::id(100),
            },
            ttl_seconds: 60,
        };
        let counts = fixture.crypto.decrypt_counts();
        let grant = caller.authorize_email_at(&runtime, &request, now).unwrap();
        let accepted = consume(&caller, &runtime, &request.email, &grant.grant, now).unwrap();
        assert_eq!(accepted.credential(), f::id(100));
        assert_eq!(accepted.secret_revision(), 1);
        assert_eq!(fixture.crypto.decrypt_counts(), counts);
        let mut changed_email = request.email.clone();
        changed_email.subject.push('!');
        assert!(consume(&caller, &runtime, &changed_email, &grant.grant, now).is_err());
        assert!(
            consume(
                &caller,
                &runtime,
                &request.email,
                &grant.grant,
                now + 60_000
            )
            .is_err()
        );
        caller
            .mutate(&f::edit(
                &caller,
                f::id(100),
                None,
                json!({"label":"new label"}),
            ))
            .unwrap();
        assert!(consume(&caller, &runtime, &request.email, &grant.grant, now).is_ok());
        let version = f::record(&caller, f::id(100)).version;
        caller
            .write_secret(
                &fixture.crypto,
                &f::sealed(
                    &caller,
                    &fixture.crypto,
                    f::id(100),
                    None,
                    Some(version),
                    f::metadata(true),
                    "test-provider-key-two",
                ),
            )
            .unwrap();
        assert!(consume(&caller, &runtime, &request.email, &grant.grant, now).is_err());
        let grant = caller.authorize_email_at(&runtime, &request, now).unwrap();
        caller
            .mutate(&f::edit(
                &caller,
                f::id(100),
                None,
                json!({"enabled":false}),
            ))
            .unwrap();
        assert!(consume(&caller, &runtime, &request.email, &grant.grant, now).is_err());
        caller
            .mutate(&f::edit(&caller, f::id(100), None, json!({"enabled":true})))
            .unwrap();
        assert!(consume(&caller, &runtime, &request.email, &grant.grant, now).is_err());
        let grant = caller.authorize_email_at(&runtime, &request, now).unwrap();
        caller
            .mutate(&f::edit(&caller, f::id(100), Some(f::id(7)), json!({})))
            .unwrap();
        assert!(consume(&caller, &runtime, &request.email, &grant.grant, now).is_err());
        let grant = caller.authorize_email_at(&runtime, &request, now).unwrap();
        let mut graph = f::graph();
        graph
            .principals
            .iter_mut()
            .find(|p| p.id == f::id(4))
            .unwrap()
            .credential_epoch = 1;
        f::replace(&fixture.store, graph);
        assert!(consume(&caller, &runtime, &request.email, &grant.grant, now).is_err());
        let current = fixture.store.session(f::id(4), 1).unwrap();
        assert!(consume(&current, &runtime, &request.email, &grant.grant, now).is_err());
        fixture.store.check_integrity().unwrap();
    }
    #[test]
    fn real_hidden_platform_binding_and_use_without_read_issue_no_secrets() {
        use crate::credentials::store::test_support as f;
        let fixture = f::fixture();
        let use_only = fixture.store.session(f::id(9), 0).unwrap();
        let read_only = fixture.store.session(f::id(8), 0).unwrap();
        for (store, id, owner) in [
            (&fixture.store, 101, Some(f::id(5))),
            (&use_only, 102, None),
            (&read_only, 103, None),
        ] {
            store
                .write_secret(
                    &fixture.crypto,
                    &f::sealed(
                        store,
                        &fixture.crypto,
                        f::id(id),
                        owner,
                        None,
                        f::metadata(true),
                        "test-provider-key",
                    ),
                )
                .unwrap();
        }
        let binding = PlatformBinding {
            slot: PlatformSlot::TransactionalEmail,
            credential: f::id(101),
            provider: Provider::Resend,
            account: "test-mail".into(),
            purpose: Purpose::EmailSend,
        };
        let runtime = Runtime::new(
            fixture.crypto.clone(),
            PlatformBindings::new(vec![binding.clone()]).unwrap(),
        );
        let now = crate::mutation::creation_time().unwrap();
        let counts = fixture.crypto.decrypt_counts();
        let mut request = AuthorizeRequest {
            model: use_only.model.identity().into(),
            email: email(),
            selection: Selection::Byoc {
                credential: f::id(102),
            },
            ttl_seconds: 60,
        };
        assert!(
            use_only
                .get(use_only.model.identity(), f::id(102))
                .unwrap()
                .is_none()
        );
        assert!(use_only.authorize_email_at(&runtime, &request, now).is_ok());
        request.selection = Selection::Byoc {
            credential: f::id(103),
        };
        assert!(
            read_only
                .get(read_only.model.identity(), f::id(103))
                .unwrap()
                .is_some()
        );
        assert!(
            read_only
                .authorize_email_at(&runtime, &request, now)
                .is_err()
        );
        request.selection = Selection::Byoc {
            credential: f::id(101),
        };
        assert!(
            use_only
                .authorize_email_at(&runtime, &request, now)
                .is_err()
        );
        request.selection = Selection::Platform {
            slot: PlatformSlot::TransactionalEmail,
        };
        let grant = use_only
            .authorize_email_at(&runtime, &request, now)
            .unwrap();
        assert_eq!(
            consume(&use_only, &runtime, &request.email, &grant.grant, now)
                .unwrap()
                .credential(),
            f::id(101)
        );
        assert!(
            use_only
                .get(use_only.model.identity(), f::id(101))
                .unwrap()
                .is_none()
        );
        let mut moved = binding.clone();
        moved.credential = f::id(102);
        let changed = Runtime::new(
            fixture.crypto.clone(),
            PlatformBindings::new(vec![moved]).unwrap(),
        );
        assert!(consume(&use_only, &changed, &request.email, &grant.grant, now).is_err());
        let mut wrong = binding;
        wrong.provider = Provider::Brevo;
        let wrong = Runtime::new(
            fixture.crypto.clone(),
            PlatformBindings::new(vec![wrong]).unwrap(),
        );
        assert!(use_only.authorize_email_at(&wrong, &request, now).is_err());
        assert_eq!(fixture.crypto.decrypt_counts(), counts);
        let other = f::fixture();
        let other_caller = other.store.session(f::id(9), 0).unwrap();
        assert!(consume(&other_caller, &runtime, &request.email, &grant.grant, now).is_err());
    }
    #[test]
    fn grant_cannot_revive_after_credential_uuid_is_deleted_and_recreated() {
        use crate::{credentials::store::test_support as f, native_slice::Command};
        let fixture = f::fixture();
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
                    "first-test-key",
                ),
            )
            .unwrap();
        let runtime = Runtime::new(fixture.crypto.clone(), PlatformBindings::default());
        let now = crate::mutation::creation_time().unwrap();
        let request = AuthorizeRequest {
            model: caller.model.identity().into(),
            email: email(),
            selection: Selection::Byoc {
                credential: f::id(100),
            },
            ttl_seconds: 60,
        };
        let first_record = f::record(&caller, f::id(100));
        let first_incarnation = first_record.derived.as_ref().unwrap().incarnation;
        let old = caller.authorize_email_at(&runtime, &request, now).unwrap();
        let mut deletion = f::edit(&caller, f::id(100), None, json!({}));
        deletion.commands = vec![Command::Delete {
            id: f::id(100),
            if_version: first_record.version,
        }];
        caller.mutate(&deletion).unwrap();
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
                    "second-test-key",
                ),
            )
            .unwrap();
        let recreated = f::record(&caller, f::id(100));
        let state = recreated.derived.as_ref().unwrap();
        assert_eq!(state.secret_revision, Some(1));
        assert_eq!(state.use_epoch, 0);
        assert_ne!(state.incarnation, first_incarnation);
        assert!(consume(&caller, &runtime, &request.email, &old.grant, now).is_err());
        let fresh = caller.authorize_email_at(&runtime, &request, now).unwrap();
        assert_eq!(
            consume(&caller, &runtime, &request.email, &fresh.grant, now)
                .unwrap()
                .incarnation(),
            state.incarnation
        );
        caller
            .mutate(&f::edit(
                &caller,
                f::id(100),
                None,
                json!({"label":"label-only"}),
            ))
            .unwrap();
        assert!(consume(&caller, &runtime, &request.email, &fresh.grant, now).is_ok());
        fixture.store.check_integrity().unwrap();
    }
}
