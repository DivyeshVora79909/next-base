//! Private delivered proof. Every state transition owns one native transaction;
//! delivery and signing happen only after its durable decision.
#[cfg(test)]
#[path = "proof_tests.rs"]
mod tests;
use super::{
    proof_crypto::{Crypto, Envelope},
    proof_types::{AuthDelivery, Begin, Consume, ServerPolicy, Status},
    types::{Input, Kind},
};
use crate::{
    access::PrincipalKind,
    binding::Binding,
    effects::Execution,
    identity::{Claims, IdentityConfig},
    local::{self, KV, RuntimeHeader, Store},
    native_codec::{self, Key, StoredValue, decimal, uuid_text},
    native_slice::{Attempt, Error, ModelRecord, Result},
    storage::{ReadTransaction, ReadableTable, TableDefinition, WriteTransaction},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const FORMAT: &str = "auth-proof-1";
pub const MAX_CHALLENGES: usize = 256;
pub const MAX_RECEIPTS: usize = 1536;
pub const PROOF_MS: i64 = 300_000;
const RECOVERY_MS: i64 = 86_400_000;
type Definition = TableDefinition<'static, &'static [u8], &'static [u8]>;
pub(crate) const CHALLENGES: Definition = TableDefinition::new("auth_challenges");
pub(crate) const RECEIPTS: Definition = TableDefinition::new("auth_receipts");
pub(crate) const HEADS: Definition = TableDefinition::new("auth_heads");
pub(crate) const HANDLES: Definition = TableDefinition::new("auth_handles");
pub(crate) const RUNTIME: Definition = TableDefinition::new("auth_runtime");
pub(crate) const TABLES: [(Definition, usize); 5] = [
    (CHALLENGES, 256),
    (RECEIPTS, 1536),
    (HEADS, 256),
    (HANDLES, 256),
    (RUNTIME, 3),
];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub keyring: PathBuf,
    pub policies: Vec<ServerPolicy>,
    pub active_signing_key: String,
    pub signing_keys: BTreeMap<String, PathBuf>,
}
pub struct Runtime {
    pub(crate) crypto: Crypto,
    pub(crate) policies: BTreeMap<Kind, ServerPolicy>,
    identity: IdentityConfig,
    active_signing_key: String,
    signing: BTreeMap<String, Zeroizing<Vec<u8>>>,
}
impl Runtime {
    pub fn load(
        config: &Config,
        identity: &IdentityConfig,
        tenant: Uuid,
        generation: Uuid,
    ) -> Result<Self> {
        if config.policies.is_empty()
            || config.policies.len() > 2
            || config.signing_keys.is_empty()
            || config.signing_keys.len() > 16
            || identity.max_token_seconds < 900
        {
            return Err(unavailable());
        }
        let crypto = Crypto::load(&config.keyring)?;
        let mut policies = BTreeMap::new();
        for policy in &config.policies {
            policy.validate()?;
            if policies.insert(policy.kind, policy.clone()).is_some() {
                return Err(unavailable());
            }
        }
        let mut signing = BTreeMap::new();
        for (kid, path) in &config.signing_keys {
            let pem = super::proof_crypto::read_private_file(path, 4096)?;
            // Verify matching custody without persisting or disclosing a token.
            crate::identity::issue(
                identity,
                &crate::identity::TokenRequest {
                    tenant,
                    actor: Uuid::new_v4(),
                    epoch: 0,
                    ttl: 900,
                    key_id: kid.clone(),
                },
                &pem,
                generation,
            )?;
            signing.insert(kid.clone(), pem);
        }
        if !signing.contains_key(&config.active_signing_key) {
            return Err(unavailable());
        }
        Ok(Self {
            crypto,
            policies,
            identity: identity.clone(),
            active_signing_key: config.active_signing_key.clone(),
            signing,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct Admission {
    key: String,
    #[serde(with = "decimal")]
    at: i64,
    consume: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    format: String,
    admission_key_id: String,
    #[serde(with = "decimal")]
    last_at: i64,
    challenges: u16,
    receipts: u16,
    points: Vec<Admission>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindingState {
    #[serde(with = "uuid_text")]
    pub identity: Uuid,
    #[serde(with = "uuid_text")]
    pub incarnation: Uuid,
    #[serde(with = "uuid_text")]
    pub owner: Uuid,
    #[serde(with = "decimal")]
    pub identity_revision: u64,
    #[serde(with = "decimal")]
    pub authentication_revision: u64,
    #[serde(with = "decimal")]
    pub credential_epoch: u64,
    pub policy: ServerPolicy,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Challenge {
    format: String,
    #[serde(with = "uuid_text")]
    pub id: Uuid,
    #[serde(with = "uuid_text")]
    pub generation: Uuid,
    #[serde(with = "uuid_text")]
    pub operation: Uuid,
    #[serde(with = "uuid_text")]
    pub source: Uuid,
    #[serde(with = "uuid_text")]
    pub execution: Uuid,
    #[serde(with = "decimal")]
    created_at: i64,
    #[serde(with = "decimal")]
    pub expires_at: i64,
    pub binding: Option<BindingState>,
    #[serde(with = "crate::native_codec::optional_uuid_text")]
    previous: Option<Uuid>,
    key_id: String,
    verifier: String,
    #[serde(with = "uuid_text")]
    nonce: Uuid,
    handle_digest: String,
    identifier_digest: String,
    response: Envelope,
    attempts: u8,
    consumed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Issuance {
    claims: Claims,
    key_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Outcome {
    Begin {
        #[serde(with = "uuid_text")]
        challenge: Uuid,
    },
    Invalid {
        challenge: Option<Uuid>,
        spent: bool,
    },
    Issued {
        #[serde(with = "uuid_text")]
        challenge: Uuid,
        issuance: Issuance,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    format: String,
    #[serde(with = "uuid_text")]
    operation: Uuid,
    #[serde(with = "uuid_text")]
    generation: Uuid,
    key_id: String,
    recovery: String,
    fingerprint: String,
    #[serde(with = "decimal")]
    created_at: i64,
    admission: Vec<Admission>,
    outcome: Outcome,
}
fn unavailable() -> Error {
    Error::new("auth_unavailable", "authentication operation unavailable")
}
fn invalid() -> Value {
    json!({"status":"invalid_proof"})
}
fn key(kind: Kind) -> [u8; 1] {
    [kind.tag()]
}
fn get<T: DeserializeOwned>(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    key: &[u8],
) -> Result<Option<T>> {
    table
        .get(key)?
        .map(|v| local::decode(v.value()))
        .transpose()
}
fn header(write: &WriteTransaction) -> Result<RuntimeHeader> {
    let header = get(&write.open_table(local::RUNTIME)?, local::HEADER)?.ok_or_else(unavailable)?;
    local::validate_header(&header)?;
    Ok(header)
}
fn state(write: &WriteTransaction) -> Result<State> {
    get(&write.open_table(RUNTIME)?, b"state")?.ok_or_else(unavailable)
}
fn store_state(write: &WriteTransaction, state: &State) -> Result<()> {
    write
        .open_table(RUNTIME)?
        .insert(b"state".as_slice(), local::encode(state)?.as_slice())?;
    Ok(())
}
pub(crate) fn create_tables(write: &WriteTransaction) -> Result<()> {
    for (def, _) in TABLES {
        write.open_table(def)?;
    }
    Ok(())
}
pub(crate) fn reset_tables(write: &WriteTransaction) -> Result<()> {
    if write.open_table(CHALLENGES)?.len()? != 0 || write.open_table(RECEIPTS)?.len()? != 0 {
        return Err(unavailable());
    }
    for (def, _) in TABLES {
        write.delete_table(def)?;
        write.open_table(def)?;
    }
    Ok(())
}

impl<B: Binding> Store<B> {
    pub(crate) fn configure_authentication(&self, runtime: Option<&Runtime>) -> Result<()> {
        let write = self.begin_write()?;
        let mut table = write.open_table(RUNTIME)?;
        for kind in [Kind::Email, Kind::Phone] {
            table.remove(key(kind).as_slice())?;
        }
        if let Some(runtime) = runtime {
            if !B::identity_enabled() || !self.secured {
                return Err(unavailable());
            }
            let existing: Option<State> = get(&table, b"state")?;
            if let Some(existing) = &existing {
                if !runtime.crypto.has_key(&existing.admission_key_id) {
                    return Err(unavailable());
                }
            } else {
                table.insert(
                    b"state".as_slice(),
                    local::encode(&State {
                        format: FORMAT.into(),
                        admission_key_id: runtime.crypto.current_id().into(),
                        last_at: 0,
                        challenges: 0,
                        receipts: 0,
                        points: vec![],
                    })?
                    .as_slice(),
                )?;
            }
            for policy in runtime.policies.values() {
                table.insert(
                    key(policy.kind).as_slice(),
                    local::encode(policy)?.as_slice(),
                )?;
            }
        }
        drop(table);
        write.commit()
    }
}
fn charge(
    state: &mut State,
    crypto: &Crypto,
    peer: &str,
    identifier: Option<&Input>,
    now: i64,
) -> Result<Vec<Admission>> {
    if now < state.last_at || state.receipts as usize >= MAX_RECEIPTS {
        return Err(unavailable());
    }
    let consume = identifier.is_none();
    let peer_key = crypto.digest_with_key(&state.admission_key_id, "peer", &peer, b"")?;
    state.points.retain(|p| p.at > now.saturating_sub(PROOF_MS));
    let peer_count = state
        .points
        .iter()
        .filter(|p| p.key == peer_key && p.consume == consume && p.at > now.saturating_sub(60_000))
        .count();
    if peer_count >= if consume { 64 } else { 32 } {
        return Err(unavailable());
    }
    let mut added = Vec::new();
    if let Some(identifier) = identifier {
        let id_key =
            crypto.digest_with_key(&state.admission_key_id, "identifier", identifier, b"")?;
        if state
            .points
            .iter()
            .filter(|p| p.key == id_key && !p.consume)
            .count()
            >= 3
        {
            return Err(unavailable());
        }
        added.push(Admission {
            key: id_key,
            at: now,
            consume: false,
        });
    }
    if state.points.len() >= MAX_RECEIPTS * 2 {
        return Err(unavailable());
    }
    added.push(Admission {
        key: peer_key,
        at: now,
        consume,
    });
    state.points.extend(added.clone());
    state.last_at = now;
    Ok(added)
}
fn source<B: Binding>(write: &WriteTransaction, id: Uuid) -> Result<Option<ModelRecord<B>>> {
    let key = Key::Record(id);
    match write.open_table(KV)?.get(key.encode())? {
        Some(v) => match native_codec::decode_for::<B>(&key, v.value())? {
            StoredValue::Record(r) => Ok(Some(r)),
            _ => Err(unavailable()),
        },
        None => Ok(None),
    }
}
fn revision<B: Binding>(write: &WriteTransaction, owner: Uuid) -> Result<u64> {
    let key = Key::AuthenticationRevision(owner);
    let table = write.open_table(KV)?;
    let value = table.get(key.encode())?.ok_or_else(unavailable)?;
    match native_codec::decode_for::<B>(&key, value.value())? {
        StoredValue::AuthenticationRevision(r) => Ok(r.revision),
        _ => Err(unavailable()),
    }
}
fn binding_current<B: Binding>(write: &WriteTransaction, binding: &BindingState) -> Result<bool> {
    let Some(record) = source::<B>(write, binding.identity)? else {
        return Ok(false);
    };
    let Ok((_, state)) = B::identity_values(&record) else {
        return Ok(false);
    };
    let graph = crate::security::write_graph(write)?;
    let Some(principal) = graph
        .graph
        .principals
        .iter()
        .find(|p| p.id == binding.owner)
    else {
        return Ok(false);
    };
    Ok(record.owner == binding.owner
        && state.incarnation == binding.incarnation
        && state.identity_revision == binding.identity_revision
        && principal.kind == PrincipalKind::User
        && principal.active
        && principal.login_access
        && principal.credential_epoch == binding.credential_epoch
        && revision::<B>(write, binding.owner)? == binding.authentication_revision)
}
fn challenge_current<B: Binding>(
    write: &WriteTransaction,
    header: &RuntimeHeader,
    c: &Challenge,
    now: i64,
    allow_consumed: bool,
) -> Result<bool> {
    if c.generation != header.session_generation
        || now < c.created_at
        || now >= c.expires_at && !allow_consumed
        || c.attempts > 5
        || c.consumed && !allow_consumed
    {
        return Ok(false);
    }
    let Some(binding) = &c.binding else {
        return Ok(false);
    };
    if allow_consumed {
        return binding_current::<B>(write, binding);
    }
    let current: Option<Uuid> = get(&write.open_table(HEADS)?, binding.incarnation.as_bytes())?;
    Ok(current == Some(c.id) && binding_current::<B>(write, binding)?)
}
pub(crate) fn preflight_delivery<B: Binding>(
    write: &WriteTransaction,
    header: &RuntimeHeader,
    delivery: &AuthDelivery,
    pin: &crate::credentials::grants::AcceptedBinding,
    now: i64,
) -> Result<()> {
    let c: Challenge = get(
        &write.open_table(CHALLENGES)?,
        delivery.challenge.as_bytes(),
    )?
    .ok_or_else(unavailable)?;
    let binding = c.binding.as_ref().ok_or_else(unavailable)?;
    let policy: Option<ServerPolicy> = get(&write.open_table(RUNTIME)?, &key(binding.policy.kind))?;
    if delivery.generation != c.generation
        || delivery.expires_at != c.expires_at
        || c.attempts >= 5
        || !challenge_current::<B>(write, header, &c, now, false)?
        || policy.as_ref() != Some(&binding.policy)
        || pin.server_policy() != Some(&binding.policy)
    {
        return Err(unavailable());
    }
    crate::credentials::grants::validate_server_pinned::<B>(write, pin)
}
fn valid_digest(value: &str) -> bool {
    super::proof_crypto::validate_secret(value).is_ok()
}
fn code_aad(header: &RuntimeHeader, tenant: Uuid, c: &Challenge) -> Value {
    json!({"format":FORMAT,"purpose":"code","store":header.store_id,"tenant":tenant,"generation":c.generation,"challenge":c.id,"nonce":c.nonce,"binding":c.binding,"identifier_digest":c.identifier_digest,"created_at":c.created_at.to_string(),"expires_at":c.expires_at.to_string()})
}
fn response_aad(header: &RuntimeHeader, id: Uuid) -> Value {
    json!({"purpose":"challenge-response","store":header.store_id,"challenge":id})
}
pub(crate) fn delivery_aad(store: Uuid, tenant: Uuid, delivery: &AuthDelivery) -> Value {
    json!({"purpose":"delivery","store":store,"tenant":tenant,"challenge":delivery.challenge,"generation":delivery.generation,"expires_at":delivery.expires_at.to_string()})
}
fn receipt<B: Binding>(
    write: &WriteTransaction,
    runtime: &Runtime,
    header: &RuntimeHeader,
    operation: Uuid,
    recovery: &[u8],
    fingerprint: Option<(&str, Value, &[u8])>,
    now: i64,
) -> Result<Option<Value>> {
    let Some(row) = get::<Receipt>(&write.open_table(RECEIPTS)?, operation.as_bytes())? else {
        return Ok(None);
    };
    if row.generation != header.session_generation
        || now < row.created_at
        || now - row.created_at >= RECOVERY_MS
        || !runtime.crypto.verify_digest_with_key(
            &row.key_id,
            "recovery",
            &operation,
            recovery,
            &row.recovery,
        )?
    {
        return Err(unavailable());
    }
    if let Some((kind, binding, secret)) = fingerprint
        && !runtime.crypto.verify_digest_with_key(
            &row.key_id,
            kind,
            &binding,
            secret,
            &row.fingerprint,
        )?
    {
        return Err(unavailable());
    }
    let value = match row.outcome {
        Outcome::Invalid { .. } => invalid(),
        Outcome::Begin { challenge } => {
            let c: Challenge = get(&write.open_table(CHALLENGES)?, challenge.as_bytes())?
                .ok_or_else(unavailable)?;
            if now >= c.expires_at {
                return Err(unavailable());
            }
            let bytes = runtime
                .crypto
                .open(&response_aad(header, c.id), &c.response)?;
            serde_json::from_slice(&bytes).map_err(|_| unavailable())?
        }
        Outcome::Issued {
            challenge,
            issuance,
        } => {
            let c: Challenge = get(&write.open_table(CHALLENGES)?, challenge.as_bytes())?
                .ok_or_else(unavailable)?;
            if !c.consumed
                || !challenge_current::<B>(write, header, &c, now, true)?
                || issuance.claims.exp <= now as u64 / 1000
            {
                return Err(unavailable());
            }
            let pem = runtime
                .signing
                .get(&issuance.key_id)
                .ok_or_else(unavailable)?;
            let token = crate::identity::issue_pinned_claims(
                &runtime.identity,
                &issuance.claims,
                &issuance.key_id,
                pem,
            )?;
            json!({"status":"authenticated","token":token})
        }
    };
    Ok(Some(value))
}
fn save_receipt(write: &WriteTransaction, state: &mut State, row: &Receipt) -> Result<()> {
    if state.receipts as usize >= MAX_RECEIPTS {
        return Err(unavailable());
    }
    write.open_table(RECEIPTS)?.insert(
        row.operation.as_bytes().as_slice(),
        local::encode(row)?.as_slice(),
    )?;
    state.receipts += 1;
    store_state(write, state)
}

impl<B: Binding> Store<B> {
    pub(crate) fn begin_proof(
        &self,
        runtime: &Runtime,
        request: &Begin,
        peer: &str,
    ) -> Result<Value> {
        self.begin_proof_controlled(runtime, request, peer, None, &mut || Ok(()), false)
    }
    pub(crate) fn begin_proof_controlled(
        &self,
        runtime: &Runtime,
        request: &Begin,
        peer: &str,
        abort: Option<usize>,
        before_commit: &mut dyn FnMut() -> Result<()>,
        lose_ack: bool,
    ) -> Result<Value> {
        request.validate()?;
        let identifier = request.identifier.normalized()?;
        let now = crate::effects::now_millis()?;
        let write = self.begin_write()?;
        let header = header(&write)?;
        let intent = json!({"identifier":identifier});
        if let Some(value) = receipt::<B>(
            &write,
            runtime,
            &header,
            request.operation_id,
            request.recovery_secret.as_bytes(),
            Some(("begin", intent.clone(), b"")),
            now,
        )? {
            return Ok(value);
        }
        let mut state = state(&write)?;
        let admission = charge(&mut state, &runtime.crypto, peer, Some(&identifier), now)?;
        let effects = crate::effects::runtime_write(&write)?;
        // Check the same conservative capacity before identifier lookup. The
        // reserve bounds the fixed auth message, row, fact and retained envelope.
        if state.challenges as usize >= MAX_CHALLENGES
            || effects.quarantined
            || effects.retained >= crate::effects::MAX_RETAINED
            || effects.unresolved >= crate::effects::MAX_UNRESOLVED
            || usize::from(effects.facts) + usize::from(effects.reserved_facts)
                >= crate::effects::MAX_FACTS
            || effects.accounted_bytes > crate::effects::MAX_BYTES - 131_072
        {
            return Err(unavailable());
        }
        let table = write.open_table(KV)?;
        let claim_key = Key::IdentityClaim(identifier.kind, identifier.value.clone());
        let claim = table
            .get(claim_key.encode())?
            .map(|v| native_codec::decode_for::<B>(&claim_key, v.value()))
            .transpose()?;
        let mut eligible = None;
        if let Some(StoredValue::IdentityClaim(claim)) = claim {
            let record = source::<B>(&write, claim.identity)?.ok_or_else(unavailable)?;
            let (input, identity) = B::identity_values(&record)?;
            if *input != identifier || identity.incarnation != claim.incarnation {
                return Err(unavailable());
            }
            let graph = crate::security::write_graph(&write)?;
            if let Some(principal) = graph.graph.principals.iter().find(|p| {
                p.id == record.owner && p.kind == PrincipalKind::User && p.active && p.login_access
            }) && let Some(policy) = runtime.policies.get(&identifier.kind)
            {
                let current: Option<ServerPolicy> =
                    get(&write.open_table(RUNTIME)?, &key(identifier.kind))?;
                if current.as_ref() == Some(policy)
                    && let Ok(pin) = crate::credentials::grants::accept_server_delivery::<B>(
                        &write,
                        self.model(),
                        policy,
                    )
                {
                    eligible = Some((
                        BindingState {
                            identity: claim.identity,
                            incarnation: identity.incarnation,
                            owner: record.owner,
                            identity_revision: identity.identity_revision,
                            authentication_revision: revision::<B>(&write, record.owner)?,
                            credential_epoch: principal.credential_epoch,
                            policy: policy.clone(),
                        },
                        pin,
                    ));
                }
            }
        }
        drop(table);
        let key_id = runtime.crypto.current_id().to_owned();
        let mut selected = None;
        // The same observable coalescing policy covers suppressed identifiers.
        // Stale bindings stay unusable until this response's original expiry;
        // checking availability must never decide whether a handle is reused.
        for row in write.open_table(CHALLENGES)?.iter()? {
            let (_, value) = row?;
            let prior: Challenge = local::decode(value.value())?;
            if prior.identifier_digest == admission[0].key
                && !prior.consumed
                && prior.expires_at > now
                && prior.generation == header.session_generation
                && selected.replace(prior).is_some()
            {
                return Err(local::corrupt("multiple current identifier challenges"));
            }
        }
        let mut previous = None;
        if let Some((binding, _)) = &eligible
            && let Some(id) =
                get::<Uuid>(&write.open_table(HEADS)?, binding.incarnation.as_bytes())?
        {
            previous = Some(id);
        }
        let challenge = if let Some(prior) = selected {
            prior
        } else {
            let id = Uuid::new_v4();
            let handle = super::proof_crypto::random_secret()?;
            let expires_at = now.checked_add(PROOF_MS).ok_or_else(unavailable)?;
            let result =
                json!({"status":"accepted","challenge":handle,"expires_at":expires_at.to_string()});
            let response = runtime.crypto.seal(
                &response_aad(&header, id),
                &Zeroizing::new(local::encode(&result)?),
            )?;
            let handle_digest = runtime.crypto.digest_with_key(
                &state.admission_key_id,
                "handle",
                &header.store_id,
                handle.as_bytes(),
            )?;
            let code = super::proof_crypto::random_code()?;
            let verifier = String::new();
            let mut c = Challenge {
                format: FORMAT.into(),
                id,
                generation: header.session_generation,
                operation: request.operation_id,
                source: Uuid::nil(),
                execution: Uuid::nil(),
                created_at: now,
                expires_at,
                binding: eligible.as_ref().map(|(binding, _)| binding.clone()),
                previous,
                key_id: key_id.clone(),
                verifier,
                nonce: Uuid::new_v4(),
                handle_digest: handle_digest.clone(),
                identifier_digest: admission[0].key.clone(),
                response,
                attempts: 0,
                consumed: false,
            };
            c.verifier = runtime.crypto.digest_with_key(
                &key_id,
                "code",
                &code_aad(&header, self.context.tenant, &c),
                code.as_bytes(),
            )?;
            if let Some((binding, pin)) = eligible {
                #[derive(Serialize)]
                struct Payload<'a> {
                    kind: Kind,
                    recipient: &'a str,
                    sender: Option<&'a str>,
                    code: &'a str,
                }
                let plaintext = Zeroizing::new(local::encode(&Payload {
                    kind: identifier.kind,
                    recipient: &identifier.value,
                    sender: binding.policy.sender.as_deref(),
                    code: &code,
                })?);
                let mut delivery = AuthDelivery {
                    challenge: id,
                    generation: header.session_generation,
                    payload: c.response.clone(),
                    expires_at,
                };
                delivery.payload = runtime.crypto.seal(
                    &delivery_aad(header.store_id, self.context.tenant, &delivery),
                    &plaintext,
                )?;
                c.source = Uuid::new_v4();
                let table = write.open_table(KV)?;
                let mut ws = Attempt::<_, B>::new(
                    |key: &[u8]| Ok(table.get(key)?.map(|v| v.value().to_vec())),
                    local::MUTATION_WORK_LIMIT,
                );
                if ws.record(c.source)?.is_some() {
                    return Err(unavailable());
                }
                let input = self.model().validate(
                    1004,
                    &serde_json::to_value(&delivery).map_err(local::storage)?,
                )?;
                let version = Uuid::new_v4();
                for (k, v) in crate::binding::headers(self.model(), c.source, &input, version)? {
                    if ws.get(&k)?.is_some() {
                        return Err(unavailable());
                    }
                    ws.put(k, Some(v))?;
                }
                ws.put(
                    Key::Record(c.source),
                    Some(StoredValue::Record(ModelRecord {
                        contract: 1004,
                        tenant: self.context.tenant,
                        owner: binding.owner,
                        created_at: now,
                        version,
                        input,
                        derived: None,
                    })),
                )?;
                let intents = crate::effects::prepare_auth_delivery(
                    &write,
                    &mut ws,
                    self.model(),
                    &header,
                    c.source,
                    request.operation_id,
                    binding.owner,
                    binding.credential_epoch,
                    pin,
                    &mut || Ok(Uuid::new_v4()),
                )?;
                c.execution = intents
                    .created()
                    .first()
                    .ok_or_else(unavailable)?
                    .execution_id;
                let batch = ws.finish()?;
                drop(ws);
                drop(table);
                self.publish_native(&write, &batch, abort)?;
                crate::effects::publish(&write, Some(intents), abort)?;
                write.open_table(HEADS)?.insert(
                    binding.incarnation.as_bytes().as_slice(),
                    local::encode(&id)?.as_slice(),
                )?;
            }
            write
                .open_table(CHALLENGES)?
                .insert(id.as_bytes().as_slice(), local::encode(&c)?.as_slice())?;
            write
                .open_table(HANDLES)?
                .insert(handle_digest.as_bytes(), local::encode(&id)?.as_slice())?;
            state.challenges += 1;
            c
        };
        let row = Receipt {
            admission,
            format: FORMAT.into(),
            operation: request.operation_id,
            generation: header.session_generation,
            key_id: key_id.clone(),
            recovery: runtime.crypto.digest_with_key(
                &key_id,
                "recovery",
                &request.operation_id,
                request.recovery_secret.as_bytes(),
            )?,
            fingerprint: runtime
                .crypto
                .digest_with_key(&key_id, "begin", &intent, b"")?,
            created_at: now,
            outcome: Outcome::Begin {
                challenge: challenge.id,
            },
        };
        save_receipt(&write, &mut state, &row)?;
        if abort == Some(usize::MAX) {
            return Err(Error::new("injected_abort", "proof receipt"));
        }
        before_commit()?;
        write.commit()?;
        if lose_ack {
            return Err(Error::new(
                "outcome_unknown",
                "recover original proof operation",
            ));
        }
        self.proof_status(
            runtime,
            &Status {
                operation_id: request.operation_id,
                recovery_secret: request.recovery_secret.clone(),
            },
        )
    }
    pub(crate) fn consume_proof(
        &self,
        runtime: &Runtime,
        request: &Consume,
        peer: &str,
    ) -> Result<Value> {
        self.consume_proof_controlled(runtime, request, peer, None, &mut || Ok(()), false)
    }
    pub(crate) fn consume_proof_controlled(
        &self,
        runtime: &Runtime,
        request: &Consume,
        peer: &str,
        abort: Option<usize>,
        before_commit: &mut dyn FnMut() -> Result<()>,
        lose_ack: bool,
    ) -> Result<Value> {
        request.validate()?;
        let now = crate::effects::now_millis()?;
        let write = self.begin_write()?;
        let header = header(&write)?;
        let intent = json!({"challenge":request.challenge.as_str()});
        if let Some(value) = receipt::<B>(
            &write,
            runtime,
            &header,
            request.operation_id,
            request.recovery_secret.as_bytes(),
            Some(("consume", intent.clone(), request.code.as_bytes())),
            now,
        )? {
            return Ok(value);
        }
        let mut state = state(&write)?;
        let admission = charge(&mut state, &runtime.crypto, peer, None, now)?;
        let digest = runtime.crypto.digest_with_key(
            &state.admission_key_id,
            "handle",
            &header.store_id,
            request.challenge.as_bytes(),
        )?;
        let id: Option<Uuid> = get(&write.open_table(HANDLES)?, digest.as_bytes())?;
        let mut outcome = Outcome::Invalid {
            challenge: None,
            spent: false,
        };
        if let Some(id) = id {
            let mut c: Challenge =
                get(&write.open_table(CHALLENGES)?, id.as_bytes())?.ok_or_else(unavailable)?;
            if c.attempts < 5 && challenge_current::<B>(&write, &header, &c, now, false)? {
                c.attempts += 1;
                outcome = Outcome::Invalid {
                    challenge: Some(c.id),
                    spent: true,
                };
                if runtime.crypto.verify_digest_with_key(
                    &c.key_id,
                    "code",
                    &code_aad(&header, self.context.tenant, &c),
                    request.code.as_bytes(),
                    &c.verifier,
                )? {
                    let binding = c.binding.as_ref().ok_or_else(unavailable)?;
                    let table = write.open_table(KV)?;
                    let mut ws = Attempt::<_, B>::new(
                        |key: &[u8]| Ok(table.get(key)?.map(|v| v.value().to_vec())),
                        local::MUTATION_WORK_LIMIT,
                    );
                    let mut record = ws.record(binding.identity)?.ok_or_else(unavailable)?;
                    let (_, identity) = B::identity_values(&record)?;
                    let mut identity = identity.clone();
                    identity.verified_revision = Some(identity.identity_revision);
                    identity.verified_at = Some(now);
                    record.derived = Some(
                        serde_json::from_value(
                            serde_json::to_value(identity).map_err(local::storage)?,
                        )
                        .map_err(local::storage)?,
                    );
                    record.version = Uuid::new_v4();
                    ws.put(
                        Key::Record(binding.identity),
                        Some(StoredValue::Record(record)),
                    )?;
                    let batch = ws.finish()?;
                    drop(ws);
                    drop(table);
                    self.publish_native(&write, &batch, abort)?;
                    let at = u64::try_from(now / 1000).map_err(|_| unavailable())?;
                    outcome = Outcome::Issued {
                        challenge: id,
                        issuance: Issuance {
                            key_id: runtime.active_signing_key.clone(),
                            claims: Claims {
                                iss: runtime.identity.issuer.clone(),
                                aud: runtime.identity.audience.clone(),
                                sub: binding.owner,
                                tenant: self.context.tenant,
                                epoch: binding.credential_epoch,
                                generation: header.session_generation,
                                iat: at,
                                nbf: at,
                                exp: at.checked_add(900).ok_or_else(unavailable)?,
                            },
                        },
                    };
                    c.consumed = true;
                }
                write
                    .open_table(CHALLENGES)?
                    .insert(id.as_bytes().as_slice(), local::encode(&c)?.as_slice())?;
            }
        }
        let key_id = runtime.crypto.current_id().to_owned();
        let row = Receipt {
            admission,
            format: FORMAT.into(),
            operation: request.operation_id,
            generation: header.session_generation,
            key_id: key_id.clone(),
            recovery: runtime.crypto.digest_with_key(
                &key_id,
                "recovery",
                &request.operation_id,
                request.recovery_secret.as_bytes(),
            )?,
            fingerprint: runtime.crypto.digest_with_key(
                &key_id,
                "consume",
                &intent,
                request.code.as_bytes(),
            )?,
            created_at: now,
            outcome,
        };
        save_receipt(&write, &mut state, &row)?;
        if abort == Some(usize::MAX) {
            return Err(Error::new("injected_abort", "proof receipt"));
        }
        before_commit()?;
        write.commit()?;
        if lose_ack {
            return Err(Error::new(
                "outcome_unknown",
                "recover original proof operation",
            ));
        }
        self.proof_status(
            runtime,
            &Status {
                operation_id: request.operation_id,
                recovery_secret: request.recovery_secret.clone(),
            },
        )
    }
    pub(crate) fn proof_status(&self, runtime: &Runtime, request: &Status) -> Result<Value> {
        request.validate()?;
        let write = self.begin_write()?;
        let header = header(&write)?;
        receipt::<B>(
            &write,
            runtime,
            &header,
            request.operation_id,
            request.recovery_secret.as_bytes(),
            None,
            crate::effects::now_millis()?,
        )?
        .ok_or_else(unavailable)
    }
}

pub(crate) fn check_delivery_origin<B: Binding>(
    read: &ReadTransaction,
    row: &Execution<B>,
) -> Result<()> {
    let delivery = B::auth_delivery(&row.request).ok_or_else(unavailable)?;
    let c: Challenge = get(&read.open_table(CHALLENGES)?, delivery.challenge.as_bytes())?
        .ok_or_else(unavailable)?;
    let binding = c.binding.as_ref().ok_or_else(unavailable)?;
    let receipt: Receipt =
        get(&read.open_table(RECEIPTS)?, c.operation.as_bytes())?.ok_or_else(unavailable)?;
    if c.source != row.source
        || c.execution != row.id
        || c.operation != row.operation_id
        || binding.owner != row.requester
        || binding.credential_epoch != row.credential_epoch
        || c.generation != delivery.generation
        || c.expires_at != delivery.expires_at
        || row
            .email_binding
            .as_ref()
            .and_then(|pin| pin.server_policy())
            != Some(&binding.policy)
        || !matches!(receipt.outcome,Outcome::Begin{challenge} if challenge==c.id)
    {
        return Err(local::corrupt("private delivery origin"));
    }
    Ok(())
}

/// Inventory is reconstructed from immutable origin receipts and delivery sources;
/// counters and current-head caches are never accepted as their own oracle.
pub(crate) fn check<B: Binding>(
    read: &ReadTransaction,
    header: &RuntimeHeader,
    records: &BTreeMap<Uuid, ModelRecord<B>>,
) -> Result<()> {
    let require = |ok: bool| {
        if ok {
            Ok(())
        } else {
            Err(local::corrupt("private proof inventory"))
        }
    };
    for (def, limit) in TABLES {
        require(read.open_table(def)?.len()? <= limit as u64)?;
    }
    let mut challenges = BTreeMap::<Uuid, Challenge>::new();
    let mut handles = BTreeMap::new();
    for row in read.open_table(CHALLENGES)?.iter()? {
        let (key, value) = row?;
        let c: Challenge = local::decode(value.value())?;
        require(
            B::identity_enabled()
                && c.format == FORMAT
                && !c.id.is_nil()
                && !c.generation.is_nil()
                && c.id.as_bytes() == key.value()
                && local::encode(&c)? == value.value()
                && c.created_at >= 0
                && c.created_at.checked_add(PROOF_MS) == Some(c.expires_at)
                && c.attempts <= 5
                && valid_digest(&c.verifier)
                && valid_digest(&c.handle_digest)
                && valid_digest(&c.identifier_digest)
                && !c.nonce.is_nil(),
        )?;
        c.response.validate()?;
        if let Some(binding) = &c.binding {
            binding.policy.validate()?;
            require(
                !c.source.is_nil()
                    && !c.execution.is_nil()
                    && !binding.identity.is_nil()
                    && !binding.owner.is_nil()
                    && !binding.incarnation.is_nil()
                    && binding.identity_revision > 0
                    && binding.authentication_revision >= binding.identity_revision,
            )?;
            let source = records
                .get(&c.source)
                .ok_or_else(|| local::corrupt("private delivery source missing"))?;
            let delivery = B::auth_delivery(&source.input)
                .ok_or_else(|| local::corrupt("private delivery type"))?;
            require(
                delivery.challenge == c.id
                    && source.owner == binding.owner
                    && source.created_at == c.created_at
                    && source.contract == 1004
                    && delivery.generation == c.generation
                    && delivery.expires_at == c.expires_at,
            )?;
            let execution: Execution<B> = get(
                &read.open_table(crate::effects::EXECUTIONS)?,
                c.execution.as_bytes(),
            )?
            .ok_or_else(|| local::corrupt("private delivery execution missing"))?;
            check_delivery_origin(read, &execution)?;
        } else {
            require(
                c.source.is_nil()
                    && c.execution.is_nil()
                    && c.attempts == 0
                    && !c.consumed
                    && c.previous.is_none(),
            )?;
        }
        require(handles.insert(c.handle_digest.clone(), c.id).is_none())?;
        challenges.insert(c.id, c);
    }
    let mut actual_handles = BTreeMap::new();
    for row in read.open_table(HANDLES)?.iter()? {
        let (k, v) = row?;
        actual_handles.insert(
            String::from_utf8(k.value().to_vec()).map_err(local::storage)?,
            local::decode::<Uuid>(v.value())?,
        );
    }
    require(actual_handles == handles)?;
    let mut expected_heads = BTreeMap::new();
    let mut predecessors = BTreeSet::new();
    for c in challenges.values() {
        if let Some(b) = &c.binding
            && let Some(previous) = c.previous
        {
            let prior = challenges
                .get(&previous)
                .ok_or_else(|| local::corrupt("missing prior challenge"))?;
            require(
                previous != c.id
                    && predecessors.insert(previous)
                    && prior.created_at <= c.created_at
                    && prior
                        .binding
                        .as_ref()
                        .is_some_and(|p| p.incarnation == b.incarnation),
            )?;
        }
    }
    for c in challenges.values() {
        if let Some(b) = &c.binding
            && !predecessors.contains(&c.id)
        {
            require(expected_heads.insert(b.incarnation, c.id).is_none())?;
        }
    }
    let incarnations: BTreeSet<_> = challenges
        .values()
        .filter_map(|c| c.binding.as_ref().map(|b| b.incarnation))
        .collect();
    require(expected_heads.keys().copied().collect::<BTreeSet<_>>() == incarnations)?;
    let mut reached = BTreeSet::new();
    for head in expected_heads.values() {
        let mut next = Some(*head);
        while let Some(id) = next {
            require(reached.insert(id))?;
            next = challenges
                .get(&id)
                .ok_or_else(|| local::corrupt("challenge chain"))?
                .previous;
        }
    }
    require(reached.len() == challenges.values().filter(|c| c.binding.is_some()).count())?;
    let mut heads = BTreeSet::new();
    for row in read.open_table(HEADS)?.iter()? {
        let (k, v) = row?;
        let id: Uuid = local::decode(v.value())?;
        let c = challenges
            .get(&id)
            .ok_or_else(|| local::corrupt("private challenge head"))?;
        require(
            c.binding
                .as_ref()
                .is_some_and(|b| b.incarnation.as_bytes() == k.value()),
        )?;
        heads.insert(id);
    }
    require(heads == expected_heads.values().copied().collect())?;
    let mut attempts = BTreeMap::<Uuid, usize>::new();
    let mut consumed = BTreeSet::new();
    let mut origins = BTreeSet::new();
    let mut receipts = 0;
    let mut admission = Vec::new();
    let mut admission_domains = BTreeMap::<(u8, String), Vec<i64>>::new();
    let mut spent_at = BTreeMap::<Uuid, Vec<i64>>::new();
    let mut issued_at = BTreeMap::<Uuid, i64>::new();
    let mut verified = BTreeMap::<(Uuid, Uuid, u64), i64>::new();
    for row in read.open_table(RECEIPTS)?.iter()? {
        let (k, v) = row?;
        let r: Receipt = local::decode(v.value())?;
        receipts += 1;
        require(
            r.admission.len()
                == if matches!(r.outcome, Outcome::Begin { .. }) {
                    2
                } else {
                    1
                },
        )?;
        for (index, point) in r.admission.iter().enumerate() {
            require(
                point.at == r.created_at
                    && valid_digest(&point.key)
                    && point.consume != matches!(r.outcome, Outcome::Begin { .. }),
            )?;
            // Position distinguishes identifier, begin-peer and consume-peer
            // domains without accepting the writer's retained-point cache.
            let domain = if matches!(r.outcome, Outcome::Begin { .. }) {
                index as u8
            } else {
                2
            };
            admission_domains
                .entry((domain, point.key.clone()))
                .or_default()
                .push(point.at);
        }
        admission.extend(r.admission.clone());
        require(
            r.format == FORMAT
                && r.operation.as_bytes() == k.value()
                && !r.operation.is_nil()
                && !r.generation.is_nil()
                && r.created_at >= 0
                && valid_digest(&r.recovery)
                && valid_digest(&r.fingerprint)
                && local::encode(&r)? == v.value(),
        )?;
        match r.outcome {
            Outcome::Begin { challenge } => {
                let c = challenges
                    .get(&challenge)
                    .ok_or_else(|| local::corrupt("private begin challenge"))?;
                require(
                    c.generation == r.generation
                        && c.created_at <= r.created_at
                        && r.created_at < c.expires_at
                        && c.identifier_digest == r.admission[0].key,
                )?;
                if c.operation == r.operation {
                    require(c.created_at == r.created_at)?;
                    origins.insert(c.id);
                }
            }
            Outcome::Invalid { challenge, spent } => {
                require(spent == challenge.is_some())?;
                if let Some(id) = challenge {
                    let c = challenges
                        .get(&id)
                        .ok_or_else(|| local::corrupt("private attempt challenge"))?;
                    require(
                        c.binding.is_some()
                            && c.generation == r.generation
                            && c.created_at <= r.created_at
                            && r.created_at < c.expires_at,
                    )?;
                    *attempts.entry(id).or_default() += 1;
                    spent_at.entry(id).or_default().push(r.created_at);
                }
            }
            Outcome::Issued {
                challenge,
                issuance,
            } => {
                let c = challenges
                    .get(&challenge)
                    .ok_or_else(|| local::corrupt("private issuance challenge"))?;
                let b = c
                    .binding
                    .as_ref()
                    .ok_or_else(|| local::corrupt("suppressed issuance"))?;
                require(
                    consumed.insert(challenge)
                        && c.generation == r.generation
                        && c.created_at <= r.created_at
                        && r.created_at < c.expires_at
                        && issuance.claims.generation == c.generation
                        && issuance.claims.sub == b.owner
                        && issuance.claims.tenant
                            == records
                                .get(&c.source)
                                .ok_or_else(|| local::corrupt("issuance source"))?
                                .tenant
                        && issuance.claims.epoch == b.credential_epoch
                        && issuance.claims.nbf == issuance.claims.iat
                        && issuance.claims.iat == r.created_at as u64 / 1000
                        && issuance.claims.iat.checked_add(900) == Some(issuance.claims.exp),
                )?;
                *attempts.entry(challenge).or_default() += 1;
                issued_at.insert(challenge, r.created_at);
                verified
                    .entry((b.identity, b.incarnation, b.identity_revision))
                    .and_modify(|time| *time = (*time).max(r.created_at))
                    .or_insert(r.created_at);
            }
        }
    }
    require(origins.len() == challenges.len())?;
    for c in challenges.values() {
        require(
            c.attempts as usize == *attempts.get(&c.id).unwrap_or(&0)
                && c.consumed == consumed.contains(&c.id),
        )?;
        if let Some(issued) = issued_at.get(&c.id) {
            // Equal millisecond timestamps do not establish transaction order,
            // but a strictly later spent attempt cannot follow consumption.
            require(
                spent_at
                    .get(&c.id)
                    .is_none_or(|times| times.iter().all(|at| at <= issued)),
            )?;
        }
    }
    for (id, record) in records {
        if B::identity_input(&record.input).is_some() {
            let (_, identity) = B::identity_values(record)?;
            let time = verified
                .get(&(*id, identity.incarnation, identity.identity_revision))
                .copied();
            require(
                identity.verified_at == time
                    && identity.verified_revision == time.map(|_| identity.identity_revision),
            )?;
        }
        if let Some(delivery) = B::auth_delivery(&record.input) {
            require(
                challenges
                    .get(&delivery.challenge)
                    .is_some_and(|c| c.source == *id),
            )?;
        }
    }
    for ((domain, _), mut times) in admission_domains {
        let (window, limit) = match domain {
            0 => (PROOF_MS, 3),
            1 => (60_000, 32),
            _ => (60_000, 64),
        };
        times.sort_unstable();
        let mut left = 0;
        for right in 0..times.len() {
            while times[left] <= times[right].saturating_sub(window) {
                left += 1;
            }
            require(right - left < limit)?;
        }
    }
    let runtime = read.open_table(RUNTIME)?;
    if let Some(state) = get::<State>(&runtime, b"state")? {
        require(admission.iter().all(|point| point.at <= state.last_at))?;
        admission.retain(|p| p.at > state.last_at.saturating_sub(PROOF_MS));
        admission.sort();
        let mut actual = state.points.clone();
        actual.sort();
        require(actual == admission)?;
        require(
            state.format == FORMAT
                && state.last_at >= 0
                && state.challenges as usize == challenges.len()
                && state.receipts == receipts
                && state.points.len() <= MAX_RECEIPTS * 2
                && !state.admission_key_id.is_empty(),
        )?;
        for point in state.points {
            require(point.at >= 0 && point.at <= state.last_at && valid_digest(&point.key))?;
        }
    } else {
        require(challenges.is_empty() && receipts == 0 && runtime.len()? == 0)?;
    }
    for row in runtime.iter()? {
        let (k, v) = row?;
        if k.value() == b"state" {
            continue;
        }
        let p: ServerPolicy = local::decode(v.value())?;
        p.validate()?;
        require(k.value() == key(p.kind))?;
    }
    // Old generations are legitimate historical inventory after supported restore;
    // they are rejected by transaction-scoped preflight and proof recovery.
    require(!header.session_generation.is_nil())
}
