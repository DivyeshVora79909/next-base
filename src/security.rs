//! Embedded authority persistence. No token parsing or domain calculation here.
#[cfg(test)]
mod session_tests;

use crate::binding::Binding;
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::storage::{ReadTransaction, ReadableTable, TableDefinition, WriteTransaction};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use uuid::Uuid;

use crate::{
    access::{Graph, PreparedGraph, Scope, denied},
    local::{CommittedValue, KV, Store, corrupt, decode, encode, storage},
    model::Prepared,
    native_codec::{self, Key, StoredValue, decimal},
    native_slice::{Attempt, Context, Error, ModelRecord, Result},
};

pub(crate) const AUTHORITY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("authority");
pub(crate) const OWNERS: TableDefinition<&[u8], u16> = TableDefinition::new("owner_records");
pub(crate) const GRAPH: &[u8] = b"graph";
pub(crate) const REVISION: &[u8] = b"revision";

/// Graph CAS counter, advanced by operator changes and internal session revocation.
pub(crate) fn authority_revision(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<u64> {
    let bytes = table
        .get(REVISION)?
        .ok_or_else(|| corrupt("missing authority revision"))?;
    let revision: u64 = decode(bytes.value())?;
    if encode(&revision)? != bytes.value() {
        return Err(corrupt("noncanonical authority revision"));
    }
    Ok(revision)
}

fn operation_mac(
    header: &crate::local::RuntimeHeader,
    context: Context,
    model: &str,
) -> Result<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&crate::local::unhex(&header.cursor_key)?)
        .map_err(|_| corrupt("operation context key"))?;
    mac.update(b"rebase-operation-context-1\0");
    mac.update(header.store_id.as_bytes());
    mac.update(&header.operation_epoch.to_be_bytes());
    mac.update(context.tenant.as_bytes());
    mac.update(context.actor.as_bytes());
    mac.update(model.as_bytes());
    Ok(mac)
}
pub(crate) fn operation_context(
    header: &crate::local::RuntimeHeader,
    context: Context,
    model: &str,
) -> Result<String> {
    Ok(native_codec::hex(
        &operation_mac(header, context, model)?
            .finalize()
            .into_bytes(),
    ))
}
pub(crate) fn check_operation_context(
    tag: &str,
    header: &crate::local::RuntimeHeader,
    context: Context,
    model: &str,
) -> Result<()> {
    let expired = || {
        Error::new(
            "operation_expired",
            "request context differs; reconcile using its archive, never refresh an uncertain request",
        )
    };
    if tag.len() != 64 {
        return Err(expired());
    }
    operation_mac(header, context, model)?
        .verify_slice(&crate::local::unhex(tag).map_err(|_| expired())?)
        .map_err(|_| expired())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaceGraph {
    pub model: String,
    #[serde(with = "decimal")]
    pub if_revision: u64,
    pub graph: Graph,
}

fn scope_key(actor: Uuid) -> Vec<u8> {
    let mut key = vec![b's'];
    key.extend_from_slice(actor.as_bytes());
    key
}

pub(crate) fn owner_key(owner: Uuid, contract: u16, id: Uuid) -> Vec<u8> {
    [
        owner.as_bytes().as_slice(),
        contract.to_be_bytes().as_slice(),
        id.as_bytes().as_slice(),
    ]
    .concat()
}

fn load_scope(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    actor: Uuid,
) -> Result<Scope> {
    let bytes = table
        .get(scope_key(actor).as_slice())
        .map_err(storage)?
        .ok_or_else(denied)?;
    decode(bytes.value())
}

pub(crate) fn read_graph(read: &crate::storage::ReadTransaction) -> Result<PreparedGraph> {
    let table = read.open_table(AUTHORITY)?;
    let bytes = table
        .get(GRAPH)?
        .ok_or_else(|| corrupt("missing principal graph"))?;
    let graph: Graph = decode(bytes.value())?;
    graph
        .prepare()
        .map_err(|_| corrupt("invalid principal graph"))
}
pub(crate) fn write_graph(write: &WriteTransaction) -> Result<PreparedGraph> {
    let table = write.open_table(AUTHORITY).map_err(storage)?;
    let bytes = table
        .get(GRAPH)
        .map_err(storage)?
        .ok_or_else(|| corrupt("missing principal graph"))?;
    let graph: Graph = decode(bytes.value())?;
    graph
        .prepare()
        .map_err(|_| corrupt("invalid principal graph"))
}

pub(crate) fn store_graph(write: &WriteTransaction, graph: &PreparedGraph) -> Result<()> {
    let mut table = write.open_table(AUTHORITY).map_err(storage)?;
    if table.get(REVISION)?.is_none() {
        table.insert(REVISION, encode(&0_u64)?.as_slice())?;
    }
    table
        .insert(GRAPH, encode(&graph.graph)?.as_slice())
        .map_err(storage)?;
    for (&id, scope) in &graph.scopes {
        table
            .insert(scope_key(id).as_slice(), encode(scope)?.as_slice())
            .map_err(storage)?;
    }
    Ok(())
}

pub(crate) fn write_header(write: &WriteTransaction) -> Result<crate::local::RuntimeHeader> {
    let table = write.open_table(crate::local::RUNTIME)?;
    let header = decode(
        table
            .get(crate::local::HEADER)?
            .ok_or_else(|| corrupt("missing runtime header"))?
            .value(),
    )?;
    crate::local::validate_header(&header)?;
    Ok(header)
}

/// Derive revocations from old and final source lifetimes after every client
/// command passed final authorization. Verification-only changes are excluded.
pub(crate) fn identity_revocation_owners<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
) -> Result<BTreeSet<Uuid>> {
    let mut owners = BTreeSet::new();
    if !B::identity_enabled() {
        return Ok(owners);
    }
    for id in ws.changed_records() {
        let Some(StoredValue::Record(original)) = ws.original(&Key::Record(id))? else {
            continue;
        };
        if B::identity_input(&original.input).is_none() {
            continue;
        }
        let (_, old) = B::identity_values(&original)?;
        let current = ws.record(id)?;
        let unchanged = current
            .as_ref()
            .filter(|row| B::identity_input(&row.input).is_some())
            .map(B::identity_values)
            .transpose()?
            .is_some_and(|(_, state)| {
                state.incarnation == old.incarnation
                    && state.identity_revision == old.identity_revision
            });
        if !unchanged {
            owners.insert(original.owner);
        }
    }
    Ok(owners)
}

/// Internal revocation writes share the already-authorized mutation transaction;
/// they never authorize another client mutation or rewrite source population.
pub(crate) fn stage_credential_revocations(
    write: &WriteTransaction,
    owners: &BTreeSet<Uuid>,
) -> Result<()> {
    if owners.is_empty() {
        return Ok(());
    }
    let mut graph = write_graph(write)?.graph;
    for owner in owners {
        let principal = graph
            .principals
            .iter_mut()
            .find(|principal| principal.id == *owner)
            .filter(|principal| principal.kind == crate::access::PrincipalKind::User)
            .ok_or_else(|| corrupt("revoked identity owner is not a User"))?;
        principal.credential_epoch = principal
            .credential_epoch
            .checked_add(1)
            .ok_or_else(|| Error::new("revision_exhausted", "credential epoch"))?;
    }
    let revision = authority_revision(&write.open_table(AUTHORITY)?)?
        .checked_add(1)
        .ok_or_else(|| Error::new("revision_exhausted", "authority counter"))?;
    store_graph(write, &graph.prepare()?)?;
    write
        .open_table(AUTHORITY)?
        .insert(REVISION, encode(&revision)?.as_slice())?;
    Ok(())
}

fn advance_authentication_revisions<B: Binding>(
    write: &WriteTransaction,
    owners: &BTreeSet<Uuid>,
) -> Result<()> {
    if owners.is_empty() || !B::identity_enabled() {
        return Ok(());
    }
    let mut table = write.open_table(KV)?;
    for owner in owners {
        let key = Key::AuthenticationRevision(*owner);
        let previous = table
            .get(key.encode())?
            .map(|bytes| native_codec::decode_for::<B>(&key, bytes.value()))
            .transpose()?;
        let previous = match previous {
            None => 0,
            Some(StoredValue::AuthenticationRevision(value)) => value.revision,
            _ => return Err(corrupt("principal authentication revision role")),
        };
        // An operator login toggle must not repair missing/regressed proof
        // history. Protect this owner's Identity range, including its absence.
        let identity = crate::models::services::IDENTITY;
        let lower = owner_key(*owner, identity, Uuid::nil());
        let upper = owner_key(*owner, identity, Uuid::from_u128(u128::MAX));
        for row in write
            .open_table(OWNERS)?
            .range(lower.as_slice()..=upper.as_slice())?
        {
            let (address, contract) = row?;
            if address.value().len() != 34 || contract.value() != identity {
                return Err(corrupt("identity owner index"));
            }
            let source_id = Uuid::from_slice(&address.value()[18..])
                .map_err(|_| corrupt("identity owner index"))?;
            let source_key = Key::Record(source_id);
            let bytes = table
                .get(source_key.encode())?
                .ok_or_else(|| corrupt("identity owner source missing"))?;
            let StoredValue::Record(source) =
                native_codec::decode_for::<B>(&source_key, bytes.value())?
            else {
                return Err(corrupt("identity owner source role"));
            };
            let (_, state) = B::identity_values(&source)?;
            if source.owner != *owner || previous < state.identity_revision {
                return Err(corrupt(
                    "identity authentication revision missing or regressed",
                ));
            }
        }
        let revision = previous
            .checked_add(1)
            .ok_or_else(|| Error::new("revision_exhausted", "principal authentication revision"))?;
        let bytes = native_codec::encode_for::<B>(
            &key,
            &StoredValue::AuthenticationRevision(
                crate::authentication::types::AuthenticationRevision { revision },
            ),
        )?;
        table.insert(key.encode().as_slice(), bytes.as_slice())?;
    }
    Ok(())
}

pub(crate) fn update_owner_index<B: Binding>(
    write: &WriteTransaction,
    native: &impl ReadableTable<&'static [u8], &'static [u8]>,
    model: &Prepared<B>,
    id: Uuid,
    new: Option<&[u8]>,
) -> Result<()> {
    let record = |bytes: &[u8]| -> Result<Option<ModelRecord<B>>> {
        match native_codec::decode_for::<B>(&Key::Record(id), bytes)? {
            StoredValue::Record(r)
                if model.contract(r.contract)?.visibility == crate::model::Visibility::Public =>
            {
                Ok(Some(r))
            }
            StoredValue::Record(_) => Ok(None),
            _ => Err(corrupt("record index type")),
        }
    };
    let old = native
        .get(Key::Record(id).encode().as_slice())
        .map_err(storage)?
        .map(|b| record(b.value()))
        .transpose()?
        .flatten();
    let new = new.map(record).transpose()?.flatten();
    let entry = |r: &ModelRecord<B>| (owner_key(r.owner, r.contract, id), r.contract);
    let old = old.as_ref().map(entry);
    let new = new.as_ref().map(entry);
    if old != new {
        let mut table = write.open_table(OWNERS).map_err(storage)?;
        if let Some((key, _)) = old {
            table.remove(key.as_slice()).map_err(storage)?;
        }
        if let Some((key, code)) = new {
            table.insert(key.as_slice(), code).map_err(storage)?;
        }
    }
    Ok(())
}

impl<B: Binding> Store<B> {
    pub fn operation_context(&self, model: &str) -> Result<String> {
        let (read, _, header) = self.read(model)?;
        self.authority(&read)?;
        operation_context(&header, self.context, model)
    }
    pub fn create_secured(
        path: impl AsRef<std::path::Path>,
        model: Arc<Prepared<B>>,
        context: Context,
    ) -> Result<Self> {
        Self::create_backend_secured(Self::create_redb_database(path)?, model, context)
    }

    /// Trusted identity-adapter seam. Network code must verify a credential
    /// before constructing this session. Current authority is checked per call.
    pub fn session(&self, actor: Uuid, credential_epoch: u64) -> Result<Self> {
        if !self.secured {
            return Err(Error::new("invalid_input", "authenticated store required"));
        }
        Ok(Self {
            db: self.db.clone(),
            model: self.model.clone(),
            context: Context {
                tenant: self.context.tenant,
                actor,
            },
            bootstrap_actor: self.bootstrap_actor,
            secured: true,
            credential_epoch: Some(credential_epoch),
            issued_at: None,
            session_generation: None,
            expected_store: self.expected_store,
            credentials: self.credentials.clone(),
            authentication: self.authentication.clone(),
        })
    }

    fn check_scope(&self, scope: Scope) -> Result<Scope> {
        if scope.tenant != self.context.tenant || scope.actor != self.context.actor {
            return Err(corrupt("principal scope binding"));
        }
        scope.require_active()?;
        if self
            .credential_epoch
            .is_some_and(|e| e != scope.credential_epoch)
        {
            return Err(denied());
        }
        Ok(scope)
    }

    pub(crate) fn authority(&self, read: &ReadTransaction) -> Result<Scope> {
        if !self.secured {
            return Ok(Scope::local(self.context));
        }
        self.check_session_generation(&crate::local::read_header(read)?)?;
        self.check_scope(load_scope(
            &read.open_table(AUTHORITY).map_err(storage)?,
            self.context.actor,
        )?)
    }

    pub(crate) fn write_authority(&self, write: &WriteTransaction) -> Result<Scope> {
        if !self.secured {
            return Ok(Scope::local(self.context));
        }
        self.check_session_generation(&write_header(write)?)?;
        self.check_scope(load_scope(
            &write.open_table(AUTHORITY).map_err(storage)?,
            self.context.actor,
        )?)
    }

    fn check_session_generation(&self, header: &crate::local::RuntimeHeader) -> Result<()> {
        if self
            .session_generation
            .is_some_and(|generation| generation != header.session_generation)
        {
            return Err(denied());
        }
        Ok(())
    }

    pub(crate) fn receipt_key(&self, operation: Uuid) -> Vec<u8> {
        if self.secured {
            [
                self.context.actor.as_bytes().as_slice(),
                operation.as_bytes().as_slice(),
            ]
            .concat()
        } else {
            operation.as_bytes().to_vec()
        }
    }

    pub(crate) fn disclose<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        &self,
        scope: &Scope,
        mut result: CommittedValue<B>,
        ws: &mut Attempt<L, B>,
    ) -> Result<CommittedValue<B>> {
        if self.secured {
            for returned in &mut result.records {
                let current = self.project(scope, returned.id, ws.record(returned.id)?);
                if !matches!((&returned.record, current), (Some(old), Some(now)) if old.version == now.version)
                {
                    returned.record = None;
                }
            }
        }
        Ok(result)
    }

    pub(crate) fn disclose_result<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        &self,
        scope: &Scope,
        result: crate::local::ReceiptResult<B>,
        ws: &mut Attempt<L, B>,
    ) -> Result<Value> {
        match result {
            crate::local::ReceiptResult::Records(result) => {
                let mut result = self.disclose(scope, result, ws)?;
                let mut visible = vec![];
                for execution in result.executions {
                    if ws
                        .record(execution.target)?
                        .is_some_and(|r| scope.can_read(&r))
                    {
                        visible.push(execution);
                    }
                }
                result.executions = visible;
                serde_json::to_value(result).map_err(storage)
            }
            crate::local::ReceiptResult::Cancel(result) => {
                if ws
                    .record(result.target)?
                    .is_some_and(|r| scope.can_read(&r))
                {
                    serde_json::to_value(result).map_err(storage)
                } else {
                    Ok(Value::Null)
                }
            }
        }
    }

    pub fn access_graph(&self, model: &str) -> Result<Value> {
        let (read, _, _) = self.read(model)?;
        if !self.secured || !self.authority(&read)?.grants.admin {
            return Err(denied());
        }
        let table = read.open_table(AUTHORITY).map_err(storage)?;
        let graph: Graph = decode(
            table
                .get(GRAPH)
                .map_err(storage)?
                .ok_or_else(|| corrupt("missing graph"))?
                .value(),
        )?;
        Ok(json!({"revision":authority_revision(&table)?.to_string(),"graph":graph}))
    }

    /// Separate compare-and-set administration. No domain batch can grant its
    /// own permissions. Unknown outcomes are reconciled by reading the graph.
    pub fn replace_access(&self, request: &ReplaceGraph) -> Result<Value> {
        if !self.secured {
            return Err(denied());
        }
        let write = self.begin_write().map_err(storage)?;
        if !self.write_authority(&write)?.grants.admin {
            return Err(denied());
        }
        let native = write.open_table(KV).map_err(storage)?;
        let meta = match native_codec::decode_for::<B>(
            &Key::Meta,
            native
                .get(Key::Meta.encode().as_slice())
                .map_err(storage)?
                .ok_or_else(|| corrupt("missing meta"))?
                .value(),
        )? {
            StoredValue::Meta(meta) => meta,
            _ => return Err(corrupt("meta type")),
        };
        self.check_meta(&meta, &request.model)?;
        let revision = authority_revision(&write.open_table(AUTHORITY)?)?;
        if revision != request.if_revision {
            return Err(Error::new("stale_version", "authority revision changed"));
        }
        if request.graph.tenant != meta.tenant {
            return Err(denied());
        }
        let mut graph = request.graph.clone().prepare()?;
        for p in &graph.graph.principals {
            for &code in p.grants.contracts.keys() {
                self.model.public_contract(code)?;
            }
        }
        let old = write_graph(&write)?;
        let mut login_changes = BTreeSet::new();
        for p in &old.graph.principals {
            let next = graph
                .graph
                .principals
                .iter_mut()
                .find(|n| n.id == p.id)
                .ok_or_else(|| {
                    Error::new(
                        "invalid_input",
                        "disable principals instead of deleting identities",
                    )
                })?;
            if p.kind != next.kind
                || next.credential_epoch < p.credential_epoch
                || (!p.active && next.active && next.credential_epoch == p.credential_epoch)
            {
                return Err(Error::new(
                    "invalid_input",
                    "principal identity/credential lifecycle",
                ));
            }
            if p.login_access != next.login_access {
                let revoked = p
                    .credential_epoch
                    .checked_add(1)
                    .ok_or_else(|| Error::new("revision_exhausted", "credential epoch"))?;
                next.credential_epoch = next.credential_epoch.max(revoked);
                login_changes.insert(p.id);
            }
        }
        let graph = graph.graph.prepare()?;
        if old.graph == graph.graph {
            // FoundationDB does not validate conflict ranges for a read-only
            // commit. This administration-only same-value write makes the
            // graph CAS and authorization reads participate without advancing
            // the epoch or changing the logical image.
            write
                .open_table(AUTHORITY)?
                .insert(REVISION, encode(&revision)?.as_slice())?;
            drop(native);
            write.commit()?;
            return Ok(json!({"revision":revision.to_string(),"changed":false}));
        }
        let revision = revision
            .checked_add(1)
            .ok_or_else(|| Error::new("revision_exhausted", "authority counter"))?;
        drop(native);
        advance_authentication_revisions::<B>(&write, &login_changes)?;
        store_graph(&write, &graph)?;
        write
            .open_table(AUTHORITY)?
            .insert(REVISION, encode(&revision)?.as_slice())?;
        write.commit().map_err(storage)?;
        Ok(json!({"revision":revision.to_string(),"changed":true}))
    }
}
