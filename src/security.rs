//! Embedded authority persistence. No token parsing or domain calculation here.

use crate::binding::{Binding, NativeInput};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

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
pub(crate) const READERS: TableDefinition<&[u8], u16> = TableDefinition::new("reader_records");
const GRAPH: &[u8] = b"graph";
pub(crate) const REVISION: &[u8] = b"revision";

/// Administration-only CAS counter; domain mutations never rewrite it.
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

pub(crate) fn reader_key(reader: Uuid, contract: u16, id: Uuid) -> Vec<u8> {
    [
        reader.as_bytes().as_slice(),
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

/// Final-source preorder: resource owner, then reader references in catalog order.
/// Record cycles and diamond paths are visited once; scalar reader caches are unused.
/// Prepared catalogs prohibit public references to engine-private contracts, so
/// public discovery cannot encounter a managed output. Managed roots are repaired
/// separately by following their producer chain.
pub(crate) fn reader_candidates<B: Binding, L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    id: Uuid,
) -> Result<Vec<Uuid>> {
    let mut stack = vec![id];
    let mut seen = BTreeSet::new();
    let mut owners = BTreeSet::new();
    let mut candidates = Vec::new();
    while let Some(id) = stack.pop() {
        ws.charge("reader", 1)?;
        if !seen.insert(id) {
            continue;
        }
        let record = ws
            .record(id)?
            .ok_or_else(|| corrupt("missing reader reference"))?;
        if owners.insert(record.owner) {
            candidates.push(record.owner);
        }
        let contract = model.contract(record.contract)?;
        let references = record.input.references();
        let mut targets = Vec::new();
        for declaration in &contract.references {
            ws.charge("reader", 1)?;
            if declaration.reader {
                for &(target, _, slot) in &references {
                    ws.charge("reader", 1)?;
                    if slot == declaration.slot {
                        targets.push(target);
                    }
                }
            }
        }
        stack.extend(targets.into_iter().rev());
    }
    Ok(candidates)
}

// Authored provenance only: payload, derived values and selected-reader caches
// cannot change the reachable owner frontier.
type ReaderProvenance = (Uuid, Option<Uuid>, Vec<(u16, Uuid)>);

fn reader_provenance<B: Binding, L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    record: Option<&ModelRecord<B>>,
) -> Result<Option<ReaderProvenance>> {
    ws.charge("reader", 1)?;
    let Some(record) = record else {
        return Ok(None);
    };
    let mut references = Vec::new();
    let source = record.input.references();
    for declaration in &model.contract(record.contract)?.references {
        ws.charge("reader", 1)?;
        if declaration.reader {
            for &(target, _, slot) in &source {
                ws.charge("reader", 1)?;
                if slot == declaration.slot {
                    references.push((slot, target));
                }
            }
        }
    }
    Ok(Some((
        record.owner,
        record.input.managed().map(|(producer, _)| producer),
        references,
    )))
}

pub(crate) fn repair_readers<B: Binding, L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    mut ids: BTreeSet<Uuid>,
    revision: Uuid,
    select: &mut impl FnMut(&[Uuid], Uuid) -> Result<Uuid>,
) -> Result<()> {
    // Expand through final reverse references even when the selected scalar stays
    // equal: a hidden candidate may change a downstream minimal survivor.
    // Initial payload-only changes need repair, but cannot affect consumers.
    // Keep expansion visitation separate from ids: an initially payload-only
    // consumer can later be reached from a changed ancestor frontier.
    let mut pending = Vec::new();
    let mut enqueued = BTreeSet::new();
    for &id in &ids {
        let original = match ws.original(&Key::Record(id))? {
            Some(StoredValue::Record(record)) => Some(record),
            None => None,
            _ => return Err(corrupt("reader source record type")),
        };
        let current = ws.record(id)?;
        if reader_provenance(ws, model, original.as_ref())?
            != reader_provenance(ws, model, current.as_ref())?
        {
            enqueued.insert(id);
            pending.push(id);
        }
    }
    while let Some(id) = pending.pop() {
        ws.charge("reader", 1)?;
        let consumers = crate::routes::select(
            ws,
            &Key::Incoming(id),
            std::ops::Bound::Unbounded,
            std::ops::Bound::Unbounded,
            false,
        )?;
        for consumer in consumers {
            let record = ws
                .record(consumer.id)?
                .ok_or_else(|| corrupt("missing reader consumer"))?;
            if model
                .contract(record.contract)?
                .references
                .iter()
                .any(|r| r.slot == consumer.slot && r.reader)
                && enqueued.insert(consumer.id)
            {
                ids.insert(consumer.id);
                pending.push(consumer.id);
            }
        }
        if let Some(record) = ws.record(id)? {
            for output in &model.contract(record.contract)?.outputs {
                ws.charge("reader", 1)?;
                if let Some(StoredValue::Role(role)) = ws.get(&Key::Role(
                    crate::native_codec::Address::new(id, output.role),
                ))? && !role.retired
                    && ws.record(role.output)?.is_some()
                    && enqueued.insert(role.output)
                {
                    ids.insert(role.output);
                    pending.push(role.output);
                }
            }
        }
    }
    // Managed outputs inherit only after all public source readers are repaired.
    for private in [false, true] {
        for &id in &ids {
            let Some(mut record) = ws.record(id)? else {
                continue;
            };
            if record.input.managed().is_none()
                && model.contract(record.contract)?.visibility != crate::model::Visibility::Public
            {
                continue;
            }
            if record.input.managed().is_some() != private {
                continue;
            }
            let reader = if let Some((producer, _)) = record.input.managed() {
                let mut producer = producer;
                let mut visited = BTreeSet::new();
                loop {
                    ws.charge("reader", 1)?;
                    if !visited.insert(producer) {
                        return Err(corrupt("managed reader producer cycle"));
                    }
                    let source = ws
                        .record(producer)?
                        .ok_or_else(|| corrupt("missing output producer"))?;
                    if let Some((parent, _)) = source.input.managed() {
                        producer = parent;
                    } else {
                        break source.reader;
                    }
                }
            } else {
                let candidates = reader_candidates(ws, model, id)?;
                let count = u64::try_from(candidates.len())
                    .map_err(|_| Error::new("work_limit", "reader candidates"))?;
                let comparisons = count
                    .checked_add(1)
                    .and_then(|n| n.checked_mul(n))
                    .and_then(|n| n.checked_mul(2))
                    .ok_or_else(|| Error::new("work_limit", "reader comparisons"))?;
                ws.charge("reader", comparisons)?;
                select(&candidates, record.owner)?
            };
            if record.reader != reader {
                record.reader = reader;
                record.version = revision;
                ws.put(Key::Record(id), Some(StoredValue::Record(record)))?;
            }
        }
    }
    Ok(())
}

pub(crate) fn stored_reader(
    write: &WriteTransaction,
    owners: &[Uuid],
    fallback: Uuid,
    cache: &mut BTreeMap<Uuid, BTreeSet<Uuid>>,
) -> Result<Uuid> {
    let table = write.open_table(AUTHORITY).map_err(storage)?;
    let tenant = load_scope(&table, fallback)?.tenant;
    for owner in std::iter::once(fallback).chain(owners.iter().copied()) {
        if let std::collections::btree_map::Entry::Vacant(entry) = cache.entry(owner) {
            let scope = load_scope(&table, owner)?;
            if scope.tenant != tenant {
                return Err(corrupt("reader owner tenant"));
            }
            entry.insert(scope.descendants);
        }
    }
    Ok(crate::plan::choose_reader(owners, fallback, |a, b| {
        cache[&a].contains(&b)
    }))
}

pub(crate) fn update_reader_index<B: Binding>(
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
    let entry = |r: &ModelRecord<B>| (reader_key(r.reader, r.contract, id), r.contract);
    let old = old.as_ref().map(entry);
    let new = new.as_ref().map(entry);
    if old != new {
        let mut table = write.open_table(READERS).map_err(storage)?;
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
            expected_store: self.expected_store,
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
        self.check_scope(load_scope(
            &read.open_table(AUTHORITY).map_err(storage)?,
            self.context.actor,
        )?)
    }

    pub(crate) fn write_authority(&self, write: &WriteTransaction) -> Result<Scope> {
        if !self.secured {
            return Ok(Scope::local(self.context));
        }
        self.check_scope(load_scope(
            &write.open_table(AUTHORITY).map_err(storage)?,
            self.context.actor,
        )?)
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
        let graph = request.graph.clone().prepare()?;
        for p in &graph.graph.principals {
            for &code in p.grants.contracts.keys() {
                self.model.public_contract(code)?;
            }
        }
        let old = write_graph(&write)?;
        for p in &old.graph.principals {
            let next = graph
                .graph
                .principals
                .iter()
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
        }
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
        let mut ws = Attempt::<_, B>::new(
            |key: &[u8]| {
                native
                    .get(key)
                    .map(|v| v.map(|v| v.value().to_vec()))
                    .map_err(storage)
            },
            crate::local::MUTATION_WORK_LIMIT,
        );
        let mut ids = BTreeSet::new();
        for row in native.iter().map_err(storage)? {
            ws.charge("inventory", 1)?;
            let (key, _) = row.map_err(storage)?;
            if let Key::Record(id) = Key::decode(key.value())? {
                ids.insert(id);
            }
        }
        repair_readers(
            &mut ws,
            &self.model,
            ids,
            Uuid::new_v4(),
            &mut |owners, fallback| {
                if !graph.scopes.contains_key(&fallback) {
                    return Err(corrupt("unknown owner"));
                }
                Ok(graph.reader(owners, fallback))
            },
        )?;
        let batch = ws.finish()?;
        drop(ws);
        drop(native);
        self.publish_native(&write, &batch, None)?;
        store_graph(&write, &graph)?;
        write
            .open_table(AUTHORITY)?
            .insert(REVISION, encode(&revision)?.as_slice())?;
        write.commit().map_err(storage)?;
        Ok(json!({"revision":revision.to_string(),"changed":true}))
    }
}

#[cfg(test)]
mod reader_candidate_tests {
    use super::*;
    use crate::models::quantity::{Derived, Input, Quantity};

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn image() -> BTreeMap<Vec<u8>, Vec<u8>> {
        // Raw source traversal fixture only: the publication resolver is not run.
        // Its separate causal-cycle rule does not govern relation traversal.
        [
            (
                1,
                101,
                Input::Join {
                    left: id(2),
                    right: id(3),
                },
            ),
            (
                2,
                102,
                Input::Join {
                    left: id(4),
                    right: id(4),
                },
            ),
            (
                3,
                103,
                Input::Join {
                    left: id(4),
                    right: id(5),
                },
            ),
            (4, 104, Input::Source { value: 0 }),
            (
                5,
                102,
                Input::Join {
                    left: id(1),
                    right: id(4),
                },
            ),
        ]
        .into_iter()
        .map(|(record_id, owner, input)| {
            let key = Key::Record(id(record_id));
            let record = ModelRecord::<Quantity> {
                contract: input.contract(),
                tenant: id(99),
                owner: id(owner),
                reader: id(999),
                version: id(900),
                input,
                derived: Some(Derived { quantity: 0 }),
            };
            (
                key.encode(),
                native_codec::encode_for(&key, &StoredValue::Record(record)).unwrap(),
            )
        })
        .collect()
    }

    #[test]
    fn source_preorder_deduplicates_diamonds_and_terminates_record_loops() {
        let image = image();
        let model = Prepared::<Quantity>::prepare(Quantity::declarations().unwrap()).unwrap();
        let mut ws = Attempt::new(|key: &[u8]| Ok(image.get(key).cloned()), 10_000);
        assert_eq!(
            reader_candidates(&mut ws, &model, id(1)).unwrap(),
            vec![id(101), id(102), id(104), id(103)]
        );

        // Catalog order, rather than NativeInput's slot order, controls preorder.
        let mut declarations = Quantity::declarations().unwrap();
        declarations
            .iter_mut()
            .find(|c| c.code == crate::models::quantity::JOIN)
            .unwrap()
            .references
            .reverse();
        let reversed = Prepared::<Quantity>::prepare(declarations).unwrap();
        let mut ws = Attempt::new(|key: &[u8]| Ok(image.get(key).cloned()), 10_000);
        assert_eq!(
            reader_candidates(&mut ws, &reversed, id(1)).unwrap(),
            vec![id(101), id(103), id(102), id(104)]
        );
    }

    #[test]
    fn candidate_discovery_obeys_exact_work_budget() {
        let image = image();
        let model = Prepared::<Quantity>::prepare(Quantity::declarations().unwrap()).unwrap();
        let mut ws = Attempt::new(|key: &[u8]| Ok(image.get(key).cloned()), 10_000);
        reader_candidates(&mut ws, &model, id(1)).unwrap();
        let required = ws.work.work_units;
        assert!(required > 1);
        let mut exact = Attempt::new(|key: &[u8]| Ok(image.get(key).cloned()), required);
        reader_candidates(&mut exact, &model, id(1)).unwrap();
        let mut short = Attempt::new(|key: &[u8]| Ok(image.get(key).cloned()), required - 1);
        assert_eq!(
            reader_candidates(&mut short, &model, id(1))
                .unwrap_err()
                .code,
            "work_limit"
        );
    }

    #[test]
    fn payload_only_source_edit_does_not_read_incoming_routes() {
        let image = image();
        let model = Prepared::<Quantity>::prepare(Quantity::declarations().unwrap()).unwrap();
        let mut ws = Attempt::new(
            |key: &[u8]| {
                // This source has several consumers in the fixture. Reader repair
                // must not inspect their route, regardless of its population.
                assert!(!matches!(Key::decode(key)?, Key::Incoming(_)));
                Ok(image.get(key).cloned())
            },
            10_000,
        );
        let mut source = ws.record(id(4)).unwrap().unwrap();
        source.input = Input::Source { value: 1 };
        source.derived = Some(Derived { quantity: 1 });
        ws.put(Key::Record(id(4)), Some(StoredValue::Record(source)))
            .unwrap();
        repair_readers(
            &mut ws,
            &model,
            BTreeSet::from([id(4)]),
            id(901),
            &mut |_, owner| Ok(owner),
        )
        .unwrap();
        assert_eq!(ws.record(id(4)).unwrap().unwrap().reader, id(104));
        assert_eq!(ws.work.selector_visits, 0);
    }
}
