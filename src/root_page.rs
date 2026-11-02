//! Authorized occurrence paging; structural `members` permission includes raw topology.
use crate::{
    access::Action,
    binding::Binding,
    local::{self, KV, PublicRecordValue, RuntimeHeader, Store},
    model::{API_VERSION, Visibility},
    native_codec::{self, Address, Key, StoredValue, decimal, uuid_text},
    native_slice::{Error, Result},
    storage::{BatchGetOptions, Table},
    tree_read,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, num::NonZeroUsize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootPageRequest {
    pub model: String,
    #[serde(with = "uuid_text")]
    pub owner: Uuid,
    pub slot: u16,
    pub limit: u16,
    pub candidate_budget: u16,
    pub cursor: Option<String>,
}
/// Trusted service configuration; never deserialize this from client parameters.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct RootPagePolicy {
    pub max_output: u16,
    pub max_candidates: u16,
    pub max_gets: usize,
    pub max_bytes: usize,
    pub batch_keys: NonZeroUsize,
    pub concurrency: NonZeroUsize,
}
impl Default for RootPagePolicy {
    fn default() -> Self {
        Self {
            max_output: 32,
            max_candidates: 128,
            max_gets: 4096,
            max_bytes: 4 * 1024 * 1024,
            batch_keys: NonZeroUsize::new(64).unwrap(),
            concurrency: NonZeroUsize::new(8).unwrap(),
        }
    }
}
#[derive(Clone, Debug, Serialize)]
#[serde(bound(serialize = ""))]
pub struct RawOccurrenceResponse<B: Binding> {
    #[serde(with = "decimal")]
    pub rank: u64,
    pub slot: u16,
    pub record: PublicRecordValue<B>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(bound(serialize = ""))]
pub struct RootPage<B: Binding> {
    pub occurrences: Vec<RawOccurrenceResponse<B>>,
    pub visited: u16,
    #[serde(with = "decimal")]
    pub total: u64,
    pub exhausted: bool,
    pub cursor: Option<String>,
    pub revision: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    domain: String,
    api: String,
    store: Uuid,
    model: String,
    actor: Uuid,
    tenant: Uuid,
    owner: Uuid,
    slot: u16,
    root_revision: Uuid,
    scope_revision: String,
    next: u64,
}
const DOMAIN: &str = "root-members-1";
type Mac256 = Hmac<Sha256>;
fn bad_cursor() -> Error {
    Error::new(
        "invalid_cursor",
        "root member cursor does not match request",
    )
}
fn work_limit() -> Error {
    Error::new("work_limit", "root member resource budget")
}
fn sign(cursor: &Cursor, header: &RuntimeHeader) -> Result<String> {
    let bytes = local::encode(cursor)?;
    let mut mac =
        Mac256::new_from_slice(&local::unhex(&header.cursor_key)?).map_err(|_| bad_cursor())?;
    mac.update(DOMAIN.as_bytes());
    mac.update(&bytes);
    Ok(format!(
        "{}.{}",
        native_codec::hex(&bytes),
        native_codec::hex(&mac.finalize().into_bytes())
    ))
}
fn parse(token: &str, header: &RuntimeHeader) -> Result<Cursor> {
    if token.len() > 4096 {
        return Err(bad_cursor());
    }
    let (payload, signature) = token.split_once('.').ok_or_else(bad_cursor)?;
    let bytes = local::unhex(payload).map_err(|_| bad_cursor())?;
    let signature = local::unhex(signature).map_err(|_| bad_cursor())?;
    let mut mac =
        Mac256::new_from_slice(&local::unhex(&header.cursor_key)?).map_err(|_| bad_cursor())?;
    mac.update(DOMAIN.as_bytes());
    mac.update(&bytes);
    mac.verify_slice(&signature).map_err(|_| bad_cursor())?;
    serde_json::from_slice(&bytes).map_err(|_| bad_cursor())
}
struct Budget {
    gets: usize,
    bytes: usize,
}
impl Budget {
    fn charge(&mut self, gets: usize, bytes: usize) -> Result<()> {
        self.gets = self.gets.checked_sub(gets).ok_or_else(work_limit)?;
        self.bytes = self.bytes.checked_sub(bytes).ok_or_else(work_limit)?;
        Ok(())
    }
    fn encoded<T: Serialize>(&mut self, value: &T) -> Result<()> {
        self.charge(0, local::encode(value)?.len())
    }
}
fn batch<B: Binding>(
    table: &Table<&'static [u8], &'static [u8]>,
    keys: &[Key],
    policy: &RootPagePolicy,
    budget: &mut Budget,
    missing: &'static str,
) -> Result<Vec<StoredValue<B>>> {
    let mut decoded = Vec::new();
    for chunk in keys.chunks(policy.batch_keys.get()) {
        if chunk.len() > budget.gets {
            return Err(work_limit());
        }
        let encoded: Vec<_> = chunk.iter().map(Key::encode).collect();
        let refs: Vec<_> = encoded.iter().map(Vec::as_slice).collect();
        let values = table.batch_get(
            &refs,
            BatchGetOptions {
                max_keys: policy.batch_keys.get(),
                max_bytes: budget.bytes,
                concurrency: policy.concurrency,
            },
        )?;
        for ((key, encoded), value) in chunk.iter().zip(encoded).zip(values) {
            let value =
                value.ok_or_else(|| Error::new(missing, "root member value unavailable"))?;
            budget.charge(
                1,
                encoded
                    .len()
                    .checked_add(value.value().len())
                    .ok_or_else(work_limit)?,
            )?;
            decoded.push(native_codec::decode_for::<B>(key, value.value())?);
        }
    }
    Ok(decoded)
}
impl<B: Binding> Store<B> {
    /// Raw occurrence positions/counts require explicit `members` and `summary`.
    /// Every returned record is independently projected under current authority.
    pub fn root_page(
        &self,
        request: &RootPageRequest,
        policy: &RootPagePolicy,
    ) -> Result<RootPage<B>> {
        if request.limit == 0
            || request.limit > policy.max_output
            || request.candidate_budget == 0
            || request.candidate_budget > policy.max_candidates
            || policy.max_gets < 3
            || policy.max_gets == usize::MAX
            || policy.max_bytes == 0
        {
            return Err(Error::new("invalid_input", "root member limits"));
        }
        let (read, meta, header) = self.read(&request.model)?;
        let scope = self.authority(&read)?;
        let mut budget = Budget {
            gets: policy.max_gets,
            bytes: policy.max_bytes,
        };
        // Shared setup has existing authority inventory limits. Account its reads
        // conservatively, including missing epochs, before candidate discovery.
        budget.charge(
            2,
            local::encode(&header)?.len()
                + local::HEADER.len()
                + native_codec::encode_for::<B>(&Key::Meta, &StoredValue::Meta(meta))?.len()
                + Key::Meta.encode().len(),
        )?;
        if self.secured {
            budget.charge(1, 17 + local::encode(&scope)?.len())?;
        }
        let table = read.open_table(KV)?;
        let owner = batch::<B>(
            &table,
            &[Key::Record(request.owner)],
            policy,
            &mut budget,
            "not_found",
        )?
        .pop()
        .ok_or_else(|| local::corrupt("owner load"))?;
        let StoredValue::Record(owner_record) = owner else {
            return Err(local::corrupt("root owner type"));
        };
        let owner = self
            .project(&scope, request.owner, Some(owner_record))
            .ok_or_else(|| Error::new("not_found", "root owner unavailable"))?;
        let contract = self.model.public_contract(owner.contract)?;
        let declaration = contract
            .roots
            .iter()
            .find(|root| root.slot == request.slot)
            .ok_or_else(|| Error::new("unsupported_query", "undeclared root"))?;
        if !declaration.reads.contains(&"members") || !declaration.reads.contains(&"summary") {
            return Err(Error::new(
                "unsupported_query",
                "undeclared root member operation",
            ));
        }
        let address = Address::new(request.owner, request.slot);
        let StoredValue::Root(root) = batch::<B>(
            &table,
            &[Key::Root(address)],
            policy,
            &mut budget,
            "corrupt_state",
        )?
        .pop()
        .ok_or_else(|| local::corrupt("root load"))?
        else {
            return Err(local::corrupt("root type"));
        };
        if root.kind != declaration.kind {
            return Err(local::corrupt("root declaration kind"));
        }
        let codes: Vec<_> = self
            .model
            .contracts()
            .filter(|c| {
                c.visibility == Visibility::Public && scope.grants.allows(c.code, Action::Read)
            })
            .map(|c| c.code)
            .collect();
        let epochs = scope
            .accessible
            .len()
            .checked_mul(codes.len())
            .ok_or_else(work_limit)?;
        budget.charge(epochs, epochs.checked_mul(34).ok_or_else(work_limit)?)?;
        if self.secured {
            budget.charge(1, 8 + 20)?;
        }
        let scope_revision = crate::query::scope_revision(
            &read,
            &scope,
            &codes,
            self.secured,
            BatchGetOptions {
                max_keys: policy.batch_keys.get(),
                max_bytes: policy
                    .batch_keys
                    .get()
                    .checked_mul(34)
                    .ok_or_else(work_limit)?,
                concurrency: policy.concurrency,
            },
        )?;
        let mut next = 0;
        if let Some(token) = &request.cursor {
            let cursor = parse(token, &header)?;
            if cursor.domain != DOMAIN
                || cursor.api != API_VERSION
                || cursor.store != header.store_id
                || cursor.model != self.model.identity()
                || cursor.actor != self.context.actor
                || cursor.tenant != self.context.tenant
                || cursor.owner != request.owner
                || cursor.slot != request.slot
            {
                return Err(bad_cursor());
            }
            if cursor.root_revision != root.revision || cursor.scope_revision != scope_revision {
                return Err(Error::new(
                    "query_changed",
                    "restart after root, projection or authority changes",
                ));
            }
            if cursor.next > root.size {
                return Err(bad_cursor());
            }
            next = cursor.next;
        }
        let mut occurrences = vec![];
        let mut visited = 0;
        while next < root.size
            && visited < request.candidate_budget
            && occurrences.len() < usize::from(request.limit)
        {
            let count = usize::from(request.candidate_budget - visited)
                .min(usize::from(request.limit) - occurrences.len())
                .min(policy.batch_keys.get());
            let end = next
                .checked_add(count as u64)
                .ok_or_else(work_limit)?
                .min(root.size);
            let max_nodes = budget
                .gets
                .checked_sub(1)
                .filter(|n| *n > 0)
                .ok_or_else(work_limit)?;
            let window = tree_read::rank_window::<B, _>(
                &table,
                address,
                next..end,
                tree_read::Limits {
                    max_nodes,
                    max_bytes: budget.bytes,
                    batch_keys: policy.batch_keys,
                    concurrency: policy.concurrency,
                },
            )?;
            let costs = window
                .counters
                .read_bytes
                .checked_add(window.counters.output_bytes)
                .and_then(|n| n.checked_add(window.counters.allocation_bytes))
                .ok_or_else(work_limit)?;
            budget.charge(window.counters.gets, costs)?;
            if window.revision != root.revision
                || window.total != root.size
                || window.occurrences.len()
                    != usize::try_from(end - next).map_err(|_| work_limit())?
            {
                return Err(local::corrupt("nonprogressing member window"));
            }
            let mut ids: Vec<_> = window.occurrences.iter().map(|n| n.address.id).collect();
            ids.sort_unstable();
            ids.dedup();
            let keys: Vec<_> = ids.iter().copied().map(Key::Record).collect();
            let values = batch::<B>(&table, &keys, policy, &mut budget, "corrupt_state")?;
            let mut records = BTreeMap::new();
            for (id, value) in ids.into_iter().zip(values) {
                let StoredValue::Record(record) = value else {
                    return Err(local::corrupt("member record type"));
                };
                records.insert(id, record);
            }
            for occurrence in window.occurrences {
                visited += 1;
                next = occurrence.rank.checked_add(1).ok_or_else(work_limit)?;
                let raw = records
                    .get(&occurrence.address.id)
                    .ok_or_else(|| local::corrupt("hydration identity"))?;
                if let Some(record) = self.project(&scope, occurrence.address.id, Some(raw.clone()))
                {
                    let item = RawOccurrenceResponse {
                        rank: occurrence.rank,
                        slot: occurrence.address.slot,
                        record,
                    };
                    budget.encoded(&item)?;
                    occurrences.push(item);
                }
            }
        }
        let exhausted = next >= root.size;
        let cursor = if exhausted {
            None
        } else {
            Some(sign(
                &Cursor {
                    domain: DOMAIN.into(),
                    api: API_VERSION.into(),
                    store: header.store_id,
                    model: self.model.identity().into(),
                    actor: self.context.actor,
                    tenant: self.context.tenant,
                    owner: request.owner,
                    slot: request.slot,
                    root_revision: root.revision,
                    scope_revision: scope_revision.clone(),
                    next,
                },
                &header,
            )?)
        };
        let mut digest = Sha256::new();
        digest.update(DOMAIN.as_bytes());
        digest.update(root.revision.as_bytes());
        digest.update(scope_revision.as_bytes());
        let result = RootPage {
            occurrences,
            visited,
            total: root.size,
            exhausted,
            cursor,
            revision: native_codec::hex(&digest.finalize()),
        };
        // Includes cursor/envelope as well as item bytes (conservative double charge).
        budget.encoded(&result)?;
        Ok(result)
    }
}
