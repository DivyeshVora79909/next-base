//! Explicit owner-partitioned access trees, maintained in the source transaction.

use crate::{
    binding::Binding,
    model::{API_VERSION, Contract, Prepared},
    native_codec::{Address, Key, StoredValue, uuid_text},
    native_slice::{Attempt, Error, ModelRecord, Result},
    order_value::{AccessOrder, ORDER_INDEX, OrderAtom, OrderAtomKind, OrderKey},
    tree::{self, FullKey, Node, Root, TreeStore},
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum Component {
    CreatedAt,
    Field {
        field: &'static str,
        kind: OrderAtomKind,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct Declaration {
    /// Positive catalog-wide identity; distinct from domain root/member slots.
    pub code: u16,
    pub name: &'static str,
    pub components: Vec<Component>,
}

impl Declaration {
    pub fn created(code: u16) -> Self {
        Self {
            code,
            name: "created",
            components: vec![Component::CreatedAt],
        }
    }
    fn validate_key(&self, key: &OrderKey) -> Result<()> {
        key.validate()?;
        if self.components.len() != key.0.len()
            || self.components.iter().zip(&key.0).any(|(c, a)| {
                a.kind()
                    != match c {
                        Component::CreatedAt => OrderAtomKind::Integer,
                        Component::Field { kind, .. } => *kind,
                    }
            })
        {
            return Err(Error::new(
                "invalid_input",
                "order key differs from declared tuple",
            ));
        }
        Ok(())
    }
}

pub(crate) fn validate_declarations<'a>(
    contracts: impl Iterator<Item = &'a Contract>,
) -> Result<()> {
    let mut codes = BTreeSet::new();
    for c in contracts {
        let mut names = BTreeSet::new();
        for d in &c.access_indexes {
            if d.code == 0 || !codes.insert(d.code) || d.name.is_empty() || !names.insert(d.name)
                || d.components.is_empty() || d.components.len() > crate::order_value::ORDER_MAX_COMPONENTS
                || d.components.iter().any(|v| matches!(v, Component::Field{field,..} if !c.fields.iter().any(|f| f.name == *field))) {
                return Err(Error::new("model", "invalid or duplicate access index declaration"));
            }
        }
    }
    Ok(())
}

/// The store header fixes the tenant namespace; catalog-wide codes fix resource/order.
/// Principal UUIDs inhabit AccessRoot, never the domain Root namespace.
pub fn root_address(_tenant: Uuid, owner: Uuid, _contract: u16, code: u16) -> Address {
    Address::new(owner, code)
}

pub(crate) fn memberships<B: Binding>(
    model: &Prepared<B>,
    id: Uuid,
    record: &ModelRecord<B>,
) -> Result<Vec<(Address, Address, OrderKey)>> {
    let declarations = &model.contract(record.contract)?.access_indexes;
    if declarations.is_empty() {
        return Ok(vec![]);
    }
    let fields = serde_json::to_value(&record.input).map_err(crate::local::storage)?;
    declarations
        .iter()
        .map(|d| {
            let components = d
                .components
                .iter()
                .map(|c| match c {
                    Component::CreatedAt => Ok(OrderAtom::Integer(i128::from(record.created_at))),
                    Component::Field { field, kind } => OrderAtom::from_json(
                        *kind,
                        fields.get(*field).ok_or_else(|| {
                            Error::new("invalid_input", "missing declared order field")
                        })?,
                    ),
                })
                .collect::<Result<Vec<_>>>()?;
            Ok((
                root_address(record.tenant, record.owner, record.contract, d.code),
                Address::new(id, d.code),
                OrderKey::new(components)?,
            ))
        })
        .collect()
}

pub(crate) struct Trees<'a, L, B: Binding>(pub &'a mut Attempt<L, B>);
impl<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding> TreeStore for Trees<'_, L, B> {
    type Index = AccessOrder;
    fn root(&mut self, id: Address) -> Result<Option<Root<AccessOrder>>> {
        match self.0.get(&Key::AccessRoot(id))? {
            Some(StoredValue::AccessRoot(r)) => Ok(Some(r)),
            None => Ok(None),
            _ => Err(crate::local::corrupt("access root type")),
        }
    }
    fn node(&mut self, id: Address) -> Result<Option<Node<AccessOrder>>> {
        match self.0.get(&Key::AccessNode(id))? {
            Some(StoredValue::AccessNode(n)) => Ok(Some(n)),
            None => Ok(None),
            _ => Err(crate::local::corrupt("access node type")),
        }
    }
    fn put_root(&mut self, id: Address, value: Option<Root<AccessOrder>>) -> Result<()> {
        self.0
            .put(Key::AccessRoot(id), value.map(StoredValue::AccessRoot))
    }
    fn put_node(&mut self, id: Address, value: Option<Node<AccessOrder>>) -> Result<()> {
        self.0
            .put(Key::AccessNode(id), value.map(StoredValue::AccessNode))
    }
    fn charge(&mut self, kind: &str, count: u64) -> Result<()> {
        self.0.charge(kind, count)
    }
    fn rotated(&mut self) {
        self.0.work.rotations += 1;
    }
}

/// Compare against this settlement call's entry state, including composed attempts.
/// Unchanged order projections do not touch nodes or root revisions.
pub(crate) fn reconcile<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    entry: &BTreeMap<Uuid, Option<ModelRecord<B>>>,
    revision: Uuid,
) -> Result<()> {
    let mut candidates = ws.changed_records();
    candidates.extend(entry.keys().copied());
    for id in candidates {
        ws.charge("dependency", 1)?;
        let old = match entry.get(&id) {
            Some(v) => v.clone(),
            None => match ws.original(&Key::Record(id))? {
                Some(StoredValue::Record(r)) => Some(r),
                None => None,
                _ => return Err(crate::local::corrupt("access source type")),
            },
        };
        let current = ws.record(id)?;
        let before = old
            .as_ref()
            .map(|r| memberships(model, id, r))
            .transpose()?
            .unwrap_or_default();
        let after = current
            .as_ref()
            .map(|r| memberships(model, id, r))
            .transpose()?
            .unwrap_or_default();
        let mut trees = Trees(ws);
        let mut changed = BTreeSet::new();
        for (root, node, key) in &before {
            if !after.contains(&(*root, *node, key.clone())) {
                let stored = tree::node(&mut trees, *root, *node)?;
                if stored.key.value != *key {
                    return Err(crate::local::corrupt("access source projection mismatch"));
                }
                tree::remove(&mut trees, *root, *node)?;
                changed.insert(*root);
            }
        }
        for (root, node, key) in &after {
            if !before.contains(&(*root, *node, key.clone())) {
                if trees.root(*root)?.is_none() {
                    trees.put_root(*root, Some(Root::empty(ORDER_INDEX, revision)?))?;
                }
                tree::insert(&mut trees, *root, *node, key.clone(), ())?;
                changed.insert(*root);
            }
        }
        for root in changed {
            let mut value = tree::root(&mut trees, root)?;
            value.revision = revision;
            trees.put_root(root, if value.size == 0 { None } else { Some(value) })?;
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderQuery {
    pub contract: u16,
    pub index: u16,
    pub range: crate::native_range::NativeRange<OrderKey>,
    pub equals: Option<crate::query::Equality>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageRequest {
    pub model: String,
    pub query: OrderQuery,
    pub limit: u16,
    pub visit_budget: u16,
    pub cursor: Option<String>,
}

/// Service-selected bounds, never accepted from an RPC request.
#[derive(Clone, Copy, Debug)]
pub struct PagePolicy {
    pub max_work: u64,
    pub max_gets: usize,
    pub max_loaded_bytes: usize,
    pub max_output_bytes: usize,
}
impl Default for PagePolicy {
    fn default() -> Self {
        Self {
            max_work: 50_000,
            max_gets: 4096,
            max_loaded_bytes: 4 * 1024 * 1024,
            max_output_bytes: 1024 * 1024,
        }
    }
}
fn budget() -> Error {
    Error::new("work_limit", "access page resource budget")
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    api: String,
    #[serde(with = "uuid_text")]
    store: Uuid,
    model: String,
    #[serde(with = "uuid_text")]
    actor: Uuid,
    #[serde(with = "uuid_text")]
    tenant: Uuid,
    revision: String,
    query: OrderQuery,
    after: FullKey<OrderKey>,
}
fn sign(cursor: &Cursor, header: &crate::local::RuntimeHeader) -> Result<String> {
    let bytes = crate::local::encode(cursor)?;
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&crate::local::unhex(&header.cursor_key)?)
        .map_err(|_| crate::local::corrupt("cursor key"))?;
    mac.update(b"access-order-cursor-1\0");
    mac.update(&bytes);
    Ok(format!(
        "{}.{}",
        crate::native_codec::hex(&bytes),
        crate::native_codec::hex(&mac.finalize().into_bytes())
    ))
}
fn parse(token: &str, header: &crate::local::RuntimeHeader) -> Result<Cursor> {
    let bad = || Error::new("invalid_cursor", "access cursor does not match query/store");
    if token.len() > 32768 {
        return Err(bad());
    }
    let (bytes, signature) = token.split_once('.').ok_or_else(bad)?;
    let bytes = crate::local::unhex(bytes).map_err(|_| bad())?;
    let signature = crate::local::unhex(signature).map_err(|_| bad())?;
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&crate::local::unhex(&header.cursor_key)?)
        .map_err(|_| bad())?;
    mac.update(b"access-order-cursor-1\0");
    mac.update(&bytes);
    mac.verify_slice(&signature).map_err(|_| bad())?;
    serde_json::from_slice(&bytes).map_err(|_| bad())
}

fn first<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    trees: &mut Trees<'_, L, B>,
    root: Address,
    range: &crate::native_range::NativeRange<OrderKey>,
    after: Option<&FullKey<OrderKey>>,
) -> Result<Option<Node<AccessOrder>>> {
    let Some(header) = trees.root(root)? else {
        return Ok(None);
    };
    let mut cursor = header.head;
    let mut candidate = None;
    let mut seen = BTreeSet::new();
    while let Some(id) = cursor {
        if seen.len() >= 64 || !seen.insert(id) {
            return Err(crate::local::corrupt("access seek topology"));
        }
        let node = tree::node(trees, root, id)?;
        let below = match &range.lower {
            crate::native_range::NativeBound::Unbounded => false,
            crate::native_range::NativeBound::Included(v) => node.key.value < *v,
            crate::native_range::NativeBound::Excluded(v) => node.key.value <= *v,
        };
        if below || after.is_some_and(|key| node.key <= *key) {
            cursor = node.right;
        } else {
            cursor = node.left;
            candidate = Some(node);
        }
    }
    Ok(candidate.filter(|n| range.contains(&n.key.value)))
}

impl<B: Binding> crate::local::Store<B> {
    pub fn order_page(&self, request: &PageRequest) -> Result<crate::query::PageValue<B>> {
        self.order_page_with_policy(request, &PagePolicy::default())
    }
    pub fn order_page_with_policy(
        &self,
        request: &PageRequest,
        policy: &PagePolicy,
    ) -> Result<crate::query::PageValue<B>> {
        if policy.max_work == 0
            || policy.max_gets == 0
            || policy.max_loaded_bytes == 0
            || policy.max_output_bytes == 0
        {
            return Err(Error::new("invalid_input", "access page policy"));
        }
        if !(1..=32).contains(&request.limit) || !(1..=128).contains(&request.visit_budget) {
            return Err(Error::new("invalid_input", "page/visit limits"));
        }
        let contract = self.model.public_contract(request.query.contract)?;
        let declaration = contract
            .access_indexes
            .iter()
            .find(|d| d.code == request.query.index)
            .ok_or_else(|| Error::new("unsupported_query", "undeclared access index"))?;
        for bound in [&request.query.range.lower, &request.query.range.upper] {
            match bound {
                crate::native_range::NativeBound::Unbounded => {}
                crate::native_range::NativeBound::Included(v)
                | crate::native_range::NativeBound::Excluded(v) => declaration.validate_key(v)?,
            }
        }
        if let Some(predicate) = &request.query.equals {
            self.model
                .validate_predicate(contract.code, &predicate.field, &predicate.value)?;
        }
        let (read, _, header) = self.read(&request.model)?;
        let scope = self.authority(&read)?;
        if !scope
            .grants
            .allows(contract.code, crate::access::Action::Read)
        {
            return Err(crate::access::denied());
        }
        let revision = crate::query::scope_revision(
            &read,
            &scope,
            &[contract.code],
            self.secured,
            crate::storage::BatchGetOptions {
                max_keys: 64,
                max_bytes: 64 * 34,
                concurrency: std::num::NonZeroUsize::new(8).expect("positive"),
            },
        )?;
        let after = if let Some(token) = &request.cursor {
            let c = parse(token, &header)?;
            if c.api != API_VERSION
                || c.store != header.store_id
                || c.model != self.model.identity()
                || c.actor != self.context.actor
                || c.tenant != self.context.tenant
                || c.query != request.query
            {
                return Err(Error::new("invalid_cursor", "access cursor scope differs"));
            }
            if c.revision != revision {
                return Err(Error::new(
                    "query_changed",
                    "restart after query scope or authority changes",
                ));
            }
            Some(c.after)
        } else {
            None
        };
        let table = read.open_table(crate::local::KV)?;
        use crate::storage::ReadableTable;
        let mut remaining_gets = policy.max_gets;
        let mut remaining_bytes = policy.max_loaded_bytes;
        let mut ws = Attempt::<_, B>::new(
            |key: &[u8]| {
                remaining_gets = remaining_gets.checked_sub(1).ok_or_else(budget)?;
                let value = table.get(key)?;
                remaining_bytes = remaining_bytes
                    .checked_sub(value.as_ref().map_or(0, |v| v.value().len()))
                    .ok_or_else(budget)?;
                Ok(value.map(|v| v.value().to_vec()))
            },
            policy.max_work,
        );
        let mut heads = BinaryHeap::new();
        if !request.query.range.is_empty() {
            for &owner in &scope.accessible {
                let root = root_address(scope.tenant, owner, contract.code, declaration.code);
                if let Some(node) = first(
                    &mut Trees(&mut ws),
                    root,
                    &request.query.range,
                    after.as_ref(),
                )? {
                    heads.push(Reverse((node.key, root)));
                }
            }
        }
        let (mut visited, mut last) = (0, None);
        let mut records = vec![];
        while visited < request.visit_budget && records.len() < usize::from(request.limit) {
            let Some(Reverse((key, root))) = heads.pop() else {
                break;
            };
            let node = tree::node(&mut Trees(&mut ws), root, Address::new(key.id, key.slot))?;
            if node.key != key {
                return Err(crate::local::corrupt("access key changed within snapshot"));
            }
            if let Some(next) = node.next {
                let next = tree::node(&mut Trees(&mut ws), root, next)?;
                if request.query.range.contains(&next.key.value) {
                    heads.push(Reverse((next.key, root)));
                }
            }
            visited += 1;
            last = Some(key.clone());
            let raw = ws
                .record(key.id)?
                .ok_or_else(|| crate::local::corrupt("missing access record"))?;
            if raw.owner != root.id || raw.contract != contract.code || raw.tenant != scope.tenant {
                return Err(crate::local::corrupt("access partition mismatch"));
            }
            let record = self
                .project(&scope, key.id, Some(raw))
                .ok_or_else(|| crate::local::corrupt("unreadable access member"))?;
            if let Some(p) = &request.query.equals
                && serde_json::to_value(&record.input)
                    .map_err(crate::local::storage)?
                    .get(&p.field)
                    != Some(&p.value)
            {
                continue;
            }
            records.push(record);
        }
        let exhausted = heads.is_empty();
        let cursor = if exhausted {
            None
        } else {
            Some(sign(
                &Cursor {
                    api: API_VERSION.into(),
                    store: header.store_id,
                    model: self.model.identity().into(),
                    actor: self.context.actor,
                    tenant: self.context.tenant,
                    revision: revision.clone(),
                    query: request.query.clone(),
                    after: last
                        .ok_or_else(|| crate::local::corrupt("nonprogressing access cursor"))?,
                },
                &header,
            )?)
        };
        let page = crate::query::PageValue {
            records,
            visited,
            exhausted,
            cursor,
            revision,
        };
        if crate::local::encode(&page)?.len() > policy.max_output_bytes {
            return Err(budget());
        }
        Ok(page)
    }
}
