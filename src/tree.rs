//! One linked AVL over a compiled model's native key, leaf and summary.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    binding::Binding,
    index::{IndexCode, KeyRange, NativeIndex, Selected},
    native_codec::{Address, Key, StoredValue, uuid_text},
    native_slice::{Attempt, Error, Result},
    time_range::{TimeBound, TimeRange},
};
use std::{collections::BTreeSet, ops::Bound};

type NativeKey<S> = <<S as TreeStore>::Index as NativeIndex>::Key;
type NativeLeaf<S> = <<S as TreeStore>::Index as NativeIndex>::Leaf;
type NativeSummary<S> = <<S as TreeStore>::Index as NativeIndex>::Summary;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullKey<K> {
    pub value: K,
    #[serde(with = "uuid_text")]
    pub id: Uuid,
    pub slot: u16,
}

/// Structural coverage is independent of the model's summary fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Span<K> {
    pub first: K,
    pub last: K,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound = "")]
pub struct Root<I: NativeIndex> {
    pub kind: IndexCode,
    pub head: Option<Address>,
    pub first: Option<Address>,
    pub last: Option<Address>,
    pub height: u16,
    pub size: u64,
    pub span: Option<Span<I::Key>>,
    pub summary: I::Summary,
    #[serde(with = "uuid_text")]
    pub revision: Uuid,
}

impl<I: NativeIndex> Root<I> {
    pub fn empty(kind: IndexCode, revision: Uuid) -> Result<Self> {
        Ok(Self {
            kind,
            head: None,
            first: None,
            last: None,
            height: 0,
            size: 0,
            span: None,
            summary: I::empty(kind)?,
            revision,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound = "")]
pub struct Node<I: NativeIndex> {
    pub kind: IndexCode,
    pub root: Address,
    pub key: FullKey<I::Key>,
    pub leaf: I::Leaf,
    pub parent: Option<Address>,
    pub left: Option<Address>,
    pub right: Option<Address>,
    pub prev: Option<Address>,
    pub next: Option<Address>,
    pub height: u16,
    pub size: u64,
    pub span: Span<I::Key>,
    pub summary: I::Summary,
}

/// Attempt-local storage for the shared linked AVL algorithm. Implementations
/// select the physical root/node namespace while preserving the attempt's reads,
/// staged writes and work budget.
pub trait TreeStore {
    type Index: NativeIndex;

    fn root(&mut self, id: Address) -> Result<Option<Root<Self::Index>>>;
    fn node(&mut self, id: Address) -> Result<Option<Node<Self::Index>>>;
    fn put_root(&mut self, id: Address, value: Option<Root<Self::Index>>) -> Result<()>;
    fn put_node(&mut self, id: Address, value: Option<Node<Self::Index>>) -> Result<()>;
    fn charge(&mut self, kind: &str, count: u64) -> Result<()>;
    fn rotated(&mut self);
}

impl<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding> TreeStore for Attempt<L, B> {
    type Index = B::Index;

    fn root(&mut self, id: Address) -> Result<Option<Root<Self::Index>>> {
        match self.get(&Key::Root(id))? {
            Some(StoredValue::Root(root)) => Ok(Some(root)),
            None => Ok(None),
            _ => Err(broken("missing root")),
        }
    }

    fn node(&mut self, id: Address) -> Result<Option<Node<Self::Index>>> {
        match self.get(&Key::Node(id))? {
            Some(StoredValue::Node(node)) => Ok(Some(node)),
            None => Ok(None),
            _ => Err(broken("missing or cross-root node")),
        }
    }

    fn put_root(&mut self, id: Address, value: Option<Root<Self::Index>>) -> Result<()> {
        self.put(Key::Root(id), value.map(StoredValue::Root))
    }

    fn put_node(&mut self, id: Address, value: Option<Node<Self::Index>>) -> Result<()> {
        self.put(Key::Node(id), value.map(StoredValue::Node))
    }

    fn charge(&mut self, kind: &str, count: u64) -> Result<()> {
        Attempt::charge(self, kind, count)
    }

    fn rotated(&mut self) {
        self.work.rotations += 1;
    }
}

fn broken(detail: &str) -> Error {
    Error::new("corrupt_state", detail)
}

pub fn root<S: TreeStore>(ws: &mut S, id: Address) -> Result<Root<S::Index>> {
    match ws.root(id)? {
        Some(r) => Ok(r),
        _ => Err(broken("missing root")),
    }
}

pub fn node<S: TreeStore>(ws: &mut S, owner: Address, id: Address) -> Result<Node<S::Index>> {
    ws.charge("node", 1)?;
    match ws.node(id)? {
        Some(n) if n.root == owner => Ok(n),
        _ => Err(broken("missing or cross-root node")),
    }
}

fn edit<S: TreeStore>(
    ws: &mut S,
    owner: Address,
    id: Address,
    change: impl FnOnce(&mut Node<S::Index>),
) -> Result<()> {
    let mut current = node(ws, owner, id)?;
    change(&mut current);
    ws.put_node(id, Some(current))
}

struct Child<I: NativeIndex> {
    height: u16,
    size: u64,
    summary: I::Summary,
    span: Option<Span<I::Key>>,
}

fn child_info<S: TreeStore>(
    ws: &mut S,
    owner: Address,
    parent: Address,
    child: Option<Address>,
    kind: IndexCode,
) -> Result<Child<S::Index>> {
    match child {
        None => Ok(Child {
            height: 0,
            size: 0,
            summary: S::Index::empty(kind)?,
            span: None,
        }),
        Some(id) => {
            let n = node(ws, owner, id)?;
            if n.parent != Some(parent) || n.kind != kind {
                return Err(broken("child parent/kind mismatch"));
            }
            Ok(Child {
                height: n.height,
                size: n.size,
                summary: n.summary,
                span: Some(n.span),
            })
        }
    }
}

fn refresh<S: TreeStore>(ws: &mut S, owner: Address, id: Address) -> Result<i32> {
    let current = node(ws, owner, id)?;
    let kind = current.kind;
    let left = child_info(ws, owner, id, current.left, kind)?;
    let right = child_info(ws, owner, id, current.right, kind)?;
    let leaf = S::Index::singleton(kind, &current.key.value, &current.leaf)?;
    let summary = S::Index::combine(
        kind,
        &S::Index::combine(kind, &left.summary, &leaf)?,
        &right.summary,
    )?;
    let height = left
        .height
        .max(right.height)
        .checked_add(1)
        .ok_or_else(|| broken("height overflow"))?;
    let size = left
        .size
        .checked_add(right.size)
        .and_then(|size| size.checked_add(1))
        .ok_or_else(|| broken("structural size overflow"))?;
    let span = Span {
        first: left
            .span
            .map_or_else(|| current.key.value.clone(), |s| s.first),
        last: right
            .span
            .map_or_else(|| current.key.value.clone(), |s| s.last),
    };
    edit(ws, owner, id, |n| {
        n.height = height;
        n.size = size;
        n.summary = summary;
        n.span = span;
    })?;
    Ok(i32::from(left.height) - i32::from(right.height))
}

fn replace_parent_link<S: TreeStore>(
    ws: &mut S,
    owner: Address,
    old: Address,
    new: Option<Address>,
) -> Result<()> {
    let parent = node(ws, owner, old)?.parent;
    if let Some(p) = parent {
        let current = node(ws, owner, p)?;
        if (current.left == Some(old)) == (current.right == Some(old)) {
            return Err(broken("ambiguous parent link"));
        }
        edit(ws, owner, p, |n| {
            if current.left == Some(old) {
                n.left = new;
            } else {
                n.right = new;
            }
        })?;
    } else {
        let mut header = root(ws, owner)?;
        if header.head != Some(old) {
            return Err(broken("root head mismatch"));
        }
        header.head = new;
        ws.put_root(owner, Some(header))?;
    }
    if let Some(id) = new {
        edit(ws, owner, id, |n| n.parent = parent)?;
    }
    Ok(())
}

fn rotate_left<S: TreeStore>(ws: &mut S, owner: Address, x: Address) -> Result<Address> {
    let y = node(ws, owner, x)?
        .right
        .ok_or_else(|| broken("missing rotation child"))?;
    let upper = node(ws, owner, y)?;
    if upper.parent != Some(x) {
        return Err(broken("rotation parent mismatch"));
    }
    let beta = upper.left;
    edit(ws, owner, x, |n| n.right = beta)?;
    if let Some(b) = beta {
        edit(ws, owner, b, |n| n.parent = Some(x))?;
    }
    replace_parent_link(ws, owner, x, Some(y))?;
    edit(ws, owner, y, |n| n.left = Some(x))?;
    edit(ws, owner, x, |n| n.parent = Some(y))?;
    refresh(ws, owner, x)?;
    refresh(ws, owner, y)?;
    ws.rotated();
    Ok(y)
}

fn rotate_right<S: TreeStore>(ws: &mut S, owner: Address, x: Address) -> Result<Address> {
    let y = node(ws, owner, x)?
        .left
        .ok_or_else(|| broken("missing rotation child"))?;
    let upper = node(ws, owner, y)?;
    if upper.parent != Some(x) {
        return Err(broken("rotation parent mismatch"));
    }
    let beta = upper.right;
    edit(ws, owner, x, |n| n.left = beta)?;
    if let Some(b) = beta {
        edit(ws, owner, b, |n| n.parent = Some(x))?;
    }
    replace_parent_link(ws, owner, x, Some(y))?;
    edit(ws, owner, y, |n| n.right = Some(x))?;
    edit(ws, owner, x, |n| n.parent = Some(y))?;
    refresh(ws, owner, x)?;
    refresh(ws, owner, y)?;
    ws.rotated();
    Ok(y)
}

fn balance<S: TreeStore>(ws: &mut S, owner: Address, mut at: Option<Address>) -> Result<()> {
    let mut seen = BTreeSet::new();
    while let Some(id) = at {
        if !seen.insert(id) {
            return Err(broken("cyclic parent chain"));
        }
        let difference = refresh(ws, owner, id)?;
        let top = if difference > 1 {
            let left = node(ws, owner, id)?
                .left
                .ok_or_else(|| broken("missing heavy child"))?;
            if refresh(ws, owner, left)? < 0 {
                rotate_left(ws, owner, left)?;
            }
            rotate_right(ws, owner, id)?
        } else if difference < -1 {
            let right = node(ws, owner, id)?
                .right
                .ok_or_else(|| broken("missing heavy child"))?;
            if refresh(ws, owner, right)? > 0 {
                rotate_right(ws, owner, right)?;
            }
            rotate_left(ws, owner, id)?
        } else {
            id
        };
        at = node(ws, owner, top)?.parent;
    }
    let mut header = root(ws, owner)?;
    if let Some(head) = header.head {
        let n = node(ws, owner, head)?;
        if n.parent.is_some() {
            return Err(broken("root has parent"));
        }
        header.height = n.height;
        header.size = n.size;
        header.summary = n.summary;
        header.span = Some(n.span);
    } else {
        if header.first.is_some() || header.last.is_some() {
            return Err(broken("nonempty endpoints for empty root"));
        }
        header.height = 0;
        header.size = 0;
        header.summary = S::Index::empty(header.kind)?;
        header.span = None;
    }
    ws.put_root(owner, Some(header))
}

pub fn insert<S: TreeStore>(
    ws: &mut S,
    owner: Address,
    id: Address,
    value: NativeKey<S>,
    leaf: NativeLeaf<S>,
) -> Result<()> {
    let mut header = root(ws, owner)?;
    S::Index::validate_key(header.kind, &value)?;
    S::Index::validate_leaf(header.kind, &leaf)?;
    if id.slot == 0 || owner.slot == 0 {
        return Err(broken("invalid member/root kind"));
    }
    if ws.node(id)?.is_some() {
        return Err(broken("existing member identity"));
    }
    let key = FullKey {
        value,
        id: id.id,
        slot: id.slot,
    };
    let (mut cursor, mut parent, mut previous, mut next) = (header.head, None, None, None);
    let mut seen = BTreeSet::new();
    while let Some(current) = cursor {
        if !seen.insert(current) {
            return Err(broken("cyclic search path"));
        }
        let n = node(ws, owner, current)?;
        if n.parent != parent {
            return Err(broken("search parent mismatch"));
        }
        if n.kind != header.kind {
            return Err(broken("search native code mismatch"));
        }
        S::Index::check_insert(header.kind, &key.value, &n.key.value)?;
        if key == n.key {
            return Err(broken("duplicate full key"));
        }
        parent = Some(current);
        if key < n.key {
            next = Some(current);
            cursor = n.left;
        } else {
            previous = Some(current);
            cursor = n.right;
        }
    }
    ws.put_node(
        id,
        Some(Node {
            kind: header.kind,
            root: owner,
            key: key.clone(),
            leaf: leaf.clone(),
            parent,
            left: None,
            right: None,
            prev: previous,
            next,
            height: 1,
            size: 1,
            span: Span {
                first: key.value.clone(),
                last: key.value.clone(),
            },
            summary: S::Index::singleton(header.kind, &key.value, &leaf)?,
        }),
    )?;
    if let Some(p) = parent {
        edit(ws, owner, p, |n| {
            if key < n.key {
                n.left = Some(id);
            } else {
                n.right = Some(id);
            }
        })?;
    } else {
        header.head = Some(id);
    }
    if let Some(p) = previous {
        edit(ws, owner, p, |n| n.next = Some(id))?;
    } else {
        header.first = Some(id);
    }
    if let Some(n) = next {
        edit(ws, owner, n, |n| n.prev = Some(id))?;
    } else {
        header.last = Some(id);
    }
    ws.put_root(owner, Some(header))?;
    balance(ws, owner, Some(id))
}

pub fn revalue<S: TreeStore>(
    ws: &mut S,
    owner: Address,
    id: Address,
    leaf: NativeLeaf<S>,
) -> Result<()> {
    let n = node(ws, owner, id)?;
    S::Index::validate_leaf(n.kind, &leaf)?;
    if n.leaf == leaf {
        return Ok(());
    }
    edit(ws, owner, id, |n| n.leaf = leaf)?;
    balance(ws, owner, Some(id))
}

pub fn remove<S: TreeStore>(ws: &mut S, owner: Address, id: Address) -> Result<()> {
    let n = node(ws, owner, id)?;
    let mut header = root(ws, owner)?;
    if let Some(p) = n.prev {
        if node(ws, owner, p)?.next != Some(id) {
            return Err(broken("previous neighbour mismatch"));
        }
        edit(ws, owner, p, |p| p.next = n.next)?;
    } else {
        header.first = n.next;
    }
    if let Some(next) = n.next {
        if node(ws, owner, next)?.prev != Some(id) {
            return Err(broken("next neighbour mismatch"));
        }
        edit(ws, owner, next, |next| next.prev = n.prev)?;
    } else {
        header.last = n.prev;
    }
    ws.put_root(owner, Some(header))?;
    let start = match (n.left, n.right) {
        (None, child) | (child, None) => {
            replace_parent_link(ws, owner, id, child)?;
            n.parent.or(child)
        }
        (Some(left), Some(right)) => {
            let mut successor = right;
            let mut seen = BTreeSet::new();
            loop {
                if !seen.insert(successor) {
                    return Err(broken("cyclic successor path"));
                }
                if let Some(next) = node(ws, owner, successor)?.left {
                    successor = next;
                } else {
                    break;
                }
            }
            let replacement = node(ws, owner, successor)?;
            let start = if replacement.parent == Some(id) {
                Some(successor)
            } else {
                replace_parent_link(ws, owner, successor, replacement.right)?;
                edit(ws, owner, successor, |s| s.right = Some(right))?;
                edit(ws, owner, right, |r| r.parent = Some(successor))?;
                replacement.parent
            };
            replace_parent_link(ws, owner, id, Some(successor))?;
            edit(ws, owner, successor, |s| s.left = Some(left))?;
            edit(ws, owner, left, |l| l.parent = Some(successor))?;
            start
        }
    };
    ws.put_node(id, None)?;
    balance(ws, owner, start)
}

/// Quote selection is an explicit family capability, separate from generic
/// ordering and from any incidental numeric fields a native leaf may contain.
pub fn latest<S: TreeStore>(ws: &mut S, owner: Address, at: i64) -> Result<Option<(Uuid, u16)>> {
    let header = root(ws, owner)?;
    if !S::Index::supports_quote(header.kind) {
        return Err(Error::new(
            "unsupported_query",
            "latest requires a quote root",
        ));
    }
    last_at_or_before(ws, owner, at)?
        .map(|selected| {
            Ok((
                selected.member.id,
                S::Index::quote_leaf(header.kind, &selected.leaf)?,
            ))
        })
        .transpose()
}

/// Greatest complete (business key, UUID, member slot) at or before a time.
/// The upper cut includes every occurrence at that time, without UUID sentinels.
pub fn last_at_or_before<S: TreeStore>(
    ws: &mut S,
    owner: Address,
    at: i64,
) -> Result<Option<Selected<S::Index>>> {
    let header = root(ws, owner)?;
    let key = S::Index::time_key(header.kind, at)?;
    last_key_at_or_before(ws, owner, &key)
}

/// Select the last occurrence in the complete included native-key group.
pub fn last_key_at_or_before<S: TreeStore>(
    ws: &mut S,
    owner: Address,
    key: &NativeKey<S>,
) -> Result<Option<Selected<S::Index>>> {
    let header = root(ws, owner)?;
    S::Index::validate_key(header.kind, key)?;
    let (mut cursor, mut parent, mut selected) = (header.head, None, None);
    let mut seen = BTreeSet::new();
    while let Some(id) = cursor {
        if seen.len() >= 64 || !seen.insert(id) {
            return Err(broken("cyclic or overdeep selection search"));
        }
        let n = node(ws, owner, id)?;
        if n.parent != parent || n.kind != header.kind {
            return Err(broken("selection parent/code mismatch"));
        }
        parent = Some(id);
        if &n.key.value <= key {
            selected = Some(Selected {
                member: id,
                key: n.key.value,
                leaf: n.leaf,
            });
            cursor = n.right;
        } else {
            cursor = n.left;
        }
    }
    Ok(selected)
}

/// The scalar financial prefix path visits only search-path leaves and cached
/// left sums; it never calculates unused extrema by folding full summaries.
pub fn prefix<S: TreeStore>(ws: &mut S, owner: Address, before: Option<i64>) -> Result<i128> {
    let header = root(ws, owner)?;
    let total = S::Index::financial_summary(header.kind, &header.summary)?;
    let Some(before) = before else {
        return Ok(total.sum);
    };
    let boundary = S::Index::time_key(header.kind, before)?;
    let mut sum: i128 = 0;
    let mut cursor = header.head;
    let mut parent = None;
    let mut visited = BTreeSet::new();
    while let Some(id) = cursor {
        if visited.len() >= 64 || !visited.insert(id) {
            return Err(broken("cyclic or overdeep prefix search"));
        }
        let current = node(ws, owner, id)?;
        if current.parent != parent || current.kind != header.kind {
            return Err(broken("prefix parent/code mismatch"));
        }
        parent = Some(id);
        if current.key.value < boundary {
            let left = child_info(ws, owner, id, current.left, header.kind)?;
            let left = S::Index::financial_summary(header.kind, &left.summary)?.sum;
            let leaf = S::Index::financial_leaf(header.kind, &current.leaf)?;
            sum = sum
                .checked_add(left)
                .and_then(|s| s.checked_add(leaf))
                .ok_or_else(|| Error::new("overflow", "prefix sum"))?;
            cursor = current.right;
        } else {
            cursor = current.left;
        }
    }
    Ok(sum)
}

struct RangeFold<'a, K> {
    owner: Address,
    window: &'a KeyRange<K>,
    kind: IndexCode,
    seen: BTreeSet<Address>,
}

impl<K: Ord> RangeFold<'_, K> {
    fn visit<S>(
        &mut self,
        ws: &mut S,
        id: Option<Address>,
        parent: Option<Address>,
        depth: u16,
    ) -> Result<NativeSummary<S>>
    where
        S: TreeStore,
        S::Index: NativeIndex<Key = K>,
    {
        let Some(id) = id else {
            return S::Index::empty(self.kind);
        };
        if depth >= 64 {
            return Err(broken("range path depth"));
        }
        if !self.seen.insert(id) {
            return Err(broken("range cycle or duplicate reachability"));
        }
        let current = node(ws, self.owner, id)?;
        if current.parent != parent
            || current.kind != self.kind
            || current.height == 0
            || current.height >= 64
        {
            return Err(broken("range parent/code/height mismatch"));
        }
        S::Index::validate_key(self.kind, &current.key.value)?;
        S::Index::validate_leaf(self.kind, &current.leaf)?;
        S::Index::validate_summary(self.kind, &current.summary)?;
        let Span { first, last } = &current.span;
        if !(first <= &current.key.value && &current.key.value <= last) {
            return Err(broken("range leaf outside structural span"));
        }
        S::Index::validate_key(self.kind, first)?;
        S::Index::validate_key(self.kind, last)?;
        if self.window.contains(first) && self.window.contains(last) {
            return Ok(current.summary);
        }
        if self.window.below(last) || self.window.above(first) {
            return S::Index::empty(self.kind);
        }
        // Complete business-key groups include all engine occurrence ties.
        let left_possible = !self.window.below(&current.key.value);
        let right_possible = !self.window.above(&current.key.value);
        let mut result = if left_possible {
            self.visit(ws, current.left, Some(id), depth + 1)?
        } else {
            S::Index::empty(self.kind)?
        };
        if self.window.contains(&current.key.value) {
            let leaf = S::Index::singleton(self.kind, &current.key.value, &current.leaf)?;
            result = S::Index::combine(self.kind, &result, &leaf)?;
        }
        if right_possible {
            let right = self.visit(ws, current.right, Some(id), depth + 1)?;
            result = S::Index::combine(self.kind, &result, &right)?;
        }
        Ok(result)
    }
}

/// Ordered canonical subtree coverage over native business keys. Summary
/// algebra and the AVL never interpret a key as a timestamp.
pub fn range_keys<S: TreeStore>(
    ws: &mut S,
    owner: Address,
    window: &KeyRange<NativeKey<S>>,
) -> Result<NativeSummary<S>> {
    let header = root(ws, owner)?;
    S::Index::validate_summary(header.kind, &header.summary)?;
    if header.height >= 64
        || header.head.is_none() != header.span.is_none()
        || header.head.is_none() != (header.height == 0)
    {
        return Err(broken("range root height/population"));
    }
    let Some(Span { first, last }) = &header.span else {
        if header.summary != S::Index::empty(header.kind)? {
            return Err(broken("nonempty summary for empty root"));
        }
        return S::Index::empty(header.kind);
    };
    S::Index::validate_key(header.kind, first)?;
    S::Index::validate_key(header.kind, last)?;
    if first > last {
        return Err(broken("unordered root span"));
    }
    if window.is_empty() || window.below(last) || window.above(first) {
        return S::Index::empty(header.kind);
    }
    if window.contains(first) && window.contains(last) {
        return Ok(header.summary);
    }
    RangeFold {
        owner,
        window,
        kind: header.kind,
        seen: BTreeSet::new(),
    }
    .visit(ws, header.head, None, 0)
}

/// Exact time windows use the family's explicit monotonic time adapter. The
/// native fold remains valid for unrelated key types without this adapter.
pub fn range<S: TreeStore>(
    ws: &mut S,
    owner: Address,
    window: TimeRange,
) -> Result<NativeSummary<S>> {
    let code = root(ws, owner)?.kind;
    let map = |bound| match bound {
        TimeBound::Unbounded => Ok(Bound::Unbounded),
        TimeBound::Included(at) => S::Index::time_key(code, at).map(Bound::Included),
        TimeBound::Excluded(at) => S::Index::time_key(code, at).map(Bound::Excluded),
    };
    // Validate capability even for an unbounded or empty query.
    S::Index::time_key(code, 0)?;
    range_keys(
        ws,
        owner,
        &KeyRange {
            lower: map(window.lower)?,
            upper: map(window.upper)?,
        },
    )
}
