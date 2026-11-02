//! Privileged raw occurrence reads. Callers must authorize disclosure separately.
//!
//! A table pins the native snapshot. Structural counts prune discovery, but counts
//! in unvisited descendants remain trusted metadata, not an integrity audit.
use crate::{
    binding::Binding,
    index::NativeIndex,
    native_codec::{self, Address, Key, StoredValue},
    native_slice::{Error, Result},
    storage::{BatchGetOptions, Table},
    tree::{FullKey, Node},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    ops::Range,
};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_nodes: usize,
    /// Input keys, fetched values, serialized output, and reserved output storage.
    pub max_bytes: usize,
    pub batch_keys: NonZeroUsize,
    pub concurrency: NonZeroUsize,
}
#[derive(Clone, Debug, Default)]
pub struct Counters {
    pub gets: usize,
    pub batches: usize,
    pub read_bytes: usize,
    pub output_bytes: usize,
    /// Conservative reservation for both optional rank slots and final vector.
    /// Heap-owned key/leaf contents are covered by fetched and serialized bytes.
    pub allocation_bytes: usize,
    pub waves: usize,
    pub max_frontier: usize,
}
#[derive(Clone, Debug)]
pub struct Occurrence<I: NativeIndex> {
    pub rank: u64,
    pub address: Address,
    pub key: FullKey<I::Key>,
    pub leaf: I::Leaf,
}
#[derive(Clone, Debug)]
pub struct RankWindow<I: NativeIndex> {
    pub total: u64,
    pub revision: uuid::Uuid,
    pub occurrences: Vec<Occurrence<I>>,
    pub counters: Counters,
}
fn corrupt() -> Error {
    Error::new("corrupt_state", "rank traversal structure")
}
fn limited() -> Error {
    Error::new("work_limit", "rank traversal budget")
}
fn charge(total: &mut usize, extra: usize, limit: usize) -> Result<()> {
    *total = total
        .checked_add(extra)
        .filter(|n| *n <= limit)
        .ok_or_else(limited)?;
    Ok(())
}
fn fetch<B: Binding, K>(
    table: &Table<K, &'static [u8]>,
    keys: &[Key],
    limits: Limits,
    c: &mut Counters,
) -> Result<Vec<StoredValue<B>>> {
    let mut result = Vec::new();
    for chunk in keys.chunks(limits.batch_keys.get()) {
        if c.gets
            .checked_add(chunk.len())
            .filter(|n| *n <= limits.max_nodes.saturating_add(1))
            .is_none()
        {
            return Err(limited());
        }
        let encoded: Vec<_> = chunk.iter().map(Key::encode).collect();
        let refs: Vec<_> = encoded.iter().map(Vec::as_slice).collect();
        let remaining = limits
            .max_bytes
            .checked_sub(c.read_bytes)
            .and_then(|n| n.checked_sub(c.output_bytes))
            .and_then(|n| n.checked_sub(c.allocation_bytes))
            .ok_or_else(limited)?;
        let values = table.batch_get(
            &refs,
            BatchGetOptions {
                max_keys: limits.batch_keys.get(),
                max_bytes: remaining,
                concurrency: limits.concurrency,
            },
        )?;
        c.gets += chunk.len();
        c.batches += 1;
        for ((key, bytes), encoded) in chunk.iter().zip(values).zip(encoded) {
            let bytes = bytes.ok_or_else(corrupt)?;
            charge(
                &mut c.read_bytes,
                encoded.len(),
                limits.max_bytes - c.output_bytes - c.allocation_bytes,
            )?;
            charge(
                &mut c.read_bytes,
                bytes.value().len(),
                limits.max_bytes - c.output_bytes - c.allocation_bytes,
            )?;
            result.push(native_codec::decode_for::<B>(key, bytes.value())?);
        }
    }
    Ok(result)
}

/// Read a half-open window of raw membership ranks in total FullKey order.
///
/// This does not hydrate records, filter readers, or grant access to member IDs.
/// Budget exhaustion and discovered corruption reject the entire window. Batches
/// are storage calls, not measurements of network round trips.
pub fn rank_window<B: Binding, K>(
    table: &Table<K, &'static [u8]>,
    owner: Address,
    window: Range<u64>,
    limits: Limits,
) -> Result<RankWindow<B::Index>> {
    if window.start > window.end
        || limits.max_nodes == 0
        || limits.max_nodes == usize::MAX
        || limits.max_bytes == 0
    {
        return Err(Error::new("invalid_input", "rank window or limits"));
    }
    let mut c = Counters::default();
    let StoredValue::Root(root) = fetch::<B, K>(table, &[Key::Root(owner)], limits, &mut c)?
        .pop()
        .ok_or_else(corrupt)?
    else {
        return Err(corrupt());
    };
    B::Index::validate_summary(root.kind, &root.summary)?;
    if root.size == 0 {
        if root.head.is_some()
            || root.first.is_some()
            || root.last.is_some()
            || root.height != 0
            || root.span.is_some()
        {
            return Err(corrupt());
        }
        return Ok(RankWindow {
            total: 0,
            revision: root.revision,
            occurrences: vec![],
            counters: c,
        });
    }
    if root.height == 0
        || root.height >= 64
        || root.first.is_none()
        || root.last.is_none()
        || root.span.is_none()
    {
        return Err(corrupt());
    }
    // Empty windows deliberately trust unvisited metadata after header validation.
    let expected = window.end.min(root.size) - window.start.min(root.size);
    let expected = usize::try_from(expected).map_err(|_| limited())?;
    if expected == 0 {
        return Ok(RankWindow {
            total: root.size,
            revision: root.revision,
            occurrences: vec![],
            counters: c,
        });
    }
    if expected > limits.max_nodes {
        return Err(limited());
    }
    let slot_bytes = std::mem::size_of::<Option<Occurrence<B::Index>>>()
        .checked_add(std::mem::size_of::<Occurrence<B::Index>>())
        .ok_or_else(limited)?;
    let allocation = expected.checked_mul(slot_bytes).ok_or_else(limited)?;
    charge(
        &mut c.allocation_bytes,
        allocation,
        limits.max_bytes - c.read_bytes,
    )?;
    let head = root.head.ok_or_else(corrupt)?;
    let mut seen = BTreeSet::from([head]);
    let StoredValue::Node(node) = fetch::<B, K>(table, &[Key::Node(head)], limits, &mut c)?
        .pop()
        .ok_or_else(corrupt)?
    else {
        return Err(corrupt());
    };
    if node.parent.is_some()
        || node.size != root.size
        || node.height != root.height
        || Some(&node.span) != root.span.as_ref()
    {
        return Err(corrupt());
    }
    let mut frontier = vec![(head, node, 0u64, None, None)];
    let mut occurrences: Vec<Option<Occurrence<B::Index>>> = Vec::new();
    occurrences
        .try_reserve_exact(expected)
        .map_err(|_| limited())?;
    occurrences.resize_with(expected, || None);
    while !frontier.is_empty() {
        c.waves += 1;
        c.max_frontier = c.max_frontier.max(frontier.len());
        let mut wanted = vec![];
        for (_, node, _, _, _) in &frontier {
            for child in [node.left, node.right].into_iter().flatten() {
                if seen.len() >= limits.max_nodes {
                    return Err(limited());
                }
                if !seen.insert(child) {
                    return Err(corrupt());
                }
                wanted.push(Key::Node(child));
            }
        }
        let values = fetch::<B, K>(table, &wanted, limits, &mut c)?;
        let mut children = BTreeMap::new();
        for (key, value) in wanted.into_iter().zip(values) {
            let (Key::Node(id), StoredValue::Node(node)) = (key, value) else {
                return Err(corrupt());
            };
            validate::<B::Index>(&node, id, owner, root.kind)?;
            children.insert(id, node);
        }
        let mut next = vec![];
        for (id, node, start, lower, upper) in frontier {
            if lower.as_ref().is_some_and(|k| &node.key <= k)
                || upper.as_ref().is_some_and(|k| &node.key >= k)
            {
                return Err(corrupt());
            }
            validate::<B::Index>(&node, id, owner, root.kind)?;
            let left = node
                .left
                .map(|id| children.remove(&id).ok_or_else(corrupt))
                .transpose()?;
            let right = node
                .right
                .map(|id| children.remove(&id).ok_or_else(corrupt))
                .transpose()?;
            for child in [&left, &right].into_iter().flatten() {
                if child.parent != Some(id)
                    || lower.as_ref().is_some_and(|k| &child.key <= k)
                    || upper.as_ref().is_some_and(|k| &child.key >= k)
                {
                    return Err(corrupt());
                }
            }
            let ls = left.as_ref().map_or(0, |n| n.size);
            let rs = right.as_ref().map_or(0, |n| n.size);
            let lh = left.as_ref().map_or(0, |n| n.height);
            let rh = right.as_ref().map_or(0, |n| n.height);
            if ls.checked_add(rs).and_then(|n| n.checked_add(1)) != Some(node.size)
                || lh.abs_diff(rh) > 1
                || lh.max(rh).checked_add(1) != Some(node.height)
                || left
                    .as_ref()
                    .is_some_and(|n| n.key >= node.key || n.span.last > node.key.value)
                || right
                    .as_ref()
                    .is_some_and(|n| n.key <= node.key || n.span.first < node.key.value)
                || left.as_ref().map_or(&node.key.value, |n| &n.span.first) != &node.span.first
                || right.as_ref().map_or(&node.key.value, |n| &n.span.last) != &node.span.last
            {
                return Err(corrupt());
            }
            let rank = start.checked_add(ls).ok_or_else(corrupt)?;
            if (rank == 0 && (root.first != Some(id) || node.prev.is_some()))
                || (rank.checked_add(1) == Some(root.size)
                    && (root.last != Some(id) || node.next.is_some()))
            {
                return Err(corrupt());
            }
            if window.contains(&rank) {
                let bytes = serde_json::to_vec(&(rank, id, &node.key, &node.leaf))
                    .map_err(|_| corrupt())?
                    .len();
                charge(
                    &mut c.output_bytes,
                    bytes,
                    limits.max_bytes - c.read_bytes - c.allocation_bytes,
                )?;
                let position = usize::try_from(rank - window.start).map_err(|_| corrupt())?;
                let slot = occurrences.get_mut(position).ok_or_else(corrupt)?;
                if slot.is_some() {
                    return Err(corrupt());
                }
                *slot = Some(Occurrence {
                    rank,
                    address: id,
                    key: node.key.clone(),
                    leaf: node.leaf.clone(),
                });
            }
            for (address, child, offset) in [
                (node.left, left, start),
                (node.right, right, rank.checked_add(1).ok_or_else(corrupt)?),
            ] {
                if let (Some(address), Some(child)) = (address, child) {
                    let end = offset.checked_add(child.size).ok_or_else(corrupt)?;
                    if offset < window.end && end > window.start {
                        let bounds = if Some(address) == node.left {
                            (lower.clone(), Some(node.key.clone()))
                        } else {
                            (Some(node.key.clone()), upper.clone())
                        };
                        next.push((address, child, offset, bounds.0, bounds.1));
                    }
                }
            }
        }
        frontier = next;
    }
    let mut ordered = Vec::new();
    ordered.try_reserve_exact(expected).map_err(|_| limited())?;
    for occurrence in occurrences {
        ordered.push(occurrence.ok_or_else(corrupt)?);
    }
    let occurrences = ordered;
    Ok(RankWindow {
        total: root.size,
        revision: root.revision,
        occurrences,
        counters: c,
    })
}
fn validate<I: NativeIndex>(
    n: &Node<I>,
    id: Address,
    owner: Address,
    kind: crate::index::IndexCode,
) -> Result<()> {
    if n.root != owner
        || n.kind != kind
        || n.key.id != id.id
        || n.key.slot != id.slot
        || n.size == 0
        || n.height == 0
        || n.height >= 64
        || n.span.first > n.key.value
        || n.key.value > n.span.last
    {
        return Err(corrupt());
    }
    I::validate_key(kind, &n.key.value)?;
    I::validate_key(kind, &n.span.first)?;
    I::validate_key(kind, &n.span.last)?;
    I::validate_leaf(kind, &n.leaf)?;
    I::validate_summary(kind, &n.summary)?;
    Ok(())
}
