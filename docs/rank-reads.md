# Trusted rank-window reads

C1.3 supplies `tree_read::rank_window`, a Rust engine primitive over the existing
linked augmented AVL. It uses `Table::batch_get` on the caller's transaction.
It is not a public query endpoint and grants no access to member IDs or values.

```rust,ignore
use std::num::NonZeroUsize;
use rebase_semantic_proof::{binding::Calculation, tree_read};

// table and root_address belong to an already-open trusted engine snapshot.
let result = tree_read::rank_window::<Calculation, _>(
    &table,
    root_address,
    100..150, // zero-based raw occurrence ranks, end excluded
    tree_read::Limits {
        max_nodes: 2_000,
        max_bytes: 4_000_000,
        batch_keys: NonZeroUsize::new(64).unwrap(),
        concurrency: NonZeroUsize::new(16).unwrap(),
    },
)?;
// result.total, result.revision, result.occurrences, result.counters
```

The same function handles any compiled native key/leaf family. A supplied
String-keyed `CountOnly` family has unit business summaries; structural sizes
still support rank. Keys order by the family's native `Ord`, then UUID and slot.
A source record with two memberships occupies two positions, including when both
join the same root. The result is occurrence order, not distinct-record rank or
authorized filtered rank. `revision` identifies root state, not every hydrated
payload or authorization change.

## Traversal and budgets

The half-open window is clipped to the root's structural count. Empty and entirely
out-of-range windows read only the canonical header; they do not audit its children.
An inverted window rejects. For a nonempty window, the reader batches child roots,
uses their checked sizes to locate each parent's rank and prunes disjoint subtrees.
Immediate child roots can be fetched even when their descendants are pruned.
Rank-indexed output slots return ordered results without a final comparison sort.

`max_nodes` counts fetched node values, excluding the single root header. `max_bytes`
accounts for input encoded keys, fetched values, serialized output and conservative
reservations for both output vectors. Output reservations are checked before
allocation. These are accounted budgets, not a bound on every allocator, SDK buffer,
frontier/map entry or process RSS. Node/key bounds additionally limit overhead.
`batch_keys` bounds a table call; `concurrency` bounds simultaneous native requests
where supported. The local fallback remains sequential. A byte/work/storage error
returns no partial window; callers can explicitly request smaller windows.

Counters report gets (including the header), table batches, exploration waves,
maximum frontier and accounted bytes. Waves/batches are not measured wire RTTs.
For a healthy balanced tree, a contiguous k-occurrence window discovers O(log n+k)
node values, including boundary lookahead. Set/map bookkeeping adds CPU cost
(up to O(p log p) for p fetched nodes), as do key comparison and serialization.
This does not eliminate output bytes, storage latency, authority checks or cascades.

Encountered roots/nodes and child relationships are checked for kind/root/address,
parent links, order, height, spans and size equations. Counts in unvisited descendants
remain trusted maintained metadata. Run the independent source-inventory checker
for complete integrity; a selective read cannot prove every pruned subtree valid.
All discovery uses the supplied table's snapshot, including writable overlays.

## Next: C1.4 authorized integration

First accept the owner-inclusive reader-policy correction in roadmap C2.R; current
immediate-owner/fallback folding is not the user's newly specified first-minimal
selection. This is a semantic gate, not a reason to weaken member disclosure checks.

C1.4 must compose this primitive with the existing authority resolver and public
projection. Root summary permission alone must not permit member enumeration.
Add explicit declared member-read capability, reauthorize the owner and filter every
hydrated record, including private outputs. Hydration uses the same transaction.
Do not pass caller-chosen unbounded budgets through the network: apply trusted
configured ceilings and separate candidate/output/byte budgets.

Bind continuation to store/model/actor/tenant/query/root and to both root revision
and current authority/reader-contract projection epochs. Reader or payload changes
can invalidate a page without changing an index membership. Candidate rank is not
visible rank; bounded filtering can return fewer results and must preserve progress.
A signed cursor has integrity, not confidentiality. Do not place hidden member IDs,
keys or other undisclosed facts in a plaintext signed payload. Either explicitly
authorize topology/count disclosure for raw-rank cursors or select a confidential
continuation representation with its own key/recovery contract.

Acceptance must cover inaccessible/private records, ties and duplicate memberships,
empty/partial pages, budget exhaustion, payload-only/reader-only edits, revocation,
rekeys, cross-store/query cursor substitution and concurrent source mutations.
Preserve existing UUID-page semantics. No public `members` operation is implemented
by C1.3. See [roadmap](roadmap.md) and [C1.3 evidence](checkpoints/c1-rank-reader.json).
