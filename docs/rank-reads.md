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

## Authorized member pages — C1.4

Ordinary Rust callers use `Store::root_page(request, &RootPagePolicy)`. HTTP/stdio
JSON-RPC exposes `roots.page` with the service's default policy. The existing Node
client already supplies `call`; no new command parser or method wrapper is needed:

```js
const catalog = await client.call('model.describe');
const request = {
  model: catalog.model, owner: accountId, slot: 2,
  limit: 16, candidate_budget: 64, cursor: null,
};
const page = await client.call('roots.page', request);
// page.occurrences: [{ rank: '0', slot: 1, record: { id, contract, ... } }]
// Resume only when page.cursor is non-null; budgets may change between pages.
```

Here `owner` is the model record owning the root, not a client-supplied authority
principal. The caller must have Read action and owner accessibility for the root, and the model must
explicitly declare `members` plus `summary`. A root record read authorizes that declared
public summary; FULL aggregates may include hidden contributors. This does not grant
leaf, body or ID reads. Every hydrated member still requires its own owner-access check. The supplied Calculation Account history opts in; other roots require
an explicit model declaration. Member enumeration is an engine structural capability,
not a business-summary operation added to each family.

Results contain ordered `occurrences`, `visited`, `total`, `exhausted`, `cursor`
and `revision`. Rank/total use exact decimal strings on the wire. A record can
appear once per membership slot; these are not distinct-record or visible-row ranks.
Filtered pages may contain no visible rows but still make progress. Output/candidate
limits are independently bounded. Exhaustion returns no cursor. Discovery, authority,
epoch fencing and hydration use the same native snapshot.

Continuations bind store/model/actor/tenant/root and both root state and current
owner/contract projection/authority epochs. Owner-scope or payload-only changes
can invalidate them while root summaries and root revision stay unchanged. The
signed payload carries raw next rank and query identities, not hidden member IDs,
keys or pending frontiers. HMAC supplies integrity, not confidentiality. Per-page
output/candidate budgets can change on resume under the trusted ceilings. A
`query_changed` response requires restarting the read; no mutation plan is refreshed.

Default RPC ceilings are 32 outputs, 128 candidates, 4,096 accounted application
gets and 4 MiB of accounted bytes. Trusted Rust embedding can pass another explicit
`RootPagePolicy`; request JSON cannot override it. Node, hydration, output and setup
budgets are cumulative, with conservative output reservation/encoding charges.
These are not strict peak-RSS or wire-byte bounds. Epoch guards use bounded native
batch reads too; their digest framing remains identical to existing UUID cursors.
Existing `records.page` query meaning is preserved.

Tests cover normal validated populations of 50/100/1,000 sources, ordered ties,
private gaps, permissions, progressing partial pages, budget adaptation, same-snapshot
epochs, member payload/owner-scope changes with unchanged root revision, revocation and
cursor substitution. Local default-backend correctness is not a distributed latency
or throughput benchmark. See [C1.4 evidence](checkpoints/c1-authorized-pages.json).
