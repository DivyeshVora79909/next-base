# Proposed Node engine contract

Status: design for a bounded prototype; **JS-P1 implemented, later gates pending**.
The user's execution flag has been supplied. [Context](README.md),
[capability preservation](capabilities.md) and [acceptance stages](checkpoints.md)
define scope. The current Rust implementation remains the reference for invariants,
not an obligation to preserve its internal types, names or physical layout.

## 1. One declaration authority, three index concepts

Author trusted local ESM modules containing JSON Schemas, declarative metadata and
ordinary function implementations. Prepare an immutable catalog once. Native/remote
clients may submit data and declared operations, never executable source/functions.
Public schemas and population/query metadata are projections of the same catalog.
JSON Schema `$ref` references a schema, not a database record.

| Concept | Responsibility |
| --- | --- |
| Contract | Typed partition roles, one logical ordered role, input/contribution shape, monoid identities/combine/finalize, validator scopes |
| Named view | Distinct index identity using a contract; explicitly separate effective/created/other semantic orders |
| Model binding | Eligibility plus field/reference projections into a named view, stable occurrence identities |

Example is explanatory configuration, not a promised API or a second language:

```js
const balance = {
  partition: [recordIdSchema, recordIdSchema],
  order: exactIntegerSchema,
  inputs: { incoming: exactIntegerSchema, outgoing: exactIntegerSchema },
  aggregates: { net: netPrefixMonoid },
  validators: [{ scope: "allPrefixes", implementation: nonnegativePrefix }]
};
const views = {
  effectiveBalance: { contract: balance },
  createdTotals: { contract: totalsOnlyContract }
};
const binding = {
  fields: { account: "accountId", owner: header("owner"), amount: "amount" },
  memberships: [
    { view: "effectiveBalance", partition: ["account", "owner"],
      order: "effectiveAt", inputs: { incoming: "amount", outgoing: zero } },
    { view: "createdTotals", partition: ["account", "owner"],
      order: header("createdAt"), inputs: { incoming: "amount", outgoing: zero } }
  ]
};
```

Field selectors/constants are prepared projections; callbacks are trusted pure
implementations. Other models can map different names to the same semantic roles.
Same contract does not imply same view; identical field spelling does not establish
compatible units, types or financial meaning. A declared view admits compatible
bindings from several models only when their contribution/order semantics agree.
No implicit field-presence permission: eligibility/missing/null behavior is declared;
malformed required input fails rather than silently leaving the index.

Use stable named IDs plus explicit behavior/format identities, not concatenated
field names or `Function.toString()` hashes. Canonical typed descriptors form catalog
fingerprints; trusted function IDs/versions and artifact provenance pin behavior.
Functions are not serialized closures. Duplicate incompatible view definitions fail
preparation; duplicate binding occurrences fail unless intentionally distinct.
Partition tuples are typed and ordered in encoding, but `(a,b)` versus `(b,a)`
group the same records when all values are fixed; no prefix-access power follows
merely from maintaining a separate AVL per complete tuple.

## 2. Occurrences, tree structure and arithmetic

Conceptual keys, not a frozen physical encoding:

```text
tree       = (tenantNamespace, catalogGeneration, viewId, partitionTuple)
membership = (tenantNamespace, catalogGeneration, sourceId, viewId, stableBindingOccurrence)
orderKey   = (projectedOrderedValue, sourceId, stableBindingOccurrence)
```

One logical order can be time, integer, text or another declared total-order domain;
stable ties do not count as a second user ordering role. Start with exact integers
and deterministic binary string order, plus stable IDs; no locale-dependent comparator,
NaN, implicit timestamp coercion or unsafe integer conversion. Tenant isolation is
mandatory even when partition roles are ordinary fields. Root identity is the tree's
scope, not whichever member currently occupies its rotating AVL root.
Physical membership, route and cleanup keys are generation-scoped, even when logical
source/view/occurrence identity survives a rebuild. Candidate construction must never
overwrite active-generation entries. Selectors may address trusted source-header
metadata such as created-at; clients cannot forge those headers through body fields.

Each occurrence owns left/right links, height or balance metadata, structural size
and summaries. Root headers locate roots; parent/previous/next links are optional
optimizations requiring evidence, not prerequisites. Keep source bodies separate
from engine-owned membership entries so unrelated index-node changes do not all
rewrite the source body. All entries still share one atomic transaction. Logical
segment objects need not be serialized as one giant source record.

`size(v)=size(L)+1+size(R)`; rank is derived, not stored globally. The engine reconciles
old/final membership multisets: remove old positions, insert new, repair changed
contributions, skip unchanged projections. Retargets affect old and new partitions;
deleting the final occurrence changes that partition to the monoid identity.
Repeated references/participation require stable occurrence IDs and defined duplicate
semantics. Structural occurrence count and distinct-source count are different.

For each ordered monoid: `A(v)=A(L) combine lift(v) combine A(R)` with identity.
Rotations preserve inorder; associativity permits regrouping, not operand permutation.
No subtraction/inverse is required. Update descendants before recomputing ancestors.
Expose `finalize(summary)` for average/SD/etc; do not average averages. Prototype
exact quantities use BigInt in memory with explicit units/scale and canonical decimal
strings in JSON. No JSON BigInt or unsafe Number round-trip. Arbitrary rationals and
floating statistics need their own declared arithmetic contract before admission.
Floating regrouping is approximate unless proved otherwise. Monoid laws are developer
obligations backed by algebraic witnesses; a schema validator cannot prove them.

Counts/sums/min/max/prefix summaries are initial modules. Variable-size monoids may
be supported but must account for combine/storage/output bytes. String length can
use sum-of-lengths; materialized concatenation has no constant-size guarantee simply
because inputs are often empty. No claim every associative operation is cheap.

## 3. Validation, references and publication

Separate record shape, record/parent predicates, tree structure, cached-summary
correctness and business invariants. Business validators name whole partition,
all-prefix, or explicit range scopes. Do not apply a root-balance rule blindly to
each rotation-dependent subtree. All-prefix nonnegativity uses a proved prefix
monoid; arbitrary quantified rules need suitable augmentation or explicit extra work.
Linear predicates over summaries check conditions; they do not solve constraints or
generate valid records automatically. A validator's inspected fields/ranges are
dependencies just like a calculation's inputs.
Validator lifetime follows its declared scope/anchor: a live empty scope validates
the identity summary. Removing the final member alone cannot erase that obligation;
retiring the anchor and all its dependents may retire the scope explicitly.

Relations declare source field/array slots, target model/domain, optionality and
`onDelete: reject` initially. The engine derives protected reverse-reference entries;
models/tools do not maintain a second relationship inventory. 1:1 requires tuple
uniqueness; n:m is a junction with two 1:n references and optional pair uniqueness.
Final-state uniqueness releases old claims before acquiring final claims, permitting
valid swaps. Protect missing keys as well as existing keys. Stage all authored rows
before checking forward references; reject unresolved final references. Reference
cycles and forbidden causal cycles are distinct. Generic cascade/nullify is deferred.
Cross-parent equality or chronological predicates are explicit rules, not inferred
from matching reference types. Explicit reference-derived dependencies cover updates
to parent values, including hidden dependents and previously empty target scopes.

Conceptual mutation pipeline (ordinary functions, one transaction owner):

```text
authenticate/authorize command scope
  -> validate/stage authored final inputs
  -> resolve final reference/unique/membership changes
  -> settle dependent computations and generated occurrences
  -> validate final scopes and final authority
  -> publish source + indexes + routes + revisions + receipt + effect intent once
```

Intermediate structural assertions may fail early; business validation must allow
jointly repairing commands whose settled final state is valid. Unresolved computed
values are pending/errors, never zero. Reconcile generated output creation, update,
absence and reactivation with stable producer/role identities and first-creation
metadata. Direct client writes cannot modify these internal rows. External provider
calls occur after a committed intent, never in a replayable calculation/validator.

## 4. Reactive semantics

Two dependency types share one explicit registration interface:

- Direct: `(sourceIdentity, field)` including declared relationship/authority inputs.
- Ordered: `(viewId, partition, summaryField, keyBounds)` with explicit open/closed
  endpoints and optional infinities. Numeric/string/time orders use the same engine.

Resolved declared selectors supply pure-function inputs. Dynamic bounds/calculations
may use an explicit transaction-bound tracked read facade which records successful,
absent and empty reads before returning values or pending results. Raw store access,
ambient clock/random/I/O and undeclared mutable closure inputs are unavailable to
replayable model calculations. Ordinary JavaScript is not automatically dependency-
tracked; there is no source-code analysis that infers hidden reads.

A range fold computes a value. Reverse interval stabbing discovers subscribers of
a changed point. These are separate algorithms. Route contribution changes, old/new
positions, old/new partitions, changed bounds and partition-empty transitions; replace
old registrations atomically. Empty ranges and producers currently emitting nothing
remain registered. Final-graph causality governs diamonds and moved queries, not
command order or the historical graph. Use an explicit pending worklist/evaluation
stack with pending-item coalescing and input-version invalidation; a permanent visited
set would miss changes after an earlier evaluation. Recursive helpers are fine;
unbounded JavaScript call-stack depth and hidden repeated scans are not contracts.

Reject causal feedback cycles initially; do not silently iterate to an unproved fixed
point. A calculation sees settled predecessors or remains pending. Read evidence and
registrations must reconcile even when the visible result is unchanged. Final-state
equality/no-op elimination cannot discard conflict guards.

An upper-endpoint AVL with lower-bound pruning does not automatically prove
`O(log n + matches)` reporting. Select a proved reporter or charge actual visited
registrations; worst-case linear discovery is possible. Keep this distinct from
`O(log n)` range folds. One-sided, fixed-orientation subscriptions can reduce to
threshold ranges. Rank reads are supported, but reactive rank-window subscriptions
are deferred: insertion before a rank window can change it without stabbing it.
Time passing without a stored change requires explicit clock/wakeup input; the
ordering index alone is not a scheduler or rate-limit admission protocol.

## 5. Read, authority and work contracts

Assuming bounded comparison and fixed-size summary arithmetic, logical tree work for
point/rank/select and range folds is `O(log(n+1))`. Enumerate a
contiguous window in `O(log(n+1)+k)` node work; count/bound-pruned BFS batches independent
frontiers and hydration on one snapshot. Finite concurrency, buffering and bytes
remain costs. A batch is not necessarily one wire RTT. Do not call select separately
for every rank. Residual filters can inspect many candidates for little output;
raw occurrence ranks are not visible, filtered or distinct-record ranks.

Owner-only baseline: same tenant and action; Read/Create/Update scope is self, strict
descendants and direct Group parents; Delete is self/strict descendants. Direct Tenant
parent is not ordinary data scope; tenant-grant inheritance is separate. Admin does
not widen ordinary data scope. Create checks requested owner; update checks both
old and new owners before CAS diagnostics and against final authority. Keep engine
repairs privileged while authorizing client commands and retargeted references.
No readers/read_by/indexes/inference. The principal DAG must be acyclic and same-tenant.
Prototype uses explicit fixture authority; this is not a production authentication API.

For scoped reads, declare owner as a partition role and k-way merge accessible owner
streams with one comparator/tie order, bounded initialization and candidate work.
An authorization-candidate view must bind that role to the trusted source owner;
a similarly named arbitrary body field is insufficient. Preparation checks that
binding and the selected resource/action plan, with final per-record disclosure.
K-way merge is a general multi-stream algorithm, not an authorization primitive alone.
Full-parent ordered integrity can require a separate owner-independent membership;
noncommutative summaries from owner streams cannot simply be concatenated in owner
order. Shared business roots may contend legitimately. Tenant namespace alone does
not require a mutable tenant-wide aggregate/counter.

Readable semantic anchors expose only explicitly published summaries, possibly FULL
summaries including hidden contributions; they never reveal unauthorized member IDs
or bodies. A generic partition without a record anchor needs an explicit read policy.
Do not assume a partition tuple grants access. Cursors bind catalog/view/partition,
query and authority/snapshot-or-scope revision; changed relevant state rejects or
restarts explicitly. Scope-local fencing may coordinate necessary shared reads;
no universal population/revision write on every mutation.

## 6. Storage, index lifecycle and limits

Adapter obligations: coherent point/batch reads, protected absence/ranges used by
invariants, staged put/delete, one atomic commit, rollback and an explicit commit
outcome. A generic KV `get/put` interface without these semantics is insufficient.
Async Node functions await native adapter operations; no Surreal dependency or Rust
host required for the prototype. Snapshot isolation alone does not prevent write
skew. Later adapters must prove read/write invariant protection or explicit guards.

Memory baseline may serialize writers and use an attempt overlay over a stable base;
avoid deep-cloning the complete store per mutation while claiming logarithmic work.
Serialization is a labeled test-adapter property, not a production global mutation
counter or distributed acceptance. After known conflicts, reject cleanly initially;
unknown commit outcomes require original receipt/status recovery, never blind replay
with a new operation identity. Prototype atomic rollback is not crash durability.

Lifecycle: `declared -> building -> checked -> active -> retired`. Initially pause
all writers, including workers, while building a candidate generation; readers retain
the old catalog/snapshot. Build/fold/check from source, activate once, retain old data
until admitted in-flight reads finish. Activation invalidates old-generation cursors;
idle serialized cursors do not pin storage forever. Failed validation leaves the old active
generation intact. Changing order/mapping/monoid can require rebuilding; changing only
a whole-partition validator may reuse verified summaries for revalidation. Removal
rejects live references to the view or replaces dependencies in the same migration.
Rebind/rebuild affected routes, computations, claims and validator evidence as part of
the candidate generation and settle them before activation. If a changed definition
changes generated source records, stage those changes too; switching only root pointers
is insufficient. Initial support may reject a migration class it cannot settle safely,
with explicit recreation as the alternative, instead of leaving stale derived state.
Physical cleanup is proportional to entries. Persistent chunking, crash recovery and
online catch-up are separate gates, not hidden in the memory prototype.

Unsorted bulk input generally requires `O(n log n)` sorting; sorted bulk tree/summary
construction is `O(n)` plus projection/validation. New index construction has an
input-size lower bound. Full independent inventories are explicitly batch/stream
operations; normal writes/open must not acquire hidden population scans or arbitrary
4096-record ceilings. Work/byte/time budgets remain explicit and configurable;
exhaustion returns rejection or incomplete evidence, never a false integrity pass.

## 7. Composition, dependencies and unresolved gates

Public surface should represent real capabilities: prepare catalog, transact/read,
plan/install/remove views, source-derived checking, and population/workload tools.
Names can change during JS-P1; maintain one implementation behind direct calls and
future RPC handlers. Internal balancing/secret/worker helpers are not remotely callable.
No wrapper around each filesystem operation, loop or process command; no bespoke CLI.
Keep population candidates caller-owned, seeded and proposal-local; commit/reject
updates available reference space/uniqueness/fanout only after authoritative outcome.
Optional solvers supply candidates, not a validity or performance guarantee.

Choose one validator: JSON Schema + Ajv is the default candidate, already used in
the repository. JS-P1 checks supported dialect, exact-value schemas, license/security
and compatible maintained versions; compile/cache once. Avoid parallel Zod/Valibot
authority or a portability wrapper before a real requirement. Use Node built-ins for
test runner, async orchestration and resource measurement. Authoring is trusted ESM
plus standard schemas; arbitrary closures are not a portable wire configuration.

Persistent adapter/client selection (FoundationDB/redb/SurrealKV or another engine)
is **unresolved** for Node until maintenance, licensing, native bindings and transaction
conformance are checked. Existing Rust adapters are references, not ready Node APIs.
TiKV, B/B+ page rewrites, canonical exact-median trees and native-rank-skip assumptions
are not selected. No promise JIT matches Rust CPU/memory behavior. Model/system
metadata should remain opaque typed data so measured hotspots can later move behind
the same semantic boundary; speculative FFI frameworks are unnecessary now.

After prototype gates: persistent crash/concurrency/receipt acceptance; full
email/phone identity and session fencing; credentials/key custody and durable provider
adapters; object lifecycle/full fake pipeline; retention/recovery/capacity/deployment.
Maintain distinct provider implementations (e.g. Resend/Brevo), without requiring a
versioned operation naming convention. Optional live feeds, recurrence, frontend,
domain accounting/CRM/HRM models and TiKV remain separate. See the capability map for
retained guarantees and missing behaviors; omission from the prototype is not deletion.

| Decision still requiring evidence | Gate / disposition |
| --- | --- |
| Exact JSON Schema subset, codecs and supported Node/Ajv versions | JS-P1 compatibility/dependency check; explicit integer/string order baseline above |
| Reverse-interval reporter and its actual adversarial bound | JS-P3 algorithm witness; never substitute rank-window enumeration or claim a proof from AVL balance |
| Reuse of current population/workload code versus replacement | JS-P5 demonstrate equivalent constraints with the same prepared catalog; compare maintenance surface |
| Native Node persistent client and concurrency mapping | After JS-P5; choose only after client support and real adapter conformance review |
| Online migration, custom floating/variable-size algebras, reactive rank windows | Outside initial acceptance; require explicit semantics and cost evidence before adding |
