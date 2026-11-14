# Node prototype checkpoints

This is a proposed implementation sequence against current main `77a8fd2`.
The user has supplied the implementation flag. JS-P0 documentation review and JS-P1
and JS-P2 are complete; JS-P3 and raw JS-P4a are accepted for the local volatile
adapter. Full JS-P4 and JS-P5 remain unaccepted. See
[JS-P1 evidence](../checkpoints/js-p1.json) and [JS-P2 evidence](../checkpoints/js-p2.json).
The existing Rust engine and its historical evidence remain the current baseline.
Persisted/store-format compatibility is dropped: do not migrate or decode Rust store
bytes. Semantic fixtures may be copied with their provenance and independently checked.

Read the [overview](README.md), [architecture](architecture.md), and
[capability roadmap](capabilities.md) together with this sequence. The future
prototype belongs under `prototypes/node-engine/`; its package and evidence are
isolated from the existing native application.

Each checkpoint produces a small runnable contract before expanding its scope.
Use ordinary Node ESM functions and explicit state, with Node's built-in test runner.
Keep a single JSON Schema authority; JS-P1 selects Ajv 8.20.0 with explicit synchronous
schema/field-binding limits and a pinned dependency graph. Bindings supply ordinary
functions for semantics that JSON Schema cannot express. Do not add a second DSL,
new CLI, or Python/Rust implementation for this prototype.

## JS-P0 — Review the bounded design

**Entry:** inspect the source revision, current transaction and owner-only contracts,
index mathematics, and the retained-capability inventory. Record uncertainty rather
than inferring parity from reused names.

**Deliverable:** reviewed architecture, capability mapping and this dependency-ordered
plan. Name the contract/binding boundary, occurrence identity, transaction guarantees,
independent oracle and explicit exclusions. Resolve implementation-blocking semantics
before enabling JS-P1; leave adapter-specific deployment choices at their own gates.

**Witnesses:** trace source mutation through references, multiple memberships,
settlement, validation and one publication. Trace an absent uniqueness claim and an
empty dependency result; neither may disappear as an optimization. Review one hidden
contributor and one owner transfer against disclosure and final authorization rules.

**Exit:** coordinating review finds every current capability retained in the roadmap
or explicitly deferred with an acceptance gate. The separate implementation flag is
required to enter JS-P1; planning review itself supplies no implementation proof.

**Limits:** neither a production replacement decision nor a production schedule.
The prototype is not a promise of production readiness in one to three days.

## JS-P1 — Executable specification and transaction boundary

**Entry:** JS-P0 reviewed and implementation flag supplied. Select and document exact
key comparison, numeric domain, stable identities and JSON Schema subset.

**Deliverable:** a prepared model compiler over named index contracts and bindings;
source schemas, references, memberships, summaries, dependencies and developer metadata
share this authority. Reject missing bindings, unstable/duplicate slots, incompatible
root/key/summary declarations and unsupported schema features before opening a model.
Add a transactional in-memory KV adapter with explicit attempt/snapshot state,
point and range reads, same-view batch reads, overlay reads and one atomic commit.
Protect existence, absence and scanned ranges; retained read guards survive no-op
elimination. Aborted attempts publish no partial source or derived rows.

**Witnesses:** start with a flat source-fact oracle that enumerates declared
occurrences and independently sorts/folds them without tree or writer-cache helpers.
Test malformed declarations and schema/binding disagreement, absent-key reservation,
protected empty scans, read-your-writes/deletes, no-op guards and failure before each
publication boundary. Verify deterministic preparation identity from declared semantics.

**Exit:** compiler and adapter contract tests pass using Node's test runner; independent
expected results can be derived from source facts with reproducible seeds. Document
what serialization the memory adapter enforces and which guards its interface retains.

**Limits:** memory serialization is not distributed conflict, crash, durability or
unknown-ACK proof. Do not introduce a production global population counter, revision
counter or write lock to make tests pass. A test scheduler/commit mutex is a labeled
memory-adapter mechanism, not a production coordination design.

## JS-P2 — Generic occurrence tree and final integrity

**Entry:** JS-P1's lawful bindings and atomic overlay are usable by both writer and oracle.

**Deliverable:** generic linked AVL CRUD with left/right navigation, mandatory structural
size, and ordered monoid summaries. Parent/previous/next links are optional only when
a demonstrated need justifies maintaining them. Include point/select/range-fold reads
needed by subsequent settlement. Root anchor identity
is independent of the rotating head. Each stable record/slot occurrence has exactly
one validated root and total-order key with deterministic record/slot ties.
Support multiple independently projected memberships, including unit-summary count
indexes. Maintain typed reverse references and protected uniqueness claims atomically.
Release obsolete claims before final acquisitions; validate final root and prefix
invariants against the staged graph, including joint repairs and hidden dependents.

**Witnesses:** independent inventory reconstructs every expected occurrence, reverse
reference and uniqueness claim from source records. Verify links, ordering, balance,
heights, subtree sizes, root counts and every ordered subtree fold after rotations,
inserts, edits, deletes, root moves and rollback. Include duplicate slots, two slots in
one root, root deletion guards, swaps, forward references and reference retargets.
Use lawful noncommutative summaries, equal-key ties, prefix-vs-final-total
counterexamples, overflow policy and CRUD/permutation/metamorphic sequences.

**Exit:** flat oracle, tree invariants and transactional rollback witnesses agree.
Unchanged membership projections cause no occurrence writes; other changed memberships
still update. Count visits and physical writes separately per changed occurrence.

**Limits:** logarithmic AVL paths assume bounded comparisons and constant-size summary
work; they do not bound whole cascades, bytes, authorization or variable-width arithmetic.
A uniqueness declaration and a reference remain different contracts.

JS-P2 verification: 60 Node tests passed on Node 24.22.1, zero failed/skipped.
Accepted scope: linked AVL insert/update/delete with structural sizes and ordered
folds; transactional occurrence reconciliation, final typed references and unique swaps;
trusted point/select/range reads; and complete active-generation independent inventory
checking. No-op projections retain guarded O(h) lookups with zero occurrence writes.
The memory adapter's prefix scan still enumerates the Map; reference guards therefore
add scan work. `allPrefixes` validators consume witness summaries such as `minPrefix`,
not arbitrary per-prefix quantification. Last deletion validates the identity summary;
live empty anchors and generation lifecycle remain deferred. This checkpoint does not
supply authorization or reactive settlement. See the linked evidence for executable
witnesses and the [API guide](../../prototypes/node-engine/README.md) for composition.

## JS-P3 — Dependency settlement and key-range routing

JS-P3 is split into evidence gates; accepting internal primitives does not accept
the whole checkpoint.

- **JS-P3a — staging, complete cuts and reverse routing:** internal attempt-local
  `createMutation` stages source/tree edits and validates the joint final graph at
  finish; typed ranges distinguish whole-value ties from complete occurrence cuts;
  reverse field/range registrations support replace/read/affected-subscriber operations.
  Verify multi-stage repairs/rollback, tie-bound edges, empty registrations, retargets,
  conservative interval pruning and explicit visit-budget rejection against flat scans.
  [JS-P3a evidence](../checkpoints/js-p3a.json): accepted with 81 Node tests on
  Node 24.22.1, zero failed/skipped. Routing reports
  actual visits and has worst-case O(R) interval work; memory prefix scans remain linear.
- **JS-P3b — integrated settlement:** prepare versioned catalog callbacks for resolve
  and evaluate; declare a potential-emission inventory before evaluation so producers
  with zero current outputs remain part of final-graph closure and cycle detection.
  Wire routing to old/new positions, settle the final graph with explicit cycle checks,
  and manage zero-output creation, deactivation, reactivation and deletion atomically.
  Compare with independent full recomputation, including joint repairs, changed routes,
  empty inputs and command-order permutations. This gate is accepted locally below.
  JS-P3b has two bounded subgates:
  1. **JS-P3b.1 — contracts and full-snapshot reference:** prepare versioned model
     calculations and managed models; resolve authored-only topology, reserve complete
     potential outputs including null emissions, detect potential cycles before synchronous
     evaluation, and independently derive final inventories/routes. Accepted with 102 Node
     tests on Node 24.22.1, zero failed/skipped:
     [reference evidence](../checkpoints/js-p3b-oracle.json). Complete authored snapshots
     and historical reservation ledgers are caller preconditions. Full scans/sorts,
     pairwise edge checks and repeated topological scans may be quadratic or higher;
     producer/edge caps are not whole-work budgets. This is not an incremental writer.
  2. **JS-P3b.2 — integrated incremental writer:** connect callbacks, staged edits,
     routes, managed reservation ledgers, final-graph closure/cycle checks and evaluation;
     compare committed state with the independent reference and verify rollback. This
     is accepted for the local volatile adapter: 140 Node tests on Node 24.22.1, zero
     failed/skipped. See [settlement evidence](../checkpoints/js-p3b-settlement.json).
     The writer follows routes/potential AVL indexes without tenant-wide source/producer
     scans; one transaction publishes public/private state, joint final checks and live
     potential empty-scope validation. Explicit logical budgets/metrics do not bound
     callbacks or physical memory scans. Independent same-snapshot checking covers active
     inventories; missing retired ledger history is not inferable from present facts.
     JS-P4/JS-P5 entry gates are unchanged.

Intermediate staging is local overlay state, not a valid published graph or a guarantee
of managed/private-output rules by itself. JS-P3b.2 integrates these rules through public
mutation and independent checking; full JS-P3 is accepted locally. The complete JS-P3 obligations follow.

**Entry:** JS-P2 supplies valid point/range aggregate reads and final-graph integrity.

**Deliverable:** explicit direct field dependencies and typed root/order/key-range
dependencies; route changed old and new positions to affected registrations. Resolve
declared selectors and use a tracked transaction read facade for dynamic dependencies,
including absent/empty reads; arbitrary JavaScript reads are not automatically tracked. Settle
from the staged final graph using a deduplicated pending work set and an explicit
acyclic dependency order. Reject causal cycles with a useful bounded diagnostic.
Preserve subscriptions whose current result is empty and manage creation, retargeting,
deactivation, reactivation and deletion of managed outputs and registrations together.

**Witnesses:** compare incremental settlement with a separate full recomputation from
source facts. Exercise diamonds, several inputs changing one dependent, moved bounds,
old/new root moves, empty-to-nonempty and nonempty-to-empty results, zero-output
producers, parent edits, joint repairs and command-order permutations. Deliberately
omit an invalidation in a mutation test and show the independent check detects it.
Demonstrate failed cycles publish nothing and repeated pending work does not duplicate
outputs or lose changes arriving during settlement.

**Exit:** resulting records, memberships, routes and summaries match recomputation;
each registration's inputs and lifecycle are accounted for. Report actual routing
visits, matches, recomputations and writes, including adversarial overlap.

**Limits:** interval stabbing's output-sensitive bound requires separate proof;
AVL balance alone does not establish it. Rank/select are reads, not reactive rank-window
dependencies. Clock advancement needs an explicit future temporal/wake adapter.

## JS-P4 — Bounded readers and owner-scoped merge

JS-P4 is implemented through three acceptance gates. Passing a raw read gate does
not grant access to its counts, member identities or summaries:

- **JS-P4a — raw same-snapshot windows:** `treeReadWindow(tx, catalog, scope, options)`
  intersects an optional half-open **absolute occurrence-rank** window with optional
  typed key cuts. Cache fetched nodes, batch each independent frontier and scatter
  output by rank; never select every output rank separately. Child-root metadata
  probes count as reads because parent nodes do not store separate child sizes.
  Explicit finite node/batch/output/encoded-byte budgets reject the complete call
  on exhaustion. Adjacent windows or exclusive complete cuts compose only within
  the same transaction; they are not cross-request cursors. Byte accounting checks
  encoded values after the adapter fetch, so it does not cap earlier cloning,
  transport or actual heap use. Accepted with 152 Node tests on Node 24.22.1, zero
  failed/skipped: [JS-P4a evidence](../checkpoints/js-p4a.json). Twelve reader tests
  cover independent expected rows, same-snapshot composition, bounded work, budgets,
  corruption and integration with public mutation. This is not authorization acceptance.
- **JS-P4b — disclosure and owner-stream composition:** validate hydrated sources
  against occurrences, declare trusted owner-partition/resource bindings, apply
  fixture authority and merge cached heads across permitted streams. Include
  candidate/setup/refill budgets, both-owner transfer and summary disclosure.
  Raw counts do not become visible counts. No authentication acceptance follows.
- **JS-P4c — continuation fencing:** bind serialized continuation to exact query,
  model and authority plus relevant data state, including payload-only changes and
  owner transfers. Use snapshot identity or scope-local invalidation, never a
  universal mutation counter. Resume must reject or explicitly restart on change.

**Entry:** JS-P2 index integrity and JS-P3 settled final views pass; a trusted raw reader may
be developed after JS-P2, but public acceptance waits for JS-P3 and owner-policy fixtures.

**Deliverable:** same-snapshot count-pruned batched rank/range traversal and hydration,
with explicit candidate, node, batch, byte and output budgets and continuation behavior.
Distinguish raw occurrence rank from visible filtered rows. Implement scoped k-way
merge only across declared streams of one opted-in resource/order under owner-only
fixtures. Cache heads, advance the popped stream and bound setup/refill work.

**Witnesses:** compare linked traversal, batch traversal and flat sorted expectations
for empty roots, ties, composite bounds, rank edges, continuation and budget exhaustion.
Exercise self, strict descendants, direct group parents, tenant-parent exclusion,
missing action grants, private records and hidden contributors to public summaries.
Owner transfers require access to both owners and change relevant cursor partitions.
Bind cursors to model/query, total-order position, scope/authority and relevant data
revision semantics; test payload-only changes and resume rejection/restart policy.

**Exit:** authorized rows, continuation and disclosure agree with an independently
filtered oracle. Report stream discovery and initial seeks, candidates, nodes, bytes,
batches and writes; test that all reads share one adapter snapshot.

**Limits:** fixture authorization is not authentication/session migration acceptance.
No global visible rank or arbitrary cross-resource union is implied. A batch count is
not a network RTT count; k-way initialization and rejected candidates still cost work.

## JS-P5 — Index lifecycle, composed tools and bounded demonstration

**Entry:** JS-P1–JS-P4 pass and catalog/format identities are explicit.

**Deliverable:** build, independent validation, activation and retirement of declared
indexes. Use a writer-paused baseline: freeze writes, build from source facts, validate,
then publish all affected catalog/source/root/route/derived state atomically. Candidate
memberships and routes have separate generation-scoped keys. A failed build leaves
the previous active identity usable. Activation invalidates old-generation cursors;
retire storage after admitted in-flight reads finish, not after unbounded idle cursors.
Compose importable developer functions for model inspection, source checking,
population and workloads; use standard REPL/scripts rather than a new command parser.
Population reuses model contracts, typed pools, quotas and caller strategies; transaction
validation remains authoritative for hidden/final-state constraints.

**Witnesses:** compare rebuilt inventory with JS-P1's oracle, inject failure during build
and activation, reject incompatible cursors/models, and test retirement preconditions.
Prove candidate writes/cleanup cannot overwrite active generations, and test a changed
index definition with dependent calculations and validators; either settle all affected
state atomically or explicitly reject that unsupported migration class.
Population exercises skew, ties, multiple memberships, dependency diamonds, rejection
and rollback with reproducible seeds. Benchmark a declared bounded workload across
several sizes and membership counts; disclose hardware/runtime, dataset, seed, limits,
setup costs, node visits, reads, writes, batches, bytes and latency distribution.

**Exit:** a reviewer can import functions, populate, mutate, query, rebuild and validate
one bounded demonstration with documented commands and complete acceptance evidence.
Compare logical work as well as elapsed time; timing does not prove complexity.

**Limits:** paused writes are an intentional baseline, not online backfill acceptance.
No live-provider, multi-host, production capacity or full migration claim follows.

## Gates after the prototype

Persistent adapters must separately establish conflict and protected-range semantics,
concurrent uniqueness/final-graph invariants, rollback, crash/reopen and durable original
receipts. Unknown commit outcomes require original request/status recovery; a timeout
must never cause a fresh mutation. Test lost ACKs against a real persistent adapter.

Full authorization/session migration must retain current authority, both-owner transfer,
revocation, restore fencing and disclosure behavior. Secure credentials/providers,
durable outbox intent, charged starts, fencing, fact/application separation and unknown
provider outcomes retain their own integration gates. The capability roadmap retains
all existing obligations, including deferred objects, recurrence and live invalidation.

Production capacity and rollout require representative topology, contention, retention,
backup/restore, operational limits and staged migration evidence. These are separate
from JS-P5's demonstration; retain existing production behavior until replacement evidence
covers each retained capability. Prefer this dependency order; revise checkpoint cuts
when a concrete counterexample exposes a prerequisite, recording the reason and limits.
