# Node engine prototype

JS-P1 and JS-P2 supply prepared index contracts/bindings, an independent flat source
oracle, exact monoids, a transactional memory adapter and augmented AVL mutation/read
functions. JS-P3a internal staging/routing primitives are accepted; JS-P3b.1 full-snapshot reference is accepted; JS-P3b.2 incremental reactive
settlement and JS-P4a raw batched windows are accepted for the local volatile adapter.
This package is not a replacement server.

Use Node 24+ and `npm ci` in this directory. There is no custom command parser;
`npm test` uses the standard Node test runner. From the repository-root Node REPL:

```js
const engine = await import('./prototypes/node-engine/src/index.mjs');
const example = await import('./prototypes/node-engine/examples/activity.mjs');
const catalog = engine.prepareCatalog(example.activityDefinition);
const records = example.activityRecords();
const store = engine.createMemoryStore();
await engine.mutate(store, catalog, 'tenant',
  records.map(record => ({ type: 'put', record })));
await engine.checkStore(store, catalog, 'tenant');
// { sources: 4, trees: 5, occurrences: 9, references: 3, claims: 3 }
const scope = { tenant: 'tenant', view: 'resourceEffective', partition: ['resource'] };
await store.read(async tx => ({
  first: await engine.treeSelect(tx, catalog, scope, 0),
  totals: await engine.treeAggregate(tx, catalog, scope),
  throughTwo: await engine.treeAggregate(tx, catalog, scope,
    { upper: { value: '2' } }),
}));
await engine.mutate(store, catalog, 'tenant', [{ type: 'delete', id: 'fix' }]);
await engine.checkStore(store, catalog, 'tenant');
```

The example declares two source models mapping different amount fields into shared
contracts and three named views. Effective and created views have distinct identities
and folds; three contributing records produce nine occurrences. `sourceOracle` sorts
and folds complete source facts; it never reads maintained indexes. It also checks
final reference targets and unique claims. This deliberate whole-source operation is
an inspector/test oracle, not a mutation algorithm.

## Current functions

- `prepareCatalog(definition, { monoids, validators, calculations })`: compile JSON Schema and
  check binding/reference/view declarations, returning frozen metadata and identity.
- `validateRecord(catalog, record)`: validate and detach one source record. It does
  not check database references, authorize callers, or execute summary validators.
- `projectRecord(catalog, record)`: derive zero/one/many typed membership contributions.
- `sourceOracle(catalog, records)`: independent expected trees, references and claims
  for a complete supplied snapshot. Partial data is not proof of full-store integrity.
- `mutate(store, catalog, tenant, changes, options?)`: atomically apply
  `{ type: 'put', record }` / `{ type: 'delete', id }` commands, one per source ID.
  Reconcile memberships, reverse references and unique claims against the final graph;
  release old claims before acquisition so joint swaps work. `model` and `createdAt`
  are immutable on update. Return changed-source/membership counts, touched tree scopes
  and adapter metrics. Reactive catalogs also return `settlement` metrics; see below.
  The optional `beforeCommit` fault hook runs before publication.
- `checkStore(store, catalog, tenant)`: independently reconstruct complete active-generation
  inventories from source facts, then check ordering, links, AVL balance, heights,
  structural sizes, subtree folds, references, claims and business validators.
  Return source/tree/occurrence/reference/claim counts; throw on disagreement.
- `readRoot(tx, catalog, scope)`: return the current head node, or `undefined`.
  Scope is `{ tenant, view, partition }`; the stable anchor is independent of its head.
- `treeGet(tx, catalog, scope, { order, sourceId, slot })`: exact occurrence lookup.
- `treeSelect(tx, catalog, scope, rank)`: zero-based structural occurrence selection.
  Missing keys/out-of-range ranks return `undefined`; invalid ranks reject.
- `treeAggregate(tx, catalog, scope, { lower, upper }?)`: ordered aggregate map.
  Bounds are `{ value, inclusive? }` on the declared order domain (inclusive by default),
  applying equally to all record/slot ties. A complete occurrence bound adds both
  `sourceId` and `slot`: `{ value, sourceId, slot, inclusive? }`, cutting within a tie
  group in order/source/slot order. Empty ranges return monoid identities.
- `treeReadWindow(tx, catalog, scope, { ranks?, range?, limits })`: batched raw
  occurrences in order, with absolute ranks and work metrics. Rank bounds are
  half-open `{ start, end }`; key cuts use the same syntax as `treeAggregate`.
  Both constraints intersect. Counts and member IDs are privileged; see below.
- `createMemoryStore()`: caller-owned `transact` and `read` callbacks; transaction
  methods are `get`, `getMany`, `set`, `delete`, `scan`, and `inspect` for work/guards.
  A `beforeCommit({ changes })` fault hook receives detached changes before publication.

Declarations are JSON data; trusted ordinary monoid/validator functions are supplied
separately with explicit versions. Function source is not a semantic fingerprint.
Authors must update versions when behavior changes. `standardMonoids` supplies
exact integer sum, minimum, maximum and ordered minimum-prefix state. Validators are
executed synchronously against final touched-root summaries in JS-P2. An `allPrefixes`
rule requires a suitable witness monoid (for example, `prefix.minPrefix >= 0n`);
the engine does not quantify an arbitrary predicate over every prefix. Validators must
return exactly `true`. Deleting the last occurrence validates identity summaries before
removing the anchor; persistent live empty-anchor lifetimes remain deferred.

## Batched raw windows

Compose windows inside one `store.read` callback to keep the same snapshot. All
limits below are caller-selected budgets, not fixed engine capacity ceilings:

```js
const limits = {
  maxNodes: 2000, maxBatches: 200, maxBytes: 4_000_000,
  maxOutput: 100, batchKeys: 64,
};
await store.read(async tx => {
  const first = await engine.treeReadWindow(tx, catalog, scope, {
    ranks: { start: 0, end: 2 }, limits,
  });
  const second = await engine.treeReadWindow(tx, catalog, scope, {
    ranks: { start: 2, end: 4 }, limits,
  });
  return { first, second };
});
```

The result is `{ total, occurrences, metrics }`. Each occurrence is
`{ rank, sourceId, slot, order }`: two slots from one source are two occurrences.
`total` is the complete raw tree count; ranks always refer to that tree, even when
`range` removes some rows. Without `ranks`, read the whole requested key range;
without `range`, use only ranks. Ends beyond the tree count are clipped. An
exclusive complete lower cut also composes continuation within the same snapshot.
These calls are not serialized cursors; another read callback may see changed data.

All five limits are required finite safe integers, nonnegative except positive
`batchKeys`. Misspelled options reject. Exhausting a budget throws `WORK_LIMIT`
without returning a partial page. `maxOutput` rejects oversized results rather
than truncating a breadth-first frontier into an incorrectly ordered page.

`metrics.nodes` counts distinct node keys fetched, including child-root count
probes; `batches` counts every `getMany`, including the root header. `readBytes`
counts UTF-8 requested keys plus canonical encoded present values; `outputBytes`
counts encoded returned occurrences. Their sum is capped by `maxBytes`. This check
happens **after** the memory adapter fetches/clones a batch; it does not bound
earlier transfer, cloning or heap allocation. `waves` counts traversal levels
after header/head setup, `maxFrontier` counts the largest processing frontier,
and `outputs` counts occurrences. Empty windows still read header/head for `total`.

For valid AVL trees, traversal plus child metadata probes takes `O(log(n+1)+k)`
node work; cached nodes are fetched once, and rank scattering orders results in
`O(k)` without sorting them. Adequate batch capacity gives logarithmic dependent
tree levels, not guaranteed logarithmic wall time or bytes. Finite batches add
storage calls; a batch is not a measured network round trip. The reader checks
loaded identities and expanded local structure but trusts summaries in pruned
subtrees. Use `checkStore` for independent full integrity checking.

This raw API neither hydrates sources nor authorizes disclosure. Owner-scoped
merge, candidate budgets and cross-request cursor fencing remain later JS-P4 gates.
JS-P4a acceptance: 152 tests passed on Node 24.22.1, zero failed/skipped; see
[evidence](../../docs/checkpoints/js-p4a.json).

## JS-P3a internal primitives

The staging and routing primitives below are internal imports, not exports from
`src/index.mjs`. The extended `treeAggregate` remains public.
`createMutation(tx, catalog, tenant)` in `src/stage.mjs` (re-exported internally by
`src/mutate.mjs`) returns asynchronous
`stage(changes)` and `finish()`. Repeated stages update sources/trees in the local
transaction overlay; finish checks final references, unique claims and root validators,
allowing joint repairs before publication. Call finish exactly once and propagate any
error to abort the surrounding transaction. Final validator scopes derive from the
original-to-final transition, excluding transient-only scopes. Intermediate staging has no independently
valid graph or managed/private-output guarantees. Public `mutate` wraps plain catalogs in one stage/finish transaction and dispatches
calculation/managed-model catalogs through incremental settlement. Internal
`finish({ scopes })` can add final live potential scopes for identity validation.

`src/routes.mjs` supplies `replaceRoutes`, `readRoutes` and `affectedSubscribers` for
explicit direct-field and typed aggregate-range registrations. Callers must supply
changed fields and old/new occurrence points; the JS-P3b.2 writer now supplies these
signals automatically.
Registrations may persist when the selected range is empty; unchanged registrations
retain guards without delete/reinsert work. The router reuses AVL
nodes with maximum-upper summaries and conservative pruning; it reports actual
interval-node/direct-entry visits and matches. `maxVisits` exhaustion rejects rather
than returning an incomplete answer. Worst-case interval routing is O(R) for R
registrations, not a demonstrated logarithmic-plus-matches bound. Memory prefix scans
still enumerate the Map, outside the logical route-visit budget.

Acceptance: 81 Node tests passed on Node 24.22.1, zero failed/skipped.
JS-P3b.1 adds prepared calculation contracts and a full-snapshot reference below.
Incremental routing/staging integration and managed storage are accepted locally
in JS-P3b.2.

## JS-P3b.1 calculation reference

From the repository-root Node REPL:

```js
const engine = await import('./prototypes/node-engine/src/index.mjs');
const causal = await import('./prototypes/node-engine/examples/causal.mjs');
const catalog = engine.prepareCatalog(causal.causalDefinition,
  { calculations: causal.causalCalculations() });
const result = await engine.settlementOracle(catalog, 't', causal.causalDiamond());
Object.fromEntries(['A', 'B', 'D'].map(id =>
  [id, result.generated.find(r => r.id === causal.causalOutput(id)).data.amount]));
// { A: '20', B: '30', D: '50' }
```

`settlementOracle(catalog, tenant, authored, { reservations, maxProducers, maxEdges }?)`
is a full recomputation reference, not a transactional writer. Supply the complete tenant
**authored** snapshot and complete historical reservation ledger, including retired roles;
these are caller preconditions, not facts checked against a database. It returns final
`records`, `generated`, retained `reservations`, producers, graph order/edges, routes,
static inventory and work metrics. `generatedId(tenant, anchorId, calculationSlot, role)`
is public; `producerId` remains an internal module function.

Authored models declare `calculations: [{ slot, use }]`. Output-only models declare
`managed: true` and must not declare calculations. The trusted calculation registry
supplies a version and ordinary `resolve`/`evaluate` functions.
Resolve may be synchronous or asynchronous. Its `readField(id, selector)` is synchronous
(and await-compatible), returns `{ exists, present, value? }`, reads authored records
only and records implicit field/existence routes. Dynamic topology may depend only on
authored facts. Explicit reads are direct fields or typed aggregate ranges with the
same complete cuts as tree reads.

Resolve returns parameters, reads and complete schema-valid output templates with a
role, managed model, owner, creation time, data and exact `computed` field names.
Template values establish potential membership topology; placeholders never serve as
computed values. Potential edges include outputs whose evaluation is null. The oracle
orders/checks the full potential graph for cycles before evaluation. Synchronous evaluate
returns `{ outputs: { role: patchOrNull } }`; each patch contains exactly its declared
computed fields and must preserve membership topology. Null emits no current record.
The first potential declaration reserves output model and creation time even if null;
retired reservations remain, and a later changed model/time rejects rather than being
automatically replaced with historical metadata.

Callbacks are trusted ordinary JavaScript with a developer purity obligation, not a
sandbox. The reference deliberately scans/sorts complete snapshots, compares potential
edges pairwise and repeatedly scans during topological ordering; work may be quadratic
or higher with query costs. Producer/edge caps do not bound all CPU, bytes or callback
work. No incremental complexity, durability or production capacity follows.

The JS-P3b.2 writer now accepts calculation/managed-model catalogs through public
`mutate`; direct caller commands still reject managed models and reserved derived IDs.
`sourceOracle` inspects static final-record inventories inside the reference, while
`checkStore` independently compares reactive and public inventories in one snapshot.
Acceptance: 102 Node tests passed on Node 24.22.1, zero failed/skipped.
See [JS-P3b.1 evidence](../../docs/checkpoints/js-p3b-oracle.json).

## JS-P3b.2 transactional settlement

Using `engine`, `causal` and `catalog` from the reference example above:

```js
const store = engine.createMemoryStore();
const mutation = await engine.mutate(store, catalog, 't',
  causal.causalDiamond().map(record => ({ type: 'put', record })),
  { maxProducers: 100, maxEdges: 1000,
    maxRouteVisits: 10000, maxPotentialVisits: 10000 });
const checked = await engine.checkStore(store, catalog, 't');
const d = await store.read(tx => engine.treeGet(tx, catalog,
  { tenant: 't', view: 'effective', partition: ['D'] },
  { order: '1', sourceId: engine.generatedId('t', 'D', 'main', 'value'), slot: 'main' }));
d.contributions.total; // 50n
mutation.settlement; // resolved, evaluated, routeVisits, potentialVisits, edges, pending
```

One transaction stages authored and generated rows, producer state, retained identity
reservations, reverse routes and potential-output AVL indexes. The writer follows
changed routes and potential predecessors without scanning all tenant sources or
producers. It resolves authored-only topology, closes the affected final graph and
rejects cycles before evaluating. It withdraws all pending producers' old actual
outputs before evaluation, preventing moved stale points from entering range reads.
References, uniqueness and final validators—including live potential scopes with no
actual output—validate jointly before publication. Failure rolls back private and
public changes together. The existing `beforeCommit` hook remains available.

Runtime resolver `readField` is asynchronous; await its result. Outstanding reads are
drained and failures latched even if a callback ignores their promises. The batch
reference facade remains synchronous and await-compatible. Both enforce authored-only
resolver topology and exact synchronous evaluation patches. Reservations retain first
potential model/time; caller commands cannot write managed models or reserved IDs.

Options `maxProducers`, `maxEdges`, `maxRouteVisits`, `maxPotentialVisits` default to
`Infinity`. They bound logical counters, not all callback CPU, bytes or physical scans;
callbacks remain trusted ordinary JavaScript. Route reporting can be O(R); memory
prefix scans still enumerate the Map. `pending` counts the affected cohort processed, not remaining unsettled jobs.
Counts of changed sources include authored and
generated rows. No authentication/owner-policy, durability or production-capacity claim
follows from this local serialized volatile adapter.

`checkStore` runs the independent full reference in the same snapshot as public-tree
checking and verifies active managed records, producers, routes, potential forests and
retained reservations. Its full scans are deliberate. A missing retired reservation
cannot always be inferred from present facts alone; historical ledger completeness
remains a precondition. See [JS-P3b.2 evidence](../../docs/checkpoints/js-p3b-settlement.json)
Acceptance: 140 Node tests passed on Node 24.22.1, zero failed/skipped.
Full JS-P3 is accepted within the local volatile adapter; JS-P4 bounded readers/owner-scoped
merge/cursors and JS-P5 lifecycle/tools
remain unaccepted.

## Explicit boundaries

Sources contain exactly `id`, `tenant`, `owner`, `model`, `createdAt`, `data`.
IDs are nonempty well-formed Unicode strings in this prototype, not a claim of UUID
authentication. Authored inputs cannot use the reserved `@next/derived/` prefix,
including through plain static-catalog mutations; generated identities are engine-owned. Integers in ordered/input roles and creation metadata use canonical
decimal strings; computations use BigInt. Ordinary JSON numbers must be safe integers.
Strings compare by UTF-8 bytes, not locale. Generic decimal/floating domains are not
implemented. Structural counts are distinct from business sums.

Schemas use synchronous JSON Schema 2020-12 via Ajv 8.20.0 (MIT), with strict mode,
no coercion/defaults/property removal, no remote schema loading and no async schemas.
Binding selectors require explicitly declared top-level properties, trusted header
selectors or constants. Supported role domains are `integer`, `id`, `string`,
`boolean`; unknown configuration keys reject. Missing values skip a membership only
under `onMissing: 'skip'`; malformed present values still fail. Scalar/array/polymorphic
references and unique tuples are declared once. Static distinct membership slots can
repeat a source in the same view. Array-expanded membership binding is not yet supplied.
Nonempty contract-level calculation/dependency declarations remain unsupported; model
calculation contracts use the reference and incremental paths described above.

The memory adapter serializes **both readers and writers**, retains protected-read
evidence and publishes a touched-key overlay without copying the complete store.
Point operations use Map lookup; prefix scans enumerate the entire Map and sort matches,
so reference guards using scans are not logarithmic index queries. AVL point/select/range
reads and per-membership repairs take O(h) logical path work for bounded summaries;
a whole-root fold takes O(1) logical reads. Unchanged projections still require O(h)
guarded lookup but cause zero physical occurrence writes; a complete no-op on an
initialized valid store causes zero physical writes. Variable-width BigInt cost,
multiple memberships, cascades and adapter scans add work. Values are detached; undefined is the absence sentinel; shared memory is
rejected. Reentry into the same store and transaction use after closure reject.
No crash durability, distributed OCC, automatic retry or unknown-ACK acceptance is
claimed. Direct adapter calls are trusted internal operations, not authorized RPCs.

The checker covers the requested tenant and current catalog generation, not unknown
inactive generations or lifecycle activation. Direct mutation/read functions are trusted
internal APIs: tenant partitioning is not caller authentication or authorization.

See [JS-P3a evidence](../../docs/checkpoints/js-p3a.json),
[JS-P2 evidence](../../docs/checkpoints/js-p2.json),
[historical JS-P1 evidence](../../docs/checkpoints/js-p1.json) and
[remaining gates](../../docs/node-redesign/checkpoints.md).
