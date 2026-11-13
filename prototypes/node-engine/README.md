# Node engine prototype

JS-P1 and JS-P2 supply prepared index contracts/bindings, an independent flat source
oracle, exact monoids, a transactional memory adapter and augmented AVL mutation/read
functions. Reactive settlement remains JS-P3; this package is not a replacement server.

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

- `prepareCatalog(definition, { monoids, validators })`: compile JSON Schema and
  check binding/reference/view declarations, returning frozen metadata and identity.
- `validateRecord(catalog, record)`: validate and detach one source record. It does
  not check database references, authorize callers, or execute summary validators.
- `projectRecord(catalog, record)`: derive zero/one/many typed membership contributions.
- `sourceOracle(catalog, records)`: independent expected trees, references and claims
  for a complete supplied snapshot. Partial data is not proof of full-store integrity.
- `mutate(store, catalog, tenant, changes, { beforeCommit }?)`: atomically apply
  `{ type: 'put', record }` / `{ type: 'delete', id }` commands, one per source ID.
  Reconcile memberships, reverse references and unique claims against the final graph;
  release old claims before acquisition so joint swaps work. `model` and `createdAt`
  are immutable on update. Return changed-source/membership counts, touched tree scopes
  and adapter metrics. The optional fault hook runs before publication.
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
  applying equally to all record/slot ties. Empty ranges return monoid identities.
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

## Explicit boundaries

Sources contain exactly `id`, `tenant`, `owner`, `model`, `createdAt`, `data`.
IDs are nonempty well-formed Unicode strings in this prototype, not a claim of UUID
authentication. Integers in ordered/input roles and creation metadata use canonical
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
Nonempty calculation/dependency declarations reject explicitly pending JS-P3.

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

See [JS-P2 evidence](../../docs/checkpoints/js-p2.json),
[historical JS-P1 evidence](../../docs/checkpoints/js-p1.json) and
[remaining gates](../../docs/node-redesign/checkpoints.md).
