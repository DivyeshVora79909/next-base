# Node engine prototype

JS-P1 supplies prepared index contracts/bindings, an independent flat source oracle,
exact monoids and a transactional memory adapter. AVL maintenance and reactive
settlement are subsequent checkpoints; this package is not a replacement server.

Use Node 24+ and `npm ci` in this directory. There is no custom command parser;
`npm test` uses the standard Node test runner. From the repository-root Node REPL:

```js
const engine = await import('./prototypes/node-engine/src/index.mjs');
const example = await import('./prototypes/node-engine/examples/activity.mjs');
const catalog = engine.prepareCatalog(example.activityDefinition);
const records = example.activityRecords();
const expected = engine.sourceOracle(catalog, records);
expected.trees.map(t => [t.view, t.partition, t.count, t.aggregates]);
const store = engine.createMemoryStore();
await store.transact(async tx => {
  for (const record of records) await tx.set(`source/${record.id}`, record);
});
await store.read(tx => tx.getMany(['source/add', 'source/use']));
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
- `createMemoryStore()`: caller-owned `transact` and `read` callbacks; transaction
  methods are `get`, `getMany`, `set`, `delete`, `scan`, and `inspect` for work/guards.
  A `beforeCommit({ changes })` fault hook receives detached changes before publication.

Declarations are JSON data; trusted ordinary monoid/validator functions are supplied
separately with explicit versions. Function source is not a semantic fingerprint.
Authors must update versions when behavior changes. `standardMonoids` supplies
exact integer sum, minimum, maximum and ordered minimum-prefix state. Validators are
prepared metadata in JS-P1; executing final root/prefix rules belongs to JS-P2.

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
Point operations use Map lookup; scans enumerate/sort and are not logarithmic index
queries. Values are detached; undefined is the absence sentinel; shared memory is
rejected. Reentry into the same store and transaction use after closure reject.
No crash durability, distributed OCC, automatic retry or unknown-ACK acceptance is
claimed. Direct adapter calls are trusted internal operations, not authorized RPCs.

See [checkpoint evidence](../../docs/checkpoints/js-p1.json) and
[remaining gates](../../docs/node-redesign/checkpoints.md).
