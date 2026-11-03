# Next Base

A native Rust calculation and transactional state engine over KV adapters, with
linked augmented AVL indexes and ordinary Node developer functions. Existing models
demonstrate exact calculations, reactive history, references, authorization, receipts
and external-effect intent. No SurrealDB or original ReBase runtime dependency.

Start with [AGENTS.md](AGENTS.md), [CONTEXT.md](CONTEXT.md),
[architecture](docs/architecture.md) and [roadmap](docs/roadmap.md).
Code, native catalogs and executable examples supply the detailed API reference.

Use rust-toolchain.toml and the Node LTS version in .nvmrc:

```sh
cargo build --locked
npm --prefix tools/node ci
node
```

Compose directly in the Node REPL:

```js
const path = await import('node:path');
const dev = await import('./tools/node/index.mjs');
const config = dev.resolveConfig({ overrides: { native: {
  binary: path.resolve('target/debug/rebase-next'),
  configuration: {
    model: 'equipment', backend: { kind: 'redb', cluster_file: null },
    target: null, operator_methods: [],
  },
} } });
const native = await dev.openNative(config);
const catalog = await native.catalog({ scope: 'developer' });
await native.close();
```

The catalog describes schemas and references. Complete examples cover
[equipment](tools/node/examples/n2-equipment-workflow.mjs),
[population](tools/node/examples/n3-population.mjs) and
[workloads](tools/node/examples/n4-original-intent-replay.mjs).
Imports start no database/server; configuration and handles are explicit.

Checks: cargo test --locked and npm --prefix tools/node test.
CI builds the host before Node integration tests. See
[storage](docs/storage-backends.md) and [deployment](docs/deployment.md)
for backend prerequisites and lifecycle.

Bounded BFS reads, catalog reference uniqueness and [declared owner order indexes](docs/ordered-access.md)
and [bounded adaptive population](docs/c4-population.md) are implemented.
Service/deployment gates follow the roadmap. Imported bounded acceptance
does not establish unrestricted scale. [Provenance](PROVENANCE.json) records the import.
