# Working on Next Base

Read this file, CONTEXT.md and the relevant section of [architecture](docs/architecture.md)
and [roadmap](docs/roadmap.md). Retrieve code, catalogs and independent checks for detail;
do not load every historical paper or duplicate these instructions into memories.

## Selected foundation

- Native Rust calculation/transaction engine over a transactional KV adapter.
  redb is the local baseline; FoundationDB and standalone SurrealKV are optional.
  SurrealKV is not SurrealDB. Adapter guarantees and limits remain backend-specific.
- Linked augmented AVL is selected, not a B-tree page rewrite. Count-pruned batched
  BFS has research evidence; C1 integrates it as a bounded, authorized reader.
- One prepared model/catalog supplies schemas, references, index participation and
  developer metadata. Use ordinary Rust and Node ESM functions with explicit state.
  No second query/workflow DSL, hidden registry or duplicate schema authority.
- Preserve capabilities, not old names or backwards compatibility. Map an obligation
  to a retained implementation/test before deleting its machinery.
- Server services compose ordinary functions and typed versioned operations. Read
  [server execution](docs/server-execution.md) for credentials, grants, durable jobs,
  objects and scheduling; these extensions are planned, not implemented capability.

## Working loop

1. Inspect Git status, source provenance and the current checkpoint.
2. Select a coherent slice and its input/output/invariant obligations. Begin with
   a small independent oracle or counterexample, then integrate.
   Translate informal requests into established concepts and explicit guarantees
   first; do not turn a mistaken name into an architectural requirement.
3. Delegate disjoint files when it reduces total work; include context, retries and
   integration cost. One owner builds Cargo and one owner integrates Git.
4. Run checks for changed obligations. A skipped prerequisite or mock is not acceptance.
5. Record results, limits and the next dependency in CONTEXT.md. Commit verified
   checkpoints and push to verified destinations. Continue authorized checkpoints
   without requiring repeated "continue" prompts.

Use the actual environment's limits and model routing. Do not infer billing or
invent savings. In constrained cloud builds use two Cargo jobs and incremental off;
do not impose that policy on every workstation. Keep user updates concise.

## Correctness to preserve

- Resolve signed tenant/subject and current authority in transaction scope.
  Owner controls writes; reader controls disclosure. Check client actions and
  reference access. Trusted balancing/derivation may touch hidden records but
  cannot disclose them or authorize extra client mutations.
- Stage source, typed references, memberships, summaries, dependency effects,
  authority repairs, receipts and applicable effect intent; commit once.
  Preserve final-graph causality, zero-output dependencies and exact arithmetic.
- Protect existence, absence and ranges needed by invariants and uniqueness.
  No-op elimination must preserve conflict guards and protected empty reads.
- Unknown commit outcome requires original receipt/status recovery. Timeout or
  cancellation does not alone prove rollback. Never refresh an uncertain plan.
- Independent checks derive expected results from source facts, not writer caches.
  Prefer property, permutation and metamorphic witnesses to implementation snapshots.
- Constant-size associative summaries plus AVL balance give logarithmic path work
  per changed membership. Cascades, authorization DAGs, bytes and returned rows add
  work; do not claim universal logarithmic mutations or unrestricted capacity.
- External I/O follows committed intent outside engine transactions. Keep native
  transactional KV I/O distinct from provider calls. Preserve unknown-outcome,
  secret-ingress, fenced-worker and fact/application boundaries when composing services.
- Format/semantic changes require explicit identities. Historical evidence remains
  bound to its original source; do not rewrite old checksums as new acceptance.

## Boundaries

src/ is the engine, model/ the schemas/fixtures, tools/node/index.mjs the developer
functions, tests/ and Node tests the executable contracts. Cargo is the standard
native tool. Compose Node tools in the normal REPL; avoid new command parsers and
wrappers around filesystem, loops, fetch or subprocess APIs already available.

Keep application-linked N/S0 instructions and required fixtures here. Independent
experiments belong in research. Do not relabel local three-process tests as multi-host,
or user-reported results as our measurements. No binaries, caches, credentials,
private stores or local plans in Git. Frontend, live providers and TiKV remain optional.
