# Current checkpoint

## E0 — Server execution contracts, planning only

The user's latest steering keeps this pass in planning mode. Read
docs/server-execution.md for the current/absent capability matrix, ordinary Rust
composition, secret-safe credential records, grants, versioned jobs, object
lifecycle and optional recurrence. E1–E5 have acceptance witnesses and dependencies
in docs/roadmap.md. No server capability, API, schema, dependency or codec changed.

Preserve the existing intent/start-marker/fence/fact/application machinery.
Async functions are not durable jobs; client-callable entries are explicitly
authorized and private helpers consume trusted capabilities. Secret-safe ingress
must account for saved plans and receipts, not only at-rest encryption or redaction.
Native transactional KV awaits are distinct from unrelated provider I/O.

The legacy design had signing grants and queued/inline tasks, but removed cron;
the current native demo has one-shot scheduling, not object storage or provider
credential records. These are planned extensions, not features inferred from names.
C1 remains the next core implementation checkpoint when implementation resumes.
For each slice: meaning -> established concept -> invariant/counterexample -> small
prototype -> composition -> independent verification -> checkpoint. Do not start
production service implementation as part of this documentation-only contract pass.

## C0 — Clean application and research repositories, verified

Selected: native Rust KV harness and linked augmented AVL. No SurrealDB wrapper
or B-tree page redesign. AGENTS.md and docs/roadmap.md are current; historical
N/S0 documents retain their original acceptance boundaries.

Application: https://github.com/DivyeshVora79909/next-base
Research: https://github.com/DivyeshVora79909/research
Source import: ReBase 270d875, rebase-next/ subtree. Both destinations preserve
the user's existing initial commits. PROVENANCE.json records imported hashes
and the 68 research paths moved to Research at 0986b06d120b18713f76fec26b71faa5c40c60b6.
The original ReBase checkout is untouched. Keep N/S0 instructions and required
fixtures here; independent experiments are archived with unchanged evidence.

Standalone setup includes LICENSE attribution, ignores, editor settings, pinned
CI actions and compact architecture/checkpoints. Rust/Node implementation files,
schemas, model identities and dependency versions are unchanged by C0.

Verification: staged standalone copy passed 116 Rust library tests and 167 Node
tests with no skips, formatting and locked offline Cargo metadata. The final destination also passed all 167 Node tests with zero skips; exact
inputs and scope are in docs/checkpoints/c0-bootstrap.json.
Optional adapter campaigns were not rerun; no new scale/deployment claim.

## Next: C1 — Bounded count-pruned batch reader

Research has checked prototypes; production readers are synchronous and public
UUID paging is separate. Add bounded batch fetch, family count capabilities and
authorized root/rank traversal under one transaction. Preserve query meaning,
ordering, continuation, work/byte limits and original receipt semantics.

No owner-time or tenant-created indexes exist. Created and effective differ;
generic created-at metadata is not yet a query primitive. Measure Population-key,
reader/contract-epoch and AVL-root contention before adding analytics indexes.
Typed references exist; generic 1:1 uniqueness and declarative adaptive
skew/cardinality are C2/C4 work, not inferred capabilities.

HTTP JSON-RPC uses Axum/Tokio. Optional WebSocket invalidations need an atomic
durable log, partitioned replay, scope revalidation and backpressure. TiKV,
frontend and live providers remain optional. User-reported three-node cloud
results were not independently measured here.

Continue authorized checkpoints after their acceptance obligations pass. Keep
semantic/format identity changes explicit and avoid duplicate schemas/DSLs,
unused frameworks, universal hot counters or mandatory solver dependencies.
