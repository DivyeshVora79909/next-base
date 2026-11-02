# Current checkpoint

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
