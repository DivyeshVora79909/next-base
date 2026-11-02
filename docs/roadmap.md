# Native base checkpoints

The current choice is linked augmented AVL, native RPC and native transactional KV adapters.
Historical accepted N/S0 evidence stays unchanged; it does not choose a different current layout.
Plan and bootstrap work proceeds now. Checkpoints can continue automatically when their stated
obligations pass; unresolved semantic choices or failed evidence must be reported explicitly.
Do not add unused traits, dependencies or a second DSL merely to illustrate future capabilities.
The current server-extension checkpoint is planning-only. The
[E0–E5 service plan](server-execution.md) adds contracts and acceptance witnesses;
it does not declare credentials, object storage or recurrence implemented.

## C0 — Clean root and reproducible bootstrap

Record the imported source revision/content hashes, retained capability inventory and selected
configuration. Establish the independent repository root and CI commands without modifying the
source repository. Preserve model/codec identities unless actual semantics/formats change.
Inputs: [architecture](architecture.md), Cargo configuration and existing Node entry points.
Outputs: runnable native bootstrap, explicit backend/model setup and focused CI evidence.
Acceptance: native RPC opens the expected store/model, wrong target fails closed, and relevant
existing checks pass. Reuse [`storage/conformance.rs`](../src/storage/conformance.rs),
[`tests/local_api.rs`](../tests/local_api.rs) and Node config/client tests where applicable.
A copied historical result is provenance, not a test of changed code.

## C1 — Bounded batch reads and count-pruned traversal

Introduce only the adapter batch-get capability justified by the reader; cap concurrency,
bytes and work. Use one native transaction/read version for root, nodes and hydrated records.
Counts must be validated against the selected family and occurrence semantics. Implement
count-pruned frontier traversal with explicit continuation and budget exhaustion behavior.
Preserve existing UUID-page query meaning; register a root/rank path only for index families
with the required count capability. A batch operation may fall back to sequential local gets;
the distributed adapter must actually issue independent requests before awaiting completion.
Define raw membership rank versus visible result rank. Permission to read a root summary
does not grant access to every member or private output; preserve per-record disclosure checks.
Inputs: existing linked reader and verified scratch research, kept separate from production claims.
Acceptance: independent source-derived oracle agrees for 50/100/1,000 rows, empty ranges,
equal-key ties, boundaries, continuation, inaccessible records and concurrent mutations.
Compare ordinary linked traversal, BFS and known-ID hydration while labeling discovery costs.
Report actual gets, batches, bytes, conflicts and bounded topology; do not equate batches to RTTs.
Reuse [`src/index_tests.rs`](../src/index_tests.rs) and access/page witnesses in
[`tests/access_control.rs`](../tests/access_control.rs); add property/metamorphic counterexamples.

## C2 — Catalog relationships and final-graph guards

Expose one prepared schema/reference catalog with explicit reader and deletion semantics.
Keep implemented reject behavior distinct from any newly supported deletion policy.
Cover 1:n child references, 1:1 target uniqueness and n:m typed junction/pair uniqueness.
Reuse existing cardinality roots where sufficient; otherwise reserve uniqueness keys.
Protect incoming-reference existence/absence inside the transaction.
Acceptance: concurrent competing links cannot both win; concurrent delete/reference creation
cannot leave dangling edges; retarget, delete/recreate and joint final-state repairs work.
Verify command permutations with the same final graph, cross-tenant/type rejection, hidden
reference targets, incomparable readers and full rollback on invariant failure.
Reuse [`src/mutation.rs`](../src/mutation.rs), [`src/dependency.rs`](../src/dependency.rs),
[`src/publication_tests.rs`](../src/publication_tests.rs) and authority tests as starting witnesses.

## C3 — Optional authorized chronological query indexes

First measure current Population-key, reader/contract-epoch and AVL-root contention separately.
Existing independent-tree writes are not automatically independent transactions. Refine only
operational coordination that can be split without weakening exact business invariants.
Preserve query-change detection and authority fences when evaluating epoch alternatives.
Declare query shape and scope before choosing an index. Owner/effective-time, owner/created-time
and tenant/created-time are distinct needs; zero added indexes is a valid decision.
Specify stable ties, root partitioning, reader filtering and exact range/continuation semantics.
Acceptance: independent scan oracle matches results under rekeys, deletion and authorization
changes; payload-only updates avoid unchanged index writes where semantics permit.
Measure bytes, changed memberships, hot ancestors and conflicts for tenant/owner root alternatives.
Do not add a shared global count/root solely for convenience or claim filtered counts from raw rank.

## C4 — Adaptive valid population from the same catalog

Use catalog rules and typed reference pools to adapt cardinality, skew and relationship fanout.
Keep ledger/global constraints explicit; population-limit removal does not imply arbitrary valid
connected generation. An optional external solver callback may propose candidates through the
same catalog; it neither becomes a required dependency nor bypasses native validation.
Acceptance: deterministic seeds and original receipts reproduce intent; an independent checker
verifies generated facts, relationships and declared invariants, including deliberate invalid cases.
Bound generation effort and record unsatisfied rules instead of silently weakening them.
Reuse Node population tests and model-specific independent checkers; do not mirror writer caches.

## C5 — Optional live invalidations and deployment gates

If selected, add WebSocket delivery from committed durable invalidation/outbox entries with
partitioned cursors, resumable replay, duplicate handling, retention and expired-cursor behavior.
Acceptance: aborted writes emit nothing; disconnect/restart resumes without hidden gaps; current
authority governs subscription/replay disclosure. Reuse native receipt, effects, lifecycle,
coordination and backend failure checks; preserve TLS/JWT ingress and private operator boundaries.
Report tested topology and recovery limits. Frontend, external providers and TiKV are optional
follow-ons, not mandatory dependencies of completing this base.

## E-series — Composable server services

The [server plan](server-execution.md) preserves existing execution/fact/application
machinery while adding strict typed capabilities. E0 is the current contract pass;
C1 stays the next core implementation checkpoint when implementation resumes.

| Gate | Scope | Dependencies |
| --- | --- | --- |
| E0 | Current/absent capabilities, modes and recovery obligations | C0 and existing effect evidence; planning only |
| E1 | Credential records, secret-safe ingress, use authorization and bounded grants | Existing authority; C2 reference/uniqueness rules where needed |
| E2 | Explicit operation versions and durable inline/queued jobs | E1 contracts; reuse the present worker state machine |
| E3 | Authorized object grants, immutable finalize and recoverable cleanup | E1–E2; one selected object adapter |
| E4 | Optional recurrence producing ordinary one-shot jobs | E2 and protected occurrence uniqueness; no workflow engine |
| E5 | Independent fake full-pipeline, failure and recovery verification | Each selected E feature; C4 catalog tooling where used |

C1 and service contract preparation can proceed independently. Shared source edits
and schema/codec changes require a single integrator. Live-provider acceptance is
separate from fake protocol checks. Client WebSocket invalidations remain C5 work;
they are not provider webhooks or a substitute for the durable job protocol.
