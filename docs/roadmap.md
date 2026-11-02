# Native base checkpoints

The current choice is linked augmented AVL, native RPC and native transactional KV adapters.
Historical accepted N/S0 evidence stays unchanged; it does not choose a different current layout.
Plan and bootstrap work proceeds now. Checkpoints can continue automatically when their stated
obligations pass; unresolved semantic choices or failed evidence must be reported explicitly.
Do not add unused traits, dependencies or a second DSL merely to illustrate future capabilities.
M0 recorded planning and bounded algebra witnesses. The user has now authorized
three implementation commits, then a stop for a new flag. C1 is split into C1.1
structural size/count-only indexes, C1.2 same-view storage batches, C1.3 trusted
rank-window traversal, and C1.4 authorized member paging/cursors. Stop after C1.3;
do not call the whole C1 gate complete before its public integration is accepted.
The [mathematical catalog](index-mathematics.md) and [rate contract](rate-admission.md)
separate mathematical representability from implemented capability. The
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
Add checked structural subtree/root size independent of the business summary, including a
count-only index. Independently reconstruct counts after CRUD/rotations; distinguish occurrences
from distinct records. Update persisted identities explicitly, without implicit old-store defaults.
Implement count-pruned traversal with continuation and budget exhaustion behavior. Preserve
existing UUID-page meaning and optional family query capabilities. Local batch-get may be sequential;
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
Declare cross-record order predicates and their direct parent-field dependencies:
e.g. created/effective lower and upper bounds with explicit strictness and units.
Validate both child edits and parent edits, retargeting and joint final-graph repair;
a local schema check or a child-only predicate is insufficient.
Acceptance: concurrent competing links cannot both win; concurrent delete/reference creation
cannot leave dangling edges; retarget, delete/recreate and joint final-state repairs work.
Verify command permutations with the same final graph, cross-tenant/type rejection, hidden
reference targets, incomparable readers and full rollback on invariant failure.
Reuse [`src/mutation.rs`](../src/mutation.rs), [`src/dependency.rs`](../src/dependency.rs),
[`src/publication_tests.rs`](../src/publication_tests.rs) and authority tests as starting witnesses.

## C3 — Explicit global and domain indexes

First measure current Population-key, reader/contract-epoch and AVL-root contention separately.
Existing independent-tree writes are not automatically independent transactions. Refine only
operational coordination that can be split without weakening exact business invariants.
Preserve query-change detection and authority fences when evaluating epoch alternatives.
Implement the selected shared tenant/created and tenant/reader/created definitions with explicit
per-resource opt-in, stable ties, root scope and created metadata. Multiple domain indexes may
order by effective time, created time, distance or another declared total order with independent
summaries/validators. Define principal-root namespaces and transaction-domain boundaries.
Generalize non-time range query/dependency cuts deliberately: current subscriber routes are
time-specific. Preserve final-graph causality, exact boundaries, old/new route repair and field
identity across indexes. Test numeric/string/composite bounds without timestamp coercion.
Use one ordered root where sufficient; bounded k-way merge is for multiple sorted reader/resource
streams. Specify snapshot, disclosure, cursor and filter semantics before promising global rank.
Acceptance: independent scan oracle matches results under rekeys, deletion and authorization
changes; payload-only updates avoid unchanged index writes where semantics permit.
Measure bytes, changed memberships, hot ancestors and conflicts for tenant/owner root alternatives.
Do not add a shared global count/root solely for convenience or claim filtered counts from raw rank.
Shared analytics roots are selected intentionally; measure their unavoidable write coordination.

## R0 — Declarative rate admission, after its scoped contract is selected

Use [rate admission](rate-admission.md) to choose point-count online admission or fixed-window
endpoint/prefix-max validation. Neither is inferred from the presence of interval stabbing.
Reuse the existing root write guard where it supplies coordination. Accept only after racing
workers, unknown start ACK, quota accounting, clock-only expiry, ties and delayed/backdated
cases pass independent checks. Integrate admission with the existing dispatch-start transaction;
do not perform a check and provider call as two unprotected steps. This feature is not in M0.

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
machinery while adding strict typed capabilities. E0 records the service contract pass;
C1 stays the next core implementation checkpoint when implementation resumes.

| Gate | Scope | Dependencies |
| --- | --- | --- |
| E0 | Current/absent capabilities, modes and recovery obligations | C0 and existing effect evidence; planning only |
| E1 | Credential records, secret-safe ingress, use authorization and bounded grants | Existing authority; C2 reference/uniqueness rules where needed |
| E2 | One EmailSend contract with independent Resend/Brevo adapters and durable jobs | E1 contracts; reuse the present worker state machine |
| E3 | Authorized object grants, immutable finalize and recoverable cleanup | E1–E2; one selected object adapter |
| E4 | Optional recurrence producing ordinary one-shot jobs | E2 and protected occurrence uniqueness; no workflow engine |
| E5 | Independent fake full-pipeline, failure and recovery verification | Each selected E feature; C4 catalog tooling where used |

C1 and service contract preparation can proceed independently. Shared source edits
and schema/codec changes require a single integrator. Live-provider acceptance is
separate from fake protocol checks. Client WebSocket invalidations remain C5 work;
they are not provider webhooks or a substitute for the durable job protocol.
