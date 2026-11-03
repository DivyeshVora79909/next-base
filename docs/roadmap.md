# Native base checkpoints

The current choice is linked augmented AVL, native RPC and native transactional KV adapters.
Historical accepted N/S0 evidence stays unchanged; it does not choose a different current layout.
Plan and bootstrap work proceeds now. Checkpoints can continue automatically when their stated
obligations pass; unresolved semantic choices or failed evidence must be reported explicitly.
Do not add unused traits, dependencies or a second DSL merely to illustrate future capabilities.
M0 recorded planning and bounded algebra witnesses. C1 is split into C1.1
structural size/count-only indexes, C1.2 same-view storage batches, C1.3 trusted
rank-window traversal, and C1.4 authorized member paging/cursors. Historical C2.R reader policy was superseded by current owner-only direction (C2.O accepted); C1.4 acceptance
remains historical evidence under its original source identity. C1.1–C1.4 have bounded default-backend acceptance;
distributed performance/deployment gates remain separate. Follow the current user's authorization; conversation
usage budgets are not standing commit-count instructions for future agents.
The [mathematical catalog](index-mathematics.md) and [rate contract](rate-admission.md)
separate mathematical representability from implemented capability. The
[E0–E5 service plan](server-execution.md) adds contracts and acceptance witnesses;
E1 credentials are now accepted within [their checkpoint](checkpoints/e1-credentials.json);
EmailSend, object storage and recurrence retain their following milestone boundaries.

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

### C2.R — Historical reader policy (superseded; frozen evidence)

C2.R's owner-inclusive minimal reader inference/repair was an accepted historical
policy. It is no longer a current requirement and must not be restored. Preserve its
source identity and results in the checkpoint [evidence](checkpoints/c2-reader-policy.json).


### C2.O — Current owner-only access contract (accepted)

The user's breaking direction is current: ModelRecord has only an owner; Reference has no
reader flag or reader inference/repair. Physical indexes are `owner_records`; lookups
k-way merge accessible owner streams. Read/Create/Update require same-tenant scope, the
action grant, and owner accessibility through self, strict descendants, or direct group
parents only. Direct tenant-parent records are excluded from ordinary data scope; tenant-
grant inheritance remains separate. Delete permits self or strict descendants only. Admin
actions do not widen ordinary scope. Create accepts optional canonical UUID `owner`,
defaults to actor and requires access to the requested owner. The subsequent
[ownership-transfer checkpoint](checkpoints/c2-ownership-transfer.json) permits optional
Update `owner` metadata with Update permission and access to both owners; it supersedes
C2.O's Update immutability restriction. Generated outputs follow their producer, while
business roots retain their declared UUID/slot identities. Indexes and both owner cursor
partitions change atomically; same-owner/no-input-change updates preserve data revisions.
Acceptance is complete. Internal balancing/cascades validate hidden records without granting
client access. Root access authorizes explicitly declared public summary data; FULL
aggregates may include hidden contributors but do not grant leaf/body/ID reads. Proof:
[C2.O checkpoint](checkpoints/c2-owner-only.json). Verification passed 284 Rust all-target
tests (0 ignored), all 174 full Node tests (0 skipped), formatting, and default/FDB
all-target Clippy with `-D warnings`. FoundationDB 7.3.77 on one host/process passed
coordination/lifecycle/application/effects/predicates 18/14/19/27/10; sequential redb
controls passed 15/10/13/27/7. The new tests cover optional canonical owner wire input,
protected group-owned CRUD, FULL hidden contributions (sum 13, visible member IDs 20/21/22,
hidden contribution 90), and a record remaining readable under its own owner after its
related source is hidden. Superseded reader-specific tests were removed; replacement
access-control, authority-scope and root-page cases verify the new contract. Original C3
creates/deletes and same-owner query-epoch/business-root conflict controls remain intact.
This is local correctness evidence, not multi-host/production evidence; SurrealKV was not
rerun. Roots use `(root_record_uuid, declared_slot)` and members `(record_uuid,
membership_slot)`, sorted by declared total order and stable ties. Composite ordering can
use tuples of root grouping and sort fields despite one parent/child participation; infer
no all-ancestor or all-permutation memberships. Tenant remains a strict namespace, with
no implicit central aggregate/counter absent an explicit business root. Codec `native-slice-kv-12`
requires old-store recreation. General C3 owner/order access streams remain planned.

### Remaining relationship guards

Final-graph source reference binding and final client reference authorization are
accepted as C2.F: see [evidence](checkpoints/c2-final-graph-references.json).
Early action/CAS boundaries remain; final owner accessibility is checked before target access.
This does not implement arbitrary relationship predicates or allow causal cycles.
Catalog scalar/pair tuple uniqueness is accepted as C2.U: see
[semantics](relationships.md) and [evidence](checkpoints/c2-reference-uniqueness.json).
Own-input/immediate-parent predicates and parent-edit revalidation are accepted
as C2.P: see [semantics](relationships.md#pure-parentchild-rules) and
[evidence](checkpoints/c2-relationship-predicates.json). Broader global or reverse
cardinality rules are not inferred. Preserve the following full C2 obligations.
Engine-owned Incoming bookkeeping is accepted as C2.A: see
[evidence](checkpoints/c2-automatic-incoming.json). Binding authoring requires typed
references, without a second manual Incoming implementation. Direct/Subscribers
policies remain separate. C3 accounting is the next bounded prerequisite.

Expose one prepared schema/reference catalog with explicit ownership and deletion semantics.
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
reference targets, owner-scope boundaries and full rollback on invariant failure.
Reuse [`src/mutation.rs`](../src/mutation.rs), [`src/dependency.rs`](../src/dependency.rs),
[`src/publication_tests.rs`](../src/publication_tests.rs) and authority tests as starting witnesses.

## C3 — Explicit global and domain indexes (accepted)

[Ordered access](ordered-access.md) and [checkpoint evidence](checkpoints/c3-ordered-access.json)
record the implemented owner-stream and native-range contract. Codec13 adds trusted creation
metadata and separate AccessRoot/AccessNode namespaces. Public paging covers one declared
resource/order across accessible owners; cross-resource union and visible global rank are
not supplied. The full C3/C4 verification passed 315 Rust and 193 Node tests, none skipped,
plus default/FDB lint and actual local FoundationDB/redb coordination and recovery controls.
The obligations below define the accepted scope and optional workload alternatives.

C3.0 preserves the historical pre-change real-adapter [contention baseline](checkpoints/c3-contention-baseline.json).
Historical C3.1 removed the stored capacity counter and `Binding::Limits` entirely, with no
tracked/untracked mode. That source used codec `native-slice-kv-11`; the current owner-only
format is `native-slice-kv-12`. Source-derived `Population` statistics remain read-only at
open/checking, never stored or scanned by normal mutations.
Business invariants, work/byte budgets, reservation identities, receipts and required
reader/contract epochs remain in historical C3.1 evidence; since C2.O, current epochs
are owner/contract scoped. [C3.1 is accepted](checkpoints/c3-counter-removal.json)
on FoundationDB 7.3.77, one local process/host: both original separate-scope creates
and deletes committed without automatic retries; the historical reader epoch and shared-business-root
conflict controls remain. See [results and continuation](c3-accounting-handoff.md).
C3 now implements declared chronological owner access/order streams and native non-time reactive cuts.
Measure remaining epoch and AVL-root coordination independently; do not remove required
guards to manufacture success or infer unrestricted capacity from counter removal.

Implement resource/tenant/owner/declared-order access definitions with explicit
per-resource opt-in, stable ties, root scope and created metadata. Prefer scoped streams and
authorized k-way merge; tenant-only ordered indexes are optional for measured workloads.
Owner accessibility controls ordinary reads and mutations subject to action-specific scope. Multiple domain indexes may
order by effective time, created time, distance or another declared total order with independent
summaries/validators. Define principal-root namespaces and transaction-domain boundaries.
Generalize non-time range query/dependency cuts deliberately: current subscriber routes are
time-specific. Preserve final-graph causality, exact boundaries, old/new route repair and field
identity across indexes. Test numeric/string/composite bounds without timestamp coercion.
Use one ordered root where sufficient; bounded k-way merge is for multiple sorted owner/resource streams. Specify snapshot, disclosure, cursor and filter semantics before promising global rank.
Acceptance: independent scan oracle matches results under rekeys, deletion and authorization
changes; payload-only updates avoid unchanged index writes where semantics permit.
Measure bytes, changed memberships, hot ancestors and conflicts for tenant/owner root alternatives.
Do not add a shared global count/root solely for convenience or claim filtered counts from raw rank.
Measure write coordination of each opted-in root; do not impose a universal analytics root.

## R0 — Scoped charged email submissions (accepted)

[E2/R0](e2-email.md) selects immutable point-count admission per provider/account/
email purpose in the store transaction domain. Protected policy/time and range reads
share the exact charged start transaction; quota denial consumes no submission attempt.
Ties, exact expiry, clock regression, stale calls, every-write rollback, unknown ACKs
and real FoundationDB races passed. This is bounded email submission admission,
not a generic mutable-policy limiter or a quota shared across independent stores.
See [acceptance evidence](checkpoints/e2-email-rate.json).

## C4 — Adaptive valid population from the same catalog (accepted)

[Population semantics](c4-population.md) and [evidence](checkpoints/c4-population.json)
cover deterministic catalog-derived proposals, tentative same-batch anchors, uniqueness,
fanout/skew, bounded failures, validated solver hooks and original-receipt recovery. The
full current-source suite above includes signed real-redb source-oracle/rollback checks.
Native validation remains authoritative over hidden/concurrent facts.

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
C3/C4 and [E1 credentials](e1-credentials.md) are accepted. E1 also fixes managed
UUID lifetime creation metadata and array-reference tentative fanout selection.
[E2/R0](e2-email.md) and [A0 identities](a0-identity.md) are accepted.
[A1–A2 private proof and sessions](a1-proof-sessions.md) are accepted: both fake
email/SMS paths, five attempts, one-use original issuance recovery and restored-session
fencing. See [evidence](checkpoints/a1-proof-sessions.json). E3 objects, E5 full-pipeline
recovery and fresh release/bootstrap verification remain required and unaccepted.
Work stops after A1/A2 at the user's request; resume with E3.

| Gate | Scope | Dependencies |
| --- | --- | --- |
| E0 | Current/absent capabilities, modes and recovery obligations | C0 and existing effect evidence; planning only |
| E1 | Accepted Credential records, secret-safe ingress, use authorization and bounded grants | Existing authority; C2 reference/uniqueness rules where needed |
| E2 | Accepted EmailSend, pinned secrets, independent fake Resend/Brevo transports and R0 charged starts | E1; shared worker and exact original recovery |
| A0 | Accepted protected email/phone identities and exact claims | E1–E2 |
| A1/A2 | Accepted private delivered proof and recoverable EdDSA sessions | A0; E2/R0 worker, credential and receipt guarantees |
| E3 | Authorized object grants, immutable finalize and recoverable cleanup | E1–E2, A1/A2; one selected object adapter |
| E4 | Optional recurrence producing ordinary one-shot jobs | E2 and protected occurrence uniqueness; no workflow engine |
| E5 | Independent fake full-pipeline, failure and recovery verification | Each selected E feature; C4 catalog tooling where used |

C1 and service contract preparation can proceed independently. Shared source edits
and schema/codec changes require a single integrator. Live-provider acceptance is
separate from fake protocol checks. Client WebSocket invalidations remain C5 work;
they are not provider webhooks or a substitute for the durable job protocol.
