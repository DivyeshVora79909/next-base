# Current checkpoint

## C1.3 — Trusted count-pruned rank windows

`tree_read::rank_window` now composes same-view Table batching with generic linked
AVL structural counts. It returns raw ordered occurrences, root revision/count and
accounted work/byte counters. Explicit budgets cover fetched nodes and checked
output reservations; selective reads trust unvisited subtree metadata. Non-time
String/unit-summary membership, ties, multislot order, pruning, snapshot, exact
budgets and encountered corruption have independent tests. See docs/rank-reads.md
and docs/checkpoints/c1-rank-reader.json. Node backup/S0 checkers and synthetic test
constructors now match mandatory codec-v9 sizes; historical evidence stays unchanged.

The latest user instruction supersedes the earlier six-commit allowance: complete
this ONE next commit (C1.3), then STOP for a new flag. Do not begin C1.4 here.
Next implementation must first settle C2.R's owner-inclusive minimal-reader policy,
then C1.4 authorized member paging/hydration/cursors. The trusted primitive is not
exposed over RPC. Retain existing UUID-page meaning. Read docs/roadmap.md C2.R;
current immediate-owner/fallback folding is not the newly requested policy.

Latest C3 direction: explicitly opt into resource/tenant/reader-or-owner/declared-
order streams and merge authorized streams; a tenant-only index is optional for a
measured workload. Reads use reader visibility; owner controls writes. Tenant is a
strict namespace. Do not add a universal hot counter or remove required guards to
claim independent writers. Existing Population capacity accounting is still shared
even for unbounded models; specialize it only with inventory/recovery/race evidence.
Non-time range subscriptions still require C3 type/routing integration; time is
simply one total order. Direct parent/child field predicates remain C2 work.

Handoff for a fresh agent: read AGENTS.md, this file, docs/roadmap.md,
docs/index-mathematics.md and docs/rank-reads.md; inspect current Git before editing.
Continue only for the user's newly authorized commit count. Start C2.R with a small
source-DAG oracle/counterexample before changing reader semantics/identities; preserve
tenant isolation, current action grants, request reference checks, privileged internal
repairs, receipts and rollback. Then compose C1.4 from existing primitives. Do not
infer that a signed cursor hides its payload or that owner and reader are identical.

## C1.2 — Bounded same-view storage batches

ReadView/Table batch_get preserves positions, duplicates, missing keys and native
transaction visibility. Explicit max_keys/max_bytes/nonzero concurrency bound each
call; FoundationDB issues protected native gets in concurrent chunks, while local
adapters retain the ordinary fallback. Byte budgets describe accounted input/output,
not strict heap or wire bounds. Diagnostic facade get events use role batch; native
binding requests retain their own counts. See docs/storage.md and
docs/checkpoints/c1-storage-batches.json for tests and the single-host FDB campaign.
No public member API is added. C1.3 adds trusted rank traversal; C1.4 public
authorization/cursor integration remains pending.

## C1.1 — Checked structural size and count-only indexes

The initial implementation authorization covered three commits and was later
extended as above. C1.1 adds mandatory Root/Node size and a supplied String-keyed
CountOnly family with unit business summary. Independent inventory/topology checks
reconstruct sizes; CRUD, rotations, ties, multislot membership and overflow are tested.
Native codec is now native-slice-kv-9. Recreate old stores explicitly; missing-size
values are rejected. Historical fixture/evidence bytes remain unchanged. The host
protocol test derives only its expected model identity from the current catalog.

C1.2 adds same-view storage batches; C1.3 adds trusted rank-window traversal.
C1.4 must integrate authorized member paging, hydration, scope/root
revision-bound cursors and declared read permissions before C1 is complete.
No new public member enumeration or non-time subscription API is accepted here.
Parent/child order predicates are C2 direct-dependency rules; parent edits must
revalidate children against the staged final graph. See docs/index-mathematics.md.

Verification and inputs: docs/checkpoints/c1-structural-counts.json. The application
stays on main; pending storage/reader work is delegated in disjoint files and is
excluded from the isolated C1.1 verification and commit.

## M0 — Index mathematics and rate contracts, planning plus bounded witnesses

This historical pass stopped after one planning checkpoint. The user subsequently
authorized the three C1 implementation slices above; that is the current boundary.
Read docs/index-mathematics.md, docs/rate-admission.md and docs/roadmap.md.
Seven focused Rust witnesses exercise actual financial algebra and independent
window/source oracles. Their bounded scope is not production quota acceptance.
Results and reviewed identities are in docs/checkpoints/m0-index-contract.json.
No production source, API, schema, dependency or codec changed.

Selected targets: structural count independent of business summaries; count-only
indexes and multiple arbitrary total orders/memberships. The initial shared-index
proposal is superseded by the resource-scoped C3 direction above. Generic Key: Ord
does not generalize time-specific Query/routing subscriptions. C3 must address it.
Associativity permits regrouping; commutativity permits reordering. Linear totals
allow arbitrary declared exact coefficients, but validation is not a solver.
Online rate admission needs one point; fixed-window all-history maxima can instead
use two derived endpoints and complete-group prefix maximum. Both need protected
dispatch integration. Tree events alone do not wake clock-dependent queries.

For C1 the selected transaction domain is one store/prepared model, with explicit
budgets and independent source-derived tests. No unresolved product choice blocks
that slice. Cross-store global timelines require a separate contract, not an
assumption that identical tenant IDs give cross-store atomic indexes.

## E0 — Server execution contracts, planning only

Read docs/server-execution.md for current/absent capabilities, ordinary Rust
composition, secret-safe credential records, grants, durable jobs, object lifecycle
and optional recurrence. E1–E5 have acceptance witnesses in docs/roadmap.md.
Prove one EmailSend contract with independent Resend and Brevo adapters; mandatory
public v1/v2 APIs are not selected. Accepted jobs retain their provider/account,
canonical request, semantic identity and required decoder through recovery.
Historical E0 evidence remains bound to the original E0 source.

Preserve the existing intent/start-marker/fence/fact/application machinery.
Async functions are not durable jobs; client-callable entries are explicitly
authorized and private helpers consume trusted capabilities. Secret-safe ingress
must account for saved plans and receipts, not only at-rest encryption or redaction.
Native transactional KV awaits are distinct from unrelated provider I/O.

The legacy design had signing grants and queued/inline tasks, but removed cron;
the current native demo has one-shot scheduling, not object storage or provider
credential records. These are planned extensions, not features inferred from names.
C1 is the active core implementation gate, split into the slices above.
For each slice: meaning -> established concept -> invariant/counterexample -> small
prototype -> composition -> independent verification -> checkpoint. Production
server-service implementation is outside these three C1 commits.

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

## Open gate: C1 — Bounded count-pruned batch reader

Research has checked prototypes; production readers are synchronous and public
UUID paging is separate. Structural counts and count-only indexing are C1.1;
add bounded batch fetch and authorized root/rank traversal under one transaction. Preserve query meaning,
ordering, continuation, work/byte limits and original receipt semantics.

Resource/tenant/reader-or-owner/order access trees are not implemented; the current
public index is reader/contract/UUID. Created and effective differ;
generic created-at metadata is not yet a query primitive. Measure Population-key,
reader/contract-epoch and AVL-root contention before adding analytics indexes.
Typed references exist; generic 1:1 uniqueness and declarative adaptive
skew/cardinality are C2/C4 work, not inferred capabilities.

HTTP JSON-RPC uses Axum/Tokio. Optional WebSocket invalidations need an atomic
durable log, partitioned replay, scope revalidation and backpressure. TiKV,
frontend and live providers remain optional. User-reported three-node cloud
results were not independently measured here.

When the next implementation agent is authorized, continue checkpoints after
their acceptance obligations pass. Keep
semantic/format identity changes explicit and avoid duplicate schemas/DSLs,
unused frameworks, universal hot counters or mandatory solver dependencies.
