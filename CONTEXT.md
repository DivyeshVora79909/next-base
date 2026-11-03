# Current checkpoint

## A0 — Protected email and phone identities

Implemented and verified. The services catalog declares immutable User-owned Identity
(1003) with owner/created index 10031, shared ASCII email/phone normalization, a private
exact claim dictionary and retained principal authentication revision. Self mutations
require verified JWT issuance within 600 seconds; strict descendant managers retain
ordinary action checks. Generic mutations, no-ops and final authorization enforce the
same policy. Original receipts recover before recency checks, with current disclosure.
Identity incarnation is private; replacement clears verification, delete/recreate starts
a new lifetime, and last-identity deletion remains legal. Native codec16 keys 18/19 and
the Services derived-state union require explicit recreation of earlier stores.

Claims release before final acquisitions, supporting swaps in either order. Source,
private metadata, ordered/owner indexes, epochs and receipts publish atomically.
Missing/regressed proof history rejects instead of being silently recreated. Repeated
settlements preserve each call's entry state and unchanged source version; full reverts
restore the database-original source token without dropping protected reads. E1 managed
creation metadata, tentative array fanout, both-owner transfers and no population counter
remain intact. A0 establishes proof fences; factor-removal session revocation is still A2.

Acceptance: 400 Rust all-target tests passed (0 ignored), 224 full Node tests passed
(0 skipped) using Node 26.12.0 and a freshly built default host. Formatting and default/FDB
all-target Clippy with warnings denied passed. Actual FoundationDB 7.3.77 on one local
process/host passed coordination/lifecycle/application/effects/predicates/credentials/
email/identity at 20/14/19/27/24/6/12/11; sequential redb controls at 17/10/13/27/16/6/12/11.
A0 covers duplicate/absence and four authority races, independent-owner disjoint writes,
ten native-write rollback positions plus post-receipt/final abort, lost ACK/original
receipt recovery, reopen, source-derived native/Node inventories, signed HTTP recency,
indexes/cursors and backup/restore. An initial Node run used Node 18 for shebang fixtures;
rerunning with Node 26 on PATH passed all 224. See [A0 evidence](docs/checkpoints/a0-identities.json)
and [contract](docs/a0-identity.md). This is local correctness, not distributed capacity.

Next: implement [A1/A2 private delivered proof and recoverable sessions](docs/a1-proof-sessions.md).
The selected bounded profile requires fake email AND phone delivery, five atomic attempts,
one use, encrypted private intent, original issuance recovery and restored-session fencing.
These remain unimplemented/unaccepted, followed by E3 objects, E5 full fake-pipeline
recovery and fresh committed-source release/bootstrap. Optional password mode, C5 live
invalidations, E4 recurrence, frontend, live providers and TiKV remain deferred.

## E2/R0 — Durable EmailSend and charged submission admission

Implemented and verified on redb and FoundationDB 7.3.77 on one local process/host.
Services now exposes immutable owner-scoped EmailSend (1002), explicit `email.enqueue`,
and transient request-bound grants. Original receipt recovery precedes grant validation;
final staged credential authorization and source/index/intent/receipt publication are
atomic. Use does not require Credential Read. Email status anchors to the current
EmailSend owner; hidden platform account/binding and bearer grants are not disclosed.
Ordinary both-owner transfers, managed creation metadata and no population counter remain.

Accepted jobs retain their exact credential incarnation and secret revision across
rotation. Shared retained envelopes count once in the eight-MiB service budget;
rewrap, custody, source-derived checkers and restore include all retained revisions.
Envelope `rebase-credential-secret-2`, effect codec `rebase-effects-5` and native codec
`native-slice-kv-15` are explicit breaking identities; recreate older stores.

The owned worker uses distinct Resend/Brevo fake loopback protocols, two bounded
HTTP calls, explicit no transport retries, exact start confirmation and a 1,000ms
maximum admission-to-call age. Missing keys stop owned work without a provider call;
restored keys permit original read-only reconciliation. Success records a durable
fact with `not_required` application. Uncertainty retains charges and never permits
a new send merely because lookup is empty. Only current-submit NotAccepted permits
up to three charged physical starts.

R0 enforces literal point counts in `(now-W, now]` per provider/account/email purpose.
Start history, quota points, policy/time rows and the exact start marker commit once.
Equal-time multiplicity, exact boundary expiry, clock regression, denied wake times,
rollback and unknown ACK recovery are checked. Policies are immutable and prevent
reset from erasing consumed quota. Retention is bounded to 256 executions/768 starts;
there is no retention compactor or cross-store account quota claim.

Acceptance: 367 Rust all-target tests passed (0 ignored); 214 full Node tests passed
(0 skipped) on Node 26.12.0 with the rebuilt default host. Formatting and default/FDB
all-target Clippy with warnings denied passed. Real FDB coordination/lifecycle/
application/effects/predicates/credentials/email passed 20/14/19/27/24/6/12; sequential
redb controls passed 17/10/13/27/16/6/12. E2 injected rollback after each of 12 enqueue
writes and seven start/admission writes, plus final-write aborts and durable ACK loss.
Full-slot and authority revocation races ran on FDB; redb results are sequential
controls. Both actual fake HTTP protocols, pinned old keys, secret/grant nondisclosure,
key-loss shutdown, byte-exact retained ciphertext/quota restore and reconciliation
passed. Original effect-demo, owner/index/cursor/rollback and source-derived checks
remain green. See [E2 evidence](docs/checkpoints/e2-email-rate.json) and
[E2 contract and entrypoints](docs/e2-email.md). This is local correctness evidence,
not live provider or multi-host capacity acceptance.

Next dependency: [A0 protected identities](docs/a0-identity.md), then A1 private
email/phone proof delivery and A2 sessions, E3 objects, E5 full fake-pipeline recovery,
and fresh committed-source release/bootstrap verification. These remain required,
unimplemented/unaccepted scope. Optional password mode, C5 live invalidations, E4
recurrence, frontend, live providers and TiKV remain deferred. The A0 document records
its concrete implementation contract and source-only legacy comparison.

## E1 — Credentials, grants and requested lifetime/fanout fixes

Publication status: published on `origin/main` as `b88645f`; verified against the
remote branch on 2026-11-03. E2/R0 implementation continues from this checkpoint.

Implemented and verified on the default backend and one local FoundationDB 7.3.77
process/host. The compiled `services` binding adds owner-scoped Credential metadata,
HPKE encrypted ingress, private XChaCha20-Poly1305 envelopes, explicit Use grants,
request-bound opaque email authorization, stopped-service rewrap and restore custody
checks. Source/private rows, indexes, query epochs and original operation receipts
share one commit. Current authority and both old/new owners are checked before CAS
and decrypt. Replayed committed writes recover before trying an expired capsule.
Grant issuance loads no provider secret and sends no requests. A retained internal
credential incarnation prevents delete/recreate from reviving old grants. Label
edits retain grants; rotation pins revisions and use-affecting edits advance epochs.

The Node client seals secret bytes before creating a persistable `credential-write`
plan. Execute/status retain the original target, context, operation and capsule.
The native host and developer tools expose all seven compiled models, a disabled
credential metadata fixture, and explicit operator rewrap/verification methods.
Keyrings stay external/private; backups contain ciphertext and restore secret use
requires the matching keys. Native and Node checkers derive private inventory from
source facts. E1 keeps one current envelope per credential in native KV tag 17;
E2 must change the explicit format to retain accepted job revisions.

Requested fixes are included: `Role.first_created_at` outlives inactive/retired
managed output rows and is reused across committed inactivity and repeated
settlements in one Attempt. The independent counterexample failed before the fix.
First activation/reactivation/transfer, index keys, rollback and reopen are covered.
Array references select and reserve each occurrence independently with candidate-local
fanout usage, allowing two unused parents for two references at maxFanout 1. Rules
and solver results still receive final validation, and rejection discards usage.

Acceptance: 344 Rust all-target tests passed (0 ignored), 202 full Node tests passed
(0 skipped) on Node 26.12.0 with the freshly built default redb host. Formatting,
default/FDB all-target Clippy with warnings denied, real HPKE known-answer and
cross-runtime tests passed. FDB coordination/lifecycle/application/effects/predicates/
credentials passed 20/14/19/27/24/6; redb controls passed 17/10/13/27/16/6. Independent
credential rotations committed with no shared writes; same-credential rotation and
four concurrent authority revocations correctly conflicted. Existing owner transfer,
managed output, cursor, source-derived index, rollback and recovery controls remain.
This is local correctness evidence; live providers, distributed capacity and standalone
SurrealKV were not accepted by this run. Current codec is `native-slice-kv-14`;
changed stores require explicit recreation. See [E1 evidence](docs/checkpoints/e1-credentials.json)
and [E1 contract and entrypoints](docs/e1-credentials.md).

Next dependency: implement [E2/R0](docs/e2-email.md): durable EmailSend using independently
bound Resend/Brevo fake protocols, retained credential revisions and scoped rate
admission. Then A0–A2 identity/proof/sessions, E3 objects, E5 full fake-pipeline recovery
and fresh committed-source release/bootstrap verification. These are required remaining
work, not completed capability. C5 live invalidations, E4 recurrence, frontend, live
provider acceptance and TiKV remain optional/deferred. No population counter is present.

## C3 and C4 — Ordered access, native reactivity and adaptive population

C3 is implemented and verified. Explicit catalog access indexes maintain linked
owner-scoped AVL streams in the same transaction as source facts, generated outputs,
transfers and receipts. Public ordered pages k-way merge one declared resource/index
across currently accessible owners, with exact tagged tuple bounds, stable UUID/slot
ties, filters, scoped cursor epochs and explicit work/get/load/response byte budgets.
The fixed tenant store and catalog-wide access index code define the root namespace;
there is no shared tenant aggregate or population counter. Payload-only edits skip
unchanged memberships. Both-owner transfer rules and private-output disclosure remain.

Trusted immutable `created_at` is UTC milliseconds at first materialization, distinct
from effective time or commit order. Generated outputs retain their own timestamps.
NativeRange over each family's key now drives public root ranges, query descriptors,
reverse routes, dependency gates and final-graph causal discovery. Numeric, string and
composite windows preserve complete-key boundaries and query slot identity. Explicit
temporal adapters retain the prior i64 boundary semantics. Codec `native-slice-kv-13`
and changed prepared identities require explicit store recreation.

C4 uses the same catalog for proposal-local typed anchors, ordered tuple uniqueness,
reference fanout/skew and declared rule checks. Bounded attempts/work expose unsatisfied
rules and unmet counts. Optional solver candidates pass the same schema/reference/check
path; native validation remains authoritative. Deterministic generation and exact original
plan/receipt recovery survive rejection and unknown outcomes. No external solver or
native population counter was introduced.

Acceptance: 315 Rust all-target tests passed (0 ignored); 193 full Node tests passed
(0 skipped) using Node 26.12.0 and the freshly built redb host. Formatting and default/FDB
all-target Clippy with warnings denied passed. Real FoundationDB 7.3.77 on one disposable
local process/host passed coordination/lifecycle/application/effects/predicates at
20/14/19/27/24; sequential redb controls passed 17/10/13/27/16. New independent-owner
original creates share no protected point dependencies; same-owner creates share two
access roots and one required owner epoch. Original output-producing create/delete,
reference, shared business-root, transfer/revocation/rollback and receipt controls remain.
Source-derived native/Node checks include whole missing forests, stale ownership/rekeys,
AVL structure, generated provenance, bounded reads, reopen and backup/restore.
See [C3 evidence](docs/checkpoints/c3-ordered-access.json), [ordered access](docs/ordered-access.md),
[C4 evidence](docs/checkpoints/c4-population.json) and [population](docs/c4-population.md).
These are local correctness and measured point-write costs, not multi-host capacity
or live-provider acceptance. Standalone SurrealKV was not rerun.

Next dependency: implement [E1's concrete credential/grant contract](docs/e1-credentials.md),
then E2 with scoped R0 admission, A0–A2 authentication and E3 objects, E5 full fake-pipeline
recovery, and fresh committed-source release/bootstrap verification. E1 is a design
contract only at this checkpoint. C5 live invalidations, E4 recurrence, frontend, live
providers and TiKV remain optional/deferred. Ordinary principal-management CRUD has no
selected implementation milestone; retain explicit operator graph provisioning.

## C2.T — Ordinary ownership transfers

Update accepts optional canonical UUID `owner` metadata outside model `set`; omitted
means unchanged and null rejects. Owner-only edits accept empty `set`/`unset`. Current
Update permission and access to BOTH old and new owners are required in the same
tenant/transaction, without an additional Read grant. Old-owner and destination scope
checks precede CAS diagnostics; final records are checked before publication. Delete
remains self/strict-descendant only. The unscoped native entrypoint remains self-only.

Generated outputs follow their producer even with unchanged calculated values. Public
owner indexes and both owner/contract query epochs move atomically; ordinary business
root/member identities stay source UUID/slot based. Root summaries retain their explicit
hidden-contribution disclosure contract, and cursors/receipt disclosure use current
authority. Same-owner/no-input-change updates preserve source versions, memberships and
query guards while retaining conflict reads and operation receipts. The scheduler skips
initial no-op producers but still discovers them through changed dependencies.

Composed settlements use immediately staged output identities, query subscriptions and
memberships; create/retarget/delete followed by a transfer in one Attempt is covered.
Original route discovery ignores producers already deleted by an earlier settlement.
Effect application explicitly rejects owner metadata or owner changes. Transfers preserve
pinned requester/intent/facts; pre-start worker authority and durable fact application
retain their existing boundaries. Email/phone identity linkage remains separately planned
and immutable, not an ordinary-transfer exception silently removed.

The owner policy identity is
`owner-only-update-both-owners-accessible-delete-self-descendants-2`.
Codec remains `native-slice-kv-12`; changed prepared identities require explicit store
recreation. See [checkpoint evidence](docs/checkpoints/c2-ownership-transfer.json) and
[bounded legacy comparison](docs/ownership-transfer-legacy.md). The comparison freshly
generated ordinary clauses and passed 11 disposable SurrealDB 3.3.0 witnesses. Legacy
group-member transfer can silently retain ownership; Next Base intentionally permits it
when both owners are accessible and rejects forbidden transfers atomically.

Acceptance: 298 Rust all-target tests passed (0 ignored), 176 full Node tests passed
(0 skipped), formatting and default/FDB all-target Clippy with warnings denied passed.
Real FoundationDB 7.3.77 on one disposable local process/host passed coordination /
lifecycle / application / effects / predicates at 18 / 14 / 19 / 27 / 24; sequential
redb controls passed 15 / 10 / 13 / 27 / 16. Transfer coverage includes seven physical
write abort points plus post-receipt abort, exact old/new indexes, original-operation
unknown-outcome recovery, and concurrent old-owner/new-owner scope, Update grant,
active-caller and credential-epoch revocation. Original independent output-producing
create/delete and conflicting owner-epoch/business-root controls remain. These are
local correctness results; no multi-host/throughput/capacity claim. SurrealKV was not
rerun. Source-derived integrity, generated provenance, receipt replay, reopen and
backup/restore are checked; broader C3 capabilities are not implied.

Next dependency: resume C3 chronological owner access/order streams and general non-time
reactive cuts from [the C3 handoff](docs/c3-accounting-handoff.md). These remain planned;
do not restore readers, a shared population counter or legacy compatibility machinery.

## C2.O — Owner-only access accepted

ModelRecord has an owner only; Reference has no reader flag. No reader inference or
repair is part of the current contract. The physical index is `owner_records`, not
`reader_records`; lookup k-way merges accessible owner streams. Read/Create/Update require
same-tenant scope, the action grant, and owner accessibility: self, strict descendants,
and direct group parents only. Direct tenant-parent records are excluded from ordinary
data scope; tenant-grant inheritance remains a separate legacy rule. Delete permits self
and strict descendants only. Admin actions do not widen ordinary scope. Create may specify
`owner` as a canonical UUID; omission defaults to the actor. A requested owner must be
accessible, enabling group-owned sharing. C2.O's immutable Update owner restriction is
superseded by C2.T above; its acceptance numbers below remain historical.

Privileged engine balancing/cascades validate hidden records without granting client
access. A root record read authorizes explicitly declared public summary data for its
tree; FULL aggregates may include hidden contributors but do not authorize leaf/body/ID
reads. Trees key roots by `(root_record_uuid, declared_slot)` and members by
`(record_uuid, membership_slot)`, sorted by declared total order with stable ties. A
single parent/child root participation still allows composite order by tuples of grouping
and sort fields; infer neither all ancestors nor all permutations. Tenant is a strict
namespace with no implicit central aggregate/counter absent an explicit business root.
The new codec is `native-slice-kv-12`; old stores require recreation. UUIDv7 is a
recommendation for millisecond-prefix locality plus randomness, not exact server
`created_at` or commit order, and cannot replace `effective_at`; nanoepoch alone is not
unique across servers. UUIDv7 is not enforced or auto-generated; callers may submit
supported canonical UUID formats, and the current native model does not auto-author
server `created_at` metadata.

Acceptance is complete: 284 Rust all-target tests passed with 0 ignored; all 174 full
Node tests passed with 0 skipped; formatting and default/FDB all-target Clippy with
`-D warnings` passed. Proof: [C2.O checkpoint](docs/checkpoints/c2-owner-only.json).
Real FoundationDB 7.3.77 ran on one host/process: coordination/lifecycle/application/
effects/predicates passed 18/14/19/27/10. Redb sequential controls passed 15/10/13/27/7.
Original independent C3 creates/deletes still commit; same-owner/contract query-epoch and
shared-business-root conflict controls remain. Optional canonical wire `owner`, protected
group-owned CRUD, hidden-contribution FULL summary (sum 13; visible member IDs 20, 21, 22;
hidden contribution 90), and final-graph reference behavior passed. A record remains
readable under its own owner after its related source becomes hidden. The old
reader-specific tests were removed with the superseded policy; replacement access,
authority and root-page tests cover the owner-only rules. These are local correctness
results, not multi-host or production-readiness evidence. SurrealKV was not rerun.

## Historical C3.1 — Counter removal accepted

The stored capacity counter and `Binding::Limits` API were removed in that source;
there is no tracked/untracked mode. C3.1 used codec `native-slice-kv-11`; current
owner-only source uses `native-slice-kv-12`. Recreate older stores explicitly. `Population` remains source-derived read-only inventory statistics at
open and independent checking, never stored or scanned by normal mutations.
Business invariants, work/byte budgets, identity reservations, authority fences,
receipts and required reader/contract epochs remain in the historical C3.1 source.
Since C2.O, current query epochs are owner/contract scoped; the C3.1 reader/contract
epoch evidence remains bound to its historical source.

[C3.1 evidence](docs/checkpoints/c3-counter-removal.json) accepts both original
output-producing creates and deletes in distinct scopes on FoundationDB 7.3.77,
one local process/host, without automatic retries. No Population reads/writes,
inventory scans, shared protected point writes or cross-reads occurred in those
attempts. The historical same-reader epoch and shared-business-root conflict controls remain valid for that source.
After creates: 10 records, 4 roles, 4 reservations; after deletes: 4 records with
4 retired roles and 4 retained reservations. Validation: 289 default Rust tests, 172 full
Node tests (none skipped), and default/FDB all-target Clippy with warnings denied.
Real FDB coordination/lifecycle passed 18/14; application/effects/predicates 19/27/12.
Redb sequential coordination/lifecycle passed 15/10; application/effects/predicates
13/27/9. These are local correctness results, not multi-host throughput evidence.
Historical [C3.0 evidence](docs/checkpoints/c3-contention-baseline.json) remains the
pre-change contention baseline. C2.O is accepted. C3 chronological
owner access streams and general non-time reactive cuts remain pending; see [continuation](docs/c3-accounting-handoff.md).

Ordinary data scope is self, strict descendants and direct group parents; direct tenant-parent records are excluded. Tenant-grant inheritance remains a separate legacy rule. Admin grants do not widen ordinary data scope. Operator control-plane administration
remains separate. [Email/phone authentication](docs/email-phone-authentication.md)
is planned; current JWT verification is implemented, delivered login proof is not.

## C2.A — Engine-owned reverse-reference indexes

The shared mutation path derives Incoming indexes directly from typed references;
bindings no longer implement that bookkeeping. Stage ordinary commands after all
source headers/typed checks and before settlement. The causal managed-output
writer uses the same strict helper at its existing header lifecycle transitions.
The late ordinary pass includes both changed records and explicit IDs, using the
proposed command or current call's entry state as baseline; this undoes staged
routes even if settlement restores a source to its original value. Repeated
settlement calls in one Attempt preserve both routes and unique claims, including
restored-source no-ops. Settlement-only ordinary edits also work.

Direct and ranged Subscribers policies are preserved. Independent Snapshot route
inventories remain source-derived. Native hints do not override catalog types;
duplicate identical target/slot pairs collapse, distinct slots stay separate.
Traversal/sorting inputs and late candidates consume work budget. Ordinary raw
creation without shared lifecycle and raw managed writes remain unsupported;
noncommand ordinary deletion is explicitly rejected before publication.
Historical C2.A reference-policy identity changed with codec kv-10. See
docs/checkpoints/c2-automatic-incoming.json and docs/relationships.md.

## C2.P — Declared parent projections and final-graph rules

`Reference.validation_fields` selects authored parent inputs for the pure ordinary
`Binding::validate_relationships(input, parents)` hook. `RelationInput` exposes
slot, target UUID and exactly the declared field map. Required/optional and
polymorphic references retain actual catalog type checks; native contract hints
are nonbinding. No calculation routes or published-output dependencies are inferred.

Shared validation runs after settlement/owner-scope/client-reference authority and
before uniqueness/publication. Check all changed surviving sources and final
incoming consumers whose declared parent projection changed, including hidden
children. One-hop discovery suffices because predicates do not write state.
Compiled immutable field unions skip Incoming traversal for unrelated body edits.
Independent Snapshot source enumeration checks rules without writer candidates.
Hook error details are redacted, and a shared policy revision joins model identity.
Codec stays kv-10; changed prepared identities require explicit recreation.

See docs/relationships.md and docs/checkpoints/c2-relationship-predicates.json.
Rules must be pure, deterministic and bounded native code; there is no untrusted
code sandbox, arbitrary global solver or inferred reverse cardinality constraint.
C2.A subsequently moves Incoming bookkeeping into the shared engine. C3 retains
its separate source-derived totals/concurrency acceptance contract.

## C2.U — Protected catalog reference tuple uniqueness

`Contract.uniqueness` declares positive local constraint codes and ordered scalar
reference slots. A single slot gives 1:1 target uniqueness; multiple slots give
ordered junction-pair uniqueness. Missing optional slots omit the whole claim;
nil UUID remains a target. Per-record bound multiplicity is checked natively,
without another JSON Schema shape parser. The developer catalog is the authority.

After final client reference authorization, shared settlement reconciles all
changed source records, including settlement-only edits. Verify original claims,
release all changed old tuples, then acquire final tuples through protected point
reads. Swaps/delete-reuse are final-graph operations. Exact independent Snapshot
inventory detects missing/wrong/extra claims and duplicate source facts. Optional
omitted constraints consume work too; models without constraints skip this path.

Codec is now native-slice-kv-10; explicitly recreate older stores. See
docs/relationships.md and docs/checkpoints/c2-reference-uniqueness.json for scope,
evidence and limits. Node backup checking validates physical claims/holder contract/
target existence; native checking additionally derives complete semantic inventory.
The explicit local FoundationDB test isolates the claim primitive from population
and the historical reader epoch contract; it is not full application or multi-host performance acceptance.

C2.P adds own-input/immediate-parent predicates and parent-edit revalidation.
These are independent of uniqueness and local JSON Schema. C3 access/order work
retains its separate contract.

## C2.F — Final-graph reference binding and authorization

Authored commands retain early action/old-owner checks before version diagnostics.
Bind/stage all proposed sources and headers before resolving typed references.
After model settlement and final deletion checks, resolve final owner scope, then authorize
new/retargeted references for explicit client commands against final owner accessibility.
Internal repairs cannot grant extra client actions. Reference policy is part of
prepared identity; old stores require explicit recreation. C2.F retained kv-9;
the subsequent C2.U checkpoint changes the codec to kv-10.

Quantity witnesses cover all six source/scale/scale create and delete permutations,
literal quantities, hidden references, owner-before-CAS rejection and exact rollback.
A multiple-parent authority witness ensures a newly hidden parent cannot authorize
its child using the temporary creation owner, in either command order.
See docs/checkpoints/c2-final-graph-references.json. C2.U adds protected catalog
tuples; general parent-field predicates and their invalidation remain deferred.

## C1.4 — Authorized batched occurrence pages

`Store::root_page` and JSON-RPC `roots.page` compose native rank windows, epoch
guards and batch hydration in one snapshot. Members require accessible root owner,
explicit members+summary declarations and per-record public projection. Only the
Calculation Account history opts in by default. Raw count/rank gaps are declared
topology disclosure; hidden IDs, leaves and private bodies are not returned.

Continuation binds query/root/store/model/actor/tenant plus root and authority/
owner/contract projection revisions. Output/candidate budgets may change on resume
under trusted ceilings. Signed payloads are not confidential; cursor contains no
hidden member IDs/keys. Epoch guards now use the existing bounded batch API too,
preserving UUID cursor digest framing. RPC uses default policy; trusted Rust callers
can supply another RootPagePolicy. Ordinary Node client.call needs no new wrapper.

Default-backend acceptance includes normal validated populations of 50/100/1,000
sources, private/denied gaps, budget adaptation, cross-scope/tampered cursors and
member payload/owner-scope edits that leave root revision unchanged. See
docs/checkpoints/c1-authorized-pages.json and docs/rank-reads.md. This is not
distributed performance/deployment acceptance. Next: remaining C2 catalog relation
guards, then C3 access/order work as their contracts require.

## Historical C2.R — Reader inference and repair (superseded)

C2.R's owner-inclusive reader inference/repair is historical, superseded, and must not
be restored. Keep its source identity and evidence immutable: [checkpoint](docs/checkpoints/c2-reader-policy.json).

The accepted C1.4 layer composes authorized root member paging, same-snapshot
hydration and root/scope-bound cursors. Existing UUID-page semantics are retained.
A summary declaration alone must not enumerate members;
explicit member capability permits raw topology/counts, not hidden IDs or bodies.
Signed cursors have integrity, not confidentiality. See docs/rank-reads.md.

## Selected foundation and authoring

Native Rust transaction/calculation harness over redb (local), with optional
FoundationDB and standalone SurrealKV adapters. SurrealKV is not SurrealDB.
Linked augmented AVL is selected; no B-tree page rewrite or SurrealDB wrapper.
One prepared model/catalog supplies schemas, typed references, index participation
and developer metadata. Preserve capability through breaking redesigns, not names.

Developer tools are ordinary Node ESM functions, imported from tools/node/index.mjs
and explicitly composed in the REPL or caller scripts. No parallel developer CLI,
new argument parser or wrappers for ordinary fs/loops/fetch/process operations.
Rust/Cargo and the native server/host retain their standard command interfaces.
Current population has typed pools, quotas, strategies/selectors, clock/context
callbacks and receipt-bound accept/reject; richer native cardinality/skew/global
constraint generation remains C4. Do not claim legacy feature parity from names.

## Remaining core gates

- C1.1 structural sizes/count-only family, C1.2 same-view storage batches, C1.3
  trusted rank windows and C1.4 authorized member paging are accepted on the default
  backend. Broader distributed workload acceptance is separate.
- C2.F final-graph references, C2.U catalog uniqueness and C2.P own-input/
  immediate-parent predicates are accepted within their documented scopes.
  Parent/child order comparisons must register parent inputs and revalidate parent
  edits, not only child insertion. Local JSON Schema alone is insufficient.
- C3 declared owner/order access streams are accepted as described above. Read
  one opted-in public resource/index across current owner scopes; no cross-resource
  union, global visible rank or implicit tenant aggregate/counter is supplied.
- Non-time native ranges now drive ordered reads and reactive query/subscriber
  cuts. TimeRange remains an explicit temporal adapter.
- Stored capacity accounting is removed; source-derived inventory remains read-only.
  C3.1 local real-FDB concurrency/recovery acceptance is complete. Preserve reservation
  identities and business guards. C3.1's old reader/contract epoch evidence remains tied
  to that historical source; C2.O's current direction uses owner/contract epochs.
- C4 bounded adaptive population is accepted. Supplied pools/rule callbacks cannot
  prove hidden or concurrent state valid; native atomic validation remains required.
  C5 resumable live invalidations remain optional.

## Server extensions and evidence boundaries

E1 credentials and bounded grants are accepted as described above. E2–E5 EmailSend
with independent Resend/Brevo bindings, object lifecycle, optional recurrence and
full-pipeline acceptance remain planned.
Reuse committed intent/start/fence/fact/application and unknown-outcome recovery.
Unrelated external provider I/O follows commit, outside the native transaction.
Do not mandate public v1/v2 operations; accepted jobs pin semantics/provider/account.

Default HTTP uses Axum/Tokio. TiKV, frontend, live providers and production accounting
are deferred. Local one-host FoundationDB campaigns are not multi-host performance
proof. Full inventories/tool resource budgets do not imply unlimited scale acceptance.

C0 imported ReBase 270d875/rebase-next without changing the original repository.
Application: https://github.com/DivyeshVora79909/next-base
Independent research: https://github.com/DivyeshVora79909/research
PROVENANCE.json and docs/checkpoints retain exact historical scopes. Do not rewrite
old fingerprints as new acceptance. Application-linked N/S0 instructions stay here.

A fresh agent reads AGENTS.md, this file and the relevant roadmap contract, inspects
Git, chooses a coherent authorized slice, begins with an independent counterexample,
then implements, verifies and records the next dependency. Commit/push verified
checkpoints within the user's actual authorization. Conversation-specific pauses or
usage budgets are not a standing commit-count policy for other agents.
