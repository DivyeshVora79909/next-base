# Current checkpoint

## Next authorized checkpoint — ownership transfers

The latest user explicitly supersedes the ownership-immutability restriction below:
ordinary records should allow transfers when the caller has Update permission and
access to both old and new owners, within the same tenant. Implementation is pending;
this run only performed a small source audit and prepared
[the execution handoff](docs/ownership-transfer-handoff.md). Implement that checkpoint
before resuming broader C3 work. Do not restore readers or the population counter.
Use the actual agent environment: earlier subscription-specific routing, subagent
trees and conversation commit quotas do not constrain an API-based continuation.

## C2.O — Owner-only access accepted

ModelRecord has an owner only; Reference has no reader flag. No reader inference or
repair is part of the current contract. The physical index is `owner_records`, not
`reader_records`; lookup k-way merges accessible owner streams. Read/Create/Update require
same-tenant scope, the action grant, and owner accessibility: self, strict descendants,
and direct group parents only. Direct tenant-parent records are excluded from ordinary
data scope; tenant-grant inheritance remains a separate legacy rule. Delete permits self
and strict descendants only. Admin actions do not widen ordinary scope. Create may specify
`owner` as a canonical UUID; omission defaults to the actor. A requested owner must be
accessible, enabling group-owned sharing. Update cannot change owner.

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
- C3 chronological access indexes remain pending: explicitly opted-in
  resource/tenant/owner/order streams, k-way merged across accessible owner scopes.
  Owner-only C2.O supersedes reader disclosure. Tenant is a strict namespace; no
  implicit aggregate/counter. Today's public index implementation is not these trees.
- Non-time keys already work in native ordered reads, but reactive query/subscriber
  cuts remain TimeRange/TimeBound. C3 must generalize types/routing deliberately.
- Stored capacity accounting is removed; source-derived inventory remains read-only.
  C3.1 local real-FDB concurrency/recovery acceptance is complete. Preserve reservation
  identities and business guards. C3.1's old reader/contract epoch evidence remains tied
  to that historical source; C2.O's current direction uses owner/contract epochs.
- C4 adaptive valid population must share the catalog, expose constraints/unsatisfied
  rules and preserve deterministic seeds/receipts. Optional solver hooks cannot make
  arbitrary global validity free. C5 resumable live invalidations remain optional.

## Server extensions and evidence boundaries

E0 service contracts are planned; E1–E5 credentials, EmailSend with independent
Resend/Brevo bindings, object lifecycle and optional recurrence are not implemented.
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
