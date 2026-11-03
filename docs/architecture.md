# Native base architecture

The selected foundation is the existing Rust engine, native RPC and transactional KV adapters,
with linked augmented AVL indexes. This is the current design direction; earlier S0/N-series
reports remain historical evidence with their original acceptance boundaries.
The [roadmap](roadmap.md) distinguishes implemented behavior from planned checkpoints.
The [server execution plan](server-execution.md) defines service composition and
E-series acceptance; ordinary async functions are not durable execution records.

## Implemented authority and transaction boundary

[`identity.rs`](../src/identity.rs) verifies EdDSA JWT signature, issuer, audience, tenant,
subject and time bounds. [`server.rs`](../src/server.rs) authenticates transport ingress;
TLS terminates at the configured trusted deployment boundary. A subject identifies a principal,
not an owner supplied by an untrusted claim. JWT verification does not grant a client scope.
[`access.rs`](../src/access.rs) prepares the tenant principal DAG. The current direction is breaking owner-only access: ModelRecord has an owner and no reader field,
and Reference has no reader flag. Read/Create/Update require the action, same tenant,
and owner accessibility (self, strict descendants, and direct group parents only).
Direct tenant-parent records are excluded from ordinary data scope; tenant-grant
inheritance remains an independent legacy rule. Delete permits self or strict descendants
only. Admin actions do not widen ordinary data scope. Create may specify `owner` as a
canonical UUID, defaulting to actor when omitted; requested owners must be accessible,
which enables group-owned sharing. Update accepts optional canonical UUID `owner`
metadata, requiring Update permission and access to both old and new owners. Omission
retains ownership; an owner-only edit accepts empty `set`/`unset`. Destination scope is
checked before CAS diagnostics and final records are checked before publication. The
policy identity changes with these semantics; codec remains `native-slice-kv-12`, and
earlier prepared identities require explicit store recreation. See the
[transfer checkpoint](checkpoints/c2-ownership-transfer.json). Historical C2.O acceptance is complete;
see the [checkpoint](checkpoints/c2-owner-only.json). Verification passed 284 Rust
all-target tests (0 ignored), all 174 full Node tests (0 skipped), formatting, and
default/FDB all-target Clippy with `-D warnings`. The prior C2.R
reader inference/repair policy is historical and superseded. Privileged settlement and
cascades may validate hidden records but cannot grant client access or extra mutations.
Root reads authorize explicitly declared public summaries only; FULL summaries may
include hidden contributors, without granting leaf, body or ID reads. See the current
[roadmap](roadmap.md).

[`security.rs`](../src/security.rs) loads current persisted authority and credential epochs
inside transaction scope. Authority changes and operation-context fencing are separate from
JWT expiry. Each attempt must use current authority; retries must not reuse stale permission
results. [`local.rs`](../src/local.rs) authorizes client actions and new/changed reference targets;
[`mutation.rs`](../src/mutation.rs) checks declared type, tenant, existence and final invariants.
Trusted settlement can repair hidden nodes and derived records without user read filtering.
That internal privilege does not authorize extra client edits or disclose hidden records.
Action/old-owner checks run before binding or version diagnostics. All authored
records and their headers are staged before typed reference existence/type/tenant
checks, so a valid forward reference does not depend on command order. After model
settlement, owner-scope resolution resolves final authority before new/retargeted client
references are authorized. Only explicit client commands receive this authorization;
internal derivation does not acquire client privileges. The shared reference-policy
revision participates in prepared model identity. This does not permit causal
feedback or defer external side effects into the transaction.

[`staging.rs`](../src/staging.rs) and the native workspace hold attempt-local reads and patches.
Ordinary functions receive explicit state; they need no hidden process-global workflow context.
[`storage.rs`](../src/storage.rs) defines protected transactional reads/scans and one commit.
Source changes, references, indexes, calculations, owner-index repairs, receipts and applicable effect
intent publish together. A helper must not publish intermediate writes. Point-overlay no-op
elimination does not remove conflict guards or protected empty-range reads.
When commit outcome is uncertain, timeout/cancellation alone does not prove rollback: use
receipt/status recovery and preserve the original operation ID, request and context.
Known precommit validation rejection publishes nothing. External delivery follows committed intent;
[`effects.rs`](../src/effects.rs) does not promise exactly-once external execution.

## One model authority and explicit relationships

[`model.rs`](../src/model.rs) prepares schemas, references, roots, memberships, capabilities
and model identity; public/developer catalogs are projections of this authority.
[`binding.rs`](../src/binding.rs) supplies compiled native semantics. Keep new query,
population and authorization declarations attached to that catalog rather than parallel schemas.
Typed references have stable slots, target types, optionality and dependency roles; they carry no reader flag.
The engine automatically maintains Incoming reverse indexes for ordinary source
mutations and causal managed-output transitions, including late ordinary settlement
edits. Bindings retain their Direct/Subscribers invalidation policies; they must not
duplicate Incoming maintenance. Independent checking derives the expected routes
from complete source references rather than calling the writer helper.
Implemented model deletion declarations use `reject`; generic cascade/nullify are not supplied.
Incoming references and subscribers guard deletion and must be repaired in the same final graph.
1:n uses a child-to-parent reference, with an ordered membership only when a query needs it.
Catalog `Contract.uniqueness` reserves protected reference tuples for 1:1 partners
or ordered n:m junction pairs. A reference alone does not imply uniqueness.
Old releases precede final acquisitions, so joint retargets depend on the final graph.
See [relationship semantics](relationships.md) for scope, optionality, costs and
independent inventory checking. Endpoint deletion still follows declared reject
rules. Reuse a cardinality root instead when it fully expresses a distinct invariant;
do not duplicate coordination without a reason. Owner assignment remains explicit.
`Reference.validation_fields` and the pure `Binding::validate_relationships` hook
cover own-input/immediate-parent rules without a second expression language.
Final incoming references select affected children on parent edits; unchanged
declared field unions skip traversal. Independent source enumeration checks every
rule. Hidden dependents still constrain integrity, with redacted client errors.
See [relationship rules](relationships.md#pure-parentchild-rules) for costs and scope.

## Selected index structure and planned read work

[`tree.rs`](../src/tree.rs) maintains individually stored AVL nodes, parent/child and prev/next
links, structural spans and family summaries. [`index.rs`](../src/index.rs) and
[`indexes/standard.rs`](../src/indexes/standard.rs) define the typed family contracts.
The [mathematical contract](index-mathematics.md) separates arbitrary key order,
structural count, business summaries and quantified validators. Universal structural
count/count-only indexing is implemented in C1.1; business counts retain their
own declared meaning. Current codec `native-slice-kv-14` requires explicit store recreation.
Constant-size associative summaries permit logarithmic path work per changed occurrence;
full mutation work also includes fanout, reference checks, authority repairs and cascades.
Arbitrary aggregates or authority graphs do not inherit a universal logarithmic bound.
The count-pruned batched reader supplies trusted rank windows (C1.3) and authorized
occurrence pages (C1.4). Node hydration and cursor epoch guards use same-snapshot
batches; declared member permission still requires per-record disclosure checks.
Root and owner-scope revisions fence continuation without exposing hidden member IDs.
See [rank reads](rank-reads.md) for operational limits and the ordinary Node call.
[Prototype evidence](https://github.com/DivyeshVora79909/research/tree/0986b06d120b18713f76fec26b71faa5c40c60b6/parallel-read-foundationdb) is separate from application acceptance.

Declared access indexes now opt resources into owner-scoped creation or authored-field
order streams. `records.order_page` merges one declared resource/index across accessible
owners in one snapshot with candidate, work, get and byte budgets. Tenant remains the
store's strict transaction namespace. AccessRoot/AccessNode separate principal-root
identity from domain source-root identity; catalog-wide index codes identify resource
and order. The UUID `owner_records` lookup remains available. Trusted immutable
`created_at` records first materialization time, distinct from effective time or commit
order. See [ordered access](ordered-access.md) for declarations, cursor/filter semantics,
exact keys and independent verification.
Each resource may also declare multiple domain indexes with time or non-time keys,
business summaries and optional invariants. Created and effective time differ.
Each added membership increases maintenance; unchanged projections need not be rewritten.
Root partitioning and global ordering must be explicit; a tenant prefix alone does not
avoid hot ancestors. Raw count/rank does not prove authorized filtered count/rank.
Avoid a universal hot counter. Optional live invalidations would publish through a durable outbox
after commit, with partitioned resume cursors and replay semantics; this is C5 work, not present API.

Stored capacity counters and `Binding::Limits` are removed, with no accounting mode
fallback. The current format uses `native-slice-kv-14` and requires explicit recreation; `Population` is source-derived read-only inventory
at open/checking, never persisted or scanned by normal mutations. Business validators,
work/byte budgets, identity reservations and required owner/contract epochs remain.
Historical [C3.0 evidence](checkpoints/c3-contention-baseline.json) records pre-change
Population coupling. [C3.1 evidence](checkpoints/c3-counter-removal.json) accepts
separate-scope original creates/deletes committing without automatic retries on
FoundationDB 7.3.77, one local process/host. Required epoch and shared-business-root
conflict controls remain. See [results and continuation](c3-accounting-handoff.md);
these results do not establish multi-host performance or throughput.
[A0 protected identities](a0-identity.md) add immutable User linkage, exact normalized
claims and recent self-management. [Email/phone proof and login](a1-proof-sessions.md)
remain planned; identity presence and operator graph replacement do not prove a
factor or implement ordinary principal CRUD.
Public root ranges and reverse subscriber routes now use `NativeRange<I::Key>`.
Native numeric, string and composite keys preserve included/excluded group boundaries,
old/new registration repair and final-graph causality. TimeRange remains an explicit
temporal adapter; native ordering never requires a timestamp cast.

E1's explicit `services` binding supplies Credential metadata and encrypted secret
operations in the same ordinary transaction domain. `Role.first_created_at` and
private credential envelopes are part of codec14. A generated UUID's timestamp
survives inactivity; a Credential's internal incarnation fences delete/recreate
authorization. See [E1](e1-credentials.md) for implemented custody/grant boundaries
and accepted [E2/R0](e2-email.md) for durable email, retained secret revisions and
charged physical-start admission. Current A0 source uses codec16 for the private
identity dictionary and retained principal authentication revision.
