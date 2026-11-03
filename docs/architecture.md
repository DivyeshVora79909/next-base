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
[`access.rs`](../src/access.rs) prepares the tenant principal DAG and separates record owner
from reader: contract action plus owner accessibility controls writes; Read plus reader
accessibility controls disclosure. Current DAG grants have specific bounded semantics,
not arbitrary transitive ACL intersection. C2.R selects the first minimal owner
from the resource and its reader-marked source hierarchy, in stable catalog order.
Mutation/admin repair and independent checking follow the same declared meaning;
managed outputs inherit their producer. The shared reader-policy revision is bound
into every prepared model identity. See [C2.R](roadmap.md#c2r--owner-inclusive-minimal-reader-policy-before-c14).

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
settlement, reader repair resolves final authority before new/retargeted client
references are authorized. Only explicit client commands receive this authorization;
internal derivation does not acquire client privileges. The shared reference-policy
revision participates in prepared model identity. This does not permit causal
feedback or defer external side effects into the transaction.

[`staging.rs`](../src/staging.rs) and the native workspace hold attempt-local reads and patches.
Ordinary functions receive explicit state; they need no hidden process-global workflow context.
[`storage.rs`](../src/storage.rs) defines protected transactional reads/scans and one commit.
Source changes, references, indexes, calculations, reader repairs, receipts and applicable effect
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
Typed references have stable slots, target types, optionality and dependency/reader roles.
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
do not duplicate coordination without a reason. Reader choice remains explicit.
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
own declared meaning. Current codec v10 requires explicit store recreation.
Constant-size associative summaries permit logarithmic path work per changed occurrence;
full mutation work also includes fanout, reference checks, authority repairs and cascades.
Arbitrary aggregates or authority graphs do not inherit a universal logarithmic bound.
The count-pruned batched reader supplies trusted rank windows (C1.3) and authorized
occurrence pages (C1.4). Node hydration and cursor epoch guards use same-snapshot
batches; declared member permission still requires per-record disclosure checks.
Root and scope revisions fence continuation without exposing hidden member IDs.
See [rank reads](rank-reads.md) for operational limits and the ordinary Node call.
[Prototype evidence](https://github.com/DivyeshVora79909/research/tree/0986b06d120b18713f76fec26b71faa5c40c60b6/parallel-read-foundationdb) is separate from application acceptance.

Planned authorized indexes use resource/tenant/reader-or-owner/declared-order,
explicitly opted into per resource, with stable ID/slot ties. Merge current authorized
reader streams for reads; owner and reader are distinct policies. Tenant-only
analytics indexes are optional for measured workloads. These are not yet implemented.
Each resource may also declare multiple domain indexes with time or non-time keys,
business summaries and optional invariants. Created and effective time differ.
Each added membership increases maintenance; unchanged projections need not be rewritten.
Root partitioning and global ordering must be explicit; a tenant prefix alone does not
avoid hot ancestors. Raw count/rank does not prove authorized filtered count/rank.
Avoid a universal hot counter. Optional live invalidations would publish through a durable outbox
after commit, with partitioned resume cursors and replay semantics; this is C5 work, not present API.

Existing write contention also needs measurement: settlement reads the store-wide Population
key and writes it when counts/reservations change; public edits update reader/contract epochs.
These can couple independent AVL trees. C3 must distinguish these guards from tree-root work
and preserve required business constraints while evaluating finer operational coordination.
C3.0 now provides the controlled pre-change [contention baseline](checkpoints/c3-contention-baseline.json):
separate output-producing creates/deletes share Population, while the scoped-epoch
negative control coordinates without Population writes. This is point-key and
correctness evidence, not exclusive native abort-key attribution or a throughput
benchmark. [C3.1 accounting](c3-accounting-handoff.md) remains unimplemented.
Generic ordered reads already exist, but public root ranges and reverse subscriber
routes still use TimeRange/TimeBound. Generic non-time range reactivity is a C3
contract/implementation gap, not automatically supplied by Key: Ord.
