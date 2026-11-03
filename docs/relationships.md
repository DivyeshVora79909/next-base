# Reference tuple uniqueness

Declare constraints once in the compiled model catalog:

```rust
contract.uniqueness = vec![Unique {
    code: 1,
    reference_slots: vec![1], // At most one partner per target, in this contract.
}];
// A junction instead uses reference_slots: vec![1, 2].
```

`Unique` is `model::Unique`. Codes are positive and distinct within a contract.
Slots are positive, distinct, declared reference slots, in tuple order. The
developer catalog and prepared model identity include these declarations.
No separate population schema, registration function or command parser is needed.

For each constraint, two different source records of the same contract cannot
have the same ordered target tuple. `(A, B)` differs from `(B, A)`; repeated targets
inside one tuple are allowed. Different contracts or constraint codes have independent
claim spaces. The store's tenant namespace supplies tenant isolation; owner/reader
do not partition uniqueness. Put a cross-class exclusive relationship in a shared
claim resource when that is the actual business invariant.
Uniqueness enforces an upper cardinality bound; it does not require every target
to have a partner. Mandatory companion existence needs a separate final-graph rule.

Each constrained slot binds zero or one target through `NativeInput::references`.
More than one is rejected, not silently flattened. A missing optional slot skips
the entire tuple; a missing required slot is invalid. JSON `null` is absence only
when the native binding omits that reference. The nil UUID is a real target, not
an absence marker. The catalog does not introduce another JSON Schema shape parser:
native typed reference extraction remains the binding's authority, including nested
fields. Schemas still validate the authored input normally.

The engine derives Incoming reverse-reference indexes from those same typed
references. A binding must not write Incoming routes itself. Ordinary commands
stage them after all new headers and typed target checks, before model settlement.
The managed-output lifecycle uses the same helper at each output transition.
After settlement, a final ordinary-record pass repairs reference changes made by
settlement, including an explicit proposal restored to its original source value.
Each settlement call uses its own entry state, so several calls can share one
Attempt and final commit without reapplying old routes or misreading staged unique
claims as persisted originals. Each call still validates its own bounded final graph.
Distinct reference slots remain distinct occurrences; identical target/slot pairs
are sets and do not create duplicate route nodes. Native contract hints do not
override actual catalog target types or tenant checks.

This automation owns existence/reverse-reference bookkeeping. Direct invalidation
and ranged Subscribers retain their separately declared/model-specific semantics.
Raw ordinary-record creation without shared headers/capacity lifecycle, or raw
managed-output writes bypassing the causal lifecycle, is not an alternative public
creation API. Use the mutation and managed-output paths. The engine rejects raw
ordinary deletion outside the command lifecycle. The independent checker
continues deriving expected Incoming memberships from complete source facts.
See [C2.A evidence](checkpoints/c2-automatic-incoming.json).

The shared mutation path first stages and settles the final source graph, repairs
readers and authorizes explicit client reference changes. It then examines every
changed record, including changes made by settlement rather than client commands.
It verifies old claims against their original source, releases all changed old
claims, and acquires final claims. Swaps, cycles of retargets and delete/reuse work
in one transaction without depending on command order. Missing/wrong old claims
are corruption; a competing final holder is an `invariant` error. No holder ID is
returned in that error. Changes, claims and receipts publish once or all roll back.

A protected point read, including an absent-key read, supplies concurrency control.
There is no global uniqueness counter or incoming-reference scan. Existing population
and query epoch coordination remains separate; disjoint tuples alone do not prove
that complete application transactions are contention-free.

For `u` fulfilled constraints with total tuple arity `a`, reservation I/O is
proportional to changed claims and their bytes. Extraction also traverses declared
constraints, slots and bound references; optional omitted tuples still consume
work budget. It is not free or universally constant time. One physical claim key
uses `7 + 16 * arity` native bytes, before adapter namespace overhead; backend key
and transaction limits still apply. No-constraint models skip reconciliation.

Storage identity is `native-slice-kv-10`. Old stores require explicit recreation;
there is no compatibility migration. Complete native integrity checking independently
rebuilds every expected claim from source and compares exact key/holder inventory,
including missing and extra rows. Node `checkBackupStructure` checks framing,
holder contract and target existence; without a model catalog it does not prove
the declared slot semantics or complete claim inventory. Use native integrity
checking for that obligation.

See [checkpoint evidence](checkpoints/c2-reference-uniqueness.json) and
[executable cases](../tests/reference_uniqueness.rs). The ignored FoundationDB
test requires `NEXT_BASE_FDB_CLUSTER` and an explicit ignored-test run. It proves
the claim primitive's same-key conflict and disjoint-key independence on a real
adapter, without population or reader epochs. It is not multi-host performance
evidence or a full application concurrency campaign.

# Pure parent/child rules

Declare authored parent fields on each reference with
`reference.validation_fields = vec!["start", "end", "limit"]`, then implement the
ordinary compiled `Binding::validate_relationships(input, parents)` function.
Each `RelationInput` has the reference `slot`, target UUID and a `Map<String, Value>`
containing exactly the declared fields. No storage, allocator, owner/reader headers,
derived values or external service handle is supplied. Own authored input remains
native and typed. Optional absent references supply no entry. Polymorphic references
require every admitted target contract to declare the requested fields.

For example, a reservation can require `start <= at <= end` and `amount <= limit`.
These are ordinary comparisons, with the model defining units, numeric bindings
and strictness. Rules may compose any deterministic native functions over the given
inputs. They must be pure and have bounded cost; this is a compiled authoring
contract, not a sandbox for untrusted code. The engine budgets discovery and
projection work, not arbitrary work inside authored Rust functions.

The final mutation checks changed surviving sources and final incoming consumers
whose declared parent projections changed. It does not filter hidden children out
of integrity validation. Joint parent/child repairs and retargets use the final
graph, independent of command order. An unchanged union of consumed parent fields
skips incoming traversal, even if the parent's unrelated body changed. The union
is compiled once into immutable prepared-model metadata from the same declarations.

Predicates produce no data, so candidate discovery is one hop rather than a new
reactive scheduler. A grandparent input needs an explicit reference/declaration;
a rule must not acquire hidden dependencies. These declarations do not install
calculation routes or read published outputs. Generic order subscriptions remain
the separate C3 work described in the roadmap.

Independent native integrity checking enumerates every source and resolves its
declared parents from the complete source snapshot, then applies the same pure
authored rule. It does not trust the writer's candidate selection. Domain rejection
rolls back all staged state. Client diagnostics retain the error class but redact
rule details, which could contain hidden parent/child data. A semantic policy revision
and all declarations participate in prepared identity; old model identities require
explicit recreation. The physical codec remains `native-slice-kv-10`.

See [C2.P evidence](checkpoints/c2-relationship-predicates.json) and the
[scheduling example/tests](../tests/relationship_predicates.rs). This slice covers
own-input and declared immediate-parent rules; it does not infer reverse cardinality
requirements or provide an arbitrary global-constraint solver.
