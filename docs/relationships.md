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
evidence or a full application concurrency campaign. Generic parent/child field
predicates and parent-edit revalidation remain the next C2 slice.
