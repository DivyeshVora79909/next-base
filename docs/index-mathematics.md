# Ordered indexes: laws, declarations and limits

M0 is a planning and mathematical-witness checkpoint, not index implementation.
The structure is a linked augmented AVL: an ordered search tree with cached monoid
summaries. With structural counts it is also an order-statistic tree. It is not
a new B-tree page layout. See [rate admission](rate-admission.md) for quota policy
and [roadmap](roadmap.md) for implementation acceptance.

## One declaration, independent memberships

A resource declares each membership's root/scope, total ordering, contribution,
summary algebra, dependencies, query capabilities and optional invariant. Reuse
these declarations in the prepared catalog; do not infer indexes from table names.
Integrity and analytics indexes share mechanics, but have different predicates.
An index with no business aggregate uses the unit summary; it still needs count
metadata for rank, selection and bounded row reads.

One issue can join its invoice's effective-time integrity tree and created-time
analytics tree, plus explicitly selected tenant-global trees. These are separate
occurrences with independent keys/contributions. A value edit affects every changed
projection, not automatically every tree. A count-only created index need not be
rewritten when its root/key/contribution are unchanged by an amount edit.

Current membership address is `(record UUID, slot)`; each address belongs to one
validated root. Different memberships need distinct stable slots. Conceptually
identify an occurrence by root, record and slot; do not assume the root is already
part of the persisted node key. Two slots in the same root count twice. Distinct
records, occurrences, non-null values and accepted jobs are different counts.

Keys can be non-time values: current `NativeIndex::Key: Ord` and the Words test
family already demonstrate this. Numeric progress, sequence, name and composite
keys are possible; each needs exact comparison and tie/bound semantics. Native
order is not the lexicographic order of serialized decimal strings. A composite
prefix needs explicit range construction, not a naive string prefix/offset.

**Selected target:** structural subtree size is mandatory and independent of the
optional business summary: `size(empty)=0`, `size(node)=1+size(left)+size(right)`.
Rotations and the independent checker maintain it. Root counts must agree with
their nodes. C1.1 implements structural size and supplies a String-keyed
`CountOnly` family with unit business summary. The current owner-only format is `native-slice-kv-12`; stores with earlier identities
require explicit recreation.
Keep a separate business count only if it has different meaning or is needed by
the algebra; avoid two conflicting authorities for the same cardinality.

## Proposed resource-scoped authorized indexes

Logical orders, including deterministic cross-resource ties, use owner scope:

- Owned: `(resource_kind, tenant, owner, declared_order, record_id, membership_slot)`.

Every participating resource explicitly registers definitions; `declared_order` may
be creation, effective time or another native total order. ModelRecord has an owner
only, and Reference has no reader flag. Reads merge streams for owners accessible to
the caller under the ordinary owner-graph rules. A root read grants explicitly declared
public summary data only. FULL summaries may include hidden contributors, while leaf,
body and ID reads still require access to those records.

Each tree root is anchored by `(root_record_uuid, declared_slot)`; each member address is
`(record_uuid, membership_slot)`. Members order by the declared total order followed by
stable record/slot ties. The root anchor and its full summary stay attached to the source
record and root slot. The AVL `head` is only the current structural top node and can change
on rotations without moving the root or its summary. One parent and one child root
participation still permits composites: use a tuple of root grouping and sort fields. Do
not infer all ancestors or all permutations.

Caller-supplied IDs may use any supported canonical UUID format; the API does not require
UUIDv7 or server-issued IDs. UUIDv7 is a recommendation for millisecond-prefix locality
plus randomness. It does not provide trusted `created_at` metadata or commit order. The
current native model does not automatically author server creation metadata; add a
separate trusted `created_at` field when that business fact is required. It remains
distinct from `effective_at`. A nanoepoch alone is not unique across servers.

Tenant is a strict namespace. No central tenant aggregate or counter is implicit; use an
explicit business root when required. These access indexes are planned, not implemented.
Use one declared unit and stable catalog resource identity, not mutable display names.

Use one stream when one root already has the requested order. K-way merge is for
multiple sorted owner/resource/root streams: heap heads use the same total order
under one snapshot, then advance the smallest. Initialization is at least O(K),
with seek work per stream; merging k candidates adds O(k log K) heap work.
Cache each stream's head within the request, advance only the popped stream and
batch independent initialization/refills under explicit budgets. Scope discovery
and K initial seeks are not free; merge does not dominate every tenant-wide scan.
Bind cursor to query, full ordering key and current scope/revision semantics.
A shared last-key cursor can suffice when every stream can reseek and duplicate/
filter rules are defined; per-stream cursor state is not mandatory by default.

An index key grants no permission by itself. Action grants, current owner accessibility,
private records and residual predicates still affect eligibility.
Count/rank of raw memberships is not count/rank of visible filtered rows. Bound
stream setup, candidate visits, bytes and output; do not promise logarithmic rank
selection over an arbitrary authorized union. Count-only root revision does not
detect payload-only edits: preserve projection/authority cursor-change detection.

## The algebra obligation

For ordered adjacent sequences A and B, require a summary map H and combine ⊗:

`H([])=e`, `H(A ++ B)=H(A) ⊗ H(B)`, `e ⊗ s=s=s ⊗ e`,
`(a ⊗ b) ⊗ c = a ⊗ (b ⊗ c)` on the admitted ordered numeric domain.

This is a monoid homomorphism. AVL rotations change parentheses, not occurrence
order; an independent ordered fold must equal every cached subtree summary.
Associativity permits regrouping. Commutativity additionally permits reordering.
Both commutative summaries (sum/count/min/max) and order-sensitive summaries
(prefix extrema, composition) are useful and supported by this design.

Summary size, lift/combine cost, key comparison and arithmetic all need bounds.
Associativity alone does not make a growing set or concatenated string constant-size.
Floating rounding can make regroupings differ; do not silently substitute approximate
arithmetic/sketches for exact integrity rules. Checked fixed-width operations are
partial outside their admitted domain. A representable final sum is insufficient:
scalar `[MAX,1,-1]` may overflow in an intermediate grouping. Actual financial
summaries also retain prefix maxima and reject this example in both groupings.
Choose bounds covering every intermediate segment, sufficient exact width, or an
explicit shape-independent rejection policy. Big integers add variable arithmetic cost.

| Problem | Bounded representation / rule | Qualification |
| --- | --- | --- |
| Count | Structural size; singleton 1, combine + | Counts occurrences |
| Sum, min, max | Sum; optional min/max with empty identity | Empty is not min=0 |
| Linear forms | Vector of exact field sums or projected weighted sums | Fixed finite dimension |
| Mean | `(count,sum)` then `sum/count` | Empty undefined; not mean of means |
| Weighted mean | `(sum(weights),sum(weight*value))` | Zero/negative-weight policy |
| Variance | `(n,s=sum(x),q=sum(x*x))` | Squares/products/division need bounds |
| Running floor/ceiling | Sum plus min/max prefix | Explicit order and tie policy |
| Maximum contiguous sum | `(sum,best_prefix,best_suffix,best_subarray)` | Empty/nonempty convention |
| Sequential transforms | Fixed affine/matrix/function-composition state | Fixed dimension; arithmetic bounds |
| Finite-state sequence rules | Transition map over a fixed finite state set | State-set size part of cost |
| Rank/median/quantile | Structural count in the relevant value order | Not arbitrary time-window value median |
| Finite histogram | One count per declared bin | O(bins) bytes/combine |
| Arbitrary exact distinct | Requires overlap/set information | Not count-only or constant-size in general |

These are representability rules, not a list of installed native families.
Current source implements exact financial and other declared families; variance,
matrix/state summaries and future index declarations need their own lawful binding
and oracle tests. See `src/index.rs`, `src/algebra.rs`, `src/indexes/` and `src/index_tests.rs`.

## Linear predicates and quantifiers

For fixed coefficients a_j and field totals S_j, a final predicate such as
`b + sum(a_j*S_j) > 0` is a pure evaluation over a vector-sum summary. Coefficients
need not be 1: negatives, larger integers and exact rational weights are possible
with declared arithmetic bounds. A constant b added once differs from a per-row
constant, which contributes b*count. Changing final-query coefficients needs no
rebuild if the retained field totals suffice.

This validates an assignment; it does not solve for unknown values or generate
a feasible dataset. Linear optimization/SAT needs separate algorithms or caller
hooks. Nonlinear projections can also be useful: sum of per-row `x*y` is additive;
that does not make arbitrary cross-record nonlinear constraints cheap.

Specify the quantified invariant separately: final total, every prefix, one range,
every moving window, or all affected dependency records. A nonnegative final total
does not prove a nonnegative running balance. For amounts with sum s and min-prefix p,
`(sA,pA) ⊗ (sB,pB) = (sA+sB,min(pA,sA+pB))`; identity `(0,0)` includes empty prefix.
Starting balance b is never negative iff `b+p >= 0`. Strict inequalities and empty
roots need explicit policy. Current financial algebra also distinguishes raw
occurrence prefixes from complete equal-time groups (`complete_min/complete_max`).

For a fixed linear form, lift it per occurrence and cache its prefix extrema.
Individual fields' prefix minima cannot simply be combined linearly. Arbitrary
runtime coefficients for all-prefix predicates can require recomputation or richer,
potentially growing summaries even when final totals are cheap.

Travel examples: sum leg distances or order progress by route sequence/distance,
then validate declared reward thresholds. Ordering by per-leg length changes the
meaning of a prefix. Deriving distances between successive GPS samples requires
explicit neighbour dependencies. A scalar order is not a general spatial index,
nearest-neighbour solver, fraud check or exactly-once reward issuer; those require
appropriate domain rules, structures and execution/uniqueness guards.

## Range cover, dependencies and costs

Cross-record order predicates, such as
`parent.created_at <= child.effective_at <= parent.effective_at`, are ordinary
final-state comparisons. Each model chooses strict/inclusive bounds, units and
which fields it compares. No monoid or interval index is needed for this direct
predicate. Register every parent field read as a direct dependency so changing
the parent revalidates its dependents as well as changing/retargeting the child.
Joint parent/child repairs must use the same staged final graph; invalid final
state rejects the entire transaction. Local JSON Schema alone cannot enforce a
referenced-record comparison. Bespoke reactive bindings can express such rules;
a general catalog relation-predicate hook and creation metadata remain C2/C3 work.

A contiguous range is covered by maximal fully contained subtrees plus boundary
nodes. "Maximal" refers to coverage, not taking a numeric maximum. Combine their
summaries in key order. With fixed-size summaries and AVL height h=O(log n), one
range aggregate and one membership edit have O(h) logical tree work. Known-root
cached summary needs O(1) nodes. No inverse is required: after an edit recompute
ancestors from their current children; min/max generally cannot subtract old state.

Enumeration takes O(h+k) tree work for k raw occurrences. Count-pruned BFS batches
independent frontiers and then hydration; it reduces dependent waits, not output
bytes or all work to O(log n). Finite concurrency C needs capacity waves too.
Keep all node and record reads on one snapshot; a batch is not automatically one
wire RTT. Production batch traversal remains C1 work.

For changed memberships, path work is approximately the sum of their heights,
not one logarithm for all indexes. Two added global memberships add two occurrence
updates on relevant creates/deletes, not one update per composite field. Projection
comparison, dependencies r, disclosure, guards, bytes and conflicts add work.
Avoid universal r*m*log(n) claims for the entire system or a numeric network bound.

Direct dependencies name record/field inputs. Range dependencies additionally name
root/order/bounds. A changed point stabs subscriber intervals that include its old
or new position; final-state recomputation must cover removals and insertions.
Interval stabbing discovers affected dependents; it is not the aggregate itself,
quota admission, or a clock. Bound time subscriptions still need wakes when time
passes without a stored change. Fixed-W quota representations are derived in
[rate admission](rate-admission.md).

Current `routes::stab` uses upper-cut ordering and min-lower pruning. Charge actual
visited nodes plus matches; worst case may visit all registrations. Its output-
sensitive O(log n+k) bound is not established by AVL balance alone. Nonlocal
cascades and all-window validation require their own discovery/cost proof.
Current Query/routing bounds are TimeRange/TimeBound even though internal ordered
reads accept generic keys. Non-time subscriber cuts and public range schemas need
deliberate C3 generalization; do not claim generic reactive orders implemented today.

## Executable witnesses and remaining gates

`tests/mathematical_contracts.rs` checks actual financial summary regrouping against
an independent source oracle, signed weighted projection, noncommutativity/ties,
overflow rejection and the point/endpoint sliding-window equivalence. Rate witnesses
prove mathematics, not production admission, concurrency or provider delivery.

Remaining implementation includes batch traversal, global index/root/metadata
contracts, protected relationship and
admission checks, typed credentials/two-provider execution, object lifecycle,
adaptive population and selected live/deployment acceptance. Retention, backup/key
custody, receipt recovery, revocation, pagination budgets, telemetry and format
identities remain obligations; an algebra catalog does not eliminate them.
