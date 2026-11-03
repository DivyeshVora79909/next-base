# Declared owner order streams and native reactive ranges

C3 adds explicit `Contract.access_indexes` declarations. Each has a positive
catalog-wide code, a local name and one to eight ordered components. A component
selects trusted `created_at` metadata or a declared scalar input field with an
exact integer, UTF-8 string, Boolean or UUID kind. Integers use canonical i128
decimal strings on the wire; tuples compare lexicographically, followed by
record UUID and membership slot. No timestamp coercion, tuple-prefix matching,
locale collation or floating-point comparison is inferred. Text is limited to
256 UTF-8 bytes per component and keys to 4,096 encoded bytes.

The store header fixes one tenant transaction namespace. Within it, an access
root is `(principal UUID, catalog-wide index code)` in the separate `AccessRoot`
key namespace; the catalog code identifies the resource and ordering. Access
members are `(source UUID, index code)` in `AccessNode`. Roots exist only while
nonempty. Domain roots keep their source UUID/declared slot identities. Access
trees carry unit business summaries and checked structural sizes, without a
tenant aggregate or population counter. The shared linked AVL implementation
maintains both namespaces in the same attempt and commit as source changes.

Opt-in is explicit. Bundled Calculation opts Account into created order, Entry
into created/effective order, and its private Output into created order. Quantity
opts Source into created/value order. Other resources have no new membership
unless declared. Private outputs remain unreadable through the public API.
Payload-only edits skip unchanged access projections; rekeys, deletes and
both-owner transfers repair the affected streams. Same-owner/no-input-change
commands preserve memberships and revision guards. Generated outputs follow
their producer's ownership and retain their own creation metadata when reused.

`created_at` is a server-observed UTC millisecond value, assigned on first source
creation and preserved while that record survives. Generated records get their
own first materialization time. It is not business effective time, a globally
monotonic clock, a unique identifier or commit order. UUID/slot ties provide the
total order. Clients cannot supply it as command metadata or a model field.

## Authorized reads

`records.order_page` accepts `{model, query, limit, visit_budget, cursor}`. The
query contains a public `contract`, its declared `index`, a `range` and optional
scalar `equals` predicate. The range has `lower`/`upper` values: null is unbounded,
otherwise `{included: key}` or `{excluded: key}`. Each key is a complete tagged
tuple, for example `[{kind: "integer", value: "10"}]`. Bounds apply to the whole
equal-key group before UUID/slot ties. Unknown indexes and wrong tuple kinds reject.

The engine resolves current Read authority and merges accessible owner streams
in one read transaction. Scope remains self, strict descendants and direct group
parents; tenant-parent records and unrelated owners are excluded. Filters run
after authorized candidate discovery. A page returns at most 32 records and
visits at most 128 candidates. Empty filtered pages may have a continuation.
There is no global visible rank, filtered count or cross-resource union API.

HMAC cursors bind store, model, tenant, actor, exact query, last complete order key
and owner/contract epochs plus authority revision. Transfers invalidate both
owner partitions. Payload updates conservatively invalidate the scope even when
the tree projection is unchanged. Cursors restart after relevant changes; pages
do not promise a snapshot retained across requests. Current authority also governs
receipt disclosure and root reads.

Trusted `PagePolicy` bounds traversal work, native point gets, loaded data bytes
and serialized output bytes (defaults: 50,000 work units, 4,096 gets, 4 MiB loads,
1 MiB response). Authority/epoch setup uses its existing bounded transaction path.
Policy exhaustion fails with `work_limit`; client candidate exhaustion returns a
continuation. Seek paths additionally reject cycles/depth 64. Services select
policy; the RPC accepts no budget-widening configuration.

## Native ranges and reactivity

`NativeRange<I::Key>` now supplies public root range reads, stored queries,
reverse subscription cuts, dependency graph comparisons and final-graph causal
discovery. Query addresses retain field/slot identity across roots. Old/new route
repair, selected-result behavior, zero-output dependencies and final-graph cycle
rules remain. Included/excluded cuts operate on native numeric, string or
composite order without passing through an i64 timestamp.

`RangeKey` can declare domain extrema/adjacency for empty-gap pruning. TimeKey
retains exact i64 discrete empty windows; arbitrary string/tuple domains use
conservative pruning with exact membership comparisons. Temporal `Before` and
`Latest` operations remain explicit adapters, as does the financial prefix
optimization. Public `Range` uses the family's declared key schema.

Codec `native-slice-kv-13` identifies the added source metadata/access namespaces
and generic reverse-route endpoint format. Prepared catalog identities also
change. Recreate older stores explicitly; no compatibility default or automatic
migration is supplied. Historical checkpoint fingerprints remain unchanged.

## Independent verification and limits

Native checking reconstructs expected access memberships from complete source
facts/catalog declarations, then verifies exact root/node inventories, ordering,
links, AVL balance, spans and structural counts independently of writer caches.
The Node backup checker separately checks both forests. Supply the matching
developer catalog to verify complete access source membership, including absence
of entire missing forests and private outputs. Missing catalog is explicitly
reported as `not_evaluated`, never complete access-source acceptance.

Fixtures cover 50/100/1,000 rows, exact native ranges, transfers, generated
ownership, filtering, cursors, payload-only updates, rollback, reopen/restore and
corrupt backups. Native reactive tests use independent source sums and separate
query identities across numeric, string and composite roots. Acceptance results
and measured local adapter coordination belong in the C3 checkpoint evidence.
Each opted-in root adds write coordination; scoped streams do not promise
unrestricted throughput or multi-host correctness from local measurements.

Managed UUIDs retain their first-materialization time in `Role.first_created_at`,
beyond the lifetime of a live output row. Initial inactive roles allocate no
output identity or timestamp. Later inactivity, reactivation, transfer and producer
retirement retain the first timestamp, including repeated settlements within one
Attempt. The role and live output timestamp must agree in independent checks;
first activation and failed reactivation remain atomic with the indexes and receipt.
This role shape is part of `native-slice-kv-14`; recreate older stores explicitly.
