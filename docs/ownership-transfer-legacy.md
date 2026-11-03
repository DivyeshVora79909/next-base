# Ownership transfer: bounded legacy comparison

Audited on 2026-11-03 against the clean local ReBase checkout at
`/home/divyeshvora/javascript/node/projects/ReBase`, commit
[`1560ba176ff5e92b565e872701fcbea99132ea08`](https://github.com/DivyeshVora79909/ReBase/tree/1560ba176ff5e92b565e872701fcbea99132ea08).
`/workspace/ReBase` was absent. The reference repository was read-only throughout.
The native transfer checkpoint implements the explicitly requested policy; it does
not promise compatibility with every legacy rule.

## Ordinary tables differ from authentication tables

The actual ordinary-table generator
[`dev-tools/compiler/generators/security.js`](https://github.com/DivyeshVora79909/ReBase/blob/1560ba176ff5e92b565e872701fcbea99132ea08/dev-tools/compiler/generators/security.js#L61)
emits an Update action check and same-tenant owner access at table scope. Its owner
field permits updates when the value is unchanged, the old owner is the actor, or
the actor dominates the old owner:

```surql
FOR update WHERE 'note_update' IN $auth.permissions
    AND (tenant = $auth.tenant AND fn::rebase::can_access($auth, owned_by))
```

```surql
DEFINE FIELD OVERWRITE owned_by ON TABLE note
    TYPE record<rebase_user | rebase_group | rebase_tenant>
    ASSERT ($auth != NONE AND fn::rebase::can_access($auth, $value))
        OR record::exists($value)
    REFERENCE ON DELETE REJECT
    PERMISSIONS FOR select WHERE true FOR create WHERE true
    FOR update WHERE $value = $before OR $before = $auth
        OR fn::rebase::dominates($auth, $before);
```

The inspected `build/all-in-accounting/schema.surql:5131` currency table has those
same table/field clauses. Fresh generation for the runtime probe below used the
tracked compiler and framework, avoiding reliance on an old build artifact.

By contrast, `framework/authentication.surql:13-23` describes delivery configuration,
with owner field `FOR update NONE`. Email/phone identities additionally declare
`owned_by` `READONLY` at lines 79/120. Those are special records, not evidence that
ordinary owner transfers were forbidden. Next Base does not yet implement these
login/delivery credential contracts; ordinary transfer support does not authorize
mutable login identity linkage or relax planned secret-ingress policy.

## Fresh runtime witnesses

A disposable, loopback-only **SurrealDB 3.3.0 in-memory** process ran the current
framework and a freshly generated ordinary `note` table with one string `title`.
Each witness checked the committed row through a root connection, independently
of the record client's returned rows. All 11 witnesses passed. No application
profiles, credentials, existing database, or external provider were used.

The principal fixture had tenant A, shared group under A, Alice and Peer under the
shared group and A, Child under Alice, Stranger under A, and Foreign under tenant
B. Shared granted ordinary note CRUD. A separate group granted only `note_update`
to Writer. A fixture-only record signin selected the named user. Every ordinary
case began with `title='before'`, then the named actor submitted
`UPDATE note:<case> SET owned_by=<destination>,title='after'`.

| Case | Committed result |
| --- | --- |
| Alice: self to shared group | Owner and title changed |
| Alice: self to Child | Owner and title changed |
| Alice: Child to self | Owner and title changed |
| Peer: shared-group row to self | **Owner retained**, title changed; field permission filtered the transfer |
| Stranger: Alice row to self | No rows returned; owner and title retained |
| Alice: self to Stranger | Owner assertion rejected; owner and title retained |
| Alice: self to Foreign | Owner assertion rejected; owner and title retained |
| Alice: self to nonexistent user | Owner assertion rejected; owner and title retained |
| Writer: self to its direct group, without note Read | Owner and title changed; no rows returned |
| Root: email identity Alice to Peer | `READONLY` rejected; identity owner retained |
| Root: phone identity Alice to Peer | `READONLY` rejected; identity owner retained |

The identity fixtures used `authentication_email.address='fixture@example.invalid'`
and `authentication_phone.number='+14155550100'`. Their assertions verified stored
ownership after rejection. There was no delivery request.

For reproduction, generate the fixture using `loadMaterials` and `generateBundle`
from the pinned compiler, with the whole `framework/` plus this project schema:

```surql
DEFINE TABLE OVERWRITE note SCHEMAFULL;
DEFINE FIELD OVERWRITE title ON note TYPE string;
```

Apply through `dev-tools/temporal-tree/harness.js` using `start({engine:'memory'})`,
provision the principal graph above as root, and use the harness `client` with
record tokens from this disposable-only access definition:

```surql
DEFINE ACCESS fixture ON DATABASE TYPE RECORD
    SIGNIN type::record('rebase_user',$name)
    DURATION FOR SESSION 1h, FOR TOKEN 1h;
```

The measured generated bundle SHA-256 was
`36520dbea067c69be41b82e57a7a73b799120e8b97e628ce1cc4fb083065109a`.
The generator SHA-256 was
`348b5ea30458790dd7b78d435647b461f509cd63b6171018f0752d242679fd6a`.
These measurements belong to the pinned source and installed 3.3.0 runtime; the
older 3.2.0 update-permission report was inspected as context, not rerun or relabeled.

## Obligations retained by Next Base

| Obligation | Legacy mechanism inspected | Native boundary and executable witness |
| --- | --- | --- |
| Both owners and action authority | Table owner/action predicate plus narrower old-owner field predicate | `local.rs`, `access.rs`; `tests/ownership_transfer.rs` checks both owners, early authorization and Update without Read |
| Tenant/type/existence | Generated record types, owner-derived immutable tenant, existence assertions and `rebase_tenant_references` events in `generators/references.js` | Catalog binding and final-graph `mutation.rs` checks; `tests/final_graph_references.rs` |
| Reverse references and deletion | Native `REFERENCE ON DELETE` declarations and generated tree deletion guards | Incoming routes and protected final deletion checks; `tests/routes.rs`, `tests/final_graph_references.rs` |
| Membership and summaries | `compiler/temporal.surql` compares declared member root/key; owner edits trigger refresh in `generators/temporal.js` | Declared root/order reconciliation, not automatic business ancestor transfers; `tests/ownership_transfer.rs`, `tests/native_tree.rs` |
| Exact arithmetic and causality | Declared calculations and required-output reconciliation; source/role provenance and feedback checks | Native exact values, causal scheduler and independent `integrity.rs` source inventory; `tests/exact_values.rs`, `tests/issue_share.rs`, transfer output witness |
| Identity and uniqueness | Deterministic `[source,role]` output IDs with collision/provenance checks; schema uniqueness | Opaque reserved output IDs, retained retired roles, protected reference tuples; `causal.rs`, `tests/reference_uniqueness.rs`, `tests/storage_lifecycle.rs` |
| Receipt and effect lifecycle | `generators/effects.js` snapshots source metadata and guards attempt/lease/outcome fields | Pinned native requester/intent/facts, field-restricted application and original-operation recovery; `src/effect_tests.rs`, `src/effects/conformance.rs`, `tests/storage_lifecycle.rs` |
| Atomicity and concurrent guards | Legacy synchronous validation/refresh runs within database writes | One native publication boundary; transfer rollback witnesses and `src/storage/coordination_checks.rs` independent/conflicting-root controls |

The remaining rows are scoped **source comparisons**, not new legacy integration or
provider acceptance. Native acceptance counts and actual backend runs belong in the
transfer checkpoint evidence.

Intentional differences: Next Base permits an authorized direct-group member to
transfer the group's ordinary record when both owners are accessible. It rejects a
forbidden transfer atomically rather than silently retaining one field. Ordinary
scope excludes direct tenant-parent records (the legacy `parent_groups` includes
tenants). Read uses the record's owner only, without restoring legacy `read_by`
inference. Delete remains self/strict-descendant only. Native receipt, reservation,
cursor and effect contracts are preserved on their own evidence, not inferred from
similarly named legacy machinery.
