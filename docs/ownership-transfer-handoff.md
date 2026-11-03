# Ownership transfers — authorized implementation handoff

Status: implemented by the [ownership-transfer checkpoint](checkpoints/c2-ownership-transfer.json).
The contract and audit notes below preserve the original handoff; measured legacy
behavior is recorded in [the completed comparison](ownership-transfer-legacy.md).
Baseline: `4a89967`, owner-only access, codec `native-slice-kv-12`.
The user explicitly authorizes ordinary ownership transfers. Previous immutability
was an implementation restriction, not a mathematical requirement. Current code
rejected owner updates at this baseline; the subsequent checkpoint implements them.

## Contract

- Require current Update permission and owner accessibility for BOTH old and new
  owners in the same transaction and tenant. Accessibility is self, strict
  descendants or direct group parents. Do not additionally require resource Read
  just because this is an Update; scope access and action permissions are distinct.
- Preserve early old-owner authorization before stale-version diagnostics; check
  a supplied destination owner without disclosing unknown/foreign principal state.
  Recheck final staged authority before publishing. No client-supplied trusted flag.
- Preserve Delete's narrower self/descendant rule, tenant isolation, active caller,
  current credential/authority checks, reference access and full atomic rollback.
- Prefer optional command metadata `owner` on Update, analogous to Create, outside
  model input `set`. Omitted means unchanged; present requires a canonical UUID,
  not null. Permit owner-only updates with empty input changes. Keep native and
  Node plan validation/serialization/request hashing consistent.
- Same-owner plus unchanged inputs should remain a true no-op. Advance revision,
  indexes and query guards only when the corresponding state actually changes.
- Ordinary transfer does not imply changing special identity/credential ownership:
  legacy login identities deliberately have immutable user linkage. Preserve or
  explicitly document such model-specific restrictions; do not weaken secret policy.

## Existing machinery and integration risks

`src/local.rs` already checks old and final records through `Scope::can_write`.
`src/mutation.rs` currently clones the previous record and changes only input on
Update. Extend this deliberately; keep the unscoped native settlement path self-only.

`security::update_owner_index` compares persisted and staged `(owner,contract,id)`;
`query::publish_epochs` visits both old/new owner partitions. These provide the
ordinary transfer hooks; prove them in actual commits rather than assuming coverage.
Root record access and receipt replay disclosure must follow current owner scope.

Managed output ownership must follow its producer even for an owner-only edit with
unchanged calculations. Inspect causal scheduling, output reuse and no-op elimination:
source ownership and all affected output ownership, versions and indexes must commit
together. Independent source checking already requires producer/output owner equality.
Do not transfer unrelated referenced records or business ancestors automatically.

`native_slice::reconcile_member` removes old tree membership and inserts new membership
when a declared root/order changes; equal root/order revalues its contribution. Declared
reference retargets also reconcile Incoming routes, uniqueness and relationship rules.
Business-tree ownership is anchored to a source UUID/root slot, not an authorization
principal. Changing ACL owner alone need not move an unrelated business tree. Any
membership explicitly derived from owner must move; preserve its declared semantics.
Do not add every possible index or claim planned chronological streams already exist.

External executions retain their actual requester, pinned intent and facts; changing
source owner must not rewrite historical requester identity or erase delivery evidence.
Re-evaluate current authority where existing worker/receipt contracts require it.

## Bounded legacy comparison

Reference repository: `/workspace/ReBase`, read-only inspiration. It is not the target.
`designs/rebase-system/developer-blueprint.md:62` describes ordinary owner/action scope.
`framework/authentication.surql:13-23` checks ownership in table permissions and
asserts access to the proposed owner, BUT its owner field explicitly has
`FOR update NONE`. It therefore does NOT demonstrate a permitted owner transfer.
Email/phone login identity fields at lines 79/120 are also explicitly READONLY.
Verify the actual generated ordinary-table clauses and their before/after behavior
before claiming legacy parity; this small audit did not establish that runtime behavior.

This audit was small, not a whole-system proof. Compare relevant legacy semantics by
obligation: tenant/type/existence, old/new authority, reverse references/deletion,
memberships/aggregates, exact arithmetic/causality, identity reservations, receipts and
effect lifecycle. Keep documented differences intentional; retain current group-only
parent scope and narrower Delete semantics rather than blindly copying legacy policies.

## Acceptance and continuation

Begin with focused witnesses: allowed self/descendant/group transfers; forbidden old
owner, forbidden destination and foreign tenant; malformed owner; immutable input
protection; old-owner-before-CAS rejection; owner-only update; true no-op; transfer back;
multi-command rollback and final-graph references. Verify exact old/new owner indexes,
both cursor partitions, current disclosure, unchanged record identity and root-summary
access, and owner-only producer transfer with unchanged managed values.

Independently check source-derived inventory, AVL membership/summary integrity and
managed provenance; exercise reopen, backup/restore and receipt replay after transfers.
Retain actual FoundationDB independent-write and conflicting-root controls. Run relevant
native/Node checks and required regression suites; record actual results and limitations.
Update current docs/model policy identity for the implemented semantics; historical
checkpoint fingerprints remain unchanged. Commit and push the verified checkpoint.

Fresh agent: read AGENTS.md, CONTEXT.md and this handoff, inspect current Git first,
then implement. Optimize for the actual environment. An API-based single-model agent
need not spawn subagents or inherit subscription-specific token/commit limits. No
backward-compatibility layer, new CLI/DSL, readers or global population counter.
