# A0 protected email and phone identities

Status: concrete implementation contract, **planned and unaccepted**. This document
does not claim that identity CRUD, delivered-code proof or login sessions exist.
Implement A0 after [E2/R0](e2-email.md), followed by A1 proof and A2 sessions from
[email/phone authentication](email-phone-authentication.md). Preserve the current
owner-only policy and ordinary both-owner transfers for other resources.

## Source and protected state

Extend the prepared `services` model with Identity contract 1003. The sole authored
input is `{ "kind": "email" | "phone", "value": "..." }`. Owner is the ordinary
canonical UUID metadata, defaults to the actor on create, and must resolve to an
existing same-tenant **User** in the protected principal graph. Tenant and Group
owners are invalid. Disabled users may retain identities and have them managed by
an authorized strict ancestor; identity presence does not activate a user.

Identity kind, owner, tenant and trusted `created_at` are immutable. An update may
omit owner or repeat the same owner; any different owner rejects, even if both
owners are accessible. Neither update nor delete/recreate transfers verification.
Keep ordinary identity UUID/version CAS, owner listings, owner/created order,
query epochs and operation receipts. Declare the source/schema/index metadata in
the prepared model; do not add an independent Node schema authority.

The engine authors a private random incarnation UUID and `identity_revision = 1`
on each new lifetime. Public authorized projections may expose identity revision,
`verified_revision` and `verified_at`; clients cannot set any of them. Verification
is current exactly when the non-null verified revision equals identity revision.
Both verification fields are absent together until a successful A1 proof. Private
incarnation is included in later proof/delivery bindings and is absent from public
records, plans, receipts and diagnostic snapshots. System state must be protected
before generic serialization, not removed by a final response redaction pass.

An Identity has no ordinary business dependency on its owner record: the owner is
a protected graph principal. Principal deletion is not introduced by A0; existing
graph administration disables retained principals. Label and priority fields from
the legacy design are not part of this selected minimal identity contract.

## Canonical values and exact claims

Select an ASCII identity profile. Email trims surrounding ASCII spaces, lowercases
the **entire** address, then uses `email::normalize_address`'s single-mailbox syntax:
at most 254 bytes, a nonempty dot-atom local part of at most 64 bytes, no leading,
trailing or consecutive dots, and nonempty domain labels of at most 63 bytes with
no leading/trailing hyphen. Reject display names, comments, lists, controls (even
at the edges), non-ASCII input and malformed addresses. This is syntax validation,
not a deliverability claim. Pin this behavior in the prepared policy identity and
Rust/Node boundary tests. Whole-address lowercase deliberately differs from E2
message intent, which preserves recipient local-part case. Authentication lookup
and mutation call the same canonicalizer; neither guesses a different form.

Phone trims surrounding ASCII spaces and then must match `^\+[1-9][0-9]{7,14}$`:
8–15 ASCII digits after the plus, with a nonzero first digit. Reject internal
spaces, punctuation, extensions, non-ASCII digits and guessed country prefixes.

Use one private exact dictionary keyed by `(kind, normalized UTF-8 value)` within
the existing fixed tenant store namespace. Values identify the live source and its
incarnation. Equal identifiers are legal in different tenant stores; email and
phone have distinct key domains. No global ordered identity tree, UUID coercion
of strings or population counter is needed. The current catalog's reference-tuple
uniqueness implementation is not a string identity dictionary.

Protect old claims and new-key absence in the source write transaction. Derive
dictionary deltas from the complete final graph: release all changed/deleted old
claims, reject duplicate final claims, then acquire new claims. Thus an authorized
two-record value swap succeeds in either command order, while two final sources
claiming the same normalized key fail atomically. Do not expose another claimant's
UUID, owner, value or version in a duplicate error. Anonymous lookup is never a
public dictionary read, ordered page, count, or identifier-existence endpoint.

## Management authorization and recent authentication

Every read or mutation requires a current, active actor, the same tenant and the
ordinary Identity action grant. Reads require the owner to be self or a strict
descendant. This agrees with ordinary scope for User-owned records; a direct group
parent cannot own an Identity. Admin grants never widen this owner scope.

Create, update and delete additionally require one of:

- Self management: owner equals actor and verified JWT issuance is at most 600
  seconds old at the mutation's transaction authorization check.
- Management of a strict descendant: the current protected authority scope proves
  strict descent. This path does not require the manager's token to be recent.

Recency is `iat <= now && now - iat <= 600`, with checked arithmetic and a trusted
server clock. An `iat` JSON field, request header supplied by the client, token
decoding without signature verification, or a newly opened store session cannot
establish recency. The current JWT verifier checks `iat`, but HTTP ingress currently
constructs `Store::session(actor, epoch)` and discards it. A0 must pass verified
issuance time through an explicit internal authenticated-session seam. Existing
native sessions without issuance evidence cannot silently satisfy self recency.
Tests use an explicit trusted clock/session seam; operator provisioning remains an
explicit control-plane action rather than a public bypass.

Generic `records.mutate`, batch commands, owner-only edits and native public write
entrypoints must enforce the same rule. A special endpoint alone is insufficient.
Authorize current old-owner scope and immutable-owner rules before CAS diagnostics;
validate final source owners against the final protected graph before publication.
An expired self token cannot manufacture a refresh by copying itself into a plan.
Definite rejection rolls back every source, system-state, dictionary and index write.

Original operation recovery precedes executing another mutation, while current
receipt disclosure retains its normal Read/owner and credential-epoch checks.
Unknown commit outcome keeps the original operation identity; it does not permit
submitting a fresh identity change or repeating revision/epoch increments.

## Lifetime and revision transitions

| Transition | Identity state | Principal proof/session boundary |
| --- | --- | --- |
| Create | Fresh incarnation; revision 1; unverified | Advance private authentication revision |
| Normalize to the same value | Preserve revision, verification and incarnation | No proof or session change; retain protected reads/receipt behavior |
| Replace normalized value | Increment revision; clear verification; keep incarnation | Advance authentication revision; revoke prior sessions through the credential epoch by A2 |
| Delete, including last identity | Release claim and remove live system state | Advance authentication revision; revoke prior sessions through the credential epoch by A2 |
| Recreate a previously used source UUID | New incarnation; revision 1; unverified | New create; old proofs and delivery facts cannot bind to it |
| A1 successful verification | Set verified revision/time for the exact current lifetime | Does not itself rotate the credential epoch or invalidate its own successful proof |

Revision arithmetic is checked; overflow rejects the whole transaction. The
principal authentication revision is private and monotonic, not a factor count or
an authenticated boolean. It must not be copied from an operator's stale graph
snapshot over newer identity activity. A0 must establish its protected storage and
atomic identity-change updates; A1 consumes it as a fence. Multiple changes in one
atomic final mutation may advance it once per affected principal, provided every
pending proof is fenced and original-operation replay advances it zero times.

A1 adds current challenges and private delivery. A value change or deletion fences
them through identity incarnation/revision and principal authentication revision;
unstarted delivery is cancelled or fails preflight. Do not pin Identity as an
undeletable ordinary E2 status anchor: last-identity deletion must remain possible.
An already started external send can still produce a durable remote fact; that fact
cannot restore a deleted/replaced identity or verify a new lifetime. Other pending
proofs for the same user fail after its authentication revision changes.

The selected A2 session policy is explicit: factor replacement/removal and disabling
login advance credential epoch, so previously issued tokens fail current authority
checks immediately after commit. Adding an identity fences pending challenges but
does not by itself revoke existing sessions. Graph `active` disablement already
denies current sessions; reactivation retains the existing required epoch advance.
A0 acceptance must state whether these A2 transitions are already implemented or
remain unaccepted; verification fields alone are not session revocation.

Add `login_access` to the protected User authentication eligibility contract by
A1/A2, with an explicit operator-provisioned value and a scope projection from the
same authority. Login requires `User && active && login_access`. False-to-true must
not revive old challenges or old sessions. Administrative graph changes and proof
consumption must conflict on the relevant protected authority state. Do not add
ordinary principal CRUD or let identity creation assign a role, reparent a user,
grant login access or attach a principal to the full-permission tenant root.

## Required A1/A2 delivery and issuance continuation

The selected deployable authentication mode is delivered six-digit email/phone
codes. The plan calls password authentication optional; it is explicitly deferred
for this profile, together with username, passkeys, OAuth and frontend flows.
Phone identity storage alone is not phone proof or accepted phone login.

A1 must add a bounded fake phone/SMS delivery adapter and a typed private delivery
seam alongside the E2 email adapters. Operator configuration selects explicit
same-tenant email/phone delivery policy and credential bindings; callers cannot
choose namespace/database, recipient, target identity UUID, provider URL or account.
Use the existing lease/start/observe/fact machinery, with challenge-specific
preflight and system authority, rather than a parallel task engine.

Challenge state and encrypted server-authored delivery intent commit together.
Never store OTP text in public EmailSend, an authored source, generic saved plan,
receipt, status, logs or Debug output. A six-digit code has low entropy: use a
domain-separated keyed verifier with external key custody and constant-time
comparison, plus an independently encrypted payload for delivery. Include the
tenant, principal, identity incarnation/revision, authentication revision, expiry
and fresh delivery nonce in the private binding. Configure bounded challenge expiry,
rate policies, retention and key rotation explicitly before implementation acceptance.

Provide narrow anonymous challenge begin/consume routes. The current `/rpc` route
requires JWT authentication; adding an exception for arbitrary RPC methods is not
the intended boundary. Unavailable identity/policy responses remain generic. Retain
at most one current challenge per identity and five atomic consumption attempts;
expiry, concurrent wrong attempts, successful one-use races and replacement all
need independent counterexamples. A retry of the same original consumption attempt
after unknown commit acknowledgement cannot spend another attempt or issue another
session lifetime. Request/operation binding and recovery evidence must be private.

A2 integrates successful proof with current principal eligibility, linkage and
epoch checks and a declared signing-key runtime. The present server is a verifier
with an offline issuer; server-side signing changes that deployment/key-custody
boundary explicitly. Persist successful issuance identity and pinned claims/time
before returning a token. Original issuance recovery must return the same claims,
`iat`, `exp`, key ID and epoch, never call the existing fresh-time `identity::issue`
as a replay. Current revocation and removed signing keys can prevent disclosure;
they do not authorize silently reissuing or extending the session. Define bounded
recovery retention, key-rotation/revocation and restore behavior before A2 acceptance.

## Independent acceptance obligations

A0 acceptance requires executable source-derived checks, not this document or a
mock claiming a real transaction passed. Derive expected dictionary entries from
live Identity source facts, validate exact system-state inventory and public
projection exclusions, and reject orphan/missing/duplicate/wrong-incarnation keys.
No writer-maintained index or population count may be the expected-result oracle.

Required witnesses cover:

- Equivalent email/phone normalization, malformed boundary inputs, duplicate claims,
  same identifier in separate tenants, and kind separation.
- Two-way and longer final-graph swaps in command permutations; concurrent duplicate
  acquisition, release/reacquire and protected absence conflicts.
- Fresh/stale/future/missing trusted `iat`, the exact 600-second boundary, current
  self/strict-descendant authorization, action denial, hidden owners, wrong tenant,
  group/tenant owners and immutable-owner rejection before stale-CAS disclosure.
- Create/replace/no-op/delete/recreate transitions, last-identity deletion, source
  UUID ABA, revision overflow, private-field forgery and principal revision fencing.
- Exact owner/order indexes and cursor invalidation, retained no-op conflict guards,
  original-operation recovery, injected physical-write rollback, reopen and
  backup/restore with independent checking after each relevant transition.
- Authority revocation versus identity writes on the accepted transactional backend,
  without automatic retry concealing the conflict. Independent principals must not
  gain a shared source population counter or global identity mutation fence.

A1/A2 require their own durable delivery, five-attempt/one-use races, disabled and
zero-identity login negatives, removed/replaced-factor and epoch revocation checks,
secret-leak checks and original issuance recovery. A0 does not accept those flows.
Node developer functions must use the prepared catalog, preserve exact operation
identity under uncertainty, and keep secret proof inputs outside generic saved
plans. Fresh release verification must identify actual adapters and process bounds;
fake email/SMS evidence does not establish live delivery.

## Bounded legacy comparison

Read-only reference inspected on 2026-11-03: clean local ReBase checkout at
`1560ba176ff5e92b565e872701fcbea99132ea08`. Files read were
`framework/authentication.surql`, `framework/auth.surql`,
`framework/authentication-indexes.surql`, and
`designs/rebase-system/tenant-authentication.md`. This is source comparison, not a
fresh SurrealDB probe or acceptance of historical mock results. The separately
documented historical `270d875` object was unavailable in that local checkout and
was not represented as inspected.

Retained obligations are immutable User ownership, tenant/kind normalized uniqueness,
self ten-minute recency or strict-descendant management, system verification state,
revision fencing, zero identities/last deletion, one-use/five-attempt code proof and
atomic encrypted delivery intent. Next Base uses a private exact KV dictionary
instead of the legacy private tenant AVL and omits the legacy reader field. Legacy
authentication revision fences pending work; the declared Next Base credential-epoch
policy adds explicit immediate session revocation. No ordinary owner-transfer rule,
legacy identity label/priority, username, passkey or OAuth machinery is imported by
this contract. The bounded ASCII mailbox/space-trimming profile is selected for
Next Base and does not claim complete parity with SurrealDB's email validator.
