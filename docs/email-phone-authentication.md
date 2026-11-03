# Email and phone authentication

Protected Identity CRUD is accepted as [A0](a0-identity.md). Delivered proof and
session issuance are implemented in [A1/A2](a1-proof-sessions.md), with final
checkpoint acceptance pending. That document specifies the current configuration,
private state, limits, developer functions and recovery contract. Provider API
Credentials remain separate records from login identities. Email and phone are
the selected authentication channels; password mode remains deferred.

## Authority and identity records

Ordinary records have an owner only. Read/Create/Update require same tenant, the
action grant, and accessibility through self, strict descendants or direct group
parents; direct tenant-parent records are excluded. Tenant-grant inheritance is a
separate legacy rule. Delete permits self or strict descendants. Admin actions do
not widen ordinary scope. Create may name an accessible owner (default actor).
Ordinary Update transfers require Update plus access to both old and new owners,
before CAS diagnostics and again in the final graph.

Identity has immutable User ownership, tenant and kind. Its special immutable
linkage does not weaken ordinary transfer authorization. Bulk graph replacement
remains an operator control plane; ordinary principal CRUD, invitations and role
assignment are not supplied by authentication. `login_access` is an explicit User
flag; non-Users must have it false. Provisioning a factor does not grant roles or
attach its owner to an administrator tenant root.

Each email/phone identity is a standalone source record. Email is trimmed,
lowercased and validated as ASCII; phone is trimmed and must match
`^\+[1-9][0-9]{7,14}$` (8–15 digits), with no guessed country. A private exact
transactional dictionary indexes `(tenant,kind,normalized_value)`; the TenantStore
prefix supplies tenant isolation. The same value may appear in another tenant.
Absence/claim changes publish with source, owner/order indexes and receipts.
Ordered access is independently declared, not inferred from tenant membership.

Self management requires verified JWT issuance within 600 seconds; strict
ancestor managers retain ordinary action/scope checks. Verification fields are
system-written. Normalized content replacement increments identity revision and
clears verification. Private incarnation distinguishes delete/recreate. Successful
proof verifies only the exact current incarnation/revision; private receipts are
the independent verification oracle. Creating an identity advances authentication
revision without revoking sessions; normalized no-ops do neither. Replacement or
removal also advances credential epoch, once per affected User per transaction.
Last-factor deletion remains legal.

## Delivered proof and sessions

A current same-tenant `User && active && login_access` may prove an email or phone
factor using six delivered ASCII digits. No Identity CRUD, EmailSend Create or
Credential Use grant is required for login. An existing or verified identity and a
successful provider delivery are not proof of code possession.

Dedicated begin/consume/status routes use canonical operation UUIDs and independent
32-byte recovery capabilities. Begins return generic opaque challenges for eligible
and suppressed identifiers. Both coalesce unexpired/unconsumed challenges to the
same handle, expiry and five-attempt budget. Changed eligibility or policy makes
old proof unusable but does not disclose that change through a new handle or
immediate resend; a fresh challenge waits the original 300-second expiry unless
the old one was consumed. Bounded identifier/peer admission and common prelookup
capacity checks apply to all identifiers. The contract does not claim constant-time
lookup or unobservable actual delivery.

Codes, request fingerprints and recovery evidence use domain-separated keyed
HMAC-SHA256; unkeyed six-digit hashes are forbidden, including wrong attempts.
XChaCha20-Poly1305 encrypts complete delivery payloads and replayable handle
responses. Private keys, plaintext codes, recovery secrets and JWTs are not stored
in KV, logs, catalogs or generic mutation plans. Node preparation functions retain
original evidence in closures and reject JSON serialization.

The same transaction stages the private challenge, encrypted engine-only
AuthDelivery, pinned credential revision and original receipt. An explicit server
policy authorizes the exact channel/credential/account; it does not grant user
CRUD. The owned worker performs provider I/O after committed start/quota intent.
Distinct loopback Resend, Brevo and FakeSms protocols provide the selected fake
acceptance paths. Uncertain delivery requires original reconciliation; an empty
lookup does not prove rollback or permit resubmission. Delivery alone never marks
a factor verified.

Consume first resolves its original receipt. Five atomic attempts and one success
are allowed; a correct fifth may succeed, a sixth cannot. Success atomically
verifies the current factor and pins a 900-second EdDSA decision with tenant,
subject, epoch, session generation and exact issuance times/key. Signing follows
commit. Original recovery reconstructs the same token without another attempt or
TTL. Revoked/expired factors, Users, generations or keys cannot recover issuance.

Both `login_access` toggles advance credential epoch and authentication revision;
reenabling cannot revive old sessions. Active reactivation still requires a larger
epoch. Approved self removal publishes before invalidating the old token. Every
HTTP transaction checks current authority/epoch and the signed generation.
Supported restore rotates that generation while preserving original operation
context, preventing old backup epochs from reviving JWTs or proof. Restored effects
remain quarantined and may reconcile prior intent; fresh proof requires explicit
recreation. Restart/archive preserve generation. Reset rejects retained proof;
there is no online compactor. Raw filesystem rollback is outside this lifecycle.

## Acceptance and provenance

A0 and [A1/A2](checkpoints/a1-proof-sessions.json) are accepted in their bounded
scopes. Verification covers suppressed coalescing, all three fake delivery protocols,
attempt/one-use races, original recovery, revocation, key custody, source-derived
indexes/private inventories, rollback and restore. Preserve ordinary owner-only/both-owner checks, atomic
integrity and the absence of a population counter. E3 objects, E5 full-pipeline
recovery and fresh release/bootstrap verification remain outstanding. Password,
C5 invalidations, E4 recurrence, frontend, live providers and TiKV remain deferred.

Legacy source provenance is `/ReBase/framework/auth.surql`,
`authentication.surql`, `authentication-indexes.surql`, `access.surql`, and
`designs/rebase-system/tenant-authentication.md` in the separate ReBase repository.
Retained obligations include self/recent management, strict ancestor management,
zero identities, normalized exact claims, revision fencing, five attempts and
one use. Next Base keeps the durable receipt, ciphertext, transaction and restore
contracts above; legacy names and delivery success are not acceptance evidence.
Legacy `designs/index-analytics/records.surql` separately declares creation and
effective-time indexes. Current C3 access/order indexes preserve those independent
orders; an owner principal does not itself create an index root.

The A1/A2 source-only comparison reread clean ReBase commit
`1560ba176ff5e92b565e872701fcbea99132ea08`. Its `authentication.surql:150`
declares one private challenge per identity, at most five attempts and ciphertext
delivery; `access.surql:78` conditionally claims an attempt and consumption before
verification. Next Base's literal attempt oracle, FDB original-transaction races
and HTTP email/SMS witnesses exercise those obligations. Next Base uses a keyed
code verifier and strict `now < expires_at`, replacing legacy Argon2 code comparison
and inclusive expiry. Retained predecessor/receipt history replaces challenge
deletion on factor changes; factor incarnation/revision, epoch and session
generation fence use and recovery. No legacy runtime or live provider was executed
for this comparison, and optional password/OAuth behavior is not a parity claim.
