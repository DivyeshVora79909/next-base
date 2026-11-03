# Planned email and phone authentication

Protected Identity CRUD is accepted as [A0](a0-identity.md). Delivered proof and
session issuance remain [A1/A2 work](a1-proof-sessions.md). Next Base currently
verifies signed JWTs through [identity.rs](../src/identity.rs) and resolves current authority
and credential epochs in transactions through [security.rs](../src/security.rs).
There are no email/phone login flows to migrate. This plan covers email and phone only.
Provider API credentials in [E1](server-execution.md) are separate records from login identities.

## Authority and identity records

The current ordinary-record contract is owner-only; C2.O is accepted. There
is no reader field or inferred reader. Read/Create/Update require same tenant, action grant,
and owner accessibility through self, strict descendants, or direct group parents; direct
tenant-parent records are excluded from ordinary data scope. Tenant-grant inheritance remains
a separate legacy rule. Delete permits self or strict descendants only. Admin actions do not
widen ordinary scope. Create may name an accessible owner (default actor). Ordinary
Update may transfer ownership with Update permission and access to both old and new
owners. The special immutable identity linkage below remains a separate planned rule.

Current bulk graph replacement remains an operator control plane. This plan does not claim
ordinary user/group CRUD parity is implemented. Future principal management must enforce
its specific self/dominance, operation-permission and bounded role-assignment checks.
Provisioning or invitations require explicit policy: creating an identity must not grant an
administrator role or attach a user directly to the full-permission tenant root.

Each email/phone identity is a standalone source record with immutable user owner and
immutable tenant derived from that owner. Email is trimmed, lowercased and validated.
Phone is trimmed and must match `^\+[1-9][0-9]{7,14}$` (8–15 digits); do not guess a country.
Use a private transactional exact uniqueness key `(tenant, kind, normalized_value)`.
An implicit TenantStore prefix may supply tenant isolation. The same email or phone is
allowed in different tenants; kinds have separate domains. Protect absence reads and claim
changes in the same transaction as source mutations. An ordered tenant aggregation tree is
optional for ordered queries, not required for exact identity lookup. Tenant principals and
the authorization DAG remain control-plane concepts independent of this dictionary.

Identity management is sensitive: preserve legacy self access or strict dominating management,
with recent authentication for self mutations (legacy requires issuance within ten minutes).
Verification fields are system-written. Identity revision starts at one; changing normalized
content increments it and clears verified revision/time and outstanding challenges. Verification
is current only when verified revision equals identity revision. Principal authentication
revision fences challenges; integrate credential epoch changes with session revocation.

## Proof and session boundary

Authentication requires an active user with `login_access` and proof through a currently
linked email/phone identity. Zero identities may exist, but cannot authenticate through these
methods. This does not impose a last-identity deletion prohibition. Presence alone is not proof.
Legacy modes are optional password plus currently verified email/phone, or a delivered code
that can verify an initially unverified identity. No username-only method is introduced.

Expose protected identity CRUD, challenge begin/consume, and JWT session issuance through
ordinary functions and typed inputs. Bind challenge to tenant, user, identity, both revisions,
expiry and delivery nonce. Hash the six-digit code; allow at most five atomic attempts and
exactly one successful consumption. Success verifies the current identity revision. Recheck
active/login state and current linkage before issuing a JWT with tenant, subject and credential
epoch. Removal, replacement or disablement must invalidate affected proof and apply the
declared session-revocation policy through current epochs, not only wait for JWT expiry.

Keep hashes, delivery secrets and tokens private. Commit durable delivery intent with challenge
state; perform provider I/O outside database transactions through typed adapters and the existing
worker machinery. Unknown delivery outcomes require recovery/idempotency policy, not a claim
of exactly-once delivery. Reuse issuer/transport and durable intent infrastructure; add no global
versioned method registry. [Server execution](server-execution.md) describes these boundaries.

## Acceptance milestones and provenance

- **A0 — records, accepted:** protected identity management, tenant/kind normalization and uniqueness;
  independently test duplicate claims, cross-tenant reuse, immutable ownership and revisions.
- **A1 — proof:** durable delivery and challenge consumption; test expiry, five-attempt races,
  one-use races, changed identities, revision fencing and secret nondisclosure.
- **A2 — sessions:** integrate proof with JWT issuance/current authority; test disabled users,
  zero identities, removed factors, epoch revocation, tenant negatives and uncertain outcomes.

Legacy provenance: `/ReBase/framework/auth.surql`, `authentication.surql`,
`authentication-indexes.surql`, `access.surql`, and `designs/rebase-system/tenant-authentication.md`
are reference source paths in the separate ReBase repository. Its contract explicitly permits
zero identities. Its `designs/index-analytics/records.surql` separately declares creation/effective
time indexes; Next Base [index mathematics](index-mathematics.md) keeps those independent
orders explicit. C3 access/order index work remains planned; ordinary owner principals do not
imply every corresponding index root already exists.
