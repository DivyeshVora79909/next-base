# A1/A2 private delivered proof and recoverable sessions

Implemented and verified in the [A1/A2 checkpoint](checkpoints/a1-proof-sessions.json). [A0 identities](a0-identity.md) and [E2/R0 delivery](e2-email.md)
remain prerequisites. This document describes current code, not live-provider,
multi-host or production-capacity acceptance. E3 objects, E5 full-pipeline recovery
and fresh committed-source release/bootstrap verification remain outstanding.

## Public operations and developer functions

The Services backend supplies dedicated `POST /auth/begin`, `/auth/consume` and
`/auth/status` JSON routes. Each has a 4096-byte body limit and `Cache-Control:
no-store`. Existing blocking admission, timeout and shutdown ownership applies:
a transport timeout does not release a still-running transaction's permit or prove
rollback. Socket peer identity supplies admission scope; forwarded headers do not.
These routes do not expose an anonymous arbitrary `/rpc` dispatcher.

| Operation | Strict input | Result |
| --- | --- | --- |
| Begin | `operation_id`, `recovery_secret`, `identifier:{kind,value}` | Generic `accepted`, opaque `challenge`, original `expires_at` |
| Consume | `operation_id`, `recovery_secret`, `challenge`, six ASCII-digit `code` | `invalid_proof` or committed `authenticated` token |
| Status | Original `operation_id`, `recovery_secret` | Original result under current recovery/disclosure fences |

UUIDs and 32-byte base64url secrets must be canonical. Identifier normalization is
exactly A0's ASCII email/E164 phone normalizer. Client tenant, principal, recipient,
provider, credential, URL, template, expiry, signing key and claim overrides reject.
The store fixes tenant and model. Invalid request syntax may reject before lookup;
otherwise availability and eligibility failures share generic responses. This
is an observable response/coalescing contract, not constant-time lookup or a claim
that actual delivery cannot be observed.

The Node exports `prepareAuthentication({endpoint,identifier,timeoutMs})` and
`prepareCodeProof({endpoint,challenge,code,timeoutMs})` return frozen operation
objects with `operationId`, `execute()` and `status()`. Their exact original input,
operation UUID and recovery secret live in closures. Repeated execution/status uses
that evidence; a new explicit code-proof object is a new attempt. Unknown results
must recover the original object. `toJSON()` rejects; these objects never enter
`savePlan`, generic mutation/status handling or inspect output. Returned handles
and tokens are transient sensitive results. These convenience objects do not
persist client evidence across client-process loss. Endpoints require HTTPS or
loopback HTTP; redirects are rejected.

## Begin, admission and coalescing

A single transaction resolves the original private receipt before charging new
admission. Matching replay returns its original result; differing recovery evidence
or intent cannot recover it. A fresh accepted begin charges the normalized
identifier and trusted peer, whether the identifier is eligible or suppressed:

- Three begins per keyed identifier in `(now-300s, now]`.
- Thirty-two begins per socket peer in `(now-60s, now]`.
- Sixty-four consumes per socket peer in `(now-60s, now]` before proof assessment.

Complete timestamp ties count separately. Protected time cannot regress. State
retains at most 256 challenges, 1536 original receipts and 3072 current admission
points; no silent eviction or online retention compactor exists. Before identifier
lookup, the same capacity check applies to all begins: challenge/receipt capacity,
effect quarantine, 256 retained effects, 64 unresolved effects, 1024 facts including
reservations, and at least 128 KiB headroom within the eight-MiB effect service
budget. Capacity rejection commits no partial charge or intent. These are bounded
service retention controls; there is no ordinary-source population counter.

Every unexpired, unconsumed identifier challenge coalesces to the same handle and
original 300-second expiry, **including suppressed identifiers**. A bounded scan
of retained challenges uses the keyed identifier digest. Each new begin still has
its own receipt and admission charge; it grants no new attempts or delivery.
Changed factors, login state or policy invalidate proof but retain that identifier's
old handle until its original expiry. Becoming eligible does not trigger immediate
resend through a previously suppressed challenge. Consumed or expired challenges
permit a fresh challenge, subject to all admission/capacity checks. There is no
public resend operation.

Eligible means a current same-tenant User with `active && login_access`, a matching
A0 claim/source lifetime, and a valid configured channel policy/credential. An
eligible new challenge atomically creates encrypted private delivery intent and
retains the exact accepted credential revision. A suppressed challenge has no user
binding, source or execution and can never validate a code. Neither path invents
ordinary user grants. The User need not have Identity CRUD, EmailSend Create or
Credential Use to prove their identity.

## Configuration and private custody

`ServerConfig.authentication` is optional and valid only for secured Services. Its
strict fields are `keyring`, `policies`, `active_signing_key`, `signing_keys`.
`keyring` is an absolute private-file path. `signing_keys` maps explicit key IDs to
absolute private Ed25519 PEM paths; the active ID selects new issuance. The existing
`identity` verifier configuration supplies issuer/audience/public keys and must
allow the fixed 900-second session lifetime. Startup verifies corresponding public
and private signing keys. Credentials and fake delivery runtime remain separately
configured through E1/E2 `credentials` and `email` settings.
The email worker config carries distinct loopback `resend_origin`, `brevo_origin`,
optional `sms_origin`, `mode`, quota `policies` and optional `probe_directory`.
The phone path requires its separate SMS origin; no public request selects one.

The proof keyring is `{format:"next-base-auth-proof-keyring-1",current,keys}`;
`keys` contains one to four distinct `{key_id,key}` entries with canonical
base64url 32-byte material. Signing configuration permits up to sixteen keys.
Custody requires bounded, singly linked Unix regular files without symlinks or
group/other access, with file identity checked across open/read. Keys and PEMs stay
in owned private runtime state, outside KV, catalog fixtures and generic plans.

Each of the one or two `policies` binds `kind`, operator UUID `revision`, exact
`credential`, expected credential `owner`, `provider`, `account`, and `sender`.
Email binds Resend or Brevo plus a canonical sender; phone binds `fake_sms` and
`sender:null`. Policy revision or binding changes revoke new starts under the old
policy. Server authorization is explicit and does not inherit the anonymous
user's grants. Current credential enabled state, incarnation, use epoch, purpose
and owner still gate each new physical start. Accepted secret revisions remain
pinned across rotation; no credential/provider failover is inferred.

The initial admission-key ID remains pinned until explicit store recreation, so
rotation cannot reset identifier/peer quotas or handle lookup. An active proof key
may rotate while retaining that admission key and keys needed for unexpired
recovery/delivery. Removed proof keys make their recovery unavailable. Retired
signing keys serve existing issuance only when explicitly retained in both signing
and verifier configuration; removing either revokes recovery. Nothing silently
selects a replacement key or extends an old lifetime.

## Cryptography and durable state

An OS CSPRNG with bounded rejection produces unbiased codes in `[0,1000000)`,
formatted as six ASCII digits including leading zeros. HMAC-SHA256 domain
separation protects code verification, recovery, request fingerprints, handle and
identifier/peer lookup. Private digests are canonical 32-byte base64url values;
there is no offline-guessable unkeyed hash of a code, including wrong attempts.
The verifier binding includes format, tenant/store, session generation, challenge,
nonce, user/factor lifetime and revisions, credential epoch, policy and exact times.

XChaCha20-Poly1305 encrypts replayable handle responses and the complete delivery
payload, with fresh 24-byte nonces and separate derived-purpose keys/AAD. Envelope
fields are `key_id`, `nonce`, `ciphertext`; plaintext is bounded to 4096 bytes.
Delivery request hashes bind immutable ciphertext, not the six-digit plaintext.
Neither raw code, signing key, recovery secret nor JWT is persisted.

| Private table | Key and retained value |
| --- | --- |
| `auth_challenges` | Challenge UUID; lifetime/binding, identifier/handle digests, predecessor, encrypted response, verifier, attempts and consumed state |
| `auth_heads` | Identity incarnation UUID to latest challenge UUID; exact predecessor chains derive the inventory |
| `auth_handles` | Handle digest to challenge UUID; derived from retained challenges |
| `auth_receipts` | Operation UUID; keyed recovery/fingerprint, generation/time, immutable admission charges and begin/invalid/issued decision |
| `auth_runtime` | `state` with protected clock/capacity/current admission plus at most two channel-policy rows |

Successful issuance lives in its original receipt, not a second issuance registry.
Invalid receipts explicitly distinguish spent attempts from ineligible/unspent
rejections. Native and Node checkers derive counts, handles, heads, consumption,
current admission and verified factor state from receipts and source facts. The
Node checker reports that cryptographic authentication is not evaluated without
private keys; its inspect-compatible projection omits private delivery records and
private factor incarnations. Complete operator backups retain private ciphertext
and keyed state and require private custody.

`Services::Input::AuthDelivery` is compiled engine-private contract/action **1004**,
with `challenge`, `generation`, `payload`, `expires_at`; action version is
`auth-delivery-1`. It is a retained execution anchor, excluded from public CRUD,
owner/access indexes, population, ordinary receipts, effect status/cancel and
public catalogs. The factor is a revocable proof binding, not a foreign-key pin
that prevents deletion. Explicit compiled action selection distinguishes ordinary
EmailSend from AuthDelivery; no serialized workflow or dynamic handler registry
was introduced.

Current identities are native codec `native-slice-kv-16`, store
`rebase-store-11`, effect codec `rebase-effects-6`, proof state `auth-proof-1`,
crypto `next-base-auth-proof-crypto-1`, and signed claims
`rebase-eddsa-tenant-subject-epoch-generation-2`. Services behavior is
`services-private-auth-delivery-pinned-server-authority-4`; prepared identities
include the changed declarations. Recreate earlier stores explicitly. Historical
checkpoint evidence retains its original formats and checksums.

## Worker delivery, consume and session recovery

AuthDelivery uses the existing owned worker and retained execution/fact protocol.
Resend and Brevo use distinct bounded loopback fake email protocols; FakeSms is a
separate typed fake SMS submit/lookup protocol. This is not live SMS/Twilio or live
email-provider support. Only fake test custody exposes delivered codes to the
acceptance harness; application routes never return them.

Claim/start rechecks current challenge, generation, factor lifetime/revisions,
User eligibility/epoch and server policy. Denied preflight cannot load a secret or
send. Physical start, quota and exact start marker commit before I/O; unknown start
ACK requires confirmation. Dispatch retains E2 lease/maximum-age fencing, bounded
calls and no transport retry. Only the current submit's definitive NotAccepted
permits another charged physical start. Uncertain work requires original read-only
reconciliation; an empty lookup does not permit resubmission. Email authentication
shares ordinary email's provider/account `email.send` quota. SMS uses `sms.send`.
Delivery facts have `not_required` domain application and never verify an identity.

Consume resolves its original receipt before a new attempt. Current, eligible,
unexpired proof permits five total atomic attempts; a correct fifth can succeed,
a sixth cannot. Wrong, suppressed, consumed, expired or revoked proof returns the
same invalid shape. Success atomically consumes the challenge, sets the exact
current Identity verified revision/time, repairs applicable indexes/epochs, and
stores a pinned issuance decision. Concurrent attempts conflict on the challenge.
All changes and the original receipt share one transaction.

The decision pins issuer, audience, tenant, subject, credential epoch, mandatory
session generation, `iat == nbf`, `exp == iat + 900`, and signing key. Signing occurs
only after commit. `issue_pinned_claims` reconstructs the same Ed25519 token bytes;
signer/response loss does not spend another attempt or refresh times. Recovery
requires the original secret and current factor/User/epoch/generation/key policy,
with token expiry and a maximum 24-hour original-receipt window. Ordinary
`operations.status` is not anonymous proof recovery.

## Revocation and supported lifecycle

Identity creation advances private authentication revision, fencing pending proof;
normalized no-ops do not. Replacement/removal additionally advances the credential
epoch once per affected User in the same commit. Both `login_access` toggles
advance epoch and authentication revision, preserving a larger supplied operator
epoch. Reactivation still requires an increased epoch. Missing/regressed history
and overflow reject atomically. Self factor removal is authorized first, then
revokes the old session without undoing that successful mutation. Last-factor
deletion remains legal. Owner-only access, both-owner transfers on ordinary records,
final-graph authorization and atomic integrity remain unchanged.

Every authenticated HTTP transaction checks the signed generation against the
protected RuntimeHeader and current authority/epoch. Operator `identity.issue`
reads generation from the store; clients cannot override it. Missing or stale
JWT generation fails closed. The native `Store::session` remains an explicitly
trusted embedding seam, not unsigned HTTP authorization.

Creation initializes a random generation; restart and receipt archive preserve it.
Supported restore rotates it while preserving store ID, cursor key and original
operation context. Old proofs/JWTs cannot revive when a backup restores old epochs.
Effects remain quarantined: original possibly-started work may reconcile, but new
begins remain unavailable in that restored service. Explicit recreation is the
initial route to fresh proof. Raw filesystem rollback bypasses this protocol and
is outside the guarantee. Reset rejects retained proof state; there is no online
compactor or reset that discards it.

## Acceptance boundary

Acceptance passed 442 Rust all-target tests with no ignored tests, all 253 Node
checks with no skips on Node 26.12.0 and the freshly built default host, formatting
and default/FoundationDB all-target Clippy with warnings denied. Both real HTTP
workflows (Resend + SMS, Brevo + SMS) pass delivery, suppressed/coalesced begins,
fifth/sixth attempts, exact issuance recovery, backup, process restart and restore.
Focused corruption tests independently reject impossible receipt lifetimes,
generations, admission histories and post-consumption attempts.

Actual FoundationDB 7.3.77, one local process/host, passed ten proof cases: concurrent
email/phone begins, four consume races, factor/login revocation races, and physical
begin/consume rollback plus durable ACK loss. Every one of the eleven begin writes
and six consume writes was aborted independently, with final-abort, original
receipt recovery and reopen checks. Redb passed the same cases as explicitly
sequential controls. Full coordination/lifecycle/application/effects/predicates/
credentials/email/identity suites also passed on both adapters. Ordinary email,
owner and ordered indexes/cursors, both-owner transfers and no population counter
remain covered. Evidence preserves selected-adapter limits and exact source/log
fingerprints; SurrealKV and live providers were not rerun for this checkpoint.

Password mode, username/passkeys/OAuth, C5 live invalidations, E4 recurrence,
frontend, live providers and TiKV remain deferred. The implemented slice does not
complete E3, E5 or fresh release/bootstrap verification.
