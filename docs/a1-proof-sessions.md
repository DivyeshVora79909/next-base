# A1/A2 private delivered proof and recoverable sessions

Status: selected implementation contract, **planned and unaccepted**. The selected
profile below fixes policy choices for implementation and verification. This
document maps the required contract onto the current engine; it does not announce
authentication capability. Prerequisites are [A0 identities](a0-identity.md),
[E2/R0 delivery](e2-email.md) and the current transactional authority/JWT verifier.
The [email/phone scope](email-phone-authentication.md) remains authoritative.

## Selected implementation profile

The following choices are selected for implementation; acceptance remains pending.
Use dedicated `/auth/begin`, `/auth/consume` and `/auth/status` JSON routes with
4096-byte request bounds. Each operation carries a canonical UUID and a canonical
base64url 32-byte recovery secret. Return a generic accepted challenge/expiry or
invalid/unavailable result, without provider or identifier-existence diagnostics.
The existing owned blocking admission permit survives transport timeout. This
does not claim constant-time lookup or protection against observing actual delivery.

Coalesce a current, eligible, unexpired challenge without another delivery or a
new attempt budget. A challenge expires after 300 seconds and permits five new
consumption attempts. Every consume operation has its own replay receipt; the
successful decision pins a 900-second JWT lifetime. Begin and consume both resolve
their original receipts before new admission or attempts. Replays never renew times.

Use explicit same-tenant server policies keyed by channel, with an operator UUID
revision, exact credential UUID and expected owner/provider/account. Changing any
binding revokes new starts under its predecessor. Enabled state, incarnation,
use epoch, retained secret and current policy still gate every new start. Email
requires `email.send`; FakeSms requires `sms.send`. Policy authorization is server
authority, independent of the anonymous user's ordinary grants. Email auth shares
the existing provider/account `email.send` charged-start quota; SMS has its own
provider/account `sms.send` domain. All provider origins remain fixed loopback fake
adapters for this acceptance profile.

Use an external private proof keyring, separately domain-separated verifier,
recovery-fingerprint and payload-encryption keys, and a private Ed25519 signing-key
runtime. Persist ciphertext, keyed fingerprints and pinned issuance claims only.
Never persist an unkeyed hash of the six-digit message: the current public email
request hash would permit offline guessing. Authentication delivery hashes bind
its immutable encrypted request; providers echo that opaque binding.

Bound service retention to 256 challenges and 1536 original receipts, alongside
the existing 256-effect bound. Recovery lasts at most 24 hours and cannot outlive
the original proof/session disclosure fences. Admission charges all fresh begin
requests, including suppressed identifiers: at most three per keyed identifier
per 300 seconds and 32 per trusted transport peer per 60 seconds. Fresh consume
requests additionally have a 64-per-peer/60-second bound before proof assessment.
Only the socket peer supplies ingress identity; no forwarded client header is
trusted. Keep admission state bounded and reject uniformly at capacity. No online
retention compactor or silent eviction is selected. Reset must reject retained
proof state; explicit store recreation is the initial capacity recovery boundary.

Retain key IDs only while their original unexpired receipts/delivery/issuance
require them. Removed verification/signing keys revoke recovery instead of issuing
with a replacement key. Supported restore rotates mandatory session generation,
invalidating old proof and JWT disclosure, while preserving original effect facts
and read-only reconciliation. Restored delivery remains quarantined under E2;
recreation is the initial route to new proof in that restored service. Raw filesystem
rollback remains outside the supported restore protocol.

The selected profile proves an email **or phone** identity using a delivered
six-digit code, then issues a standard bounded EdDSA JWT. Both fake email and fake
phone paths are required. Password authentication is optional and deferred, as are
username, passkeys, OAuth, frontend and live provider acceptance. An existing
identity or successful provider send is not proof that the user received its code.

## Narrow anonymous operations

Add three fixed ordinary functions, with dedicated anonymous HTTP handlers rather
than an unauthenticated arbitrary `/rpc` dispatcher:

| Function | Strict input | Result boundary |
| --- | --- | --- |
| Begin | Client operation UUID, recovery secret, `{kind,value}` identifier | Generic accepted result, opaque challenge handle, fixed expiry |
| Consume | Client operation UUID, recovery secret, challenge handle, six-digit string | Generic invalid proof or committed session result |
| Status | Original operation UUID and recovery secret | Original operation outcome, subject to its recovery/disclosure fences |

The server's existing Store selects tenant, model and transaction domain. Reject
client namespace/database, tenant redirection, principal/identity UUID, recipient,
provider/credential, URL, template, expiry, signing key, claims or role inputs.
Normalization is exactly A0's canonicalizer. Schema-invalid requests can fail
before lookup; availability, eligibility and configured-policy failures cannot
disclose whether an otherwise valid identifier exists.

Recovery secrets and challenge handles are independent, cryptographically random
32-byte values encoded as canonical base64url. The client generates each operation's
recovery secret before sending. Store only a domain-separated keyed verifier of
the recovery secret; it is a bearer capability, not an ordinary record UUID. Begin
returns a server-generated handle without exposing the identity UUID. Persist any
replayable handle response encrypted. Never put recovery secrets, handles, codes or
JWTs in generic saved mutation plans, HTTP logs, error causes or observations.

An unknown transport result retains the original operation UUID, recovery secret
and exact input. Status reads do not create a new challenge, spend an attempt,
refresh a lifetime or send again. Reusing an operation UUID with different intent
or recovery evidence must not recover another operation. Existing authenticated
`operations.status` and its source Read policy are not an anonymous proof-recovery
API; use a separate private typed receipt domain in the same transaction adapter.

Use the existing HTTP body/admission/timeout/shutdown ownership rules. Give proof
requests a tighter body bound (proposed 4096 bytes); do not release blocking permits
merely because an HTTP wait times out. Anonymous operations return `Cache-Control:
no-store`. No response includes provider delivery status, identity availability,
principal revisions, remaining attempt count or private credential metadata.

## Begin linearization and generic responses

Within one write transaction:

1. Protect/read the original private receipt first. A matching completed begin
   returns its original encrypted response after recovery authorization. A replay
   cannot repeat admission, lookup side effects, code generation or delivery.
2. Charge bounded begin admission using the normalized identifier's keyed digest
   and trusted ingress identity, whether the identifier exists or not. Protect
   absence/range predicates and preserve complete-timestamp ties. Client headers
   cannot invent a source IP; use the configured trusted ingress boundary.
3. Resolve A0's private exact claim and current source/owner state. Eligibility is
   current same-tenant `User && active && login_access`. Load the authentication
   revision and credential epoch in this transaction. Zero identities and absent,
   disabled or ineligible users follow the same generic response shape.
4. Select only the fixed operator authentication-delivery policy for that channel,
   same tenant and configured credential. Pin its policy revision, provider,
   logical account, credential incarnation/use epoch/secret revision and purpose.
5. Create the challenge and private encrypted delivery intent, update the current
   challenge pointer, retain accepted credential material and write the safe
   original receipt. Commit once. Only the worker may perform provider I/O.

The proposed non-enumerating storage path also creates an opaque suppressed
challenge/receipt for unavailable identifiers or policies. Suppressed challenges
cannot validate a code and create no delivery execution. Their external handles,
expiry and error shapes match eligible challenges. Bounded capacity rejection must
apply before availability-specific work and use the same public response policy.
This is an observable-protocol guarantee; no constant-time database execution or
undetectable network delivery timing is claimed.

At most one live proof challenge is current for an identity lifetime. Proposed
duplicate-begin policy: coalesce a still-current unexpired challenge, sharing its
attempt budget and original delivery, instead of invalidating it or resending for
every new begin. Each begin operation still has its own private recovery receipt
and admission charge. A changed identity/user revision makes the old challenge
ineligible and permits a new one. No public resend operation is selected. Freeze
coalescing versus bounded replacement before implementation; tests must prove the
selected policy under concurrent begins and avoid duplicate delivery.

## Code, cryptography and persistent proof state

Generate an unbiased integer in `[0,1_000_000)` from an OS-backed CSPRNG with a
bounded rejection loop, and encode **six ASCII digits**, including leading zeros.
The proof parser accepts only that string shape, never an integer, Unicode digits,
whitespace or an alternative spelling. Random generation failure commits nothing.
Faker, test seeds, timestamps and source UUIDs are not authentication randomness.

Use HMAC-SHA256 (or the selected equivalent keyed hash), with a dedicated external
key ID and constant-time comparison, over a domain-separated encoding of the full
challenge binding and code. An unkeyed hash of six digits, including an operation
request digest containing the code, exposes an offline million-value search in a
backup. Keyed request fingerprints must protect both wrong and correct attempts.

The binding contains policy/format identity, store/tenant, session generation,
challenge UUID, user UUID, identity UUID/incarnation/revision, principal authentication
revision, credential epoch, channel, expiry and a fresh delivery nonce. The private
challenge stores the code verifier/key ID, attempt count, current/consumed state,
verified outcome and execution identity. Neither verifier nor binding is a public
source field. A suppressed challenge has an explicit private suppressed state;
do not invent a real user or manufacture graph authority for it.

Encrypt the entire delivery payload: recipient, OTP/message content and any private
binding needed by the adapter. Use the existing audited XChaCha20-Poly1305 library
with fresh nonces and AAD binding the immutable tenant/store/delivery/challenge
identity and decoder version. Ciphertext, keyed verifier and receipt-recovery keys
have distinct purposes; derive separate keys or configure separate keyrings, with
explicit domain separation. Keys are loaded into owned runtime state from external
private custody before transactions. No master key, raw code or signing PEM enters
KV, a public source, saved plan, status, Debug output or catalog fixture.

The proposed proof lifetime is 300 seconds and the successful session lifetime is
900 seconds, bounded by the configured JWT verifier maximum. All persisted times
use canonical exact integers and trusted server time; reject arithmetic overflow
or a regressing protected clock. `now < expires_at` is required. These are proposal
defaults, not constants inherited from the legacy implementation.

## Private delivery using the current worker

The present implementation has one `B::effect_action()`, stores `B::Input` inside
Execution, requires public action source/target contracts in `Prepared`, and assumes
an ordinary retained source for EmailSend. Its worker resolves requester Create and
Credential Use at start. A1 must change these assumptions explicitly; an anonymous
user cannot be made into an ordinary authorized EmailSend requester.

Proposed minimal compiled source is engine-private AuthDelivery contract 1004, with
`Services::Input::AuthDelivery` and a strict immutable ciphertext/binding DTO. It is
authored only by the trusted begin transaction, declared `Visibility::Engine`, and
excluded from public create/read/update/delete, population, owner access indexes,
receipts and effect-status/cancel methods. Its private source is retained as the
execution anchor. The Identity is a revocable proof binding, **not** a foreign-key
pin preventing deletion. Deleting the last identity remains legal.

Choose the action from an explicit compiled request enum: ordinary EmailSend or
AuthDelivery. Request, outcome, source visibility, authority, quota and status
selection must agree on that variant. Replace the single-action assumption only
where required; do not introduce client handler names, a serialized workflow,
runtime method registry or another task engine. Bind the new action/decoder and
visibility policy into prepared/storage/effect identities. Old checkpoint evidence
continues to refer to its original format.

An AuthDelivery dispatch has **server authentication authority**, selected by a
fixed configured policy. It does not require the login user to hold Identity CRUD,
EmailSend Create or Credential Use. It does not grant those actions to that user.
The policy explicitly authorizes server use of one same-tenant credential and
channel/purpose. Current enabled state, purpose, incarnation, use epoch and exact
retained secret must still match before each new start. Credential rotation keeps
the E2 accepted-secret policy; disabled/replaced credentials or revoked server-use
policy prevent new starts. Never search another account or credential as failover.

Challenge preflight runs in the claim/start transaction and checks current pointer,
user eligibility, identity linkage/incarnation/revision, authentication revision,
credential epoch, nonce, expiry and unconsumed attempts below five. It rechecks the
configured server-use policy and session generation. Missing/stale proof cancels unstarted
delivery without fetching a provider secret or decrypting the payload. Confirm the
exact committed start immediately before secret loading and network dispatch;
apply the existing maximum admission-to-call age, lease and expiry bounds.

Email delivery uses the independent Resend and Brevo fake protocols. Phone requires
a distinct bounded fake SMS protocol and typed request/outcome/credential binding;
do not rename email delivery or claim live Twilio/SMS support. The fake phone
process validates exact phone recipient, account, request hash and execution
identity, and has explicit submit/lookup failure controls. Only fake test custody
may expose the delivered code to the acceptance harness; no application debug/RPC
route returns it. That harness is not a production inbox.

Retain all E2 rules: commit provider-start before I/O; confirm unknown start ACK;
count physical starts, not claims; charge quota and start atomically; only the
CURRENT submit's definitive NotAccepted permits another submit; ambiguous calls
are reconciled; stale lease results cannot authorize retries. Current challenge
revocation blocks new sends but cannot erase a started send's remote facts.
Trusted observation of prior intent may load pinned material without minting a
new submission or resurrecting proof. Missing custody leaves safe recoverable work.

Delivery facts do **not** mark an identity verified. Authentication delivery has
explicit not-required domain application; code consumption is the proof mutation.
Remote success, failure and uncertain facts remain durable independently of proof
consumption. A late success after deletion/replacement/consumption updates only its
private delivery fact. Public EmailSend and effect-demo behavior remains covered.

Email physical submissions share the existing provider/account `email.send` quota
with ordinary email on that account. Distinguish server-use authorization purpose
from provider-quota grouping; a new auth purpose cannot bypass that shared budget.
Phone gets an explicit same-store provider/account SMS quota. Generalize the
bounded admission implementation by compiled purpose/provider only as needed, with
new explicit format identities and source-derived start checks. This is not a
cross-store or all-provider-HTTP quota claim.

## Five attempts, one use and atomic JWT decision

Consume first resolves the original private attempt receipt. A matching replay
returns its recorded rejection or issuance decision without spending another
attempt; a mismatched code under that operation identity rejects. Status alone
cannot turn an invalid attempt into a valid one. Use keyed fingerprints so neither
the stored receipt nor its conflict key contains an offline-checkable code hash.

For a new attempt, protect the challenge, current pointer, source state, user
authentication revision and current graph scope. Recheck session generation, expiry,
linkage, User/active/login state, epoch and unconsumed state before accepting proof.
Each otherwise eligible attempt atomically increments the shared attempt count,
with at most five total; a correct fifth attempt may succeed, a sixth cannot.
Suppressed, expired, already-consumed, replaced and invalid-code cases use the same
public invalid-proof shape. Concurrent attempts conflict on the challenge; the
engine must not silently replay an uncertain attempt as a new attempt.

On correct proof, atomically mark it consumed, set the exact current Identity's
verified revision/time, invalidate unstarted delivery, create an issuance decision
and store the original consumption receipt. Preserve source version/index/query
epoch semantics for any public verified-field change. Other challenge bindings
cannot inherit this proof. Source ownership/kind changes are not part of consume.

An issuance decision pins issuer/audience, subject, tenant, current credential epoch,
current session generation, `iat`, `nbf`, `exp`, signing key ID, claims
serialization/format and original attempt
identity. Sign only a committed decision. A failed/lost signature response leaves
recoverable committed proof; it does not rerun consumption or grant another TTL.
Add a narrow `issue_pinned_claims` function: existing `identity::issue` captures a
fresh current time and is unsuitable for recovery. Ed25519 plus fixed header and
claims bytes gives the same token for the same retained signing key and decision.
Never persist the plaintext token; replay can reconstruct it from pinned claims.

Recovery rechecks the original capability, current User eligibility, credential
epoch, factor incarnation/revision, session generation, token expiry and
signing-key policy. A revoked/expired decision returns a generic unavailable result;
it never silently issues with a new factor, epoch, key or expiry. Key rotation may
retain a retired key only for recovery of already committed unexpired decisions;
key revocation removes both verification and recovery signing authority. Bound and
document that retention. The server's previous verification-only/offline-issuer
deployment boundary must explicitly change when its owned runtime loads signing
keys; startup verifies the configured public/private key correspondence.

## Revocation, restore and retention

Implement A0's declared session policy: identity creation advances authentication
revision and fences pending proof; normalized no-op does neither. Replacement or
removal advances authentication revision and credential epoch in the same commit.
Disabling login advances both; reenabling cannot revive old proof/sessions. Current
active=false already denies service sessions, with an epoch advance required on
reactivation. Ordinary owner-only access/both-owner transfer rules are unchanged.

Add explicit operator-provisioned `login_access` to the existing protected principal
authority, with no new public principal CRUD. Preserve private authentication
revision against stale operator graph replacement. System epoch changes must
update the graph/current scope and graph-CAS fence consistently. Final authorization
must not undo an approved self factor-removal merely because that same commit
invalidates the actor's old token; authorize the ordinary commands/final graph,
then stage the exact internal revocation without granting any additional mutation.
Original mutation receipts still use current disclosure rules; deleting the last
factor does not promise anonymous recovery of arbitrary prior mutation receipts.

Restore must not revive consumed challenges, used attempt receipts, or sessions
revoked after the backup. E2 effect activation rotation/quarantine alone is
insufficient for epoch-only JWTs when older graph epochs are restored. The selected
A2 fix is a mandatory signed **session generation** sourced from RuntimeHeader:
initialize it randomly on store creation, preserve it across ordinary restart,
and rotate it during supported restore. Keep original store ID and receipt context
intact for existing operation recovery.

Authenticated ingress passes the verified generation into its internal Store
session. Each protected transaction compares it with the current RuntimeHeader
generation together with current principal epoch/authority. The operator
`identity.issue` function reads generation from its trusted store scope; clients
cannot select it. A2 pinned issuance carries that exact generation. Missing or
stale token generation fails closed; change the signed-claims identity explicitly.
Challenge/proof/recovery bindings also carry generation, so pre-restore proof and
issuance cannot become valid in the restored service.

Reconcile retained possibly-started delivery under its original intent and E2
quarantine rules; do not send it afresh or use late facts to verify a new generation.
New proof follows the declared restored-service activation policy. A raw filesystem
rollback or copy bypassing supported restore does not provide generation rotation
and is outside the supported lifecycle. No external monotonic-generation service
is selected, and ordinary restart does not require rotating signing keys.

Reuse existing bounded effect execution/fact/quota retention. Add bounded private
challenge, head, anonymous receipt and admission state; keep it in the same backend
transaction domain. Proposed initial limits are 256 retained challenges, five
attempts per challenge, 300-second proof expiry, 900-second session lifetime, and
24-hour original-request recovery retention. Receipt/byte limits and per-identifier/
trusted-ingress admission limits must be frozen together; anonymous begin cannot
allocate unbounded unique-key state. Service retention accounting is explicitly
bounded service state, never a restored ordinary-source population counter.

No automatic deletion may remove active quota charges, unresolved started delivery,
unexpired issuance decisions or their recovery/key requirements. If capacity is
full, reject new work uniformly. The first implementation may require a stopped
operator reset after all retention windows/uncertain work are resolved; it cannot
pretend eviction proves rollback. Pin restore/reset policy identities and test
expired, active and uncertain entries independently.

## Minimal implementation inventory and decisions to freeze

Proposed private typed state comprises Challenge, CurrentChallenge keyed by identity
lifetime, AnonymousReceipt keyed by operation/capability digest, PinnedIssuance,
the existing runtime session generation plus a protected authentication clock and
bounded admission points. PinnedIssuance can
live in the successful consumption receipt; avoid duplicate issuance authority.
AuthDelivery uses the existing execution/due/fact tables and retained credential
envelopes. Allocate new native tags or tables explicitly; do not repurpose A0 claim
or principal-revision encodings.

Required code seams are typed server configuration/key loading; dedicated anonymous
handlers; transaction-scoped begin/consume/status functions; private engine source
and request/action discrimination; trusted server credential use; challenge start
preflight; encrypted-payload transport preparation; fake SMS submit/lookup; pinned
claim signing; identity-change/graph login revocation; restore/reset fences; native
and Node independent inventories; and explicit Node proof functions that never
route secrets through savePlan. Existing redb/FDB adapter guarantees still apply.

The selected profile above resolves the policy choices. During implementation,
record the exact typed representations and format identities for these seams:

- Exact anonymous route/DTO names, recovery-capability derivation and generic
  unavailable/overload response behavior, including timing-leakage limits.
- Coalesced challenge and exact begin/consume admission key layouts, carrying the
  selected windows, limits, storage caps and retention.
- Server authentication policy revision, credential scope names and FakeSms
  provider/purpose declarations; credential owner changes must have an explicit
  server-use revocation effect rather than inheriting anonymous user accessibility.
- Exact private AuthDelivery/source/action representation and format identities,
  without weakening ordinary source visibility or public execution disclosure.
- Proof activation after supported restore, signing-key retirement/revocation,
  receipt retention/cleanup and all checks required before operator reactivation;
  mandatory RuntimeHeader/signed session-generation fencing above is selected.

## Independent acceptance

Start with a small model of challenge currentness, attempt count, consumption and
issuance identity driven by source facts and a deterministic clock. Compare command
permutations and races against that model, not writer-maintained caches. Verify:

- Absent, zero-identity, disabled/login-denied, wrong-tenant and missing-policy
  cases do not expose availability or create unauthorized delivery; begin replay
  and concurrent begins follow the frozen coalescing/replacement policy.
- Both fake email providers and the distinct fake phone path deliver through one
  worker protocol; an eligible user with no Identity CRUD/EmailSend Create/Credential
  Use can authenticate, while arbitrary server credential use is impossible.
- Leading-zero codes, five wrong attempts, correct fifth, rejected sixth, concurrent
  wrong attempts and concurrent correct one-use attempts; expiry at the exact bound;
  changed user revision, factor incarnation/revision, login state and epochs.
- Original begin/consume/status after definite abort, commit-with-lost-ACK, restart,
  signer failure and response loss; successful recovery preserves exact JWT bytes
  and claims times without another attempt, session lifetime or provider request.
- Provider unknown outcomes, CURRENT-submit-only retry, stale lease fencing,
  credential/policy revocation, quota exhaustion, cancelled/replaced proof and late
  remote facts; secret-load/send counters prove denied preflight does neither.
- Public source/list/order/effect/status/catalog/receipt/error/Debug/projection and
  saved-plan leakage negatives; raw backups contain ciphertext/keyed verifiers but
  no code, signing key, recovery secret or token. Fake harness code retrieval stays
  outside production routes and diagnostic output.
- Source-derived exact private inventories, owner/order indexes and cursor repair,
  injected physical-write rollback, conflicting authority changes, reopen, key
  rotation, full retention, protected empty admission reads, reset and restore
  quarantine/reactivation. Removing the last identity remains legal throughout.

A1 accepts proof/delivery only after its own checks. A2 additionally accepts current
session authority and recovery. Report real adapter/process boundaries and skipped
prerequisites explicitly; fake delivery and historical legacy source reading are
not live email/SMS evidence or a fresh distributed-capacity measurement.
