# E1 credentials and bounded grants

Status: implemented and verified; see [checkpoint evidence](checkpoints/e1-credentials.json). This fixes
the E1 choices left open by [server execution](server-execution.md). Implement E1
after C4, then reuse its types in E2/R0, A0–A2 and E3. Local deterministic fake
adapters supply acceptance; live account credentials are not a prerequisite.

## Scope and transaction domain

Add one explicitly selected compiled `services` binding. Its first public source
contract is `Credential` (code 1001); E2 adds EmailSend sources, A0 identity
sources and E3 object sources to this same binding and transaction domain.
Existing calculation models retain their current contracts. Applications can
explicitly compose the shared credential declarations and ordinary helpers into
their own compiled binding; a separate service store does not make writes in
another model/store atomic.

Credential metadata is an ordinary `ModelRecord`: tenant, owner, trusted creation
time, version and typed input. Use the same source lifecycle, owner access,
references, public indexes, query epochs, CAS, receipts and rollback path. Keep
encrypted secret envelopes in the engine-owned `native_kv` credential-secret
namespace (tag 17), keyed by credential UUID. E1 retains exactly the current
revision in its envelope; E2 must explicitly change the format identity to retain
multiple revisions for accepted jobs. This is private payload storage for the declared Credential,
not a second public resource schema or authority registry. The prepared catalog
owns both the public input/projection and the private envelope/operation schemas.

E1 does not introduce OAuth refresh, arbitrary provider URLs, an execution DSL,
provider failover, delegated signing, or a generic credential-decryption RPC.
The selected Resend/Brevo contract uses API keys. Object credential payloads and
object grants are added with E3's selected adapter rather than guessed in E1.

## Types and wire shapes

All objects deny unknown fields. UUIDs are canonical lowercase text. Versions use
the existing native UUID revision. Integer epochs/revisions use canonical u64
decimal strings where they may exceed JSON's safe integer range.

Credential public authored input:

```json
{
  "label": "Transactional mail",
  "provider": "resend",
  "account": "primary-mail",
  "enabled": true,
  "scopes": ["email.send"]
}
```

`provider` is `resend` or `brevo`. `account` is an immutable logical remote account
identifier: 1–128 ASCII letters, digits, `.`, `_`, `:`, `-`; it is not an endpoint
or secret. `label` is at most 128 UTF-8 bytes. `scopes` is a sorted distinct subset
of the selected provider's declared purposes; E1's only purpose is `email.send`.
Neither provider nor account can change on an existing Credential. A different
remote account requires another credential ID and explicit new job intent.

The system-written public state is `{ has_secret, secret_revision, use_epoch }`.
Persist an additional internal UUID `incarnation` in the source derived metadata,
assigned from the first creation revision and retained on all edits. It is not a
published field. Grants pin it so deleting and recreating the same credential UUID
cannot restore an old authorization even when revision and epoch numbers repeat.
`secret_revision` is null until submission of a secret, otherwise a positive u64;
`use_epoch` starts at zero. These are derived metadata, never caller-controlled
fields. They must agree with the private secret row. Generic record CRUD may
create a disabled Credential without a secret, change its label/enabled/scopes,
transfer its owner or delete it under the ordinary action rules. Enabling without
a secret rejects. The specialized secret write below also supports atomic
metadata-and-secret creation, so callers do not need an intermediate empty row.

`ApiKeySecret` is a distinct non-serializable/non-Debug runtime type produced from
the decrypted strict payload `{ "api_key": "..." }`. The key is 1–512 UTF-8 bytes,
without ASCII control characters. Both providers use that one private payload
schema, identified as `provider-api-key-1`. The actual value never becomes
`B::Input`, ordinary `serde_json::Value` record fields, a receipt or a diagnostic.
Deserialize inside the private ingress module and immediately move sensitive
buffers into zeroizing storage. Do not print parse failures or secret lengths in
client errors; all cryptographic failures use fixed safe errors.

Public methods are an explicit compiled allowlist:

| Method | Input and result |
| --- | --- |
| `credentials.ingress_key` | `{model}` → current public ingress descriptor, after current session authorization; no private key or credential payload is loaded |
| `credentials.write_secret` | Existing mutation envelope `{model,context,operation_id}`, `id`, nullable `if_version`, optional canonical `owner`, complete Credential metadata and `sealed_secret`; → ordinary committed receipt with ID/version and metadata projection |
| `email.authorize` | Typed request described below, selected BYOC/platform binding and TTL; → bounded purpose-specific use grant; this sends no email and does not create a job |

`if_version: null` means create-only and protects record absence. A UUID means
update with CAS. Ownership checks run before version diagnostics. Existing provider
and account must match before any secret decrypt. `owner` omission retains the
existing owner on update and defaults to actor on create. Null owner rejects.
Every other metadata field is present, avoiding PATCH ambiguity in the sealed
operation. Generic record updates still use their existing set/unset form.

Ordinary `operations.status` recovers the specialized write by the exact original
operation ID/context. Extend the existing receipt's typed result alternatives if
necessary; do not create a second receipt store. A successful response contains
no ingress capsule, ciphertext, private key identifier or plaintext. A repeat
whose receipt already exists recovers that receipt before trying to decrypt the
capsule again, subject to current receipt disclosure rules.

## Secret-safe ingress and saved intent

Use RFC 9180 HPKE base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
AES-256-GCM. Use an audited HPKE implementation on each side, pin exact released
versions in Cargo/npm lockfiles and execute interoperable known-answer and
cross-runtime tests. Do not implement HPKE arithmetic or compose an ad-hoc ECIES
protocol. The Rust `hpke` and Node `hpke-js` packages are the selected library
families; resolve their exact versions/features against the actual environment
when adding the locked dependencies.

The public descriptor is `{ format: "rebase-secret-ingress-1", key_id,
suite: "X25519-HKDF-SHA256-AES256GCM", public_key }`; keys are canonical unpadded
base64url. A sealed capsule is `{ format, key_id, enc, ciphertext, expires_at }`.
Require the exact KEM encapsulated-key length, at most 2,048 ciphertext bytes and
expiry after the transaction's captured UTC now but no more than 15 minutes
ahead. Never accept caller-selected algorithms, public endpoints or extra key
material. Old committed receipts remain recoverable after capsule expiry.

HPKE info is the constant UTF-8 `next-base/credential-ingress/1`. AAD is the
canonical serialized typed tuple of format, model, store UUID, signed tenant,
signed actor, principal credential epoch, original operation context hash,
operation ID, credential ID, requested owner-or-omitted marker, if_version,
provider, account, complete metadata and expires_at. Include explicit nulls and
fixed field order. Server reconstruction uses its actual store/session, never
trusts client tenant/actor fields, and compares metadata before decrypt.

The Node preparation function first obtains the session/context and ingress
descriptor, constructs the final operation ID/target/AAD, encrypts the provided
secret bytes, and only then creates the persistable detached plan. Plaintext is
never an intermediate generic operation plan. Its buffer is zeroed in a finally
block where possible; JavaScript copies cannot be promised physically erased.
The function never records the secret in thrown errors or debug objects.

Extend the typed plan validator with an explicit credential-write variant and
fixed RPC method, reusing `persistWriteOnce`, target fencing and original-context
recovery. `savePlan` accepts only the encrypted variant. A generic arbitrary-method
plan or a plaintext-secret option is not introduced. `execute` verifies the same
model/store/tenant/actor/credential epoch before resending the original capsule.
Retries never re-encrypt an uncertain operation. Re-encryption changes its request
hash and is permitted only after a definite no-commit outcome for the old intent.

## Authorization and revocation

Add `Use` to the existing action vocabulary. The same persisted Graph/Scope grants
that authorize CRUD supply this action; no role strings come from a token and no
separate credential permission table is introduced. Secret-use action grants are
not inferred from metadata Read, Update or administrator status. Specifically,
the new Use check consults the prepared `contracts[Credential].contains(Use)`
grant rather than the current `Grants::allows` administrator shortcut. Existing
CRUD administrator semantics and owner accessibility remain unchanged. Explicit
Use grants inherit through the same existing grant rules; this is an extension
of the one authority graph, not a second ACL.

| Operation | Required current authority; checked in the data transaction |
| --- | --- |
| Read metadata | Credential Read plus same tenant and ordinary owner accessibility |
| Create metadata/secret | Credential Create plus access to requested owner |
| Change metadata/secret | Credential Update plus access to old and final owner; both checks precede CAS |
| Delete | Credential Delete plus self/strict-descendant ownership; reject while a retained job requires its binding |
| BYOC use/grant | Explicit Credential Use, ordinary accessibility of its current owner, enabled state, matching provider/account/purpose, and the operation's own action and target checks |
| Platform use/grant | Explicit Credential Use, the requested purpose and a fixed trusted platform binding; no ordinary Read/access privilege on the hidden credential is granted |
| Internal secret load | An unforgeable private capability returned only by the successful checks above; never a client DTO |

Owner accessibility stays self, strict descendants and direct group parents.
There is no arbitrary delegate list or shared-with ACL: group ownership and
existing authority edges supply BYOC sharing. A tenant-parent owner remains
excluded from ordinary scope. A fixed platform credential may live there; the
narrow operation binding authorizes use without revealing that record.

Platform bindings are bounded operator configuration, mapping the compiled slot
`transactional_email` to one exact credential UUID, expected provider, expected
account and purpose. At most 16 bindings; duplicate slots reject startup. Public
requests select this slot or a typed BYOC reference, not arbitrary credential IDs
in platform mode. Changing the configured mapping affects new accepted intent;
E2 pins the resolved credential/provider/account in each job. Existing jobs cannot
be redirected by a new mapping.

E1's stateless email authorization requires Credential Use and the requested
purpose. E2 additionally requires Create on its newly declared EmailSend source
contract and any declared target permission. Do not reserve an action grant on
a nonexistent contract in E1 or create an unused placeholder EmailSend table.

Disable, re-enable, owner transfer and scope changes increment `use_epoch` once
per effective mutation. Label-only edits and secret rotation for the same account
do not. At every E2 claim/start, recheck the captured requester epoch, current
operation rights, current credential use scope, enabled state, binding identity
and captured credential use_epoch. Old jobs cannot regain authorization merely
by disabling and re-enabling a credential. An ordinary both-accessible ownership
transfer is allowed, while its use_epoch fences previously accepted use.

Secret rotation may replace the API key for the same logical provider/account
for new jobs. Select the conservative pinning policy: E2 records the secret
revision at job acceptance, and claim/start/reconciliation use that exact revision
while rechecking current use authority. Rotation never changes an already
accepted job's secret, provider or account. Retain an older envelope while any
retained unresolved job needs it; protect reference presence/absence transactionally
before removing it. A revoked provider key can leave an old job needing operator
resolution rather than silently redirecting it through another credential.
This grants no permission to retry a possibly accepted send. E1 has no durable
jobs, so only its current referenced secret revision needs retention; E2 extends
the same source-derived inventory with pinned execution references.

The logical account label and encryption do not prove that an arbitrary API key
actually belongs to that remote account. Fake adapters must independently bind
test keys to accounts. A live adapter needs its own account-binding verification
before claiming live acceptance. Keeping accepted secret revisions immutable
prevents a rotation from quietly changing this binding for existing jobs.

## At-rest encryption, custody and lifecycle

Use XChaCha20-Poly1305 from the audited RustCrypto `chacha20poly1305` library with
32-byte external keys and fresh 24-byte OS-CSPRNG nonces. Never derive nonces from
time, record IDs, Faker, seeds, counters that can roll back, or client input. The
nonce is generated for one encryption and retained with that envelope; never
replace ciphertext under a reused key/nonce pair. The 192-bit random nonce space
provides probabilistic collision resistance, not an absolute infinite-lifetime
uniqueness claim. No population counter or shared nonce counter is required.

Private row shape is `{ format: "rebase-credential-secret-1", credential,
secret_revision, key_id, nonce, ciphertext }`. Require canonical base64url, exact
nonce/tag lengths and a 2,048-byte envelope bound. AAD binds the format/domain,
tenant, credential UUID, secret_revision, provider, account and secret schema ID.
Owner is excluded from AAD so an authorized owner transfer need not decrypt or
rewrite the secret; its use_epoch supplies revocation. No row may be orphaned or
disagree with the source's system metadata or a retained execution's pinned
binding. An independent inventory checker derives expected current rows from
Credential records (plus E2 retained job references when introduced) and rejects
missing/extra rows. Rotation replaces the current reference atomically; old rows
are removed only when no current source/job requires that revision.

`service.credentials` supplies an absolute private keyring file and the fixed
platform bindings. The bounded file contains at most 16 at-rest keys, one active
write key ID, at most 16 HPKE ingress private keys and one active ingress key ID,
plus at most 16 grant keys and one active grant key ID.
Key IDs are 1–64 ASCII letters/digits/`_`/`-`. Reject symlinks, oversized files,
incorrect key lengths, duplicate IDs and world/group-readable private files.
Load it once into explicit zeroizing runtime state before accepting credential
work; never load key-service/filesystem data during a native transaction. Existing
service/host lifecycle owns the state and drops it on shutdown. A future external
key service is a separately typed I/O adapter, not a formula call.

The database and its backups contain encrypted envelopes, not root keys. A
matching keyring is an external recovery prerequisite. Metadata/structural
inspection can operate without decrypting secrets; enabling secret use fails
closed on missing keys or failed authentication. Do not turn ciphertext validation
into a claim that key custody or live account access has been verified.

Root-key rotation is an operator-only, stopped-service operation. The explicit
host methods `credentials.plan`, `credentials.rewrap` and `credentials.verify`
require their configured operator grants and matching model/store scope. The Node
operator exposes `prepareRewrap({ids})`, `rewrapCredentials({keyring,request})` and
`verifyCredentials({keyring})`. Save the returned secret-free rewrap request with
ordinary private file I/O before submitting it; retain that exact request after an
unknown outcome. A plan pins source versions, secret revisions and old envelope
SHA256 digests, protecting concurrent rewrites without changing source versions.
Verification authenticates the complete bounded envelope inventory and enables no
delivery. Only rewrap/verify load the explicit external private keyring. Load old and
new key IDs, make the new ID active, and rewrap a bounded caller-selected list of
credentials with CAS in ordinary short transactions. Each rewrap authenticates
the old AAD and creates a new envelope without changing provider/account,
secret_revision/use_epoch, source business version or queued intent. Its original
operation receipt records progress. Conflicts leave the old row intact; unknown
ACKs require that receipt rather than assuming another rewrap is needed. Retain
old decryption keys until all live rows and retained backups needing them have an
explicit custody disposition. Losing an old key is not repaired by rewriting its
key ID.

Restore retains ciphertext and its original AAD identities, rotates the existing
store/worker activation fences and preserves reconciliation quarantine. Do not
rewrite envelopes as if they belonged to a different tenant. Explicit restore
verification checks required key IDs and authenticates envelopes before secret
use; it does not enable email delivery. A missing key produces a recoverable
operator configuration error without partial data changes. Restored local stores
may inspect metadata while delivery remains disabled.

## Bounded use grants

`email.authorize` accepts a strict EmailSend request: sender address, 1–16 distinct
recipient addresses, subject (at most 512 UTF-8 bytes), and text body (at most
16,384 UTF-8 bytes), plus the typed credential selection and TTL 1–60 seconds.
No HTML, attachments, client endpoint, extra headers or transport override is
selected in this first contract. Address normalization trims outer ASCII space,
rejects controls/CRLF, retains the local part and lowercases the domain; validation
is syntactic and does not claim deliverability. E2 uses this same request type,
normalization and canonical hash; it does not introduce a second email schema.
Secret-bearing bodies such as A1 codes use server-authored private intent later;
they must not be copied into generic developer plans or grant diagnostics.

The private grant claims bind model/store/tenant, actor and principal epoch, resolved credential
UUID/incarnation/use_epoch/secret_revision, provider/account, operation version `email-send-1`, exact canonical
request hash, issued_at, expires_at and a CSPRNG UUID nonce. It is a sealed
authorization artifact for the native EmailSend entrypoint, not a provider token
or permission to perform HTTP. Seal the claims with XChaCha20-Poly1305 using a
dedicated external grant key, distinct from vault and HPKE keys, and fixed AAD
`next-base/email-use-grant/1`. Return only `{ grant, expires_at }`, with the opaque
canonical-base64url token containing format/key ID/nonce/ciphertext and at most
4,096 bytes. Use a fresh OS-CSPRNG nonce. A readable JWT would disclose the hidden
platform credential UUID, account and use_epoch; do not return those claims.
There is no public generic token decrypt or verifier endpoint. Native consumption
checks the fixed purpose, audience/store and exact typed request hash after
authenticating the envelope, then performs the current authorization checks.

Grant issuance reads current authority and credential metadata in one snapshot,
then performs bounded local grant sealing using loaded keys. It loads/decrypts zero
provider secrets and sends zero requests. A concurrent revocation may overlap an
already-authorized issuance; consuming a grant rechecks current authority and
credential state inside the accepting transaction. E2 still commits durable
intent and follows claim/start/confirm/provider/fact/application. A valid grant
does not bypass that path, quota admission, or original operation receipts.
If its selected secret revision changed before acceptance, grant consumption
fails and a new authorization is required; an existing committed job's original
receipt is still recovered before checking a now-stale grant.

No generic byte-signing method is exposed. Never persist returned grant tokens in
ordinary records, operation receipts, audits or observation snapshots. Grant
issuance is stateless and does not consume an operation receipt: after a lost
response a caller may request a new grant under current authority. A queued job
accepted with a grant is durable and recovers by its job/operation receipt, not
by issuing another send. E3's provider URL grants will separately define bearer
expiry, immutable object identity and cleanup obligations.

## Mutation ordering and minimal integration hooks

1. Strictly bind the encrypted request and verify signed session/store/model/
   original operation context. Read the original receipt using the existing
   protected receipt path. Recover an existing receipt without secret decrypt.
2. Begin one writable transaction; resolve current authority; protect existing
   Credential/source absence and old/new owner scope. Check Create/Update before
   CAS. Check immutable provider/account and requested metadata. These failures
   perform zero ingress/at-rest decrypts and zero provider requests.
3. Authenticate the HPKE capsule using explicit runtime keys and reconstructed
   AAD; parse its private payload; encrypt the at-rest envelope. This is bounded
   local cryptography with no external I/O. Stage the ordinary source change,
   derived secret/use revisions, private row and indexes in the same workspace.
4. Run final-graph ordinary authority and invariant checks. Final source metadata
   must match the staged secret row. Stage the safe ordinary receipt and commit
   once. On a definite abort, no source, indexes, secret row or receipt survives.
   On an unknown commit result, keep the original request and recover its receipt.

Refactor the existing mutation entrypoint only enough to let a typed service
operation compose additional private staging into the same attempt and final
commit. Do not call `Store::mutate` and then write the secret in a second
transaction. Shared paths remain responsible for both-owner transfers, indexes,
cursor epochs, final authority and original receipt recovery.

`Binding` gets explicit optional credential declarations/accessors needed by the
shared lifecycle, analogous to its present effect declaration. Ordinary modules
receive the store/attempt, prepared catalog, current Scope and loaded crypto
handle explicitly. Do not dispatch from a user-provided handler name or add a
global service registry. A model without Credential support publishes no
credential capability and rejects these methods before any secret access.

E2 integrates at `effects::stage` (resolve/pin the accepted credential binding),
`worker::effect_submit_authority` (current use checks), `start_effect_at` (confirm
the accepted secret revision with start and R0 admission), and `confirm_effect_start` plus the
transport boundary (validate the exact committed marker before private secret
load/HTTP). Generalize only the presently hardcoded Account/Create/Update checks
that the EmailSend contract replaces. Preserve the existing fake worker as an
independent protocol regression; credential loading cannot authorize dispatch.

## Executable checkpoint decomposition

| Slice | Files and obligation |
| --- | --- |
| E1.1 primitive oracle | New `src/credentials/crypto.rs` and `tools/node/credentials.mjs`; HPKE interoperability, AEAD/AAD tampering, redacted types, key-file validation and deterministic adversarial tests; library lockfiles owned by the Cargo integrator |
| E1.2 catalog and atomic storage | New `src/models/services.rs`, `src/credentials/store.rs`; small shared hooks in `binding.rs`, `local.rs`, `mutation.rs`, `rpc.rs`, model/host allowlist; source/private-row invariant and ordinary metadata/transfer semantics |
| E1.3 grants and runtime | `src/credentials/grants.rs`, server/host runtime configuration; strict EmailSend input normalization, BYOC/platform authority, bounded opaque grants and current-authority consumption checks |
| E1.4 lifecycle and tools | Existing lifecycle/backup/restore/receipt modules, Node structure checker and typed encrypted-plan integration; rewrap, restore custody and observed failure injection |
| E1 acceptance | Native credential/authority/atomicity tests, Node saved-plan/leakage/real signed workflow tests, fake secret-loader/provider spies, current adapter checks and source-bound checkpoint evidence |

Use new explicit credential/secret/grant format identities and update prepared
catalog/API/storage identities where their actual serialized formats change.
Do not migrate old stores implicitly or rewrite historical checkpoint hashes.
Changing compiled model inventory requires updating current host/release tests,
without relabeling historical six-model results as seven-model acceptance.

Acceptance must include: metadata Read without Use; Use without Read; wrong
tenant/owner/provider/account/purpose; old/new owner transfer denial before CAS;
revoked caller epoch and credential use_epoch; fixed platform binding changes;
zero secret-loader/provider calls for unauthorized attempts; ciphertext and AAD
tampering; unchanged metadata-only edits; atomic source/secret/index/receipt
failures at every actual write; original-capsule unknown-ACK recovery; saved plan,
Debug, error, projection, receipt, backup and observe plaintext searches; key
rotation and missing-key restore; expired/forged/mismatched grants; and two native
handles racing a secret rotation or revocation. Independently derive expected
private-row inventory and safe projections from source facts rather than writer
caches. A fake send does not establish live Resend/Brevo delivery.

## Current developer entrypoints

The compiled `services` model also supplies a disabled metadata-only fixture. It
needs no keyring and makes no provider request. Enable the credential endpoints
with service configuration `credentials: { keyring: <absolute private file>,
platform: [] }`; metadata-only service use can omit this configuration.

```js
const secret = Buffer.from(JSON.stringify({ api_key: process.env.TEST_MAIL_KEY }));
try {
  const plan = await client.prepareCredential({
    model: model.identity, id: credentialId, if_version: null,
    metadata: { label: 'Mail', provider: 'resend', account: 'primary-mail',
      enabled: true, scopes: ['email.send'] },
  }, secret);
  await savePlan(planPath, plan);
  const result = await client.execute(plan);
} finally {
  secret.fill(0);
}
```

A response loss retains that saved encrypted plan for `client.status(plan)` and
original-capsule replay. The plan validator accepts the fixed `credential-write`
kind only; no arbitrary RPC method is persistable through this path. JavaScript
string copies cannot be guaranteed physically erased. Public email authorization
uses `{ model, email: { sender, to, subject, text }, selection, ttl_seconds }` and
returns an opaque grant without a provider call. E2 supplies durable enqueue and
consumption; authorization alone never sends mail.
