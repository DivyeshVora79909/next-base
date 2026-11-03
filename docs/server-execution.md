# Server execution: planning reference

E1 credentials and bounded grants are accepted in the
[credential checkpoint](checkpoints/e1-credentials.json). [E2/R0](e2-email.md) now
accepts durable EmailSend, pinned secret revisions, independent fake Resend/Brevo
transports and charged submission admission. A0–A2, objects and E5 remain planned
until their own acceptance checks pass.

This is a design and acceptance map, not implemented provider functionality.
Read with [external effects](external-effects.md), [architecture](architecture.md),
[developer tools](developer-tools.md), and [roadmap](roadmap.md).

## Current capability versus planned extension

| Capability | Current native implementation | Planned boundary |
| --- | --- | --- |
| HTTP/runtime | Axum, Tokio, bounded blocking RPC, owned shutdown | Retain admission and recovery guarantees |
| Provider action | EmailSend with independent Resend/Brevo fake loopback transports; original effect-demo retained | Private authentication delivery and objects |
| Credentials | Encrypted owner-scoped records, explicit Use grants and accepted revision retention | Additional typed provider credential profiles |
| Execution | Transactional intent, receipts, leases, facts, application | Reuse for composed durable jobs |
| Scheduling | One-shot `execute_at` / `not_after` | Optional recurring occurrence materializer |
| Objects | No blob API, presigning, finalize, or cleanup | Authorized metadata and private object adapter |
| Sync grants | No general grant API | Bounded stateless authorized signing/read work |

`credential_epoch` revokes a service principal; it is not an SMTP, OAuth, or S3
credential version. `effects::Template` describes target and one-shot timing, not
an email template or workflow interpreter. No generic function registry exists.
Sources: `src/binding.rs`, `src/effects.rs`, `src/models/effect_demo.rs`,
`src/effects/{state,worker,application,fake,inbox}.rs`, `src/rpc.rs`, `src/server.rs`.

## Functions, authority, and execution modes

Use ordinary Rust functions with explicit inputs, dependencies, and typed results.
Compose functions by calls and async awaits. The prepared model/catalog remains the
single schema and operation authority; compiled bindings explicitly connect handlers
and strict request, outcome, and credential schemas. No serialized closure, second
workflow DSL, runtime plugin registry, or client-selected arbitrary function dispatch.

Keep helpers private to modules and expose a deliberate public operation allowlist.
Visibility alone grants no permission: the server checks current tenant/principal,
client intent, target access, allowed operation/account, and credential-use authority.
Credential metadata Read is separate from permission to use its secret. Only after
these checks may a narrow trusted internal capability load credentials or dispatch.
Trusted application may touch hidden dependencies without exposing them to clients.
Do not expose generic signing/decryption or raw worker transition RPCs. Public
functions issue purpose-bound grants; internal capabilities are not client DTOs.

Three modes share ordinary helpers but have different durable boundaries:

- Pure/local work: validation, formulas, normalization and bounded cryptography run
  directly; formulas have no I/O. Immediate grants authorize bounded stateless work
  such as signing a constrained upload/download URL. Grant issuance is not delivery.
  Signing is stateless; the endpoint may still commit authorization/expiry bookkeeping.
- Inline wait: commit a durable job first, then wait for its ordinary worker result.
  A response deadline leaves the committed job/status intact; return its identity
  for recovery. Waiting is not permission for a separate direct provider send.
- Queued work: return the committed job identity immediately. Inline and queued
  execution use the same claim/start/observe/apply path and authorization checks.

An `async fn` is a suspended computation, not a durable job. Tokio tasks do not
survive process exit. Persist intent when accepted work needs crash recovery.
Execution mode and retry safety are separate: deterministic pure work can be
recomputed; external writes need their declared reconciliation/idempotency contract.
Clients cannot select a flag that makes an unsafe operation replayable.
Business changes and their job intent share one transaction domain; a separate
service module or job store does not provide cross-store atomicity automatically.
External observations enter explicit facts, not hidden HTTP reads inside formulas.
Provider HTTP, object I/O, and key-service calls occur outside KV transactions.
This does not ban native async KV operations inside their own transaction: for
example, FoundationDB batch reads must preserve that transaction's read/conflict scope.
Run synchronous store work and substantial CPU work through bounded blocking
admission; keep permits until actual completion, including after HTTP timeout.
Do not assume aborting a blocking task stops it. Bound bytes, tasks, deadlines,
scans, retries, and shutdown. Preserve `src/server.rs` ownership/drain behavior.

## Credentials and versioned operation contracts

Provider credentials are ordinary versioned records with typed metadata and encrypted
secret payloads, not raw strings in job inputs. Specify tenant, owner/delegates,
provider/account identity, credential schema/version, enabled state, scopes and epoch.
Use authenticated encryption with unique nonces, key IDs and AAD binding tenant,
record identity and version. Bootstrap root key custody outside the database;
rotation, restore and key loss need explicit policies. Encrypted credential blobs
may be backed up; restoring them requires the matching external key custody.
JSON Schema `writeOnly` alone enforces neither secrecy nor access control.
Secret submission must also be safe for saved plans and replay: retain an encrypted
envelope or secret-safe receipt-bound request, never plaintext in a generic plan.
OTP/reset messages can contain secrets too. Test Faker seeds are not production nonces.

Never disclose plaintext through projections, status, receipts, catalog examples,
logs, Debug output, errors, audits, or ordinary record serialization. Apply secrecy
before these surfaces, not as a final JSON redaction pass. Keep signing keys,
provider tokens and grant URLs out of diagnostic snapshots and fixtures.
Platform credentials may be hidden root records resolved by a fixed trusted binding.
BYOC accepts an explicit typed credential reference under current owner/delegate
use authorization. An ID is not authority; neither pattern relaxes cross-tenant FK checks.

Use one `EmailSend` operation contract with a strict typed request and explicit
Resend or Brevo adapter binding. Each accepted job pins its operation semantics,
canonical request/hash, provider, account, credential binding and required payload
decoder. Retries, failover, restore and credential rotation cannot redirect an
accepted job to another provider or reinterpret its request. Semantic or format
changes that affect stored jobs require an explicit identity change and retained
decoder; no public v1/v2 operation pair or general compatibility framework is required.
Credential rotation may select a new secret for the same logical account under an
explicit policy, but cannot switch account or mutate an ambiguously sent request.
Current revocation and credential-use authority still govern dispatch of old jobs.
OAuth refresh also needs fenced persistence and unknown-result recovery; replacing
a newly rotated refresh token with stale data can destroy access.
An operation may need no credential or no domain application. Do not inherit the
fake demo's Account permission, timing bounds or single-action limitation as universal rules.

## Execution invariants to preserve

The implementation in `src/effects/worker.rs` and `src/effects/fake.rs` is the base:

- Claim/start checks bind activation, store/execution identity, ordered revision,
  random lease token and mode. Current requester authority is rechecked at start.
- Persist provider-start before I/O. Unknown start commit acknowledgement permits
  dispatch only after `confirm_effect_start` reads the exact committed marker;
  an unknown claim acknowledgement never itself authorizes dispatch.
- A started call that times out, crashes, loses its lease or returns malformed data
  is uncertain. Reconcile; cancellation and stale-finish fencing cannot undo it.
- Only definitive `NotAccepted` from the CURRENT submit call permits resubmission.
  Lookup/webhook nonacceptance cannot authorize retry. Stable provider idempotency
  keys help within provider scope/retention but do not prove universal exactly once.
  Broader safe replay requires a separately proven operation-specific contract;
  never loosen the conservative policy globally because a provider is called idempotent.
- Facts remain durable separately from local application. Remote success plus blocked
  domain application is still remote success; repair/retry application without sending.
- Inbox deduplication, fact application tokens, receipt recovery and bounded retry/
  observation budgets survive generalization. Unknown local ACK recovery reads local
  committed evidence rather than repeating provider I/O.
- Restore rotates activation, clears leases and quarantines unresolved executions;
  reconciliation is allowed, new delivery is refused until the existing reset policy.
Operation-specific preflight must handle stale source versions and replaced/expired
challenge nonces. Cleanup jobs may intentionally outlive their deleted source.
Distributed KV storage alone does not establish active-active worker safety.

Reuse `src/effects/{worker_tests,inbox_tests,conformance}.rs` and `src/effect_tests.rs`.
Fake adapter evidence is not proof of live provider delivery or distributed topology.

## Object lifecycle and recurrence

Object records need pending/ready/deleting states, tenant ownership, immutable object
key/version identity, size/digest expectations and upload-grant expiry. Begin upload
commits pending metadata before issuing a constrained short-lived grant. Finalize
verifies the actual remote object/version, byte size and required checksum before
publishing ready metadata; ETag is not a universal checksum. Repeated finalize is
idempotent. Download grants require current read authority and bounded expiry.
Ready reads must pin an immutable remote version, or uploads must be promoted from
staging into a server-owned immutable object. A live write grant must not alter ready bytes.
Do not accept arbitrary client endpoints, unrestricted proxy URLs, bucket names or
credentials as authority. Signed URLs are bearer capabilities until expiry.

KV and object storage cannot commit atomically. Finalize/delete/abort/cleanup form
recoverable steps with explicit reconciliation. A late upload can recreate a key
after deletion: wait out or invalidate outstanding grants, account for in-flight
uploads/multipart sessions, and reconcile afterward before declaring cleanup final.
Use unique object/version identities; stale cleanup cannot delete replacement data.
Versioned-bucket cleanup must paginate and handle versions plus delete markers,
including the 1001-version boundary; deleting a visible key alone is insufficient.

One-shot scheduling already exists. Cron does not, and the legacy accepted design
removed recurring schedules rather than implementing them. If selected, add a bounded
materializer that creates ordinary jobs with a unique schedule-version/occurrence
identity and atomically advances the cursor. Define timezone, DST ambiguity/gaps,
misfire policy, catch-up and overlap caps, edits/cancel, and current authorization.
Business effective time, earliest job eligibility and observed provider time differ.
Scheduled instants do not promise exact execution; declare clock-skew and delay policy.
Use the schedule definition version in occurrence identity, not the changing cursor/CAS revision.
A deterministic clock oracle must cover duplicate pollers, restart and missed ticks.
Tokio timers only wake polling; persisted state provides correctness. No workflow
engine or Redis dependency is required for this correctness model.

## Developer loop, libraries, and acceptance gates

Use existing catalog and `preparePopulation` functions, the fake provider,
`runWorkload`, independent checks and complete `observe` output first. Compose
ordinary Node ESM functions; add no CLI wrappers or parallel schema authority.
Reuse Tokio, Axum, Reqwest, Serde and current hash/HMAC/JWT facilities where suitable.
Reqwest currently declares `json` with default features disabled: verify HTTPS/TLS
features before a live adapter. JWT's transitive AWS-LC backend is not an existing
credential vault. Select an audited AEAD library and one object SDK only when their
concrete APIs/features are needed and checked. No new mandatory framework dependency.

Each feature implements only after its own design and acceptance checks are specified:
First freeze exact schemas, public/private function inputs, authorization matrix,
linearization points, state transitions, resource limits and failure outcomes for
one small fake operation. Then implement and generalize only demonstrated reuse.
E0 does not claim these feature-specific schemas or library choices are finalized.

- E0 — Planning: inventory current behavior and specify mode, schemas, authority,
  version identities, recovery transitions and independent counterexamples. Confirm
  no claimed provider, object or cron capability comes merely from existing async code.
- E1 — Credential/grant: prove metadata Read cannot use secrets; private helpers
  cannot leak secrets; fixed platform/BYOC bindings enforce current use permission.
  Cover secret-safe saved plans, revocation, encryption/AAD/key rotation, constrained
  grants and restore custody; unauthorized calls must load zero secrets and send zero requests.
- E2 — Durable jobs: prove both Resend and Brevo bindings use the same worker protocol
  with independent fake adapters; jobs remain pinned to their accepted provider and
  account through retry/recovery. Prove current revocation, unknown start ACK
  confirmation, unknown provider outcomes, CURRENT-submit-only retry, lease fences
  and blocked-application recovery. This is fake protocol evidence, not live delivery.
- E3 — Objects: fake adapter covers begin/finalize/delete partial failure, checksum
  rejection, stale cleanup, late upload grants and replacement protection. Include
  multipart recovery and paginated 1001-version/delete-marker cleanup.
- E4 — Recurrence: deterministic oracle checks DST, misfires/caps, duplicate materializers,
  atomic cursor/job publication, edit/cancel and restart. Repeated discovery creates
  one logical occurrence and still uses ordinary current job authorization.
- E5 — Full fake pipeline/recovery: connect catalog/population, authorized enqueue,
  fake transport, status/facts/application and observe/check workloads. Exercise
  restart/restore quarantine, private leakage, all failure points and bounded capacity;
  report exactly which persistence adapters/process boundaries were tested.

Live provider/frontend work is not a prerequisite for these fake/native contracts.
Legacy guidance is static historical evidence, not a parent-repository import:
[ReBase at 270d875](https://github.com/DivyeshVora79909/ReBase/tree/270d875a6e97b276d9cf7876a9bb4666a21d0f53),
particularly `designs/rebase-system/{operations,credential-ownership-contract}.md`
and `dev-tools/compiler/table-handlers.js`. Preserve principles, not SurrealDB
permissions/events, old cron proposals, or historical mock results as new acceptance.
