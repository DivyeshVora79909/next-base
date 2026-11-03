# E2 EmailSend and scoped R0 admission

Status: implemented and accepted within the bounded fake/native scope below.
See [source-bound evidence](checkpoints/e2-email-rate.json): 367 Rust tests, 214 Node
tests, real local FoundationDB races and redb controls. Implemented after
[E1](e1-credentials.md), before the still-required A0–A2, E3 and E5 in the
[roadmap](roadmap.md). This selects the bounded fake-adapter scope left open by
[server execution](server-execution.md) and [rate admission](rate-admission.md).
Native email jobs and rate admission are required checkpoints. Live Resend/Brevo
delivery, recurrence, frontend and client live invalidations remain deferred.

## One source and one accepted operation

Extend the selected `services` binding with public `EmailSend` source contract
1002 and a declared owner/created access index. Keep Credential code 1001 and its
metadata semantics. Services input becomes an explicit Rust enum selected by the
prepared contract; do not infer record kind from arbitrary field presence.

EmailSend authored fields are:

```json
{
  "email": {
    "sender": "sender@example.com",
    "to": ["recipient@example.net"],
    "subject": "Example",
    "text": "Example body"
  },
  "selection": {"kind": "byoc", "credential": "00000000-0000-0000-0000-000000000064"},
  "execute_at": null,
  "not_after": null
}
```

Use E1's exact `EmailRequest`, normalization, request hash, `Selection` and
`Purpose::EmailSend`. Platform selection remains
`{"kind":"platform","slot":"transactional_email"}`; no resolved hidden
credential/account is added to the public source. Deny unknown fields, duplicate
JSON fields, sequence aliases and noncanonical UUID/integer text. All four source
fields are required. Times are UTC millisecond decimal strings or null. Use the
existing bounded one-shot policy: creation-time defaults, default expiry sixty
seconds later, explicit due within twenty-four hours of creation, and expiry after
creation/due and at most twenty-four hours after creation. Persist resolved times
in the immutable execution; only `execute_at <= now < not_after` permits starting.

Normalize before binding the persisted source. Email recipient order, local-part
case, subject and text remain part of exact intent. All authored EmailSend fields
are immutable after creation. Owner-only updates use the ordinary both-owner
Update checks and move access indexes/cursors atomically. Ownership does not
change the execution's pinned requester, credential selection or request.

An ordinary EmailSend body is readable under that source's current owner policy.
Do not use this public source or a generic saved plan to store an OTP, reset code,
password or provider secret. A1 adds a server-authored private delivery intent and
its challenge preflight, using this worker protocol and email request semantics.
That required A1 work is not implemented or waived by this checkpoint.

## Enqueue, authority and receipt ordering

Add explicit `email.enqueue`; its input is the ordinary mutation envelope
`{model,context,operation_id,commands,returning}` plus `authorizations`, a bounded
array of `{source,grant}`. Require exactly one entry per newly created EmailSend,
no duplicates or extras. The normal command/work/byte limits apply, with at most
16 EmailSend creates in one enqueue. Other authorized ordinary Services commands
may share the transaction. The prepared catalog describes this typed operation;
there is no arbitrary-method plan, handler string or second command language.

Generic `records.mutate` cannot create EmailSend without the service authorization
stage. It still supports authorized ordinary metadata transfers and permitted
deletions. Grant evidence is transient: it is neither an authored field nor part
of the logical operation hash, receipt, public projection or observation snapshot.
Hash the normalized commands and ordinary mutation envelope. A grant proves
permission for that exact email and selection; it is not new job intent.

The enqueue transaction has these boundaries:

1. Bind the strict request and signed model/store/session/operation context.
   Protect/read the original receipt and recover an existing matching operation
   before decrypting a grant or checking its expiry. A different logical request
   under that operation ID remains `operation_conflict`.
2. Resolve current authority in the write transaction and apply ordinary command
   Create/Update/Delete scope, both-owner, CAS and final-graph rules. Creating
   EmailSend requires its Create grant and accessibility of its requested owner.
3. Consume every E1 grant in that same write transaction and compare its accepted
   selection with the source selection. Require current explicit Credential Use,
   current principal epoch, credential incarnation/use/secret revision,
   provider/account/purpose and exact normalized email hash. A grant alone does
   not bypass source Create or ordinary owner scope.
4. Settle source changes, declared indexes/references and final authority. Derive
   private immutable intent from the final source and accepted credential binding.
   Stage source, intent, private credential-revision retention, due discovery,
   resource reservations and the ordinary safe receipt; commit once.

BYOC credential accessibility is checked under Use. It must not accidentally
require metadata Read through generic reference authorization. The credential
dependency is an explicitly typed private service binding with protected
existence/type/tenant checks, not an ordinary client Read-authorized reference.
Platform selection uses only its configured trusted binding and explicit Use;
its hidden credential UUID/account remains private.

The returned ordinary receipt adds execution identities tied to authorized
EmailSend sources. Status and receipt disclosure require current EmailSend Read
and current owner scope; a use-only platform caller learns no hidden credential
metadata. `effects.cancel` requires current EmailSend Update/owner scope plus the
existing requester-or-admin control check. Admin never widens ordinary scope.
Retained EmailSend sources are the status and ACL anchors: deletion rejects while
their executions are retained. The original effect-demo keeps its Account anchor
and source-deletion behavior.

Node adds explicit `prepareEmail`/`enqueueEmail` functions using existing catalog
validation, detached plans and target fencing. A persistable plan contains the
logical request, not bearer grants. Execution takes the separately obtained grant
map; it does not copy it into plan/error/trace output. A lost enqueue ACK recovers
the original operation before any further action. Never refresh an uncertain
plan, allocate a replacement job or automatically reauthorize after uncertainty.
A definite no-commit result permits a new grant for the unchanged saved intent.

Queued execution returns the committed receipt immediately. A bounded inline-wait
helper may wait for this same execution's ordinary worker status after commit;
its timeout returns the committed identity for recovery and never performs a
second direct send. Waiting is owned/cancelled by the server lifecycle and holds
no native transaction open. The helper does not weaken current status disclosure.

## Pinned credentials and safe secret loading

An execution pins operation identity `email-send-1`, model/store/tenant, source,
requester/principal epoch, normalized request/hash, selection, resolved credential
UUID/incarnation/use_epoch/secret_revision, provider and logical account. These
fields are immutable across retries, source transfers, configuration changes and
restore. Do not persist the opaque grant or its private decoded claims object.

Select exact accepted-secret pinning. E1 stores only the current envelope; E2 adds
an explicitly versioned private format retaining revisions needed by executions.
New secret rotation invalidates unused grants. Accepted jobs retain their
accepted secret revision; no retry silently adopts the new secret or another
provider/account. Current enabled state, purpose, owner accessibility, principal
epoch, credential incarnation and use_epoch still gate a new dispatch start.
A label-only edit or same-account secret rotation does not itself revoke an
already accepted job. A provider may independently reject an old key; that does
not authorize account failover.

Protect revision retention and job acceptance in the same transaction. Credential
deletion rejects while any retained execution references its incarnation. New
secret revision writes preserve older pinned envelopes. Root-key rewrap and
verification enumerate current and retained revisions; each envelope's AAD binds
its original tenant, credential incarnation, provider/account and secret revision.
Include retained revision bytes in bounded service accounting, and count a shared
retained envelope once. Derive expected revision references from executions during
independent checking; a writer-maintained reference count is not its oracle.
Use a new explicit envelope/storage identity where this changes E1's encoding.
Existing E1 stores require the documented explicit recreation, not guessed defaults.

Grant issuance, enqueue rejection, denied claim/start and ordinary status load
zero provider secrets. After exact committed start confirmation, a private
transport capability may load/decrypt only the pinned envelope. This capability
is not an RPC DTO or a publicly callable decrypt helper. Root keys are already
loaded into owned runtime state. Provider HTTP and any external key service remain
outside all native transactions. Recheck the committed start/lease and bounded
dispatch age immediately before a call; discard decrypted buffers afterward.

Observation of an already possibly submitted job is trusted reconciliation of
committed intent. It may use its retained binding after requester revocation;
it cannot start or retry a send. Revocation cannot erase remote facts. A missing
retained key leaves reconciliation blocked with a safe recoverable error.

## Shared worker and independent fake adapters

Reuse the existing execution/lease/start/fact/application state machine. Generalize
only the hardcoded source/target authority, request type, provider binding,
disclosure and optional application assumptions demonstrated by EmailSend. Keep
effect-demo and its independent provider protocol tests. Do not require a fake
Account, Account Update permission or a no-op business mutation for email.

Worker configuration is operator-owned and typed: disabled by default, with
explicit delivery or reconcile mode, loaded credential runtime, fixed Resend and
Brevo fake loopback origins, and the quota policies below. An endpoint does not
enable delivery. Client fields cannot select URLs, headers, transport settings,
credentials or handlers. Keep two actual HTTP calls per worker, five-second call
timeouts, bounded blocking admission, bounded sweeps and owned shutdown/drain.
Caller timeout does not release a permit while its blocking work still runs.

Use two independent fake adapters with distinct request/response encoders and
journals. The Resend adapter uses bearer API-key authentication and its email
request shape; the Brevo adapter uses its API-key header and transactional-email
shape. Both receive the same normalized EmailRequest and accepted binding. The
fake harness must check the exact expected body, key and account independently;
sharing one encoder with two names is not adapter acceptance. Endpoint validation
keeps these adapters local and fake. HTTPS features and live provider behavior
are separate acceptance, not implied by similar wire shapes.

Each accepted fake action has stable provider/account/execution/action identity.
Repeated physical requests and unique remote acceptances are separately recorded.
Return bounded typed outcomes binding execution, provider, account, request hash,
disposition and a bounded provider receipt. Reject mismatched or oversized results.
Errors never contain request text, authorization headers or provider response
bytes. Lookup is read-only and returns bound evidence from the independent journal.
Fake acceptance supplies no universal provider idempotency/retention guarantee.

Preserve unknown claim/start/finish ACK recovery and exact activation, execution
revision, lease token and mode checks. Only definitive NotAccepted from the
CURRENT submit call permits another submission. Missing lookup results, old facts,
webhook nonacceptance, timeouts, malformed responses and lease expiry do not.
An uncertain submission remains charged and goes to reconciliation. Cancellation
after start cannot prove rollback or authorize a replacement send.

Email success needs no domain mutation. Persist its terminal fact and an explicit
not-required application state atomically. Retain pending/blocked/applied
application for operations that declare it; remote success plus failed domain
application stays remote success and never resubmits. Generalize the current
`Succeeded iff application != None` validation deliberately, including restore,
status, inventory checks and due discovery. A1 later supplies its selected
challenge preflight and fact application without weakening this boundary.

## R0: fixed-window charged physical submissions

Select online point-count admission, not endpoint-derived quotas or backdated
edits. For every immutable committed physical submission at trusted time `s`,
charge one occurrence and enforce `#{s : now-W < s <= now} < L` before inserting
the candidate. Distinct attempt identities retain multiplicity at equal times.
Charge at start, not enqueue or successful delivery. Reconciliation reads are not
EmailSend submissions and are governed by the separate existing observation/call
budgets. This does not claim to enforce a provider's all-HTTP-request quota.

Quota identity is `(store transaction domain, provider, logical account,
email.send)`. All local principals, platform/BYOC selections, credential UUIDs and
secret revisions mapped to that account share it. Reject missing policy rather
than selecting an unlimited fallback. A deployment requiring one quota across
multiple stores or unrelated external workers must provide one common transaction
domain or separately allocated account budgets; this checkpoint proves only the
configured store's admissions. Duplicate aliases for one physical remote account
must not be configured as independent quotas.

Select at most 16 immutable quota policies per store, each with integer window
`1 <= W <= 86,400,000` milliseconds and `1 <= L <= 64`. On first use persist the
typed policy identity/window/limit and protected last admitted time in that scope.
Restart configuration must match. Reject policy changes for existing scopes in
this checkpoint; changing a label cannot reset consumed quota. Mixed windows,
backdating, refunds and mutable policy transitions are not supported alternatives.

Capture UTC once inside start. Reject negative or regressing time relative to the
scope's last admission; equality is allowed. Arithmetic is checked. Use a
protected ordered range over private immutable admission facts, keyed by scope,
admitted_at and attempt identity; enumerate at most the selected bounded retained
start inventory, short-circuiting after L active points. Protect empty ranges and
the scope policy/time row. The existing protected runtime/root write may already
supply coordination; do not add a redundant global guard or population counter.

Retain each physical start charge with its execution/attempt/token so an
independent checker can derive the range inventory from committed start facts.
With 256 retained executions and three submissions each, the retained charge
inventory is bounded to 768, independent of source population. A store with full
retention rejects new work; silently dropping active charges is forbidden. A
future retention compactor must preserve live-window charges and recovery facts.
These bounds are service retention limits, not a restored source-population count.

Admission and the exact effect start marker commit together. No start means no
new charge; definite rollback leaves neither. Original start recovery reuses its
existing charge and token. A denied slot clears its unstarted lease, leaves the
job ready and persists `next_at` at the earliest blocking point's `s+W`, bounded
by the job's expiry. Denial does not consume a physical submission attempt or
exhaust its retry allowance. Adjust the current claim-time attempt increment
explicitly: the public submission count represents committed charged starts.

Select maximum admission-to-call age delta of 1,000 milliseconds for this fake
contract, further bounded by lease and job expiry. Confirm the original marker
and freshness immediately before dispatch. A pause past that deadline sends
nothing, retains its charge and follows conservative uncertainty/reconciliation;
it never reuses the expired token. This proves local admission times with the
tested clock; no strict remote receipt-time quota is claimed under unbounded
process pauses, clock skew or network delay.

The independent oracle sorts physical starts by timestamp/attempt identity and
counts complete equal-time groups directly. It must cover ties, a point expiring
exactly at `now-W`, clock-only expiry with no source edits, queued-yesterday/send-
today, account sharing across credential rotations, regressing clock, checked
overflow, full-slot races, denied wake persistence, wasted crash charges, unknown
start ACK and delayed calls. Count the candidate exactly once. Historical
mathematical witnesses alone are not worker/concurrency acceptance.

## Retention, recovery and verification slices

Keep the bounded effect retention, fact reservations, three charged submission
attempts, six observations and eight-MiB private-store budget. Replace the fake
demo's one-KiB request ceiling with an explicit per-email serialized ceiling of
64 KiB; keep the existing 64-KiB outer RPC limit. Enforce E1's decoded UTF-8 bounds
independently. JSON escaping and other commands/grants consume the outer budget,
so a schema-valid maximal body or batch can still hit that byte limit. The catalog
must advertise both limits and the tools must check the final wire envelope. A
larger per-effect ceiling is not a capacity claim.

Backups include immutable requests, pinned credential revisions, physical start
charges, policy/time rows, facts and original receipts. Restore rotates worker
activation, clears leases and keeps unresolved work disabled/quarantined under
the existing policy. It preserves admission facts and original AAD identities.
Inspection does not decrypt secrets. Missing external keys block secret use
without changing facts or silently enabling delivery. A restored store may
reconcile; it cannot start fresh sends merely because old local leases vanished.

Implement and accept these slices in dependency order; one owner integrates shared
native files and owns Cargo, while disjoint files may be delegated when useful.

| Slice | Files and independently checked obligation |
| --- | --- |
| E2.1 typed intent and retained secrets | `src/email.rs`, `src/models/services.rs`, `src/credentials/{grants,store}.rs`; strict DTO/catalog, Use-without-Read, private binding/incarnation, exact secret revision retention, source transfers, safe disclosure |
| R0 primitive and storage | New `src/effects/admission.rs` plus source-derived checker; independent timestamp oracle, scoped protected keys, clock/boundary cases and original token accounting |
| E2.2 atomic acceptance and lifecycle | `src/effects.rs`, `src/effects/{state,worker,application}.rs`, `src/local.rs`; enqueue receipt ordering, shared transaction publication, current Use checks, atomic quota/start, optional application, failure injection |
| E2.3 provider seam and runtime | New explicit email adapter module plus `src/server.rs`/host configuration; independent Resend/Brevo fake journals, post-confirm secret capability, bounded calls, revocation and stale-start pauses |
| E2.4 developer functions | Node client/plan/catalog functions and independent checker; bearer-free saved intent, target fencing, original status recovery, both signed real-store workflows and source-derived inventories |
| E2/R0 acceptance | Native authority/atomicity/concurrency tests, both fake transports, restart/restore/key-loss witnesses, real configured adapter races, original effect-demo regression, source-bound checkpoint and continuation updates |

Before claiming acceptance, inject failures after every actual new source/private/
intent/admission/receipt write, including post-receipt abort and unknown commit
ACKs. Search plans, Debug/errors, public records, status, receipts, backup and
observation for test credential plaintext and opaque grant tokens. Verify current
owner/epoch revocation races, label-only and secret rotations, delete/recreate ABA,
same-account quota sharing, exact cross-provider noninterference, independent
full-state inventory, reopen and backup restore. Run actual redb controls and the
configured real FoundationDB concurrency checks; label process/host topology.

E5 later composes the selected native email/auth/object services into the full
fake recovery workload. E2/R0 acceptance does not finish that required gate or
establish live delivery, multi-host worker coordination or unlimited retention.

## Implemented entrypoints and operation

Use `client.prepareEmail({ model, commands, returning })` to normalize and persist
an `email-enqueue` plan. Obtain each request-bound grant through `email.authorize`,
then call `client.enqueueEmail(plan, [{ source, grant }])`. `client.execute` rejects
email plans so bearer evidence cannot accidentally become saved intent. Use ordinary
`client.status(plan)`/`operations.status` after an unknown enqueue outcome, and
`effects.status` for each committed execution. Recovery keeps the original target,
operation context and source identities. The final wire envelope includes the
grants and still obeys the 64-KiB RPC limit.

`ServerConfig.email` selects disabled/delivery/reconcile mode, fixed fake origins,
quota policies and an optional local probe directory. It composes the existing
credential runtime; it cannot be enabled alongside the old fake-demo worker.
Policies persist even when the worker is disabled. A configured rate scope prevents
store reset, because this checkpoint has no charge/retention compactor. Ordinary
secret rotation preserves pinned revisions; stopped operator rewrap enumerates
current and retained ciphertext and updates actual byte accounting atomically.

On a custody failure, the owned worker stops and leaves the original charged start
for reconciliation. A failed joined service can already be absent at the host;
Node clears its local service identity only after an explicit matching
`service_not_running` response. Timeout alone never clears ownership. Restore keeps
work quarantined, retains exact ciphertext and quota facts, and permits read-only
reconciliation after matching keys are supplied. Restoring keys does not authorize
a new submission.

The native adapter suite injects after every actual enqueue and admission/start
write and drops acknowledgements only after real commits. Its FoundationDB runs
use one local process/host. The independent Node fake providers validate expected
source email, account and key, and keep distinct submission/observation/acceptance
counts. No live Resend/Brevo behavior or distributed throughput is inferred.
