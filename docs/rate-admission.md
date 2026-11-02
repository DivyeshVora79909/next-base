# Rate admission and interval counting

This is a planning contract for a shared email/provider quota. Native ordered
counts and the complete-prefix algebra provide useful ingredients; a generic rate
limiter, automatic quota participations and an upper-bound admission hook are
planned integration, not current provider capabilities.

## Meaning and time

Choose a provider account/credential quota identity, operation class, fixed window
W > 0 and limit L. Workers, users and credential revisions sharing a remote quota
must share this scope. For charged admissions A, require
`C(t) = #{s in A : t-W < s <= t} <= L` for every time t.
Distinct attempt IDs preserve multiplicity at equal timestamps. Time bounds must
include or exclude the entire equal-time group; arithmetic must be checked.

Use explicit `created_at`, `admitted_at`/`start_at`, and `completed_at` names.
`processed_at` needs one of those meanings before it can define an invariant.
Creating queued emails yesterday must not let today's dispatches escape today's
quota. Charge a committed dispatch-start admission before external I/O, not job
creation or successful completion. A logical job can have several charged physical
submission attempts. Provider idempotency does not imply that repeated requests
are free of request quota. Define which failures and reconciliation reads count.
The conservative default consumes a charge for every potentially charged attempt,
including timeout or unknown response, and does not refund without evidence.

Capture trusted UTC now once for admission and protect a per-scope nondecreasing
time policy or reject regression. Monotonic process time supports elapsed deadlines;
it is not a durable cross-process timestamp. Fixed W and L belong to a typed,
effective policy version. Updating policy must define prospective applicability,
without silently rewriting old quota facts or retroactively changing their W.
Changing policy identity must not reset a shared provider account's consumed quota.
Mixed policy windows need an explicit transition rule and independent witness;
the fixed-W endpoint proof below does not silently generalize across such changes.

Admission time proves a local admission limit. A paused worker can send much later,
and provider receipt times can differ through clock skew and network delay.
Define a bounded admission-to-send interval Δ and skew assumptions if needed;
without such bounds this does not prove a strict provider acceptance-time quota.
A stale admission cannot silently authorize an arbitrarily late send. Scheduling
or conservative margins need a separate proof against the provider's contract.

## One source occurrence or two derived endpoints

One occurrence at s supports online `rangeCount((now-W,now])`. With immutable,
nondecreasing admissions, protect and check the pre-insert count plus the candidate,
or validate the candidate final-state count once; do not count it twice. Equal-time
admissions still count separately. Prior windows are unchanged and between arrivals
counts decrease, so the new endpoint suffices for this append-only upper bound.

The same point contributes to C(t) on `[s,s+W)`: rolling count is interval stabbing
under this coordinate transform. A shifted subscriber interval does not force two
producer memberships. One stored point plus bounded range queries is sufficient.

A second valid representation automatically derives two occurrences per source:
`+1 at s`, `-1 at s+W`, with stable `(source ID, participation slot)` identities.
Use positive fixed weights if weighted units replace requests. A prefix sum after
each complete equal-time group is exactly C(t). Thus the existing
[`Summary::complete_max`](../src/algebra.rs) over the full ordered endpoint root,
including its empty prefix, gives an all-time proof via `complete_max <= L`.
Equal-time groups are atomic mathematically: an expiration and arrival at the same
time must not create a false transient excess from arbitrary tie order. Ordinary
`max_prefix` over partial groups would be the wrong predicate. Automatic derivation,
final-state endpoint validation and a generic protected native upper-bound hook
remain planned. Do not expose endpoints as independently editable quota facts.

This two-endpoint encoding makes an exact constant-size associative summary
available; do not claim that a point-only count summary alone stores the exact
maximum of every sliding window. Cross-boundary windows need additional reasoning.
Actual occupancy `[start,end)` also naturally uses +1/-1, but measures concurrent
work rather than rolling request count. A local lease expiry can release a local
reservation; it cannot prove an already running remote operation has stopped.

## Historical changes and dependency direction

Backdated insertion at s changes C(t) for `t in [s,s+W)`. W=10,L=2 with points
0 and 9 is valid. Inserting 8 passes its own count at 8, but makes C(9)=3.
The point-only design must validate final counts at every affected arrival endpoint,
including s and complete ties. For nonnegative weights and an upper bound, maxima
occur at arrivals: every real t and every expiration need not be checked. Signed
weights or lower bounds require a different proof. Validate combined batch state;
independent old-state checks miss interacting candidates. Moving a point includes
an insertion obligation; deletion only reduces this upper-bound count. The derived
endpoint design instead checks the final root's complete maximum.

Dependency tracking must distinguish a source edit affecting future query windows
from time passing with no source edit. A cached `count(now-W,now]` needs scheduled
wake/re-evaluation at relevant expiration boundaries; a tree write dependency alone
cannot wake it. Avoid defining a contribution through a formula that queries its
own unresolved contribution. Use an explicit fixed candidate with final-state
validation, or an explicitly guarded before-state count plus that candidate.

## Atomic dispatch boundary and existing machinery

Within one short native transaction, resolve authority and current quota policy,
protect the scoped root/range and any required absence, validate the count or final
root, and commit the unique admission plus effect start marker. Concurrent workers
must conflict when racing for the final slot. Existing native AVL/root/header
write coordination may supply the necessary common guard; add another guard only
if the selected adapter's protected reads and mutation path require it. An
unprotected lookup followed by HTTP does not enforce admission. Backend transaction
I/O may be asynchronous; unrelated external HTTP must follow commit outside it.

Confirm the original start commit/ACK or recover its original receipt before
submission; an unknown commit outcome cannot authorize a fresh duplicate attempt.
A crash after charging but before HTTP may waste capacity safely. Unknown remote
outcomes retain their charges and enter reconciliation; retry policy must distinguish
another physical submission from observation of the existing logical action.
On denial persist a retry/wake time rather than holding a transaction open.

The current [bounded effect demo](external-effects.md) already separates committed
intent/start markers, provider I/O, facts and domain application, and documents
in-flight remote calls surviving local lease expiry. Its two-call worker limit and
[`effects.rs`](../src/effects.rs) retained/unresolved/byte capacities are not a
provider rolling quota. Shared `EFFECT_RUNTIME` coordination is an existing pattern,
not proof of this planned admission hook. General provider credentials remain planned.

Token bucket, leaky bucket, fixed windows or a limiter crate can be product choices;
they require their own burst, clock and distributed guarantees rather than an
assumption of equivalence to the exact rolling-window rule.

The [`mathematical witnesses`](../tests/mathematical_contracts.rs) cover independent endpoint,
count and boundary mathematics. They do not establish production worker concurrency,
protected adapter conflicts, crash recovery, provider timing or clock correctness;
those need integration witnesses before this plan becomes an implemented guarantee.
