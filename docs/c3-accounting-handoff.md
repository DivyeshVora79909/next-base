# C3.1 accepted: counter removal and continuation

The stored capacity counter and `Binding::Limits` API are removed entirely. There
is no tracked/untracked accounting mode or fallback. Codec is `native-slice-kv-11`;
older stores require explicit recreation. `Population` is retained only as truthful,
source-derived read-only inventory statistics at open and independent checking.
Normal mutations neither persist that aggregate nor scan source inventory.

Business invariants and work/byte budgets remain. Preserve Record/Reserved/Role
identity collision guards, protected absence reads, receipts, authority fencing,
and required reader/contract query epochs. Removing capacity ceilings does not
remove domain validators or make arbitrary global validity free.

## Accepted local evidence

[C3.1 evidence](checkpoints/c3-counter-removal.json) records FoundationDB 7.3.77
on one local process/host. Both original creates and both original deletes in distinct
reader/business scopes committed without automatic retries. Those attempts had no
Population reads/writes, scans, shared protected point writes or cross-reads.
Same-reader epoch and shared-business-root conflict controls remain effective.
After creates the snapshot contains 10 records, 4 roles and 4 reservations; after
deletes it contains 4 records, with 4 retired roles and 4 retained reservations.

Validation passed: 289 default Rust tests; 172 full Node tests, none skipped;
all-target default/FDB Clippy with warnings denied. Real FDB coordination/lifecycle
passed 18/14 and application/effects/predicates 19/27/12. Redb sequential controls
passed coordination/lifecycle 15/10 and application/effects/predicates 13/27/9.
These establish scoped local correctness, not multi-host performance or throughput.

The historical [C3.0 evidence](checkpoints/c3-contention-baseline.json) remains a
pre-change baseline: separate scopes shared Population, while the same-reader
control demonstrated epoch contention without that write. Do not rewrite this
historical evidence as counter-free acceptance.

Full C3 remains later work: explicit resource/tenant/reader-or-owner/order streams
and generic non-time query/dependency cuts. Creation and effective order are already
separate concepts; adding general access indexes requires explicit memberships and
independent disclosure/cursor tests. Email/phone authentication is separately
[planned](email-phone-authentication.md), not part of this implementation checkpoint.
