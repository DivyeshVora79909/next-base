# C3 continuation

Full C3 is implemented and verified by [ordered access](ordered-access.md) and
[the checkpoint evidence](checkpoints/c3-ordered-access.json). Current codec is
`native-slice-kv-13`. C4 is also accepted; E1 credentials/grants are next under
[the concrete contract](e1-credentials.md). Preserve owner-only access, both-owner
transfers, source-derived inventories and the absence of a population counter.
The historical counter-removal record below remains bound to its original source.

# Historical C3.1 accepted: counter removal and continuation

The stored capacity counter and `Binding::Limits` API were removed in this historical source. There
is no tracked/untracked accounting mode or fallback. Codec is `native-slice-kv-11`;
older stores require explicit recreation. `Population` is retained only as truthful,
source-derived read-only inventory statistics at open and independent checking.
Normal mutations neither persist that aggregate nor scan source inventory.

Business invariants and work/byte budgets remain. Preserve Record/Reserved/Role
identity collision guards, protected absence reads, receipts, authority fencing,
and required query-scope/contract epoch guards in that historical source. Removing capacity ceilings does not
remove domain validators or make arbitrary global validity free.

## Accepted local evidence

[C3.1 evidence](checkpoints/c3-counter-removal.json) records FoundationDB 7.3.77
on one local process/host. Both original creates and both original deletes in distinct
reader/business scopes committed without automatic retries. Those attempts had no
Population reads/writes, scans, shared protected point writes or cross-reads.
The historical same-reader epoch and shared-business-root conflict controls remain effective for that source.
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

The C3.1 results above remain historical evidence under their source identity; C2.O owner-only access is now accepted. Full C3
remains pending: chronological resource/tenant/owner/order streams, k-way lookup over
accessible owner scopes, and generic non-time query/dependency cuts. C2.O's accepted
owner-only format requires `native-slice-kv-12` and explicit old-store recreation. Creation and effective order are already
separate concepts; adding general access indexes requires explicit memberships and
independent disclosure/cursor tests. Email/phone authentication is separately
[planned](email-phone-authentication.md), not part of this implementation checkpoint.
