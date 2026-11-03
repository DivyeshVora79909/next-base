# Next checkpoint: C3.1 immutable capacity accounting

This is a source-audited implementation packet, not implementation/acceptance evidence.
C3.0 adds the executable pre-change contention baseline; accounting behavior is unchanged.
Start by inspecting HEAD/status, AGENTS.md, CONTEXT.md, docs/architecture.md and docs/roadmap.md C3.
Read the committed C3.0 report and fresh recorder code; retain its measured pre-fix result.
Use function anchors and current source rather than treating any recorded line numbers as fixed.
Implement only this accounting prerequisite; access/order streams and generalized cuts remain later C3.
Preserve the native engine + transactional KV adapter foundation (redb, optional FDB/SurrealKV).
No new Node/CLI wrappers, hidden registry, second catalog, global counter/tree or epoch semantics change.

## Fixed semantics

1. Derive immutable AccountingMode from the exact validated Limits during Prepared::prepare:
   tracked iff public_records/outputs/reservations is Some (including Some(0)), or per_contract nonempty.
   Omitted ceilings mean untracked. Freeze Limits and mode in Prepared; runtime checks/catalog use those values.
   Do not add an independently configurable Binding flag or repeatedly call B::limits at runtime.
2. Tracked retains exact complete Population and protected counter admission; untracked has NO Population key.
   No fake zero, stale cache, per-attempt delta exposed as totals, or marker at that global key.
   Add explicit accounting policy revision and mode to prepared identity/catalog; bump native codec identity
   and update compatibility fixtures. Require explicit recreation; do not silently migrate old stores.
3. Keep persisted/source Population as a struct. Add attempt AccountingAccumulator::{Tracked(Population),Untracked}
   with narrow add/remove/reserve/check/writeback helpers; mechanically propagate settlement signatures.
   Untracked capacity helper no-ops must not remove source existence, identity or authorization guards.
   Do not replace the missing mutation counter with a source-range scan: source totals
   belong to bounded open/integrity inventories. Such a scan would reintroduce global
   read/write contention and linear mutation work under an untracked name.
4. Reservations count retained private identities, not live outputs; deletion/role retirement does not decrement.
   Keep original/current Record/Reserved/Role collision reads, eight allocation retries, original role ownership,
   retained reserved identities, retired producer prohibition, and receipt recovery unchanged.

## Verified edit map (anchors, not immutable line numbers)

- src/binding.rs: Limits near 33; Binding::settle_changes currently takes &mut Population near 67.
- src/model.rs: Prepared near 177 lacks limits/mode fields; prepare reads B::limits near 310;
  semantic hash includes limits near 655 plus policy strings near 665; model_capabilities re-reads limits near 832.
  Make catalog declaration come from the prepared authority; inspect all describe/capabilities call sites.
- src/native_slice.rs: Population near 58; apply near 1050 forwards it to causal::settle near 1224.
- src/mutation.rs: check_counts currently calls B::limits near 20; settle_authorized loads Population near 201,
  authored count changes near 257/303, checks near 317/410, final writeback near 474.
  IMPORTANT C2.A entry_records near 207 captures current staged facts per settlement call;
  late incoming_candidates near 358 merges changed/proposed/entry IDs; uniqueness::reconcile_from near 454
  uses the SAME entry_records. Preserve repeated-settlement restored-source behavior and raw-delete rejection.
- src/causal.rs: write_output near 359 adjusts contract counts near 373/392; settle near 456;
  allocation/collision loop near 629, reservation increment near 647, Role/Reserved publication near 653.
- Signature sweep: rg -n 'population: &mut Population|_: &mut Population' src
  includes binding/native_slice/causal, models and test fixtures in relationships/uniqueness; do not miss unnamed args.
- src/local.rs: create_backend zero initialization near 291; open_backend near 350 currently trusts stored
  Population for public cardinality and checks model identity later; read_population near 1030 requires key.
- src/lifecycle.rs: reset initialization near 244; restore checks disposable image before publication.
- src/integrity.rs: check_populations near 41 re-reads B::limits; Snapshot::load near 375 requires Population
  near 397, always expects its key near 469, compares reserved near 603 and counts near 731.
  Snapshot.population must become truthful SOURCE-derived totals in BOTH modes for model checker consumers.
- src/native_codec.rs: CODEC kv-10; Key::Record tag 1, Reserved tag 9, Population tag 13.
- Raw initializers also exist in examples/s0_baseline.rs::initialize and examples/native_slice.rs;
  search ALL Rust/Node fixture writers for Key::Population or population rows, not only src/.
  Update current executable fixtures/checkers for the selected mode; never rewrite historical
  S0 manifests/evidence/checksums as fresh acceptance. Include raw chunked-Attempt examples in tests.
- tools/node/storage-check.mjs: checkBackupStructure options near 23; recognizes Population key near 294,
  but currently has no catalog-based accounting semantics. Existing physical claims must remain accurate.

## Independent open/integrity contract

Implement bounded source accounting inventory over native_kv Record prefix Included([1])..Excluded([2])
and Reserved prefix Included([9])..Excluded([10]) through existing Table::range. Decode every row/key;
validate record contract/type/header, checked u64 arithmetic and combined MAX_INVENTORY_ROWS (262144).
Reject overflow, incomplete/over-bound inventory and malformed keys inside scanned prefixes.
Check model/codec/mode identity BEFORE interpreting accounting data under that policy.
In the SAME read transaction, compare source-derived public count with public_records.len().
Tracked must have exact stored counts/reserved matching source totals; untracked must have absent Population.
Source totals still enforce configured limits independently. Opening cardinality is not exact membership proof.
Keep Snapshot's complete bounded native inventory, exact expected key set and independent Role↔Reserved checks;
branch expected Population membership by mode and reject extra Population in untracked, missing/wrong in tracked.
Keep full structural/membership inventory in integrity/restore, including same-cardinality public swaps.
Public len is metadata on redb; default storage::ReadView::len near 179 scans rows in pages (FDB O(public rows)).
State honest startup cost: O(source+reserved+public rows) on scan adapters, not universal constant-time open.
Node keeps 81920-row/64MiB/depth64 bounds. Without explicit prepared catalog/identity, report physical-only scope.
If semantic mode/count/cap validation is added, require that explicit authority and derive totals from source;
never infer visibility/ceilings from codec alone or synthesize absent counters in observations/backups.

## Staged implementation and acceptance

A. Add mode/identity/cached Limits and accumulator; propagate signatures, compile/type-check before test codegen.
B. Switch writers plus create/reset; implement source inventory and mode-aware open/full integrity together.
C. Update codec/catalog/Node fixtures and corruption/lifecycle tests; retain all C2 incoming/uniqueness regressions.
D. Reuse C3.0 real-adapter recorder, SAME fixture/scopes and precommit barrier; change expectations only after proof.
   Separately report Population, reader/contract epochs, AVL/business roots, authority/header and receipt conflicts.
   Uncapped output-producing creates in distinct readers AND invariant roots AND receipt slots: BOTH ORIGINAL
   attempts commit; repeat for deletes. Assert output/source facts, retained reservations/retired roles,
   exact independent inventory and zero Population writes. Retry success is not first-attempt success.
   Preserve same-partition epoch and same-business-root negative controls. Never alter epochs to make this pass.
E. Bounded public cap1 race from empty on real FDB: exactly one original commit; loser retries/revalidates to
   state_limit; independently derive final total1. Exercise output/reservation cap races and per-contract-only cap.
   Cover Some(0), public-only/output-only/reservation-only/per-contract-only tracked selection/boundaries;
   all omitted ceilings untracked, absent key through create/delete/reopen/reset/backup/restore.
F. Known rollback publishes no counters/identities. Unknown outcome resolves ORIGINAL receipt/allocation plan;
   exercise output creation and retained reservations through recovery/reopen, not only payload updates.
   Corrupt tracked missing/wrong counters; untracked extra key; unknown contract; cap excess; malformed prefix;
   missing/wrong Role/Reserved; missing/extra public entries; same-cardinality public swaps must be rejected
   at their stated open vs full-integrity/restore boundary before restore publication.

Run cargo fmt --check; type/lint-check all targets before expensive test codegen, then targeted changed tests,
full required Rust/Node regression suites, and explicit actual-adapter acceptance.
Run existing examples/g7_coordination: cargo run --example g7_coordination -- redb <fresh-dir>;
real FDB: cargo run --features foundationdb --example g7_coordination -- foundationdb <cluster-file>.
Confirm actual environment prerequisites; missing real FDB is unfinished acceptance, not a mock substitution.
Keep one Cargo owner; on constrained cloud use CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 as AGENTS advises.
Record exact commands/results, source provenance and limits in checkpoint/CONTEXT. Preserve historical checksums.
Finish means C3.1 accounting acceptance above, NOT full C3. Stop/commit according to the new user's authorization.
