# Current checkpoint

## C2.R — Owner-inclusive minimal readers

The selected policy is resource owner first, then recursively followed
`reader: true` references in catalog declaration preorder. Visit source records
and owners once. Eliminate any candidate strictly dominating another and select
the first survivor; incomparable survivors are permitted. Managed private outputs
inherit their ultimate producer's reader. No union or intersection ACL is inferred.

Implementation repairs reader-only dependents through final reverse references,
including when an upstream chosen reader and published value stay unchanged.
Initial payload-only edits do not scan irrelevant consumers. Writer/admin repair,
reader indexes, cursor epochs and independent source checks must agree.
`access::READER_POLICY` is part of every prepared model identity. Old model identities
require explicit recreation; storage codec remains native-slice-kv-9.
Verification: docs/checkpoints/c2-reader-policy.json.

Next is C1.4: compose authorized root member paging, same-snapshot hydration and
root/scope-bound cursors from the accepted trusted rank reader. Keep existing
UUID-page semantics. A summary declaration alone must not enumerate members;
explicit member capability permits raw topology/counts, not hidden IDs or bodies.
Signed cursors have integrity, not confidentiality. See docs/rank-reads.md.

## Selected foundation and authoring

Native Rust transaction/calculation harness over redb (local), with optional
FoundationDB and standalone SurrealKV adapters. SurrealKV is not SurrealDB.
Linked augmented AVL is selected; no B-tree page rewrite or SurrealDB wrapper.
One prepared model/catalog supplies schemas, typed references, index participation
and developer metadata. Preserve capability through breaking redesigns, not names.

Developer tools are ordinary Node ESM functions, imported from tools/node/index.mjs
and explicitly composed in the REPL or caller scripts. No parallel developer CLI,
new argument parser or wrappers for ordinary fs/loops/fetch/process operations.
Rust/Cargo and the native server/host retain their standard command interfaces.
Current population has typed pools, quotas, strategies/selectors, clock/context
callbacks and receipt-bound accept/reject; richer native cardinality/skew/global
constraint generation remains C4. Do not claim legacy feature parity from names.

## Remaining core gates

- C1.1 structural sizes/count-only family, C1.2 same-view storage batches and C1.3
  trusted rank windows are accepted. Public member paging is still C1.4.
- C2 retains catalog 1:1/pair uniqueness and final-graph relationship predicates.
  Parent/child order comparisons must register parent inputs and revalidate parent
  edits, not only child insertion. Local JSON Schema alone is insufficient.
- C3 access indexes are explicitly opted-in resource/tenant/reader-or-owner/order
  streams. Merge current authorized reader streams; owner controls writes, reader
  controls disclosure. Tenant is a strict namespace. Tenant-only indexes are optional.
  Today's public index is reader/contract/UUID, not the proposed chronological trees.
- Non-time keys already work in native ordered reads, but reactive query/subscriber
  cuts remain TimeRange/TimeBound. C3 must generalize types/routing deliberately.
- Population capacity accounting still coordinates creates/deletes across roots.
  Removing unnecessary unbounded-model coordination needs explicit mode/identity,
  source-derived reopen/integrity totals and real concurrency/recovery witnesses.
  Preserve reservation identities and required reader/contract epochs/business guards.
- C4 adaptive valid population must share the catalog, expose constraints/unsatisfied
  rules and preserve deterministic seeds/receipts. Optional solver hooks cannot make
  arbitrary global validity free. C5 resumable live invalidations remain optional.

## Server extensions and evidence boundaries

E0 service contracts are planned; E1–E5 credentials, EmailSend with independent
Resend/Brevo bindings, object lifecycle and optional recurrence are not implemented.
Reuse committed intent/start/fence/fact/application and unknown-outcome recovery.
Unrelated external provider I/O follows commit, outside the native transaction.
Do not mandate public v1/v2 operations; accepted jobs pin semantics/provider/account.

Default HTTP uses Axum/Tokio. TiKV, frontend, live providers and production accounting
are deferred. Local one-host FoundationDB campaigns are not multi-host performance
proof. Full inventories/tool resource budgets do not imply unlimited scale acceptance.

C0 imported ReBase 270d875/rebase-next without changing the original repository.
Application: https://github.com/DivyeshVora79909/next-base
Independent research: https://github.com/DivyeshVora79909/research
PROVENANCE.json and docs/checkpoints retain exact historical scopes. Do not rewrite
old fingerprints as new acceptance. Application-linked N/S0 instructions stay here.

A fresh agent reads AGENTS.md, this file and the relevant roadmap contract, inspects
Git, chooses a coherent authorized slice, begins with an independent counterexample,
then implements, verifies and records the next dependency. Commit/push verified
checkpoints within the user's actual authorization. Conversation-specific pauses or
usage budgets are not a standing commit-count policy for other agents.
