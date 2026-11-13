# Node engine redesign — compact agent context

Status: **Execution authorized; JS-P1/JS-P2 accepted; JS-P3a internal primitives accepted; JS-P3b next.**
This packet is the redesign contract, not an implemented production replacement. Rust
`src/`, models, stores and historical evidence remain the executable baseline.
Experimental code belongs in [prototypes/node-engine](../../prototypes/node-engine/README.md).
Its accepted scope and evidence are checkpoint-specific; do not resume unrelated
historical native tasks automatically.

## Intent and selected direction

Preserve broad capability through a small composable core, not API/name parity.
Use established abstractions: **partitioned augmented AVL forest; ordered monoids;
declarative index contracts; explicit occurrences; transactional incremental
computation; reverse references; owner-DAG authorization; durable effect intent**.
Translate informal user terms into these contracts before implementing them.

- Node ESM ordinary functions, explicit catalog/transaction/state arguments; no
  application CLI duplicate, Python runtime, SurrealQL/event compiler or new DSL.
- One model authority: JSON Schemas + relation/index/dependency declarations +
  trusted ordinary function implementations. Prepare once; tooling consumes it.
- Separate reusable index **contract**, named index **view**, and model **binding**.
  Effective and created views can share a contract but must not share tree identity.
- A model emits zero/one/many occurrences into explicitly selected views. Multiple
  memberships `m`, including intentional repeated participation, are first-class.
  Do not infer every ancestor index, generate permutations, or duplicate rules per model.
- One generic linked augmented AVL; count is structural; rank is computed. Stable
  order ties, balancing and fixed-size monoid repair preserve logarithmic path work.
- Direct field dependencies and **key-range** dependencies are independent of time.
  Range folding is not subscriber stabbing. General reactive rank windows are deferred.
- Source/reference/index/derived/guard state settles and publishes atomically.
  Final-graph causality, unresolved outputs, zero-output producers and cycles need
  explicit treatment; an arbitrary recursive callback chain is not the contract.
- Tenant is an isolated namespace. Owner only: no reader field, reader index or
  inference. Preserve before/after owner checks and explicit summary disclosure.
  No universal population counter or automatic tenant-wide mutable root.
- Reference metadata derives reverse entries. 1:1 needs uniqueness; n:m uses a
  junction model. Declaring a relation does not require an ordered membership.
- Start with a transactional in-memory adapter and fixture authority. Persistent
  adapters, full identity/services and deployment have separate acceptance gates.
  KV adapters must meet the transaction contract; backend portability is not automatic.

## Read in this order

1. This page: compact intent, current status and ROI gates.
2. [Architecture](architecture.md): authoritative proposed semantics, unresolved choices.
3. [Capabilities](capabilities.md): source-backed preservation map and deferred scope.
4. [Checkpoints](checkpoints.md): implementation dependency order and acceptance witnesses.

Existing [index mathematics](../index-mathematics.md) remains the algebra reference;
its historical implementation-status sentences do not override this packet or
[current baseline context](../../CONTEXT.md). Independent
[research context](https://github.com/DivyeshVora79909/research/blob/81dc54f/notes/2026-11-06-ordered-index-context.md)
records the range/work-span/stabbing distinctions. Do not recopy historical evidence
as new acceptance or expand these four documents into parallel authorities.

## Proof and cost vocabulary

`h = O(log(n+1))`; point membership maintenance including rotations/summary repair
is `O(h)` for bounded summaries/comparison. Range fold `O(h)`; reporting `k` raw
occurrences `O(h+k)` work. Pruned frontier batches reduce dependent tree-read depth
to `O(h)` with adequate concurrency, not total bytes/work or guaranteed wall time.
Whole known-root summary is `O(1)` logical reads. Cascades, authorization, variable
summary size and discovery add costs; actual changed-membership work is `sum h_i`.
Bulk construction/checking/physical deletion may visit all source/index entries.
One-host measured processes are not multi-host/WAN performance evidence.

## ROI and working loop

1. State input/output/invariants and source provenance. Keep implemented, proposed,
   measured and assumed claims separate; unsupported claims remain open.
2. Use a flat source-derived oracle and counterexamples before integration. Summarize
   decisions here only when they affect another checkpoint; keep detail in its owner doc.
3. Reuse a maintained dependency where it removes more work than it introduces;
   one schema validator, not an abstraction over every validator library. Ajv is
   the selected candidate already used by current tools; JS-P1 checks compatibility.
4. Evaluate each slice against correctness, model-author effort and measured costs.
   Two models sharing a contract and three index views must need no engine edits.
   New monoids should add a bounded algebra module, not duplicate tree code.
5. Compare equivalent workloads, summaries and transaction guarantees. Record CPU,
   memory, gets, bytes, waits, changed keys and throughput with workload provenance.
   JIT/library availability is not proof of Rust-equivalent throughput or lower cost.
6. Stop widening a failing design. Repair the shared mechanism, narrow a claim, or
   record why an alternative is needed. Preserve successful independent evidence.

One to three days is a **prototype investigation timebox**, not a delivery promise.
JS-P1–JS-P5 completion demonstrates a local core and developer workflow, not a
deployable replacement. Existing Rust semantic fixtures are reusable evidence
specifications; their passing results are not Node results. No persisted Rust-format
compatibility is required; explicit recreation/import must be deliberate.

JS-P2 implements trusted atomic AVL mutation, point/select/range-fold reads and a
complete active-generation source-derived checker. See the [API guide](../../prototypes/node-engine/README.md)
and [JS-P2 evidence](../checkpoints/js-p2.json). This local serialized volatile adapter
does not establish authentication, persistent transactions or production capacity.

JS-P3 is split into internal staging/complete-cut/reverse-routing primitives (JS-P3a)
and catalog-integrated final-graph settlement (JS-P3b). JS-P3a passed 81 Node tests;
[its evidence](../checkpoints/js-p3a.json) does not establish a wired reactive engine.
Full catalog calculations still reject; see the [split gates](checkpoints.md).

## Continuation context

Baseline inspected: Next-Base `77a8fd2fb1cccf30b6af97f5aed0978dec8fe778`,
ReBase `270d875a6e97b276d9cf7876a9bb4666a21d0f53`, research `81dc54f`.
The latest Rust baseline records completed A1/A2; E3 objects and E5 full pipeline
remain outstanding. This planning pass did not rerun or certify those suites.

Handoff: read this packet, inspect current Git status and newer commits, and preserve
its capability/acceptance distinctions. The user has supplied implementation approval.
Continue after JS-P1 through dependency gates, using the actual environment's
available models and budget. Delegate disjoint work when useful; one owner integrates
and verifies each checkpoint. Do not invent subscription limits or impose a fixed
commit count on another agent. Report remaining gaps instead of claiming universal
logarithmic behavior, production readiness or lossless automatic migration.
