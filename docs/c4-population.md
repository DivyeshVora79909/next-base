# C4 adaptive population

`preparePopulation`, `propose`, `accept` and `reject` remain ordinary Node ESM
functions. The prepared native catalog supplies schemas, typed reference paths,
ordered uniqueness tuples and rule identities. Native mutation validation is the
authority; generation is a proposal, never a promise that concurrent or hidden
state permits its commit.

Counts request additional records per public contract. Existing rows supply typed
anchors, without consuming those quotas. Proposed anchors become available to
later rows of the same batch, but enter caller-owned committed pools only after
the exact bound operation receives its committed receipt. Selection adapts to
available anchors and remaining cardinality. It never increases parent quotas,
reduces a requested count or drops a constraint to make a population finish.

Catalog `uniqueness` tuples are checked against supplied source fields and earlier
proposal rows. Ordered pairs remain ordered; absent optional references omit the
whole tuple claim. Existing duplicate source tuples reject preparation. These
checks cover supplied facts, not inaccessible or concurrently created native rows.

Additional options on `preparePopulation(model, counts, options)` are:

- `maxAttempts`: candidate attempts per selected row/contract, default 32, maximum
  256. A newly generated anchor can make a blocked contract eligible again.
- `maxWork`: proposal work budget, default 100,000, maximum 1,000,000. Pool copies,
  selection, candidates, visited reference targets, claims, checks and solver calls
  consume work. This is a local effort limit, not a stored population counter or
  a native population ceiling.
- `references`: maps public contract names and declared reference paths to
  `{ maxFanout, distribution, skew }`. `maxFanout` bounds known occurrences for
  that child contract/path/target. Arrays charge every occurrence. `uniform`
  selects equal-weight candidates; `balanced` selects among least-used targets;
  `prefer_used` weights targets by `(usage + 1) ** skew` (default 1, range 0–8).
  Exhausted targets leave the candidate pool. Rule/solver retargets undergo the
  same final fanout check. These are requested population shapes, not additional
  native invariants. Existing usage is derived from supplied source fields;
  optional `referenceUsage` may include additional known consumers but may not
  undercount supplied facts.
- `checks`: maps a public contract to an ordinary callback
  `(fields, context, references, { contract, parents, proposed })`. Return an
  array of unsatisfied strings from that contract's native `rules`. The input
  includes actual final referenced parent rows and earlier proposed rows.
  Fields/context/metadata are detached and frozen. There is no expression parser
  or second rule catalog. Global/ledger checks still require explicit source
  context and a model-specific callback; the engine rechecks its own invariants.
- `solver`: an optional ordinary callback receives a frozen candidate with
  contract, fields, context, references, parents, proposed rows, unsatisfied
  obligations, seed, cursor and attempt. It may return replacement fields or
  null. A replacement passes the same schema, typed-pool, uniqueness, fanout and
  declared-rule checks. It cannot author owner metadata or bypass native writes.

Existing strategies and transforming `rules` callbacks remain supported. Strategy
context now includes `attempt` alongside an explicitly supplied clock. Custom
callbacks own their I/O and deadlines; the library bounds callback invocation
count, not execution of arbitrary caller code. A fresh context callback still runs
after reference selection, and the explicit clock is captured once per record
cursor. Proposal-local generated references may not yet be queryable remotely;
use the passed `parents`/`proposed` facts for local checks where appropriate.

Candidate Faker and selector streams derive from the explicit seed, contract,
cursor and attempt. A failed local call consumes no hidden generator state, so
the same inputs reproduce its candidates. A solver or context callback with
external nondeterminism must retain its original proposal and plan to reproduce
intent. A definite native rejection may release that proposal; an uncertain
response may not. Never regenerate an uncertain request with a new operation ID
or context. Receipt replay advances the population exactly once.

Every proposal includes a fingerprinted `generation` report with candidates,
work, remaining cardinality, attempted unsatisfied obligations and catalog rules
not checked locally. `state.lastReport` also records an exhausted run.
`population_unsatisfied` returns structured rule/reference/fanout/uniqueness
failures after bounded attempts. Missing anchors or completed quotas retain the
existing `stalled` result; work exhaustion is `population_budget`. A partial
proposal explicitly retains unmet counts; it is not reported as a complete
population. Schemas and final command bytes remain bounded, and all native
work, byte, authority and transaction guards still apply.

Verification uses source-derived witnesses for same-batch anchors, scalar and
ordered-pair uniqueness, optional tuples, exact parent bounds, array occurrence
counts, skew/fanout, bounded failure, deterministic regeneration and solver
rejection. The native redb case creates 12 Quantity sources in one signed atomic
mutation, checks exact derived values and a full backup from authored facts,
discards the first response and recovers the saved original receipt, and proves
an invalid overflowing graph leaves every backup table unchanged. Existing N3
Equipment/Quantity receipt and stale-context controls are also retained. See
the [source-bound checkpoint evidence](checkpoints/c4-population.json). Full
current-source acceptance passed 315 Rust and 193 Node tests, with no ignored or
skipped tests; the Node native cases used the freshly built redb host.
