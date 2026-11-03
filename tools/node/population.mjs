import { createGeneratorSync } from 'json-schema-faker';
import { createHash } from 'node:crypto';
import { validateOperationPlan } from './private/operation-plan.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DEFINITE_NO_COMMIT = new Set([
  'invalid_input', 'forbidden', 'not_found', 'unavailable_reference', 'already_exists',
  'stale_version', 'transaction_conflict', 'transaction_aborted', 'transaction_limit',
  'model_mismatch', 'invariant', 'feedback', 'inexact', 'operation_conflict',
  'work_limit', 'state_limit', 'receipt_limit', 'request_limit', 'overflow',
]);

/** Prepare reusable population metadata from an already prepared native model. */
export function preparePopulation(model, counts, options = {}) {
  if (!model || !model.catalog || typeof model.validate !== 'function') {
    throw new TypeError('model must be a prepared native model');
  }
  const catalog = cloneJson(model.catalog, 'model catalog');
  const limits = catalog.capabilities?.limits;
  if (!isRecord(limits) || !Number.isSafeInteger(limits.commands) || limits.commands < 1 || limits.commands > 64) {
    throw new TypeError('native catalog must publish a valid command limit');
  }
  if (!isRecord(counts)) throw new TypeError('counts must be an object keyed by public contract name');
  const contracts = new Map();
  const codes = new Map();
  for (const entry of catalog.contracts ?? []) {
    if (entry.visibility !== 'public') continue;
    if (typeof entry.name !== 'string' || !Number.isSafeInteger(entry.code) || contracts.has(entry.name) || codes.has(entry.code)) {
      throw new TypeError('public catalog contracts need unique names and integer codes');
    }
    const schema = entry.schema ?? entry.input_schema;
    if (!isRecord(schema)) throw new TypeError(`public contract ${entry.name} has no input schema`);
    contracts.set(entry.name, deepFreeze({ ...entry, schema, references: entry.references ?? [],
      uniqueness: entry.uniqueness ?? [], rules: entry.rules ?? [] }));
    codes.set(entry.code, entry.name);
  }
  if (contracts.size === 0) throw new TypeError('native catalog has no public contracts');
  const quotas = Object.fromEntries([...contracts.keys()].map(name => [name, counts[name] ?? 0]));
  for (const [name, value] of Object.entries(counts)) {
    if (!contracts.has(name)) throw new TypeError(`unknown or private contract in counts: ${name}`);
    nonnegativeInteger(value, `count for ${name}`);
  }
  const batchSize = options.batchSize ?? 1;
  nonnegativeInteger(batchSize, 'batchSize');
  if (batchSize < 1 || batchSize > limits.commands) throw new TypeError('batchSize exceeds native command limit');
  const seed = options.seed;
  if (!(typeof seed === 'string' || Number.isSafeInteger(seed))) throw new TypeError('seed must be a string or safe integer');
  for (const key of ['strategies', 'rules', 'checks', 'priorities', 'references']) {
    if (options[key] !== undefined && !isRecord(options[key])) throw new TypeError(`${key} must be an object`);
    for (const name of Object.keys(options[key] ?? {})) if (!contracts.has(name)) throw new TypeError(`${key} contains unknown public contract ${name}`);
  }
  for (const [name, fn] of Object.entries(options.strategies ?? {})) if (typeof fn !== 'function') throw new TypeError(`strategy for ${name} must be callable`);
  for (const [name, fn] of Object.entries(options.rules ?? {})) if (typeof fn !== 'function') throw new TypeError(`rule for ${name} must be callable`);
  for (const [name, fn] of Object.entries(options.checks ?? {})) if (typeof fn !== 'function') throw new TypeError(`check for ${name} must be callable`);
  for (const [name, weight] of Object.entries(options.priorities ?? {})) nonnegativeInteger(weight, `priority for ${name}`);
  for (const key of ['selectReference', 'selectContract', 'solver']) if (options[key] !== undefined && typeof options[key] !== 'function') throw new TypeError(`${key} must be callable`);
  const maxAttempts = options.maxAttempts ?? 32;
  const maxWork = options.maxWork ?? 100_000;
  for (const [name, value, ceiling] of [['maxAttempts', maxAttempts, 256], ['maxWork', maxWork, 1_000_000]]) {
    if (!Number.isSafeInteger(value) || value < 1 || value > ceiling) throw new TypeError(`${name} must be an integer from 1 to ${ceiling}`);
  }
  const referencePolicies = prepareReferencePolicies(options.references ?? {}, contracts);
  for (const contract of contracts.values()) for (const unique of contract.uniqueness) {
    if (!Number.isSafeInteger(unique.code) || unique.code < 1 || !Array.isArray(unique.reference_slots)
      || !unique.reference_slots.length || unique.reference_slots.some(slot => !contract.references.some(ref => ref.slot === slot))) {
      throw new TypeError(`Invalid catalog uniqueness declaration for ${contract.name}`);
    }
  }
  if (options.clock !== undefined && typeof options.clock !== 'function') cloneJson(options.clock, 'clock');
  if (options.context !== undefined && typeof options.context !== 'function') cloneJson(options.context, 'context');
  const pools = Object.fromEntries([...contracts.keys()].map(name => [name, new Map()]));
  const poolIds = Object.fromEntries([...contracts.keys()].map(name => [name, []]));
  const identities = new Set();
  for (const [name, rows] of Object.entries(options.existing ?? {})) {
    if (!contracts.has(name) || !Array.isArray(rows)) throw new TypeError(`existing pool must name a public contract: ${name}`);
    for (const row of rows) {
      if (!isRecord(row) || row.contract !== name || typeof row.id !== 'string' || !UUID.test(row.id) || identities.has(row.id)) {
        throw new TypeError('existing rows need unique canonical IDs and their declared public contract');
      }
      if (row.fields !== undefined && !model.validate(name, row.fields).valid) throw new TypeError(`existing projection does not match ${name}`);
      const stored = Object.freeze({ id: row.id, contract: name, ...(row.fields === undefined ? {} : { fields: cloneJson(row.fields, 'existing fields') }) });
      pools[name].set(row.id, stored);
      poolIds[name].push(row.id);
      identities.add(row.id);
    }
  }
  const usage = validateInitialUsage(options.referenceUsage ?? {}, contracts);
  const knownUsage = {};
  const uniqueClaims = new Set();
  for (const contract of contracts.values()) for (const row of pools[contract.name].values()) {
    if (!row.fields) continue;
    for (const reference of contract.references) for (const id of getPathValues(row.fields, reference.field)) {
      const target = [...contracts.values()].find(item => reference.targets.includes(item.code) && pools[item.name].has(id));
      if (target) increment(knownUsage, usageKey(contract.name, reference.field, target.name, id));
    }
    for (const claim of claimsFor(contract, row.fields)) {
      if (uniqueClaims.has(claim.key)) throw new TypeError(`Existing source facts violate ${contract.name} uniqueness ${claim.code}`);
      uniqueClaims.add(claim.key);
    }
  }
  for (const [key, value] of Object.entries(knownUsage)) {
    if (Object.hasOwn(usage, key) && usage[key] < value) throw new TypeError('referenceUsage undercounts supplied source facts');
    usage[key] ??= value;
  }
  return {
    model, catalog, contracts, codes, quotas, accepted: Object.fromEntries([...contracts.keys()].map(name => [name, 0])),
    pools, poolIds, identities, seed, cursor: 0, batchSize, priorities: { ...(options.priorities ?? {}) },
    strategies: { ...(options.strategies ?? {}) }, rules: { ...(options.rules ?? {}) }, checks: { ...(options.checks ?? {}) },
    maxAttempts, maxWork, referencePolicies, uniqueClaims, solver: options.solver,
    selectReference: options.selectReference, selectContract: options.selectContract,
    clock: options.clock, context: options.context, referenceUsage: usage, pending: null,
    lastTarget: options.target === undefined ? null : cloneJson(options.target, 'target'), proposing: false,
  };
}

/** Produce a detached bounded proposal. It never submits or retries a mutation. */
export async function propose(state, context = state?.context, options = {}) {
  assertState(state);
  if (state.pending || state.proposing) throw populationError('proposal_pending', 'Accept or reject the current pending proposal first');
  if (context === undefined || (typeof context !== 'function' && !isRecord(context))) {
    throw populationError('missing_context', 'Provide a fresh context mapping or callback');
  }
  state.proposing = true;
  try { return await buildProposal(state, context, options); }
  finally { state.proposing = false; }
}

async function buildProposal(state, context, { maxCommands = state.batchSize } = {}) {
  nonnegativeInteger(maxCommands, 'maxCommands');
  if (maxCommands < 1 || maxCommands > state.batchSize) throw populationError('invalid_batch', 'maxCommands exceeds prepared batchSize');
  const remaining = Object.fromEntries([...state.contracts.keys()].map(name => [name, state.quotas[name] - state.accepted[name]]));
  const report = { candidates: 0, work: 0, unsatisfied: [], uncheckedRules: [] };
  const snapshot = status => ({ status, ...cloneJson(report, 'generation report'), remaining: { ...remaining } });
  const charge = (amount = 1) => {
    if (!Number.isSafeInteger(amount) || amount < 0 || report.work + amount > state.maxWork) {
      state.lastReport = snapshot('budget_exhausted');
      throw populationError('population_budget', 'Population proposal exhausted its explicit work budget', state.lastReport);
    }
    report.work += amount;
  };
  const failed = (contract, kind, rule) => {
    const previous = report.unsatisfied.find(item => item.contract === contract && item.kind === kind && item.rule === rule);
    if (previous) previous.attempts += 1;
    else report.unsatisfied.push({ contract, kind, rule, attempts: 1 });
  };
  // Only these local maps see tentative rows. Receipt acceptance publishes pools.
  const pools = {};
  for (const [name, rows] of Object.entries(state.pools)) {
    charge(rows.size);
    pools[name] = new Map(rows);
  }
  const usage = { ...state.referenceUsage };
  const claims = new Set(state.uniqueClaims);
  charge(Object.keys(usage).length + claims.size);
  const additions = [];
  const commands = [];
  const addedUsage = {};
  const blocked = new Set();
  const selectionRng = seededRandom(state.seed, state.cursor);
  const clockCache = new Map();
  const getClock = cursor => {
    if (state.clock === undefined) return undefined;
    if (!clockCache.has(cursor)) clockCache.set(cursor, cloneJson(typeof state.clock === 'function' ? state.clock(cursor) : state.clock, 'clock value'));
    return cloneJson(clockCache.get(cursor), 'clock value');
  };
  while (commands.length < maxCommands) {
    charge(state.contracts.size);
    const eligible = [...state.contracts.values()].filter(contract => remaining[contract.name] > 0
      && !blocked.has(contract.name) && (state.priorities[contract.name] ?? 1) > 0
      && prerequisitesAvailable(state, contract, pools));
    if (!eligible.length) break;
    const custom = await state.selectContract?.(Object.freeze(eligible.map(x => x.name)), Object.freeze({ ...remaining }), selectionRng);
    const name = custom ?? weightedPick(eligible, eligible.map(x => remaining[x.name] * (state.priorities[x.name] ?? 1)), selectionRng).name;
    if (!eligible.some(contract => contract.name === name)) throw populationError('invalid_selection', 'selectContract chose an ineligible contract');
    const contract = state.contracts.get(name);
    const cursor = state.cursor + commands.length;
    if (!Number.isSafeInteger(cursor + 1)) throw populationError('cursor_exhausted', 'Population cursor exhausted');
    const id = deterministicId(state.seed, cursor);
    if (state.identities.has(id) || additions.some(row => row.id === id)) throw populationError('identity_collision', 'Deterministic proposal ID collides with a known identity');
    let accepted;
    for (let attempt = 0; attempt < state.maxAttempts; attempt += 1) {
      charge();
      report.candidates += 1;
      const rng = seededRandom(state.seed, `${contract.code}:${cursor}:${attempt}`);
      const info = { attempt };
      const clock = getClock(cursor);
      if (clock !== undefined) info.clock = clock;
      let fields;
      if (state.strategies[name]) fields = await state.strategies[name](cloneJson(contract.schema, 'schema'), state.seed, cursor, frozenCopy(info));
      else {
        try {
          // Cursor/attempt seeds make local failure and replay independent of
          // mutable Faker generator consumption in other proposals or states.
          fields = createGeneratorSync({ seed: seedNumber(state.seed, `${contract.code}:${cursor}:${attempt}`),
            alwaysFakeOptionals: true, useDefaultValue: true, maxDepth: 8 }).generate(contract.schema);
        } catch (cause) { throw populationError('generation_unsupported', `Schema generation for ${name} failed; provide an explicit strategy`, { cause }); }
      }
      if (!isRecord(fields)) throw populationError('invalid_generated_shape', `Base values for ${name} must be an object`);
      if (Buffer.byteLength(JSON.stringify(fields)) > 65_536) throw populationError('proposal_too_large', 'Generated fields exceed 65536 bytes');
      fields = cloneJson(fields, 'generated fields');
      const selected = {};
      // Reserve each selected occurrence only for this candidate. Final rule/solver
      // fields are independently assessed against the accepted proposal usage below.
      const tentativeUsage = { ...usage };
      charge(Object.keys(usage).length);
      let unavailable = false;
      for (const reference of contract.references) {
        const path = reference.field;
        const current = getPathValues(fields, path);
        if (reference.optional && (!current.length || current.every(value => value === null))) continue;
        const policy = state.referencePolicies[name]?.[path] ?? {};
        const targets = [...state.contracts.values()].filter(target => (reference.targets ?? []).includes(target.code) && pools[target.name].size > 0);
        const occurrences = [];
        setDeclaredPath(fields, path, value => { occurrences.push(value); return value; });
        const replacements = [];
        for (const value of occurrences) {
          if (reference.optional && value === null) { replacements.push(null); continue; }
          const candidates = [];
          for (const target of targets) for (const row of pools[target.name].values()) {
            charge();
            const used = tentativeUsage[usageKey(name, path, target.name, row.id)] ?? 0;
            if (policy.maxFanout === undefined || used < policy.maxFanout) candidates.push({ target: target.name, row, used });
          }
          if (!candidates.length) {
            failed(name, targets.length ? 'fanout' : 'reference', path);
            unavailable = true;
            break;
          }
          let picked;
          if (state.selectReference) {
            const view = Object.fromEntries(targets.map(target => [target.name, candidates.filter(item => item.target === target.name).map(item => item.row)]).filter(([, rows]) => rows.length));
            picked = await state.selectReference(name, path, frozenCopy(view), Object.freeze({ ...tentativeUsage }), rng, frozenCopy(typeof context === 'function' ? {} : context));
          } else {
            let available = candidates;
            if (policy.distribution === 'balanced') {
              const minimum = candidates.reduce((minimum, item) => Math.min(minimum, item.used), Infinity);
              available = candidates.filter(item => item.used === minimum);
            }
            const chosen = weightedPick(available, available.map(item => policy.distribution === 'prefer_used' ? (item.used + 1) ** (policy.skew ?? 1) : 1), rng);
            picked = [chosen.target, chosen.row.id];
          }
          if (!Array.isArray(picked) || picked.length !== 2 || !candidates.some(item => item.target === picked[0] && item.row.id === picked[1])) {
            throw populationError('invalid_selection', `Reference selector chose an incompatible or exhausted pool for ${name}.${path}`);
          }
          replacements.push(picked[1]);
          increment(tentativeUsage, usageKey(name, path, picked[0], picked[1]));
        }
        if (unavailable) break;
        let occurrence = 0;
        setDeclaredPath(fields, path, () => replacements[occurrence++]);
        const present = replacements.filter(value => value !== null);
        if (present.length) selected[path] = present.length === 1 ? present[0] : present;
      }
      if (unavailable) continue;
      const fresh = typeof context === 'function' ? await context(name, frozenCopy(selected), cursor) : cloneJson(context, 'context');
      if (!isRecord(fresh)) throw populationError('invalid_context', 'Context callback must return a mapping');
      const withClock = { ...fresh };
      if (clock !== undefined) {
        if (Object.hasOwn(withClock, 'clock')) throw populationError('duplicate_clock', 'clock must come from the explicit clock option');
        withClock.clock = clock;
      }
      if (state.rules[name]) fields = await state.rules[name](cloneJson(fields, 'rule fields'), frozenCopy(withClock), frozenCopy(selected), frozenCopy(info));
      let candidate = await assessCandidate(state, contract, fields, withClock, pools, usage, claims, additions, charge);
      for (const issue of candidate.issues) failed(name, issue.kind, issue.rule);
      if (candidate.issues.length && state.solver) {
        charge();
        const replacement = await state.solver(frozenCopy({ contract, fields, context: withClock,
          references: candidate.references, parents: candidate.parents, proposed: additions,
          unsatisfied: candidate.issues, seed: state.seed, cursor, attempt }));
        if (replacement !== null && replacement !== undefined) {
          candidate = await assessCandidate(state, contract, replacement, withClock, pools, usage, claims, additions, charge);
          for (const issue of candidate.issues) failed(name, issue.kind, issue.rule);
        }
      }
      if (candidate.issues.length) continue;
      accepted = candidate;
      break;
    }
    if (!accepted) { blocked.add(name); continue; }
    const fields = accepted.fields;
    if (!state.checks[name]) for (const rule of contract.rules) {
      if (!report.uncheckedRules.some(item => item.contract === name && item.rule === rule)) report.uncheckedRules.push({ contract: name, rule });
    }
    commands.push({ op: 'create', id, contract: contract.code, fields });
    additions.push({ id, contract: name, fields, references: accepted.references });
    pools[name].set(id, deepFreeze({ id, contract: name, fields: cloneJson(fields, 'tentative fields') }));
    for (const [key, amount] of Object.entries(accepted.usage)) {
      increment(usage, key, amount);
      increment(addedUsage, key, amount);
    }
    for (const claim of accepted.claims) claims.add(claim.key);
    remaining[name] -= 1;
    // A new anchor or source may satisfy a previously blocked contract.
    blocked.clear();
  }
  if (!commands.length) {
    if (!report.unsatisfied.length) for (const contract of state.contracts.values()) {
      if (remaining[contract.name] <= 0) continue;
      if ((state.priorities[contract.name] ?? 1) === 0) failed(contract.name, 'selection', 'zero priority');
      for (const ref of contract.references) if (!ref.optional && ![...state.contracts.values()].some(target => ref.targets.includes(target.code) && pools[target.name].size)) failed(contract.name, 'reference', ref.field);
    }
    state.lastReport = snapshot('unsatisfied');
    throw populationError(report.candidates ? 'population_unsatisfied' : 'stalled', 'No candidate satisfies the remaining population obligations', state.lastReport);
  }
  if (Buffer.byteLength(JSON.stringify(commands)) > 65_536) throw populationError('proposal_too_large', 'Proposal exceeds 65536 command bytes');
  state.lastReport = snapshot('proposed');
  const proposal = { commands, returning: additions.slice(0, 32).map(row => row.id), additions,
    usage: addedUsage, startCursor: state.cursor, endCursor: state.cursor + additions.length,
    generation: snapshot('proposed') };
  proposal.digest = proposalFingerprint(proposal);
  state.pending = makePending(state, proposal);
  return proposal;
}

async function assessCandidate(state, contract, value, context, pools, usage, claims, proposed, charge) {
  charge();
  const issues = [];
  const references = {};
  const parents = {};
  const addedUsage = {};
  if (!isRecord(value)) return { issues: [{ kind: 'schema', rule: 'object' }], references, parents };
  if (Buffer.byteLength(JSON.stringify(value)) > 65_536) throw populationError('proposal_too_large', 'Candidate fields exceed 65536 bytes');
  const fields = cloneJson(value, 'candidate fields');
  if (!state.model.validate(contract.name, fields).valid) return { fields, issues: [{ kind: 'schema', rule: contract.name }], references, parents };
  for (const reference of contract.references) {
    const path = reference.field;
    const values = getPathValues(fields, path);
    parents[path] = [];
    if (!values.length && !reference.optional && !path.includes('[]') && !path.includes('[*]')) issues.push({ kind: 'reference', rule: path });
    const selected = [];
    for (const id of values) {
      charge();
      if (id === null && reference.optional) continue;
      const target = [...state.contracts.values()].find(item => reference.targets.includes(item.code) && pools[item.name].has(id));
      if (!target) { issues.push({ kind: 'reference', rule: path }); continue; }
      selected.push(id);
      parents[path].push(pools[target.name].get(id));
      const key = usageKey(contract.name, path, target.name, id);
      increment(addedUsage, key);
      const max = state.referencePolicies[contract.name]?.[path]?.maxFanout;
      if (max !== undefined && (usage[key] ?? 0) + addedUsage[key] > max) issues.push({ kind: 'fanout', rule: path });
    }
    if (selected.length) references[path] = selected.length === 1 ? selected[0] : selected;
  }
  const candidateClaims = claimsFor(contract, fields);
  for (const claim of candidateClaims) {
    charge();
    if (claims.has(claim.key)) issues.push({ kind: 'uniqueness', rule: String(claim.code) });
  }
  if (!issues.length && state.checks[contract.name]) {
    charge();
    const failures = await state.checks[contract.name](frozenCopy(fields), frozenCopy(context), frozenCopy(references),
      frozenCopy({ contract, parents, proposed }));
    if (!Array.isArray(failures) || failures.some(rule => typeof rule !== 'string' || !contract.rules.includes(rule))) {
      throw populationError('invalid_check', `Checks must return unsatisfied rules declared by ${contract.name}`);
    }
    for (const rule of new Set(failures)) issues.push({ kind: 'rule', rule });
  }
  return { fields, issues, references, parents, usage: addedUsage, claims: candidateClaims };
}

/** Advance committed population state after validating the native receipt. */
export function accept(state, proposal, plan, receipt) {
  const pending = bound(state, proposal, plan);
  if (!isRecord(receipt) || receipt.status !== 'committed' || !isRecord(receipt.result)
    || receipt.result.operation_id !== plan.request.operation_id
    || !UUID.test(receipt.result.revision ?? '') || !Array.isArray(receipt.result.records)) {
    throw populationError('receipt_invalid', 'accept requires the client committed receipt for the exact operation ID');
  }
  const nativeReceipt = receipt.result;
  const returned = nativeReceipt.records.map(row => row?.id);
  if (returned.length !== proposal.returning.length || returned.some((id, i) => id !== proposal.returning[i])) {
    throw populationError('receipt_invalid', 'Receipt returned IDs differ from the exact ordered request');
  }
  for (const row of nativeReceipt.records) if (!isRecord(row) || typeof row.id !== 'string' || (row.record !== undefined && row.record !== null && !isRecord(row.record))) {
    throw populationError('receipt_invalid', 'Receipt records have an invalid projection shape');
  }
  for (const addition of proposal.additions) {
    const name = addition.contract;
    state.pools[name].set(addition.id, Object.freeze({ id: addition.id, contract: name, fields: cloneJson(addition.fields, 'accepted fields') }));
    state.poolIds[name].push(addition.id);
    state.identities.add(addition.id);
    state.accepted[name] += 1;
    for (const claim of claimsFor(state.contracts.get(name), addition.fields)) state.uniqueClaims.add(claim.key);
  }
  for (const [key, amount] of Object.entries(proposal.usage)) state.referenceUsage[key] = (state.referenceUsage[key] ?? 0) + amount;
  state.cursor = proposal.endCursor;
  state.lastReceipt = nativeReceipt.operation_id;
  state.lastTarget ??= cloneJson(plan.target, 'plan target');
  state.pending = null;
  return state;
}

/** Release only an unbound proposal or an exact plan with a definite native rejection. */
export function reject(state, proposal, plan, outcome) {
  assertState(state);
  const pending = state.pending;
  if (!pending || pending.proposal !== proposal || pending.digest !== proposalFingerprint(proposal)) throw populationError('pending_mismatch', 'Only the exact current proposal may be rejected');
  if (plan === undefined && outcome === undefined) {
    if (pending.plan) throw populationError('plan_bound', 'A bound plan requires a definite no-commit server outcome');
    state.cursor = proposal.endCursor;
    state.pending = null;
    return state;
  }
  bound(state, proposal, plan);
  const kind = outcome?.code ?? outcome?.kind;
  if (outcome?.name !== 'RpcError' || outcome?.httpStatus !== 200 || !DEFINITE_NO_COMMIT.has(kind)
    || outcome?.outcomeUnknown === true || ['outcome_unknown', 'operation_expired', 'not_observed'].includes(kind)) {
    throw populationError('outcome_uncertain', 'Unknown outcomes retain the exact pending proposal and plan');
  }
  state.cursor = proposal.endCursor;
  state.pending = null;
  return state;
}

function makePending(state, proposal) {
  const proposalDigest = proposalFingerprint(proposal);
  let planSnapshot = null;
  const pending = { proposal, digest: proposalDigest };
  Object.defineProperty(pending, 'plan', {
    enumerable: true,
    get() { return planSnapshot && cloneJson(planSnapshot, 'bound plan'); },
    set(value) {
      if (proposalDigest !== proposalFingerprint(pending.proposal) || pending.proposal.digest !== proposalDigest) throw populationError('proposal_changed', 'Proposal changed before plan binding');
      validatePlanBinding(state, proposal, value);
      const encoded = cloneJson(value, 'plan');
      if (planSnapshot && digest(planSnapshot) !== digest(encoded)) throw populationError('plan_rebound', 'Pending plan binding is write-once');
      planSnapshot ??= deepFreeze(encoded);
    },
  });
  return Object.freeze(pending);
}

function validatePlanBinding(state, proposal, plan) {
  try { validateOperationPlan(plan); }
  catch (cause) { throw populationError('plan_invalid', 'Bind a complete client operation plan', { cause }); }
  if (plan.request.model !== state.catalog.model || plan.target.model !== state.catalog.model || !UUID.test(plan.request.operation_id ?? '')
    || digest(plan.request.commands) !== digest(proposal.commands) || digest(plan.request.returning) !== digest(proposal.returning)) {
    throw populationError('plan_mismatch', 'Plan model, operation ID, commands or returning IDs differ from proposal');
  }
  if (state.lastTarget && digest(plan.target) !== digest(state.lastTarget)) throw populationError('target_mismatch', 'Plan target differs from previously committed target');
}

function bound(state, proposal, plan) {
  assertState(state);
  const pending = state.pending;
  if (!pending || pending.proposal !== proposal || pending.digest !== proposalFingerprint(proposal) || proposal.digest !== pending.digest) throw populationError('pending_mismatch', 'Proposal is not the exact intact pending proposal');
  const boundPlan = pending.plan;
  if (!boundPlan || digest(boundPlan) !== digest(plan)) throw populationError('plan_unbound', 'Bind the exact plan on state.pending.plan before submission');
  validatePlanBinding(state, proposal, plan);
  return pending;
}

function validateInitialUsage(usage, contracts) {
  if (!isRecord(usage)) throw new TypeError('referenceUsage must be an object');
  const result = {};
  for (const [key, value] of Object.entries(usage)) {
    nonnegativeInteger(value, `referenceUsage ${key}`);
    const parts = key.split('\0');
    const [child, path, parent, id] = parts;
    if (parts.length !== 4 || !contracts.has(child) || !contracts.has(parent) || typeof path !== 'string' || !UUID.test(id ?? '')) throw new TypeError('referenceUsage keys must encode child, path, parent and UUID');
    const declared = contracts.get(child).references.some(ref => ref.field === path && ref.targets.includes(contracts.get(parent).code));
    if (!declared) throw new TypeError(`referenceUsage is not declared by ${child}.${path}`);
    result[key] = value;
  }
  return result;
}

function prepareReferencePolicies(policies, contracts) {
  const result = cloneJson(policies, 'reference policies');
  for (const [name, fields] of Object.entries(result)) {
    if (!isRecord(fields)) throw new TypeError(`reference policies for ${name} must be an object`);
    for (const [field, policy] of Object.entries(fields)) {
      if (!contracts.get(name).references.some(ref => ref.field === field)) throw new TypeError(`Unknown declared reference ${name}.${field}`);
      if (!isRecord(policy) || Object.keys(policy).some(key => !['maxFanout', 'distribution', 'skew'].includes(key))) throw new TypeError('Invalid reference policy');
      if (policy.maxFanout !== undefined) nonnegativeInteger(policy.maxFanout, 'maxFanout');
      if (policy.distribution !== undefined && !['uniform', 'balanced', 'prefer_used'].includes(policy.distribution)) throw new TypeError('Unknown reference distribution');
      if (policy.skew !== undefined && (!Number.isFinite(policy.skew) || policy.skew < 0 || policy.skew > 8 || policy.distribution !== 'prefer_used')) throw new TypeError('skew must be from 0 to 8 with prefer_used distribution');
    }
  }
  return deepFreeze(result);
}
function claimsFor(contract, fields) {
  const claims = [];
  for (const constraint of contract.uniqueness) {
    const tuple = [];
    for (const slot of constraint.reference_slots) {
      const ref = contract.references.find(ref => ref.slot === slot);
      const values = getPathValues(fields, ref.field);
      if (!values.length || values[0] === null) break;
      if (values.length !== 1 || typeof values[0] !== 'string' || !UUID.test(values[0])) {
        throw populationError('invalid_catalog', `Uniqueness requires scalar reference ${contract.name}.${ref.field}`);
      }
      tuple.push(values[0]);
    }
    if (tuple.length === constraint.reference_slots.length) claims.push({ code: constraint.code, key: JSON.stringify([contract.code, constraint.code, tuple]) });
  }
  return claims;
}
function usageKey(child, path, parent, id) { return `${child}\0${path}\0${parent}\0${id}`; }
function increment(map, key, amount = 1) {
  const next = (map[key] ?? 0) + amount;
  if (!Number.isSafeInteger(next)) throw populationError('usage_exhausted', 'Reference usage exhausted');
  map[key] = next;
}
function prerequisitesAvailable(state, contract, pools) {
  return contract.references.every(ref => ref.optional || [...state.contracts.values()].some(target => ref.targets.includes(target.code) && pools[target.name].size));
}
function weightedPick(items, weights, rng) {
  const total = weights.reduce((sum, weight) => sum + weight, 0);
  if (!(total > 0) || !Number.isFinite(total)) throw populationError('stalled', 'No positive selection weight remains');
  let choice = rng() * total;
  for (let i = 0; i < items.length; i += 1) if ((choice -= weights[i]) < 0) return items[i];
  return items.at(-1);
}
function seededRandom(seed, cursor) {
  let state = seedNumber(seed, cursor) || 1;
  return () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return (state >>> 0) / 0x1_0000_0000; };
}
function seedNumber(seed, cursor) { return Number.parseInt(createHash('sha256').update(`${typeof seed}:${seed}:${cursor}`).digest('hex').slice(0, 8), 16); }
function deterministicId(seed, cursor) { const hex = createHash('sha256').update(`rebase-population:${typeof seed}:${seed}:${cursor}`).digest('hex').slice(0, 32); return `${hex.slice(0,8)}-${hex.slice(8,12)}-5${hex.slice(13,16)}-a${hex.slice(17,20)}-${hex.slice(20)}`; }
function digest(value) { return createHash('sha256').update(JSON.stringify(value)).digest('hex'); }
function proposalFingerprint(proposal) { const { digest: _ignored, ...content } = proposal; return digest(content); }
function cloneJson(value, label) { assertJson(value, label); return JSON.parse(JSON.stringify(value)); }
function assertJson(value, label, seen = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number') { if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) throw new TypeError(`${label} contains an unsafe number`); return; }
  if (Array.isArray(value)) { if (seen.has(value)) throw new TypeError(`${label} is cyclic`); seen.add(value); for (const item of value) assertJson(item, label, seen); seen.delete(value); return; }
  if (!isRecord(value) || seen.has(value)) throw new TypeError(`${label} must be finite JSON`);
  seen.add(value); for (const [key, item] of Object.entries(value)) { if (item === undefined || typeof item === 'function' || typeof item === 'bigint' || typeof item === 'symbol') throw new TypeError(`${label} must be finite JSON`); assertJson(item, label, seen); } seen.delete(value);
}
function isRecord(value) { if (!value || typeof value !== 'object' || Array.isArray(value)) return false; const proto = Object.getPrototypeOf(value); return proto === Object.prototype || proto === null; }
function nonnegativeInteger(value, label) { if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${label} must be a nonnegative safe integer`); }
function frozenCopy(value) { return deepFreeze(cloneJson(value, 'callback input')); }
function deepFreeze(value) { if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const item of Object.values(value)) deepFreeze(item); Object.freeze(value); } return value; }
function assertState(state) { if (!state || !(state.contracts instanceof Map) || !Number.isSafeInteger(state.cursor)) throw new TypeError('state must come from preparePopulation'); }
function populationError(code, message, details) { const error = new TypeError(message); error.name = 'PopulationError'; error.code = code; if (details !== undefined) error.details = details; return error; }

function pathTokens(path) {
  if (typeof path !== 'string' || !path) throw populationError('reference_path', 'Reference declaration has an empty path');
  if (path.startsWith('/')) return path.slice(1).split('/').map(token => token.replace(/~1/g, '/').replace(/~0/g, '~'));
  const tokens = [];
  for (const match of path.matchAll(/(?:^|\.)([^.\[\]]+)|\[(\*|\d*)\]/g)) tokens.push(match[1] ?? (match[2] === '' || match[2] === '*' ? '*' : Number(match[2])));
  if (!tokens.length) throw populationError('reference_path', `Unsupported reference path ${path}`);
  return tokens;
}
function setDeclaredPath(root, path, replacement) {
  const tokens = pathTokens(path);
  const visit = (node, index) => {
    if (index === tokens.length) return typeof replacement === 'function' ? replacement(node) : replacement;
    const token = tokens[index];
    if (token === '*') {
      if (!Array.isArray(node)) throw populationError('reference_shape', `${path} expects an array`);
      return node.map(item => visit(item, index + 1));
    }
    if (Array.isArray(node)) {
      const at = typeof token === 'number' ? token : Number(token);
      if (!Number.isInteger(at) || at < 0 || at > node.length) throw populationError('reference_shape', `${path} has an invalid array position`);
      if (at === node.length) node.push(visit({}, index + 1)); else node[at] = visit(node[at], index + 1);
      return node;
    }
    if (isRecord(node)) {
      if (!Object.hasOwn(node, token)) node[token] = tokens[index + 1] === '*' || typeof tokens[index + 1] === 'number' ? [] : {};
      node[token] = visit(node[token], index + 1);
      return node;
    }
    throw populationError('reference_shape', `${path} has incompatible generated shape`);
  };
  return visit(root, 0);
}
function getPathValues(root, path) {
  const tokens = pathTokens(path);
  const visit = (node, index) => {
    if (index === tokens.length) return [node];
    const token = tokens[index];
    if (token === '*') return Array.isArray(node) ? node.flatMap(item => visit(item, index + 1)) : [];
    if (Array.isArray(node)) return visit(node[typeof token === 'number' ? token : Number(token)], index + 1);
    if (isRecord(node) && Object.hasOwn(node, token)) return visit(node[token], index + 1);
    return [];
  };
  return visit(root, 0);
}
