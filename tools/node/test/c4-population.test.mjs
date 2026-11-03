import assert from 'node:assert/strict';
import test from 'node:test';
import { prepareModel } from '../model.mjs';
import { accept, preparePopulation, propose, reject } from '../population.mjs';

const id = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const identity = 'a'.repeat(64);
const dialect = 'https://json-schema.org/draft/2020-12/schema';
const uuid = { type: 'string', format: 'uuid' };
const exact = { type: 'string', pattern: '^(0|[1-9][0-9]*)$' };
const schema = properties => ({ $schema: dialect, type: 'object', additionalProperties: false,
  properties, required: Object.keys(properties) });
const rule = 'value does not exceed parent maximum';
function model({ unique = false } = {}) {
  return prepareModel({ model: identity, capabilities: { limits: { commands: 64 } }, contracts: [
    { name: 'Parent', code: 101, visibility: 'public', schema: schema({ maximum: exact }), references: [], rules: [], uniqueness: [] },
    { name: 'Child', code: 201, visibility: 'public', schema: schema({ parent: uuid, value: exact }),
      references: [{ slot: 1, field: 'parent', targets: [101], optional: false }], rules: [rule],
      uniqueness: unique ? [{ code: 1, reference_slots: [1] }] : [] },
  ] }, { selector: 'c4-test' });
}
const existing = { Parent: [1, 2, 3].map(n => ({ id: id(n), contract: 'Parent', fields: { maximum: '10' } })) };
const target = { url: 'http://127.0.0.1:8080/rpc', model: identity, store: id(800), tenant: id(801), actor: id(802), credential_epoch: 0 };
function commit(state, proposal, operation = id(900)) {
  const plan = { format: 'rebase-operation-plan-1', target,
    request: { model: identity, context: 'original-context', operation_id: operation,
      commands: proposal.commands, returning: proposal.returning } };
  state.pending.plan = plan;
  const receipt = { status: 'committed', result: { operation_id: operation, revision: id(901), records: proposal.returning.map(id => ({ id })) } };
  accept(state, proposal, plan, receipt);
  return { plan, receipt };
}
const check = (fields, _context, _refs, info) => {
  const parent = info.parents.parent[0];
  return BigInt(fields.value) <= BigInt(parent.fields.maximum) ? [] : [rule];
};

test('C4 constructs typed anchors and unique children in one bounded proposal from source facts', async () => {
  const native = model({ unique: true });
  const state = preparePopulation(native, { Parent: 3, Child: 3 }, {
    seed: 'atomic-anchors', batchSize: 6, maxAttempts: 32,
    strategies: { Parent: () => ({ maximum: '10' }), Child: () => ({ value: '8' }) },
    selectContract(eligible) { return eligible.includes('Child') ? 'Child' : 'Parent'; },
    checks: { Child: check },
  });
  const proposal = await propose(state, {});
  assert.equal(proposal.commands.length, 6);
  const sourceParents = new Map(proposal.commands.filter(row => row.contract === 101).map(row => [row.id, row.fields]));
  const sourceChildren = proposal.commands.filter(row => row.contract === 201);
  assert.equal(sourceParents.size, 3);
  assert.equal(sourceChildren.length, 3);
  assert.equal(new Set(sourceChildren.map(row => row.fields.parent)).size, 3);
  for (const row of sourceChildren) assert.ok(BigInt(row.fields.value) <= BigInt(sourceParents.get(row.fields.parent).maximum));
  assert.deepEqual(state.accepted, { Parent: 0, Child: 0 });
  assert.equal(state.poolIds.Parent.length, 0);
  commit(state, proposal);
  assert.deepEqual(state.accepted, { Parent: 3, Child: 3 });
});

test('C4 balances bounded fanout and accounts for accepted source references and staged rows', async () => {
  const state = preparePopulation(model(), { Child: 5 }, {
    seed: 'fanout', batchSize: 5,
    existing: { ...existing, Child: [{ id: id(20), contract: 'Child', fields: { parent: id(1), value: '1' } }] },
    strategies: { Child: () => ({ value: '2' }) },
    references: { Child: { parent: { maxFanout: 2, distribution: 'balanced' } } },
  });
  const proposal = await propose(state, {});
  const counts = new Map([[id(1), 1], [id(2), 0], [id(3), 0]]);
  for (const row of proposal.commands) counts.set(row.fields.parent, counts.get(row.fields.parent) + 1);
  assert.deepEqual([...counts.values()], [2, 2, 2]);
  commit(state, proposal);
  for (const [parent, count] of counts) assert.equal(state.referenceUsage[`Child\0parent\0Parent\0${parent}`], count);
});

test('C4 skew and retries are deterministic and fresh seeds replay failed local attempts', async () => {
  const options = { seed: 'retry-oracle', batchSize: 4, existing, maxAttempts: 4,
    strategies: { Child: (_schema, _seed, _cursor, info) => ({ value: info.attempt === 0 ? '11' : '7' }) },
    checks: { Child: check }, references: { Child: { parent: { distribution: 'prefer_used', skew: 3 } } } };
  const first = preparePopulation(model(), { Child: 4 }, options);
  const replay = preparePopulation(model(), { Child: 4 }, options);
  const one = await propose(first, {});
  const two = await propose(replay, {});
  assert.deepEqual(one, two);
  assert.equal(one.generation.candidates, 8);
  assert.equal(one.generation.unsatisfied.find(x => x.rule === rule).attempts, 4);
  for (const row of one.commands) assert.equal(row.fields.value, '7');
});

test('C4 reports exact exhausted rules without lowering quotas or publishing tentative pools', async () => {
  const state = preparePopulation(model(), { Child: 2 }, { seed: 'impossible', existing, maxAttempts: 3,
    strategies: { Child: () => ({ value: '11' }) }, checks: { Child: check } });
  await assert.rejects(propose(state, {}), error => {
    assert.equal(error.code, 'population_unsatisfied');
    assert.equal(error.details.candidates, 3);
    assert.deepEqual(error.details.unsatisfied, [{ contract: 'Child', kind: 'rule', rule, attempts: 3 }]);
    return true;
  });
  assert.deepEqual(state.quotas, { Parent: 0, Child: 2 });
  assert.equal(state.cursor, 0);
  assert.equal(state.pending, null);
  assert.equal(state.poolIds.Child.length, 0);
  const first = structuredClone(state.lastReport);
  await assert.rejects(propose(state, {}), error => error.code === 'population_unsatisfied');
  assert.deepEqual(state.lastReport, first);
});

test('C4 optional solver receives declared rules and cannot bypass schema, typed pools or checks', async () => {
  const options = { seed: 'solver', existing, maxAttempts: 2,
    strategies: { Child: () => ({ value: '11' }) }, checks: { Child: check } };
  let calls = 0;
  const solved = preparePopulation(model(), { Child: 1 }, { ...options, solver(candidate) {
    calls += 1;
    assert.equal(Object.isFrozen(candidate), true);
    assert.deepEqual(candidate.contract.rules, [rule]);
    assert.equal(candidate.unsatisfied[0].rule, rule);
    return { ...candidate.fields, value: '10' };
  } });
  const proposal = await propose(solved, {});
  assert.equal(calls, 1);
  assert.equal(proposal.commands[0].fields.value, '10');
  for (const replacement of [{ value: '10', parent: id(999) }, { value: '11', parent: id(1) }, { value: 10, parent: id(1) }]) {
    const bypass = preparePopulation(model(), { Child: 1 }, { ...options, solver: () => replacement });
    await assert.rejects(propose(bypass, {}), error => error.code === 'population_unsatisfied');
    assert.equal(bypass.pending, null);
  }
});

test('C4 retries preserve original plan binding after lost ACK and count only its committed receipt', async () => {
  const state = preparePopulation(model(), { Child: 1 }, { seed: 'receipt', existing, strategies: { Child: () => ({ value: '5' }) } });
  const proposal = await propose(state, {});
  const plan = { format: 'rebase-operation-plan-1', target,
    request: { model: identity, context: 'original-context', operation_id: id(930), commands: proposal.commands, returning: proposal.returning } };
  state.pending.plan = plan;
  assert.throws(() => reject(state, proposal, plan, Object.assign(new Error('lost ACK'), { name: 'RpcError', code: 'outcome_unknown', httpStatus: 200 })), error => error.code === 'outcome_uncertain');
  await assert.rejects(propose(state, {}), error => error.code === 'proposal_pending');
  assert.deepEqual(state.pending.plan, plan);
  const recovered = { status: 'committed', replayed: true, result: { operation_id: id(930), revision: id(931), records: proposal.returning.map(id => ({ id })) } };
  accept(state, proposal, plan, recovered);
  assert.equal(state.accepted.Child, 1);
  assert.throws(() => accept(state, proposal, plan, recovered), error => error.code === 'pending_mismatch');
});

test('C4 bounds proposal work and validates controls against catalog reference identities', async () => {
  assert.throws(() => preparePopulation(model(), {}, { seed: 1, maxAttempts: 0 }), /maxAttempts/);
  assert.throws(() => preparePopulation(model(), {}, { seed: 1, references: { Child: { hidden: { maxFanout: 1 } } } }), /reference/);
  assert.throws(() => preparePopulation(model(), {}, { seed: 1, references: { Child: { parent: { distribution: 'magic' } } } }), /distribution/);
  const state = preparePopulation(model(), { Child: 1 }, { seed: 'work', existing, maxWork: 1, strategies: { Child: () => ({ value: '1' }) } });
  await assert.rejects(propose(state, {}), error => error.code === 'population_budget');
  assert.equal(state.pending, null);
  assert.equal(state.cursor, 0);
});

test('C4 preserves ordered junction-pair uniqueness and independently inventories partial cardinality', async () => {
  const catalog = structuredClone(model().catalog);
  catalog.contracts.push({ name: 'Junction', code: 301, visibility: 'public',
    schema: schema({ left: uuid, right: uuid }), rules: [],
    references: [{ slot: 1, field: 'left', targets: [101], optional: false }, { slot: 2, field: 'right', targets: [101], optional: false }],
    uniqueness: [{ code: 2, reference_slots: [1, 2] }] });
  const native = prepareModel(catalog, { selector: 'c4-test' });
  const state = preparePopulation(native, { Junction: 5 }, { seed: 'pair-space', batchSize: 5, maxAttempts: 128,
    existing: { Parent: existing.Parent.slice(0, 2) }, strategies: { Junction: () => ({}) } });
  const proposal = await propose(state, {});
  const actual = proposal.commands.map(row => JSON.stringify([row.fields.left, row.fields.right])).sort();
  const expected = [1, 2].flatMap(left => [1, 2].map(right => JSON.stringify([id(left), id(right)]))).sort();
  assert.deepEqual(actual, expected);
  assert.equal(proposal.generation.remaining.Junction, 1);
  assert.ok(proposal.generation.unsatisfied.some(issue => issue.kind === 'uniqueness' && issue.rule === '2'));
  commit(state, proposal);
  assert.equal(state.accepted.Junction, 4);
  await assert.rejects(propose(state, {}), error => error.code === 'population_unsatisfied');
  assert.equal(state.quotas.Junction, 5);
});

test('C4 optional absence omits a tuple claim while supplied duplicates and undercounted usage reject', async () => {
  const catalog = structuredClone(model({ unique: true }).catalog);
  const child = catalog.contracts[1];
  child.schema.required = ['value'];
  child.references[0].optional = true;
  const native = prepareModel(catalog, { selector: 'c4-test' });
  const state = preparePopulation(native, { Child: 3 }, { seed: 'optional', batchSize: 3, strategies: { Child: () => ({ value: '4' }) } });
  const proposal = await propose(state, {});
  assert.equal(proposal.commands.length, 3);
  assert.ok(proposal.commands.every(row => !Object.hasOwn(row.fields, 'parent')));
  assert.deepEqual(proposal.generation.uncheckedRules, [{ contract: 'Child', rule }]);
  const children = [20, 21].map(n => ({ id: id(n), contract: 'Child', fields: { parent: id(1), value: '1' } }));
  assert.throws(() => preparePopulation(model({ unique: true }), {}, { seed: 1, existing: { ...existing, Child: children } }), /violate Child uniqueness/);
  assert.throws(() => preparePopulation(model(), {}, { seed: 1, existing: { ...existing, Child: children },
    referenceUsage: { [`Child\0parent\0Parent\0${id(1)}`]: 1 } }), /undercounts/);
});

test('C4 final rule and solver retargets cannot evade fanout and all array occurrences are charged', async () => {
  const catalog = structuredClone(model().catalog);
  catalog.contracts[1].schema = schema({ links: { type: 'array', minItems: 2, maxItems: 2, items: schema({ parent: uuid }) }, value: exact });
  catalog.contracts[1].references = [{ slot: 1, field: 'links[*].parent', targets: [101], optional: false }];
  const native = prepareModel(catalog, { selector: 'c4-test' });
  const state = preparePopulation(native, { Child: 2 }, { seed: 'array-fanout', batchSize: 2, existing,
    strategies: { Child: () => ({ links: [{ parent: id(1) }, { parent: id(1) }], value: '1' }) },
    references: { Child: { 'links[*].parent': { maxFanout: 2, distribution: 'balanced' } } } });
  const proposal = await propose(state, {});
  const occurrences = proposal.commands.flatMap(row => row.fields.links.map(link => link.parent));
  const histogram = Object.fromEntries(existing.Parent.map(parent => [parent.id, occurrences.filter(id => id === parent.id).length]));
  assert.deepEqual(Object.values(histogram).sort(), [0, 2, 2]);
  for (const [parent, count] of Object.entries(histogram)) assert.equal(proposal.usage[`Child\0links[*].parent\0Parent\0${parent}`] ?? 0, count);
  const blocked = preparePopulation(model(), { Child: 1 }, { seed: 'retarget', existing, maxAttempts: 2,
    referenceUsage: { [`Child\0parent\0Parent\0${id(1)}`]: 1 },
    strategies: { Child: () => ({ value: '1' }) }, rules: { Child: fields => ({ ...fields, parent: id(1) }) },
    solver: candidate => ({ ...candidate.fields, parent: id(1) }),
    references: { Child: { parent: { maxFanout: 1 } } } });
  await assert.rejects(propose(blocked, {}), error => error.code === 'population_unsatisfied' && error.details.unsatisfied.every(issue => issue.kind === 'fanout'));
});

test('C4 callback diagnostics must name native catalog rules and failed generation leaves deterministic Faker intent', async () => {
  const invalid = preparePopulation(model(), { Child: 1 }, { seed: 'bad-check', existing,
    strategies: { Child: () => ({ value: '1' }) }, checks: { Child: () => ['undeclared rule'] } });
  await assert.rejects(propose(invalid, {}), error => error.code === 'invalid_check');
  const fields = [];
  const catalog = structuredClone(model().catalog);
  catalog.contracts[1].schema.properties.value = { type: 'string', enum: ['2', '4', '6', '8'] };
  const native = prepareModel(catalog, { selector: 'c4-test' });
  const failed = preparePopulation(native, { Child: 1 }, { seed: 'faker-retry', existing, maxAttempts: 4,
    checks: { Child: candidate => { fields.push(candidate); return [rule]; } } });
  await assert.rejects(propose(failed, {}), error => error.code === 'population_unsatisfied');
  await assert.rejects(propose(failed, {}), error => error.code === 'population_unsatisfied');
  assert.deepEqual(fields.slice(0, 4), fields.slice(4));
});
