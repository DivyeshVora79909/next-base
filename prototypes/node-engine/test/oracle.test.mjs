import test from 'node:test';
import assert from 'node:assert/strict';
import { prepareCatalog } from '../src/catalog.mjs';
import { sourceOracle } from '../src/oracle.mjs';

const prefix = {
  version: '1', inputDomain: 'integer', identity: () => ({ total: 0n, min: 0n }),
  lift: value => ({ total: value, min: value < 0n ? value : 0n }),
  combine: (a, b) => ({ total: a.total + b.total, min: a.min < a.total + b.min ? a.min : a.total + b.min }),
};
function fixture() {
  const selector = field => ({ field });
  const membership = (slot, view, field, order = selector('at')) => ({ slot, view, partition: [{ header: 'owner' }], order, inputs: { amount: selector(field) }, onMissing: 'reject' });
  const model = (field, memberships) => ({
    schema: { type: 'object', additionalProperties: false, properties: { [field]: { type: 'string' }, at: { type: 'string' }, tag: { type: 'string' }, parent: { type: 'string' } }, required: [field, 'at', 'tag'] },
    memberships, uniqueness: [{ slot: 'tag', fields: [selector('tag')] }], references: [],
  });
  const definition = {
    name: 'oracle', version: '1',
    contracts: { balance: { version: '1', partition: ['id'], order: 'integer', inputs: { amount: 'integer' }, aggregates: { prefix: { monoid: 'prefix', input: 'amount' } }, validators: [] } },
    views: { effective: { contract: 'balance' }, created: { contract: 'balance' } },
    models: { debit: model('amount', [membership('a', 'effective', 'amount'), membership('b', 'effective', 'amount'), membership('created', 'created', 'amount', { header: 'createdAt' })]), credit: model('total', [membership('a', 'effective', 'total')]) },
  };
  const record = (id, model, data, createdAt) => ({ id, tenant: 't', owner: 'o', model, data, createdAt });
  const records = [record('z', 'debit', { amount: '-4', at: '1', tag: 'z' }, '9'), record('a', 'credit', { total: '6', at: '1', tag: 'a' }, '2'), record('b', 'debit', { amount: '3', at: '0', tag: 'b' }, '0')];
  return { definition, records, prepare: () => prepareCatalog(definition, { monoids: { prefix } }) };
}

test('flat oracle maps each model, separates views and preserves multiplicity with stable ties', () => {
  const { prepare, records } = fixture();
  const prepared = prepare(), result = sourceOracle(prepared, records);
  const effective = result.trees.find(tree => tree.view === 'effective');
  assert.deepEqual(effective.members.map(member => [member.sourceId, member.slot]), [['b', 'a'], ['b', 'b'], ['a', 'a'], ['z', 'a'], ['z', 'b']]);
  assert.equal(effective.count, 5);
  assert.deepEqual(effective.aggregates.prefix, { total: 4n, min: 0n });
  assert.deepEqual(result.trees.find(tree => tree.view === 'created').members.map(member => member.sourceId), ['b', 'z']);
  assert.deepEqual(result.trees.find(tree => tree.view === 'created').aggregates.prefix, { total: -1n, min: -1n });
  assert.deepEqual(sourceOracle(prepared, [...records].reverse()), result);
  assert.deepEqual(sourceOracle(prepared, []), { trees: [], references: [], claims: [] });
  // Corrupt compiled writer metadata: expected source binding stays authoritative.
  assert.deepEqual(sourceOracle({ ...prepared, models: { ...prepared.models, debit: { ...prepared.models.debit, memberships: [] } } }, records), result);
  assert.deepEqual(sourceOracle({ ...prepared, contracts: { ...prepared.contracts, balance: { ...prepared.contracts.balance, order: 'string' } } }, records), result);
});

test('reserved aggregate names remain data in both writer projections and oracle', () => {
  const { definition, records, prepare } = fixture();
  definition.contracts.balance.aggregates = JSON.parse('{"__proto__":{"monoid":"prefix","input":"amount"}}');
  const tree = sourceOracle(prepare(), records).trees.find(tree => tree.view === 'effective');
  assert.equal(Object.hasOwn(tree.aggregates, '__proto__'), true);
  assert.deepEqual(tree.aggregates.__proto__, { total: 4n, min: 0n });
});

test('flat oracle enumerates reference positions and claims and rejects invalid final source graphs', () => {
  const { definition, records, prepare } = fixture();
  definition.models.debit.references = [{ slot: 'parent', field: 'parent', targets: ['credit'], many: false, onDelete: 'reject' }];
  records[0].data.parent = 'a';
  const prepared = prepare(), result = sourceOracle(prepared, records);
  assert.deepEqual(result.references, [{ tenant: 't', sourceId: 'z', slot: 'parent', position: 0, targetId: 'a', targets: ['credit'] }]);
  assert.equal(result.claims.length, 3);
  assert.throws(() => sourceOracle(prepared, [...records, records[0]]), { code: 'DUPLICATE_SOURCE' });
  assert.throws(() => sourceOracle(prepared, [records[0]]), { code: 'INVALID_REFERENCE' });
  const duplicate = structuredClone(records[2]); duplicate.id = 'other';
  assert.throws(() => sourceOracle(prepared, [...records, duplicate]), { code: 'DUPLICATE_CLAIM' });
});

test('skip applies only to absent values and invalid present values still reject', () => {
  const { definition, records, prepare } = fixture();
  definition.models.credit.schema.required = ['at', 'tag'];
  definition.models.credit.memberships[0].onMissing = 'skip';
  delete records[1].data.total;
  assert.equal(sourceOracle(prepare(), records).trees.find(tree => tree.view === 'effective').count, 4);
  records[1].data.total = '01';
  assert.throws(() => sourceOracle(prepare(), records));
});
