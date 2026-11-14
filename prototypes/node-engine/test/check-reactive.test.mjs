import test from 'node:test';
import assert from 'node:assert/strict';
import { prepareCatalog } from '../src/catalog.mjs';
import { createMemoryStore } from '../src/memory.mjs';
import { settlementOracle } from '../src/calculation-oracle.mjs';
import { checkReactive } from '../src/check-reactive.mjs';
import { producerKey, reservationKey, reactivePrefix, allNodesPrefix } from '../src/keys.mjs';
import { replaceRoutes } from '../src/routes.mjs';
import { replacePotential, potentialCatalog } from '../src/potential.mjs';
import { causalDefinition, causalCalculations, causalDiamond } from '../examples/causal.mjs';

async function fixture(withRanges = false) {
  const calculations = causalCalculations();
  if (withRanges) {
    const resolve = calculations.derive.resolve;
    calculations.derive.resolve = async args => {
      const shape = await resolve(args);
      shape.reads.push({slot:'window',kind:'range',view:'effective',partition:['base'],aggregate:'total',...(args.record.id === 'A' ? {} : {lower:{value:-1n}}),...(args.record.id === 'D' ? {} : {upper:{value:5n}})});
      return shape;
    };
  }
  const catalog = prepareCatalog(causalDefinition,{calculations}), authored = causalDiamond();
  const expected = await settlementOracle(catalog,'t',authored), store = createMemoryStore();
  await store.transact(async tx => {
    for (const r of expected.reservations) await tx.set(reservationKey(catalog,'t',r.outputId),r);
    for (const p of expected.producers) {
      await tx.set(producerKey(catalog,'t',p.id),p);
      await replacePotential(tx,catalog,'t',p.id,[],p.outputs);
    }
    for (const r of expected.routes) await replaceRoutes(tx,catalog,'t',r.subscriber,r.registrations);
  });
  return {catalog,store,expected,check:() => store.read(tx => checkReactive(tx,catalog,'t',expected.records))};
}

test('independent reactive inventory accepts complete snapshot and detects private corruption',async () => {
  const f = await fixture();
  assert.equal((await f.check()).producers,3);
  await f.store.transact(tx => tx.set(`${reactivePrefix(f.catalog,'t')}unknown/orphan`,{}));
  await assert.rejects(f.check(),{code:'INTEGRITY'});
});

test('independent potential traversal rejects corrupt aggregate and stale generated values',async () => {
  const f = await fixture();
  const stale = structuredClone(f.expected.records);
  stale.find(r => r.id === f.expected.generated[0].id).data.amount = '999';
  await assert.rejects(f.store.read(tx => checkReactive(tx,f.catalog,'t',stale)),{code:'INTEGRITY'});
  await f.store.transact(async tx => {
    const [row] = await tx.scan({prefix:allNodesPrefix(potentialCatalog(f.catalog),'t')});
    await tx.set(row.key,{...row.value,aggregates:{forged:1n}});
  });
  await assert.rejects(f.check(),{code:'INTEGRITY'});
});


test('independent interval forest verifies bounded/unbounded routes and max-upper summaries',async () => {
  const f = await fixture(true);
  assert.equal((await f.check()).interval.occurrences,3);
  const { fingerprint } = await import('../src/values.mjs');
  const internal = {identity:fingerprint(['internal-route-interval-avl-v1',f.catalog.identity])};
  await f.store.transact(async tx => {
    const [row] = await tx.scan({prefix:allNodesPrefix(internal,'t')});
    await tx.set(row.key,{...row.value,aggregates:{upper:{order:-100n}}});
  });
  await assert.rejects(f.check(),{code:'INTEGRITY'});
});
