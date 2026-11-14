import test from 'node:test';
import assert from 'node:assert/strict';
import {prepareCatalog} from '../src/catalog.mjs';
import {createMemoryStore} from '../src/memory.mjs';
import {settle} from '../src/settlement.mjs';
import {settlementOracle,producerId} from '../src/calculation-oracle.mjs';
import {sourcePrefix,sourceKey,producerKey,potentialOwnerKey} from '../src/keys.mjs';
import {causalDefinition,causalCalculations,causalDiamond,causalAnchor,causalOutput} from '../examples/causal.mjs';
const setup=()=>({catalog:prepareCatalog(structuredClone(causalDefinition),{calculations:causalCalculations()}),store:createMemoryStore()});
const put=records=>records.map(record=>({type:'put',record}));
const apply=(store,catalog,changes,options)=>store.transact(tx=>settle(tx,catalog,'t',changes,options));
async function compare(store,catalog,authored) {
  const expected=await settlementOracle(catalog,'t',authored);
  const records=await store.read(async tx=>(await tx.scan({prefix:sourcePrefix('t')})).map(r=>r.value));
  assert.deepEqual(records.sort((a,b)=>a.id.localeCompare(b.id)),expected.records.sort((a,b)=>a.id.localeCompare(b.id)));
}
test('incremental diamond settles coalesced changes and preserves a complete no-op',async()=>{
  const {store,catalog}=setup(),records=causalDiamond();
  const initial=await apply(store,catalog,put(records));assert.equal(initial.settlement.evaluated,3);
  await compare(store,catalog,records);
  records[0]={...records[0],data:{...records[0].data,amount:'12'}};
  const next=await apply(store,catalog,put([records[0]]));assert.equal(next.settlement.evaluated,3);assert.equal(next.settlement.resolved,0);
  await compare(store,catalog,records);
  let writes;
  const noop=await store.transact(tx=>settle(tx,catalog,'t',put([records[0]])),{beforeCommit:({changes})=>{writes=changes.length;}});
  assert.equal(noop.settlement.evaluated,0);assert.equal(writes,0);
});
test('final potential cycle through an unchanged descendant rejects atomically',async()=>{
  const {store,catalog}=setup(),records=causalDiamond();await apply(store,catalog,put(records));
  const before=await store.read(tx=>tx.scan());
  await assert.rejects(apply(store,catalog,put([causalAnchor('A',[causalOutput('D')],'2')])),{code:'CALCULATION_CYCLE'});
  assert.deepEqual(await store.read(tx=>tx.scan()),before);
});
test('settlement rejects invalid budgets and reserved absent identities',async()=>{
  const {store,catalog}=setup();
  await assert.rejects(apply(store,catalog,[],{maxProducers:null}),{code:'CALCULATION_BUDGET'});
  await assert.rejects(apply(store,catalog,[{type:'delete',id:causalOutput('missing')}]),{code:'INVALID_CALCULATION'});
});
test('disjoint producer remains untouched during a causal cascade',async()=>{
  const {store,catalog}=setup(),records=causalDiamond();records.push(causalAnchor('unrelated',[]));
  await apply(store,catalog,put(records));
  const next={...records[0],data:{...records[0].data,amount:'20'}};
  const result=await apply(store,catalog,put([next]));assert.equal(result.settlement.pending,3);
  assert.equal((await store.read(tx=>tx.get(sourceKey('t',causalOutput('D'))))).data.amount,'100');
});

test('private corruption is rejected instead of repaired, including newly anchored IDs',async()=>{
  for(const damaged of ['producer','owner','new-null']) {
    const {store,catalog}=setup(),records=causalDiamond();
    if(damaged!=='new-null')await apply(store,catalog,put(records));
    await store.transact(async tx=>{
      if(damaged==='owner')await tx.delete(potentialOwnerKey(catalog,'t',causalOutput('D')));
      else await tx.set(producerKey(catalog,'t',producerId('t',damaged==='new-null'?'A':'D','main')),null);
    });
    const before=await store.read(tx=>tx.scan());
    const changes=damaged==='new-null'?put(records):put([{...records[0],data:{...records[0].data,amount:'11'}}]);
    await assert.rejects(apply(store,catalog,changes),{code:'CORRUPT_STATE'});
    assert.deepEqual(await store.read(tx=>tx.scan()),before);
  }
});
test('logical budget exhaustion rolls back the entire authored and private overlay',async()=>{
  for(const options of [{maxProducers:2},{maxEdges:0},{maxRouteVisits:0},{maxPotentialVisits:0}]) {
    const {store,catalog}=setup(),records=causalDiamond();await apply(store,catalog,put(records));
    const before=await store.read(tx=>tx.scan());
    await assert.rejects(apply(store,catalog,put([{...records[0],data:{...records[0].data,amount:'11'}}]),options));
    assert.deepEqual(await store.read(tx=>tx.scan()),before);
  }
});

test('extra producer and output keys cannot be repaired by re-resolving an anchor',async()=>{
  for(const damage of ['producer','output']) {
    const {store,catalog}=setup(),records=causalDiamond();await apply(store,catalog,put(records));
    await store.transact(async tx=>{
      const key=producerKey(catalog,'t',producerId('t','A','main')),p=await tx.get(key);
      if(damage==='producer')p.corruptExtra=true;else p.outputs[0].corruptExtra=true;
      await tx.set(key,p);
    });
    const before=await store.read(tx=>tx.scan());
    await assert.rejects(apply(store,catalog,put([{...records[1],data:{...records[1].data,factor:'4'}}])),{code:'CORRUPT_STATE'});
    assert.deepEqual(await store.read(tx=>tx.scan()),before);
  }
});
