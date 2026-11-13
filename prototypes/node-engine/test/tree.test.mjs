import test from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryStore } from '../src/memory.mjs';
import { standardMonoids } from '../src/monoids.mjs';
import { canonical } from '../src/values.mjs';
import { nodeKey, rootKey, occurrenceToken } from '../src/keys.mjs';
import { treePut, treeDelete, readRoot, treeSelect, treeGet, treeAggregate } from '../src/tree.mjs';

const catalog={identity:'tree-test',views:{v:{identity:'v-test',contract:{order:'integer',partition:[],aggregates:{sum:{implementation:standardMonoids.sum},prefix:{implementation:standardMonoids.prefix}}}}}};
const scope={tenant:'t',view:'v',partition:[]};
const occurrence=(id,order,value=order)=>({...scope,sourceId:`s${String(id).padStart(4,'0')}`,slot:'m',order:BigInt(order),contributions:{sum:BigInt(value),prefix:standardMonoids.prefix.lift(BigInt(value))}});
const cmp=(a,b)=>a.order<b.order?-1:a.order>b.order?1:a.sourceId.localeCompare(b.sourceId)||a.slot.localeCompare(b.slot);
const fold=items=>({sum:items.reduce((s,o)=>s+o.contributions.sum,0n),prefix:items.reduce((s,o)=>standardMonoids.prefix.combine(s,o.contributions.prefix),standardMonoids.prefix.identity())});
const equal=(a,b)=>assert.equal(canonical(a),canonical(b));

test('partition keys normalize exact integer wire values and reject invalid scopes', async () => {
  const numeric = { ...catalog, views: { v: { ...catalog.views.v, contract: { ...catalog.views.v.contract, partition: ['integer'] } } } };
  const store = createMemoryStore();
  const member = { ...occurrence(1, 3), partition: [7n] };
  await store.transact(tx => treePut(tx, numeric, member));
  await store.read(async tx => {
    const wireScope = { ...scope, partition: ['7'] };
    assert.equal((await readRoot(tx, numeric, wireScope)).sourceId, member.sourceId);
    assert.equal((await treeAggregate(tx, numeric, wireScope)).sum, 3n);
    assert.equal((await treeSelect(tx, numeric, wireScope, 0)).sourceId, member.sourceId);
    await assert.rejects(readRoot(tx, numeric, { ...scope, partition: ['07'] }), { code: 'INVALID_VALUE' });
    await assert.rejects(readRoot(tx, numeric, scope), { code: 'INVALID_SCOPE' });
    await assert.rejects(readRoot(tx, numeric, { ...wireScope, view: 'missing' }), { code: 'INVALID_SCOPE' });
  });
});

async function verify(tx,items) {
  const sorted=[...items].sort(cmp), seen=new Set();
  async function visit(n) {
    if(!n)return [];
    const token=occurrenceToken(n); assert.ok(!seen.has(token));seen.add(token);
    const left=await visit(n.left===null?undefined:await tx.get(nodeKey(catalog,scope,n.left)));
    const right=await visit(n.right===null?undefined:await tx.get(nodeKey(catalog,scope,n.right)));
    const all=[...left,n,...right]; assert.equal(n.size,all.length);equal(n.aggregates,fold(all));
    const l=n.left===null?undefined:await tx.get(nodeKey(catalog,scope,n.left));
    const r=n.right===null?undefined:await tx.get(nodeKey(catalog,scope,n.right));
    assert.equal(n.height,1+Math.max(l?.height??0,r?.height??0));assert.ok(Math.abs((l?.height??0)-(r?.height??0))<=1);
    assert.ok(left.every(o=>cmp(o,n)<0));assert.ok(right.every(o=>cmp(o,n)>0));return all;
  }
  const all=await visit(await readRoot(tx,catalog,scope));equal(all.map(occurrenceToken),sorted.map(occurrenceToken));
  const stored=await tx.scan();assert.equal(stored.length,items.length+(items.length?1:0));
  equal(await treeAggregate(tx,catalog,scope),fold(sorted));
  for(let rank=0;rank<=sorted.length;rank++) assert.equal((await treeSelect(tx,catalog,scope,rank))?.sourceId,sorted[rank]?.sourceId);
  for(const value of [-1n,0n,2n,4n,9n]) for(const inclusive of [true,false]) {
    const lower={value,inclusive},upper={value:4n,inclusive};
    equal(await treeAggregate(tx,catalog,scope,{lower,upper}),fold(sorted.filter(o=>(inclusive?o.order>=value:o.order>value)&&(inclusive?o.order<=4n:o.order<4n))));
  }
}

test('AVL seeded mutations preserve stable identities, all summaries, ranges and ranks',async()=>{
  const store=createMemoryStore(), items=new Map();let seed=1729;
  const random=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;};
  for(let step=0;step<180;step++) {
    const id=random()%35;
    await store.transact(async tx=>{
      if(random()%3===0) {const old=items.get(id)??occurrence(id,id%7);assert.equal(await treeDelete(tx,catalog,old),items.has(id));items.delete(id);}
      else {const old=items.get(id), o=occurrence(id,old?.order??BigInt(id%7),BigInt(random()%21)-10n);await treePut(tx,catalog,o);items.set(id,o);equal((await treeGet(tx,catalog,scope,o)).contributions,o.contributions);}
      await verify(tx,[...items.values()]);
    });
  }
  for(const o of [...items.values()])await store.transact(async tx=>{assert.equal(await treeDelete(tx,catalog,o),true);items.delete(Number(o.sourceId.slice(1)));await verify(tx,[...items.values()]);});
});

test('rotations, successor promotion, move rejection and rollback',async()=>{
  for(const orders of [[1,2,3],[3,2,1],[3,1,2],[1,3,2],[4,2,6,1,3,5,7]]) {
    const store=createMemoryStore(),items=orders.map(n=>occurrence(n,n));
    await store.transact(async tx=>{for(const o of items)await treePut(tx,catalog,o);await verify(tx,items);});
    await assert.rejects(store.transact(async tx=>{await treeDelete(tx,catalog,items[0]);throw Error('abort');}),/abort/);
    await store.read(tx=>verify(tx,items));
    await assert.rejects(store.transact(tx=>treePut(tx,catalog,{...items[0],order:99n})),{code:'MEMBERSHIP_MOVE_REQUIRED'});
    await store.transact(async tx=>{await treeDelete(tx,catalog,items[0]);await verify(tx,items.slice(1));});
  }
});

test('point-operation work follows height and root summary uses two gets',async()=>{
  const store=createMemoryStore();
  await store.transact(async tx=>{for(let i=0;i<512;i++)await treePut(tx,catalog,occurrence(i,i));});
  await store.read(async tx=>{await treeAggregate(tx,catalog,scope);assert.equal(tx.inspect().metrics.gets,2);});
  await store.transact(async tx=>{await treePut(tx,catalog,occurrence(512,512));const m=tx.inspect().metrics;assert.ok(m.gets<250);assert.ok(m.stagedWrites<30);assert.equal(m.scans,0);});
  await store.read(async tx=>{await treeAggregate(tx,catalog,scope,{lower:{value:30n},upper:{value:470n}});assert.ok(tx.inspect().metrics.gets<80);});
  await store.read(async tx=>{await assert.rejects(treeSelect(tx,catalog,scope,-1),{code:'INVALID_RANK'});await assert.rejects(treeAggregate(tx,catalog,scope,{lower:{value:'bad'}}),{code:'INVALID_VALUE'});});
});

test('dangling links and malformed root headers fail without repair',async()=>{
  const store=createMemoryStore(),o=occurrence(1,1);
  await store.transact(tx=>treePut(tx,catalog,o));
  await store.transact(tx=>tx.delete(nodeKey(catalog,scope,occurrenceToken(o))));
  await assert.rejects(store.read(tx=>treeAggregate(tx,catalog,scope)),{code:'CORRUPT_STATE'});
  await assert.rejects(store.transact(tx=>treePut(tx,catalog,occurrence(2,2))),{code:'CORRUPT_STATE'});
  await store.transact(tx=>tx.set(rootKey(catalog,scope),{}));
  await assert.rejects(store.transact(tx=>treePut(tx,catalog,o)),{code:'CORRUPT_STATE'});
  await assert.rejects(store.transact(tx=>treeDelete(tx,catalog,o)),{code:'CORRUPT_STATE'});
});

test('range options reject misspellings and invalid containers',async()=>{
  const store=createMemoryStore();
  for(const options of [null,[],1,{low:1},{lower:{value:1n,inclusve:false}},{upper:[]}]) {
    await assert.rejects(store.read(tx=>treeAggregate(tx,catalog,scope,options)),{code:'INVALID_RANGE'});
  }
  await store.read(tx=>treeAggregate(tx,catalog,scope));
});

test('actual descents reject cycles and orphan upserts abort without publishing',async()=>{
  const store=createMemoryStore(),o=occurrence(2,2),smaller=occurrence(1,1);
  await store.transact(async tx=>{
    await treePut(tx,catalog,o);
    const n=await readRoot(tx,catalog,scope);n.left=occurrenceToken(n);await tx.set(nodeKey(catalog,scope,occurrenceToken(n)),n);
  });
  for(const operation of [tx=>treeGet(tx,catalog,scope,smaller),tx=>treeSelect(tx,catalog,scope,0),tx=>treePut(tx,catalog,smaller),tx=>treeDelete(tx,catalog,smaller),tx=>treeAggregate(tx,catalog,scope,{upper:{value:1n}}),tx=>treeAggregate(tx,catalog,scope,{lower:{value:1n}})]) {
    await assert.rejects(store.transact(operation),{code:'CORRUPT_STATE'});
    await store.read(async tx=>assert.equal((await readRoot(tx,catalog,scope)).sourceId,o.sourceId));
  }
  await store.transact(tx=>tx.delete(rootKey(catalog,scope)));
  await assert.rejects(store.transact(tx=>treePut(tx,catalog,o)),{code:'CORRUPT_STATE'});
  await store.read(async tx=>{assert.equal(await readRoot(tx,catalog,scope),undefined);assert.equal((await tx.scan()).length,1);});
  // A different reachable root must not make an orphan's identity replaceable.
  await store.transact(tx=>treePut(tx,catalog,occurrence(4,4)));
  await assert.rejects(store.transact(tx=>treePut(tx,catalog,o)),{code:'CORRUPT_STATE'});
  await store.read(async tx=>assert.equal((await readRoot(tx,catalog,scope)).sourceId,occurrence(4,4).sourceId));
});

test('local stored node metadata is checked before descent',async()=>{
  for(const patch of [{height:0},{size:1.5},{left:undefined},{right:2}]) {
    const store=createMemoryStore(),o=occurrence(1,1);
    await store.transact(async tx=>{await treePut(tx,catalog,o);const n=await readRoot(tx,catalog,scope);await tx.set(nodeKey(catalog,scope,occurrenceToken(o)),{...n,...patch});});
    await assert.rejects(store.read(tx=>readRoot(tx,catalog,scope)),{code:'CORRUPT_STATE'});
    await store.read(tx=>tx.get(rootKey(catalog,scope)));
  }
});
