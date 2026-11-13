import test from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryStore } from '../src/memory.mjs';
import { replaceRoutes, readRoutes, affectedSubscribers } from '../src/routes.mjs';

const catalog={identity:'routing-test',models:{m:{schema:{properties:{x:{}}}}},views:{v:{contract:{partition:['string'],order:'integer',aggregates:{sum:{}}}},words:{contract:{partition:[],order:'string',aggregates:{sum:{}}}}}};
const range=(slot,lower,upper)=>({slot,kind:'range',view:'v',partition:['p'],aggregate:'sum',...(lower===undefined?{}:{lower}),...(upper===undefined?{}:{upper})});
const point=(order,sourceId='a',slot='m')=>({view:'v',partition:['p'],aggregate:'sum',order:BigInt(order),sourceId,slot});
const field=(slot='f')=>({slot,kind:'field',sourceId:'source',selector:{field:'x'}});
// Flat independent cut comparison; deliberately does not use range.mjs or writer metadata.
function flatMatch(r,p) {
  if(r.kind!=='range'||r.view!==p.view||r.aggregate!==p.aggregate||JSON.stringify(r.partition)!==JSON.stringify(p.partition))return false;
  for(const [side,sign] of [['lower',-1],['upper',1]]) {
    const b=r[side];if(!b)continue;
    let c=p.order<b.value?-1:p.order>b.value?1:0;
    if(!c&&Object.hasOwn(b,'sourceId'))c=p.sourceId<b.sourceId?-1:p.sourceId>b.sourceId?1:p.slot<b.slot?-1:p.slot>b.slot?1:0;
    if(c===sign||(!c&&b.inclusive===false))return false;
  }
  return true;
}

test('seeded replacements/deletions agree with an independent flat interval oracle',async()=>{
  const store=createMemoryStore(), all=new Map();let seed=734;
  const random=()=>seed=(Math.imul(seed,1664525)+1013904223)>>>0;
  for(let step=0;step<95;step++) {
    const subscriber=`s${random()%15}`, registrations=[];
    if(random()%4) for(let i=0;i<3;i++) {
      const cut=()=>({value:BigInt(random()%9)-4n,inclusive:!!(random()%2),...(random()%2?{sourceId:random()%2?'a':'z',slot:'m'}:{})});
      registrations.push(range(`r${i}`,random()%3?cut():undefined,random()%3?cut():undefined));
    }
    all.set(subscriber,registrations);
    await store.transact(tx=>replaceRoutes(tx,catalog,'t',subscriber,registrations));
    await store.read(async tx=>{
      assert.deepEqual(await readRoutes(tx,catalog,'t',subscriber),registrations);
      const points=[point(-3),point(0),point(3,'z')];
      const expected=[];
      for(const [s,rs] of all)for(const r of rs)if(points.some(p=>flatMatch(r,p)))expected.push({subscriber:s,slot:r.slot});
      expected.sort((a,b)=>a.subscriber.localeCompare(b.subscriber)||a.slot.localeCompare(b.slot));
      const got=await affectedSubscribers(tx,catalog,'t',{points});
      assert.deepEqual(got.matches,expected);assert.equal(got.metrics.matches,expected.length);
    });
  }
});

test('ties, mixed scalar/tuple cuts, empty/open/unbounded and strings',async()=>{
  const store=createMemoryStore();
  const registrations=[range('all'),range('empty',{value:2n},{value:1n}),range('open',{value:1n,inclusive:false},{value:1n}),range('tuple',{value:1n,sourceId:'b',slot:'m'},{value:1n}),{slot:'word',kind:'range',view:'words',partition:[],aggregate:'sum',lower:{value:'a'},upper:{value:'z',inclusive:false}}];
  await store.transact(tx=>replaceRoutes(tx,catalog,'t','s',registrations));
  await store.read(async tx=>{
    assert.deepEqual((await affectedSubscribers(tx,catalog,'t',{points:[point(1,'a')]})).matches.map(x=>x.slot),['all']);
    assert.deepEqual((await affectedSubscribers(tx,catalog,'t',{points:[point(1,'b')]})).matches.map(x=>x.slot),['all','tuple']);
    const p={view:'words',partition:[],aggregate:'sum',sourceId:'a',slot:'m',order:'hello'};
    assert.deepEqual((await affectedSubscribers(tx,catalog,'t',{points:[p]})).matches.map(x=>x.slot),['word']);
    assert.deepEqual((await affectedSubscribers(tx,catalog,'t',{points:[{...p,order:'z'}]})).matches,[]);
  });
});

test('direct routes coalesce duplicate changes; old and new positions both route',async()=>{
  const store=createMemoryStore();
  await store.transact(async tx=>{
    await replaceRoutes(tx,catalog,'t','old',[range('r',{value:0n},{value:2n}),field()]);
    await replaceRoutes(tx,catalog,'t','new',[range('r',{value:8n},{value:10n})]);
  });
  await store.read(async tx=>{
    const change={sourceId:'source',selector:{field:'x'}};
    const result=await affectedSubscribers(tx,catalog,'t',{fields:[change,change],points:[point(1),point(9),point(9)]});
    assert.deepEqual(result.subscribers,['new','old']);assert.equal(result.metrics.directEntries,1);assert.equal(result.matches.length,3);
  });
});

test('tenant/catalog isolation and empty descriptors persist',async()=>{
  const store=createMemoryStore(), other={...catalog,identity:'other'};
  await store.transact(async tx=>{
    await replaceRoutes(tx,catalog,'t','s',[field(),range('empty',{value:9n},{value:1n})]);
    await replaceRoutes(tx,catalog,'u','s',[range('r')]);
    await replaceRoutes(tx,other,'t','s',[range('r')]);
  });
  await store.read(async tx=>{
    assert.equal((await readRoutes(tx,catalog,'t','s')).length,2);
    assert.deepEqual((await affectedSubscribers(tx,catalog,'t',{points:[point(2)]})).matches,[]);
    assert.equal((await affectedSubscribers(tx,catalog,'u',{points:[point(2)]})).matches.length,1);
    assert.equal((await affectedSubscribers(tx,other,'t',{points:[point(2)]})).matches.length,1);
  });
  await store.transact(tx=>replaceRoutes(tx,catalog,'t','s',[]));
  await store.read(async tx=>assert.deepEqual(await readRoutes(tx,catalog,'t','s'),[]));
});

test('validation precedes writes; rollback and budget exhaustion reject atomically',async()=>{
  const store=createMemoryStore();await store.transact(tx=>replaceRoutes(tx,catalog,'t','s',[field(),range('r')]));
  for(const rs of [[field(),field()],[{...field(),selector:{field:'unknown'}}],[{...range('r'),view:'missing'}],[{...range('r'),aggregate:'missing'}],[{...range('r'),partition:[]}],[{...range('r'),typo:true}]]) {
    await store.transact(async tx=>{await assert.rejects(replaceRoutes(tx,catalog,'t','s',rs));assert.equal(tx.inspect().metrics.stagedWrites,0);});
  }
  await assert.rejects(store.transact(async tx=>{await replaceRoutes(tx,catalog,'t','s',[]);throw Error('abort');}),/abort/);
  await store.read(async tx=>{
    assert.equal((await readRoutes(tx,catalog,'t','s')).length,2);
    await assert.rejects(affectedSubscribers(tx,catalog,'t',{points:[point(0)]},{maxVisits:0}),{code:'ROUTE_BUDGET'});
    await assert.rejects(affectedSubscribers(tx,catalog,'t',{fields:[{sourceId:'source',selector:{field:'x'}}],points:[point(0)]},{maxVisits:1}),{code:'ROUTE_BUDGET'});
  });
});

test('missing expected direct/range rows reject rather than repair',async()=>{
  for(const kind of ['direct','row','node']) {
    const store=createMemoryStore();await store.transact(tx=>replaceRoutes(tx,catalog,'t','s',[field(),range('r')]));
    await store.transact(async tx=>{
      const entries=await tx.scan();const victim=entries.find(({key})=>kind==='node'?key.startsWith('node/'):key.includes(`/${kind}/`));assert.ok(victim);await tx.delete(victim.key);
    });
    await assert.rejects(store.transact(tx=>replaceRoutes(tx,catalog,'t','s',[])),{code:'CORRUPT_STATE'});
  }
});

test('identical replacements preserve a shared interval forest with zero physical changes',async()=>{
  const store=createMemoryStore();
  const registrations=[field(),range('bounded',{value:2n},{value:5n}),range('unbounded',undefined,{value:8n})];
  await store.transact(async tx=>{
    for(let i=0;i<12;i++)await replaceRoutes(tx,catalog,'t',`s${i}`,[range('r',{value:BigInt(i)},{value:BigInt(i+3)})]);
    await replaceRoutes(tx,catalog,'t','subscriber',registrations);
  });
  await store.transact(tx=>replaceRoutes(tx,catalog,'t','subscriber',registrations),{
    beforeCommit({changes}) {assert.deepEqual(changes,[]);},
  });
});

test('finite direct visit budgets bound returned scan entries and detect overflow',async()=>{
  const store=createMemoryStore();
  await store.transact(async tx=>{for(let i=0;i<8;i++)await replaceRoutes(tx,catalog,'t',`s${i}`,[field()]);});
  await store.read(async tx=>{
    const limits=[];
    const bounded={...tx,scan:async options=>{limits.push(options.limit);const rows=await tx.scan(options);assert.ok(rows.length<=3);return rows;}};
    await assert.rejects(affectedSubscribers(bounded,catalog,'t',{fields:[{sourceId:'source',selector:{field:'x'}}]},{maxVisits:2}),{code:'ROUTE_BUDGET'});
    assert.deepEqual(limits,[3]);
  });
});
