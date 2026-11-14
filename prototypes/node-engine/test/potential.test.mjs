import test from 'node:test';
import assert from 'node:assert/strict';
import {prepareCatalog} from '../src/catalog.mjs';
import {createMemoryStore} from '../src/memory.mjs';
import {replacePotential,potentialPredecessors,potentialCatalog} from '../src/potential.mjs';
import {potentialOwnerKey,nodeKey,occurrenceToken} from '../src/keys.mjs';
import {causalDefinition,causalCalculations,causalRecord} from '../examples/causal.mjs';
const definition=structuredClone(causalDefinition);
definition.models.result.memberships.push({...definition.models.result.memberships[0],slot:'second'});
const catalog=prepareCatalog(definition,{calculations:causalCalculations()});
const output=(id,at=0,group='g')=>({role:id,record:causalRecord(id,'result',{amount:'0',group,at:String(at)}),computed:['amount']});
const query=(slot='q',cuts={})=>({slot,kind:'range',view:'effective',partition:['g'],aggregate:'total',...cuts});
const field=id=>({slot:id,kind:'field',sourceId:id,selector:{field:'amount'}});
const flat=(outputs,q)=>outputs.filter(o=>{
  for(const slot of ['main','second']) {
    let included=true;
    for(const [side,sign] of [['lower',-1],['upper',1]]) {
      const b=q[side];if(!b)continue;
      let c=BigInt(o.record.data.at)<b.value?-1:BigInt(o.record.data.at)>b.value?1:0;
      if(!c&&b.sourceId!==undefined)c=o.record.id<b.sourceId?-1:o.record.id>b.sourceId?1:slot<b.slot?-1:slot>b.slot?1:0;
      if(c===sign||(!c&&b.inclusive===false))included=false;
    }
    if(included)return true;
  }
  return false;
}).map(o=>`p${o.record.id}`).sort();

test('seeded replace, move and removal queries agree with flat complete-cut oracle without scans',async()=>{
  const store=createMemoryStore(),outputs=new Map();let seed=791;
  const random=()=>seed=(Math.imul(seed,1664525)+1013904223)>>>0;
  for(let step=0;step<70;step++) {
    const id=`o${random()%17}`,old=outputs.get(id),next=random()%4?output(id,random()%7):undefined;
    await store.transact(tx=>replacePotential(tx,catalog,'t',`p${id}`,old?[old]:[],next?[next]:[]));
    if(next)outputs.set(id,next);else outputs.delete(id);
    await store.read(async tx=>{
      const cut=()=>({value:BigInt(random()%8),inclusive:!!(random()%2),...(random()%2?{sourceId:`o${random()%17}`,slot:random()%2?'main':'second'}:{})});
      const reads=[query('all'),query('random',{lower:cut(),upper:cut()}),query('lower',{lower:cut()})];
      const safe={get:tx.get,scan:()=>assert.fail('Potential lookup scanned')};
      const got=await potentialPredecessors(safe,catalog,'t',reads);
      assert.deepEqual(got.bySlot,reads.map(q=>({slot:q.slot,producers:flat([...outputs.values()],q)})));
    });
  }
});

test('potential templates remain predecessors with absent actual output; repeated bindings deduplicate',async()=>{
  const store=createMemoryStore(),o=output('a',2);
  await store.transact(tx=>replacePotential(tx,catalog,'t','producer',[],[o]));
  await store.read(async tx=>{
    assert.deepEqual((await potentialPredecessors(tx,catalog,'t',[query(),field('a'),field('absent')])).bySlot,[{slot:'q',producers:['producer']},{slot:'a',producers:['producer']},{slot:'absent',producers:[]}]);
    assert.deepEqual((await potentialPredecessors(tx,catalog,'other',[query()])).bySlot,[{slot:'q',producers:[]}]);
    await assert.rejects(potentialPredecessors(tx,catalog,'t',[query()],{maxVisits:0}),{code:'POTENTIAL_BUDGET'});
    await assert.rejects(potentialPredecessors(tx,catalog,'t',[field('a')],{maxVisits:0}),{code:'POTENTIAL_BUDGET'});
  });
  await store.transact(async tx=>{
    let writes=0;const wrapped={get:tx.get,set:async()=>{writes++;},delete:async()=>{writes++;}};
    await replacePotential(wrapped,catalog,'t','producer',[o],[o]);assert.equal(writes,0);
  });
  await assert.rejects(store.transact(tx=>replacePotential(tx,catalog,'t','intruder',[],[o])),{code:'CORRUPT_STATE'});
  await store.transact(tx=>tx.set(potentialOwnerKey(catalog,'t','a'),{producer:'producer',extra:true}));
  await assert.rejects(store.read(tx=>potentialPredecessors(tx,catalog,'t',[field('a')])),{code:'CORRUPT_STATE'});
});

test('orphaned and missing tree positions reject guarded replacement and range reads',async()=>{
  const store=createMemoryStore(),o=output('a');
  await store.transact(tx=>replacePotential(tx,catalog,'t','p',[],[o]));
  const scope={tenant:'t',view:'effective',partition:['g']},internal=potentialCatalog(catalog);
  await store.transact(tx=>tx.delete(nodeKey(internal,scope,occurrenceToken({sourceId:'a',slot:'main'}))));
  await assert.rejects(store.read(tx=>potentialPredecessors(tx,catalog,'t',[query()])),{code:'CORRUPT_STATE'});
  await assert.rejects(store.transact(tx=>replacePotential(tx,catalog,'t','p',[o],[o])),{code:'CORRUPT_STATE'});
});

test('narrow predecessor queries charge bounded height work and enforce exact budgets',async()=>{
  const store=createMemoryStore();
  await store.transact(async tx=>{
    for(let i=0;i<127;i++)await replacePotential(tx,catalog,'t',`p${i}`,[],[output(`o${String(i).padStart(3,'0')}`,i)]);
  });
  await store.read(async tx=>{
    const reads=[query('narrow',{lower:{value:63n},upper:{value:63n}})];
    const result=await potentialPredecessors(tx,catalog,'t',reads);
    assert.deepEqual(result.bySlot,[{slot:'narrow',producers:['p63']}]);
    assert.ok(result.visits<35,`logical visits ${result.visits}`);
    assert.deepEqual(await potentialPredecessors(tx,catalog,'t',reads,{maxVisits:result.visits}),result);
    await assert.rejects(potentialPredecessors(tx,catalog,'t',reads,{maxVisits:result.visits-1}),{code:'POTENTIAL_BUDGET'});
  });
});
