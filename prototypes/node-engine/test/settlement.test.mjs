import test from 'node:test';
import assert from 'node:assert/strict';
import { prepareCatalog, createMemoryStore, mutate, checkStore, settlementOracle, canonical, fingerprint } from '../src/index.mjs';
import { sourceKey, sourcePrefix, producerPrefix, reservationPrefix, potentialOwnerPrefix, allNodesPrefix } from '../src/keys.mjs';
import { causalDefinition, causalCalculations, causalRecord, causalAnchor, causalOutput, causalDiamond } from '../examples/causal.mjs';
const put=record=>({type:'put',record}), del=id=>({type:'delete',id});
const snapshot=store=>store.read(tx=>tx.scan());
const amount=(store,id)=>store.read(async tx=>(await tx.get(sourceKey('t',causalOutput(id))))?.data.amount);
function config(){return {definition:structuredClone(causalDefinition),calculations:causalCalculations()};}
function setup(c=config(),options={}){return {store:createMemoryStore(),catalog:prepareCatalog(c.definition,{calculations:c.calculations,...options})};}
async function verify(store,catalog){
  await checkStore(store,catalog,'t');
  const records=await store.read(async tx=>(await tx.scan({prefix:sourcePrefix('t')})).map(r=>r.value));
  const reservations=await store.read(async tx=>(await tx.scan({prefix:reservationPrefix(catalog,'t')})).map(r=>r.value));
  const oracle=await settlementOracle(catalog,'t',records.filter(r=>!catalog.models[r.model].managed),{reservations});
  assert.deepEqual(records.filter(r=>catalog.models[r.model].managed).sort((a,b)=>a.id.localeCompare(b.id)),oracle.generated.toSorted((a,b)=>a.id.localeCompare(b.id)));
}
async function rejectsAtomic(store,action,code){const before=await snapshot(store);await assert.rejects(action,code?{code}:undefined);assert.deepEqual(await snapshot(store),before);}

test('integrated diamond settles hand-computed values, coalesces joint changes and ignores source order',async()=>{
  for(const reverse of [false,true]){
    const {store,catalog}=setup(),records=causalDiamond();
    const result=await mutate(store,catalog,'t',(reverse?records.toReversed():records).map(put));
    assert.deepEqual(await Promise.all(['A','B','D'].map(id=>amount(store,id))),['20','30','50']);
    assert.equal(result.settlement.evaluated,3);assert.equal(result.settlement.edges,2);assert.equal(result.settlement.pending,3);
    records[0].data.amount='5';await mutate(store,catalog,'t',[put(records[0])]);
    assert.deepEqual(await Promise.all(['A','B','D'].map(id=>amount(store,id))),['10','15','25']);
    records[1].data.factor='4';records[2].data.factor='5';
    const joint=await mutate(store,catalog,'t',(reverse?[records[2],records[1]]:[records[1],records[2]]).map(put));
    assert.equal(joint.settlement.evaluated,3);assert.equal(await amount(store,'D'),'45');await verify(store,catalog);
  }
});

test('resolver parent and changed dependency with equal output install final routes',async()=>{
  const {store,catalog}=setup(),base=causalDiamond()[0],a=causalAnchor('A',['base'],'1',{parent:'P'}),p=causalAnchor('P',[],'2',{enabled:false}),q=causalAnchor('Q',[],'2',{enabled:false});
  await mutate(store,catalog,'t',[base,a,p,q].map(put));assert.equal(await amount(store,'A'),'20');
  a.data.parent='Q';await mutate(store,catalog,'t',[put(a)]);assert.equal(await amount(store,'A'),'20');
  q.data.factor='7';await mutate(store,catalog,'t',[put(q)]);assert.equal(await amount(store,'A'),'70');
  p.data.factor='9';const result=await mutate(store,catalog,'t',[put(p)]);assert.equal(result.settlement.evaluated,1);assert.equal(await amount(store,'A'),'70');await verify(store,catalog);
});

test('final range bounds reverse old causal ordering in both command orders',async()=>{
  for(const reverse of [false,true]){
    const c=config(),resolve=c.calculations.derive.resolve;
    c.calculations.derive.resolve=async args=>{const shape=await resolve(args);shape.reads=[{slot:'range',kind:'range',view:'effective',partition:[args.record.data.sources[0]],aggregate:'total',lower:{value:0n},upper:{value:BigInt(args.record.data.at)}}];return shape;};
    const {store,catalog}=setup(c),base=causalDiamond()[0];
    await mutate(store,catalog,'t',[base,causalAnchor('A',['base'],'2'),causalAnchor('B',['A'],'3',{at:'2'})].map(put));assert.equal(await amount(store,'B'),'60');
    const changes=[causalAnchor('B',['base'],'3'),causalAnchor('A',['B'],'2',{at:'2'})];await mutate(store,catalog,'t',(reverse?changes.toReversed():changes).map(put));
    assert.equal(await amount(store,'B'),'30');assert.equal(await amount(store,'A'),'60');await verify(store,catalog);
  }
});

test('old managed positions are withdrawn before a query can consume a moved predecessor',async()=>{
  const c=config(),resolve=c.calculations.derive.resolve;
  c.calculations.derive.resolve=async args=>{const shape=await resolve(args);if(args.record.data.range){shape.reads=[{slot:'range',kind:'range',view:'effective',partition:['inputs'],aggregate:'total',upper:{value:2n}}];shape.outputs[0].data.group='results';}return shape;};
  const {store,catalog}=setup(c),base=causalDiamond()[0],a=causalAnchor('A',['base'],'2',{group:'inputs',at:'1'}),reader=causalAnchor('R',[],'1',{range:true});
  await mutate(store,catalog,'t',[base,a,reader].map(put));assert.equal(await amount(store,'R'),'20');
  a.data.at='9';await mutate(store,catalog,'t',[put(a)]);assert.equal(await amount(store,'R'),'0');await verify(store,catalog);
});

test('disabled potential cycle rejects before evaluation and preserves complete snapshot',async()=>{
  const c=config();let evaluations=0;const evaluate=c.calculations.derive.evaluate;c.calculations.derive.evaluate=args=>{evaluations++;return evaluate(args);};
  const {store,catalog}=setup(c);await rejectsAtomic(store,()=>mutate(store,catalog,'t',[causalAnchor('A',[causalOutput('B')],'1',{enabled:false}),causalAnchor('B',[causalOutput('A')],'1',{enabled:false})].map(put)),'CALCULATION_CYCLE');assert.equal(evaluations,0);
});

test('optional absent field source existence invalidates direct evaluation',async()=>{
  const c=config();c.definition.models.fact.schema.required=['group','at'];for(const m of c.definition.models.fact.memberships)m.onMissing='skip';
  c.calculations.derive.evaluate=({values})=>({outputs:{value:{amount:values.source0.exists?'7':'3'}}});
  const {store,catalog}=setup(c);await mutate(store,catalog,'t',[put(causalAnchor('A',['optional']))]);assert.equal(await amount(store,'A'),'3');
  await mutate(store,catalog,'t',[put(causalRecord('optional','fact',{group:'g',at:'0'}))]);assert.equal(await amount(store,'A'),'7');
  await mutate(store,catalog,'t',[del('optional')]);assert.equal(await amount(store,'A'),'3');await verify(store,catalog);
});

test('ignored invalid resolver read rejects and closes read facade',async()=>{
  const c=config(),resolve=c.calculations.derive.resolve;let facade;
  c.calculations.derive.resolve=args=>{facade=args.readField;args.readField(causalOutput('forbidden'),{field:'amount'});return resolve(args);};
  const {store,catalog}=setup(c);await rejectsAtomic(store,()=>mutate(store,catalog,'t',[put(causalAnchor('A',[]))]),'INVALID_CALCULATION');
  await assert.rejects(async()=>facade('base',{field:'amount'}),{code:'INVALID_CALCULATION'});
});

test('null reactivation deletion retain ledger and reject changed first timestamp and model',async()=>{
  const c=config();c.definition.models.otherResult=structuredClone(c.definition.models.result);
  const resolve=c.calculations.derive.resolve;let model='result';c.calculations.derive.resolve=async args=>{const shape=await resolve(args);shape.outputs[0].model=model;return shape;};
  const {store,catalog}=setup(c),a=causalAnchor('A',[]);await mutate(store,catalog,'t',[put(a)]);
  const ledger=await store.read(tx=>tx.scan({prefix:reservationPrefix(catalog,'t')}));assert.equal(ledger.length,1);
  a.data.enabled=false;await mutate(store,catalog,'t',[put(a)]);assert.equal(await amount(store,'A'),undefined);
  a.data.enabled=true;await mutate(store,catalog,'t',[put(a)]);assert.equal(await amount(store,'A'),'0');
  await mutate(store,catalog,'t',[del('A')]);assert.deepEqual(await store.read(tx=>tx.scan({prefix:reservationPrefix(catalog,'t')})),ledger);
  a.createdAt='2';await rejectsAtomic(store,()=>mutate(store,catalog,'t',[put(a)]),'INVALID_CALCULATION');a.createdAt='1';model='otherResult';
  await rejectsAtomic(store,()=>mutate(store,catalog,'t',[put(a)]),'INVALID_CALCULATION');model='result';await mutate(store,catalog,'t',[put(a)]);await verify(store,catalog);
});

test('authored managed and generated identity create update delete commands reject including retired IDs',async()=>{
  const {store,catalog}=setup();await mutate(store,catalog,'t',[put(causalAnchor('A',[]))]);
  const id=causalOutput('A');
  for(const command of [put(causalRecord('forged','result',{amount:'1',group:'g',at:'0'})),put(causalRecord(id,'fact',{amount:'1',group:'g',at:'0'})),del(id),put(causalRecord(causalOutput('unknown'),'fact',{amount:'1',group:'g',at:'0'}))])await rejectsAtomic(store,()=>mutate(store,catalog,'t',[command]));
  await mutate(store,catalog,'t',[del('A')]);await rejectsAtomic(store,()=>mutate(store,catalog,'t',[del(id)]));await verify(store,catalog);
});

test('live empty potential scope validates identity even when actual output is null',async()=>{
  const c=config();c.definition.contracts.amounts.validators=[{scope:'root',use:'positive'}];
  const {store,catalog}=setup(c,{validators:{positive:{version:'1',validate:s=>s.total>0n}}});
  await rejectsAtomic(store,()=>mutate(store,catalog,'t',[put(causalAnchor('A',[],'1',{enabled:false}))]),'VALIDATION_FAILED');
});

test('one joint beforeCommit contains private and public staging and failure restores every byte',async()=>{
  const {store,catalog}=setup(),records=causalDiamond();await mutate(store,catalog,'t',records.map(put));records[1].data.factor='4';let calls=0;
  await rejectsAtomic(store,()=>mutate(store,catalog,'t',[put(records[1])],{beforeCommit:({changes})=>{calls++;assert.ok(changes.some(c=>c.key.startsWith(sourcePrefix('t'))));assert.ok(changes.some(c=>c.key.startsWith(producerPrefix(catalog,'t'))));throw new Error('publication fault');}}));assert.equal(calls,1);await verify(store,catalog);
});

test('explicit logical budgets reject atomically with clear calculation budget errors',async()=>{
  for(const [budget,code] of [[{maxProducers:2},'CALCULATION_BUDGET'],[{maxEdges:1},'CALCULATION_BUDGET'],[{maxRouteVisits:0},'ROUTE_BUDGET'],[{maxPotentialVisits:0},'POTENTIAL_BUDGET']]){
    const {store,catalog}=setup();await rejectsAtomic(store,()=>mutate(store,catalog,'t',causalDiamond().map(put),budget),code);
  }
});

test('disjoint producer stays unevaluated and no-op has no writes or full source producer scans',async()=>{
  const c=config(),calls=new Map(),resolve=c.calculations.derive.resolve,evaluate=c.calculations.derive.evaluate;
  c.calculations.derive.resolve=async args=>{const shape=await resolve(args);shape.parameters.anchor=args.record.id;return shape;};
  c.calculations.derive.evaluate=args=>{calls.set(args.parameters.anchor,(calls.get(args.parameters.anchor)||0)+1);return evaluate(args);};
  const {store,catalog}=setup(c),base=causalDiamond()[0],other=causalRecord('other','fact',{amount:'7',group:'other',at:'0'}),a=causalAnchor('A',['base'],'2'),u=causalAnchor('U',['other'],'3');
  await mutate(store,catalog,'t',[base,other,a,u].map(put));calls.clear();const prefixes=[];
  const traced={...store,transact:(callback,options)=>store.transact(tx=>callback({...tx,scan:async options=>{prefixes.push(options?.prefix);return tx.scan(options);}}),options)};
  base.data.amount='5';await mutate(traced,catalog,'t',[put(base)]);assert.equal(calls.get('A'),1);assert.equal(calls.has('U'),false);assert.equal(await amount(store,'U'),'21');
  assert.ok(!prefixes.includes(sourcePrefix('t')));assert.ok(!prefixes.includes(producerPrefix(catalog,'t')));assert.ok(!prefixes.includes(undefined));
  calls.clear();let writes;const result=await mutate(traced,catalog,'t',[put(base)],{beforeCommit:event=>{writes=event.changes;}});
  assert.equal(calls.size,0);assert.deepEqual(writes,[]);assert.equal(result.metrics.metrics.stagedWrites,0);await verify(store,catalog);
});

test('seeded authored mutations agree with independent recomputation after each transition',async()=>{
  const {store,catalog}=setup(),facts=new Map(),anchors=new Map();let seed=0x12345678;
  const random=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;};
  for(let i=0;i<4;i++){const id=`f${i}`;facts.set(id,causalRecord(id,'fact',{amount:String(i+1),group:'inputs',at:String(i)}));}
  for(let i=0;i<3;i++)anchors.set(`a${i}`,causalAnchor(`a${i}`,[`f${i}`],String(i+1)));
  await mutate(store,catalog,'t',[...facts.values(),...anchors.values()].map(put));
  for(let step=0;step<24;step++){
    const n=random()%4,id=`f${n}`;let command;
    if(step%6===0){facts.delete(id);command=del(id);}
    else if(step%3===0){const a=anchors.get(`a${random()%3}`);a.data.enabled=!a.data.enabled;a.data.factor=String(random()%5);a.data.at=String(random()%9);command=put(a);}
    else {const f=causalRecord(id,'fact',{amount:String(Number(random()%21)-10),group:random()%2?'inputs':'moved',at:String(random()%9)});facts.set(id,f);command=put(f);}
    await mutate(store,catalog,'t',[command]);await verify(store,catalog);
    for(const a of anchors.values())assert.equal(await amount(store,a.id),a.data.enabled?String(BigInt(facts.get(a.data.sources[0])?.data.amount??'0')*BigInt(a.data.factor)):undefined,`seeded transition ${step}, ${a.id}`);
  }
});

test('checker rejects independent corruption of producer routes potential owner node and reservation',async()=>{
  for(const kind of ['producer','route','owner','potential-node','reservation']){
    const {store,catalog}=setup();await mutate(store,catalog,'t',causalDiamond().map(put));
    const prefix=kind==='producer'?producerPrefix(catalog,'t'):kind==='owner'?potentialOwnerPrefix(catalog,'t'):kind==='reservation'?reservationPrefix(catalog,'t'):kind==='route'?`routes/v1/`:allNodesPrefix({identity:fingerprint(['internal-potential-avl-v1',catalog.identity])},'t');
    await store.transact(async tx=>{const rows=await tx.scan({prefix});assert.ok(rows.length,kind);const row=rows[0];if(kind==='producer'){row.value.parameters={factor:999n,enabled:true};await tx.set(row.key,row.value);}else if(kind==='reservation'){row.value.createdAt='999';await tx.set(row.key,row.value);}else await tx.delete(row.key);});
    await assert.rejects(checkStore(store,catalog,'t'),{code:kind==='reservation'?'INVALID_CALCULATION':'INTEGRITY'},kind);
  }
});

test('omitted reverse invalidation produces stale arithmetic which independent checker detects',async()=>{
  const {store,catalog}=setup(),base=causalDiamond()[0];await mutate(store,catalog,'t',[base,causalAnchor('A',['base'],'2')].map(put));
  await store.transact(async tx=>{
    const routes=(await tx.scan({prefix:'routes/v1/'})).filter(row=>row.key.includes('/direct/'));
    const row=routes.find(row=>row.key.includes(canonical(['base',{field:'amount'}])));assert.ok(row,'base amount reverse route');await tx.delete(row.key);
  });
  base.data.amount='5';await mutate(store,catalog,'t',[put(base)]);assert.equal(await amount(store,'A'),'20','missing route deliberately leaves old output');
  await assert.rejects(checkStore(store,catalog,'t'),{code:'INTEGRITY'});
});
