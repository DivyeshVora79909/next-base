import test from 'node:test';
import assert from 'node:assert/strict';
import {prepareCatalog} from '../src/catalog.mjs';
import {settlementOracle,producerId} from '../src/calculation-oracle.mjs';
import {causalDefinition,causalCalculations,causalRecord,causalAnchor,causalOutput,causalDiamond} from '../examples/causal.mjs';
const setup=()=>({definition:structuredClone(causalDefinition),calculations:causalCalculations()});
const prepare=({definition,calculations}=setup())=>prepareCatalog(definition,{calculations});
const amounts=result=>Object.fromEntries(result.generated.map(record=>[record.id,record.data.amount]));
const amount=(result,id,slot='main')=>amounts(result)[causalOutput(id,slot)];

test('complete snapshot arithmetic diamond settles exact values independent of authored enumeration',async()=>{
  const records=causalDiamond(),catalog=prepare();
  for(const snapshot of [records,[...records].reverse(),[records[3],records[1],records[0],records[2]]]){
    const result=await settlementOracle(catalog,'t',snapshot);
    assert.equal(amount(result,'A'),'20'); assert.equal(amount(result,'B'),'30'); assert.equal(amount(result,'D'),'50');
    assert.equal(result.producers.length,3); assert.equal(result.edges.length,2);
  }
});

test('final moved dependency bounds replace old ordering; all final snapshot permutations agree',async()=>{
  const config=setup(),resolve=config.calculations.derive.resolve;
  config.calculations.derive.resolve=async args=>{
    const shape=await resolve(args);
    shape.reads=[{slot:'range',kind:'range',view:'effective',partition:[args.record.data.sources[0]],aggregate:'total',lower:{value:0n},upper:{value:BigInt(args.record.data.at)}}];
    return shape;
  };
  const catalog=prepare(config);
  const base=causalRecord('base','fact',{amount:'10',group:'base',at:'0'});
  const old=[base,causalAnchor('A',['base'],'2'),causalAnchor('B',['A'],'3',{at:'2'})];
  assert.equal(amount(await settlementOracle(catalog,'t',old),'B'),'60');
  const final=[base,causalAnchor('B',['base'],'3'),causalAnchor('A',['B'],'2',{at:'2'})];
  for(const snapshot of [final,[final[0],final[2],final[1]],[final[1],final[0],final[2]],[final[1],final[2],final[0]],[final[2],final[0],final[1]],[...final].reverse()]){
    const result=await settlementOracle(catalog,'t',snapshot);
    assert.equal(amount(result,'B'),'30');assert.equal(amount(result,'A'),'60');
    assert.ok(result.order.indexOf(producerId('t','B','main'))<result.order.indexOf(producerId('t','A','main')));
  }
});

test('potential zero-output cycle rejects before evaluating disabled producers',async()=>{
  const config=setup();let calls=0;
  const evaluate=config.calculations.derive.evaluate;
  config.calculations.derive.evaluate=args=>{calls++;return evaluate(args);};
  await assert.rejects(settlementOracle(prepare(config),'t',[
    causalAnchor('A',[causalOutput('B')],'1',{enabled:false}),causalAnchor('B',[causalOutput('A')],'1',{enabled:false}),
  ]),{code:'CALCULATION_CYCLE'});assert.equal(calls,0);
});

test('empty range registration survives and a later complete snapshot activates it',async()=>{
  const anchor=causalAnchor('reader',[],'2',{range:true,group:'inputs'});
  // Keep output outside its own queried partition, otherwise the potential shape is cyclic.
  const config=setup(),resolve=config.calculations.derive.resolve;
  config.calculations.derive.resolve=async args=>{const shape=await resolve(args);shape.outputs[0].data.group='results';return shape;};
  const catalog=prepare(config),empty=await settlementOracle(catalog,'t',[anchor]);
  assert.equal(amount(empty,'reader'),'0');assert.ok(empty.routes.length>0);
  const active=await settlementOracle(catalog,'t',[anchor,causalRecord('new','fact',{amount:'7',group:'inputs',at:'0'})]);
  assert.equal(amount(active,'reader'),'14');
});

test('authored parent field changes resolver parameters and is protected as a read',async()=>{
  const catalog=prepare(),records=causalDiamond().slice(0,2);
  records[1].data.parent='parent';
  records.push(causalAnchor('parent',[],'4',{enabled:false}));
  const before=await settlementOracle(catalog,'t',records);assert.equal(amount(before,'A'),'40');
  records[2].data.factor='9';const after=await settlementOracle(catalog,'t',records);assert.equal(amount(after,'A'),'90');
  assert.ok(after.producers.find(p=>p.anchorId==='A').resolveReads.length>0);
});

test('absent generated record retains producer edge and reactivation retains reserved identity and first timestamp',async()=>{
  const catalog=prepare(),records=causalDiamond();records[1].data.enabled=false;
  const absent=await settlementOracle(catalog,'t',records);
  assert.equal(amount(absent,'A'),undefined);assert.equal(amount(absent,'D'),'30');assert.equal(absent.edges.length,2);
  const removed=await settlementOracle(catalog,'t',records.filter(r=>r.id!=='A'),{reservations:absent.reservations});
  records[1].data.enabled=true;records[1].createdAt='99';
  await assert.rejects(settlementOracle(catalog,'t',records,{reservations:removed.reservations}),{code:'INVALID_CALCULATION'});
  records[1].createdAt='1';
  const active=await settlementOracle(catalog,'t',records,{reservations:removed.reservations});
  assert.equal(amount(active,'A'),'20');assert.equal(active.generated.find(r=>r.id===causalOutput('A')).createdAt,'1');
  assert.deepEqual(active.reservations,absent.reservations);
});

test('multiple calculation slots and repeated memberships preserve count and noncommutative prefix',async()=>{
  const records=[causalRecord('negative','fact',{amount:'-4',group:'g',at:'0'}),causalRecord('positive','fact',{amount:'6',group:'g',at:'1'}),
    {...causalAnchor('adjust',['positive'],'3'),model:'adjustment'}];
  const result=await settlementOracle(prepare(),'t',records);
  assert.equal(result.producers.length,2);assert.equal(amount(result,'adjust'),'18');assert.equal(amount(result,'adjust','bonus'),'36');
  const tree=result.inventory.trees.find(t=>t.view==='doubled');
  assert.equal(tree.count,4);assert.deepEqual(tree.aggregates.prefix,{sum:4n,minPrefix:-8n});
  records[0].data.at='2';const reversed=await settlementOracle(prepare(),'t',records);
  assert.deepEqual(reversed.inventory.trees.find(t=>t.view==='doubled').aggregates.prefix,{sum:4n,minPrefix:0n});
});

test('computed topology, extra patches, asynchronous evaluation and resource budgets reject',async()=>{
  for(const variant of ['position','extra','async']){
    const config=setup();
    if(variant==='position'){
      const resolve=config.calculations.derive.resolve;
      config.calculations.derive.resolve=async args=>{const shape=await resolve(args);shape.outputs[0].computed.push('at');return shape;};
      config.calculations.derive.evaluate=()=>({outputs:{value:{amount:'1',at:'4'}}});
    }else if(variant==='extra')config.calculations.derive.evaluate=()=>({outputs:{value:{amount:'1',at:'4'}}});
    else config.calculations.derive.evaluate=()=>Promise.resolve({outputs:{value:{amount:'1'}}});
    await assert.rejects(settlementOracle(prepare(config),'t',causalDiamond()),{
      code:'INVALID_CALCULATION',
      ...(variant==='position'?{message:'Computed patch changes topology'}:{}),
    });
  }
  await assert.rejects(settlementOracle(prepare(),'t',causalDiamond(),{maxProducers:2}),{code:'CALCULATION_BUDGET'});
  await assert.rejects(settlementOracle(prepare(),'t',causalDiamond(),{maxEdges:1}),{code:'CALCULATION_BUDGET'});
});

test('managed input and reserved authored IDs reject',async()=>{
  const catalog=prepare();
  await assert.rejects(settlementOracle(catalog,'t',[causalRecord('forged','result',{amount:'1',group:'g',at:'1'})]),{code:'INVALID_CALCULATION'});
  await assert.rejects(settlementOracle(catalog,'t',[causalRecord(causalOutput('unknown'),'fact',{amount:'1',group:'g',at:'1'})]),{code:'INVALID_CALCULATION'});
});

test('missing optional field is represented distinctly from absent source',async()=>{
  const config=setup();config.definition.models.fact.schema.required=['group','at'];
  for(const membership of config.definition.models.fact.memberships)membership.onMissing='skip';
  const evaluate=config.calculations.derive.evaluate;let observed;
  config.calculations.derive.evaluate=args=>{observed=args.values;return evaluate(args);};
  const result=await settlementOracle(prepare(config),'t',[
    causalRecord('missing','fact',{group:'g',at:'0'}),causalAnchor('A',['missing','absent']),
  ]);
  assert.equal(amount(result,'A'),'0');
  assert.deepEqual({...observed.source0},{exists:true,present:false});
  assert.deepEqual({...observed.source1},{exists:false,present:false});
});

test('final generated reference and uniqueness constraints reject invalid settled graphs',async()=>{
  const references=setup();
  references.definition.models.result.references=[{slot:'group',field:'group',targets:['fact'],many:false,onDelete:'reject'}];
  await assert.rejects(settlementOracle(prepare(references),'t',causalDiamond()),{code:'INVALID_REFERENCE'});
  const unique=setup();
  unique.definition.models.result.uniqueness=[{slot:'group',fields:[{field:'group'}]}];
  const records=causalDiamond();records[1].data.group='same';records[2].data.group='same';
  await assert.rejects(settlementOracle(prepare(unique),'t',records),{code:'DUPLICATE_CLAIM'});
});

test('final exact summary constraints include generated amounts',async()=>{
  const config=setup();config.definition.contracts.amounts.validators=[{scope:'root',use:'nonnegative'}];
  const catalog=prepareCatalog(config.definition,{calculations:config.calculations,validators:{nonnegative:{version:'1',validate:summary=>summary.total>=0n}}});
  const records=causalDiamond();records[1].data.factor='-2';
  await assert.rejects(settlementOracle(catalog,'t',records),{code:'VALIDATION_FAILED'});
});

test('resolver topology cannot read computed managed outputs',async()=>{
  const records=causalDiamond();records[3].data.parent=causalOutput('A');
  await assert.rejects(settlementOracle(prepare(),'t',records),{code:'INVALID_CALCULATION'});
});

test('resolver read facade rejects ignored invalid calls synchronously and closes after resolution',async()=>{
  const invalid=setup(),original=invalid.calculations.derive.resolve;let rejectedFacade;
  invalid.calculations.derive.resolve=args=>{
    rejectedFacade=args.readField;
    // Deliberately no await: a rejected promise here could otherwise be discarded.
    args.readField(causalOutput('managed'),{field:'amount'});
    return original(args);
  };
  await assert.rejects(settlementOracle(prepare(invalid),'t',[causalAnchor('A',[])]),{code:'INVALID_CALCULATION'});
  assert.throws(()=>rejectedFacade('base',{field:'amount'}),{code:'INVALID_CALCULATION'});

  const valid=setup(),resolve=valid.calculations.derive.resolve;let retained,read;
  valid.calculations.derive.resolve=args=>{
    retained=args.readField;read=args.readField('base',{field:'amount'});
    assert.equal(read.value,'10');assert.ok(Object.isFrozen(read));
    assert.throws(()=>{read.value='999';},TypeError);
    return resolve(args);
  };
  const result=await settlementOracle(prepare(valid),'t',causalDiamond());
  assert.equal(amount(result,'A'),'20');
  assert.throws(()=>retained('base',{field:'amount'}),{code:'INVALID_CALCULATION'});
});

test('evaluation field routes protect existence when optional value stays absent',async()=>{
  const config=setup();config.definition.models.fact.schema.required=['group','at'];
  for(const membership of config.definition.models.fact.memberships)membership.onMissing='skip';
  config.calculations.derive.evaluate=({values})=>({outputs:{value:{amount:values.source0.exists?'7':'3'}}});
  const catalog=prepare(config),anchor=causalAnchor('A',['optional']);
  const absent=await settlementOracle(catalog,'t',[anchor]);
  const present=await settlementOracle(catalog,'t',[anchor,causalRecord('optional','fact',{group:'g',at:'0'})]);
  assert.equal(amount(absent,'A'),'3');assert.equal(amount(present,'A'),'7');
  for(const result of [absent,present]){
    const route=result.routes.find(route=>route.subscriber===producerId('t','A','main'));
    const selectors=route.registrations.filter(read=>read.kind==='field'&&read.sourceId==='optional').map(read=>({...read.selector}));
    assert.ok(selectors.some(selector=>selector.field==='amount'));
    assert.ok(selectors.some(selector=>selector.header==='id'));
  }
});

test('retired reservation ledger validates model identity output ID and canonical timestamp',async()=>{
  const catalog=prepare(),seed=await settlementOracle(catalog,'t',[causalAnchor('A',[])]);
  for(const change of [
    entry=>{entry.model='missing';},
    entry=>{entry.model='fact';},
    entry=>{entry.outputId=causalOutput('other');},
    entry=>{entry.createdAt=1n;},
    entry=>{entry.extra='unexpected';},
  ]){
    const reservations=structuredClone(seed.reservations);change(reservations[0]);
    await assert.rejects(settlementOracle(catalog,'t',[],{reservations}),{code:'INVALID_CALCULATION'});
  }
  const retired=await settlementOracle(catalog,'t',[],{reservations:seed.reservations});
  assert.equal(retired.generated.length,0);assert.deepEqual(retired.reservations,seed.reservations);
});
