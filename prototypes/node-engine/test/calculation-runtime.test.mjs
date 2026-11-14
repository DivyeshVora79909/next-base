import test from 'node:test';
import assert from 'node:assert/strict';
import {prepareCatalog} from '../src/catalog.mjs';
import {sourceKey} from '../src/keys.mjs';
import {resolveProducer,evaluateProducer,registrationsFor,signalsForSource,signalsForOutputs} from '../src/calculation-runtime.mjs';
import {settlementOracle} from '../src/calculation-oracle.mjs';
import {causalDefinition,causalCalculations,causalAnchor,causalRecord} from '../examples/causal.mjs';
const setup=()=>{const calculations=causalCalculations();return {calculations,catalog:prepareCatalog(structuredClone(causalDefinition),{calculations})};};
const reader=records=>({get:async key=>records.find(r=>sourceKey(r.tenant,r.id)===key)});

test('production shape and registrations match independent reference',async()=>{
  const {catalog}=setup(),anchor=causalAnchor('A',['base'],'2'),base=causalRecord('base','fact',{amount:'10',group:'base',at:'0'});
  const producer=await resolveProducer(reader([base,anchor]),catalog,'t',anchor,catalog.models[anchor.model].calculations[0]);
  const expected=await settlementOracle(catalog,'t',[base,anchor]);
  assert.deepEqual(producer,expected.producers[0]);
  assert.deepEqual(registrationsFor(producer),expected.routes[0].registrations);
  assert.deepEqual(await evaluateProducer(reader([base,anchor]),catalog,'t',producer,catalog.models[anchor.model].calculations[0].implementation),expected.generated);
});

test('ignored asynchronous resolver failures are latched and reads drained',async()=>{
  const {catalog}=setup(),anchor=causalAnchor('A',[],'2');let drained=false,late;
  const implementation={resolve:({readField})=>{
    late=readField;readField('bad',{field:'factor'});readField('slow',{field:'factor'});
    return {parameters:{},reads:[],outputs:[]};
  }};
  const tx={get:async key=>{if(key===sourceKey('t','bad')) throw new Error('ignored failure');await new Promise(resolve=>setTimeout(resolve,5));drained=true;return undefined;}};
  await assert.rejects(resolveProducer(tx,catalog,'t',anchor,{slot:'main',implementation}),/ignored failure/);
  assert.equal(drained,true);
  assert.throws(()=>late('slow',{field:'factor'}),/closed/);
});

test('resolver read registration order follows calls despite completion order and data is frozen',async()=>{
  const {catalog}=setup(),anchor=causalAnchor('A',[],'2');
  const tx={get:async key=>{if(key===sourceKey('t','first'))await new Promise(r=>setTimeout(r,5));return undefined;}};
  const implementation={resolve:({record,readField})=>{
    assert.equal(Object.isFrozen(record.data),true);
    readField('first',{field:'factor'});readField('second',{field:'factor'});
    return {parameters:{},reads:[],outputs:[]};
  }};
  const producer=await resolveProducer(tx,catalog,'t',anchor,{slot:'main',implementation});
  assert.deepEqual(producer.resolveReads.map(r=>r.sourceId),['first','first','second','second']);
});

test('computed patch must preserve template topology and exact shape',async()=>{
  const {catalog}=setup(),anchor=causalAnchor('A',[],'2');
  const producer=await resolveProducer(reader([anchor]),catalog,'t',anchor,catalog.models[anchor.model].calculations[0]);
  await assert.rejects(evaluateProducer(reader([]),catalog,'t',producer,{evaluate:()=>({outputs:{value:{amount:'1',at:'8'}}})}),/keys/);
  producer.outputs[0].computed.push('at');
  await assert.rejects(evaluateProducer(reader([]),catalog,'t',producer,{evaluate:()=>({outputs:{value:{amount:'1',at:'8'}}})}),/topology/);
  await assert.rejects(evaluateProducer(reader([]),catalog,'t',producer,{evaluate:async()=>({outputs:{value:null}})}),/synchronous/);
});

test('source signals suppress unchanged values and report existence; potential signals include every schema field',async()=>{
  const {catalog}=setup(),record=causalRecord('base','fact',{amount:'10',group:'base',at:'0'});
  assert.deepEqual(signalsForSource(catalog,record,structuredClone(record)),{fields:[],points:[]});
  const created=signalsForSource(catalog,undefined,record);
  assert.ok(created.fields.some(r=>r.selector.header==='id'));assert.ok(created.points.length>0);
  const changed=signalsForSource(catalog,record,{...record,data:{...record.data,amount:'12'}});
  assert.deepEqual(changed.fields,[{sourceId:'base',selector:{field:'amount'}}]);
  assert.ok(changed.points.every(p=>p.aggregate==='total'||p.aggregate==='prefix'));
  const anchor=causalAnchor('A',[],'2'),producer=await resolveProducer(reader([anchor]),catalog,'t',anchor,catalog.models[anchor.model].calculations[0]);
  const signals=signalsForOutputs(catalog,producer.outputs),model=catalog.models[producer.outputs[0].record.model];
  assert.equal(signals.fields.filter(r=>r.selector.field).length,Object.keys(model.schema.properties).length);
});

test('optional Object prototype names compare as own fields during source signaling',()=>{
  const definition=structuredClone(causalDefinition);
  for (const name of ['constructor']) Object.defineProperty(definition.models.anchor.schema.properties,name,{value:{type:'string'},enumerable:true});
  const catalog=prepareCatalog(definition,{calculations:causalCalculations()}),old=causalAnchor('A',[]);
  for (const name of ['constructor']) {
    const next={...old,data:{...old.data,[name]:'present'}};
    assert.deepEqual(signalsForSource(catalog,old,next),{fields:[{sourceId:'A',selector:{field:name}}],points:[]});
    assert.deepEqual(signalsForSource(catalog,next,old),{fields:[{sourceId:'A',selector:{field:name}}],points:[]});
  }
});

test('point read boundaries reject malformed or miskeyed stored sources and preserve absence',async()=>{
  const {catalog}=setup(),anchor=causalAnchor('A',[]),source=causalRecord('base','fact',{amount:'10',group:'base',at:'0'});
  const rule=catalog.models.anchor.calculations[0];
  const explicit={...anchor,data:{...anchor.data,sources:['base']}};
  const resolverRule={slot:'main',implementation:{resolve:async({readField})=>{
    await readField('base',{field:'amount'});return {parameters:{},reads:[],outputs:[]};
  }}};
  const good=await resolveProducer(reader([source]),catalog,'t',explicit,rule);
  for (const stored of [null,false,{...source,id:'other'},{...source,tenant:'other'}, {...source,data:{amount:'invalid'}}]) {
    const tx={get:async()=>stored};
    await assert.rejects(resolveProducer(tx,catalog,'t',anchor,resolverRule));
    await assert.rejects(resolveProducer(tx,catalog,'t',explicit,rule));
    await assert.rejects(evaluateProducer(tx,catalog,'t',good,rule.implementation));
  }
  for (const stored of [source,undefined]) {
    const tx={get:async()=>stored};
    await resolveProducer(tx,catalog,'t',anchor,resolverRule);
    const producer=await resolveProducer(tx,catalog,'t',explicit,rule);
    const generated=await evaluateProducer(tx,catalog,'t',producer,rule.implementation);
    assert.equal(generated[0].data.amount,stored?'10':'0');
  }
});
