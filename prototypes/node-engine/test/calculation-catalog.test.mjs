import test from 'node:test';
import assert from 'node:assert/strict';
import { prepareCatalog } from '../src/catalog.mjs';
import { fingerprint } from '../src/values.mjs';
import { createMemoryStore } from '../src/memory.mjs';
import { mutate } from '../src/mutate.mjs';
import { checkStore } from '../src/check.mjs';
const definition = () => ({ name:'calc',version:'1',contracts:{},views:{},models:{source:{schema:{type:'object',properties:{},additionalProperties:false},calculations:[{slot:'result',use:'derive'}]},output:{managed:true,schema:{type:'object',properties:{},additionalProperties:false}}} });
const implementation = () => ({version:'1',resolve:async()=>({}),evaluate:()=>({})});
const prepare = (d=definition(), impl=implementation()) => prepareCatalog(d,{calculations:{derive:impl}});

test('managed models cannot be written directly even without an active calculation', async () => {
  for (const d of [definition(), { ...definition(), models: { output: definition().models.output } }]) {
    const catalog = prepare(d), store = createMemoryStore();
    const record = { id: 'forged', tenant: 'tenant', owner: 'owner', model: 'output', createdAt: '1', data: {} };
    await assert.rejects(mutate(store, catalog, 'tenant', [{ type: 'put', record }]), { code: 'INVALID_CALCULATION' });
    assert.deepEqual(await store.read(tx => tx.scan()), []);
    await mutate(store, catalog, 'tenant', []);
    assert.equal((await checkStore(store, catalog, 'tenant')).sources, 0);
  }
});

test('static mutation fast path also protects generated identities and rejects misspelled options', async () => {
  const d = definition(); delete d.models.source.calculations; delete d.models.output;
  const catalog = prepareCatalog(d), store = createMemoryStore();
  const record = { id: '@next/derived/forged', tenant: 'tenant', owner: 'owner', model: 'source', createdAt: '1', data: {} };
  for (const change of [{ type: 'put', record }, { type: 'delete', id: record.id }]) {
    await assert.rejects(mutate(store, catalog, 'tenant', [change]), { code: 'INVALID_CALCULATION' });
  }
  await assert.rejects(mutate(store, catalog, 'tenant', [], { maxProducer: 1 }), { code: 'INVALID_MUTATION' });
  assert.deepEqual(await store.read(tx => tx.scan()), []);
  assert.equal((await checkStore(store, catalog, 'tenant')).sources, 0);
});

test('calculation compilation copies and freezes declarations and implementation references',()=>{
  const d=definition(),impl=implementation(),p=prepare(d,impl),rule=p.models.source.calculations[0];
  assert.equal(p.models.source.managed,false); assert.equal(p.models.output.managed,true);
  assert.deepEqual(p.models.output.calculations,[]);
  assert.deepEqual(Object.keys(rule.implementation).sort(),['evaluate','resolve','version']);
  assert.equal(rule.implementation.resolve,impl.resolve); assert.equal(rule.implementation.evaluate,impl.evaluate);
  for(const value of [rule,rule.implementation,p.models.source.calculations]) assert.ok(Object.isFrozen(value));
  assert.equal(Object.isFrozen(impl.resolve),false);
  const original=impl.resolve; impl.resolve=async()=>null; impl.version='2'; d.models.source.calculations[0].use='other';
  assert.equal(rule.implementation.resolve,original); assert.equal(rule.implementation.version,'1'); assert.equal(rule.use,'derive');
  assert.doesNotThrow(()=>prepare(definition(),{...implementation(),resolve:()=>({})}));
});

test('identity pins used versions and declarations without hashing callback source',()=>{
  const d=definition(),a=prepare(d);
  assert.equal(a.identity,prepare(d,{version:'1',resolve:()=>null,evaluate:()=>null}).identity);
  assert.notEqual(a.identity,prepare(d,{...implementation(),version:'2'}).identity);
  const b=definition(); b.models.source.calculations[0].slot='other'; assert.notEqual(a.identity,prepare(b).identity);
  assert.equal(a.identity,prepareCatalog(d,{calculations:{derive:implementation(),unused:{version:'9'}}}).identity);
  delete d.models.source.calculations; delete d.models.output.managed;
  const p=prepareCatalog(d); assert.equal(p.identity,fingerprint({declaration:d,monoids:{},validators:{}})); assert.equal(p.identity,prepare(d).identity);
  for(const model of Object.values(p.models)){assert.equal(model.managed,false);assert.deepEqual(model.calculations,[]);}
});

test('malformed calculation declarations, managed anchors and implementations reject',()=>{
  for(const change of [
    d=>d.models.source.calculations.push({slot:'result',use:'derive'}),
    d=>d.models.source.calculations[0].slot='', d=>d.models.source.calculations[0].use='',
    d=>d.models.source.calculations[0].use='missing',d=>d.models.source.calculations[0].extra=true,
    d=>d.models.source.calculations={},d=>d.models.source.calculations=null,
    d=>d.models.source.managed='yes',d=>d.models.source.managed=null,d=>d.models.source.managed=true,
    d=>d.models.source.dependencies=[{}],d=>d.calculations=[{}],
  ]){const d=definition();change(d);assert.throws(()=>prepare(d),{code:'INVALID_CATALOG'});}
  const nonJson=definition(); nonJson.models.source.calculations[0].use=()=>null; assert.throws(()=>prepare(nonJson),{code:'INVALID_VALUE'});
  for(const impl of [{},{version:'1'},{...implementation(),version:''},{...implementation(),version:1},{...implementation(),resolve:null},{...implementation(),evaluate:null},{...implementation(),evaluate:async()=>({})}]) assert.throws(()=>prepare(definition(),impl),{code:'INVALID_CATALOG'});
  assert.throws(()=>prepareCatalog(definition(),{calculations:Object.create({derive:implementation()})}),{code:'INVALID_CATALOG'});
});

test('contract and view calculations and all nonempty dependencies remain unsupported',()=>{
  for(const location of ['catalog','contract','view'])for(const key of ['calculations','dependencies']){
    const d={name:'placement',version:'1',contracts:{c:{version:'1',partition:[],order:'integer',inputs:{},aggregates:{}}},views:{v:{contract:'c'}},models:{}};
    const target=location==='catalog'?d:location==='contract'?d.contracts.c:d.views.v;target[key]=[{slot:'result',use:'derive'}];
    assert.throws(()=>prepare(d),{code:'INVALID_CATALOG'});
  }
});
