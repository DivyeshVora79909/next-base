import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeRange, compareKey, containsRange } from '../src/range.mjs';
import { createMemoryStore } from '../src/memory.mjs';
import { standardMonoids } from '../src/monoids.mjs';
import { treePut, treeAggregate, readRoot } from '../src/tree.mjs';

const scope={tenant:'t',view:'v',partition:[]};
const catalog={identity:'range-test',views:{v:{identity:'v',contract:{order:'integer',partition:[],aggregates:{sum:{implementation:standardMonoids.sum},prefix:{implementation:standardMonoids.prefix}}}}}};
// Independent UTF-8 tuple comparator and bound oracle; no range implementation helpers.
const cmp=(a,b)=>a.order<b.order?-1:a.order>b.order?1:Buffer.compare(Buffer.from(a.sourceId),Buffer.from(b.sourceId))||Buffer.compare(Buffer.from(a.slot),Buffer.from(b.slot));
const accepts=(o,b,lower)=>{
  if(!b)return true;
  const v=BigInt(b.value), c=o.order<v?-1:o.order>v?1:Object.hasOwn(b,'sourceId')?cmp(o,{order:v,sourceId:b.sourceId,slot:b.slot}):0;
  return lower ? c>0||(c===0&&b.inclusive!==false) : c<0||(c===0&&b.inclusive!==false);
};
const fold=items=>({sum:items.reduce((a,o)=>a+o.contributions.sum,0n),prefix:items.reduce((a,o)=>standardMonoids.prefix.combine(a,o.contributions.prefix),standardMonoids.prefix.identity())});

test('scalar and complete cuts agree with flat oracle across ties, mixed cuts and empty ranges',async()=>{
  const store=createMemoryStore(),items=[];
  for(const order of [-1n,0n,1n])for(const sourceId of ['a','é','\uE000','😀'])for(const slot of ['', 'a','😀']){
    const value=BigInt(items.length%7)-3n;
    items.push({...scope,order,sourceId:`${order}:${sourceId}`,slot,contributions:{sum:value,prefix:standardMonoids.prefix.lift(value)}});
  }
  const sorted=[...items].sort(cmp);
  await store.transact(async tx=>{for(const o of [...items].reverse())await treePut(tx,catalog,o);});
  const cuts=[undefined];
  for(const value of [-2n,-1n,0n,1n,2n])for(const inclusive of [true,false])cuts.push({value,inclusive});
  for(const o of sorted.filter((_,i)=>i%4===0))for(const inclusive of [true,false])cuts.push({value:o.order.toString(),sourceId:o.sourceId,slot:o.slot,inclusive});
  await store.read(async tx=>{
    for(const lower of cuts)for(const upper of cuts){
      const expected=fold(sorted.filter(o=>accepts(o,lower,true)&&accepts(o,upper,false)));
      const actual=await treeAggregate(tx,catalog,scope,{lower,upper});
      assert.deepEqual({...actual},expected);
    }
  });
});

test('range normalization is exact, detached and strict about malformed cuts',()=>{
  const input=Object.freeze({lower:Object.freeze({value:'9007199254740993',sourceId:'é',slot:'',inclusive:false})});
  const range=normalizeRange('integer',input);
  assert.deepEqual(range,{lower:{value:9007199254740993n,sourceId:'é',slot:'',inclusive:false}});
  assert.notEqual(range.lower,input.lower);
  range.lower.slot='changed';assert.equal(input.lower.slot,'');
  assert.deepEqual(normalizeRange('integer',{upper:{value:1n}}),{upper:{value:1n,inclusive:true}});
  for(const options of [null,[],true,{low:{}},{lower:null},{upper:[]},{lower:{value:1n,inclusve:true}},{lower:{value:1n,sourceId:'a'}},{lower:{value:1n,slot:''}},{lower:{value:1n,inclusive:0}},{lower:{value:1n,[Symbol()]:1}}])assert.throws(()=>normalizeRange('integer',options),{code:'INVALID_RANGE'});
  for(const bound of [{value:true},{value:1},{value:'01'},{value:1n,sourceId:'',slot:''},{value:1n,sourceId:'a',slot:'\uD800'},{value:1n,sourceId:'\uD800',slot:''}])assert.throws(()=>normalizeRange('integer',{lower:bound}),{code:'INVALID_VALUE'});
  const getter={};Object.defineProperty(getter,'lower',{enumerable:true,get(){throw Error('executed');}});
  assert.throws(()=>normalizeRange('integer',getter),{code:'INVALID_RANGE'});
});

test('complete keys compare by binary UTF-8 for identifiers and slots',()=>{
  const a={order:1n,sourceId:'\uE000',slot:''},b={order:'1',sourceId:'😀',slot:''};
  assert.equal(compareKey('integer',a,b),-1);
  assert.equal(compareKey('integer',{...a,slot:'\uE000'},{...a,slot:'😀'}),-1);
  assert.equal(containsRange('integer',a,normalizeRange('integer',{lower:{value:'1',sourceId:a.sourceId,slot:''},upper:{value:1n,sourceId:a.sourceId,slot:''}})),true);
});

test('narrow complete cuts follow boundary spines at scale without scans',async()=>{
  const store=createMemoryStore(),items=[];
  await store.transact(async tx=>{
    for(let i=0;i<2048;i++){
      const o={...scope,order:0n,sourceId:`s${String(i).padStart(5,'0')}`,slot:'m',contributions:{sum:1n,prefix:standardMonoids.prefix.lift(1n)}};
      items.push(o);await treePut(tx,catalog,o);
    }
  });
  for(const [lo,hi,inclusive] of [[1000,1000,true],[1000,1000,false],[1000,1003,true],[1800,200,true]])await store.read(async tx=>{
    const height=(await readRoot(tx,catalog,scope)).height, before=tx.inspect().metrics.gets;
    const cut=i=>({value:'0',sourceId:items[i].sourceId,slot:'m',inclusive});
    const actual=await treeAggregate(tx,catalog,scope,{lower:cut(lo),upper:cut(hi)});
    assert.equal(actual.sum,lo>hi||!inclusive?0n:BigInt(hi-lo+1));
    const metrics=tx.inspect().metrics;
    assert.ok(metrics.gets-before<=8*height+2);assert.equal(metrics.scans,0);
  });
});
