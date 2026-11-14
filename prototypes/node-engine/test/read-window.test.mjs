import test from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryStore } from '../src/memory.mjs';
import { treePut } from '../src/tree.mjs';
import { treeReadWindow } from '../src/read-window.mjs';
import { nodeKey, rootKey } from '../src/keys.mjs';
import { canonical } from '../src/values.mjs';

const catalog = { identity: 'window-test', views: { v: { identity: 'v', contract: { order: 'integer', partition: [], aggregates: {} } } } };
const scope = { tenant: 't', view: 'v', partition: [] };
const limits = { maxNodes: 100000, maxBatches: 100000, maxBytes: 100000000, maxOutput: 100000, batchKeys: 32 };
const bytes = value => Buffer.byteLength(canonical(value));
const textCompare = (a,b) => Buffer.compare(Buffer.from(a),Buffer.from(b));
const compare = (a,b) => a.order < b.order ? -1 : a.order > b.order ? 1 : textCompare(a.sourceId,b.sourceId) || textCompare(a.slot,b.slot);
const row = (i, order = i, slot = 'm') => ({ ...scope, sourceId: `s${String(i).padStart(5,'0')}`, slot, order: BigInt(order), contributions: {} });
const project = (o, rank) => ({ rank, sourceId: o.sourceId, slot: o.slot, order: o.order });
function oracle(items, options = {}) {
  const { ranks = {}, range = {} } = options;
  return [...items].sort(compare).map(project).filter(o => {
    if (o.rank < (ranks.start ?? 0) || o.rank >= (ranks.end ?? Infinity)) return false;
    for (const side of ['lower','upper']) {
      const cut = range[side]; if (!cut) continue;
      const value = BigInt(cut.value);
      const c = Object.hasOwn(cut,'sourceId') ? compare(o,{order:value,sourceId:cut.sourceId,slot:cut.slot}) : o.order < value ? -1 : o.order > value ? 1 : 0;
      if (side === 'lower' ? c < 0 || (c === 0 && cut.inclusive === false) : c > 0 || (c === 0 && cut.inclusive === false)) return false;
    }
    return true;
  });
}
async function fixture(items) {
  const store = createMemoryStore();
  await store.transact(async tx => { for (const item of items) await treePut(tx,catalog,item); });
  return store;
}
function instrument(tx) {
  const calls = [], seen = new Set(); let readBytes = 0;
  return { calls, seen, get readBytes() { return readBytes; }, tx: {
    async getMany(keys) {
      calls.push([...keys]);
      const values = await tx.getMany(keys);
      keys.forEach((key,i) => { readBytes += Buffer.byteLength(key) + (values[i] === undefined ? 0 : bytes(values[i])); if (key.startsWith('node/')) { assert.ok(!seen.has(key),'node fetched twice'); seen.add(key); } });
      return values;
    },
    get() { assert.fail('reader must use getMany'); }, scan() { assert.fail('reader scanned'); },
    set() { assert.fail('reader wrote'); }, delete() { assert.fail('reader deleted'); },
  } };
}

test('raw rank/range intersection agrees with independent sorted occurrence oracle', async () => {
  const items = Array.from({length:41},(_,i) => row(i,i%7));
  items.push({...row(3,3,'a')},{...row(3,3,'é')},{...row(3,3,'😀')},{...row(3,3,'z')});
  const store = await fixture(items);
  const options = [{}, {ranks:{start:0,end:0}}, {ranks:{start:4,end:25}}, {ranks:{start:100,end:200}}, {range:{lower:{value:'2'},upper:{value:4n,inclusive:false}}}, {range:{lower:{value:4n},upper:{value:2n}}}];
  for (const inclusive of [true,false]) {
    options.push({range:{lower:{value:3n,inclusive},upper:{value:3n,inclusive}}});
    options.push({ranks:{start:8,end:30},range:{lower:{value:3n,sourceId:row(3).sourceId,slot:'a',inclusive},upper:{value:5n,sourceId:row(33).sourceId,slot:'not-present',inclusive}}});
  }
  for (const option of options) await store.read(async tx => {
    const watched = instrument(tx), result = await treeReadWindow(watched.tx,catalog,scope,{...option,limits});
    assert.equal(result.total,items.length);
    assert.deepEqual(result.occurrences,oracle(items,option));
    assert.equal(result.metrics.outputs,result.occurrences.length);
    assert.equal(result.metrics.nodes,watched.seen.size);
    assert.equal(result.metrics.batches,watched.calls.length);
    assert.equal(result.metrics.readBytes,watched.readBytes);
    assert.equal(result.metrics.outputBytes,result.occurrences.reduce((n,o)=>n+bytes(o),0));
    assert.ok(watched.calls.every(keys=>keys.length>0 && keys.length<=limits.batchKeys));
  });
});

test('empty roots and namespaces remain isolated', async () => {
  const store = await fixture([row(1)]);
  for (const other of [{...scope,tenant:'other'},scope]) await store.read(async tx => {
    const result = await treeReadWindow(tx,catalog,other,{limits});
    assert.equal(result.total,other.tenant==='t'?1:0);
    assert.equal(result.occurrences.length,result.total);
  });
});

test('finite limits reject atomically at each measured boundary', async () => {
  const store = await fixture(Array.from({length:31},(_,i)=>row(i)));
  const baseline = await store.read(tx=>treeReadWindow(tx,catalog,scope,{limits}));
  const exact = {...limits,maxNodes:baseline.metrics.nodes,maxBatches:baseline.metrics.batches,maxBytes:baseline.metrics.readBytes+baseline.metrics.outputBytes,maxOutput:baseline.metrics.outputs};
  assert.deepEqual((await store.read(tx=>treeReadWindow(tx,catalog,scope,{limits:exact}))).occurrences,baseline.occurrences);
  for (const key of ['maxNodes','maxBatches','maxBytes','maxOutput']) {
    await assert.rejects(store.read(tx=>treeReadWindow(tx,catalog,scope,{limits:{...exact,[key]:exact[key]-1}})),{code:'WORK_LIMIT'});
  }
});

test('read options reject malformed finite budgets and rank windows', async () => {
  const store = createMemoryStore();
  const bad = [undefined,{}, {limits:{}}, {limits:{...limits,extra:1}}, {limits:{...limits,batchKeys:0}}, {limits:{...limits,maxBytes:Infinity}}, {limits:{...limits,maxNodes:-1}}, {limits:{...limits,maxOutput:1.5}}, {limits,ranks:{start:-1}}, {limits,ranks:{start:3,end:2}}, {limits,ranks:{end:Number.MAX_SAFE_INTEGER+1}}, {limits,extra:1}];
  for (const option of bad) await assert.rejects(store.read(tx=>treeReadWindow(tx,catalog,scope,option)),{code:'INVALID_READ'});
  await assert.rejects(store.read(tx=>treeReadWindow(tx,catalog,scope,{limits,range:{lower:{value:'01'}}})),{code:'INVALID_VALUE'});
});

test('frontier traversal has linear node work and height-bounded waves', async () => {
  for (const n of [255,256,257,1023]) {
    const items = Array.from({length:n},(_,i)=>row(i)), store = await fixture(items);
    await store.read(async tx => {
      const root = await tx.get(rootKey(catalog,scope));
      const node = await tx.get(nodeKey(catalog,scope,root.head));
      for (const option of [{},{ranks:{start:Math.floor(n/2),end:Math.floor(n/2)+3}}]) {
        const watched = instrument(tx), result = await treeReadWindow(watched.tx,catalog,scope,{...option,limits:{...limits,batchKeys:4096}});
        assert.deepEqual(result.occurrences,oracle(items,option));
        assert.ok(result.metrics.nodes<=n);
        assert.ok(result.metrics.waves<=node.height+1);
        if (option.ranks) assert.ok(result.metrics.nodes<=8*node.height+12,'narrow read traversed excessive nodes');
      }
    });
  }
});

test('loaded corruption fails without repair', async () => {
  for (const damage of ['missing','cycle','count','order','height','shared','identity','link','header']) {
    const store = await fixture([row(1),row(0),row(2)]);
    await store.transact(async tx => {
      const header = await tx.get(rootKey(catalog,scope)), root = await tx.get(nodeKey(catalog,scope,header.head));
      if (damage==='header') await tx.set(rootKey(catalog,scope),{head:null});
      else if (damage==='missing') await tx.delete(nodeKey(catalog,scope,root.left));
      else if (damage==='order') { const child = await tx.get(nodeKey(catalog,scope,root.left)); child.order=99n; await tx.set(nodeKey(catalog,scope,root.left),child); }
      else { if(damage==='identity')root.slot='wrong'; if(damage==='link')root.left=42; if(damage==='cycle')root.left=header.head; if(damage==='count')root.size++; if(damage==='height')root.height++; if(damage==='shared')root.right=root.left; await tx.set(nodeKey(catalog,scope,header.head),root); }
    });
    await assert.rejects(store.read(tx=>treeReadWindow(instrument(tx).tx,catalog,scope,{limits})),{code:'CORRUPT_STATE'});
  }
});

test('queued mutation cannot mix snapshots across batch waves', async () => {
  const items = Array.from({length:15},(_,i)=>row(i)), store = await fixture(items);
  let signal, resume; let inserted = false;
  const reached = new Promise(resolve => { signal = resolve; });
  const released = new Promise(resolve => { resume = resolve; });
  const reading = store.read(async tx => {
    let calls = 0;
    const wrapped = { async getMany(keys) { const values = await tx.getMany(keys); if (++calls===2) { signal(); await released; } assert.equal(inserted,false); return values; } };
    return treeReadWindow(wrapped,catalog,scope,{limits:{...limits,batchKeys:2}});
  });
  await reached;
  const queued = store.transact(async writer=>{await treePut(writer,catalog,row(99));inserted=true;});
  resume();
  const result = await reading;
  await queued;
  assert.deepEqual(result.occurrences,oracle(items));
  assert.equal(inserted,true);
  assert.equal((await store.read(tx=>treeReadWindow(tx,catalog,scope,{limits}))).total,16);
});

// Child remains locally ordered beneath its parent while violating an ancestor cut.
test('ancestor ordering cuts reject locally plausible descendants', async () => {
  const store = await fixture([row(4),row(2),row(6),row(1),row(3),row(5),row(7)]);
  await store.transact(async tx => {
    const header = await tx.get(rootKey(catalog,scope));
    const root = await tx.get(nodeKey(catalog,scope,header.head));
    const left = await tx.get(nodeKey(catalog,scope,root.left));
    const descendant = await tx.get(nodeKey(catalog,scope,left.right));
    descendant.order = 5n;
    await tx.set(nodeKey(catalog,scope,left.right),descendant);
  });
  await assert.rejects(store.read(tx=>treeReadWindow(tx,catalog,scope,{limits})),{code:'CORRUPT_STATE'});
});

test('malformed fetched head links reject even empty or disjoint rank windows', async () => {
  for (const self of [true,false]) {
    const store = await fixture([row(1),row(0),row(2)]);
    await store.transact(async tx => {
      const header = await tx.get(rootKey(catalog,scope));
      const head = await tx.get(nodeKey(catalog,scope,header.head));
      if (self) head.left = header.head; else head.right = head.left;
      await tx.set(nodeKey(catalog,scope,header.head),head);
    });
    for (const ranks of [{start:0,end:0},{start:20,end:30}]) await assert.rejects(store.read(tx=>treeReadWindow(tx,catalog,scope,{limits,ranks})),{code:'CORRUPT_STATE'});
  }
});

test('ordinary activity mutations produce raw windows matching source-only oracle', async () => {
  const { prepareCatalog } = await import('../src/catalog.mjs');
  const { mutate } = await import('../src/mutate.mjs');
  const { sourceOracle } = await import('../src/oracle.mjs');
  const { activityDefinition, activityRecords } = await import('../examples/activity.mjs');
  const prepared = prepareCatalog(activityDefinition), store = createMemoryStore(), records = activityRecords();
  await mutate(store,prepared,'tenant',records.toReversed().map(record=>({type:'put',record})));
  records[1].data.effective='3';
  await mutate(store,prepared,'tenant',[{type:'put',record:records[1]}]);
  const expected = sourceOracle(prepared,records);
  await store.read(async tx => {
    for (const tree of expected.trees) {
      const result = await treeReadWindow(instrument(tx).tx,prepared,{tenant:tree.tenant,view:tree.view,partition:tree.partition},{limits});
      assert.equal(result.total,tree.count);
      assert.deepEqual(result.occurrences,tree.members.map(project));
    }
  });
});

test('string and boolean order domains preserve cuts and stable ties', async () => {
  for (const [domain,values,lower] of [['string',['😀','z','é','a','é'],'z'],['boolean',[true,false,true,false],true]]) {
    const prepared = {...catalog,views:{v:{...catalog.views.v,contract:{...catalog.views.v.contract,order:domain}}}};
    const items=values.map((order,i)=>({...row(i),order})), store=createMemoryStore();
    await store.transact(async tx=>{for(const item of items)await treePut(tx,prepared,item);});
    const cmp=(a,b)=>(domain==='string'?textCompare(a.order,b.order):Number(a.order)-Number(b.order))||textCompare(a.sourceId,b.sourceId);
    const sorted=[...items].sort(cmp).map(project);
    const expected=sorted.filter(o=>domain==='string'?textCompare(o.order,lower)>=0:o.order>=lower);
    const result=await store.read(tx=>treeReadWindow(instrument(tx).tx,prepared,scope,{limits,range:{lower:{value:lower}}}));
    assert.deepEqual(result.occurrences,expected);
  }
});

test('same-transaction adjacent rank and exclusive complete-key pages compose across ties', async () => {
  const items = [row(1,2,'a'),row(1,2,'b'),row(1,2,'c'),row(2,2,'a'),row(3,1),row(4,3)];
  const store=await fixture(items), expected=oracle(items), mid=3;
  await store.read(async tx=>{
    const first=await treeReadWindow(tx,catalog,scope,{limits,ranks:{start:0,end:mid}});
    const adjacent=await treeReadWindow(tx,catalog,scope,{limits,ranks:{start:mid,end:items.length}});
    assert.deepEqual([...first.occurrences,...adjacent.occurrences],expected);
    const last=first.occurrences.at(-1);
    const continued=await treeReadWindow(tx,catalog,scope,{limits,range:{lower:{value:last.order,sourceId:last.sourceId,slot:last.slot,inclusive:false}}});
    assert.deepEqual([...first.occurrences,...continued.occurrences],expected);
    const empty=await treeReadWindow(tx,catalog,scope,{limits,ranks:{start:0,end:0}});
    assert.equal(empty.occurrences.at(-1),undefined);
    const restarted=await treeReadWindow(tx,catalog,scope,{limits});
    assert.deepEqual([...empty.occurrences,...restarted.occurrences],expected);
  });
});
