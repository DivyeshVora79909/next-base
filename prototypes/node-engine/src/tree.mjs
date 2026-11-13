import { decodeDomain, fail } from './values.mjs';
import { compareKey, normalizeRange, belowRange, aboveRange } from './range.mjs';
import { rootKey, nodeKey, occurrenceToken } from './keys.mjs';

function enter(seen, token) {
  if (seen.has(token)) fail('CORRUPT_STATE', 'Cyclic tree traversal');
  seen.add(token);
}

function context(tx, catalog, scope) {
  const view = catalog.views[scope.view];
  if (!view) fail('INVALID_VIEW', 'Unknown view');
  const contract = view.contract;
  const get = async token => {
    if (token === null) return undefined;
    if (typeof token !== 'string') fail('CORRUPT_STATE', 'Invalid tree link');
    const node = await tx.get(nodeKey(catalog, scope, token));
    if (!node || occurrenceToken(node) !== token || !Number.isSafeInteger(node.height) || node.height < 1 || !Number.isSafeInteger(node.size) || node.size < 1 || ![node.left,node.right].every(link => link === null || typeof link === 'string')) fail('CORRUPT_STATE', 'Missing or mismatched tree node');
    return node;
  };
  const identity = () => Object.assign(Object.create(null), Object.fromEntries(Object.entries(contract.aggregates).map(([k,a]) => [k,a.implementation.identity()])));
  const combine = (a,b) => Object.assign(Object.create(null), Object.fromEntries(Object.entries(contract.aggregates).map(([k,v]) => [k,v.implementation.combine(a[k], b[k])])));
  const compare = (a,b) => compareKey(contract.order,a,b);
  const save = async n => {
    const [l,r] = await Promise.all([get(n.left),get(n.right)]);
    n.height = 1 + Math.max(l?.height ?? 0,r?.height ?? 0);
    n.size = 1 + (l?.size ?? 0) + (r?.size ?? 0);
    if (!Number.isSafeInteger(n.size)) fail('COUNT_OVERFLOW', 'Tree size exceeds safe integer');
    n.aggregates = combine(combine(l?.aggregates ?? identity(),n.contributions),r?.aggregates ?? identity());
    await tx.set(nodeKey(catalog,scope,occurrenceToken(n)),n);
    return n;
  };
  const rotate = async (n, direction) => {
    const other = direction === 'left' ? 'right' : 'left';
    const child = await get(n[other]);
    n[other] = child[direction];
    child[direction] = occurrenceToken(n);
    await save(n); await save(child);
    return child;
  };
  const balance = async n => {
    await save(n);
    const [l,r] = await Promise.all([get(n.left),get(n.right)]);
    if ((l?.height ?? 0) - (r?.height ?? 0) > 1) {
      const [ll,lr] = await Promise.all([get(l.left),get(l.right)]);
      if ((lr?.height ?? 0) > (ll?.height ?? 0)) n.left = occurrenceToken(await rotate(l,'left'));
      return rotate(n,'right');
    }
    if ((r?.height ?? 0) - (l?.height ?? 0) > 1) {
      const [rl,rr] = await Promise.all([get(r.left),get(r.right)]);
      if ((rl?.height ?? 0) > (rr?.height ?? 0)) n.right = occurrenceToken(await rotate(r,'right'));
      return rotate(n,'left');
    }
    return n;
  };
  return {get,identity,combine,compare,save,balance,contract};
}
export async function readRoot(tx,catalog,scope) {
  const header = await tx.get(rootKey(catalog,scope));
  if (header === undefined) return undefined;
  if (!header || typeof header.head !== 'string') fail('CORRUPT_STATE', 'Invalid root header');
  return context(tx,catalog,scope).get(header.head);
}
async function setHead(tx,catalog,scope,before,after) {
  if (before === after) return;
  if (after === null) await tx.delete(rootKey(catalog,scope));
  else await tx.set(rootKey(catalog,scope),{head:after});
}
export async function treePut(tx,catalog,o) {
  const c = context(tx,catalog,o), token = occurrenceToken(o);
  const existing = await tx.get(nodeKey(catalog,o,token));
  if (existing !== undefined) await c.get(token);
  if (existing && c.compare(existing,o) !== 0) fail('MEMBERSHIP_MOVE_REQUIRED','Delete membership before changing order');
  decodeDomain(c.contract.order,o.order); decodeDomain('id',o.sourceId); decodeDomain('string',o.slot);
  const header = await tx.get(rootKey(catalog,o));
  if (header !== undefined && (!header || typeof header.head !== 'string')) fail('CORRUPT_STATE', 'Invalid root header');
  const seen = new Set();
  async function insert(head) {
    if (head === null && existing !== undefined) fail('CORRUPT_STATE', 'Existing membership is unreachable');
    if (head === null) return c.save({sourceId:o.sourceId,slot:o.slot,order:o.order,contributions:o.contributions,left:null,right:null});
    enter(seen,head);
    const n = await c.get(head), comparison = c.compare(o,n);
    if (!comparison) n.contributions = o.contributions;
    else { const side = comparison < 0 ? 'left' : 'right'; n[side] = occurrenceToken(await insert(n[side])); }
    return c.balance(n);
  }
  const root = await insert(header?.head ?? null);
  await setHead(tx,catalog,o,header?.head ?? null,occurrenceToken(root));
}
export async function treeDelete(tx,catalog,o) {
  const c=context(tx,catalog,o), header=await tx.get(rootKey(catalog,o));
  if (header !== undefined && (!header || typeof header.head !== 'string')) fail('CORRUPT_STATE', 'Invalid root header');
  let found=false;
  const seen=new Set();
  async function detachMin(head) {
    enter(seen,head);
    const n=await c.get(head);
    if (n.left===null) return {minimum:n,head:n.right};
    const result=await detachMin(n.left); n.left=result.head;
    return {minimum:result.minimum,head:occurrenceToken(await c.balance(n))};
  }
  async function remove(head) {
    if (head===null) return null;
    enter(seen,head);
    const n=await c.get(head), comparison=c.compare(o,n);
    if (comparison) {
      const side=comparison<0?'left':'right'; n[side]=await remove(n[side]);
      return found ? occurrenceToken(await c.balance(n)) : head;
    }
    found=true; await tx.delete(nodeKey(catalog,o,head));
    if (n.left===null) return n.right;
    if (n.right===null) return n.left;
    const result=await detachMin(n.right), successor=result.minimum;
    successor.left=n.left; successor.right=result.head;
    return occurrenceToken(await c.balance(successor));
  }
  const after=await remove(header?.head ?? null);
  await setHead(tx,catalog,o,header?.head ?? null,after);
  return found;
}
export async function treeGet(tx,catalog,scope,key) {
  const c=context(tx,catalog,scope);
  decodeDomain(c.contract.order,key.order); decodeDomain('id',key.sourceId); decodeDomain('string',key.slot);
  let n=await readRoot(tx,catalog,scope);
  const seen=new Set();
  while(n) { enter(seen,occurrenceToken(n)); const comparison=c.compare(key,n); if(!comparison)return n; n=await c.get(n[comparison<0?'left':'right']); }
}
export async function treeSelect(tx,catalog,scope,rank) {
  if(!Number.isSafeInteger(rank)||rank<0) fail('INVALID_RANK','Rank must be a nonnegative safe integer');
  const c=context(tx,catalog,scope); let n=await readRoot(tx,catalog,scope);
  const seen=new Set();
  while(n) { enter(seen,occurrenceToken(n)); const l=await c.get(n.left), size=l?.size??0; if(rank===size)return n; if(rank<size)n=l;else {rank-=size+1;n=await c.get(n.right);} }
}
export async function treeAggregate(tx,catalog,scope,options={}) {
  const c=context(tx,catalog,scope), range=normalizeRange(c.contract.order,options);
  const {lower,upper}=range, seen=new Set();
  const below=n=>belowRange(c.contract.order,n,range);
  const above=n=>aboveRange(c.contract.order,n,range);
  // Once the split lies within the range, each boundary follows one spine;
  // all subtrees between those spines contribute their stored summaries.
  async function suffix(n) { if(!n)return c.identity(); enter(seen,occurrenceToken(n)); if(below(n))return suffix(await c.get(n.right)); return c.combine(c.combine(await suffix(await c.get(n.left)),n.contributions),(await c.get(n.right))?.aggregates??c.identity()); }
  async function prefix(n) { if(!n)return c.identity(); enter(seen,occurrenceToken(n)); if(above(n))return prefix(await c.get(n.left)); return c.combine(c.combine((await c.get(n.left))?.aggregates??c.identity(),n.contributions),await prefix(await c.get(n.right))); }
  let n=await readRoot(tx,catalog,scope);
  if(lower===undefined&&upper===undefined)return n?.aggregates??c.identity();
  while(n) { enter(seen,occurrenceToken(n)); if(below(n))n=await c.get(n.right);else if(above(n))n=await c.get(n.left);else return c.combine(c.combine(await suffix(await c.get(n.left)),n.contributions),await prefix(await c.get(n.right))); }
  return c.identity();
}
