import { sourceOracle } from './oracle.mjs';
import { checkReactive } from './check-reactive.mjs';
import { canonical, decodeDomain, fail } from './values.mjs';
import { catalogKey, sourcePrefix, sourceKey, rootKey, nodeKey, occurrenceToken, allRootsPrefix, allNodesPrefix, allIncomingPrefix, allClaimsPrefix, incomingKey, claimKey } from './keys.mjs';

const ensure = (condition, message) => { if (!condition) fail('INTEGRITY', message); };
const same = (a, b) => canonical(a) === canonical(b);
function inventory(actual, expected, label) {
  ensure(actual.size === expected.size, `${label} inventory size`);
  for (const [key, value] of expected) ensure(actual.has(key) && same(actual.get(key), value), `${label} entry ${key}`);
}

/** Complete active-generation check from source facts; deliberately O(total rows). */
export async function checkStore(store, catalog, tenant) {
  decodeDomain('id', tenant);
  return store.read(async tx => {
    const identity = await tx.get(catalogKey(tenant));
    const sources = await tx.scan({ prefix: sourcePrefix(tenant) });
    ensure(identity === catalog.identity || (identity === undefined && sources.length === 0), 'Catalog identity');
    for (const { key, value } of sources) ensure(value.tenant === tenant && key === sourceKey(tenant, value.id), 'Source storage identity');
    const expected = sourceOracle(catalog, sources.map(row => row.value));
    const load = async prefix => new Map((await tx.scan({ prefix })).map(row => [row.key, row.value]));
    const roots = await load(allRootsPrefix(catalog, tenant));
    const nodes = await load(allNodesPrefix(catalog, tenant));
    const incoming = await load(allIncomingPrefix(catalog, tenant));
    const claims = await load(allClaimsPrefix(catalog, tenant));
    ensure(roots.size === expected.trees.length, 'Root inventory size');
    inventory(incoming, new Map(expected.references.map(ref => [incomingKey(catalog, tenant, ref.targetId, ref), ref])), 'Incoming');
    inventory(claims, new Map(expected.claims.map(claim => [claimKey(catalog, tenant, claim.model, claim.slot, claim.values), claim])), 'Unique');
    const visited = new Set();
    for (const tree of expected.trees) {
      const header = roots.get(rootKey(catalog, tree));
      ensure(header && typeof header.head === 'string' && Object.keys(header).length === 1, 'Root header');
      const contract = catalog.views[tree.view].contract;
      const byToken = new Map(tree.members.map(member => [occurrenceToken(member), member]));
      const ordered = [];
      const empty = () => Object.fromEntries(Object.entries(contract.aggregates).map(([name, agg]) => [name, agg.implementation.identity()]));
      function walk(token) {
        if (token === null) return { height: 0, size: 0, aggregates: empty() };
        ensure(typeof token === 'string', 'Child token');
        const key = nodeKey(catalog, tree, token), node = nodes.get(key), member = byToken.get(token);
        ensure(!visited.has(key), 'Cycle or shared child'); visited.add(key);
        ensure(node && member, 'Missing or extraneous membership');
        const names = ['sourceId', 'slot', 'order', 'contributions', 'left', 'right', 'height', 'size', 'aggregates'];
        ensure(Object.keys(node).length === names.length && names.every(name => Object.hasOwn(node, name)), 'Node shape');
        ensure(node.sourceId === member.sourceId && node.slot === member.slot && same(node.order, member.order) && same(node.contributions, member.contributions), 'Node contribution/source binding');
        const left = walk(node.left); ordered.push(token); const right = walk(node.right);
        const height = 1 + Math.max(left.height, right.height), size = left.size + 1 + right.size;
        ensure(Math.abs(left.height - right.height) <= 1 && node.height === height && node.size === size, 'Balance, height or count');
        const aggregates = Object.create(null);
        for (const [name, aggregate] of Object.entries(contract.aggregates)) {
          const combine = aggregate.implementation.combine;
          aggregates[name] = combine(combine(left.aggregates[name], member.contributions[name]), right.aggregates[name]);
        }
        ensure(same(aggregates, node.aggregates), 'Subtree summary');
        return { height, size, aggregates };
      }
      const full = walk(header.head);
      ensure(same(ordered, tree.members.map(occurrenceToken)), 'Inorder member sequence');
      ensure(full.size === tree.count && same(full.aggregates, tree.aggregates), 'Root summary');
      for (const validator of contract.validators) {
        const scope = { tenant: tree.tenant, view: tree.view, partition: tree.partition };
        const result = validator.implementation.validate(structuredClone(full.aggregates), { scope: structuredClone(scope) });
        if (result && typeof result.then === 'function') Promise.resolve(result).catch(() => {});
        ensure(result === true, 'Business invariant');
      }
    }
    ensure(visited.size === nodes.size, 'Orphan node inventory');
    await checkReactive(tx, catalog, tenant, sources.map(row => row.value));
    return { sources: sources.length, trees: roots.size, occurrences: nodes.size, references: incoming.size, claims: claims.size };
  });
}
