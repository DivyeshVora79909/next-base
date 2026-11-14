import { canonical, decodeDomain, fail } from './values.mjs';
import { rootKey, nodeKey, occurrenceToken } from './keys.mjs';
import { normalizeRange, compareKey, belowRange, aboveRange } from './range.mjs';

const invalid = () => fail('INVALID_READ', 'Invalid read window options');
const corrupt = () => fail('CORRUPT_STATE', 'Invalid read window tree');
function fields(value, allowed) {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!allowed.includes(key) || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) invalid();
  }
}
const natural = value => Number.isSafeInteger(value) && value >= 0;
const bytes = value => Buffer.byteLength(canonical(value));

/** Privileged raw occurrences. Use one read-only transaction for all composed windows.
 * Bytes are logical encoding charges checked after the adapter's eager batch clone;
 * they do not bound heap allocation or network transfer. Hard limits return no page.
 */
export function treeReadWindow(tx, catalog, scope, options) {
  fields(options, ['ranks', 'range', 'limits']);
  fields(options.limits, ['maxNodes', 'maxBatches', 'maxBytes', 'maxOutput', 'batchKeys']);
  const limits = { ...options.limits };
  for (const name of ['maxNodes', 'maxBatches', 'maxBytes', 'maxOutput', 'batchKeys']) {
    if (!natural(limits[name])) invalid();
  }
  if (limits.batchKeys === 0 || !tx || typeof tx.getMany !== 'function') invalid();
  let start = 0, end;
  if (Object.hasOwn(options, 'ranks')) {
    fields(options.ranks, ['start', 'end']);
    ({ start, end } = options.ranks);
    if (!natural(start) || !natural(end) || start > end) invalid();
  }
  const headerKey = rootKey(catalog, scope); // Validate the full typed scope before I/O.
  const domain = catalog.views[scope.view].contract.order;
  if (Object.hasOwn(options, 'range') && options.range === undefined) fail('INVALID_RANGE', 'Expected range object');
  const range = Object.hasOwn(options, 'range') ? normalizeRange(domain, options.range) : {};
  const fixedScope = structuredClone(scope);
  return read();

  async function read() {
    const metrics = { nodes: 0, batches: 0, readBytes: 0, outputBytes: 0, waves: 0, maxFrontier: 0, outputs: 0 };
    const cache = new Map(), owners = new Map(), selected = new Map();
    const compare = (a, b) => compareKey(domain, a, b);
    const limited = () => fail('WORK_LIMIT', 'Read window budget exceeded');
    const charge = () => {
      if (metrics.readBytes + metrics.outputBytes > limits.maxBytes) limited();
    };
    async function fetch(keys, nodes) {
      const result = [];
      for (let offset = 0; offset < keys.length; offset += limits.batchKeys) {
        const chunk = keys.slice(offset, offset + limits.batchKeys);
        if (metrics.batches >= limits.maxBatches || (nodes && metrics.nodes + chunk.length > limits.maxNodes)) limited();
        metrics.batches++;
        if (nodes) metrics.nodes += chunk.length;
        const values = await tx.getMany(chunk);
        if (!Array.isArray(values) || values.length !== chunk.length) corrupt();
        for (let index = 0; index < chunk.length; index++) {
          metrics.readBytes += Buffer.byteLength(chunk[index]);
          if (values[index] !== undefined) {
            try { metrics.readBytes += bytes(values[index]); } catch { corrupt(); }
          }
          charge();
          result.push(values[index]);
        }
      }
      return result;
    }
    function validate(node, token) {
      try {
        if (!node || occurrenceToken(node) !== token || !Number.isSafeInteger(node.height) || node.height < 1
          || !Number.isSafeInteger(node.size) || node.size < 1
          || ![node.left, node.right].every(link => link === null || typeof link === 'string')
          || node.left === token || node.right === token
          || (node.left !== null && node.left === node.right)) corrupt();
        decodeDomain(domain, node.order); decodeDomain('id', node.sourceId); decodeDomain('string', node.slot);
      } catch { corrupt(); }
    }
    async function load(tokens) {
      const missing = [...new Set(tokens.filter(token => token !== null && !cache.has(token)))];
      const values = await fetch(missing.map(token => nodeKey(catalog, fixedScope, token)), true);
      missing.forEach((token, index) => { validate(values[index], token); cache.set(token, values[index]); });
    }
    const [header] = await fetch([headerKey], false);
    if (header === undefined) return { total: 0, occurrences: [], metrics };
    if (!header || typeof header.head !== 'string') corrupt();
    await load([header.head]);
    const total = cache.get(header.head).size;
    const stop = Math.min(end ?? total, total);
    if (start >= stop) return { total, occurrences: [], metrics };
    owners.set(header.head, null);
    let frontier = [{ token: header.head, offset: 0 }];
    let minimum = Infinity, maximum = -1;
    while (frontier.length) {
      metrics.waves++;
      metrics.maxFrontier = Math.max(metrics.maxFrontier, frontier.length);
      const tokens = [];
      for (const item of frontier) {
        const n = cache.get(item.token);
        for (const token of [n.left, n.right]) {
          if (token === null) continue;
          if (owners.has(token)) corrupt();
          owners.set(token, item.token); tokens.push(token);
        }
      }
      await load(tokens);
      const next = [];
      for (const item of frontier) {
        const n = cache.get(item.token), l = cache.get(n.left), r = cache.get(n.right);
        if (n.size !== 1 + (l?.size ?? 0) + (r?.size ?? 0)
          || n.height !== 1 + Math.max(l?.height ?? 0, r?.height ?? 0)
          || Math.abs((l?.height ?? 0) - (r?.height ?? 0)) > 1) corrupt();
        const bounded = (node, lower, upper) => {
          if (node && ((lower && compare(node, lower) <= 0) || (upper && compare(node, upper) >= 0))) corrupt();
        };
        bounded(n, item.lower, item.upper);
        bounded(l, item.lower, n); bounded(r, n, item.upper);
        const rank = item.offset + (l?.size ?? 0);
        if (!natural(rank) || rank >= total) corrupt();
        if (rank >= start && rank < stop && !belowRange(domain, n, range) && !aboveRange(domain, n, range)) {
          if (selected.size >= limits.maxOutput) limited();
          const occurrence = { rank, sourceId: n.sourceId, slot: n.slot, order: n.order };
          metrics.outputBytes += bytes(occurrence); charge();
          selected.set(rank, occurrence); minimum = Math.min(minimum, rank); maximum = Math.max(maximum, rank);
        }
        if (l && item.offset < stop && rank > start && !belowRange(domain, n, range)) {
          next.push({ token: n.left, offset: item.offset, lower: item.lower, upper: n });
        }
        if (r && rank + 1 < stop && item.offset + n.size > start && !aboveRange(domain, n, range)) {
          next.push({ token: n.right, offset: rank + 1, lower: n, upper: item.upper });
        }
      }
      frontier = next;
    }
    const occurrences = [];
    for (let rank = minimum; rank <= maximum; rank++) {
      if (!selected.has(rank)) corrupt();
      occurrences.push(selected.get(rank));
    }
    metrics.outputs = occurrences.length;
    return { total, occurrences, metrics };
  }
}
