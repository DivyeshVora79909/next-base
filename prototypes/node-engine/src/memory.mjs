import { AsyncLocalStorage } from 'node:async_hooks';
import { isDeepStrictEqual } from 'node:util';

const context = new AsyncLocalStorage();
const fail = (code, message) => Object.assign(new Error(message), { code });
// Clone first so accessors cannot substitute shared memory after validation.
// Walk cloned containers (including cycles); shared backing is never engine data.
function copy(value) {
  const detached = structuredClone(value);
  const seen = new WeakSet();
  function check(item) {
    if (item === null || typeof item !== 'object' || seen.has(item)) return;
    seen.add(item);
    if (item instanceof SharedArrayBuffer
      || (ArrayBuffer.isView(item) && item.buffer instanceof SharedArrayBuffer)) {
      throw fail('INVALID_VALUE', 'Shared memory is not supported in engine values');
    }
    if (ArrayBuffer.isView(item) || item instanceof ArrayBuffer) return;
    if (item instanceof Map) for (const [key, entry] of item) { check(key); check(entry); }
    if (item instanceof Set) for (const entry of item) check(entry);
    for (const name of Object.getOwnPropertyNames(item)) check(item[name]);
  }
  check(detached);
  return detached;
}
function keyCheck(key) {
  if (typeof key !== 'string' || key.length === 0 || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(key)) {
    throw fail('INVALID_KEY', 'Keys must be nonempty well-formed Unicode strings');
  }
  return key;
}
const compare = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));

/** Volatile serialized test adapter. Scans enumerate and sort, without an index. */
export function createMemoryStore() {
  const base = new Map();
  let queue = Promise.resolve();
  const identity = Symbol('memory store');
  const capabilities = Object.freeze({
    serialized: true, volatile: true, durable: false,
    scans: 'nonindexed: O(N + T + M log M) work, O(N + T) scratch keys',
    guards: 'retained point, absence and range evidence; serialization supplies isolation',
  });

  function run(callback, options, readonly) {
    if (context.getStore()?.has(identity)) {
      return Promise.reject(fail('NESTED_TRANSACTION', 'Same-store nested transactions are unsupported'));
    }
    if (typeof callback !== 'function') return Promise.reject(fail('INVALID_CALLBACK', 'Expected a callback'));
    const parents = context.getStore() ?? new Set();
    const task = queue.then(() => context.run(new Set([...parents, identity]), async () => {
      const overlay = new Map();
      const points = new Map();
      const ranges = [];
      const metrics = { gets: 0, getMany: 0, scans: 0, scannedKeys: 0, stagedWrites: 0 };
      let open = true;
      const assertOpen = () => { if (!open) throw fail('TRANSACTION_CLOSED', 'Transaction is closed'); };
      const guard = key => {
        if (!points.has(key)) points.set(key, { type: 'point', key, exists: base.has(key) });
      };
      const current = key => overlay.has(key) ? overlay.get(key) : { exists: base.has(key), value: base.get(key) };
      const readKey = key => {
        keyCheck(key); guard(key);
        const entry = current(key);
        return entry.exists ? copy(entry.value) : undefined;
      };
      const tx = Object.freeze({
        async get(key) { assertOpen(); metrics.gets++; return readKey(key); },
        async getMany(keys) {
          assertOpen();
          if (!Array.isArray(keys)) throw fail('INVALID_KEYS', 'Expected an array of keys');
          keys.forEach(keyCheck);
          metrics.getMany++;
          return keys.map(readKey);
        },
        async set(key, value) {
          assertOpen();
          if (readonly) throw fail('READ_ONLY', 'Cannot write in a read transaction');
          keyCheck(key);
          if (value === undefined) throw fail('INVALID_VALUE', 'Undefined denotes a missing key');
          const detached = copy(value);
          guard(key); overlay.set(key, { exists: true, value: detached }); metrics.stagedWrites++;
        },
        async delete(key) {
          assertOpen();
          if (readonly) throw fail('READ_ONLY', 'Cannot write in a read transaction');
          keyCheck(key); guard(key); overlay.set(key, { exists: false }); metrics.stagedWrites++;
        },
        async scan(options = {}) {
          assertOpen();
          if (!options || typeof options !== 'object' || Array.isArray(options)) throw fail('INVALID_RANGE', 'Expected range options');
          if (Object.keys(options).some(key => !['prefix', 'gte', 'gt', 'lte', 'lt', 'limit'].includes(key))) throw fail('INVALID_RANGE', 'Unknown range option');
          const range = {};
          for (const name of ['prefix', 'gte', 'gt', 'lte', 'lt']) {
            if (options[name] !== undefined) {
              range[name] = name === 'prefix' && options[name] === '' ? '' : keyCheck(options[name]);
            }
          }
          const limit = options.limit ?? Infinity;
          if (limit !== Infinity && (!Number.isSafeInteger(limit) || limit < 0)) throw fail('INVALID_RANGE', 'Invalid scan limit');
          range.limit = limit;
          ranges.push({ type: 'range', ...range }); metrics.scans++;
          const keys = new Set(base.keys());
          for (const key of overlay.keys()) keys.add(key);
          metrics.scannedKeys += keys.size;
          const matches = [...keys].filter(key => current(key).exists
            && (range.prefix === undefined || key.startsWith(range.prefix))
            && (range.gte === undefined || compare(key, range.gte) >= 0)
            && (range.gt === undefined || compare(key, range.gt) > 0)
            && (range.lte === undefined || compare(key, range.lte) <= 0)
            && (range.lt === undefined || compare(key, range.lt) < 0));
          matches.sort(compare);
          return matches.slice(0, limit).map(key => ({ key, value: copy(current(key).value) }));
        },
        inspect() {
          assertOpen();
          return copy({ metrics: { ...metrics, touchedEntries: overlay.size }, guards: [...points.values(), ...ranges] });
        },
      });
      try {
        const result = await callback(tx);
        open = false;
        const changes = [];
        for (const [key, entry] of overlay) {
          if (entry.exists) {
            if (!base.has(key) || !isDeepStrictEqual(base.get(key), entry.value)) changes.push({ type: 'set', key, value: entry.value });
          } else if (base.has(key)) changes.push({ type: 'delete', key });
        }
        if (options?.beforeCommit !== undefined) await options.beforeCommit({ changes: copy(changes) });
        // No awaits or user callbacks between publication writes.
        for (const change of changes) {
          if (change.type === 'set') base.set(change.key, change.value);
          else base.delete(change.key);
        }
        return result;
      } finally { open = false; }
    }));
    queue = task.catch(() => {});
    return task;
  }
  return Object.freeze({ capabilities, transact: (callback, options = {}) => run(callback, options, false), read: callback => run(callback, {}, true) });
}
