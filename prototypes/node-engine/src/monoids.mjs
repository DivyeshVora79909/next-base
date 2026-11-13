import { decodeDomain, freezeDeep } from './values.mjs';

const integer = value => decodeDomain('integer', value);
/** Constant-field exact summaries. BigInt byte/arithmetic cost is additional. */
export const standardMonoids = freezeDeep({
  sum: {
    version: '1', inputDomain: 'integer',
    identity: () => 0n, lift: integer, combine: (a, b) => a + b,
  },
  prefix: {
    version: '1', inputDomain: 'integer',
    identity: () => ({ sum: 0n, minPrefix: 0n }),
    lift: value => { const sum = integer(value); return { sum, minPrefix: sum < 0n ? sum : 0n }; },
    combine: (a, b) => ({ sum: a.sum + b.sum, minPrefix: a.minPrefix < a.sum + b.minPrefix ? a.minPrefix : a.sum + b.minPrefix }),
  },
  min: {
    version: '1', inputDomain: 'integer',
    identity: () => null, lift: integer,
    combine: (a, b) => a === null ? b : b === null ? a : a < b ? a : b,
  },
  max: {
    version: '1', inputDomain: 'integer',
    identity: () => null, lift: integer,
    combine: (a, b) => a === null ? b : b === null ? a : a > b ? a : b,
  },
});
