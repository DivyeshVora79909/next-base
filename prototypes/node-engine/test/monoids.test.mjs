import test from 'node:test';
import assert from 'node:assert/strict';
import { standardMonoids } from '../src/monoids.mjs';

// Oracle scans source numbers directly; it does not use lift/combine or cached summaries.
function expected(name, values) {
  if (name === 'min') return values.length ? values.reduce((a, b) => a < b ? a : b) : null;
  if (name === 'max') return values.length ? values.reduce((a, b) => a > b ? a : b) : null;
  let sum = 0n, minPrefix = 0n;
  for (const value of values) { sum += value; if (sum < minPrefix) minPrefix = sum; }
  return name === 'sum' ? sum : { sum, minPrefix };
}
function fold(monoid, values) {
  return values.reduce((summary, value) => monoid.combine(summary, monoid.lift(value.toString())), monoid.identity());
}
let seed = 0x12345678;
function random() { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed; }
const samples = [[], [0n], [-1n], [5n, -9n, 7n], [2n ** 100n, -(2n ** 100n) - 1n, 3n]];
for (let i = 0; i < 24; i++) samples.push(Array.from({ length: random() % 15 }, () => (BigInt(random()) - 2147483648n) * 9007199254740993n));

for (const [name, monoid] of Object.entries(standardMonoids)) {
  test(`${name} matches independent flat arithmetic under every ordered three-way regrouping`, () => {
    for (const values of samples) {
      const want = expected(name, values);
      assert.deepEqual(fold(monoid, values), want);
      for (let i = 0; i <= values.length; i++) for (let j = i; j <= values.length; j++) {
        const a = fold(monoid, values.slice(0, i));
        const b = fold(monoid, values.slice(i, j));
        const c = fold(monoid, values.slice(j));
        const before = structuredClone([a, b, c]);
        if (a && typeof a === 'object') Object.freeze(a);
        if (b && typeof b === 'object') Object.freeze(b);
        if (c && typeof c === 'object') Object.freeze(c);
        assert.deepEqual(monoid.combine(monoid.combine(a, b), c), want);
        assert.deepEqual(monoid.combine(a, monoid.combine(b, c)), want);
        assert.deepEqual([a, b, c], before);
      }
      assert.deepEqual(monoid.combine(monoid.identity(), want), want);
      assert.deepEqual(monoid.combine(want, monoid.identity()), want);
    }
  });
}

test('prefix is ordered and noncommutative, including the empty prefix', () => {
  const m = standardMonoids.prefix, a = m.lift('5'), b = m.lift('-7');
  assert.deepEqual(m.combine(a, b), { sum: -2n, minPrefix: -2n });
  assert.deepEqual(m.combine(b, a), { sum: -2n, minPrefix: -7n });
  assert.deepEqual(fold(m, [2n, 3n]), { sum: 5n, minPrefix: 0n });
  assert.deepEqual([a, b], [{ sum: 5n, minPrefix: 0n }, { sum: -7n, minPrefix: -7n }]);
});
