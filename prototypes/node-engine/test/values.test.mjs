import test from 'node:test';
import assert from 'node:assert/strict';
import { canonical, fingerprint, compareDomain, decodeDomain, assertJson, cloneData, freezeDeep } from '../src/values.mjs';

test('canonical tags distinguish numeric domains and marker-looking data', () => {
  const values = [1n, '1', 1, ['integer', '1'], { integer: '1' }, { type: 'integer', value: '1' }];
  assert.equal(new Set(values.map(canonical)).size, values.length);
  assert.equal(new Set(values.map(fingerprint)).size, values.length);
  assert.equal(canonical({ z: [1n, { b: true, a: null }], a: 'x' }), canonical({ a: 'x', z: [1n, { a: null, b: true }] }));
});

test('text comparison uses deterministic UTF-8 order including astral characters', () => {
  const ordered = ['', 'a', 'z', 'é', '\ue000', '😀', '𠮷'];
  for (let i = 0; i < ordered.length; i++) for (let j = 0; j < ordered.length; j++) {
    assert.equal(compareDomain('string', ordered[i], ordered[j]), Math.sign(i - j));
  }
  assert.equal(compareDomain('integer', '9007199254740993', '9007199254740992'), 1);
  assert.equal(compareDomain('boolean', false, true), -1);
});

test('wire domains reject malformed Unicode and noncanonical exact integers', () => {
  for (const value of ['\ud800', '\udfff', 'a\ud800b']) {
    assert.throws(() => canonical(value));
    assert.throws(() => canonical({ [value]: true }));
    assert.throws(() => decodeDomain('id', value));
    assert.throws(() => compareDomain('string', value, 'x'));
  }
  for (const value of ['-0', '00', '01', '-01', '+1', ' 1', '1.0', '', 1, -0, null]) assert.throws(() => decodeDomain('integer', value));
  assert.equal(decodeDomain('integer', '-9007199254740993'), -9007199254740993n);
  assert.equal(decodeDomain('integer', 0n), 0n);
  assert.throws(() => decodeDomain('id', ''));
});

test('canonical data rejects unsafe Numbers, nondata, sparse and extended arrays', () => {
  const cycle = {}; cycle.self = cycle;
  for (const value of [NaN, Infinity, 1.5, Number.MAX_SAFE_INTEGER + 1, -0, undefined, Symbol('x'), () => {}, new Date(), new Map(), cycle, new Array(2), Object.assign([1], { extra: 2 }), { [Symbol('x')]: 1 }, Object.defineProperty({}, 'x', { value: 1 })]) {
    assert.throws(() => canonical(value));
  }
  assert.throws(() => assertJson({ x: 1n }));
  assert.doesNotThrow(() => assertJson({ x: Number.MAX_SAFE_INTEGER, n: null }));
});

test('object and array accessors reject without executing user code', () => {
  for (const object of [{}, [0]]) {
    let calls = 0;
    Object.defineProperty(object, Array.isArray(object) ? '0' : 'x', { enumerable: true, get() { calls++; return 1; } });
    assert.throws(() => canonical(object));
    assert.equal(calls, 0);
  }
});

test('canonical arrays do not consult a mutated inherited iterator', () => {
  const original = Array.prototype[Symbol.iterator];
  let encoded;
  try {
    Array.prototype[Symbol.iterator] = function* () { yield 'forged'; };
    encoded = canonical([1, 2]);
  } finally { Array.prototype[Symbol.iterator] = original; }
  assert.equal(encoded, '["array",[["number",1],["number",2]]]');
});

test('clones isolate nested data and deep freezing protects every nesting level', () => {
  const source = { rows: [{ amount: 9007199254740993n, nested: ['original'] }] };
  const copy = cloneData(source);
  copy.rows[0].nested[0] = 'changed';
  assert.equal(source.rows[0].nested[0], 'original');
  assert.equal(copy.rows[0].amount, 9007199254740993n);
  assert.equal(freezeDeep(copy), copy);
  for (const value of [copy, copy.rows, copy.rows[0], copy.rows[0].nested]) assert.ok(Object.isFrozen(value));
  assert.throws(() => { copy.rows[0].amount = 0n; }, TypeError);
});
