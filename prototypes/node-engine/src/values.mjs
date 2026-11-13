import { createHash } from 'node:crypto';

export function fail(code, message) {
  throw Object.assign(new Error(message), { code });
}

function text(value) {
  if (typeof value !== 'string' || !value.isWellFormed()) fail('INVALID_VALUE', 'Expected well-formed Unicode');
  return value;
}

/** Explicit numeric wire domain. No implicit Number conversion or locale rules. */
export function decodeDomain(domain, value) {
  switch (domain) {
    case 'integer':
      if (typeof value === 'bigint') return value;
      if (typeof value !== 'string' || !/^(0|-?[1-9][0-9]*)$/.test(value)) fail('INVALID_VALUE', 'Expected canonical integer string');
      return BigInt(value);
    case 'id':
      if (!text(value).length) fail('INVALID_VALUE', 'Expected nonempty identifier');
      return value;
    case 'string': return text(value);
    case 'boolean':
      if (typeof value !== 'boolean') fail('INVALID_VALUE', 'Expected boolean');
      return value;
    default: fail('INVALID_DOMAIN', `Unsupported domain ${domain}`);
  }
}

export function compareDomain(domain, left, right) {
  const a = decodeDomain(domain, left), b = decodeDomain(domain, right);
  if (domain === 'id' || domain === 'string') return Math.sign(Buffer.compare(Buffer.from(a), Buffer.from(b)));
  return a < b ? -1 : a > b ? 1 : 0;
}

// Canonical tagged encoding: data objects cannot collide with integer/type markers.
function encode(value, seen, jsonOnly) {
  if (value === null) return ['null'];
  if (typeof value === 'string') return ['string', text(value)];
  if (typeof value === 'boolean') return ['boolean', value];
  if (typeof value === 'bigint') {
    if (jsonOnly) fail('INVALID_JSON', 'BigInt requires a canonical string at the JSON boundary');
    return ['integer', value.toString()];
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) fail('INVALID_JSON', 'Numbers must be safe integers; exact quantities use strings');
    return ['number', value];
  }
  if (!value || typeof value !== 'object') fail('INVALID_VALUE', 'Expected plain data');
  if (seen.has(value)) fail('INVALID_VALUE', 'Cyclic data is unsupported');
  const prototype = Object.getPrototypeOf(value);
  if (!Array.isArray(value) && prototype !== Object.prototype && prototype !== null) fail('INVALID_VALUE', 'Expected plain object');
  seen.add(value);
  let result;
  if (Array.isArray(value)) {
    if (Reflect.ownKeys(value).length !== value.length + 1) fail('INVALID_VALUE', 'Sparse or extended arrays are unsupported');
    const items = [];
    for (let index = 0; index < value.length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) fail('INVALID_VALUE', 'Array entries must be own enumerable data');
      items.push(encode(descriptor.value, seen, jsonOnly));
    }
    result = ['array', items];
  } else {
    const keys = Reflect.ownKeys(value);
    if (keys.some(key => typeof key !== 'string')) fail('INVALID_VALUE', 'Symbol keys are unsupported');
    keys.sort((a, b) => compareDomain('string', a, b));
    result = ['object', keys.map(key => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail('INVALID_VALUE', 'Accessors and hidden properties are unsupported');
      return [text(key), encode(descriptor.value, seen, jsonOnly)];
    })];
  }
  seen.delete(value);
  return result;
}

export function assertJson(value) { encode(value, new Set(), true); }
export function canonical(value) { return JSON.stringify(encode(value, new Set(), false)); }
export function fingerprint(value) { return createHash('sha256').update(canonical(value)).digest('hex'); }
export function cloneData(value) { return structuredClone(value); }
export function freezeDeep(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freezeDeep(child);
    Object.freeze(value);
  }
  return value;
}

export function selectValue(record, selector) {
  if (Object.hasOwn(selector, 'constant')) return { present: true, value: selector.constant };
  const field = Object.hasOwn(selector, 'field');
  const object = field ? record.data : record;
  const key = field ? selector.field : selector.header;
  return { present: Object.hasOwn(object, key), value: object[key] };
}
