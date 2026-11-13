import { compareDomain, decodeDomain, fail } from './values.mjs';

// Accept only ordinary data objects, including frozen and null-prototype input.
function fields(value, allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('INVALID_RANGE', 'Expected range object');
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!allowed.includes(key) || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail('INVALID_RANGE', 'Invalid range field');
  }
}

/** Detach and decode cuts. Scalar cuts bound a whole order-value tie group. */
export function normalizeRange(domain, options = {}) {
  fields(options, ['lower', 'upper']);
  const range = {};
  for (const side of ['lower', 'upper']) {
    if (options[side] === undefined) continue;
    const bound = options[side];
    fields(bound, ['value', 'inclusive', 'sourceId', 'slot']);
    if (!Object.hasOwn(bound, 'value') || (bound.inclusive !== undefined && typeof bound.inclusive !== 'boolean')) fail('INVALID_RANGE', 'Invalid range bound');
    const complete = Object.hasOwn(bound, 'sourceId');
    if (complete !== Object.hasOwn(bound, 'slot')) fail('INVALID_RANGE', 'Complete cuts require sourceId and slot');
    const result = { value: decodeDomain(domain, bound.value), inclusive: bound.inclusive !== false };
    if (complete) {
      result.sourceId = decodeDomain('id', bound.sourceId);
      result.slot = decodeDomain('string', bound.slot);
    }
    range[side] = result;
  }
  return range;
}

export function compareKey(domain, a, b) {
  return compareDomain(domain, a.order, b.order) || compareDomain('id', a.sourceId, b.sourceId) || compareDomain('string', a.slot, b.slot);
}

function compareBound(domain, key, bound) {
  return Object.hasOwn(bound, 'sourceId')
    ? compareKey(domain, key, { order: bound.value, sourceId: bound.sourceId, slot: bound.slot })
    : compareDomain(domain, key.order, bound.value);
}

export function belowRange(domain, key, range) {
  if (range.lower === undefined) return false;
  const comparison = compareBound(domain, key, range.lower);
  return comparison < 0 || (comparison === 0 && range.lower.inclusive === false);
}

export function aboveRange(domain, key, range) {
  if (range.upper === undefined) return false;
  const comparison = compareBound(domain, key, range.upper);
  return comparison > 0 || (comparison === 0 && range.upper.inclusive === false);
}

export function containsRange(domain, key, range) {
  return !belowRange(domain, key, range) && !aboveRange(domain, key, range);
}
