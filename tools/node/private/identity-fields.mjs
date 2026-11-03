import { isObject, rpcError } from './client-wire.mjs';
import { normalizeEmailAddress } from './email-address.mjs';

const invalid = () => rpcError('invalid_identity', 'Identity input is not valid');

/** Canonical authored identity input; verification and lifetime fields are native-only. */
export function normalizeIdentityFields(fields, { requireCanonical = false } = {}) {
  if (!isObject(fields) || Object.keys(fields).length !== 2
    || !Object.hasOwn(fields, 'kind') || !Object.hasOwn(fields, 'value')
    || typeof fields.value !== 'string') throw invalid();
  let value;
  if (fields.kind === 'email') {
    try { value = normalizeEmailAddress(fields.value).toLowerCase(); }
    catch { throw invalid(); }
  } else if (fields.kind === 'phone') {
    value = fields.value.replace(/^ +| +$/gu, '');
    if (!/^\+[1-9][0-9]{7,14}$/u.test(value)) throw invalid();
  } else throw invalid();
  if (requireCanonical && value !== fields.value) throw invalid();
  return { kind: fields.kind, value };
}
