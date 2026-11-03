import { rpcError } from './client-wire.mjs';

/** Shared ASCII mailbox syntax; message intent preserves local-part case. */
export function normalizeEmailAddress(input) {
  const invalid = () => rpcError('invalid_plan', 'Invalid typed email enqueue intent');
  if (typeof input !== 'string' || /[^\x20-\x7e]/u.test(input)) throw invalid();
  const value = input.replace(/^ +| +$/gu, '');
  if (!value || value.length > 254) throw invalid();
  const parts = value.split('@');
  const [local, domain] = parts;
  if (parts.length !== 2 || !local || local.length > 64 || local.startsWith('.') || local.endsWith('.')
    || local.includes('..') || !/^[A-Za-z0-9.!#$%&'*+\-/=?^_`{|}~]+$/u.test(local)
    || !domain || domain.length > 253 || domain.split('.').some(label => !label || label.length > 63
      || !/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u.test(label))) throw invalid();
  return `${local}@${domain.toLowerCase()}`;
}
