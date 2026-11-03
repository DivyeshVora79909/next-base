import { isObject, rpcError } from './client-wire.mjs';
import { validateCredentialMetadata } from '../credentials.mjs';
import { normalizeEmailAddress } from './email-address.mjs';
import { normalizeIdentityFields } from './identity-fields.mjs';

export { normalizeEmailAddress } from './email-address.mjs';

export const EMAIL_CONTRACT = 1002;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const metadataFields = new Set(['label', 'provider', 'account', 'enabled', 'scopes', 'kind', 'value']);
const invalid = () => rpcError('invalid_plan', 'Invalid typed email enqueue intent');
const keys = (value, expected) => isObject(value) && Object.keys(value).length === expected.length
  && expected.every(key => Object.hasOwn(value, key));

/** E1's syntactic normalization; prepared catalog validation and native checks follow. */
export function normalizeEmailFields(fields, { requireCanonical = false } = {}) {
  if (!keys(fields, ['email', 'selection', 'execute_at', 'not_after'])
    || !keys(fields.email, ['sender', 'to', 'subject', 'text'])) throw invalid();
  const { email, selection } = fields;
  if (!Array.isArray(email.to) || email.to.length < 1 || email.to.length > 16
    || typeof email.subject !== 'string' || Buffer.byteLength(email.subject) > 512 || /[\x00-\x1f\x7f]/u.test(email.subject)
    || typeof email.text !== 'string' || Buffer.byteLength(email.text) > 16_384) throw invalid();
  const normalized = { sender: normalizeEmailAddress(email.sender), to: email.to.map(normalizeEmailAddress), subject: email.subject, text: email.text };
  if (new Set(normalized.to).size !== normalized.to.length
    || (requireCanonical && (normalized.sender !== email.sender || normalized.to.some((value, index) => value !== email.to[index])))) throw invalid();
  if (!(keys(selection, ['kind', 'credential']) && selection.kind === 'byoc' && UUID.test(selection.credential)
    || keys(selection, ['kind', 'slot']) && selection.kind === 'platform' && selection.slot === 'transactional_email')) throw invalid();
  for (const value of [fields.execute_at, fields.not_after]) {
    if (value !== null && !(typeof value === 'string' && /^(0|[1-9][0-9]*)$/u.test(value) && BigInt(value) <= 9223372036854775807n)) throw invalid();
  }
  return { email: normalized, selection: { ...selection }, execute_at: fields.execute_at, not_after: fields.not_after };
}

export function emailCommands(commands, options) {
  let count = 0;
  const ids = new Set();
  const normalized = commands.map(command => {
    if (!UUID.test(command.id ?? '') || ids.has(command.id)) throw invalid();
    ids.add(command.id);
    if (command.op !== 'create' && !UUID.test(command.if_version ?? '')) throw invalid();
    if (command.op === 'create') {
      if (command.contract === EMAIL_CONTRACT) {
        count += 1;
        return { ...command, fields: normalizeEmailFields(command.fields, options) };
      }
      if (command.contract === 1003) {
        try { return { ...command, fields: normalizeIdentityFields(command.fields, options) }; }
        catch { throw invalid(); }
      }
      if (command.contract !== 1001) throw invalid();
      try { validateCredentialMetadata(command.fields); } catch { throw invalid(); }
    } else if (command.op === 'update') {
      if (!isObject(command.set) || Object.keys(command.set).some(key => !metadataFields.has(key))
        || !Array.isArray(command.unset) || command.unset.some(key => !metadataFields.has(key))) throw invalid();
    }
    return command;
  });
  if (count < 1 || count > 16) throw invalid();
  return normalized;
}

/** Validate transient evidence without returning it in a diagnostic or saved plan. */
export function emailAuthorizations(commands, authorizations) {
  const expected = new Set(commands.filter(command => command.op === 'create' && command.contract === EMAIL_CONTRACT).map(command => command.id));
  if (!Array.isArray(authorizations) || authorizations.length !== expected.size) throw rpcError('invalid_authorizations', 'One transient grant per email source is required');
  for (const item of authorizations) {
    if (!keys(item, ['source', 'grant']) || !expected.delete(item.source) || typeof item.grant !== 'string'
      || item.grant.length < 1 || item.grant.length > 4096 || !/^[A-Za-z0-9_-]+$/u.test(item.grant)) {
      throw rpcError('invalid_authorizations', 'Invalid transient email authorization');
    }
  }
  return authorizations.map(({ source, grant }) => ({ source, grant }));
}
