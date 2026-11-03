import {
  encodeJson, isObject, MAX_PLAN_BYTES, MAX_REQUEST_BYTES, PLAN_FORMAT, rpcError,
} from './client-wire.mjs';

import { validateCredentialMetadata, validateIngressEnvelope } from '../credentials.mjs';
import { emailCommands } from './email-plan.mjs';

const PLAN_KEYS = new Set(['format', 'target', 'request', 'fixture', 'kind']);
const TARGET_KEYS = ['url', 'model', 'store', 'tenant', 'actor', 'credential_epoch'];
const REQUEST_KEYS = ['model', 'context', 'operation_id', 'commands', 'returning'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function validateOperationDraft(draft) {
  if (!isObject(draft) || !['model', 'commands', 'returning'].every(key => Object.hasOwn(draft, key))
    || Object.keys(draft).some(key => !['model', 'commands', 'returning', 'fixture'].includes(key))
    || typeof draft.model !== 'string' || !draft.model || !Array.isArray(draft.commands)
    || draft.commands.length < 1 || draft.commands.length > 64
    || !Array.isArray(draft.returning) || draft.returning.length > 32) {
    throw rpcError('invalid_plan', 'Draft requires model, 1-64 commands, up to 32 returning IDs, and optional fixture metadata');
  }
  for (const command of draft.commands) {
    const keys = command?.op === 'create' ? ['op', 'id', 'contract', 'fields']
      : command?.op === 'update' ? ['op', 'id', 'if_version', 'set', 'unset']
        : command?.op === 'delete' ? ['op', 'id', 'if_version'] : null;
    if (!isObject(command) || keys === null
      || !keys.every(key => Object.hasOwn(command, key))
      || Object.keys(command).some(key => !keys.includes(key)
        && !(['create', 'update'].includes(command.op) && key === 'owner'))) {
      throw rpcError('invalid_plan', 'Invalid mutation command fields');
    }
    if (Object.hasOwn(command, 'owner')) validateUuid(command.owner, `${command.op}.owner`);
  }
  for (const id of draft.returning) validateUuid(id, 'returning ID');
  if (new Set(draft.returning).size !== draft.returning.length) throw rpcError('invalid_plan', 'Duplicate returning ID');
  encodeJson(draft, MAX_REQUEST_BYTES);
}

/** Shared full validator for client plans and the population pre-submit binding. */
export function validateOperationPlan(plan) {
  if (!isObject(plan) || plan.format !== PLAN_FORMAT || Object.keys(plan).some(key => !PLAN_KEYS.has(key))
    || !Object.hasOwn(plan, 'target') || !Object.hasOwn(plan, 'request')) throw rpcError('invalid_plan', 'Unsupported saved plan');
  const target = plan.target;
  const request = plan.request;
  const secretWrite = plan.kind === 'credential-write';
  const emailEnqueue = plan.kind === 'email-enqueue';
  if (Object.hasOwn(plan, 'kind') && !secretWrite && !emailEnqueue) throw rpcError('invalid_plan', 'Unsupported saved plan kind');
  const requestKeys = secretWrite ? ['model', 'context', 'operation_id', 'id', 'if_version', 'metadata', 'sealed_secret'] : REQUEST_KEYS;
  if (secretWrite && Object.hasOwn(request ?? {}, 'owner')) requestKeys.push('owner');
  if (!isObject(target) || !sameKeys(target, TARGET_KEYS) || !isObject(request) || !sameKeys(request, requestKeys)) {
    throw rpcError('invalid_plan', 'Invalid plan target or mutation request');
  }
  const endpoint = normalizeEndpoint(target.url);
  if (endpoint.href !== target.url || target.model !== request.model || typeof target.model !== 'string' || !target.model) {
    throw rpcError('invalid_plan', 'Inconsistent plan target');
  }
  for (const key of ['store', 'tenant', 'actor']) validateUuid(target[key], `target.${key}`);
  if (!Number.isSafeInteger(target.credential_epoch) || target.credential_epoch < 0) throw rpcError('invalid_plan', 'Invalid credential epoch');
  validateUuid(request.operation_id, 'operation_id');
  if (typeof request.context !== 'string' || !request.context) throw rpcError('invalid_plan', 'Original operation context is required');
  if (secretWrite) {
    if (Object.hasOwn(plan, 'fixture')) throw rpcError('invalid_plan', 'Credential plans cannot contain fixture metadata');
    validateUuid(request.id, 'id');
    if (request.if_version !== null) validateUuid(request.if_version, 'if_version');
    if (Object.hasOwn(request, 'owner')) validateUuid(request.owner, 'owner');
    try { validateCredentialMetadata(request.metadata); validateIngressEnvelope(request.sealed_secret); }
    catch { throw rpcError('invalid_plan', 'Invalid encrypted credential request'); }
  } else {
    validateOperationDraft({ model: request.model, commands: request.commands, returning: request.returning });
    if (emailEnqueue) {
      if (Object.hasOwn(plan, 'fixture')) throw rpcError('invalid_plan', 'Email plans cannot contain fixture metadata');
      emailCommands(request.commands, { requireCanonical: true });
    }
  }
  if (Object.hasOwn(plan, 'fixture')) encodeJson(plan.fixture, MAX_PLAN_BYTES);
  const envelope = { jsonrpc: '2.0', id: '00000000-0000-4000-8000-000000000000', method: secretWrite ? 'credentials.write_secret' : emailEnqueue ? 'email.enqueue' : 'records.mutate', params: request };
  if (encodeJson(envelope).byteLength > MAX_REQUEST_BYTES) throw rpcError('invalid_plan', 'Saved mutation exceeds the request byte limit');
  if (encodeJson(plan, MAX_PLAN_BYTES).byteLength > MAX_PLAN_BYTES) throw rpcError('invalid_plan', 'Plan exceeds the file byte limit');
}

function normalizeEndpoint(value) {
  let endpoint;
  try { endpoint = new URL(value); } catch { throw rpcError('invalid_plan', 'Plan target URL is invalid'); }
  if (!['http:', 'https:'].includes(endpoint.protocol) || !endpoint.hostname || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    throw rpcError('invalid_plan', 'Plan target must be an HTTP(S) URL without credentials, query or fragment');
  }
  if (!endpoint.pathname || endpoint.pathname === '/') endpoint.pathname = '/rpc';
  return endpoint;
}

function validateUuid(value, name) {
  if (typeof value !== 'string' || !UUID.test(value)) throw rpcError('invalid_plan', `Canonical UUID required for ${name}`);
}

function sameKeys(object, keys) { return Object.keys(object).length === keys.length && keys.every(key => Object.hasOwn(object, key)); }
