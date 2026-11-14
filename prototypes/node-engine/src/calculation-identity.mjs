import { decodeDomain, fingerprint } from './values.mjs';

export const GENERATED_PREFIX = '@next/derived/';
export function generatedId(tenant, anchorId, calculation, role) {
  for (const part of [tenant, anchorId, calculation, role]) decodeDomain('id', part);
  return GENERATED_PREFIX + fingerprint([tenant, anchorId, calculation, role]);
}
export function producerId(tenant, anchorId, calculation) {
  for (const part of [tenant, anchorId, calculation]) decodeDomain('id', part);
  return '@next/producer/' + fingerprint([tenant, anchorId, calculation]);
}
