import { canonical, decodeDomain, fail } from './values.mjs';

export const catalogKey = tenant => `catalog/${canonical(tenant)}`;
export const sourcePrefix = tenant => `source/${canonical(tenant)}/`;
export const sourceKey = (tenant, id) => `${sourcePrefix(tenant)}${canonical(id)}`;
const space = (kind, catalog, tenant) => `${kind}/${canonical(tenant)}/${catalog.identity}/`;
export const allRootsPrefix = (catalog, tenant) => space('root', catalog, tenant);
export const allNodesPrefix = (catalog, tenant) => space('node', catalog, tenant);
export const allIncomingPrefix = (catalog, tenant) => space('incoming', catalog, tenant);
export const allClaimsPrefix = (catalog, tenant) => space('claim', catalog, tenant);
function scopeParts(catalog, scope) {
  const view = scope && Object.hasOwn(catalog.views, scope.view) && catalog.views[scope.view];
  if (!view || !Array.isArray(scope.partition) || scope.partition.length !== view.contract.partition.length) fail('INVALID_SCOPE', 'Unknown view or incompatible partition');
  decodeDomain('id', scope.tenant);
  return [scope.view, scope.partition.map((value, index) => decodeDomain(view.contract.partition[index], value))];
}
export const rootKey = (catalog, scope) => `${allRootsPrefix(catalog, scope.tenant)}${canonical(scopeParts(catalog, scope))}`;
export const occurrenceToken = occurrence => canonical([occurrence.sourceId, occurrence.slot]);
export const nodeKey = (catalog, scope, token) => `${allNodesPrefix(catalog, scope.tenant)}${canonical(scopeParts(catalog, scope))}/${token}`;
export const incomingPrefix = (catalog, tenant, targetId) => `${allIncomingPrefix(catalog, tenant)}${canonical(targetId)}/`;
export const incomingKey = (catalog, tenant, targetId, occurrence) => `${incomingPrefix(catalog, tenant, targetId)}${canonical([occurrence.sourceId, occurrence.slot, occurrence.position])}`;
export const claimKey = (catalog, tenant, model, slot, values) => `${allClaimsPrefix(catalog, tenant)}${canonical([model, slot, values])}`;

export const reactivePrefix = (catalog, tenant) => `reactive/v1/${canonical(tenant)}/${catalog.identity}/`;
export const producerPrefix = (catalog, tenant) => `${reactivePrefix(catalog, tenant)}producer/`;
export const producerKey = (catalog, tenant, id) => `${producerPrefix(catalog, tenant)}${canonical(id)}`;
export const reservationPrefix = (catalog, tenant) => `${reactivePrefix(catalog, tenant)}reservation/`;
export const reservationKey = (catalog, tenant, id) => `${reservationPrefix(catalog, tenant)}${canonical(id)}`;
export const potentialOwnerPrefix = (catalog, tenant) => `${reactivePrefix(catalog, tenant)}owner/`;
export const potentialOwnerKey = (catalog, tenant, id) => `${potentialOwnerPrefix(catalog, tenant)}${canonical(id)}`;
