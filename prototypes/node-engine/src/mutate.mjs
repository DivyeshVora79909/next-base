import { validateRecord, projectRecord } from './catalog.mjs';
import { canonical, decodeDomain, selectValue } from './values.mjs';
import { sourceKey, catalogKey, incomingPrefix, incomingKey, claimKey } from './keys.mjs';
import { treePut, treeDelete, readRoot, treeGet } from './tree.mjs';

const fail = (code, message) => { throw Object.assign(new Error(message), { code }); };
const equal = (a, b) => canonical(a) === canonical(b);
function relations(catalog, record) {
  const references = [], claims = [];
  const model = catalog.models[record.model];
  for (const spec of model.references) {
    if (!Object.hasOwn(record.data, spec.field)) continue;
    const value = record.data[spec.field];
    if (spec.many && !Array.isArray(value)) fail('INVALID_REFERENCE', 'Expected reference array');
    (spec.many ? value : [value]).forEach((id, position) => {
      decodeDomain('id', id);
      references.push({ tenant: record.tenant, sourceId: record.id, slot: spec.slot, position, targetId: id, targets: [...spec.targets] });
    });
  }
  for (const spec of model.uniqueness) {
    const values = spec.fields.map(selector => {
      const selected = selectValue(record, selector);
      if (!selected.present || selected.value === undefined) fail('MISSING_CLAIM', `Missing claim value ${spec.slot}`);
      return selected.value;
    });
    claims.push({ tenant: record.tenant, model: record.model, slot: spec.slot, values, sourceId: record.id });
  }
  return { references, claims };
}
const scopeOf = occurrence => ({ tenant: occurrence.tenant, view: occurrence.view, partition: occurrence.partition });

/** Trusted internal mutation boundary; authorization is supplied by a later layer. */
export async function mutate(store, catalog, tenant, changes, { beforeCommit } = {}) {
  decodeDomain('id', tenant);
  if (!Array.isArray(changes)) fail('INVALID_MUTATION', 'Expected changes array');
  const seen = new Set();
  const commands = changes.map(change => {
    if (!change || typeof change !== 'object' || Array.isArray(change)) fail('INVALID_MUTATION', 'Expected command');
    let record, id;
    if (change.type === 'put') {
      if (Object.keys(change).some(key => !['type', 'record'].includes(key))) fail('INVALID_MUTATION', 'Unknown command field');
      record = validateRecord(catalog, change.record); id = record.id;
      if (record.tenant !== tenant) fail('NAMESPACE_MISMATCH', 'Record belongs to another tenant');
    } else if (change.type === 'delete') {
      if (Object.keys(change).some(key => !['type', 'id'].includes(key))) fail('INVALID_MUTATION', 'Unknown command field');
      id = decodeDomain('id', change.id);
    } else fail('INVALID_MUTATION', 'Unknown command');
    if (seen.has(id)) fail('DUPLICATE_SOURCE', `Duplicate command for ${id}`);
    seen.add(id);
    return { id, record };
  });
  return store.transact(async tx => {
    const identityKey = catalogKey(tenant), identity = await tx.get(identityKey);
    if (identity === undefined) await tx.set(identityKey, catalog.identity);
    else if (identity !== catalog.identity) fail('CATALOG_MISMATCH', 'Store catalog identity differs');
    const touched = [];
    let changedSources = 0, changedMemberships = 0;
    const scopes = new Map();
    for (const command of commands) {
      const key = sourceKey(tenant, command.id), old = await tx.get(key), next = command.record;
      if (old !== undefined) {
        validateRecord(catalog, old);
        if (old.id !== command.id || old.tenant !== tenant) fail('CORRUPT_STATE', 'Source key mismatch');
        if (next && (old.model !== next.model || old.createdAt !== next.createdAt)) fail('IMMUTABLE_HEADER', 'Model and createdAt are immutable');
      }
      const oldRelations = old !== undefined ? relations(catalog, old) : { references: [], claims: [] };
      const nextRelations = next ? relations(catalog, next) : { references: [], claims: [] };
      const changed = old === undefined ? next !== undefined : next === undefined || !equal(old, next);
      touched.push({ old, next, oldRelations, nextRelations, changed });
      if (changed) { changedSources++; if (next) await tx.set(key, next); else await tx.delete(key); }
    }
    // Guard and release every old claim/reference before any acquisition.
    for (const entry of touched) {
      for (const ref of entry.oldRelations.references) {
        const key = incomingKey(catalog, tenant, ref.targetId, ref), stored = await tx.get(key);
        if (stored === undefined || !equal(stored, ref)) fail('CORRUPT_STATE', 'Missing or invalid incoming reference');
        if (entry.changed) await tx.delete(key);
      }
      for (const claim of entry.oldRelations.claims) {
        const key = claimKey(catalog, tenant, claim.model, claim.slot, claim.values), stored = await tx.get(key);
        if (stored === undefined || !equal(stored, claim)) fail('CORRUPT_STATE', 'Missing or invalid uniqueness claim');
        if (entry.changed) await tx.delete(key);
      }
    }
    for (const entry of touched) {
      for (const ref of entry.nextRelations.references) {
        const target = await tx.get(sourceKey(tenant, ref.targetId));
        if (!target || target.tenant !== tenant || target.id !== ref.targetId || !ref.targets.includes(target.model)) fail('INVALID_REFERENCE', `Invalid final reference ${ref.targetId}`);
        if (entry.changed) await tx.set(incomingKey(catalog, tenant, ref.targetId, ref), ref);
      }
      for (const claim of entry.nextRelations.claims) {
        const key = claimKey(catalog, tenant, claim.model, claim.slot, claim.values), stored = await tx.get(key);
        if (stored !== undefined && !equal(stored, claim)) fail('DUPLICATE_CLAIM', `Claim already held: ${claim.slot}`);
        if (entry.changed) await tx.set(key, claim);
      }
    }
    for (const entry of touched) if (entry.old && !entry.next) {
      if ((await tx.scan({ prefix: incomingPrefix(catalog, tenant, entry.old.id), limit: 1 })).length) fail('DELETE_RESTRICTED', `Source ${entry.old.id} still referenced`);
    }
    for (const entry of touched) {
      const old = new Map((entry.old ? projectRecord(catalog, entry.old) : []).map(o => [canonical([o.view, o.slot]), o]));
      const next = new Map((entry.next ? projectRecord(catalog, entry.next) : []).map(o => [canonical([o.view, o.slot]), o]));
      for (const key of new Set([...old.keys(), ...next.keys()])) {
        const a = old.get(key), b = next.get(key);
        const samePosition = a && b && equal(a.partition, b.partition) && equal(a.order, b.order);
        if (samePosition) {
          const node = await treeGet(tx, catalog, a, a);
          if (!node || node.sourceId !== a.sourceId || node.slot !== a.slot || !equal(node.order, a.order) || !equal(node.contributions, a.contributions)) fail('CORRUPT_STATE', 'Missing or invalid old membership');
          if (equal(a, b)) continue;
          changedMemberships++;
          await treePut(tx, catalog, b);
          const scope = scopeOf(b); scopes.set(canonical(scope), scope);
          continue;
        }
        changedMemberships++;
        if (a) {
          if (!await treeDelete(tx, catalog, a)) fail('CORRUPT_STATE', 'Missing old membership');
          const scope = scopeOf(a); scopes.set(canonical(scope), scope);
        }
        if (b) { await treePut(tx, catalog, b); const scope = scopeOf(b); scopes.set(canonical(scope), scope); }
      }
    }
    for (const scope of scopes.values()) {
      const contract = catalog.views[scope.view].contract, root = await readRoot(tx, catalog, scope);
      const aggregates = root?.aggregates ?? Object.fromEntries(Object.entries(contract.aggregates).map(([name, spec]) => [name, spec.implementation.identity()]));
      for (const rule of contract.validators) {
        const result = rule.implementation.validate(structuredClone(aggregates), { scope: structuredClone(scope) });
        if (result && typeof result.then === 'function') Promise.resolve(result).catch(() => {});
        if (result !== true) fail('VALIDATION_FAILED', `Summary validator ${rule.use} rejected scope`);
      }
    }
    return { changedSources, changedMemberships, trees: [...scopes.values()], metrics: tx.inspect() };
  }, { beforeCommit });
}
