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

function commandsFor(catalog, tenant, changes) {
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
  return commands;
}

function occurrencesBySlot(catalog, record) {
  return new Map((record ? projectRecord(catalog, record) : []).map(o => [canonical([o.view, o.slot]), o]));
}

async function reconcileMemberships(tx, catalog, oldRecord, nextRecord) {
  const old = occurrencesBySlot(catalog, oldRecord);
  const next = occurrencesBySlot(catalog, nextRecord);
  for (const key of new Set([...old.keys(), ...next.keys()])) {
    const a = old.get(key), b = next.get(key);
    const samePosition = a && b && equal(a.partition, b.partition) && equal(a.order, b.order);
    if (samePosition) {
      const node = await treeGet(tx, catalog, a, a);
      if (!node || node.sourceId !== a.sourceId || node.slot !== a.slot || !equal(node.order, a.order) || !equal(node.contributions, a.contributions)) fail('CORRUPT_STATE', 'Missing or invalid old membership');
      if (equal(a, b)) continue;
      await treePut(tx, catalog, b);
      continue;
    }
    if (a) {
      if (!await treeDelete(tx, catalog, a)) fail('CORRUPT_STATE', 'Missing old membership');
    }
    if (b) await treePut(tx, catalog, b);
  }
}

function membershipTransitions(catalog, oldRecord, nextRecord) {
  const old = occurrencesBySlot(catalog, oldRecord);
  const next = occurrencesBySlot(catalog, nextRecord);
  return [...new Set([...old.keys(), ...next.keys()])].filter(key => !old.has(key) || !next.has(key) || !equal(old.get(key), next.get(key)))
    .map(key => [old.get(key), next.get(key)]);
}

/** Attempt-local internal workspace. Caller must propagate errors to abort its transaction. */
export async function createMutation(tx, catalog, tenant) {
  decodeDomain('id', tenant);
  if (Object.values(catalog.models).some(model => model.managed || model.calculations?.length)) {
    fail('UNSUPPORTED_SETTLEMENT', 'Calculation or managed catalogs require the integrated settlement writer; only the reference oracle is available');
  }
  const identityKey = catalogKey(tenant), identity = await tx.get(identityKey);
  if (identity === undefined) await tx.set(identityKey, catalog.identity);
  else if (identity !== catalog.identity) fail('CATALOG_MISMATCH', 'Store catalog identity differs');
  const entries = new Map();
  let state = 'open';
  function assertOpen() {
    if (state !== 'open') fail('MUTATION_CLOSED', `Mutation workspace is ${state}`);
  }
  async function stage(changes) {
    assertOpen();
    state = 'staging';
    try {
      const commands = commandsFor(catalog, tenant, changes);
      for (const command of commands) {
        const key = sourceKey(tenant, command.id), current = await tx.get(key), next = command.record;
        if (current !== undefined) {
          validateRecord(catalog, current);
          if (current.id !== command.id || current.tenant !== tenant) fail('CORRUPT_STATE', 'Source key mismatch');
        }
        const entry = entries.get(command.id) ?? { old: current, next: current, header: current ?? next };
        const original = entry.old;
        for (const prior of [original, current, entry.header]) {
          if (prior !== undefined && next && (prior.model !== next.model || prior.createdAt !== next.createdAt)) fail('IMMUTABLE_HEADER', 'Model and createdAt are immutable');
        }
        // Parse relation shapes now; existence and claims belong to the final graph.
        if (next) relations(catalog, next);
        const changed = current === undefined ? next !== undefined : next === undefined || !equal(current, next);
        if (changed) { if (next) await tx.set(key, next); else await tx.delete(key); }
        await reconcileMemberships(tx, catalog, current, next);
        entry.next = next;
        entry.header ??= next;
        entries.set(command.id, entry);
      }
      state = 'open';
    } catch (error) { state = 'failed'; throw error; }
  }
  async function finish() {
    assertOpen();
    state = 'finishing';
    try {
      const touched = [...entries.values()].map(entry => ({
        ...entry,
        changed: entry.old === undefined ? entry.next !== undefined : entry.next === undefined || !equal(entry.old, entry.next),
        oldRelations: entry.old !== undefined ? relations(catalog, entry.old) : { references: [], claims: [] },
        nextRelations: entry.next !== undefined ? relations(catalog, entry.next) : { references: [], claims: [] },
      }));
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
      // Validator obligations follow committed old-to-final transitions. A scope
      // visited only by transient stages is not part of the final mutation.
      const scopes = new Map();
      let changedMemberships = 0;
      for (const entry of touched) {
        const transitions = membershipTransitions(catalog, entry.old, entry.next);
        changedMemberships += transitions.length;
        for (const transition of transitions) for (const occurrence of transition) {
          if (!occurrence) continue;
          const scope = scopeOf(occurrence);
          scopes.set(canonical(scope), scope);
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
      // Counts describe committed old-to-final differences, not transient staging work.
      const changedSources = touched.filter(entry => entry.changed).length;
      state = 'finished';
      return { changedSources, changedMemberships, trees: [...scopes.values()], metrics: tx.inspect() };
    } catch (error) { state = 'failed'; throw error; }
  }
  return { stage, finish };
}

/** Trusted internal mutation boundary; authorization is supplied by a later layer. */
export async function mutate(store, catalog, tenant, changes, { beforeCommit } = {}) {
  return store.transact(async tx => {
    const mutation = await createMutation(tx, catalog, tenant);
    await mutation.stage(changes);
    return mutation.finish();
  }, { beforeCommit });
}
