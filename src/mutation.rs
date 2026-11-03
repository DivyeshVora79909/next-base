//! Shared command staging and final publication. Model behavior cannot select a
//! different receipt, authority, CAS or transaction implementation.
use crate::{
    binding::{self, Binding, NativeInput},
    index::NativeIndex,
    model::{Prepared, Visibility},
    native_codec::{Address, Key, StoredValue},
    native_slice::{Attempt, Command, Context, Error, ModelChange, ModelRecord, Result, Settled},
    tree,
};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// Bound into prepared identity when reference authorization or routing semantics change.
pub const REFERENCE_POLICY: &str = "final-graph-reference-policy-v2-engine-incoming";

/// Server-observed UTC milliseconds, not a commit sequence or business effective time.
pub(crate) fn creation_time() -> Result<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|v| i64::try_from(v.as_millis()).ok())
        .ok_or_else(|| Error::new("clock", "creation timestamp unavailable"))
}

pub fn validate_references<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    input: &B::Input,
    context: Context,
) -> Result<()> {
    let contract = model.contract(input.contract())?;
    for (id, _, slot) in input.references() {
        let declaration = contract
            .references
            .iter()
            .find(|r| r.slot == slot)
            .ok_or_else(|| Error::new("model", "undeclared bound reference"))?;
        let record = ws
            .record(id)?
            .ok_or_else(|| Error::new("unavailable_reference", "required source unavailable"))?;
        if record.tenant != context.tenant || !declaration.targets.contains(&record.contract) {
            return Err(Error::new(
                "unavailable_reference",
                "reference type or tenant",
            ));
        }
    }
    Ok(())
}

/// Maintain the reverse existence routes derived from typed source references.
/// Record headers must already exist; Direct and Subscribers retain binding policy.
pub(crate) fn reconcile_incoming<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    id: Uuid,
    old: Option<&B::Input>,
    new: Option<&B::Input>,
) -> Result<()> {
    let mut references = |input: Option<&B::Input>| -> Result<BTreeSet<(Uuid, u16)>> {
        let references = input.map(NativeInput::references).unwrap_or_default();
        ws.charge("dependency", 1 + references.len() as u64)?;
        Ok(references
            .into_iter()
            .map(|(target, _, slot)| (target, slot))
            .collect())
    };
    let before = references(old)?;
    let after = references(new)?;
    for (target, slot) in before.difference(&after) {
        crate::routes::change(
            ws,
            &Key::Incoming(*target),
            Address::new(id, *slot),
            crate::native_range::NativeRange::ALL,
            false,
        )?;
    }
    for (target, slot) in after.difference(&before) {
        crate::routes::change(
            ws,
            &Key::Incoming(*target),
            Address::new(id, *slot),
            crate::native_range::NativeRange::ALL,
            true,
        )?;
    }
    Ok(())
}

#[allow(clippy::type_complexity)]
pub fn reconcile_member<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    id: Address,
    old: Option<(
        Address,
        <B::Index as NativeIndex>::Key,
        <B::Index as NativeIndex>::Leaf,
    )>,
    new: Option<(
        Address,
        <B::Index as NativeIndex>::Key,
        <B::Index as NativeIndex>::Leaf,
    )>,
) -> Result<()> {
    if old == new {
        return Ok(());
    }
    if let Some((root, at, leaf)) = old {
        let actual = tree::node(ws, root, id)?;
        if actual.key.value != at || actual.leaf != leaf {
            return Err(Error::new(
                "corrupt_state",
                "old membership differs from source",
            ));
        }
        tree::remove(ws, root, id)?;
    }
    if let Some((root, at, leaf)) = new {
        tree::insert(ws, root, id, at, leaf)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn settle_authorized<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    context: Context,
    commands: &[Command],
    allocate: &mut dyn FnMut() -> Result<Uuid>,
    trusted: bool,
    authorize: &mut dyn FnMut(
        &mut Attempt<L, B>,
        &Command,
        Option<&ModelRecord<B>>,
        Option<&ModelRecord<B>>,
    ) -> Result<()>,
    finalize: &mut dyn FnMut(&mut Attempt<L, B>, Uuid) -> Result<()>,
) -> Result<Settled> {
    let Some(StoredValue::Meta(meta)) = ws.get(&Key::Meta)? else {
        return Err(Error::new("corrupt_state", "missing model header"));
    };
    if meta.model != model.identity()
        || meta.codec != crate::native_codec::CODEC
        || model.engine().codec != crate::native_codec::CODEC
    {
        return Err(Error::new("model_mismatch", "store/model identity differs"));
    }
    if meta.tenant != context.tenant {
        return Err(Error::new("forbidden", "tenant differs"));
    }
    if commands.is_empty()
        || commands.len() > 64
        || commands
            .iter()
            .map(Command::id)
            .collect::<BTreeSet<_>>()
            .len()
            != commands.len()
    {
        return Err(Error::new(
            "invalid_input",
            "one command per UUID; 1..64 commands",
        ));
    }
    // A caller may settle several command chunks in one Attempt. Capture the
    // already-staged source facts so late reconciliation starts at this call's
    // entry graph rather than reapplying earlier calls from database originals.
    let mut entry_records = BTreeMap::new();
    for id in ws.changed_records() {
        ws.charge("dependency", 1)?;
        entry_records.insert(id, ws.record(id)?);
    }
    // A token identifies the state produced by this attempt. It is never an
    // ordered store sequence, and cannot repeat after delete/recreate.
    let revision = Uuid::new_v4();
    let role_slots: BTreeSet<_> = model
        .contracts()
        .flat_map(|c| c.outputs.iter().map(|o| o.role))
        .collect();
    let mut changes = vec![];
    let mut created_at = None;
    for command in commands {
        ws.charge("command", 1)?;
        let id = command.id();
        let old = ws.record(id)?;
        authorize(ws, command, old.as_ref(), None)?;
        if let Some(old) = &old {
            let visibility = model.contract(old.contract)?.visibility;
            if visibility == Visibility::Engine || visibility == Visibility::Fixture && !trusted {
                return Err(Error::new("forbidden", "private record"));
            }
        }
        let new = match command {
            Command::Create {
                contract,
                owner,
                fields,
                ..
            } => {
                let declaration = model.contract(*contract)?;
                if declaration.visibility == Visibility::Engine
                    || declaration.visibility == Visibility::Fixture && !trusted
                {
                    return Err(Error::new("forbidden", "private contract"));
                }
                if old.is_some() {
                    return Err(Error::new("already_exists", "source UUID exists"));
                }
                if ws.get(&Key::Reserved(id))?.is_some() {
                    return Err(Error::new("unavailable_reference", "reserved identity"));
                }
                for slot in &role_slots {
                    if ws.get(&Key::Role(Address::new(id, *slot)))?.is_some() {
                        return Err(Error::new(
                            "unavailable_reference",
                            "retired producer identity",
                        ));
                    }
                }
                let input = model.validate(*contract, fields)?;
                let created_at = *created_at.get_or_insert(creation_time()?);
                Some(ModelRecord {
                    contract: *contract,
                    tenant: context.tenant,
                    owner: owner.unwrap_or(context.actor),
                    created_at,
                    version: revision,
                    input,
                    derived: None,
                })
            }
            Command::Update { if_version, .. } | Command::Delete { if_version, .. } => {
                let previous = old
                    .as_ref()
                    .ok_or_else(|| Error::new("unavailable_reference", "source unavailable"))?;
                if previous.tenant != context.tenant {
                    return Err(Error::new("forbidden", "source authority"));
                }
                if previous.version != *if_version {
                    return Err(Error::new("stale_version", "source version"));
                }
                if let Command::Update {
                    owner, set, unset, ..
                } = command
                {
                    let declaration = model.contract(previous.contract)?;
                    if !unset.is_empty()
                        || set.keys().any(|key| {
                            !declaration
                                .fields
                                .iter()
                                .any(|f| f.name == key && f.mutable)
                        })
                    {
                        return Err(Error::new("invalid_input", "protected or required field"));
                    }
                    let mut value = serde_json::to_value(&previous.input)
                        .map_err(|e| Error::new("codec", e.to_string()))?;
                    value
                        .as_object_mut()
                        .ok_or_else(|| Error::new("internal", "input object"))?
                        .extend(set.clone());
                    let mut next = previous.clone();
                    next.owner = owner.unwrap_or(previous.owner);
                    next.input = model.validate(previous.contract, &value)?;
                    Some(next)
                } else {
                    None
                }
            }
        };
        ws.put(Key::Record(id), new.clone().map(StoredValue::Record))?;
        changes.push(ModelChange { id, old, new });
    }
    for change in &changes {
        if let (None, Some(new)) = (&change.old, &change.new) {
            for (key, value) in binding::headers(model, change.id, &new.input, revision)? {
                if ws.get(&key)?.is_some() {
                    return Err(Error::new(
                        "corrupt_state",
                        "orphan private header on create",
                    ));
                }
                ws.put(key, Some(value))?;
            }
        }
    }
    // Resolve authored references only after every proposed record is staged.
    for change in &changes {
        if let Some(new) = &change.new {
            validate_references(ws, model, &new.input, context)?;
        }
    }
    for change in &changes {
        reconcile_incoming(
            ws,
            change.id,
            change.old.as_ref().map(|r| &r.input),
            change.new.as_ref().map(|r| &r.input),
        )?;
    }
    B::settle_changes(ws, model, context, &changes, revision, allocate)?;
    // Settlement may edit ordinary records beyond the explicit commands. Explicit
    // IDs remain candidates even if settlement restores their original contents.
    // Managed outputs reconcile each transition inside the causal writer instead.
    let proposed: BTreeMap<_, _> = changes.iter().map(|c| (c.id, c.new.as_ref())).collect();
    let mut incoming_candidates = ws.changed_records();
    incoming_candidates.extend(proposed.keys().copied());
    incoming_candidates.extend(entry_records.keys().copied());
    for id in incoming_candidates {
        ws.charge("dependency", 1)?;
        let original = match ws.original(&Key::Record(id))? {
            Some(StoredValue::Record(record)) => Some(record),
            None => None,
            _ => return Err(Error::new("corrupt_state", "original record type")),
        };
        let current = ws.record(id)?;
        let entry = match entry_records.get(&id) {
            Some(record) => record.as_ref(),
            None => original.as_ref(),
        };
        let before = match proposed.get(&id) {
            Some(record) => *record,
            None => entry,
        };
        if original
            .iter()
            .chain(entry)
            .chain(before)
            .chain(current.iter())
            .any(|r| r.input.managed().is_some())
        {
            continue;
        }
        if entry.is_some() && current.is_none() && !proposed.contains_key(&id) {
            return Err(Error::new(
                "model",
                "ordinary deletion requires command lifecycle",
            ));
        }
        if let Some(record) = &current {
            // Raw ordinary creation by a binding must provide the shared lifecycle;
            // it cannot silently bypass source headers.
            if !matches!(ws.get(&Key::Incoming(id))?, Some(StoredValue::Incoming(_))) {
                return Err(Error::new(
                    "corrupt_state",
                    "missing ordinary source header",
                ));
            }
            validate_references(ws, model, &record.input, context)?;
        }
        reconcile_incoming(
            ws,
            id,
            before.map(|r| &r.input),
            current.as_ref().map(|r| &r.input),
        )?;
    }
    for change in &changes {
        if let Some(new) = ws.record(change.id)? {
            validate_references(ws, model, &new.input, context)?;
        } else {
            for (key, _) in binding::headers(
                model,
                change.id,
                &change
                    .old
                    .as_ref()
                    .ok_or_else(|| Error::new("internal", "missing deleted source"))?
                    .input,
                revision,
            )? {
                match ws.get(&key)? {
                    Some(StoredValue::Root(root)) if root.head.is_some() => {
                        return Err(Error::new("unavailable_reference", "nonempty retired root"));
                    }
                    Some(
                        StoredValue::Incoming(rows)
                        | StoredValue::Direct(rows)
                        | StoredValue::Subscribers(rows),
                    ) if !rows.is_empty() => {
                        return Err(Error::new(
                            "unavailable_reference",
                            "surviving reference or subscriber",
                        ));
                    }
                    _ => {}
                }
                ws.put(key, None)?;
            }
        }
    }
    // Trusted settlement does not authorize client mutations. Authorize only
    // the original client commands against their final records and references.
    finalize(ws, revision)?;
    for (command, change) in commands.iter().zip(&changes) {
        let current = ws.record(change.id)?;
        authorize(ws, command, change.old.as_ref(), current.as_ref())?;
    }
    crate::relationships::validate(ws, model)?;
    crate::uniqueness::reconcile_from(ws, model, &entry_records)?;
    crate::access_index::reconcile(ws, model, &entry_records, revision)?;
    for id in ws.changed_roots() {
        if let Some(StoredValue::Root(mut root)) = ws.get(&Key::Root(id))? {
            root.revision = revision;
            ws.put(Key::Root(id), Some(StoredValue::Root(root)))?;
        }
    }
    for id in ws.changed_records() {
        if let Some(mut current) = ws.record(id)? {
            // A later settlement may leave an earlier chunk's result unchanged.
            // Preserve that entry token, while a full return to the database
            // original still eliminates the source write.
            let entry_version = entry_records.get(&id).and_then(|entry| {
                entry.as_ref().and_then(|entry| {
                    let mut comparable = current.clone();
                    comparable.version = entry.version;
                    (comparable == *entry).then_some(entry.version)
                })
            });
            if let Some(StoredValue::Record(old)) = ws.original(&Key::Record(id))? {
                current.version = old.version;
                if current != old {
                    current.version = entry_version.unwrap_or(revision);
                }
            } else {
                current.version = entry_version.unwrap_or(revision);
            }
            ws.put(Key::Record(id), Some(StoredValue::Record(current)))?;
        }
    }
    Ok(Settled { revision })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        models::quantity::{Quantity, SOURCE},
        native_codec,
        native_slice::Meta,
        staging::Batch,
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    type Image = BTreeMap<Vec<u8>, Vec<u8>>;
    type Applied = (Uuid, Batch, BTreeSet<Vec<u8>>);

    fn quantity_chunk<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Attempt<L, Quantity>,
        model: &Prepared<Quantity>,
        context: Context,
        commands: &[Command],
    ) -> Settled {
        settle_authorized(
            ws,
            model,
            context,
            commands,
            &mut || Err(Error::new("unexpected_allocation", "source has no outputs")),
            false,
            &mut |_, _, _, _| Ok(()),
            &mut |_, _| Ok(()),
        )
        .unwrap()
    }
    fn quantity_create(id: u128, value: &str) -> Command {
        Command::Create {
            owner: None,
            id: Uuid::from_u128(id),
            contract: SOURCE,
            fields: json!({"value":value}),
        }
    }
    fn quantity_update(id: u128, if_version: Uuid, value: &str) -> Command {
        Command::Update {
            owner: None,
            id: Uuid::from_u128(id),
            if_version,
            set: BTreeMap::from([("value".into(), json!(value))]),
            unset: vec![],
        }
    }
    fn quantity_image(populated: bool) -> (Prepared<Quantity>, Context, Image) {
        let model = Prepared::<Quantity>::load().unwrap();
        let context = Context {
            tenant: Uuid::from_u128(1),
            actor: Uuid::from_u128(2),
        };
        let mut rows = BTreeMap::from([(
            Key::Meta.encode(),
            native_codec::encode_for::<Quantity>(
                &Key::Meta,
                &StoredValue::Meta(Meta {
                    model: model.identity().into(),
                    codec: native_codec::CODEC.into(),
                    tenant: context.tenant,
                    actor: context.actor,
                }),
            )
            .unwrap(),
        )]);
        if populated {
            let mut ws =
                Attempt::<_, Quantity>::new(|key: &[u8]| Ok(rows.get(key).cloned()), 200_000);
            quantity_chunk(
                &mut ws,
                &model,
                context,
                &[quantity_create(3, "1"), quantity_create(4, "10")],
            );
            let batch = ws.finish().unwrap();
            drop(ws);
            for (key, value) in batch {
                if let Some(value) = value {
                    rows.insert(key, value);
                } else {
                    rows.remove(&key);
                }
            }
        }
        (model, context, rows)
    }

    #[test]
    fn repeated_chunks_preserve_source_tokens_across_noops_and_unrelated_edits() {
        for preexisting in [false, true] {
            let (model, context, rows) = quantity_image(preexisting);
            let mut ws =
                Attempt::<_, Quantity>::new(|key: &[u8]| Ok(rows.get(key).cloned()), 200_000);
            if !preexisting {
                quantity_chunk(
                    &mut ws,
                    &model,
                    context,
                    &[quantity_create(3, "1"), quantity_create(4, "10")],
                );
            }
            let original = ws.record(Uuid::from_u128(3)).unwrap().unwrap();
            quantity_chunk(
                &mut ws,
                &model,
                context,
                &[quantity_update(3, original.version, "2")],
            );
            let first = ws.record(Uuid::from_u128(3)).unwrap().unwrap();
            assert_ne!(first.version, original.version);
            assert_eq!(first.derived.unwrap().quantity, 2);
            let second_version = ws.record(Uuid::from_u128(4)).unwrap().unwrap().version;
            quantity_chunk(
                &mut ws,
                &model,
                context,
                &[quantity_update(4, second_version, "20")],
            );
            let unrelated = ws.record(Uuid::from_u128(4)).unwrap().unwrap();
            assert_eq!(ws.record(Uuid::from_u128(3)).unwrap(), Some(first.clone()));
            let noop = quantity_chunk(
                &mut ws,
                &model,
                context,
                &[quantity_update(3, first.version, "2")],
            );
            assert_ne!(noop.revision, first.version);
            assert_eq!(ws.record(Uuid::from_u128(3)).unwrap(), Some(first.clone()));
            assert_eq!(
                ws.record(Uuid::from_u128(4)).unwrap(),
                Some(unrelated.clone())
            );
            // The saved token from the first actual edit remains a usable CAS
            // token after both intervening calls.
            quantity_chunk(
                &mut ws,
                &model,
                context,
                &[quantity_update(3, first.version, "3")],
            );
            assert_eq!(
                ws.record(Uuid::from_u128(3))
                    .unwrap()
                    .unwrap()
                    .derived
                    .unwrap()
                    .quantity,
                3
            );
            assert_eq!(ws.record(Uuid::from_u128(4)).unwrap(), Some(unrelated));
        }
    }

    #[test]
    fn full_source_revert_restores_original_token_and_prunes_write_without_pruning_read_guard() {
        let (model, context, rows) = quantity_image(true);
        let mut reads = BTreeSet::new();
        let mut ws = Attempt::<_, Quantity>::new(
            |key: &[u8]| {
                reads.insert(key.to_vec());
                Ok(rows.get(key).cloned())
            },
            200_000,
        );
        let original = ws.record(Uuid::from_u128(3)).unwrap().unwrap();
        quantity_chunk(
            &mut ws,
            &model,
            context,
            &[quantity_update(3, original.version, "2")],
        );
        let edited = ws.record(Uuid::from_u128(3)).unwrap().unwrap();
        let second_version = ws.record(Uuid::from_u128(4)).unwrap().unwrap().version;
        quantity_chunk(
            &mut ws,
            &model,
            context,
            &[quantity_update(4, second_version, "20")],
        );
        let unrelated = ws.record(Uuid::from_u128(4)).unwrap().unwrap();
        quantity_chunk(
            &mut ws,
            &model,
            context,
            &[quantity_update(3, edited.version, "1")],
        );
        assert_eq!(ws.record(Uuid::from_u128(3)).unwrap(), Some(original));
        assert_eq!(ws.record(Uuid::from_u128(4)).unwrap(), Some(unrelated));
        let batch = ws.finish().unwrap();
        drop(ws);
        assert!(!batch.contains_key(&Key::Record(Uuid::from_u128(3)).encode()));
        assert!(batch.contains_key(&Key::Record(Uuid::from_u128(4)).encode()));
        assert!(reads.contains(&Key::Record(Uuid::from_u128(3)).encode()));
        assert!(reads.contains(&Key::Record(Uuid::from_u128(4)).encode()));
    }

    // This native control checks state and read/write sets. The storage
    // conformance schedules independently establish real commit conflicts.
    #[test]
    fn opaque_tokens_preserve_noops_and_reject_delete_recreate_aba() {
        let model = Prepared::<Quantity>::load().unwrap();
        let context = Context {
            tenant: Uuid::from_u128(1),
            actor: Uuid::from_u128(2),
        };
        let mut rows = BTreeMap::from([(
            Key::Meta.encode(),
            native_codec::encode_for::<Quantity>(
                &Key::Meta,
                &StoredValue::Meta(Meta {
                    model: model.identity().into(),
                    codec: native_codec::CODEC.into(),
                    tenant: context.tenant,
                    actor: context.actor,
                }),
            )
            .unwrap(),
        )]);
        let run = |rows: &mut Image, command: Command| -> Result<Applied> {
            let mut reads = BTreeSet::new();
            let mut ws = Attempt::<_, Quantity>::new(
                |key: &[u8]| {
                    reads.insert(key.to_vec());
                    Ok(rows.get(key).cloned())
                },
                200_000,
            );
            let result = settle_authorized(
                &mut ws,
                &model,
                context,
                &[command],
                &mut || Err(Error::new("unexpected_allocation", "source has no outputs")),
                false,
                &mut |_, _, _, _| Ok(()),
                &mut |_, _| Ok(()),
            )?;
            let batch = ws.finish()?;
            drop(ws);
            for (key, value) in &batch {
                match value {
                    Some(value) => {
                        rows.insert(key.clone(), value.clone());
                    }
                    None => {
                        rows.remove(key);
                    }
                }
            }
            Ok((result.revision, batch, reads))
        };
        let id = Uuid::from_u128(3);
        let create = || Command::Create {
            owner: None,
            id,
            contract: SOURCE,
            fields: json!({"value":"1"}),
        };
        let update = |if_version, value| Command::Update {
            owner: None,
            id,
            if_version,
            set: BTreeMap::from([("value".into(), json!(value))]),
            unset: vec![],
        };
        let (created, batch, _) = run(&mut rows, create()).unwrap();
        assert!(!created.is_nil());
        assert!(!batch.contains_key(&Key::Meta.encode()));

        let before = rows.clone();
        let (noop, batch, reads) = run(&mut rows, update(created, "1")).unwrap();
        assert_ne!(noop, created);
        assert!(batch.is_empty());
        assert_eq!(rows, before);
        assert!(reads.contains(&Key::Record(id).encode()));

        let (changed, batch, _) = run(&mut rows, update(created, "2")).unwrap();
        assert_ne!(changed, created);
        assert!(!batch.contains_key(&Key::Meta.encode()));
        let StoredValue::Record(record) = native_codec::decode_for::<Quantity>(
            &Key::Record(id),
            &rows[&Key::Record(id).encode()],
        )
        .unwrap() else {
            panic!("record missing")
        };
        assert_eq!(record.version, changed);
        assert_eq!(record.derived.unwrap().quantity, 2);

        run(
            &mut rows,
            Command::Delete {
                id,
                if_version: changed,
            },
        )
        .unwrap();
        let (recreated, _, _) = run(&mut rows, create()).unwrap();
        assert_ne!(recreated, created);
        assert_ne!(recreated, changed);
        let before = rows.clone();
        assert_eq!(
            run(&mut rows, update(created, "3")).unwrap_err().code,
            "stale_version"
        );
        assert_eq!(rows, before);
    }
}
