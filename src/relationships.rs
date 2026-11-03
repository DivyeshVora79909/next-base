//! Pure relationship checks over the final authored graph. Validation inputs do
//! not install calculation routes or expose undeclared parent fields.
use crate::{
    binding::{Binding, NativeInput},
    model::{Prepared, Reference},
    native_codec::{Key, StoredValue},
    native_slice::{Attempt, Error, ModelRecord, Result},
    routes,
};
use serde_json::{Map, Value};
use std::{cell::RefCell, collections::BTreeSet, ops::Bound};
use uuid::Uuid;

/// Part of prepared model identity: final authored projections and one-hop
/// parent-change revalidation, after final client reference authorization.
pub const POLICY: &str = "declared-authored-parent-projections-final-incoming-1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationInput {
    pub slot: u16,
    pub target: Uuid,
    pub fields: Map<String, Value>,
}

fn projection<B: Binding>(
    input: &B::Input,
    declaration: &Reference,
    charge: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<Map<String, Value>> {
    let authored = authored::<B>(input, charge)?;
    projected(&authored, &declaration.validation_fields, charge)
}

fn authored<B: Binding>(
    input: &B::Input,
    charge: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<Value> {
    charge(1)?;
    let value = serde_json::to_value(input).map_err(crate::local::storage)?;
    charge_value(&value, charge)?;
    Ok(value)
}

fn projected(
    authored: &Value,
    names: &[&str],
    charge: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<Map<String, Value>> {
    let mut fields = Map::new();
    for field in names {
        charge(1)?;
        let value = authored
            .get(*field)
            .ok_or_else(|| Error::new("invalid_input", "missing authored relationship input"))?;
        fields.insert((*field).to_owned(), value.clone());
    }
    Ok(fields)
}

// Account for traversal and copied authored strings/keys without a second JSON
// serialization/parser pass. Storage input byte limits remain separate.
fn charge_value(value: &Value, charge: &mut dyn FnMut(u64) -> Result<()>) -> Result<()> {
    charge(1)?;
    match value {
        Value::String(text) => charge(text.len() as u64)?,
        Value::Array(values) => {
            for value in values {
                charge_value(value, charge)?;
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                charge(key.len() as u64)?;
                charge_value(value, charge)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Resolve only declared authored parent fields. Shared with the independent
/// inventory checker; callers independently supply their source-record view.
pub(crate) fn inputs<B: Binding>(
    model: &Prepared<B>,
    source: &ModelRecord<B>,
    resolve: &mut dyn FnMut(Uuid) -> Result<Option<ModelRecord<B>>>,
    charge: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<Vec<RelationInput>> {
    charge(1)?;
    let contract = model.contract(source.contract)?;
    let references = source.input.references();
    charge(references.len() as u64)?;
    let mut parents = Vec::new();
    // Catalog declaration preorder, then native occurrence order within a slot.
    for declaration in &contract.references {
        charge(1 + references.len() as u64)?;
        if declaration.validation_fields.is_empty() {
            continue;
        }
        let mut found = false;
        for (target, _, _) in references
            .iter()
            .filter(|(_, _, slot)| *slot == declaration.slot)
        {
            found = true;
            charge(1)?;
            let parent = resolve(*target)?.ok_or_else(|| {
                Error::new("unavailable_reference", "required source unavailable")
            })?;
            if source.tenant != parent.tenant || !declaration.targets.contains(&parent.contract) {
                return Err(Error::new(
                    "unavailable_reference",
                    "reference type or tenant",
                ));
            }
            parents.push(RelationInput {
                slot: declaration.slot,
                target: *target,
                fields: projection::<B>(&parent.input, declaration, charge)?,
            });
        }
        if !found && !declaration.optional {
            return Err(Error::new(
                "invalid_input",
                "missing required relationship reference",
            ));
        }
    }
    Ok(parents)
}

/// Validate changed sources plus final consumers whose declared parent input
/// changed. Predicates produce no state, so discovery is deliberately one hop.
pub fn validate<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
) -> Result<()> {
    // The immutable prepared catalog supplies the authored dependency union;
    // mutation work scales with changed records and their relevant consumers.
    let changed = ws.changed_records();
    let mut candidates: BTreeSet<_> = changed.iter().copied().collect();
    for id in changed {
        ws.charge("dependency", 1)?;
        let old = match ws.original(&Key::Record(id))? {
            Some(StoredValue::Record(record)) => Some(record),
            None => None,
            _ => return Err(Error::new("corrupt_state", "relationship source type")),
        };
        let Some(parent) = ws.record(id)? else {
            continue;
        };
        let Some(names) = model.relationship_validation_fields(parent.contract) else {
            continue;
        };
        // Reader/version/derived-only repairs cannot change authored inputs.
        if old.as_ref().is_some_and(|r| r.input == parent.input) {
            continue;
        }
        let final_authored = authored::<B>(&parent.input, &mut |n| ws.charge("dependency", n))?;
        let old_authored = old
            .as_ref()
            .map(|r| authored::<B>(&r.input, &mut |n| ws.charge("dependency", n)))
            .transpose()?;
        let names: Vec<_> = names.iter().copied().collect();
        let final_union = projected(&final_authored, &names, &mut |n| ws.charge("dependency", n))?;
        let old_union = old_authored
            .as_ref()
            .map(|value| projected(value, &names, &mut |n| ws.charge("dependency", n)))
            .transpose()?;
        if old_union.as_ref() == Some(&final_union) {
            continue;
        }
        let incoming = routes::select(
            ws,
            &Key::Incoming(id),
            Bound::Unbounded,
            Bound::Unbounded,
            false,
        )?;
        for address in incoming {
            ws.charge("dependency", 1)?;
            let Some(child) = ws.record(address.id)? else {
                return Err(Error::new("corrupt_state", "missing relationship consumer"));
            };
            let declaration = model
                .contract(child.contract)?
                .references
                .iter()
                .find(|r| r.slot == address.slot)
                .ok_or_else(|| Error::new("corrupt_state", "undeclared relationship consumer"))?;
            let references = child.input.references();
            ws.charge(
                "dependency",
                references.len() as u64 + declaration.validation_fields.len() as u64 + 1,
            )?;
            if !references
                .iter()
                .any(|(target, _, slot)| *target == id && *slot == address.slot)
            {
                return Err(Error::new("corrupt_state", "stale relationship consumer"));
            }
            ws.charge("dependency", declaration.targets.len() as u64)?;
            if !declaration.targets.contains(&parent.contract) {
                return Err(Error::new(
                    "corrupt_state",
                    "relationship consumer target type",
                ));
            }
            if declaration.validation_fields.is_empty() {
                continue;
            }
            let final_fields =
                projected(&final_authored, &declaration.validation_fields, &mut |n| {
                    ws.charge("dependency", n)
                })?;
            let original_fields = old_authored
                .as_ref()
                .map(|value| {
                    projected(value, &declaration.validation_fields, &mut |n| {
                        ws.charge("dependency", n)
                    })
                })
                .transpose()?;
            if original_fields.as_ref() != Some(&final_fields) {
                candidates.insert(address.id);
            }
        }
    }
    for id in candidates {
        ws.charge("dependency", 1)?;
        let Some(source) = ws.record(id)? else {
            continue;
        };
        let parents = {
            // The closures borrow sequentially: each projection charge is enforced
            // before continuing discovery, rather than billed after materializing it.
            let workspace = RefCell::new(&mut *ws);
            inputs::<B>(
                model,
                &source,
                &mut |id| workspace.borrow_mut().record(id),
                &mut |n| workspace.borrow_mut().charge("dependency", n),
            )?
        };
        B::validate_relationships(&source.input, &parents)
            .map_err(|error| Error::new(error.code, "relationship validation failed"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        indexes::standard::Standard,
        integrity::Snapshot,
        local::{KV, Mutation, Store},
        model::Contract,
        models::quantity::{Input, JOIN, Quantity, SOURCE},
        native_codec::{self, Address},
        native_slice::{Context, Model, ModelChange, Population},
        time_range::TimeRange,
    };
    use serde_json::json;
    use std::{collections::BTreeMap, sync::Arc};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Ordered;
    impl Binding for Ordered {
        type Index = Standard;
        type Input = Input;
        type Derived = ();
        type Outcome = ();
        const NAME: &'static str = "relationship-independent-inventory";
        const BEHAVIOR: &'static str = "authored-left-value-lte-right-value-1";
        fn engine() -> Result<Model> {
            Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
        }
        fn declarations() -> Result<Vec<Contract>> {
            let mut contracts = Quantity::declarations()?;
            contracts.retain(|c| [SOURCE, JOIN].contains(&c.code));
            for contract in &mut contracts {
                contract.published.clear();
                contract.publication_inputs.clear();
                contract.calculations.clear();
                contract.calculation_order.clear();
                for relation in &mut contract.references {
                    relation.reader = false;
                    relation.targets = vec![SOURCE];
                    relation.validation_fields = vec!["value"];
                }
            }
            Ok(contracts)
        }
        fn valid_derived(_: &Input, value: Option<&()>) -> bool {
            value.is_none()
        }
        fn published_shape(_: u16) -> Value {
            Value::Null
        }
        fn validate_relationships(input: &Input, parents: &[RelationInput]) -> Result<()> {
            if let Input::Join { .. } = input {
                let left = parents[0].fields["value"]
                    .as_str()
                    .unwrap()
                    .parse::<i128>()
                    .unwrap();
                let right = parents[1].fields["value"]
                    .as_str()
                    .unwrap()
                    .parse::<i128>()
                    .unwrap();
                if left > right {
                    return Err(Error::new("invariant", "left exceeds right"));
                }
            }
            Ok(())
        }
        fn settle_changes<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
            ws: &mut Attempt<L, Self>,
            _: &Prepared<Self>,
            _: Context,
            changes: &[ModelChange<Self>],
            _: &mut Population,
            _: Uuid,
            _: &mut dyn FnMut() -> Result<Uuid>,
        ) -> Result<()> {
            for change in changes {
                let old: BTreeSet<_> = change
                    .old
                    .iter()
                    .flat_map(|r| r.input.references())
                    .collect();
                let new: BTreeSet<_> = change
                    .new
                    .iter()
                    .flat_map(|r| r.input.references())
                    .collect();
                for (target, _, slot) in old.difference(&new) {
                    routes::change(
                        ws,
                        &Key::Incoming(*target),
                        Address::new(change.id, *slot),
                        TimeRange::ALL,
                        false,
                    )?;
                }
                for (target, _, slot) in new.difference(&old) {
                    routes::change(
                        ws,
                        &Key::Incoming(*target),
                        Address::new(change.id, *slot),
                        TimeRange::ALL,
                        true,
                    )?;
                }
            }
            Ok(())
        }
        fn check(store: &Store<Self>) -> Result<Value> {
            Snapshot::load(store)?;
            Ok(Value::Null)
        }
    }
    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }
    fn record(input: Input) -> ModelRecord<Ordered> {
        ModelRecord {
            contract: input.contract(),
            tenant: id(1),
            owner: id(2),
            reader: id(2),
            version: id(3),
            input,
            derived: None,
        }
    }
    #[test]
    fn snapshot_rejects_parent_source_corruption_with_unchanged_child() {
        let directory =
            std::env::temp_dir().join(format!("relationship-source-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let store = Store::<Ordered>::create(
            directory.join("store.redb"),
            Arc::new(Prepared::load().unwrap()),
            Context {
                tenant: id(1),
                actor: id(2),
            },
        )
        .unwrap();
        let request: Mutation = serde_json::from_value(json!({
            "model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),
            "operation_id":Uuid::new_v4(),"returning":[],"commands":[
                {"op":"create","id":id(10),"contract":SOURCE,"fields":{"value":"1"}},
                {"op":"create","id":id(11),"contract":SOURCE,"fields":{"value":"2"}},
                {"op":"create","id":id(20),"contract":JOIN,"fields":{"left":id(10),"right":id(11)}}
            ]})).unwrap();
        store.mutate(&request).unwrap();
        let original = Snapshot::load(&store).unwrap().records[&id(10)].clone();
        let child = Snapshot::load(&store).unwrap().records[&id(20)].clone();
        let mut corrupted = original.clone();
        corrupted.input = Input::Source { value: 3 };
        let replace = |record| {
            let write = store.begin_write().unwrap();
            {
                let mut table = write.open_table(KV).unwrap();
                let key = Key::Record(id(10));
                let bytes = native_codec::encode_for(&key, &StoredValue::<Ordered>::Record(record))
                    .unwrap();
                table
                    .insert(key.encode().as_slice(), bytes.as_slice())
                    .unwrap();
            }
            write.commit().unwrap();
        };
        replace(corrupted);
        assert_eq!(Snapshot::load(&store).err().unwrap().code, "corrupt_state");
        replace(original);
        assert_eq!(Snapshot::load(&store).unwrap().records[&id(20)], child);
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn projected_parent_work_limit_discards_the_staged_source() {
        let model = Prepared::<Ordered>::load().unwrap();
        let mut base = BTreeMap::new();
        for (id, value) in [(id(10), 1), (id(11), 2)] {
            let key = Key::Record(id);
            base.insert(
                key.encode(),
                native_codec::encode_for(
                    &key,
                    &StoredValue::<Ordered>::Record(record(Input::Source { value })),
                )
                .unwrap(),
            );
        }
        let unchanged = base.clone();
        let child = record(Input::Join {
            left: id(10),
            right: id(11),
        });
        let mut control =
            Attempt::<_, Ordered>::new(|key: &[u8]| Ok(base.get(key).cloned()), 10000);
        control
            .put(
                Key::Record(id(20)),
                Some(StoredValue::Record(child.clone())),
            )
            .unwrap();
        validate(&mut control, &model).unwrap();
        let needed = control.work.work_units;
        let mut limited =
            Attempt::<_, Ordered>::new(|key: &[u8]| Ok(base.get(key).cloned()), needed - 1);
        limited
            .put(Key::Record(id(20)), Some(StoredValue::Record(child)))
            .unwrap();
        assert_eq!(
            validate(&mut limited, &model).unwrap_err().code,
            "work_limit"
        );
        drop(limited);
        assert_eq!(base, unchanged);
    }
    #[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct Annotated {
        #[serde(flatten)]
        input: Input,
        body: String,
    }
    impl NativeInput for Annotated {
        fn contract(&self) -> u16 {
            self.input.contract()
        }
        fn validate(&self) -> Result<()> {
            self.input.validate()
        }
        fn bind(code: u16, mut fields: Value) -> Result<Self> {
            let body = fields
                .as_object_mut()
                .and_then(|fields| fields.remove("body"))
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or_else(|| Error::new("invalid_input", "missing body"))?;
            Ok(Self {
                input: Input::bind(code, fields)?,
                body,
            })
        }
        fn references(&self) -> Vec<(Uuid, u16, u16)> {
            self.input.references()
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct AnnotatedModel;
    impl Binding for AnnotatedModel {
        type Index = Standard;
        type Input = Annotated;
        type Derived = ();
        type Outcome = ();
        const NAME: &'static str = "relationship-unrelated-body";
        const BEHAVIOR: &'static str = "unrelated-parent-body-does-not-discover-1";
        fn engine() -> Result<Model> {
            Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
        }
        fn declarations() -> Result<Vec<Contract>> {
            let mut contracts = Ordered::declarations()?;
            for contract in &mut contracts {
                contract.fields.push(crate::model::InputField {
                    code: 99,
                    name: "body",
                    mutable: true,
                });
                contract.schema["properties"]["body"] = json!({"type":"string"});
                contract.schema["required"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("body"));
            }
            Ok(contracts)
        }
        fn valid_derived(_: &Annotated, value: Option<&()>) -> bool {
            value.is_none()
        }
        fn published_shape(_: u16) -> Value {
            Value::Null
        }
        fn settle_changes<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
            _: &mut Attempt<L, Self>,
            _: &Prepared<Self>,
            _: Context,
            _: &[ModelChange<Self>],
            _: &mut Population,
            _: Uuid,
            _: &mut dyn FnMut() -> Result<Uuid>,
        ) -> Result<()> {
            Ok(())
        }
        fn check(_: &Store<Self>) -> Result<Value> {
            Ok(Value::Null)
        }
    }
    #[test]
    fn unrelated_parent_body_edit_never_loads_incoming() {
        let model = Prepared::<AnnotatedModel>::load().unwrap();
        let original = ModelRecord::<AnnotatedModel> {
            contract: SOURCE,
            tenant: id(1),
            owner: id(2),
            reader: id(2),
            version: id(3),
            input: Annotated {
                input: Input::Source { value: 1 },
                body: "before".into(),
            },
            derived: None,
        };
        let source_key = Key::Record(id(10));
        let source_bytes = native_codec::encode_for(
            &source_key,
            &StoredValue::<AnnotatedModel>::Record(original.clone()),
        )
        .unwrap();
        let mut attempt = Attempt::<_, AnnotatedModel>::new(
            |key: &[u8]| {
                if key == Key::Incoming(id(10)).encode() {
                    return Err(Error::new(
                        "test_unexpected_read",
                        "unrelated incoming tree loaded",
                    ));
                }
                Ok((key == source_key.encode()).then(|| source_bytes.clone()))
            },
            10000,
        );
        let mut edited = original;
        edited.input.body = "after".into();
        attempt
            .put(source_key.clone(), Some(StoredValue::Record(edited)))
            .unwrap();
        validate(&mut attempt, &model).unwrap();
        assert_eq!(attempt.changed_records(), BTreeSet::from([id(10)]));
    }
}
