//! Shared resolved-shape causal settlement for compiled model bindings.
use crate::{
    binding::{Binding, NativeInput, headers},
    index::{IndexCode, NativeIndex, TimeKey},
    indexes::standard::FINANCIAL,
    model::{Contract, Prepared, PublicationSlot, Visibility},
    mutation::reconcile_member,
    native_codec::{Address, Key, Role, StoredValue},
    native_range::{NativeBound, NativeRange},
    native_slice::{Attempt, Context, Error, ModelChange, ModelRecord, Query, Result},
    routes::{self, Endpoint, Route},
    tree,
};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
#[derive(Clone, Debug)]
pub struct Read<K = TimeKey> {
    pub slot: u16,
    pub root: Address,
    pub range: NativeRange<K>,
    pub validate: bool,
}
#[derive(Clone, Copy, Debug)]
pub struct Emit<K = TimeKey> {
    pub role: u16,
    pub contract: u16,
    pub root: Address,
    pub at: K,
}

#[derive(Clone, Copy, Debug)]
pub struct PublicationRead {
    pub slot: PublicationSlot,
    pub parent: Uuid,
}

/// Values are projected only from ready parents, immediately before evaluation.
/// They remain native attempt-local values, without Clone or Serde requirements.
pub struct PublicationValue<V> {
    pub slot: PublicationSlot,
    pub value: V,
}
#[derive(Clone, Debug)]
pub struct ResolvedShape<K = TimeKey> {
    pub reads: Vec<Read<K>>,
    pub emits: Vec<Emit<K>>,
    pub publications: Vec<PublicationRead>,
}
impl<K> Default for ResolvedShape<K> {
    fn default() -> Self {
        Self {
            reads: vec![],
            emits: vec![],
            publications: vec![],
        }
    }
}
/// Attempt-local authored inputs alongside the declared ordered-read topology.
/// Parameters remain native model values; they are neither persisted nor used
/// to discover dependencies. References and direct reverse registrations must
/// explicitly cover the authored fields that the resolver consumes.
pub struct Resolved<P, K = TimeKey> {
    pub shape: ResolvedShape<K>,
    pub parameters: P,
}
pub trait ReactiveBinding: Binding {
    /// Owned parameters from this source and its declared direct authored fields.
    /// Published inputs are resolved as identities here and projected only after
    /// their parent calculation is ready. Undeclared reference chains are invalid.
    type Parameters;
    type Publication;
    /// All authored commands have been staged before resolution. Capture their
    /// final values here so evaluation needs no workspace or mutable parent copy.
    fn resolve<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Attempt<L, Self>,
        context: Context,
        id: Uuid,
        record: &ModelRecord<Self>,
    ) -> Result<Resolved<Self::Parameters, <Self::Index as NativeIndex>::Key>>;
    fn project_publication(
        _parent: &ModelRecord<Self>,
        _field_code: u16,
    ) -> Result<Self::Publication> {
        Err(Error::new(
            "model",
            "unsupported native publication projection",
        ))
    }
    fn evaluate(
        id: Uuid,
        record: &ModelRecord<Self>,
        shape: &ResolvedShape<<Self::Index as NativeIndex>::Key>,
        parameters: &Self::Parameters,
        publications: &[PublicationValue<Self::Publication>],
        values: &[<Self::Index as NativeIndex>::QueryResult],
    ) -> Result<(Self::Derived, BTreeMap<u16, i128>)>;
    fn output_input(
        _producer: Uuid,
        _emit: &Emit<<Self::Index as NativeIndex>::Key>,
        _amount: i128,
    ) -> Result<Self::Input> {
        Err(Error::new(
            "model",
            "binding has no managed financial outputs",
        ))
    }
    fn output_member(
        _input: &Self::Input,
    ) -> Result<(Address, i64, <Self::Index as NativeIndex>::Leaf)> {
        Err(Error::new(
            "model",
            "binding has no managed financial outputs",
        ))
    }
}
/// Check the authored topology before reserving identities or changing membership.
fn validate_shape<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    context: Context,
    record: &ModelRecord<B>,
    shape: &ResolvedShape<<B::Index as NativeIndex>::Key>,
) -> Result<()> {
    let contract = model.contract(record.contract)?;
    let references = record.input.references();
    let mut publication_slots = BTreeSet::new();
    for read in &shape.publications {
        ws.charge("dependency", 1)?;
        if read.slot.0 == 0 || !publication_slots.insert(read.slot) {
            return Err(Error::new(
                "model",
                "duplicate or zero resolved publication slot",
            ));
        }
        let declaration = contract
            .publication_inputs
            .iter()
            .find(|input| input.slot == read.slot)
            .ok_or_else(|| Error::new("model", "undeclared resolved publication input"))?;
        let reference = contract
            .references
            .iter()
            .find(|reference| reference.slot == declaration.reference_slot)
            .ok_or_else(|| Error::new("model", "publication reference declaration"))?;
        let mut matching = references
            .iter()
            .filter(|(_, _, slot)| *slot == reference.slot);
        if matching.next().is_none_or(|(id, _, _)| *id != read.parent) || matching.next().is_some()
        {
            return Err(Error::new(
                "model",
                "resolved publication uses a different authored reference",
            ));
        }
        let parent = ws
            .record(read.parent)?
            .ok_or_else(|| Error::new("unavailable_reference", "publication parent unavailable"))?;
        if parent.tenant != context.tenant || !reference.targets.contains(&parent.contract) {
            return Err(Error::new(
                "unavailable_reference",
                "publication parent type or tenant",
            ));
        }
        let target = model.contract(parent.contract)?;
        if !target.published.iter().any(|field| {
            field.code == declaration.field_code && field.binding == declaration.binding
        }) {
            return Err(Error::new(
                "model",
                "resolved publication field or binding mismatch",
            ));
        }
    }
    if publication_slots.len() != contract.publication_inputs.len() {
        return Err(Error::new("model", "missing resolved publication input"));
    }
    let mut slots = BTreeSet::new();
    for read in &shape.reads {
        if read.slot == 0 || !slots.insert(read.slot) {
            return Err(Error::new("model", "duplicate or zero resolved query slot"));
        }
        let query = contract
            .queries
            .iter()
            .find(|q| q.slot == read.slot)
            .ok_or_else(|| Error::new("model", "undeclared resolved query"))?;
        let root = model
            .contract(query.root_contract)?
            .roots
            .iter()
            .find(|root| root.slot == query.root_slot)
            .ok_or_else(|| Error::new("model", "missing query root declaration"))?;
        if !B::Index::causal_query(query.operation)
            || !B::Index::supports_query(root.kind, query.operation, query.phase, query.channel)
            || query.phase
                != if read.validate {
                    "validate"
                } else {
                    "calculate"
                }
            || query.root_slot != read.root.slot
        {
            return Err(Error::new(
                "model",
                "resolved query disagrees with declaration",
            ));
        }
        let reference = contract
            .references
            .iter()
            .find(|r| r.field == query.through)
            .ok_or_else(|| Error::new("model", "query reference declaration"))?;
        if !references
            .iter()
            .any(|(id, _, slot)| *slot == reference.slot && *id == read.root.id)
        {
            return Err(Error::new(
                "model",
                "resolved query uses a different authored reference",
            ));
        }
        for bound in [&read.range.lower, &read.range.upper] {
            if let NativeBound::Included(key) | NativeBound::Excluded(key) = bound {
                B::Index::validate_key(root.kind, key)?;
            }
        }
        validate_root(
            ws,
            model,
            context,
            read.root,
            query.root_contract,
            root.kind,
        )?;
    }
    let mut roles = BTreeSet::new();
    for emit in &shape.emits {
        if emit.role == 0 || !roles.insert(emit.role) {
            return Err(Error::new(
                "model",
                "duplicate or zero resolved output role",
            ));
        }
        let role = contract
            .outputs
            .iter()
            .find(|o| o.role == emit.role)
            .ok_or_else(|| Error::new("model", "undeclared resolved output role"))?;
        let output = model.contract(emit.contract)?;
        if role.contract != emit.contract || output.visibility != Visibility::Engine {
            return Err(Error::new("model", "resolved output contract mismatch"));
        }
        member_slot(model, emit.contract)?;
        let member = &output.memberships[0];
        if member.root_slot != emit.root.slot || member.kind != FINANCIAL {
            return Err(Error::new("model", "resolved output membership mismatch"));
        }
        B::Index::validate_key(member.kind, &emit.at)?;
        validate_root(
            ws,
            model,
            context,
            emit.root,
            member.root_contract,
            FINANCIAL,
        )?;
    }
    Ok(())
}
fn validate_root<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    context: Context,
    address: Address,
    code: u16,
    kind: IndexCode,
) -> Result<()> {
    if !model
        .contract(code)?
        .roots
        .iter()
        .any(|r| r.slot == address.slot && r.kind == kind)
    {
        return Err(Error::new(
            "model",
            "resolved root kind differs from its declaration",
        ));
    }
    if ws
        .record(address.id)?
        .is_none_or(|r| r.tenant != context.tenant || r.contract != code)
    {
        return Err(Error::new(
            "unavailable_reference",
            "resolved root target unavailable",
        ));
    }
    match ws.get(&Key::Root(address))? {
        Some(StoredValue::Root(root)) if root.kind == kind => Ok(()),
        _ => Err(Error::new("corrupt_state", "resolved native root missing")),
    }
}
struct Plan<B: ReactiveBinding> {
    record: Option<ModelRecord<B>>,
    old_record: Option<ModelRecord<B>>,
    shape: ResolvedShape<<B::Index as NativeIndex>::Key>,
    parameters: Option<B::Parameters>,
    old_outputs: BTreeMap<u16, (Uuid, ModelRecord<B>)>,
    bindings: BTreeMap<u16, Uuid>,
}
// Standard quote readers retain their established settlement path. Native
// family consumers and explicit publication consumers share this scheduler.
fn uses_scheduler<B: Binding>(model: &Prepared<B>, contract: &Contract) -> bool {
    contract.uses_causal_scheduler::<B::Index>() || model.has_publication_dependents(contract.code)
}
fn subscriptions<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    id: Uuid,
    old: Option<&ModelRecord<B>>,
    shape: &ResolvedShape<<B::Index as NativeIndex>::Key>,
) -> Result<()> {
    let mut before = BTreeMap::new();
    if let Some(old) = old {
        for query in &model.contract(old.contract)?.queries {
            if let Some(value) = ws.get(&Key::Query(Address::new(id, query.slot)))? {
                let StoredValue::Query(q) = value else {
                    return Err(Error::new("corrupt_state", "old query type"));
                };
                before.insert(
                    (Key::Subscribers(q.source), Address::new(id, query.slot)),
                    q.range,
                );
            }
        }
    }
    let after: BTreeMap<_, _> = shape
        .reads
        .iter()
        .map(|r| {
            (
                (Key::Subscribers(r.root), Address::new(id, r.slot)),
                r.range.clone(),
            )
        })
        .collect();
    for ((key, member), range) in &before {
        if after.get(&(key.clone(), *member)) != Some(range) {
            routes::change(ws, key, *member, range.clone(), false)?;
        }
    }
    for ((key, member), range) in &after {
        if before.get(&(key.clone(), *member)) != Some(range) {
            routes::change(ws, key, *member, range.clone(), true)?;
        }
    }
    Ok(())
}
fn impact<K: Ord>(roots: &mut BTreeMap<Address, BTreeSet<K>>, root: Address, at: K) {
    roots.entry(root).or_default().insert(at);
}
fn write_output<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    id: Uuid,
    old: Option<&ModelRecord<B>>,
    new: Option<ModelRecord<B>>,
    revision: Uuid,
) -> Result<()> {
    if old.is_none() && new.is_none() {
        return Ok(());
    }
    if old.is_none() {
        let r = new.as_ref().unwrap();
        for (k, v) in headers(model, id, &r.input, revision)? {
            if ws.get(&k)?.is_some() {
                return Err(Error::new("corrupt_state", "orphan output header"));
            }
            ws.put(k, Some(v))?;
        }
    }
    crate::mutation::reconcile_incoming(
        ws,
        id,
        old.map(|r| &r.input),
        new.as_ref().map(|r| &r.input),
    )?;
    if new.is_none() {
        if routes::header(ws, Route::Incoming(id), false)?.is_some_and(|h| !h.is_empty()) {
            return Err(Error::new(
                "unavailable_reference",
                "surviving reference to private output",
            ));
        }
        ws.put(Key::Incoming(id), None)?;
    }
    ws.put(Key::Record(id), new.map(StoredValue::Record))
}
fn read_query<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    contract: &Contract,
    id: Uuid,
    r: &Read<<B::Index as NativeIndex>::Key>,
) -> Result<<B::Index as NativeIndex>::QueryResult> {
    let declaration = contract
        .queries
        .iter()
        .find(|query| query.slot == r.slot)
        .ok_or_else(|| Error::new("model", "missing validated query declaration"))?;
    let kind = model
        .contract(declaration.root_contract)?
        .roots
        .iter()
        .find(|root| root.slot == declaration.root_slot)
        .ok_or_else(|| Error::new("model", "missing validated query root"))?
        .kind;
    // Prefix sums need no non-invertible summary fold. Preserve their narrow
    // balanced search path; general windows retain the ordered range fold.
    let descriptor = B::Index::descriptor(kind)?;
    let result = match (declaration.operation, &r.range.lower, &r.range.upper) {
        ("sum", NativeBound::Unbounded, NativeBound::Excluded(key))
            if descriptor.financial && descriptor.time =>
        {
            let at = B::Index::time(kind, key)?;
            B::Index::financial_query_result(tree::prefix(ws, r.root, Some(at))?)?
        }
        ("sum", NativeBound::Unbounded, NativeBound::Unbounded)
            if descriptor.financial && descriptor.time =>
        {
            B::Index::financial_query_result(tree::prefix(ws, r.root, None)?)?
        }
        ("latest", NativeBound::Unbounded, NativeBound::Included(key)) => {
            B::Index::selection_result(kind, tree::last_key_at_or_before(ws, r.root, key)?)?
        }
        _ => B::Index::query_result(
            kind,
            declaration.operation,
            &tree::range_keys(ws, r.root, &r.range.key_range())?,
        )?,
    };
    ws.put(
        Key::Query(Address::new(id, r.slot)),
        Some(StoredValue::Query(Query {
            source: r.root,
            operation: declaration.operation.into(),
            phase: declaration.phase.into(),
            channel: declaration.channel.into(),
            range: r.range.clone(),
            selected: None,
            result: result.clone(),
        })),
    )?;
    Ok(result)
}
pub fn settle<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: ReactiveBinding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    context: Context,
    changes: &[ModelChange<B>],
    revision: Uuid,
    allocate: &mut dyn FnMut() -> Result<Uuid>,
) -> Result<()> {
    let mut pending = BTreeSet::new();
    let mut roots = ws.causal_impacts();
    let mut discovered_publications = BTreeSet::new();
    let previous: BTreeMap<_, _> = changes.iter().map(|c| (c.id, &c.old)).collect();
    for c in changes {
        // A true no-op must not detach and reinsert otherwise unchanged AVL
        // memberships. Other changed sources can still discover this producer
        // through Direct routes or root impacts below.
        if c.old == c.new {
            continue;
        }
        if c.old.as_ref().into_iter().chain(c.new.as_ref()).any(|r| {
            model
                .contract(r.contract)
                .is_ok_and(|contract| uses_scheduler(model, contract))
        }) {
            pending.insert(c.id);
        }
        if c.old.as_ref().map(|r| &r.input) != c.new.as_ref().map(|r| &r.input) {
            routes::collect(ws, &Key::Direct(c.id), &mut pending)?;
            if c.old
                .iter()
                .chain(c.new.iter())
                .any(|record| model.has_publication_dependents(record.contract))
            {
                discovered_publications.insert(c.id);
            }
        }
    }
    let mut visited_prefix: BTreeMap<Address, <B::Index as NativeIndex>::Key> = BTreeMap::new();
    let mut prefix_impacts: BTreeMap<Address, BTreeSet<<B::Index as NativeIndex>::Key>> =
        BTreeMap::new();
    let mut visited_points = BTreeSet::new();
    let mut plans: BTreeMap<Uuid, Plan<B>> = BTreeMap::new();
    loop {
        while let Some((root, mut points)) = roots.pop_first() {
            ws.charge("dependency", points.len() as u64)?;
            let mut prefix_only = true;
            for original in [true, false] {
                prefix_only &= routes::header(ws, Route::Subscribers(root), original)?
                    .is_none_or(|header| header.bounded == 0);
            }
            if prefix_only {
                // Save the points as well as their minimum: later shape repair
                // can introduce the first bounded reader in the staged index.
                prefix_impacts
                    .entry(root)
                    .or_default()
                    .extend(points.iter().cloned());
                let Some(at) = points.first().cloned() else {
                    continue;
                };
                if visited_prefix
                    .get(&root)
                    .is_some_and(|previous| previous <= &at)
                {
                    continue;
                }
                // Reopen only the newly exposed suffix band. Through(at) sorts
                // after Time(at), so equal-time inclusive readers are selected.
                let upper = visited_prefix
                    .insert(root, at.clone())
                    .map_or(std::ops::Bound::Unbounded, |previous| {
                        std::ops::Bound::Included(Endpoint::Before(previous))
                    });
                for original in [true, false] {
                    pending.extend(
                        routes::select(
                            ws,
                            &Key::Subscribers(root),
                            std::ops::Bound::Excluded(Endpoint::Before(at.clone())),
                            upper.clone(),
                            original,
                        )?
                        .into_iter()
                        .map(|address| address.id),
                    );
                }
            } else {
                if let Some(previous) = prefix_impacts.remove(&root) {
                    points.extend(previous);
                }
                for at in points {
                    if !visited_points.insert((root, at.clone())) {
                        continue;
                    }
                    for original in [true, false] {
                        pending.extend(
                            routes::stab(ws, &Key::Subscribers(root), &at, original)?
                                .into_iter()
                                .map(|address| address.id),
                        );
                    }
                }
            }
        }
        let Some(id) = pending.pop_first() else { break };
        if plans.contains_key(&id) {
            continue;
        }
        let record = ws.record(id)?;
        if record.is_none()
            && !previous.contains_key(&id)
            && matches!(ws.original(&Key::Record(id))?, Some(StoredValue::Record(_)))
        {
            // Original subscriber scans can rediscover a producer deleted by
            // an earlier settlement in this Attempt. Its staged teardown is
            // already complete. A source absent in both images is still corrupt.
            continue;
        }
        // The caller may settle multiple command chunks in one Attempt. Source
        // inputs precede this call in ModelChange; managed outputs and query
        // caches still hold the preceding settlement until evaluation below.
        let old_record = previous
            .get(&id)
            .map_or_else(|| record.clone(), |old| (*old).clone());
        let producer = record
            .as_ref()
            .or(old_record.as_ref())
            .ok_or_else(|| Error::new("corrupt_state", "missing subscriber"))?;
        if !uses_scheduler(model, model.contract(producer.contract)?) {
            continue;
        }
        if model.has_publication_dependents(producer.contract) && discovered_publications.insert(id)
        {
            // Discover the complete affected closure before comparing values or
            // building the final graph. The route collector visits both images.
            routes::collect(ws, &Key::Direct(id), &mut pending)?;
        }
        let (shape, parameters) = match &record {
            Some(r) => {
                let resolved = B::resolve(ws, context, id, r)?;
                validate_shape(ws, model, context, r, &resolved.shape)?;
                (resolved.shape, Some(resolved.parameters))
            }
            None => (ResolvedShape::default(), None),
        };
        subscriptions(ws, model, id, old_record.as_ref(), &shape)?;
        let mut plan = Plan {
            record,
            old_record,
            shape,
            parameters,
            old_outputs: BTreeMap::new(),
            bindings: BTreeMap::new(),
        };
        let mut roles = BTreeSet::new();
        for r in plan.record.iter().chain(plan.old_record.iter()) {
            roles.extend(model.contract(r.contract)?.outputs.iter().map(|o| o.role));
        }
        for role in roles {
            let a = Address::new(id, role);
            if let Some(v) = ws.get(&Key::Role(a))? {
                let StoredValue::Role(b) = v else {
                    return Err(Error::new("corrupt_state", "role type"));
                };
                if b.retired || ws.get(&Key::Reserved(b.output))? != Some(StoredValue::Reserved(a))
                {
                    return Err(Error::new("corrupt_state", "role reservation"));
                }
                plan.bindings.insert(role, b.output);
                if let Some(output) = ws.record(b.output)? {
                    if output.input.managed() != Some((id, role)) {
                        return Err(Error::new("corrupt_state", "role output owner"));
                    }
                    let (root, at, _) = B::output_member(&output.input)?;
                    impact(&mut roots, root, B::Index::time_key(FINANCIAL, at)?);
                    plan.old_outputs.insert(role, (b.output, output));
                }
            }
        }
        for e in &plan.shape.emits {
            impact(&mut roots, e.root, e.at.clone());
        }
        plans.insert(id, plan);
    }
    ws.work.causal_candidates = plans.len() as u64;
    let order = crate::dependency::order(
        ws,
        plans
            .iter()
            .filter(|(_, p)| p.record.is_some())
            .map(|(id, p)| (*id, &p.shape)),
    )?;
    let role_slots: BTreeSet<_> = model
        .contracts()
        .flat_map(|c| c.outputs.iter().map(|o| o.role))
        .collect();
    for (producer, p) in &mut plans {
        for e in &p.shape.emits {
            if p.bindings.contains_key(&e.role) {
                continue;
            }
            let mut chosen = None;
            for _ in 0..8 {
                ws.charge("allocate", 1)?;
                let id = allocate()?;
                let mut collision = ws.get(&Key::Record(id))?.is_some()
                    || ws.original(&Key::Record(id))?.is_some()
                    || ws.get(&Key::Reserved(id))?.is_some()
                    || ws.original(&Key::Reserved(id))?.is_some();
                for slot in &role_slots {
                    collision |= ws.get(&Key::Role(Address::new(id, *slot)))?.is_some()
                        || ws.original(&Key::Role(Address::new(id, *slot)))?.is_some();
                }
                if !collision {
                    chosen = Some(id);
                    break;
                }
            }
            let id = chosen.ok_or_else(|| {
                Error::new("allocation_collision", "output allocation retry limit")
            })?;
            let a = Address::new(*producer, e.role);
            ws.put(
                Key::Role(a),
                Some(StoredValue::Role(Role {
                    output: id,
                    retired: false,
                    first_created_at: None,
                })),
            )?;
            ws.put(Key::Reserved(id), Some(StoredValue::Reserved(a)))?;
            p.bindings.insert(e.role, id);
        }
    }
    for (producer, p) in &plans {
        for (role, (id, old)) in &p.old_outputs {
            let slot = member_slot(model, old.contract)?;
            reconcile_member(
                ws,
                Address::new(*id, slot),
                Some(B::output_member(&old.input).and_then(|(root, at, leaf)| {
                    Ok((root, B::Index::time_key(FINANCIAL, at)?, leaf))
                })?),
                None,
            )?;
            ws.work.detached_outputs += 1;
            if !p.shape.emits.iter().any(|e| e.role == *role) {
                write_output(ws, model, *id, Some(old), None, revision)?;
            }
        }
        let mut slots = BTreeSet::new();
        for r in p.record.iter().chain(p.old_record.iter()) {
            slots.extend(model.contract(r.contract)?.queries.iter().map(|q| q.slot));
        }
        for slot in slots {
            if !p.shape.reads.iter().any(|r| r.slot == slot) {
                ws.put(Key::Query(Address::new(*producer, slot)), None)?;
            }
        }
        if p.record.is_none() {
            for (role, output) in &p.bindings {
                let key = Key::Role(Address::new(*producer, *role));
                let Some(StoredValue::Role(mut binding)) = ws.get(&key)? else {
                    return Err(Error::new("corrupt_state", "missing retiring role"));
                };
                if binding.output != *output {
                    return Err(Error::new("corrupt_state", "retiring role output mismatch"));
                }
                binding.retired = true;
                ws.put(key, Some(StoredValue::Role(binding)))?;
            }
        }
    }
    let track_publication_readiness = plans
        .values()
        .any(|plan| !plan.shape.publications.is_empty());
    let mut completed = BTreeSet::new();
    for id in order {
        let p = &plans[&id];
        let mut r = p.record.clone().unwrap();
        // Terminal-only readers register and resolve like other subscribers,
        // but have no formula or derived value. Declaration-level calculation
        // semantics survive temporarily inactive reads and output shapes.
        let contract = model.contract(r.contract)?;
        if contract.outputs.is_empty()
            && contract.calculations.is_empty()
            && contract.published.is_empty()
            && contract.publication_inputs.is_empty()
            && !contract
                .queries
                .iter()
                .any(|query| query.phase == "calculate")
        {
            if track_publication_readiness {
                completed.insert(id);
            }
            continue;
        }
        let mut publications = Vec::with_capacity(p.shape.publications.len());
        for read in &p.shape.publications {
            ws.charge("dependency", 1)?;
            if plans.contains_key(&read.parent) && !completed.contains(&read.parent) {
                return Err(Error::new("internal", "publication parent is not ready"));
            }
            let declaration = contract
                .publication_inputs
                .iter()
                .find(|input| input.slot == read.slot)
                .ok_or_else(|| {
                    Error::new("internal", "missing validated publication declaration")
                })?;
            // Plan.record predates evaluation and may retain the old derived
            // value. Always fetch the completed parent's current workspace row.
            let parent = ws.record(read.parent)?.ok_or_else(|| {
                Error::new("unavailable_reference", "ready publication parent missing")
            })?;
            if parent.derived.is_none() || !B::valid_derived(&parent.input, parent.derived.as_ref())
            {
                return Err(Error::new(
                    "corrupt_state",
                    "ready publication parent has invalid derived value",
                ));
            }
            ws.charge("dependency", 1)?;
            publications.push(PublicationValue {
                slot: read.slot,
                value: B::project_publication(&parent, declaration.field_code)?,
            });
        }
        let mut values = vec![];
        for read in p.shape.reads.iter().filter(|r| !r.validate) {
            values.push(read_query(ws, model, contract, id, read)?);
        }
        let parameters = p
            .parameters
            .as_ref()
            .ok_or_else(|| Error::new("internal", "missing resolved parameters"))?;
        let (derived, amounts) = B::evaluate(id, &r, &p.shape, parameters, &publications, &values)?;
        r.derived = Some(derived);
        ws.work.causal_evaluations += 1;
        ws.put(Key::Record(id), Some(StoredValue::Record(r.clone())))?;
        for e in &p.shape.emits {
            let output = p.bindings[&e.role];
            let amount = *amounts
                .get(&e.role)
                .ok_or_else(|| Error::new("internal", "missing output amount"))?;
            let input = B::output_input(id, e, amount)?;
            input.validate()?;
            let fields = serde_json::to_value(&input)
                .map_err(|error| Error::new("model", error.to_string()))?;
            let (root, at, leaf) = B::output_member(&input)?;
            if input.contract() != e.contract
                || model.validate(e.contract, &fields)? != input
                || input.managed() != Some((id, e.role))
                || root != e.root
                || B::Index::time_key(FINANCIAL, at)? != e.at
                || B::Index::financial_leaf(FINANCIAL, &leaf)? != amount
            {
                return Err(Error::new(
                    "model",
                    "managed output disagrees with resolved topology or value",
                ));
            }
            for (target, _, slot) in input.references() {
                let declaration = model
                    .contract(e.contract)?
                    .references
                    .iter()
                    .find(|r| r.slot == slot)
                    .ok_or_else(|| Error::new("model", "undeclared output reference"))?;
                if ws.record(target)?.is_none_or(|r| {
                    r.tenant != context.tenant || !declaration.targets.contains(&r.contract)
                }) {
                    return Err(Error::new(
                        "unavailable_reference",
                        "output reference unavailable",
                    ));
                }
            }
            // The role permanently reserves this UUID. Its first materialization
            // time survives intervals where the output record does not exist.
            let role_key = Key::Role(Address::new(id, e.role));
            let Some(StoredValue::Role(mut binding)) = ws.get(&role_key)? else {
                return Err(Error::new("corrupt_state", "missing output role"));
            };
            if binding.output != output || binding.retired {
                return Err(Error::new("corrupt_state", "output role identity mismatch"));
            }
            let created_at = match binding.first_created_at {
                Some(at) => {
                    if p.old_outputs
                        .get(&e.role)
                        .is_some_and(|(_, old)| old.created_at != at)
                    {
                        return Err(Error::new(
                            "corrupt_state",
                            "output creation provenance mismatch",
                        ));
                    }
                    at
                }
                None => {
                    if p.old_outputs.contains_key(&e.role) {
                        return Err(Error::new(
                            "corrupt_state",
                            "live output lacks creation provenance",
                        ));
                    }
                    let at = crate::mutation::creation_time()?;
                    binding.first_created_at = Some(at);
                    ws.put(role_key, Some(StoredValue::Role(binding)))?;
                    at
                }
            };
            let new = ModelRecord {
                contract: e.contract,
                tenant: context.tenant,
                owner: r.owner,
                created_at,
                version: revision,
                input,
                derived: None,
            };
            write_output(
                ws,
                model,
                output,
                p.old_outputs.get(&e.role).map(|(_, r)| r),
                Some(new.clone()),
                revision,
            )?;
            reconcile_member(
                ws,
                Address::new(output, member_slot(model, e.contract)?),
                None,
                Some(B::output_member(&new.input).and_then(|(root, at, leaf)| {
                    Ok((root, B::Index::time_key(FINANCIAL, at)?, leaf))
                })?),
            )?;
        }
        if track_publication_readiness {
            completed.insert(id);
        }
    }
    for (id, p) in &plans {
        let Some(record) = &p.record else { continue };
        let contract = model.contract(record.contract)?;
        for r in p.shape.reads.iter().filter(|r| r.validate) {
            B::Index::validate_terminal(&read_query(ws, model, contract, *id, r)?)?;
        }
    }
    Ok(())
}
fn member_slot<B: Binding>(model: &Prepared<B>, contract: u16) -> Result<u16> {
    let members = &model.contract(contract)?.memberships;
    if members.len() != 1 {
        return Err(Error::new(
            "model",
            "managed output requires one membership",
        ));
    }
    Ok(members[0].slot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{binding::Calculation, native_slice::Input};

    mod ownership_composition {
        use super::*;
        use crate::{
            index::TimeKey,
            indexes::standard::Leaf,
            models::equipment::{Equipment, Input as EquipmentInput},
            native_codec,
            native_slice::{Command, Meta, Settled},
        };
        use serde_json::json;
        type Bytes = BTreeMap<Vec<u8>, Vec<u8>>;

        fn id(value: u128) -> Uuid {
            Uuid::from_u128(value)
        }

        // Native transaction composition control; local integration tests own
        // the principal graph and both-owner action authorization witnesses.
        fn stage<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
            ws: &mut Attempt<L, Equipment>,
            model: &Prepared<Equipment>,
            commands: &[Command],
            allocate: &mut dyn FnMut() -> Result<Uuid>,
        ) -> Result<Settled> {
            crate::mutation::settle_authorized(
                ws,
                model,
                Context {
                    tenant: id(1),
                    actor: id(2),
                },
                commands,
                allocate,
                false,
                &mut |_, _, _, _| Ok(()),
                &mut |_, _| Ok(()),
            )
        }

        fn create(record: u128, contract: u16, fields: serde_json::Value) -> Command {
            Command::Create {
                id: id(record),
                contract,
                owner: None,
                fields,
            }
        }

        fn reservation(record: u128, starts: i64) -> Command {
            create(
                record,
                410,
                json!({
                    "pool":id(100),"starts":starts.to_string(),"ends":(starts+5).to_string(),
                    "requested":"3","active":true,
                }),
            )
        }

        fn update<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
            ws: &mut Attempt<L, Equipment>,
            record: u128,
            owner: Option<Uuid>,
            set: serde_json::Value,
        ) -> Command {
            Command::Update {
                id: id(record),
                if_version: ws.record(id(record)).unwrap().unwrap().version,
                owner,
                set: set.as_object().unwrap().clone().into_iter().collect(),
                unset: vec![],
            }
        }

        fn seed(reservations: &[(u128, i64)]) -> (Prepared<Equipment>, Bytes) {
            let model = Prepared::<Equipment>::load().unwrap();
            let mut bytes = BTreeMap::from([(
                Key::Meta.encode(),
                native_codec::encode_for::<Equipment>(
                    &Key::Meta,
                    &StoredValue::Meta(Meta {
                        model: model.identity().into(),
                        codec: native_codec::CODEC.into(),
                        tenant: id(1),
                        actor: id(2),
                    }),
                )
                .unwrap(),
            )]);
            let mut commands = vec![];
            for pool in [100, 101] {
                commands.push(create(pool, 101, json!({"unit":1})));
                commands.push(create(
                    pool + 100,
                    205,
                    json!({
                        "pool":id(pool),"at":"0","quantity":"10",
                    }),
                ));
            }
            commands.extend(
                reservations
                    .iter()
                    .map(|(record, at)| reservation(*record, *at)),
            );
            let mut ws =
                Attempt::<_, Equipment>::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 200_000);
            let mut allocated = 900;
            stage(&mut ws, &model, &commands, &mut || {
                let output = id(allocated);
                allocated += 1;
                Ok(output)
            })
            .unwrap();
            let batch = ws.finish().unwrap();
            drop(ws);
            for (key, value) in batch {
                if let Some(value) = value {
                    bytes.insert(key, value);
                } else {
                    bytes.remove(&key);
                }
            }
            (model, bytes)
        }

        fn no_allocation() -> Result<Uuid> {
            Err(Error::new(
                "unexpected_allocation",
                "existing roles must retain output identities",
            ))
        }

        fn check_output_facts<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
            ws: &mut Attempt<L, Equipment>,
            pool: u128,
            owner: u128,
        ) {
            let producer = ws.record(id(300)).unwrap().unwrap();
            assert_eq!(producer.owner, id(owner));
            // Two source-authored dates and quantity determine exact outputs;
            // expected amounts do not come from query or writer caches.
            for (role, output, at, quantity) in [(11, 900, 10, -3), (29, 901, 15, 3)] {
                let role_id = Address::new(id(300), role);
                let row = ws.record(id(output)).unwrap().unwrap();
                assert_eq!(
                    ws.get(&Key::Role(role_id)).unwrap(),
                    Some(StoredValue::Role(Role {
                        output: id(output),
                        retired: false,
                        first_created_at: Some(row.created_at),
                    }))
                );
                assert_eq!(
                    ws.get(&Key::Reserved(id(output))).unwrap(),
                    Some(StoredValue::Reserved(role_id))
                );
                assert_eq!(row.owner, id(owner));
                assert_eq!(row.version, producer.version);
                assert_eq!(
                    row.input,
                    EquipmentInput::Output {
                        producer: id(300),
                        role,
                        pool: id(pool),
                        at,
                        quantity,
                    }
                );
                let node = tree::node(ws, Address::new(id(pool), 7), Address::new(id(output), 23))
                    .unwrap();
                assert_eq!(node.key.value, TimeKey::new(at));
                assert_eq!(node.leaf, Leaf::Financial(quantity));
            }
            for root in [100, 101] {
                let members = routes::select(
                    ws,
                    &Key::Incoming(id(root)),
                    std::ops::Bound::Unbounded,
                    std::ops::Bound::Unbounded,
                    false,
                )
                .unwrap();
                let mut expected = BTreeSet::from([Address::new(id(root + 100), 1)]);
                if root == pool {
                    expected.extend([
                        Address::new(id(300), 1),
                        Address::new(id(900), 2),
                        Address::new(id(901), 2),
                    ]);
                }
                assert_eq!(members.into_iter().collect::<BTreeSet<_>>(), expected);
            }
        }

        #[test]
        fn create_then_owner_transfer_in_one_attempt_keeps_output_identities() {
            let (model, bytes) = seed(&[]);
            let mut ws =
                Attempt::<_, Equipment>::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 200_000);
            let mut allocated = 900;
            stage(&mut ws, &model, &[reservation(300, 10)], &mut || {
                let output = id(allocated);
                allocated += 1;
                Ok(output)
            })
            .unwrap();
            assert_eq!(allocated, 902);
            let command = update(&mut ws, 300, Some(id(3)), json!({}));
            stage(&mut ws, &model, &[command], &mut no_allocation).unwrap();
            check_output_facts(&mut ws, 100, 3);
        }

        #[test]
        fn retarget_then_owner_transfer_in_one_attempt_uses_staged_output_routes() {
            let (model, bytes) = seed(&[(300, 10)]);
            let mut ws =
                Attempt::<_, Equipment>::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 200_000);
            let retarget = update(&mut ws, 300, None, json!({"pool":id(101)}));
            stage(&mut ws, &model, &[retarget], &mut no_allocation).unwrap();
            let transfer = update(&mut ws, 300, Some(id(3)), json!({}));
            stage(&mut ws, &model, &[transfer], &mut no_allocation).unwrap();
            check_output_facts(&mut ws, 101, 3);
        }

        #[test]
        fn delete_then_owner_transfer_in_one_attempt_ignores_retired_subscribers() {
            let (model, bytes) = seed(&[(300, 10), (301, 30)]);
            let mut ws =
                Attempt::<_, Equipment>::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 200_000);
            let delete = Command::Delete {
                id: id(301),
                if_version: ws.record(id(301)).unwrap().unwrap().version,
            };
            stage(&mut ws, &model, &[delete], &mut no_allocation).unwrap();
            let transfer = update(&mut ws, 300, Some(id(3)), json!({}));
            stage(&mut ws, &model, &[transfer], &mut no_allocation).unwrap();
            check_output_facts(&mut ws, 100, 3);
            assert!(ws.record(id(301)).unwrap().is_none());
            for (role, output) in [(11, 902), (29, 903)] {
                let address = Address::new(id(301), role);
                let Some(StoredValue::Role(original)) = ws.original(&Key::Role(address)).unwrap()
                else {
                    panic!("original role");
                };
                assert!(original.first_created_at.is_some());
                assert_eq!(
                    ws.get(&Key::Role(address)).unwrap(),
                    Some(StoredValue::Role(Role {
                        output: id(output),
                        retired: true,
                        first_created_at: original.first_created_at,
                    }))
                );
                assert_eq!(
                    ws.get(&Key::Reserved(id(output))).unwrap(),
                    Some(StoredValue::Reserved(address))
                );
                assert!(ws.record(id(output)).unwrap().is_none());
            }
        }

        #[test]
        fn managed_uuid_creation_time_survives_inactive_reactivation_and_transfer() {
            for committed_inactive in [true, false] {
                let (model, mut bytes) = seed(&[(300, 10)]);
                let first: BTreeMap<_, _> = [900, 901]
                    .into_iter()
                    .map(|output| {
                        let key = Key::Record(id(output));
                        let StoredValue::Record(record) =
                            native_codec::decode_for::<Equipment>(&key, &bytes[&key.encode()])
                                .unwrap()
                        else {
                            panic!("output record")
                        };
                        (output, record.created_at)
                    })
                    .collect();
                // A reactivation happens after the first materialization's millisecond.
                std::thread::sleep(std::time::Duration::from_millis(2));
                if committed_inactive {
                    let mut ws = Attempt::<_, Equipment>::new(
                        |key: &[u8]| Ok(bytes.get(key).cloned()),
                        200_000,
                    );
                    let inactive = update(&mut ws, 300, None, json!({"active":false}));
                    stage(&mut ws, &model, &[inactive], &mut no_allocation).unwrap();
                    for output in [900, 901] {
                        assert!(ws.record(id(output)).unwrap().is_none());
                    }
                    let batch = ws.finish().unwrap();
                    drop(ws);
                    for (key, value) in batch {
                        if let Some(value) = value {
                            bytes.insert(key, value);
                        } else {
                            bytes.remove(&key);
                        }
                    }
                }
                let mut ws =
                    Attempt::<_, Equipment>::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 200_000);
                if !committed_inactive {
                    let inactive = update(&mut ws, 300, None, json!({"active":false}));
                    stage(&mut ws, &model, &[inactive], &mut no_allocation).unwrap();
                }
                let active = update(&mut ws, 300, None, json!({"active":true}));
                stage(&mut ws, &model, &[active], &mut no_allocation).unwrap();
                let transfer = update(&mut ws, 300, Some(id(3)), json!({}));
                stage(&mut ws, &model, &[transfer], &mut no_allocation).unwrap();
                for output in [900, 901] {
                    let record = ws.record(id(output)).unwrap().unwrap();
                    assert_eq!(
                        record.created_at, first[&output],
                        "UUID lifetime timestamp changed; committed inactive={committed_inactive}"
                    );
                    assert_eq!(record.owner, id(3));
                }
            }
        }

        #[test]
        fn first_materialization_is_atomic_retained_and_matches_created_access_keys() {
            use crate::{
                access_index::Declaration,
                local::{Mutation, Store},
                storage::ReadableTable,
            };
            fn request(store: &Store<Equipment>, commands: Vec<Command>) -> Mutation {
                Mutation {
                    model: store.model().identity().into(),
                    context: store.operation_context(store.model().identity()).unwrap(),
                    operation_id: Uuid::new_v4(),
                    commands,
                    returning: vec![],
                }
            }
            fn native(store: &Store<Equipment>, key: Key) -> Option<StoredValue<Equipment>> {
                let read = store.begin_read().unwrap();
                let table = read.open_table(crate::local::KV).unwrap();
                table.get(key.encode()).unwrap().map(|bytes| {
                    native_codec::decode_for::<Equipment>(&key, bytes.value()).unwrap()
                })
            }
            fn set_active(store: &Store<Equipment>, active: bool) -> Mutation {
                let version = store
                    .get(store.model().identity(), id(300))
                    .unwrap()
                    .unwrap()
                    .version;
                request(
                    store,
                    vec![Command::Update {
                        id: id(300),
                        if_version: version,
                        owner: None,
                        set: [("active".into(), json!(active))].into(),
                        unset: vec![],
                    }],
                )
            }
            let directory =
                std::env::temp_dir().join(format!("managed-created-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&directory).unwrap();
            let mut declarations = Equipment::declarations().unwrap();
            declarations
                .iter_mut()
                .find(|c| c.code == 900)
                .unwrap()
                .access_indexes = vec![Declaration::created(9001)];
            let model = std::sync::Arc::new(Prepared::<Equipment>::prepare(declarations).unwrap());
            let store = Store::create(
                directory.join("store.redb"),
                model.clone(),
                Context {
                    tenant: id(1),
                    actor: id(2),
                },
            )
            .unwrap();
            let initial = request(
                &store,
                vec![
                    create(100, 101, json!({"unit":1})),
                    create(200, 205, json!({"pool":id(100),"at":"0","quantity":"10"})),
                    create(
                        300,
                        410,
                        json!({"pool":id(100),"starts":"10","ends":"15","requested":"3","active":false}),
                    ),
                ],
            );
            store.mutate_with_ids(&initial, &mut no_allocation).unwrap();
            for role in [11, 29] {
                assert!(native(&store, Key::Role(Address::new(id(300), role))).is_none());
            }
            assert!(native(&store, Key::AccessRoot(Address::new(id(2), 9001))).is_none());
            std::thread::sleep(std::time::Duration::from_millis(2));
            let activation_start = crate::mutation::creation_time().unwrap();
            let activate = set_active(&store, true);
            let before = store.observe_for_verification().unwrap();
            let mut next = 900;
            assert!(
                store
                    .mutate_inner(
                        &activate,
                        &mut || {
                            let output = id(next);
                            next += 1;
                            Ok(output)
                        },
                        Some(usize::MAX)
                    )
                    .is_err()
            );
            assert_eq!(
                store.observe_for_verification().unwrap(),
                before,
                "aborted first materialization retained state"
            );
            let mut next = 900;
            store
                .mutate_with_ids(&activate, &mut || {
                    let output = id(next);
                    next += 1;
                    Ok(output)
                })
                .unwrap();
            let mut first = BTreeMap::new();
            for (role, output) in [(11, 900), (29, 901)] {
                let Some(StoredValue::Role(binding)) =
                    native(&store, Key::Role(Address::new(id(300), role)))
                else {
                    panic!("role")
                };
                let at = binding.first_created_at.unwrap();
                assert!(at >= activation_start);
                first.insert(output, at);
                let Some(StoredValue::Record(record)) = native(&store, Key::Record(id(output)))
                else {
                    panic!("output")
                };
                assert_eq!(record.created_at, at);
            }
            for _ in 0..2 {
                store
                    .mutate_with_ids(&set_active(&store, false), &mut no_allocation)
                    .unwrap();
                for (role, output) in [(11, 900), (29, 901)] {
                    let Some(StoredValue::Role(binding)) =
                        native(&store, Key::Role(Address::new(id(300), role)))
                    else {
                        panic!("inactive role")
                    };
                    assert_eq!(binding.first_created_at, Some(first[&output]));
                    assert!(native(&store, Key::Record(id(output))).is_none());
                }
                let reactivate = set_active(&store, true);
                let before = store.observe_for_verification().unwrap();
                assert!(
                    store
                        .mutate_inner(&reactivate, &mut no_allocation, Some(usize::MAX))
                        .is_err()
                );
                assert_eq!(store.observe_for_verification().unwrap(), before);
                store
                    .mutate_with_ids(&reactivate, &mut no_allocation)
                    .unwrap();
                for output in [900, 901] {
                    let Some(StoredValue::Record(record)) = native(&store, Key::Record(id(output)))
                    else {
                        panic!("output")
                    };
                    assert_eq!(record.created_at, first[&output]);
                    let Some(StoredValue::AccessNode(node)) =
                        native(&store, Key::AccessNode(Address::new(id(output), 9001)))
                    else {
                        panic!("created index")
                    };
                    assert_eq!(
                        node.key.value,
                        crate::order_value::OrderKey(vec![crate::order_value::OrderAtom::Integer(
                            i128::from(first[&output])
                        )])
                    );
                }
                store.check_integrity().unwrap();
            }
            drop(store);
            let reopened = Store::<Equipment>::open(directory.join("store.redb"), model).unwrap();
            reopened.check_integrity().unwrap();
            for output in [900, 901] {
                let Some(StoredValue::Record(record)) = native(&reopened, Key::Record(id(output)))
                else {
                    panic!("reopened output")
                };
                assert_eq!(record.created_at, first[&output]);
            }
            drop(reopened);
            std::fs::remove_dir_all(directory).unwrap();
        }

        #[test]
        fn same_owner_updates_preserve_shuffled_output_tree_bytes() {
            let sources = [
                (308, 10),
                (301, 30),
                (306, 50),
                (300, 70),
                (307, 90),
                (302, 110),
                (305, 130),
                (303, 150),
                (304, 170),
            ];
            let (model, bytes) = seed(&sources);
            for (record, _) in sources {
                let mut ws =
                    Attempt::<_, Equipment>::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 200_000);
                let command = update(&mut ws, record, Some(id(2)), json!({}));
                stage(&mut ws, &model, &[command], &mut no_allocation).unwrap();
                assert!(
                    ws.finish().unwrap().is_empty(),
                    "same-owner no-op changed native bytes for {record}"
                );
                assert!(ws.record(id(record)).unwrap().is_some());
            }
        }
    }

    // Keep authored inputs separately from the native image: expected results
    // must never depend on writer-produced private outputs or query caches.
    #[test]
    fn selective_closure_matches_source_arithmetic_through_repeated_topology_edits() {
        use crate::{
            models::equipment::{Derived, Equipment, Input as EquipmentInput},
            native_codec,
            native_slice::{Command, Work},
        };
        use serde_json::json;
        type Bytes = BTreeMap<Vec<u8>, Vec<u8>>;

        fn expected(sources: &BTreeMap<Uuid, EquipmentInput>) -> (BTreeMap<Uuid, Derived>, bool) {
            let mut events: BTreeMap<Uuid, Vec<(i64, i128)>> = BTreeMap::new();
            let mut reservations = vec![];
            for (id, input) in sources {
                match input {
                    EquipmentInput::Delivery { pool, at, quantity } => {
                        events.entry(*pool).or_default().push((*at, *quantity));
                    }
                    EquipmentInput::Reservation { starts, .. } => reservations.push((*starts, *id)),
                    _ => {}
                }
            }
            reservations.sort();
            let mut derived = BTreeMap::new();
            for (_, id) in reservations {
                let EquipmentInput::Reservation {
                    pool,
                    starts,
                    ends,
                    requested,
                    active,
                } = sources[&id]
                else {
                    unreachable!()
                };
                let events = events.entry(pool).or_default();
                let before = if active {
                    events
                        .iter()
                        .filter(|(at, _)| *at < starts)
                        .map(|(_, amount)| amount)
                        .sum::<i128>()
                } else {
                    0
                };
                let allocated = if active {
                    requested.min(before.max(0))
                } else {
                    0
                };
                derived.insert(
                    id,
                    Derived {
                        available_before: before,
                        allocated,
                    },
                );
                if active {
                    events.extend([(starts, -allocated), (ends, allocated)]);
                }
            }
            let valid = events.values().all(|events| {
                let mut grouped = BTreeMap::<i64, i128>::new();
                for (at, amount) in events {
                    *grouped.entry(*at).or_default() += amount;
                }
                let mut balance = 0;
                grouped.values().all(|amount| {
                    balance += amount;
                    balance >= 0
                })
            });
            (derived, valid)
        }
        fn mutate(
            bytes: &mut Bytes,
            model: &Prepared<Equipment>,
            commands: Vec<Command>,
        ) -> Result<Work> {
            let mut ws =
                Attempt::<_, Equipment>::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 200_000);
            crate::mutation::settle_authorized(
                &mut ws,
                model,
                Context {
                    tenant: Uuid::from_u128(1),
                    actor: Uuid::from_u128(2),
                },
                &commands,
                &mut || Ok(Uuid::new_v4()),
                false,
                &mut |_, _, _, _| Ok(()),
                &mut |_, _| Ok(()),
            )?;
            let batch = ws.finish()?;
            let work = ws.work.clone();
            drop(ws);
            for (key, value) in batch {
                if let Some(value) = value {
                    bytes.insert(key, value);
                } else {
                    bytes.remove(&key);
                }
            }
            Ok(work)
        }
        fn check(bytes: &Bytes, sources: &BTreeMap<Uuid, EquipmentInput>) {
            let (expected, valid) = expected(sources);
            assert!(valid);
            let mut ws =
                Attempt::<_, Equipment>::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 200_000);
            let mut active = 0;
            for (id, input) in sources {
                let record = ws.record(*id).unwrap().unwrap();
                assert_eq!(&record.input, input);
                let Some(derived) = expected.get(id) else {
                    continue;
                };
                assert_eq!(record.derived.as_ref(), Some(derived));
                let EquipmentInput::Reservation {
                    pool,
                    starts,
                    ends,
                    active: enabled,
                    ..
                } = input
                else {
                    unreachable!()
                };
                let query = ws.get(&Key::Query(Address::new(*id, 31))).unwrap();
                if *enabled {
                    active += 1;
                    let Some(StoredValue::Query(query)) = query else {
                        panic!("active query missing")
                    };
                    assert_eq!(
                        (query.source, query.result),
                        (Address::new(*pool, 7), derived.available_before)
                    );
                    for (role, at, quantity) in [
                        (11, *starts, -derived.allocated),
                        (29, *ends, derived.allocated),
                    ] {
                        let Some(StoredValue::Role(binding)) =
                            ws.get(&Key::Role(Address::new(*id, role))).unwrap()
                        else {
                            panic!("role missing")
                        };
                        assert_eq!(
                            ws.record(binding.output).unwrap().unwrap().input,
                            EquipmentInput::Output {
                                producer: *id,
                                role,
                                pool: *pool,
                                at,
                                quantity
                            }
                        );
                    }
                } else {
                    assert_eq!(query, None);
                }
            }
            // Detect stale outputs after deactivation as well as missing ones.
            let outputs = bytes.iter().filter(|(key, value)| {
                let key = Key::decode(key).unwrap();
                matches!(native_codec::decode_for::<Equipment>(&key, value).unwrap(), StoredValue::Record(r) if r.contract == 900)
            }).count();
            assert_eq!(outputs, 2 * active);
        }

        let model = Prepared::<Equipment>::load().unwrap();
        let meta = crate::native_slice::Meta {
            model: model.identity().into(),
            codec: native_codec::CODEC.into(),
            tenant: Uuid::from_u128(1),
            actor: Uuid::from_u128(2),
        };
        let mut bytes = BTreeMap::from([(
            Key::Meta.encode(),
            native_codec::encode_for::<Equipment>(&Key::Meta, &StoredValue::Meta(meta)).unwrap(),
        )]);
        let mut sources = BTreeMap::new();
        for (id, pool) in [(100, 100), (101, 101)] {
            sources.insert(Uuid::from_u128(id), EquipmentInput::Pool { unit: 1 });
            sources.insert(
                Uuid::from_u128(id + 100),
                EquipmentInput::Delivery {
                    pool: Uuid::from_u128(pool),
                    at: 0,
                    quantity: if pool == 100 { 10 } else { 7 },
                },
            );
        }
        for i in 0..6 {
            sources.insert(
                Uuid::from_u128(300 + i),
                EquipmentInput::Reservation {
                    pool: Uuid::from_u128(100 + i % 2),
                    starts: (i as i64 + 1) * 10,
                    ends: (i as i64 + 1) * 10 + 5,
                    requested: 8,
                    active: true,
                },
            );
        }
        sources.insert(
            Uuid::from_u128(202),
            EquipmentInput::Delivery {
                pool: Uuid::from_u128(101),
                at: i64::MAX,
                quantity: 1,
            },
        );
        // Roots precede referencing sources; reservation UUIDs deliberately do
        // not change when their temporal order is changed below.
        let creates = sources
            .iter()
            .map(|(id, input)| Command::Create {
                owner: None,
                id: *id,
                contract: input.contract(),
                fields: serde_json::to_value(input).unwrap(),
            })
            .collect();
        mutate(&mut bytes, &model, creates).unwrap();
        check(&bytes, &sources);
        let mut random = 41u64;
        let mut commits = 0;
        let mut rejections = 0;
        for step in 0..160 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            let draw = random >> 32;
            let id = Uuid::from_u128(if step < 2 {
                202
            } else {
                300 + u128::from(draw % 6)
            });
            let mut proposed = sources.clone();
            let set = if step < 2 {
                let EquipmentInput::Delivery { at, quantity, .. } = proposed.get_mut(&id).unwrap()
                else {
                    unreachable!()
                };
                *quantity = 2;
                if step == 1 {
                    *at = 55;
                }
                json!({"at":at.to_string(), "quantity":quantity.to_string()})
            } else {
                let EquipmentInput::Reservation {
                    pool,
                    starts,
                    ends,
                    requested,
                    active,
                } = proposed.get_mut(&id).unwrap()
                else {
                    unreachable!()
                };
                *pool = Uuid::from_u128(100 + u128::from((draw >> 4) % 2));
                *starts = ((draw >> 7) % 15) as i64 * 5 + 5;
                *ends = *starts + ((draw >> 12) % 5) as i64 * 5 + 5;
                *requested = i128::from((draw >> 17) % 13);
                *active = !(draw >> 22).is_multiple_of(4);
                json!({"pool":pool, "starts":starts.to_string(), "ends":ends.to_string(), "requested":requested.to_string(), "active":active})
            };
            let mut ws =
                Attempt::<_, Equipment>::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 200_000);
            let version = ws.record(id).unwrap().unwrap().version;
            drop(ws);
            let before = bytes.clone();
            let result = mutate(
                &mut bytes,
                &model,
                vec![Command::Update {
                    owner: None,
                    id,
                    if_version: version,
                    set: set.as_object().unwrap().clone().into_iter().collect(),
                    unset: vec![],
                }],
            );
            if expected(&proposed).1 {
                let work = result.unwrap();
                if step < 2 {
                    assert_eq!(work.causal_candidates, step);
                }
                sources = proposed;
                commits += 1;
            } else {
                assert_eq!(result.unwrap_err().code, "invariant");
                assert_eq!(bytes, before);
                rejections += 1;
            }
            check(&bytes, &sources);
        }
        assert!(commits > 100 && rejections > 0);
    }

    #[test]
    fn resolved_query_cannot_substitute_an_unauthored_account() {
        let model = Prepared::<Calculation>::load().unwrap();
        let context = Context {
            tenant: Uuid::from_u128(1),
            actor: Uuid::from_u128(2),
        };
        let record = ModelRecord::<Calculation> {
            created_at: 0,
            contract: 10,
            tenant: context.tenant,
            owner: context.actor,

            version: Uuid::from_u128(1),
            input: Input::Basis {
                sources: vec![Uuid::from_u128(3)],
                factor: 1,
                account: Uuid::from_u128(4),
                at: 1,
                feedback: None,
            },
            derived: None,
        };
        let shape = ResolvedShape {
            reads: vec![Read {
                slot: 1,
                root: Address::new(Uuid::from_u128(99), 2),
                range: NativeRange::ALL,
                validate: false,
            }],
            emits: vec![],
            publications: vec![],
        };
        let mut ws = Attempt::new(|_| Ok(None), 10_000);
        let error = validate_shape(&mut ws, &model, context, &record, &shape).unwrap_err();
        assert_eq!(error.code, "model");
        assert!(error.detail.contains("different authored reference"));
    }
}
