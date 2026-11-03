//! Protected email/phone source identity. Proof and session issuance follow in A1/A2.
pub mod proof;
pub mod proof_crypto;
pub mod proof_types;
#[cfg(test)]
mod tests;
pub mod types;
use crate::{
    access::{Action, PrincipalKind, Scope},
    binding::Binding,
    integrity::{Snapshot, require},
    local::Store,
    model::Prepared,
    models::services::{IDENTITY, Services, System},
    native_codec::{Key, StoredValue},
    native_slice::{Attempt, Command, Context, Error, ModelChange, ModelRecord, Result},
    storage::WriteTransaction,
};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub(crate) fn recent(issued_at: Option<u64>, now: u64) -> bool {
    issued_at.is_some_and(|issued| now.checked_sub(issued).is_some_and(|age| age <= 600))
}
impl<B: Binding> Store<B> {
    /// Only authenticated ingress (or trusted native tests) supplies verified JWT time.
    pub(crate) fn authenticated_session(
        &self,
        actor: Uuid,
        epoch: u64,
        issued_at: u64,
        generation: Uuid,
    ) -> Result<Self> {
        if generation.is_nil() {
            return Err(crate::access::denied());
        }
        let mut session = self.session(actor, epoch)?;
        session.issued_at = Some(issued_at);
        session.session_generation = Some(generation);
        Ok(session)
    }
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn authorize_identity_command<B: Binding>(
    write: &WriteTransaction,
    scope: &Scope,
    secured: bool,
    issued_at: Option<u64>,
    command: &Command,
    old: Option<&ModelRecord<B>>,
    new: Option<&ModelRecord<B>>,
    users: &mut Option<BTreeSet<Uuid>>,
) -> Result<()> {
    let identity = matches!(command,Command::Create{contract,..} if *contract==IDENTITY && B::identity_enabled())
        || old
            .into_iter()
            .chain(new)
            .any(|r| B::identity_input(&r.input).is_some());
    if !identity {
        return Ok(());
    }
    if !secured {
        return Err(crate::access::denied());
    }
    let (action, owner) = match command {
        Command::Create { owner, .. } => (Action::Create, owner.unwrap_or(scope.actor)),
        Command::Update { owner, .. } => {
            let prior = old.or(new).ok_or_else(crate::access::denied)?;
            if !scope.grants.allows(IDENTITY, Action::Update)
                || !(scope.actor == prior.owner || scope.descendants.contains(&prior.owner))
            {
                return Err(crate::access::denied());
            }
            if owner.is_some_and(|owner| owner != prior.owner) {
                return Err(Error::new("invalid_input", "identity owner is immutable"));
            }
            (Action::Update, prior.owner)
        }
        Command::Delete { .. } => (Action::Delete, old.ok_or_else(crate::access::denied)?.owner),
    };
    if !scope.active
        || !scope.grants.allows(IDENTITY, action)
        || !(owner == scope.actor || scope.descendants.contains(&owner))
        || owner == scope.actor && !recent(issued_at, crate::identity::now()?)
    {
        return Err(crate::access::denied());
    }
    if users.is_none() {
        let graph = crate::security::write_graph(write)?;
        if graph.graph.tenant != scope.tenant {
            return Err(crate::access::denied());
        }
        *users = Some(
            graph
                .graph
                .principals
                .iter()
                .filter(|p| p.kind == PrincipalKind::User)
                .map(|p| p.id)
                .collect(),
        );
    }
    if !users
        .as_ref()
        .expect("loaded principal kinds")
        .contains(&owner)
    {
        return Err(Error::new(
            "invalid_input",
            "identity requires a same-tenant User owner",
        ));
    }
    Ok(())
}

pub(crate) fn settle_identities<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Attempt<L, Services>,
    _model: &Prepared<Services>,
    _context: Context,
    changes: &[ModelChange<Services>],
    _revision: Uuid,
) -> Result<()> {
    let mut selected = Vec::new();
    let mut affected = BTreeSet::new();
    let mut previous_revisions = BTreeMap::<Uuid, u64>::new();
    for change in changes {
        let current = ws.record(change.id)?;
        if !change
            .old
            .as_ref()
            .into_iter()
            .chain(current.as_ref())
            .any(|record| Services::identity_input(&record.input).is_some())
        {
            continue;
        }
        if change
            .old
            .as_ref()
            .into_iter()
            .chain(current.as_ref())
            .any(|record| record.contract != IDENTITY)
        {
            return Err(Error::new(
                "invalid_input",
                "identity source contract is immutable",
            ));
        }
        let old = change
            .old
            .as_ref()
            .map(Services::identity_values)
            .transpose()?;
        if let (Some(record), Some((_, state))) = (&change.old, old) {
            previous_revisions
                .entry(record.owner)
                .and_modify(|revision| *revision = (*revision).max(state.identity_revision))
                .or_insert(state.identity_revision);
        }
        if change.old.as_ref().map(|r| &r.input) != current.as_ref().map(|r| &r.input)
            && let Some(record) = change.old.as_ref().or(current.as_ref())
        {
            affected.insert(record.owner);
        }
        if let Some(mut current) = current {
            let input = Services::identity_input(&current.input)
                .ok_or_else(|| crate::local::corrupt("identity source role"))?;
            let state = if let Some((previous, state)) = old {
                if change
                    .old
                    .as_ref()
                    .is_some_and(|old| old.owner != current.owner)
                    || previous.kind != input.kind
                {
                    return Err(Error::new(
                        "invalid_input",
                        "identity kind and owner are immutable",
                    ));
                }
                if previous == input {
                    state.clone()
                } else {
                    types::State {
                        identity_revision: state
                            .identity_revision
                            .checked_add(1)
                            .ok_or_else(|| Error::new("revision_exhausted", "identity revision"))?,
                        verified_revision: None,
                        verified_at: None,
                        ..state.clone()
                    }
                }
            } else {
                types::State::new(Uuid::new_v4())?
            };
            state.validate()?;
            current.derived = Some(System::Identity(state));
            ws.put(Key::Record(change.id), Some(StoredValue::Record(current)))?;
        }
        selected.push(change);
    }
    for (owner, minimum) in previous_revisions {
        if !matches!(ws.get(&Key::AuthenticationRevision(owner))?,
            Some(StoredValue::AuthenticationRevision(state)) if state.revision >= minimum)
        {
            return Err(crate::local::corrupt(
                "identity authentication revision missing or regressed",
            ));
        }
    }
    // Reconcile from this settlement call's entry graph, including prior chunks
    // in the same Attempt. Release every old claim before acquiring final claims.
    for change in &selected {
        if let Some(record) = &change.old {
            let (input, state) = Services::identity_values(record)?;
            let key = Key::IdentityClaim(input.kind, input.value.clone());
            let expected = types::Claim {
                identity: change.id,
                incarnation: state.incarnation,
            };
            if ws.get(&key)? != Some(StoredValue::IdentityClaim(expected)) {
                return Err(crate::local::corrupt("identity prior exact claim"));
            }
            ws.put(key, None)?;
        }
    }
    for change in selected {
        let Some(record) = ws.record(change.id)? else {
            continue;
        };
        let (input, state) = Services::identity_values(&record)?;
        let key = Key::IdentityClaim(input.kind, input.value.clone());
        let claim = types::Claim {
            identity: change.id,
            incarnation: state.incarnation,
        };
        match ws.get(&key)? {
            None => {}
            Some(StoredValue::IdentityClaim(existing)) if existing == claim => {}
            Some(StoredValue::IdentityClaim(_)) => {
                return Err(Error::new(
                    "identity_duplicate",
                    "identity is already claimed",
                ));
            }
            _ => return Err(crate::local::corrupt("identity exact claim role")),
        }
        ws.put(key, Some(StoredValue::IdentityClaim(claim)))?;
    }
    for owner in affected {
        let key = Key::AuthenticationRevision(owner);
        let previous = match ws.get(&key)? {
            Some(StoredValue::AuthenticationRevision(state)) => state.revision,
            None => 0,
            _ => {
                return Err(crate::local::corrupt(
                    "principal authentication revision role",
                ));
            }
        };
        let revision = previous
            .checked_add(1)
            .ok_or_else(|| Error::new("revision_exhausted", "principal authentication revision"))?;
        ws.put(
            key,
            Some(StoredValue::AuthenticationRevision(
                types::AuthenticationRevision { revision },
            )),
        )?;
    }
    Ok(())
}

/// Reconstruct exact dictionary from current source facts. Authentication revision
/// is retained proof history, not a derived identity count or a writer cache.
pub(crate) fn check(snapshot: &Snapshot<'_, Services>, expected: &mut BTreeSet<Key>) -> Result<()> {
    let graph = crate::security::read_graph(&snapshot.read)?;
    let users = graph
        .graph
        .principals
        .iter()
        .filter(|p| p.kind == PrincipalKind::User)
        .map(|p| p.id)
        .collect::<BTreeSet<_>>();
    let mut claims = BTreeMap::new();
    for (&id, record) in &snapshot.records {
        let Some(input) = Services::identity_input(&record.input) else {
            continue;
        };
        require(
            users.contains(&record.owner),
            "identity owner is not a User",
        )?;
        let (_, state) = Services::identity_values(record)?;
        state.validate()?;
        let key = Key::IdentityClaim(input.kind, input.value.clone());
        require(
            claims
                .insert(
                    key.clone(),
                    types::Claim {
                        identity: id,
                        incarnation: state.incarnation,
                    },
                )
                .is_none(),
            "duplicate identity source claim",
        )?;
        require(
            matches!(snapshot.all.get(&Key::AuthenticationRevision(record.owner)),Some(StoredValue::AuthenticationRevision(revision)) if revision.revision>=state.identity_revision),
            "identity authentication revision missing or regressed",
        )?;
        expected.insert(key);
    }
    for (key, claim) in claims {
        require(
            snapshot.all.get(&key) == Some(&StoredValue::IdentityClaim(claim)),
            "identity exact dictionary differs from source facts",
        )?;
    }
    for (key, value) in &snapshot.all {
        if let Key::AuthenticationRevision(owner) = key {
            require(
                users.contains(owner)
                    && matches!(value,StoredValue::AuthenticationRevision(revision) if revision.validate().is_ok()),
                "orphan authentication revision",
            )?;
            expected.insert(key.clone());
        }
    }
    Ok(())
}
