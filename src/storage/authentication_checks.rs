//! A0 authority, exact-claim and rollback controls on the actual selected adapter.
//! Original transactions overlap only on optimistic adapters. redb controls are
//! explicitly sequential; no conflict or commit is manufactured by a wrapper.
use super::{
    Database, ReadableTable,
    coordination_checks::{Captures, Recording, capture, label, operation, trace_value},
    credential_checks,
};
use crate::{
    access::{Action, Graph},
    authentication::types::Kind,
    binding::Binding,
    local::{self, Mutation, Store},
    model::Prepared,
    models::services::{IDENTITY, Services},
    native_codec::{self, Key, StoredValue},
    native_slice::{Context, Error, ModelRecord, Result},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn failure(detail: &str) -> Error {
    Error::new("identity_conformance", detail)
}
fn require(ok: bool, detail: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(failure(detail)) }
}
fn graph() -> Result<Graph> {
    let mut graph = credential_checks::graph()?;
    for principal in &mut graph.principals {
        principal.grants.contracts.insert(
            IDENTITY,
            [Action::Read, Action::Create, Action::Update, Action::Delete].into(),
        );
    }
    Ok(graph)
}
fn setup(db: Database) -> Result<(Store<Services>, Captures)> {
    let captures = Captures::default();
    let store = Store::create_backend_secured(
        Database::new(Recording {
            db,
            captures: captures.clone(),
        }),
        Arc::new(Prepared::load()?),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )?;
    credential_checks::replace(&store, graph()?)?;
    Ok((store, captures))
}
fn caller(store: &Store<Services>, actor: u128) -> Result<Store<Services>> {
    store.authenticated_session(id(actor), 0, crate::identity::now()?)
}
fn create(source: u128, owner: u128, kind: Kind, value: &str) -> Value {
    json!({"op":"create","id":id(source),"contract":IDENTITY,"owner":id(owner),"fields":{"kind":kind,"value":value}})
}
fn record(store: &Store<Services>, source: u128) -> Result<ModelRecord<Services>> {
    credential_checks::record(store, id(source))
}
fn update(store: &Store<Services>, source: u128, value: &str) -> Result<Value> {
    Ok(
        json!({"op":"update","id":id(source),"if_version":record(store,source)?.version,"set":{"value":value},"unset":[]}),
    )
}
fn mutation(store: &Store<Services>, commands: Value) -> Result<Mutation> {
    serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity())?,"operation_id":Uuid::new_v4(),"commands":commands,"returning":[]})).map_err(local::storage)
}
fn image(store: &Store<Services>) -> Result<Value> {
    let image = store.observe_for_verification()?;
    require(image["complete"] == true, "incomplete identity observation")?;
    Ok(image)
}
fn receipt(store: &Store<Services>, operation: Uuid, present: bool) -> Result<()> {
    let read = store.db.begin_read()?;
    require(
        read.open_table(local::RECEIPTS)?
            .get(store.receipt_key(operation))?
            .is_some()
            == present,
        "original identity receipt presence differs",
    )
}
fn source(
    store: &Store<Services>,
    source: u128,
    owner: u128,
    value: &str,
    revision: u64,
) -> Result<()> {
    let record = record(store, source)?;
    let (input, state) = Services::identity_values(&record)?;
    require(
        record.owner == id(owner)
            && input.value == value
            && state.identity_revision == revision
            && state.verified_revision.is_none()
            && state.verified_at.is_none(),
        "identity differs from literal lifecycle oracle",
    )
}
fn authentication_revision(store: &Store<Services>, owner: u128, expected: u64) -> Result<()> {
    let read = store.db.begin_read()?;
    let key = Key::AuthenticationRevision(id(owner));
    let bytes = read
        .open_table(local::KV)?
        .get(key.encode())?
        .ok_or_else(|| failure("missing authentication revision"))?;
    require(
        matches!(native_codec::decode_for::<Services>(&key,bytes.value())?,StoredValue::AuthenticationRevision(state) if state.revision==expected),
        "principal authentication revision differs from transition count",
    )
}
/// Expected dictionary keys and values come from source records. Key bytes are
/// constructed directly from the declared tag/kind/UTF-8 layout, not writer keys.
fn inventory(store: &Store<Services>) -> Result<()> {
    let read = store.db.begin_read()?;
    let table = read.open_table(local::KV)?;
    let mut expected = BTreeMap::new();
    let mut actual = BTreeMap::new();
    for row in table.iter()? {
        let (bytes, value) = row?;
        let key = Key::decode(bytes.value())?;
        match native_codec::decode_for::<Services>(&key, value.value())? {
            StoredValue::Record(record) if record.contract == IDENTITY => {
                let Key::Record(source) = key else {
                    return Err(failure("source key role"));
                };
                let (input, state) = Services::identity_values(&record)?;
                let mut key = vec![
                    18,
                    match input.kind {
                        Kind::Email => 1,
                        Kind::Phone => 2,
                    },
                ];
                key.extend_from_slice(input.value.as_bytes());
                require(
                    expected
                        .insert(
                            key,
                            json!({"identity":source,"incarnation":state.incarnation}),
                        )
                        .is_none(),
                    "duplicate source identity claims",
                )?;
            }
            StoredValue::IdentityClaim(claim) => {
                actual.insert(
                    bytes.value().to_vec(),
                    serde_json::to_value(claim).map_err(local::storage)?,
                );
            }
            _ => {}
        }
    }
    require(
        actual == expected,
        "exact identity dictionary differs from source facts",
    )?;
    store.check_integrity()?;
    Ok(())
}
fn traces(captures: &Captures) -> Result<Value> {
    let traces = capture(captures)?.traces.clone();
    for trace in &traces {
        require(
            trace
                .reads
                .iter()
                .chain(&trace.writes)
                .all(|(table, key)| table != local::KV.name() || key.first() != Some(&13)),
            "population key accessed by identity write",
        )?;
        require(
            !trace
                .writes
                .contains(&(local::KV.name().into(), Key::Meta.encode()))
                && !trace
                    .writes
                    .contains(&(local::RUNTIME.name().into(), local::HEADER.to_vec())),
            "identity write changed global native or operation identity guard",
        )?;
    }
    Ok(json!(traces.iter().map(trace_value).collect::<Vec<_>>()))
}
fn reopened(
    factory: &impl Fn(&str) -> Result<Database>,
    family: &str,
    accepted: &Value,
) -> Result<()> {
    let store = Store::<Services>::open_backend(factory(family)?, Arc::new(Prepared::load()?))?;
    require(
        image(&store)? == *accepted,
        "identity reopen changed winner",
    )?;
    inventory(&store)
}

pub fn run(factory: impl Fn(&str) -> Result<Database>, concurrent: bool) -> Result<Value> {
    let mut reports = vec![];
    for (kind, first_value, canonical) in [
        (Kind::Email, " Shared@EXAMPLE.COM ", "shared@example.com"),
        (Kind::Phone, " +12345678 ", "+12345678"),
    ] {
        let family = format!("a0-duplicate-{}", kind.tag());
        let (store, captures) = setup(factory(&family)?)?;
        let left = caller(&store, 3)?;
        let right = caller(&store, 4)?;
        let mut first = mutation(&left, json!([create(100, 3, kind, first_value)]))?;
        let mut second = mutation(&right, json!([create(200, 4, kind, canonical)]))?;
        first.operation_id = operation(&left, 10001, None)?;
        second.operation_id =
            operation(&right, 20001, Some(&left.receipt_key(first.operation_id)))?;
        capture(&captures)?.traces.clear();
        label(&captures, "original-duplicate-first")?;
        let mut barriers = 0;
        let mut winner = Value::Null;
        if concurrent {
            let result = left.mutate_controlled(
                &first,
                &mut || Ok(Uuid::new_v4()),
                None,
                &mut || {
                    barriers += 1;
                    label(&captures, "original-duplicate-second-winner")?;
                    right.mutate(&second)?;
                    winner = image(&store)?;
                    Ok(())
                },
                false,
            );
            require(
                result.is_err_and(|e| e.code == "transaction_conflict"),
                "duplicate absence read did not conflict",
            )?;
            require(image(&store)? == winner, "duplicate loser changed winner")?;
        } else {
            right.mutate(&second)?;
            winner = image(&store)?;
            require(
                left.mutate(&first)
                    .is_err_and(|e| e.code == "identity_duplicate"),
                "sequential duplicate claim was accepted",
            )?;
            require(
                image(&store)? == winner,
                "sequential duplicate rejection changed winner",
            )?;
        }
        require(
            barriers == usize::from(concurrent),
            "duplicate barrier count",
        )?;
        receipt(&left, first.operation_id, false)?;
        receipt(&right, second.operation_id, true)?;
        source(&store, 200, 4, canonical, 1)?;
        authentication_revision(&store, 4, 1)?;
        inventory(&store)?;
        let attempts = capture(&captures)?.traces.clone();
        let key = Key::IdentityClaim(kind, canonical.into()).encode();
        require(
            attempts.len() == 2
                && attempts.iter().all(|trace| {
                    trace
                        .reads
                        .contains(&(local::KV.name().into(), key.clone()))
                }),
            "duplicate witness did not protect the shared absent claim",
        )?;
        reports.push(json!({"case":family,"concurrent":concurrent,"original_loser_receipt_absent":true,"attempts":traces(&captures)?}));
        let accepted = image(&store)?;
        drop((left, right, store));
        reopened(&factory, &family, &accepted)?;
    }
    independent(&factory, concurrent, &mut reports)?;
    release_absence(&factory, concurrent, &mut reports)?;
    authority_controls(&factory, concurrent, &mut reports)?;
    swaps_and_faults(&factory, &mut reports)?;
    Ok(
        json!({"status":"passed","case_count":reports.len(),"concurrent_original_transactions":concurrent,"cases":reports,
        "limits":["Selected real adapter; redb duplicate and authority controls are sequential.","No automatic retry of conflicting or uncertain identity mutations.","Expected exact dictionary derives from source records; original operation and principal revisions are checked explicitly."]}),
    )
}

fn independent(
    factory: &impl Fn(&str) -> Result<Database>,
    concurrent: bool,
    reports: &mut Vec<Value>,
) -> Result<()> {
    let family = "a0-independent-owner-claims";
    let (store, captures) = setup(factory(family)?)?;
    let left = caller(&store, 3)?;
    let right = caller(&store, 4)?;
    let mut first = mutation(
        &left,
        json!([create(100, 3, Kind::Email, "LEFT@example.com")]),
    )?;
    let mut second = mutation(
        &right,
        json!([create(200, 4, Kind::Email, "right@example.com")]),
    )?;
    first.operation_id = operation(&left, 10001, None)?;
    second.operation_id = operation(&right, 20001, Some(&left.receipt_key(first.operation_id)))?;
    capture(&captures)?.traces.clear();
    label(&captures, "independent-owner-first")?;
    let mut barriers = 0;
    if concurrent {
        left.mutate_controlled(
            &first,
            &mut || Ok(Uuid::new_v4()),
            None,
            &mut || {
                barriers += 1;
                label(&captures, "independent-owner-second")?;
                right.mutate(&second)?;
                Ok(())
            },
            false,
        )?;
    } else {
        left.mutate(&first)?;
        label(&captures, "independent-owner-second-sequential")?;
        right.mutate(&second)?;
    }
    let attempts = capture(&captures)?.traces.clone();
    require(
        barriers == usize::from(concurrent)
            && attempts.len() == 2
            && attempts.iter().all(|t| t.outcome == "committed"),
        "independent claims did not both commit exactly once",
    )?;
    require(
        attempts[0].writes.is_disjoint(&attempts[1].writes)
            && attempts[0].reads.is_disjoint(&attempts[1].writes)
            && attempts[1].reads.is_disjoint(&attempts[0].writes),
        "independent owner claims share write or protected point dependencies",
    )?;
    require(
        attempts.iter().all(|t| t.scanned_tables.is_empty()),
        "independent identity write used a table range guard",
    )?;
    receipt(&left, first.operation_id, true)?;
    receipt(&right, second.operation_id, true)?;
    source(&store, 100, 3, "left@example.com", 1)?;
    source(&store, 200, 4, "right@example.com", 1)?;
    authentication_revision(&store, 3, 1)?;
    authentication_revision(&store, 4, 1)?;
    inventory(&store)?;
    reports.push(json!({"case":family,"concurrent":concurrent,"shared_application_writes":[],"shared_point_dependencies":[],"scans":[],"attempts":traces(&captures)?}));
    let accepted = image(&store)?;
    drop((left, right, store));
    reopened(factory, family, &accepted)
}

fn authority_controls(
    factory: &impl Fn(&str) -> Result<Database>,
    concurrent: bool,
    reports: &mut Vec<Value>,
) -> Result<()> {
    for (kind, name) in [
        (0, "epoch"),
        (1, "update-action"),
        (2, "inactive"),
        (3, "owner-descent"),
    ] {
        let family = format!("a0-identity-edit-authority-{name}");
        let (store, captures) = setup(factory(&family)?)?;
        // Actor3 manages descendant7; this intentionally requires no self iat.
        let manager = store.session(id(3), 0)?;
        manager.mutate(&mutation(
            &manager,
            json!([create(100, 7, Kind::Email, "before@example.com")]),
        )?)?;
        let first = mutation(&manager, json!([update(&store, 100, "after@example.com")?]))?;
        let mut changed = graph()?;
        let actor = changed
            .principals
            .iter_mut()
            .find(|p| p.id == id(if kind == 3 { 7 } else { 3 }))
            .ok_or_else(|| failure("fixture principal"))?;
        match kind {
            0 => actor.credential_epoch += 1,
            1 => {
                actor
                    .grants
                    .contracts
                    .get_mut(&IDENTITY)
                    .ok_or_else(|| failure("identity action grant"))?
                    .remove(&Action::Update);
            }
            2 => actor.active = false,
            _ => actor.parents = vec![id(4)],
        }
        capture(&captures)?.traces.clear();
        label(&captures, "original-identity-edit")?;
        let mut winner = Value::Null;
        let mut barriers = 0;
        if concurrent {
            let result = manager.mutate_controlled(
                &first,
                &mut || Ok(Uuid::new_v4()),
                None,
                &mut || {
                    barriers += 1;
                    label(&captures, "current-authority-winner")?;
                    credential_checks::replace(&store, changed.clone())?;
                    winner = image(&store)?;
                    Ok(())
                },
                false,
            );
            require(
                result.is_err_and(|e| e.code == "transaction_conflict"),
                "identity edit did not conflict with current authority",
            )?;
        } else {
            credential_checks::replace(&store, changed)?;
            winner = image(&store)?;
        }
        require(
            image(&store)? == winner && barriers == usize::from(concurrent),
            "identity edit changed authority winner",
        )?;
        require(
            manager.mutate(&first).is_err_and(|e| e.code == "forbidden"),
            "revoked original identity edit was accepted",
        )?;
        require(image(&store)? == winner, "revoked retry changed state")?;
        receipt(&manager, first.operation_id, false)?;
        source(&store, 100, 7, "before@example.com", 1)?;
        authentication_revision(&store, 7, 1)?;
        inventory(&store)?;
        reports.push(json!({"case":family,"concurrent":concurrent,"original_loser_receipt_absent":true,"attempts":traces(&captures)?}));
        let accepted = image(&store)?;
        drop((manager, store));
        reopened(factory, &family, &accepted)?;
    }
    Ok(())
}

fn release_absence(
    factory: &impl Fn(&str) -> Result<Database>,
    concurrent: bool,
    reports: &mut Vec<Value>,
) -> Result<()> {
    let family = "a0-claim-absence-acquire-release";
    let (store, captures) = setup(factory(family)?)?;
    let left = caller(&store, 3)?;
    let right = caller(&store, 4)?;
    let first = mutation(
        &left,
        json!([create(100, 3, Kind::Email, "reuse@example.com")]),
    )?;
    let acquire = mutation(
        &right,
        json!([create(200, 4, Kind::Email, "reuse@example.com")]),
    )?;
    capture(&captures)?.traces.clear();
    label(&captures, "original-protected-absence")?;
    let mut winner = Value::Null;
    let mut competitor = || {
        label(&captures, "competing-acquire")?;
        right.mutate(&acquire)?;
        let release = mutation(
            &right,
            json!([{"op":"delete","id":id(200),"if_version":record(&store,200)?.version}]),
        )?;
        label(&captures, "competing-release")?;
        right.mutate(&release)?;
        winner = image(&store)?;
        Ok(())
    };
    if concurrent {
        require(
            left.mutate_controlled(
                &first,
                &mut || Ok(Uuid::new_v4()),
                None,
                &mut competitor,
                false,
            )
            .is_err_and(|e| e.code == "transaction_conflict"),
            "acquire/release did not invalidate original absence",
        )?;
        require(
            image(&store)? == winner,
            "absence loser changed released winner",
        )?;
    } else {
        competitor()?;
        label(&captures, "sequential-reacquire")?;
        left.mutate(&first)?;
    }
    receipt(&left, first.operation_id, !concurrent)?;
    authentication_revision(&store, 4, 2)?;
    if !concurrent {
        source(&store, 100, 3, "reuse@example.com", 1)?;
        authentication_revision(&store, 3, 1)?;
    }
    inventory(&store)?;
    reports.push(json!({"case":family,"concurrent":concurrent,"original_absence_conflict":concurrent,"deleted_last_identity":true,"attempts":traces(&captures)?}));
    let accepted = image(&store)?;
    drop((left, right, store));
    reopened(factory, family, &accepted)
}

fn swaps_and_faults(
    factory: &impl Fn(&str) -> Result<Database>,
    reports: &mut Vec<Value>,
) -> Result<()> {
    for reverse in [false, true] {
        let family = format!("a0-final-claim-swap-{}", u8::from(reverse));
        let (store, captures) = setup(factory(&family)?)?;
        let owner = caller(&store, 3)?;
        owner.mutate(&mutation(
            &owner,
            json!([
                create(100, 3, Kind::Email, "one@example.com"),
                create(101, 3, Kind::Email, "two@example.com"),
                create(102, 3, Kind::Email, "three@example.com")
            ]),
        )?)?;
        let original = record(&store, 100)?;
        let mut commands = vec![
            update(&store, 100, "TWO@example.com")?,
            update(&store, 101, "ONE@example.com")?,
        ];
        if reverse {
            commands.reverse();
        }
        capture(&captures)?.traces.clear();
        label(&captures, "atomic-final-graph-swap")?;
        owner.mutate(&mutation(&owner, json!(commands))?)?;
        source(&store, 100, 3, "two@example.com", 2)?;
        source(&store, 101, 3, "one@example.com", 2)?;
        source(&store, 102, 3, "three@example.com", 1)?;
        let after = record(&store, 100)?;
        require(
            after.created_at == original.created_at
                && Services::identity_values(&after)?.1.incarnation
                    == Services::identity_values(&original)?.1.incarnation,
            "swap changed identity lifetime",
        )?;
        authentication_revision(&store, 3, 2)?;
        inventory(&store)?;
        reports.push(json!({"case":family,"one_atomic_final_graph":true,"source_values":["two@example.com","one@example.com","three@example.com"],"principal_authentication_revision":2,"attempts":traces(&captures)?}));
        let accepted = image(&store)?;
        drop((owner, store));
        reopened(factory, &family, &accepted)?;
    }
    let family = "a0-native-write-rollback-and-original-receipt";
    let (store, captures) = setup(factory(family)?)?;
    let owner = caller(&store, 3)?;
    let request = mutation(
        &owner,
        json!([
            create(100, 3, Kind::Email, "recover@example.com"),
            create(101, 3, Kind::Phone, "+12345678")
        ]),
    )?;
    let before = image(&store)?;
    capture(&captures)?.traces.clear();
    label(&captures, "after-native-index-and-receipt-publication")?;
    require(
        owner
            .mutate_controlled(
                &request,
                &mut || Ok(Uuid::new_v4()),
                None,
                &mut || {
                    Err(Error::new(
                        "injected_abort",
                        "before actual identity commit",
                    ))
                },
                false,
            )
            .is_err_and(|e| e.code == "injected_abort"),
        "identity final write abort not reached",
    )?;
    require(
        image(&store)? == before,
        "identity final publication escaped rollback",
    )?;
    let publication = capture(&captures)?.traces.clone();
    require(publication.len() == 1, "identity publication attempt count")?;
    let native_writes = publication[0]
        .writes
        .iter()
        .filter(|(table, _)| table == local::KV.name())
        .count();
    require(native_writes > 0, "identity native write set is empty")?;
    let write_set = traces(&captures)?;
    for after in (1..=native_writes).chain([usize::MAX]) {
        require(
            owner
                .mutate_controlled(
                    &request,
                    &mut || Ok(Uuid::new_v4()),
                    Some(after),
                    &mut || Ok(()),
                    false,
                )
                .is_err_and(|e| e.code == "injected_abort"),
            "identity injection did not reach a native write or receipt",
        )?;
        require(
            image(&store)? == before,
            "partial identity/dictionary/revision/index publication escaped rollback",
        )?;
        receipt(&owner, request.operation_id, false)?;
        inventory(&store)?;
    }
    require(
        owner
            .mutate_controlled(
                &request,
                &mut || Ok(Uuid::new_v4()),
                None,
                &mut || Ok(()),
                true,
            )
            .is_err_and(|e| e.code == "outcome_unknown"),
        "identity commit acknowledgement loss not reported",
    )?;
    receipt(&owner, request.operation_id, true)?;
    source(&store, 100, 3, "recover@example.com", 1)?;
    source(&store, 101, 3, "+12345678", 1)?;
    authentication_revision(&store, 3, 1)?;
    inventory(&store)?;
    let committed = image(&store)?;
    // A missing recent-authentication fact cannot authorize another self write,
    // but current normal receipt disclosure recovers the already committed one.
    let without_issuance = store.session(id(3), 0)?;
    require(
        without_issuance.mutate(&request)?["replayed"] == true,
        "original identity receipt not recovered before self recency",
    )?;
    require(
        image(&store)? == committed,
        "receipt replay changed identity/authentication revisions",
    )?;
    reports.push(json!({"case":family,"native_write_positions":native_writes,"post_receipt_abort":true,"before_commit_abort":true,"unknown_ack_original_receipt":true,"principal_authentication_revision":1,"write_set":write_set}));
    drop((without_issuance, owner, store));
    reopened(factory, family, &committed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_redb_identity_controls_are_explicitly_sequential() {
        let directory =
            std::env::temp_dir().join(format!("a0-identity-adapter-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let result = run(
            |family| {
                let path = directory.join(format!("{family}.redb"));
                if path.exists() {
                    Database::open(path)
                } else {
                    Database::create(path)
                }
            },
            false,
        )
        .unwrap();
        assert_eq!(result["status"], "passed");
        assert_eq!(result["case_count"], 11);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
