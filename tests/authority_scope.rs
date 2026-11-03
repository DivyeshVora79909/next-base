//! Ordinary resource access follows DAG scope even with administrative grants.
use rebase_semantic_proof::{
    access::{Action, Grants, Graph, Principal, PrincipalKind},
    local::LocalStore,
    model::PreparedModel,
    native_slice::{Context, Input, Record},
    security::ReplaceGraph,
};
use std::{collections::BTreeSet, path::PathBuf, sync::Arc};
use uuid::Uuid;

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

fn principal(n: u128, kind: PrincipalKind, parents: &[u128], grants: Grants) -> Principal {
    Principal {
        id: id(n),
        kind,
        parents: parents.iter().copied().map(id).collect(),
        active: true,
        login_access: false,
        credential_epoch: 0,
        grants,
    }
}

fn graph() -> Graph {
    let mut graph = Graph::bootstrap(Context {
        tenant: id(1),
        actor: id(2),
    })
    .unwrap()
    .graph;
    graph.principals.extend([
        principal(3, PrincipalKind::User, &[1], Grants::default()),
        principal(4, PrincipalKind::User, &[2], Grants::default()),
        principal(5, PrincipalKind::Group, &[1], Grants::default()),
        principal(6, PrincipalKind::User, &[5], Grants::default()),
    ]);
    graph
}

fn record(owner: u128) -> Record {
    Record {
        created_at: 0,
        contract: 4,
        tenant: id(1),
        owner: id(owner),
        version: id(100),
        input: Input::Account { native_unit: 1 },
        derived: None,
    }
}

#[test]
fn administrative_actions_do_not_expand_ordinary_owner_scope() {
    let prepared = graph().prepare().unwrap();
    let admin = &prepared.scopes[&id(2)];
    assert!(admin.grants.admin);
    assert_eq!(admin.accessible, BTreeSet::from([id(2), id(4)]));
    for target in [2, 4] {
        let source = record(target);
        assert!(admin.can_read(&source));
        for action in [Action::Create, Action::Update] {
            assert!(admin.can_write(&source, action));
        }
    }
    for target in [1, 3, 5, 6] {
        let source = record(target);
        assert!(!admin.can_read(&source));
        for action in [Action::Create, Action::Update, Action::Delete] {
            assert!(!admin.can_write(&source, action));
        }
    }
    assert!(!admin.can_write(&record(1), Action::Delete));
    assert!(admin.can_write(&record(2), Action::Delete));
    assert!(admin.can_write(&record(4), Action::Delete));
    let mut foreign = record(2);
    foreign.tenant = id(9);
    assert!(!admin.can_read(&foreign));
    assert!(!admin.can_write(&foreign, Action::Update));
    let mut inactive = admin.clone();
    inactive.active = false;
    assert!(!inactive.can_read(&record(2)));
    assert!(!inactive.can_write(&record(2), Action::Update));
}

#[test]
fn only_direct_groups_supply_parent_scope_while_tenants_still_supply_grants() {
    let mut graph = graph();
    graph.principals[0]
        .grants
        .contracts
        .insert(4, BTreeSet::from([Action::Read]));
    let group = graph.principals.iter_mut().find(|p| p.id == id(5)).unwrap();
    group.grants.contracts.insert(
        4,
        BTreeSet::from([Action::Read, Action::Update, Action::Delete]),
    );
    graph.principals.extend([
        principal(7, PrincipalKind::Group, &[5], Grants::default()),
        principal(8, PrincipalKind::User, &[7], Grants::default()),
        principal(9, PrincipalKind::User, &[1, 5], Grants::default()),
    ]);
    let prepared = graph.prepare().unwrap();
    let user_child = &prepared.scopes[&id(4)];
    assert_eq!(user_child.accessible, BTreeSet::from([id(4)]));
    assert!(!user_child.grants.admin);
    assert!(!user_child.can_read(&record(2)));
    assert!(!user_child.can_write(&record(4), Action::Update));
    let group_child = &prepared.scopes[&id(6)];
    assert_eq!(group_child.accessible, BTreeSet::from([id(5), id(6)]));
    assert!(group_child.can_write(&record(5), Action::Update));
    assert!(group_child.can_read(&record(5)));
    assert!(!group_child.can_write(&record(5), Action::Delete));
    // Group grants do not flow transitively through another group.
    for actor in [7, 8] {
        assert!(!prepared.scopes[&id(actor)].grants.allows(4, Action::Update));
    }
    let direct_both = &prepared.scopes[&id(9)];
    assert!(!direct_both.can_read(&record(1)));
    assert!(direct_both.grants.allows(4, Action::Read));
    assert!(direct_both.can_write(&record(5), Action::Update));
    assert!(!direct_both.can_write(&record(1), Action::Delete));
    assert_eq!(direct_both.accessible, BTreeSet::from([id(5), id(9)]));
}

#[test]
fn inactive_direct_parent_supplies_no_inherited_actions() {
    let mut graph = graph();
    let group = graph.principals.iter_mut().find(|p| p.id == id(5)).unwrap();
    group.active = false;
    group.grants.admin = true;
    let prepared = graph.prepare().unwrap();
    let scope = &prepared.scopes[&id(6)];
    assert!(!scope.grants.admin);
    assert!(!scope.can_read(&record(5)));
    assert!(!scope.can_write(&record(5), Action::Update));
}

#[test]
fn inherited_administration_grants_actions_without_sibling_scope() {
    let mut graph = graph();
    graph
        .principals
        .iter_mut()
        .find(|p| p.id == id(5))
        .unwrap()
        .grants
        .admin = true;
    graph
        .principals
        .push(principal(7, PrincipalKind::User, &[5], Grants::default()));
    let prepared = graph.prepare().unwrap();
    let scope = &prepared.scopes[&id(6)];
    assert!(scope.grants.admin);
    assert_eq!(scope.accessible, BTreeSet::from([id(5), id(6)]));
    assert!(scope.can_read(&record(5)));
    assert!(scope.can_write(&record(6), Action::Update));
    assert!(!scope.can_read(&record(7)));
    assert!(!scope.can_write(&record(7), Action::Update));
}

#[test]
fn graph_administration_remains_available_with_a_strict_tenant_fence() {
    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory =
        Directory(std::env::temp_dir().join(format!("authority-scope-{}", Uuid::new_v4())));
    std::fs::create_dir_all(&directory.0).unwrap();
    let model = Arc::new(PreparedModel::load().unwrap());
    let store = LocalStore::create_secured(
        directory.0.join("test.redb"),
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    let revision = || {
        store.access_graph(model.identity()).unwrap()["revision"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
    };
    store
        .replace_access(&ReplaceGraph {
            model: model.identity().into(),
            if_revision: revision(),
            graph: graph(),
        })
        .unwrap();
    let ordinary = graph().prepare().unwrap();
    assert!(!ordinary.scopes[&id(2)].can_read(&record(3)));
    // Admin can edit a sibling's authority even though its ordinary records are hidden.
    let mut next = graph();
    next.principals
        .iter_mut()
        .find(|p| p.id == id(3))
        .unwrap()
        .active = false;
    store
        .replace_access(&ReplaceGraph {
            model: model.identity().into(),
            if_revision: revision(),
            graph: next.clone(),
        })
        .unwrap();
    let before = store.access_graph(model.identity()).unwrap();
    next.tenant = id(99);
    assert_eq!(
        store
            .replace_access(&ReplaceGraph {
                model: model.identity().into(),
                if_revision: revision(),
                graph: next,
            })
            .unwrap_err()
            .code,
        "forbidden"
    );
    assert_eq!(store.access_graph(model.identity()).unwrap(), before);
}
