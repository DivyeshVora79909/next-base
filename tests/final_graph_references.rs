//! References and authorization are checked against the transaction's final graph.
use rebase_semantic_proof::{
    access::{Action, Grants, Graph, Principal, PrincipalKind},
    binding::Binding,
    local::{Mutation, Store},
    model::Prepared,
    models::quantity::{JOIN, Quantity, SCALE, SOURCE},
    native_slice::Context,
    security::ReplaceGraph,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::PathBuf, sync::Arc};
use uuid::Uuid;

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

fn principal(n: u128, parents: Vec<Uuid>) -> Principal {
    Principal {
        id: id(n),
        kind: PrincipalKind::User,
        parents,
        active: true,
        credential_epoch: 0,
        grants: Grants {
            admin: false,
            contracts: [SOURCE, SCALE, JOIN]
                .into_iter()
                .map(|code| {
                    (
                        code,
                        BTreeSet::from([
                            Action::Read,
                            Action::Create,
                            Action::Update,
                            Action::Delete,
                        ]),
                    )
                })
                .collect(),
        },
    }
}

struct Fixture {
    directory: PathBuf,
    admin: Store<Quantity>,
    model: Arc<Prepared<Quantity>>,
}

impl Fixture {
    fn new() -> Self {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/final-graph-references")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&directory).unwrap();
        let model = Arc::new(Prepared::<Quantity>::load().unwrap());
        let admin = Store::<Quantity>::create_secured(
            directory.join("test.redb"),
            model.clone(),
            Context {
                tenant: id(1),
                actor: id(2),
            },
        )
        .unwrap();
        let mut graph = Graph::bootstrap(Context {
            tenant: id(1),
            actor: id(2),
        })
        .unwrap()
        .graph;
        graph
            .principals
            .extend([principal(3, vec![id(1)]), principal(4, vec![id(1)])]);
        let revision = admin.access_graph(model.identity()).unwrap()["revision"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        admin
            .replace_access(&ReplaceGraph {
                model: model.identity().into(),
                if_revision: revision,
                graph,
            })
            .unwrap();
        Self {
            directory,
            admin,
            model,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn mutate<B: Binding>(
    store: &Store<B>,
    commands: Value,
) -> Result<Value, rebase_semantic_proof::native_slice::Error> {
    let request: Mutation = serde_json::from_value(json!({
        "model": store.model().identity(),
        "context": store.operation_context(store.model().identity()).unwrap(),
        "operation_id": Uuid::new_v4(),
        "commands": commands,
        "returning": []
    }))
    .unwrap();
    store.mutate(&request)
}

fn source(id_value: u128) -> Value {
    json!({"op":"create","id":id(id_value),"contract":SOURCE,"fields":{"value":"12"}})
}

fn scale(id_value: u128, parent: u128) -> Value {
    json!({"op":"create","id":id(id_value),"contract":SCALE,"fields":{
        "parent":id(parent),"factor":{"numerator":"2","denominator":"1"},"rounding":"exact"
    }})
}

fn assert_scaled(store: &Store<Quantity>, identity: u128, expected: &str) {
    let record = store
        .get(store.model().identity(), id(identity))
        .unwrap()
        .unwrap();
    assert_eq!(record.derived.unwrap()["quantity"], expected);
    store.check_integrity().unwrap();
}

#[test]
fn create_and_delete_reference_graphs_are_order_independent() {
    let create_orders = [
        [10, 20, 30],
        [10, 30, 20],
        [20, 10, 30],
        [20, 30, 10],
        [30, 10, 20],
        [30, 20, 10],
    ];
    let delete_orders = [
        [10, 20, 30],
        [10, 30, 20],
        [20, 10, 30],
        [20, 30, 10],
        [30, 10, 20],
        [30, 20, 10],
    ];
    let command = |n| match n {
        10 => source(10),
        20 => scale(20, 10),
        30 => scale(30, 20),
        _ => unreachable!(),
    };
    let normalized = |store: &Store<Quantity>| {
        [10, 20, 30]
            .into_iter()
            .map(|n| {
                let record = store.get(store.model().identity(), id(n)).unwrap().unwrap();
                json!({"contract":record.contract,"input":record.input,"derived":record.derived})
            })
            .collect::<Vec<_>>()
    };
    let mut expected = None;
    for (index, create_order) in create_orders.into_iter().enumerate() {
        let fixture = Fixture::new();
        mutate(
            &fixture.admin,
            json!(create_order.into_iter().map(command).collect::<Vec<_>>()),
        )
        .unwrap();
        assert_scaled(&fixture.admin, 30, "48");
        assert_eq!(
            fixture
                .admin
                .get(fixture.model.identity(), id(30))
                .unwrap()
                .unwrap()
                .derived
                .unwrap()["quantity"],
            "48"
        );
        let actual = normalized(&fixture.admin);
        if let Some(wanted) = &expected {
            assert_eq!(&actual, wanted);
        } else {
            expected = Some(actual);
        }
        let deletion_order = delete_orders[index];
        let commands: Vec<_> = deletion_order
            .into_iter()
            .map(|n| {
                let record = fixture
                    .admin
                    .get(fixture.model.identity(), id(n))
                    .unwrap()
                    .unwrap();
                json!({"op":"delete","id":id(n),"if_version":record.version})
            })
            .collect();
        mutate(&fixture.admin, json!(commands)).unwrap();
        assert!(
            fixture
                .admin
                .get(fixture.model.identity(), id(10))
                .unwrap()
                .is_none()
        );
        assert!(
            fixture
                .admin
                .get(fixture.model.identity(), id(20))
                .unwrap()
                .is_none()
        );
        assert!(
            fixture
                .admin
                .get(fixture.model.identity(), id(30))
                .unwrap()
                .is_none()
        );
        fixture.admin.check_integrity().unwrap();
    }
}

#[test]
fn surviving_references_block_target_deletion_and_rollback_the_batch() {
    let fixture = Fixture::new();
    mutate(&fixture.admin, json!([source(10), scale(20, 10)])).unwrap();
    let before = fixture.admin.observe_for_verification().unwrap();
    let parent = fixture
        .admin
        .get(fixture.model.identity(), id(10))
        .unwrap()
        .unwrap();
    let result = mutate(
        &fixture.admin,
        json!([{"op":"delete","id":id(10),"if_version":parent.version}]),
    );
    assert!(result.is_err());
    assert_eq!(fixture.admin.observe_for_verification().unwrap(), before);
}

#[test]
fn hidden_reference_creation_and_retargeting_fail_in_final_graph() {
    let fixture = Fixture::new();
    let hidden_owner = fixture.admin.session(id(3), 0).unwrap();
    let actor = fixture.admin.session(id(4), 0).unwrap();
    mutate(&hidden_owner, json!([source(30)])).unwrap();

    let before = fixture.admin.observe_for_verification().unwrap();
    assert!(mutate(&actor, json!([scale(40, 30)])).is_err());
    assert_eq!(fixture.admin.observe_for_verification().unwrap(), before);

    mutate(&actor, json!([source(31), scale(41, 31)])).unwrap();
    let before_retarget = fixture.admin.observe_for_verification().unwrap();
    let record = actor
        .get(fixture.model.identity(), id(41))
        .unwrap()
        .unwrap();
    let result = mutate(
        &actor,
        json!([{"op":"update","id":id(41),"if_version":record.version,
            "set":{"parent":id(30)},"unset":[]}]),
    );
    assert!(result.is_err());
    assert_eq!(
        fixture.admin.observe_for_verification().unwrap(),
        before_retarget
    );
}

#[test]
fn stale_version_does_not_disclose_or_override_missing_write_authority() {
    let fixture = Fixture::new();
    let owner = fixture.admin.session(id(3), 0).unwrap();
    let peer = fixture.admin.session(id(4), 0).unwrap();
    mutate(&owner, json!([source(50)])).unwrap();
    let record = owner
        .get(fixture.model.identity(), id(50))
        .unwrap()
        .unwrap();
    let result = mutate(
        &peer,
        json!([{"op":"update","id":id(50),"if_version":Uuid::nil(),
            "set":{"value":"99"},"unset":[]}]),
    );
    assert_eq!(result.unwrap_err().code, "forbidden");
    assert_eq!(
        owner
            .get(fixture.model.identity(), id(50))
            .unwrap()
            .unwrap()
            .version,
        record.version
    );
}

#[test]
fn readable_derived_record_remains_usable_when_its_source_owner_leaves_scope() {
    let fixture = Fixture::new();
    let mut graph = fixture
        .admin
        .access_graph(fixture.model.identity())
        .unwrap();
    let revision = graph["revision"].as_str().unwrap().parse().unwrap();
    let mut authored: Graph = serde_json::from_value(graph["graph"].take()).unwrap();
    authored
        .principals
        .iter_mut()
        .find(|p| p.id == id(3))
        .unwrap()
        .parents = vec![id(4)];
    fixture
        .admin
        .replace_access(&ReplaceGraph {
            model: fixture.model.identity().into(),
            if_revision: revision,
            graph: authored,
        })
        .unwrap();
    let source_owner = fixture.admin.session(id(3), 0).unwrap();
    let actor = fixture.admin.session(id(4), 0).unwrap();
    mutate(&source_owner, json!([source(100)])).unwrap();
    mutate(&actor, json!([scale(101, 100)])).unwrap();
    let graph = fixture
        .admin
        .access_graph(fixture.model.identity())
        .unwrap();
    let revision = graph["revision"].as_str().unwrap().parse().unwrap();
    let mut authored: Graph = serde_json::from_value(graph["graph"].clone()).unwrap();
    authored
        .principals
        .iter_mut()
        .find(|p| p.id == id(3))
        .unwrap()
        .parents = vec![id(1)];
    fixture
        .admin
        .replace_access(&ReplaceGraph {
            model: fixture.model.identity().into(),
            if_revision: revision,
            graph: authored,
        })
        .unwrap();
    assert!(
        actor
            .get(fixture.model.identity(), id(100))
            .unwrap()
            .is_none()
    );
    assert_scaled(&actor, 101, "24");
    mutate(&actor, json!([scale(102, 101)])).unwrap();
    assert_scaled(&actor, 102, "48");
    let before = fixture.admin.observe_for_verification().unwrap();
    assert_eq!(
        mutate(&actor, json!([scale(103, 100)])).unwrap_err().code,
        "forbidden"
    );
    assert_eq!(fixture.admin.observe_for_verification().unwrap(), before);
}
