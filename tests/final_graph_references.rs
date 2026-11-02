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
fn hidden_reference_creation_and_retargeting_fail_after_final_reader_repair() {
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
    let record = fixture
        .admin
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
        fixture
            .admin
            .get(fixture.model.identity(), id(50))
            .unwrap()
            .unwrap()
            .version,
        record.version
    );
}

fn shadow_frontier_actor(fixture: &Fixture) -> Store<Quantity> {
    // Actor A is above C; C is above C'; D is a second parent of C and
    // remains incomparable with A. The extra path makes a source record
    // readable at C while its recursively expanded frontier also contains D.
    let graph = fixture
        .admin
        .access_graph(fixture.model.identity())
        .unwrap();
    let revision = graph["revision"].as_str().unwrap().parse().unwrap();
    let mut authored: Graph = serde_json::from_value(graph["graph"].clone()).unwrap();
    authored.principals.extend([
        principal(5, vec![id(4), id(7)]),
        principal(6, vec![id(5)]),
        principal(7, vec![id(1)]),
    ]);
    fixture
        .admin
        .replace_access(&ReplaceGraph {
            model: fixture.model.identity().into(),
            if_revision: revision,
            graph: authored,
        })
        .unwrap();

    let c = fixture.admin.session(id(5), 0).unwrap();
    let d = fixture.admin.session(id(7), 0).unwrap();
    let c_prime = fixture.admin.session(id(6), 0).unwrap();
    mutate(&c, json!([source(100)])).unwrap();
    // B is owned by D and references C. Since C is below D, B's selected
    // reader is C, so A can read B and the next C-owned record.
    mutate(&d, json!([scale(101, 100)])).unwrap();
    mutate(&c, json!([scale(102, 101)])).unwrap();
    mutate(&c_prime, json!([source(103)])).unwrap();

    // After D has created B, remove its parent edge to C. Reader repair keeps
    // B at D (owner D precedes referenced owner C), while T remains at C
    // because C precedes B's owner in T's preorder. D is now incomparable to
    // both A and C'.
    let current = fixture
        .admin
        .access_graph(fixture.model.identity())
        .unwrap();
    let revision = current["revision"].as_str().unwrap().parse().unwrap();
    let mut authored: Graph = serde_json::from_value(current["graph"].clone()).unwrap();
    authored
        .principals
        .iter_mut()
        .find(|principal| principal.id == id(5))
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
    assert_reader(&fixture.admin, 101, 7, SCALE);
    assert_reader(&fixture.admin, 102, 5, SCALE);
    fixture.admin.check_integrity().unwrap();
    fixture.admin.session(id(4), 0).unwrap()
}

fn join(id_value: u128, left: u128, right: u128) -> Value {
    json!({"op":"create","id":id(id_value),"contract":JOIN,"fields":{
        "left":id(left),"right":id(right)
    }})
}

fn assert_reader(store: &Store<Quantity>, record: u128, reader: u128, contract: u16) {
    let expected = format!(
        "{}{:04x}{}",
        id(reader).simple(),
        contract,
        id(record).simple()
    );
    assert!(
        store.observe_for_verification().unwrap()["tables"]["reader_records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["key"] == expected)
    );
}

#[test]
fn final_frontier_cannot_authorize_a_child_through_a_newly_hidden_parent() {
    let fixture = Fixture::new();
    let actor = shadow_frontier_actor(&fixture);

    // P's immediate targets are readable by A, so P may be created. Its full
    // owner preorder is [A,C,D,C']; A and C are dominated, leaving D first.
    mutate(&actor, json!([join(104, 102, 103)])).unwrap();
    assert_reader(&fixture.admin, 104, 7, JOIN);
    assert!(
        actor
            .get(fixture.model.identity(), id(104))
            .unwrap()
            .is_none()
    );

    let before = fixture.admin.observe_for_verification().unwrap();
    assert!(mutate(&actor, json!([scale(105, 104)])).is_err());
    assert_eq!(fixture.admin.observe_for_verification().unwrap(), before);

    // Staging the child first must produce the same denial after final reader
    // repair; the temporary creation owner on P cannot authorize Q.
    for child_first in [false, true] {
        let fixture = Fixture::new();
        let actor = shadow_frontier_actor(&fixture);
        let parent = join(114, 102, 103);
        let child = scale(115, 114);
        let commands = if child_first {
            json!([child, parent])
        } else {
            json!([parent, child])
        };
        let before = fixture.admin.observe_for_verification().unwrap();
        assert_eq!(mutate(&actor, commands).unwrap_err().code, "forbidden");
        assert_eq!(fixture.admin.observe_for_verification().unwrap(), before);
    }
}
