use rebase_semantic_proof::{
    access::{Action, Grants, Graph, Principal, PrincipalKind},
    binding::Binding,
    local::{Mutation, Store},
    model::{Prepared, PreparedModel},
    native_slice::Context,
    query::{PageRequest, RecordQuery, RootRead, RootRequest},
    root_page::{RootPagePolicy, RootPageRequest},
    security::ReplaceGraph,
};
mod common;
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc};
use uuid::Uuid;

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("ownership-transfer-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn file(&self) -> PathBuf {
        self.0.join("store.redb")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn grants(actions: &[Action]) -> Grants {
    Grants {
        admin: false,
        contracts: (1..=10)
            .chain([101, 205, 410, 900])
            .map(|code| (code, actions.iter().copied().collect()))
            .collect(),
    }
}

fn graph() -> Graph {
    let mut graph = Graph::bootstrap(Context {
        tenant: id(1),
        actor: id(2),
    })
    .unwrap()
    .graph;
    // Actor 4 can access self, descendant 7 and direct group parent 6. Actor 5
    // shares the group only; actor 8 is in a separate tenant-root branch.
    graph.principals.extend(
        [
            (3, 2, PrincipalKind::User),
            (6, 2, PrincipalKind::Group),
            (4, 6, PrincipalKind::User),
            (5, 6, PrincipalKind::User),
            (7, 4, PrincipalKind::User),
            (8, 1, PrincipalKind::User),
            (9, 1, PrincipalKind::User),
            (11, 9, PrincipalKind::User),
        ]
        .map(|(n, parent, kind)| Principal {
            id: id(n),
            kind,
            parents: vec![id(parent)],
            active: true,
            login_access: false,
            credential_epoch: 0,
            grants: grants(if n == 9 {
                &[Action::Create, Action::Update]
            } else if n == 8 {
                &[Action::Read, Action::Create, Action::Delete]
            } else {
                &[Action::Read, Action::Create, Action::Update, Action::Delete]
            }),
        }),
    );
    graph
}

fn setup<B: Binding>(directory: &Directory, model: Arc<Prepared<B>>) -> Store<B> {
    let store = Store::create_secured(
        directory.file(),
        model,
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    let revision = store.access_graph(store.model().identity()).unwrap()["revision"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let mut graph = graph();
    for principal in &mut graph.principals {
        principal
            .grants
            .contracts
            .retain(|code, _| store.model().public_contract(*code).is_ok());
    }
    store
        .replace_access(&ReplaceGraph {
            model: store.model().identity().into(),
            if_revision: revision,
            graph,
        })
        .unwrap();
    store
}

fn request<B: Binding>(store: &Store<B>, commands: Value, returning: Value) -> Mutation {
    serde_json::from_value(json!({
        "model":store.model().identity(),
        "context":store.operation_context(store.model().identity()).unwrap(),
        "operation_id":Uuid::new_v4(), "commands":commands,"returning":returning,
    }))
    .unwrap()
}

fn transfer<B: Binding>(store: &Store<B>, record: u128, owner: u128) -> Mutation {
    let version = store
        .get(store.model().identity(), id(record))
        .unwrap()
        .unwrap()
        .version;
    request(
        store,
        json!([{
            "op":"update","id":id(record),"if_version":version,
            "owner":id(owner),"set":{},"unset":[],
        }]),
        json!([id(record)]),
    )
}

fn native_value(image: &Value, key: &str) -> Value {
    let row = image["tables"]["native_kv"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["key"] == key)
        .unwrap();
    let text = row["value"].as_str().unwrap();
    let bytes: Vec<_> = (0..text.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&text[offset..offset + 2], 16).unwrap())
        .collect();
    serde_json::from_slice(&bytes).unwrap()
}

fn source(image: &Value, n: u128) -> Value {
    native_value(image, &format!("01{}", id(n).simple()))["data"].clone()
}

fn native_rows_with_tag(image: &Value, tags: &[&str]) -> Vec<Value> {
    image["tables"]["native_kv"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| {
            tags.iter()
                .any(|tag| row["key"].as_str().unwrap().starts_with(tag))
        })
        .cloned()
        .collect()
}

#[test]
fn self_descendant_and_direct_group_transfers_keep_identity_and_exact_owner_index() {
    let directory = Directory::new();
    let admin = setup(&directory, Arc::new(PreparedModel::load().unwrap()));
    let caller = admin.session(id(4), 0).unwrap();
    let sibling = admin.session(id(5), 0).unwrap();
    caller
        .mutate(&request(
            &caller,
            json!([
                {"op":"create","id":id(40),"contract":4,"fields":{"native_unit":1}}
            ]),
            json!([]),
        ))
        .unwrap();
    for owner in [6, 4, 7, 4] {
        let before = caller
            .get(caller.model().identity(), id(40))
            .unwrap()
            .unwrap();
        caller.mutate(&transfer(&caller, 40, owner)).unwrap();
        let record = caller
            .get(caller.model().identity(), id(40))
            .unwrap()
            .unwrap();
        assert_eq!(record.id, id(40));
        assert_eq!(
            serde_json::to_value(record.input).unwrap(),
            json!({"native_unit":1})
        );
        assert_ne!(record.version, before.version);
        assert_eq!(
            sibling
                .get(sibling.model().identity(), id(40))
                .unwrap()
                .is_some(),
            owner == 6
        );
        let image = admin.observe_for_verification().unwrap();
        assert_eq!(source(&image, 40)["owner"], json!(id(owner)));
        assert_eq!(
            image["tables"]["owner_records"],
            json!([{
                "key":format!("{}{:04x}{}", id(owner).simple(), 4, id(40).simple()),
                "contract":4,
            }])
        );
        admin.check_integrity().unwrap();
    }
}

#[test]
fn both_owners_are_authorized_before_cas_and_rejection_rolls_back_every_table() {
    let directory = Directory::new();
    let admin = setup(&directory, Arc::new(PreparedModel::load().unwrap()));
    let _foreign = Store::create_secured(
        directory.0.join("foreign.redb"),
        Arc::new(PreparedModel::load().unwrap()),
        Context {
            tenant: id(1000),
            actor: id(1001),
        },
    )
    .unwrap();
    let caller = admin.session(id(4), 0).unwrap();
    admin
        .mutate(&request(
            &admin,
            json!([
                {"op":"create","id":id(40),"owner":id(4),"contract":4,"fields":{"native_unit":1}},
                {"op":"create","id":id(41),"owner":id(4),"contract":4,"fields":{"native_unit":1}},
                {"op":"create","id":id(50),"owner":id(3),"contract":4,"fields":{"native_unit":1}}
            ]),
            json!([]),
        ))
        .unwrap();
    let version = caller
        .get(caller.model().identity(), id(40))
        .unwrap()
        .unwrap()
        .version;
    let before = admin.observe_for_verification().unwrap();
    // Existing inaccessible users, a sibling, tenant parent, non-group ancestor,
    // missing UUID and a UUID belonging only to another tenant are indistinguishable.
    for owner in [3, 5, 8, 1, 2, 999, 1001] {
        for if_version in [version, id(9999)] {
            let invalid = json!({"op":"update","id":id(40),"if_version":if_version,
                "owner":id(owner),"set":{},"unset":[]});
            let first = serde_json::to_value(&transfer(&caller, 41, 6).commands[0]).unwrap();
            assert_eq!(
                caller
                    .mutate(&request(&caller, json!([first, invalid]), json!([])))
                    .unwrap_err()
                    .code,
                "forbidden"
            );
            assert_eq!(admin.observe_for_verification().unwrap(), before);
        }
    }
    let hidden = request(
        &caller,
        json!([{
            "op":"update","id":id(50),"if_version":id(9999),"owner":id(4),"set":{},"unset":[]
        }]),
        json!([]),
    );
    assert_eq!(caller.mutate(&hidden).unwrap_err().code, "forbidden");
    assert_eq!(admin.observe_for_verification().unwrap(), before);

    for set in [json!({"owner":id(6)}), json!({"native_unit":2})] {
        let invalid = request(
            &caller,
            json!([{
                "op":"update","id":id(40),"if_version":version,"owner":id(6),"set":set,"unset":[]
            }]),
            json!([]),
        );
        assert_eq!(caller.mutate(&invalid).unwrap_err().code, "invalid_input");
        assert_eq!(admin.observe_for_verification().unwrap(), before);
    }
    let permitted_stale = request(
        &caller,
        json!([{
            "op":"update","id":id(40),"if_version":id(9999),"owner":id(6),"set":{},"unset":[]
        }]),
        json!([]),
    );
    assert_eq!(
        caller.mutate(&permitted_stale).unwrap_err().code,
        "stale_version"
    );
    assert_eq!(admin.observe_for_verification().unwrap(), before);
}

#[test]
fn update_grant_does_not_require_read_and_does_not_widen_delete() {
    let directory = Directory::new();
    let admin = setup(&directory, Arc::new(PreparedModel::load().unwrap()));
    let write_only = admin.session(id(9), 0).unwrap();
    let created = write_only
        .mutate(&request(
            &write_only,
            json!([
                {"op":"create","id":id(90),"contract":4,"fields":{"native_unit":1}}
            ]),
            json!([id(90)]),
        ))
        .unwrap();
    assert!(
        write_only
            .get(write_only.model().identity(), id(90))
            .unwrap()
            .is_none()
    );
    let transferred = write_only
        .mutate(&request(
            &write_only,
            json!([{
                "op":"update","id":id(90),"if_version":created["result"]["revision"],
                "owner":id(11),"set":{},"unset":[]
            }]),
            json!([id(90)]),
        ))
        .unwrap();
    assert_eq!(transferred["result"]["records"][0]["record"], Value::Null);
    assert_eq!(
        source(&admin.observe_for_verification().unwrap(), 90)["owner"],
        json!(id(11))
    );

    let no_update = admin.session(id(8), 0).unwrap();
    no_update
        .mutate(&request(
            &no_update,
            json!([
                {"op":"create","id":id(80),"contract":4,"fields":{"native_unit":1}}
            ]),
            json!([]),
        ))
        .unwrap();
    let before = admin.observe_for_verification().unwrap();
    assert_eq!(
        no_update
            .mutate(&transfer(&no_update, 80, 8))
            .unwrap_err()
            .code,
        "forbidden"
    );
    assert_eq!(admin.observe_for_verification().unwrap(), before);

    let caller = admin.session(id(4), 0).unwrap();
    caller
        .mutate(&request(
            &caller,
            json!([
                {"op":"create","id":id(40),"contract":4,"fields":{"native_unit":1}}
            ]),
            json!([]),
        ))
        .unwrap();
    caller.mutate(&transfer(&caller, 40, 6)).unwrap();
    let version = caller
        .get(caller.model().identity(), id(40))
        .unwrap()
        .unwrap()
        .version;
    let before = admin.observe_for_verification().unwrap();
    let delete = request(
        &caller,
        json!([{"op":"delete","id":id(40),"if_version":version}]),
        json!([]),
    );
    assert_eq!(caller.mutate(&delete).unwrap_err().code, "forbidden");
    assert_eq!(admin.observe_for_verification().unwrap(), before);
    admin.check_integrity().unwrap();
}

#[test]
fn update_owner_wire_is_canonical_and_same_owner_is_a_true_data_noop() {
    let directory = Directory::new();
    let admin = setup(&directory, Arc::new(PreparedModel::load().unwrap()));
    let caller = admin.session(id(4), 0).unwrap();
    caller
        .mutate(&request(
            &caller,
            json!([
                {"op":"create","id":id(40),"contract":4,"fields":{"native_unit":1}},
                {"op":"create","id":id(41),"contract":4,"fields":{"native_unit":1}}
            ]),
            json!([]),
        ))
        .unwrap();
    let mut page = PageRequest {
        model: caller.model().identity().into(),
        query: RecordQuery::default(),
        limit: 1,
        visit_budget: 64,
        cursor: None,
    };
    page.cursor = caller.page(&page).unwrap().cursor;
    assert!(page.cursor.is_some());
    let before = admin.observe_for_verification().unwrap();
    let valid = transfer(&caller, 40, 4);
    for owner in [
        Value::Null,
        json!(7),
        json!(""),
        json!("bad-owner"),
        json!("ABCDEFAB-0000-0000-0000-000000000004"),
    ] {
        let mut malformed = serde_json::to_value(&valid).unwrap();
        malformed["commands"][0]["owner"] = owner;
        assert!(serde_json::from_value::<Mutation>(malformed).is_err());
    }
    for supplied in [true, false] {
        let mut command = serde_json::to_value(&valid.commands[0]).unwrap();
        if !supplied {
            command.as_object_mut().unwrap().remove("owner");
        }
        caller
            .mutate(&request(&caller, json!([command]), json!([])))
            .unwrap();
        let after = admin.observe_for_verification().unwrap();
        for table in [
            "native_kv",
            "public_records",
            "owner_records",
            "query_epochs",
            "authority",
        ] {
            assert_eq!(
                after["tables"][table], before["tables"][table],
                "no-op changed {table}"
            );
        }
        assert_eq!(caller.page(&page).unwrap().records[0].id, id(41));
    }
    admin.check_integrity().unwrap();
}

#[test]
fn transfer_fences_both_owner_cursors_and_replay_uses_current_disclosure() {
    let directory = Directory::new();
    let model = Arc::new(PreparedModel::load().unwrap());
    let admin = setup(&directory, model.clone());
    let left = admin.session(id(4), 0).unwrap();
    let right = admin.session(id(5), 0).unwrap();
    let other = admin.session(id(3), 0).unwrap();
    let created = request(
        &left,
        json!([
            {"op":"create","id":id(40),"contract":4,"fields":{"native_unit":1}},
            {"op":"create","id":id(41),"contract":4,"fields":{"native_unit":1}}
        ]),
        json!([id(40)]),
    );
    left.mutate(&created).unwrap();
    for (store, first) in [(&right, 50), (&other, 60)] {
        store
            .mutate(&request(
                store,
                json!([
                    {"op":"create","id":id(first),"contract":4,"fields":{"native_unit":1}},
                    {"op":"create","id":id(first+1),"contract":4,"fields":{"native_unit":1}}
                ]),
                json!([]),
            ))
            .unwrap();
    }
    let cursor = |store: &Store<_>| {
        let mut page = PageRequest {
            model: store.model().identity().into(),
            query: RecordQuery {
                contract: Some(4),
                ..RecordQuery::default()
            },
            limit: 1,
            visit_budget: 64,
            cursor: None,
        };
        page.cursor = store.page(&page).unwrap().cursor;
        assert!(page.cursor.is_some());
        page
    };
    let left_cursor = cursor(&left);
    let right_cursor = cursor(&right);
    let other_cursor = cursor(&other);
    let transferred = transfer(&admin, 40, 5);
    admin.mutate(&transferred).unwrap();
    let mut mismatched = serde_json::to_value(&transferred).unwrap();
    mismatched["commands"][0]["owner"] = json!(id(4));
    assert_eq!(
        admin
            .mutate(&serde_json::from_value(mismatched).unwrap())
            .unwrap_err()
            .code,
        "operation_conflict"
    );
    for (store, page) in [(&left, &left_cursor), (&right, &right_cursor)] {
        assert_eq!(store.page(page).unwrap_err().code, "query_changed");
    }
    assert_eq!(other.page(&other_cursor).unwrap().records[0].id, id(61));
    assert!(left.get(model.identity(), id(40)).unwrap().is_none());
    assert!(right.get(model.identity(), id(40)).unwrap().is_some());
    let replay = left.mutate(&created).unwrap();
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["result"]["records"][0]["record"], Value::Null);
    assert_eq!(
        left.operation_status(model.identity(), &created.context, created.operation_id)
            .unwrap()["result"]["records"][0]["record"],
        Value::Null
    );
    let exact: Vec<_> = [(3, 60), (3, 61), (4, 41), (5, 40), (5, 50), (5, 51)]
        .into_iter().map(|(owner, record)| json!({
            "key":format!("{}{:04x}{}", id(owner).simple(), 4, id(record).simple()),"contract":4,
        })).collect();
    let image = admin.observe_for_verification().unwrap();
    assert_eq!(image["tables"]["owner_records"], json!(exact));
    admin.check_integrity().unwrap();
    let backup = directory.0.join("backup.json");
    let restore = directory.0.join("restore.redb");
    admin.backup(&backup).unwrap();
    rebase_semantic_proof::lifecycle::restore(&backup, &restore, model.clone()).unwrap();
    let restored = Store::open(&restore, model.clone()).unwrap();
    common::assert_restored_image(restored.observe_for_verification().unwrap(), image.clone());
    restored.check_integrity().unwrap();
    drop((left, right, other, admin));
    let reopened = Store::open(directory.file(), model.clone()).unwrap();
    assert_eq!(reopened.observe_for_verification().unwrap(), image);
    assert!(
        reopened
            .session(id(5), 0)
            .unwrap()
            .get(model.identity(), id(40))
            .unwrap()
            .is_some()
    );
    assert_eq!(
        reopened
            .session(id(4), 0)
            .unwrap()
            .mutate(&created)
            .unwrap()["result"]["records"][0]["record"],
        Value::Null
    );
}

#[test]
fn owner_only_producer_transfer_moves_all_outputs_without_rekeying_business_trees() {
    use rebase_semantic_proof::models::equipment::Equipment;
    let directory = Directory::new();
    let model = Arc::new(Prepared::<Equipment>::load().unwrap());
    let admin = setup(&directory, model.clone());
    let caller = admin.session(id(4), 0).unwrap();
    let sibling = admin.session(id(5), 0).unwrap();
    let seed = request(
        &caller,
        json!([
            {"op":"create","id":id(100),"contract":101,"fields":{"unit":1}},
            {"op":"create","id":id(101),"contract":205,"fields":{"pool":id(100),"at":"0","quantity":"10"}},
            {"op":"create","id":id(200),"contract":410,"fields":{"pool":id(100),"starts":"10","ends":"20","requested":"3","active":true}},
            {"op":"create","id":id(201),"contract":410,"fields":{"pool":id(100),"starts":"15","ends":"25","requested":"2","active":true}}
        ]),
        json!([]),
    );
    let mut allocated = 899;
    caller
        .mutate_with_ids(&seed, &mut || {
            allocated += 1;
            Ok(id(allocated))
        })
        .unwrap();
    assert_eq!(allocated, 903);
    let initial = admin.observe_for_verification().unwrap();
    for record in [200, 201] {
        let expected = if record == 200 {
            ("10", "3")
        } else {
            ("7", "2")
        };
        let derived = caller
            .get(model.identity(), id(record))
            .unwrap()
            .unwrap()
            .derived
            .unwrap();
        assert_eq!(
            derived,
            json!({"available_before":expected.0,"allocated":expected.1})
        );
    }
    caller.mutate(&transfer(&caller, 200, 4)).unwrap();
    let noop = admin.observe_for_verification().unwrap();
    for table in [
        "native_kv",
        "public_records",
        "owner_records",
        "query_epochs",
    ] {
        assert_eq!(
            noop["tables"][table], initial["tables"][table],
            "producer no-op changed {table}"
        );
    }
    caller.mutate(&transfer(&caller, 200, 6)).unwrap();
    let after = admin.observe_for_verification().unwrap();
    let producer = source(&after, 200);
    assert_eq!(producer["owner"], json!(id(6)));
    assert_eq!(producer["input"], source(&initial, 200)["input"]);
    assert_eq!(producer["derived"], source(&initial, 200)["derived"]);
    assert_ne!(producer["version"], source(&initial, 200)["version"]);
    let mut moved_outputs = 0;
    let mut amounts = Vec::new();
    for n in 900..=903 {
        let old = source(&initial, n);
        let current = source(&after, n);
        assert_eq!(current["input"], old["input"]);
        assert_eq!(current["tenant"], old["tenant"]);
        if current["input"]["producer"] == json!(id(200)) {
            moved_outputs += 1;
            assert_eq!(current["owner"], json!(id(6)));
            assert_eq!(current["version"], producer["version"]);
            amounts.push((
                current["input"]["at"].clone(),
                current["input"]["quantity"].clone(),
            ));
        } else {
            assert_eq!(current, old);
        }
        assert!(sibling.get(model.identity(), id(n)).unwrap().is_none());
    }
    assert_eq!(moved_outputs, 2);
    amounts.sort_by_key(|(at, _)| at.as_str().unwrap().parse::<u64>().unwrap());
    assert_eq!(
        amounts,
        vec![(json!("10"), json!("-3")), (json!("20"), json!("3"))]
    );
    for n in [100, 101, 201] {
        assert_eq!(
            source(&after, n),
            source(&initial, n),
            "unrelated source {n}"
        );
    }
    // Business roots/members, role identity and lifetime reservations derive from
    // source UUID/time; changing the authorization principal cannot change them.
    assert_eq!(
        native_rows_with_tag(&after, &["02", "03", "08", "09"]),
        native_rows_with_tag(&initial, &["02", "03", "08", "09"])
    );
    let exact: Vec<_> = [(4, 101, 100), (4, 205, 101), (4, 410, 201), (6, 410, 200)]
        .into_iter().map(|(owner, contract, record)| json!({
            "key":format!("{}{:04x}{}", id(owner).simple(), contract, id(record).simple()),"contract":contract,
        })).collect();
    assert_eq!(after["tables"]["owner_records"], json!(exact));
    assert!(sibling.get(model.identity(), id(200)).unwrap().is_some());
    assert!(sibling.get(model.identity(), id(100)).unwrap().is_none());
    for (at, expected) in [(1, "10"), (11, "7"), (16, "5"), (21, "8"), (26, "10")] {
        let root = RootRequest {
            model: model.identity().into(),
            owner: id(100),
            slot: 7,
            read: RootRead::Before { at },
        };
        assert_eq!(caller.root_read(&root).unwrap()["value"]["sum"], expected);
    }
    caller.mutate(&transfer(&caller, 200, 6)).unwrap();
    let noop = admin.observe_for_verification().unwrap();
    for table in ["native_kv", "owner_records", "query_epochs"] {
        assert_eq!(noop["tables"][table], after["tables"][table]);
    }
    admin.check_integrity().unwrap();
    let backup = directory.0.join("managed-backup.json");
    let restore = directory.0.join("managed-restore.redb");
    admin.backup(&backup).unwrap();
    rebase_semantic_proof::lifecycle::restore(&backup, &restore, model.clone()).unwrap();
    let restored = Store::open(&restore, model.clone()).unwrap();
    common::assert_restored_image(restored.observe_for_verification().unwrap(), noop.clone());
    restored.check_integrity().unwrap();
    drop((caller, sibling, admin));
    let reopened = Store::open(directory.file(), model).unwrap();
    assert_eq!(reopened.observe_for_verification().unwrap(), noop);
    reopened.check_integrity().unwrap();
}

#[test]
fn root_and_member_transfers_fence_pages_without_moving_or_hiding_declared_totals() {
    let directory = Directory::new();
    let admin = setup(&directory, Arc::new(PreparedModel::load().unwrap()));
    let left = admin.session(id(4), 0).unwrap();
    let right = admin.session(id(5), 0).unwrap();
    left.mutate(&request(&left, json!([
        {"op":"create","id":id(10),"owner":id(6),"contract":4,"fields":{"native_unit":1}},
        {"op":"create","id":id(20),"owner":id(6),"contract":8,"fields":{"account":id(10),"at":"0","amount":"2"}},
        {"op":"create","id":id(21),"owner":id(6),"contract":8,"fields":{"account":id(10),"at":"1","amount":"3"}}
    ]), json!([]))).unwrap();
    let root = RootRequest {
        model: left.model().identity().into(),
        owner: id(10),
        slot: 2,
        read: RootRead::Summary,
    };
    let summary = left.root_read(&root).unwrap();
    assert_eq!(summary["value"]["sum"], "5");
    let mut page = RootPageRequest {
        model: left.model().identity().into(),
        owner: id(10),
        slot: 2,
        limit: 1,
        candidate_budget: 1,
        cursor: None,
    };
    page.cursor = right
        .root_page(&page, &RootPagePolicy::default())
        .unwrap()
        .cursor;
    assert!(page.cursor.is_some());
    let tree = admin.observe_for_verification().unwrap();
    left.mutate(&transfer(&left, 20, 4)).unwrap();
    assert_eq!(
        right
            .root_page(&page, &RootPagePolicy::default())
            .unwrap_err()
            .code,
        "query_changed"
    );
    assert_eq!(right.root_read(&root).unwrap(), summary);
    page.cursor = None;
    page.limit = 10;
    page.candidate_budget = 10;
    let visible = right.root_page(&page, &RootPagePolicy::default()).unwrap();
    assert_eq!(visible.total, 2);
    assert_eq!(
        visible
            .occurrences
            .iter()
            .map(|row| row.record.id)
            .collect::<Vec<_>>(),
        vec![id(21)]
    );
    left.mutate(&transfer(&left, 10, 4)).unwrap();
    assert_eq!(right.root_read(&root).unwrap_err().code, "not_found");
    assert_eq!(
        right
            .root_page(&page, &RootPagePolicy::default())
            .unwrap_err()
            .code,
        "not_found"
    );
    assert_eq!(left.root_read(&root).unwrap(), summary);
    assert_eq!(
        native_rows_with_tag(&admin.observe_for_verification().unwrap(), &["02", "03"]),
        native_rows_with_tag(&tree, &["02", "03"])
    );
    admin.check_integrity().unwrap();
}

#[test]
fn transfer_and_reference_retarget_use_final_graph_in_both_command_orders() {
    for reverse in [false, true] {
        let directory = Directory::new();
        let admin = setup(&directory, Arc::new(PreparedModel::load().unwrap()));
        let caller = admin.session(id(4), 0).unwrap();
        caller.mutate(&request(&caller, json!([
            {"op":"create","id":id(10),"contract":4,"fields":{"native_unit":1}},
            {"op":"create","id":id(20),"contract":8,"fields":{"account":id(10),"at":"0","amount":"2"}}
        ]), json!([]))).unwrap();
        let version = caller
            .get(caller.model().identity(), id(20))
            .unwrap()
            .unwrap()
            .version;
        let before = admin.observe_for_verification().unwrap();
        let commands = |amount: &str| {
            let mut commands = vec![
                json!({"op":"create","id":id(11),"owner":id(6),"contract":4,"fields":{"native_unit":1}}),
                json!({"op":"update","id":id(20),"if_version":version,"owner":id(6),
                    "set":{"account":id(11),"amount":amount},"unset":[]}),
            ];
            if reverse {
                commands.reverse();
            }
            json!(commands)
        };
        // This failure is a final business invariant after source, owner, routes
        // and memberships are staged, so every table and receipt must roll back.
        assert_eq!(
            caller
                .mutate(&request(&caller, commands("-1"), json!([])))
                .unwrap_err()
                .code,
            "invariant"
        );
        assert_eq!(admin.observe_for_verification().unwrap(), before);
        caller
            .mutate(&request(&caller, commands("2"), json!([])))
            .unwrap();
        let image = admin.observe_for_verification().unwrap();
        assert_eq!(source(&image, 20)["owner"], json!(id(6)));
        assert_eq!(
            source(&image, 20)["input"],
            json!({"account":id(11),"at":"0","amount":"2"})
        );
        for (root, sum) in [(10, "0"), (11, "2")] {
            assert_eq!(
                caller
                    .root_read(&RootRequest {
                        model: caller.model().identity().into(),
                        owner: id(root),
                        slot: 2,
                        read: RootRead::Summary
                    })
                    .unwrap()["value"]["sum"],
                sum
            );
        }
        let root_version = caller
            .get(caller.model().identity(), id(11))
            .unwrap()
            .unwrap()
            .version;
        assert!(
            admin
                .mutate(&request(
                    &admin,
                    json!([{
                        "op":"delete","id":id(11),"if_version":root_version,
                    }]),
                    json!([])
                ))
                .is_err()
        );
        assert_eq!(admin.observe_for_verification().unwrap(), image);
        let old_version = caller
            .get(caller.model().identity(), id(10))
            .unwrap()
            .unwrap()
            .version;
        caller
            .mutate(&request(
                &caller,
                json!([{
                    "op":"delete","id":id(10),"if_version":old_version,
                }]),
                json!([]),
            ))
            .unwrap();
        admin.check_integrity().unwrap();
    }
}
