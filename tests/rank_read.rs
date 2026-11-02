use rebase_semantic_proof::{
    binding::Calculation,
    index::TimeKey,
    indexes::standard::{FINANCIAL, Leaf},
    native_codec::{self, Address, Key, Stored},
    native_slice::Workspace,
    storage::{Database, ReadableTable, TableDefinition},
    tree::{self, Root},
    tree_read::{self, Limits},
};
use std::{num::NonZeroUsize, path::PathBuf};
use uuid::Uuid;
const KV: TableDefinition<&[u8], &[u8]> = TableDefinition::new("rank_test");
struct Fixture {
    db: Database,
    path: PathBuf,
    owner: Address,
    source: Vec<(i64, Address)>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
fn limits() -> Limits {
    Limits {
        max_nodes: 10000,
        max_bytes: 10_000_000,
        batch_keys: NonZeroUsize::new(64).unwrap(),
        concurrency: NonZeroUsize::new(8).unwrap(),
    }
}
fn fixture(n: usize) -> Fixture {
    let path = std::env::temp_dir().join(format!("rank-{}.redb", Uuid::new_v4()));
    let db = Database::create(&path).unwrap();
    let owner = Address::new(Uuid::from_u128(90000), 1);
    let write = db.begin_write().unwrap();
    let mut table = write.open_table(KV).unwrap();
    let key = Key::Root(owner);
    table
        .insert(
            key.encode(),
            &native_codec::encode(
                &key,
                &Stored::Root(Root::empty(FINANCIAL, Uuid::new_v4()).unwrap()),
            )
            .unwrap(),
        )
        .unwrap();
    let mut source = vec![];
    for i in 0..n {
        let address = Address::new(Uuid::from_u128((i / 2 + 1) as u128), (i % 2 + 1) as u16);
        let at = ((i * 37) % 17) as i64;
        source.push((at, address));
        let mut ws = Workspace::new(
            |key: &[u8]| Ok(table.get(key)?.map(|v| v.value().to_vec())),
            1_000_000,
        );
        tree::insert(
            &mut ws,
            owner,
            address,
            TimeKey(at),
            Leaf::Financial(i as i128),
        )
        .unwrap();
        let batch = ws.finish().unwrap();
        drop(ws);
        for (key, value) in batch {
            if let Some(value) = value {
                table.insert(key, &value).unwrap();
            } else {
                table.remove(key).unwrap();
            }
        }
    }
    drop(table);
    write.commit().unwrap();
    source.sort();
    Fixture {
        db,
        path,
        owner,
        source,
    }
}
#[test]
fn raw_rank_windows_match_independent_authored_order() {
    for count in [0, 50, 100, 1000] {
        let f = fixture(count);
        let read = f.db.begin_read().unwrap();
        let table = read.open_table(KV).unwrap();
        for (start, end) in [
            (0, count),
            (0, 0),
            (count, count + 3),
            (3, 11),
            (count / 2, count / 2 + 7),
        ] {
            let page = tree_read::rank_window::<Calculation, _>(
                &table,
                f.owner,
                start as u64..end as u64,
                limits(),
            )
            .unwrap();
            let expected: Vec<_> = f
                .source
                .iter()
                .enumerate()
                .skip(start)
                .take(end - start)
                .map(|(rank, (at, id))| (rank as u64, *at, *id))
                .collect();
            let actual: Vec<_> = page
                .occurrences
                .iter()
                .map(|n| (n.rank, n.key.value.0, n.address))
                .collect();
            assert_eq!(actual, expected);
            assert_eq!(page.total, count as u64);
            if count == 1000 && start == 3 {
                assert!(page.counters.gets < 100);
            }
        }
    }
}
#[test]
fn limits_reject_whole_result_and_reads_keep_their_snapshot() {
    let f = fixture(100);
    let read = f.db.begin_read().unwrap();
    let table = read.open_table(KV).unwrap();
    let before =
        tree_read::rank_window::<Calculation, _>(&table, f.owner, 0..100, limits()).unwrap();
    let mut small = limits();
    small.max_nodes = 2;
    assert!(tree_read::rank_window::<Calculation, _>(&table, f.owner, 0..100, small).is_err());
    small = limits();
    small.max_bytes = 30;
    assert!(tree_read::rank_window::<Calculation, _>(&table, f.owner, 0..100, small).is_err());
    let write = f.db.begin_write().unwrap();
    let mut changed = write.open_table(KV).unwrap();
    let key = Key::Root(f.owner);
    let bytes = changed.get(key.encode()).unwrap().unwrap().value().to_vec();
    let Stored::Root(mut root) = native_codec::decode(&key, &bytes).unwrap() else {
        panic!()
    };
    root.size += 1;
    changed
        .insert(
            key.encode(),
            &native_codec::encode(&key, &Stored::Root(root)).unwrap(),
        )
        .unwrap();
    drop(changed);
    write.commit().unwrap();
    let again =
        tree_read::rank_window::<Calculation, _>(&table, f.owner, 0..100, limits()).unwrap();
    assert_eq!(
        before
            .occurrences
            .iter()
            .map(|n| n.address)
            .collect::<Vec<_>>(),
        again
            .occurrences
            .iter()
            .map(|n| n.address)
            .collect::<Vec<_>>()
    );
    let fresh = f.db.begin_read().unwrap();
    assert!(
        tree_read::rank_window::<Calculation, _>(
            &fresh.open_table(KV).unwrap(),
            f.owner,
            0..100,
            limits()
        )
        .is_err()
    );
}
#[test]
fn discovered_cycles_cross_roots_and_forged_sizes_are_rejected() {
    for corruption in 0..3 {
        let f = fixture(50);
        let write = f.db.begin_write().unwrap();
        let mut table = write.open_table(KV).unwrap();
        let key = Key::Root(f.owner);
        let bytes = table.get(key.encode()).unwrap().unwrap().value().to_vec();
        let Stored::Root(root) = native_codec::decode(&key, &bytes).unwrap() else {
            panic!()
        };
        let key = Key::Node(root.head.unwrap());
        let bytes = table.get(key.encode()).unwrap().unwrap().value().to_vec();
        let Stored::Node(mut node) = native_codec::decode(&key, &bytes).unwrap() else {
            panic!()
        };
        match corruption {
            0 => node.left = root.head,
            1 => node.root = Address::new(Uuid::new_v4(), 1),
            _ => node.size += 1,
        }
        table
            .insert(
                key.encode(),
                &serde_json::to_vec(&Stored::Node(node)).unwrap(),
            )
            .unwrap();
        drop(table);
        write.commit().unwrap();
        let read = f.db.begin_read().unwrap();
        assert!(
            tree_read::rank_window::<Calculation, _>(
                &read.open_table(KV).unwrap(),
                f.owner,
                0..50,
                limits()
            )
            .is_err()
        );
    }
}

#[test]
fn adjacent_windows_compose_and_reader_does_not_write() {
    let f = fixture(100);
    let read = f.db.begin_read().unwrap();
    let table = read.open_table(KV).unwrap();
    let root_key = Key::Root(f.owner).encode();
    let before = table.get(&root_key).unwrap().unwrap().value().to_vec();
    let mut joined = vec![];
    for start in (0..100).step_by(7) {
        let page = tree_read::rank_window::<Calculation, _>(
            &table,
            f.owner,
            start..(start + 7).min(100),
            limits(),
        )
        .unwrap();
        joined.extend(
            page.occurrences
                .into_iter()
                .map(|n| (n.key.value.0, n.address)),
        );
    }
    assert_eq!(joined, f.source);
    let all = tree_read::rank_window::<Calculation, _>(&table, f.owner, 0..100, limits()).unwrap();
    assert!(all.counters.batches < all.counters.gets);
    assert_eq!(all.counters.gets, 101);
    assert_eq!(
        table.get(&root_key).unwrap().unwrap().value(),
        before.as_slice()
    );
    let mut serial = limits();
    serial.batch_keys = NonZeroUsize::new(1).unwrap();
    let serial = tree_read::rank_window::<Calculation, _>(&table, f.owner, 0..100, serial).unwrap();
    assert_eq!(serial.counters.gets, serial.counters.batches);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Counts;
impl rebase_semantic_proof::binding::Binding for Counts {
    type Index = rebase_semantic_proof::indexes::count_only::CountOnly;
    type Input = <Calculation as rebase_semantic_proof::binding::Binding>::Input;
    type Derived = <Calculation as rebase_semantic_proof::binding::Binding>::Derived;
    type Outcome = ();
    const NAME: &'static str = "rank-counts";
    const BEHAVIOR: &'static str = "rank-counts-1";
    fn declarations()
    -> rebase_semantic_proof::native_slice::Result<Vec<rebase_semantic_proof::model::Contract>>
    {
        Ok(vec![])
    }
    fn engine()
    -> rebase_semantic_proof::native_slice::Result<rebase_semantic_proof::native_slice::Model> {
        Calculation::engine()
    }
    fn valid_derived(input: &Self::Input, derived: Option<&Self::Derived>) -> bool {
        Calculation::valid_derived(input, derived)
    }
    fn published_shape(code: u16) -> serde_json::Value {
        Calculation::published_shape(code)
    }
    fn settle_changes<
        L: FnMut(&[u8]) -> rebase_semantic_proof::native_slice::Result<Option<Vec<u8>>>,
    >(
        _: &mut rebase_semantic_proof::native_slice::Attempt<L, Self>,
        _: &rebase_semantic_proof::model::Prepared<Self>,
        _: rebase_semantic_proof::native_slice::Context,
        _: &[rebase_semantic_proof::native_slice::ModelChange<Self>],
        _: &mut rebase_semantic_proof::native_slice::Population,
        _: Uuid,
        _: &mut dyn FnMut() -> rebase_semantic_proof::native_slice::Result<Uuid>,
    ) -> rebase_semantic_proof::native_slice::Result<()> {
        unreachable!("tree-only binding")
    }
    fn check(
        _: &rebase_semantic_proof::local::Store<Self>,
    ) -> rebase_semantic_proof::native_slice::Result<serde_json::Value> {
        unreachable!("tree-only binding")
    }
}
#[test]
fn non_time_strings_with_unit_summaries_have_independent_structural_rank() {
    use rebase_semantic_proof::{
        indexes::count_only::COUNT_ONLY, native_codec::StoredValue, native_slice::Attempt,
    };
    let f = fixture(0);
    let write = f.db.begin_write().unwrap();
    let mut table = write.open_table(KV).unwrap();
    let key = Key::Root(f.owner);
    table
        .insert(
            key.encode(),
            &native_codec::encode_for::<Counts>(
                &key,
                &StoredValue::Root(Root::empty(COUNT_ONLY, Uuid::new_v4()).unwrap()),
            )
            .unwrap(),
        )
        .unwrap();
    let mut source = vec![];
    for (i, word) in ["z", "a", "same", "aa", "same", "é", "", "same"]
        .iter()
        .enumerate()
    {
        let address = Address::new(Uuid::from_u128((i / 2 + 1) as u128), (i % 2 + 1) as u16);
        source.push((word.to_string(), address));
        let mut ws = Attempt::<_, Counts>::new(
            |key: &[u8]| Ok(table.get(key)?.map(|v| v.value().to_vec())),
            10000,
        );
        tree::insert(&mut ws, f.owner, address, word.to_string(), ()).unwrap();
        let batch = ws.finish().unwrap();
        drop(ws);
        for (key, value) in batch {
            if let Some(value) = value {
                table.insert(key, &value).unwrap();
            } else {
                table.remove(key).unwrap();
            }
        }
    }
    drop(table);
    write.commit().unwrap();
    source.sort();
    let read = f.db.begin_read().unwrap();
    let table = read.open_table(KV).unwrap();
    for start in 0..=source.len() {
        let page = tree_read::rank_window::<Counts, _>(
            &table,
            f.owner,
            start as u64..(start + 3) as u64,
            limits(),
        )
        .unwrap();
        assert_eq!(page.total, source.len() as u64);
        assert_eq!(
            page.occurrences
                .into_iter()
                .map(|n| (n.key.value, n.address))
                .collect::<Vec<_>>(),
            source
                .iter()
                .skip(start)
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn output_allocation_is_bounded_before_reserving_slots() {
    let f = fixture(1);
    let write = f.db.begin_write().unwrap();
    let mut table = write.open_table(KV).unwrap();
    let key = Key::Root(f.owner);
    let bytes = table.get(key.encode()).unwrap().unwrap().value().to_vec();
    let Stored::Root(mut root) = native_codec::decode(&key, &bytes).unwrap() else {
        panic!()
    };
    root.size = 1_000_000_000;
    table
        .insert(
            key.encode(),
            &native_codec::encode(&key, &Stored::Root(root)).unwrap(),
        )
        .unwrap();
    drop(table);
    write.commit().unwrap();
    let read = f.db.begin_read().unwrap();
    let table = read.open_table(KV).unwrap();
    let mut bounded = limits();
    bounded.max_nodes = 1_000_000_000;
    bounded.max_bytes = 4096;
    let error =
        tree_read::rank_window::<Calculation, _>(&table, f.owner, 0..1_000_000_000, bounded)
            .unwrap_err();
    assert_eq!(error.code, "work_limit");
}
#[test]
fn exact_node_budget_and_header_only_empty_windows() {
    let f = fixture(50);
    let read = f.db.begin_read().unwrap();
    let table = read.open_table(KV).unwrap();
    let mut bounded = limits();
    bounded.max_nodes = 50;
    let all = tree_read::rank_window::<Calculation, _>(&table, f.owner, 0..50, bounded).unwrap();
    assert_eq!(all.counters.gets, 51);
    bounded.max_nodes = 49;
    assert!(tree_read::rank_window::<Calculation, _>(&table, f.owner, 0..50, bounded).is_err());
    bounded.max_nodes = 1;
    for window in [0..0, 25..25, 50..60, 100..200] {
        let empty =
            tree_read::rank_window::<Calculation, _>(&table, f.owner, window, bounded).unwrap();
        assert!(empty.occurrences.is_empty());
        assert_eq!(empty.counters.gets, 1);
    }
}
#[test]
fn narrow_window_checks_discovered_child_size_and_parent() {
    for size_corruption in [true, false] {
        let f = fixture(50);
        let write = f.db.begin_write().unwrap();
        let mut table = write.open_table(KV).unwrap();
        let key = Key::Root(f.owner);
        let bytes = table.get(key.encode()).unwrap().unwrap().value().to_vec();
        let Stored::Root(root) = native_codec::decode(&key, &bytes).unwrap() else {
            panic!()
        };
        let key = Key::Node(root.head.unwrap());
        let bytes = table.get(key.encode()).unwrap().unwrap().value().to_vec();
        let Stored::Node(head) = native_codec::decode(&key, &bytes).unwrap() else {
            panic!()
        };
        let key = Key::Node(head.right.unwrap());
        let bytes = table.get(key.encode()).unwrap().unwrap().value().to_vec();
        let Stored::Node(mut child) = native_codec::decode(&key, &bytes).unwrap() else {
            panic!()
        };
        if size_corruption {
            child.size += 1;
        } else {
            child.parent = None;
        }
        table
            .insert(
                key.encode(),
                &native_codec::encode(&key, &Stored::Node(child)).unwrap(),
            )
            .unwrap();
        drop(table);
        write.commit().unwrap();
        let read = f.db.begin_read().unwrap();
        assert!(
            tree_read::rank_window::<Calculation, _>(
                &read.open_table(KV).unwrap(),
                f.owner,
                0..1,
                limits()
            )
            .is_err()
        );
    }
}
