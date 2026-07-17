use miden_crypto::{
    EMPTY_WORD, Felt, ONE, Word, ZERO,
    merkle::{
        InnerNodeInfo,
        smt::{
            LargeSmt, LargeSmtError, LargeSmtResult, RocksDbConfig, RocksDbSnapshotStorage,
            RocksDbStorage, SmtStorageReader, StorageError,
        },
    },
};
use rocksdb::{DB, IteratorMode, Options};
use tempfile::TempDir;

const LEAVES_CF: &str = "leaves";
const SUBTREE_CFS: [&str; 6] = ["st16", "st24", "st32", "st40", "st48", "st56"];
const ROCKSDB_CFS: [&str; 9] = [
    "in_mem_depth",
    "leaves",
    "st16",
    "st24",
    "st32",
    "st40",
    "st48",
    "st56",
    "metadata",
];

fn setup_storage() -> (RocksDbStorage, TempDir) {
    let temp_dir = tempfile::Builder::new()
        .prefix("test_smt_rocksdb_")
        .tempdir()
        .expect("Failed to create temporary directory for RocksDB test");

    let db_path = temp_dir.path().to_path_buf();

    let storage = RocksDbStorage::open(RocksDbConfig::new(db_path))
        .expect("Failed to open RocksDbStorage in temporary directory");
    (storage, temp_dir)
}

fn generate_entries(pair_count: usize) -> Vec<(Word, Word)> {
    (0..pair_count)
        .map(|i| {
            let key = Word::new([
                ONE,
                ONE,
                Felt::new_unchecked(i as u64),
                Felt::new_unchecked(i as u64 % 1000),
            ]);
            let value = Word::new([ONE, ONE, ONE, Felt::new_unchecked(i as u64)]);
            (key, value)
        })
        .collect()
}

fn open_raw_db(path: &std::path::Path) -> DB {
    let opts = Options::default();
    DB::open_cf(&opts, path, ROCKSDB_CFS).expect("failed to open raw RocksDB handle")
}

fn corrupt_leaf_value(path: &std::path::Path, leaf_index: u64) {
    let db = open_raw_db(path);
    let cf = db.cf_handle(LEAVES_CF).expect("leaves column family missing");
    db.put_cf(cf, leaf_index.to_be_bytes(), b"not a valid leaf")
        .expect("failed to corrupt leaf value");
}

fn corrupt_first_subtree_value(path: &std::path::Path) {
    let db = open_raw_db(path);

    for cf_name in SUBTREE_CFS {
        let cf = db.cf_handle(cf_name).expect("subtree column family missing");
        if let Some(result) = db.iterator_cf(cf, IteratorMode::Start).next() {
            let (key, _value) = result.expect("failed to read subtree entry");
            db.put_cf(cf, key, b"not a valid subtree")
                .expect("failed to corrupt subtree value");
            return;
        }
    }

    panic!("expected at least one subtree entry");
}

#[test]
fn rocksdb_sanity_insert_and_get() {
    let (storage, _tmp) = setup_storage();
    let mut smt = LargeSmt::<RocksDbStorage>::new(storage).unwrap();

    let key = Word::new([ONE, ONE, ONE, ONE]);
    let val = Word::new([ONE; Word::NUM_ELEMENTS]);

    let prev = smt.insert(key, val).unwrap();
    assert_eq!(prev, EMPTY_WORD);
    assert_eq!(smt.get_value(&key), val);
}

#[test]
fn rocksdb_reader_is_detached_snapshot() {
    fn assert_snapshot_reader(_: &LargeSmt<RocksDbSnapshotStorage>) {}

    let entries = generate_entries(1000);
    let existing_key = entries[10].0;
    let existing_value = entries[10].1;
    let (storage, _tmp) = setup_storage();
    let mut smt = LargeSmt::<RocksDbStorage>::with_entries(storage, entries).unwrap();

    let reader = smt.reader().unwrap();
    assert_snapshot_reader(&reader);

    let reader_root = reader.root();
    let key = Word::new([ONE, ONE, Felt::new_unchecked(10_000), Felt::new_unchecked(10_000)]);
    let value = Word::new([ONE, ONE, ONE, Felt::new_unchecked(10_000)]);

    assert_eq!(reader.get_value(&key), EMPTY_WORD);

    smt.insert(key, value).unwrap();

    assert_ne!(smt.root(), reader_root);
    assert_eq!(reader.root(), reader_root);
    assert_eq!(reader.get_value(&key), EMPTY_WORD);
    assert_eq!(reader.get_value(&existing_key), existing_value);

    drop(smt);

    assert_eq!(reader.root(), reader_root);
    assert_eq!(reader.get_value(&key), EMPTY_WORD);
    assert_eq!(reader.get_value(&existing_key), existing_value);
}

#[test]
fn rocksdb_persistence_reopen() {
    let entries = generate_entries(1000);

    let (initial_storage, temp_dir_guard) = setup_storage();
    let db_path = temp_dir_guard.path().to_path_buf();

    let smt = LargeSmt::<RocksDbStorage>::with_entries(initial_storage, entries).unwrap();
    let root = smt.root();

    let mut inner_nodes: Vec<InnerNodeInfo> =
        smt.inner_nodes().unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    inner_nodes.sort_by_key(|info| info.value);
    drop(smt);

    let reopened_storage = RocksDbStorage::open(RocksDbConfig::new(db_path)).unwrap();
    let smt = LargeSmt::<RocksDbStorage>::load(reopened_storage).unwrap();

    let mut inner_nodes_2: Vec<InnerNodeInfo> =
        smt.inner_nodes().unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    inner_nodes_2.sort_by_key(|info| info.value);

    assert_eq!(inner_nodes.len(), inner_nodes_2.len());
    assert_eq!(inner_nodes, inner_nodes_2);
    assert_eq!(smt.root(), root);
}

#[test]
fn rocksdb_persistence_after_insertion() {
    let entries = generate_entries(1000);

    let (initial_storage, temp_dir_guard) = setup_storage();
    let db_path = temp_dir_guard.path().to_path_buf();

    let mut smt = LargeSmt::<RocksDbStorage>::with_entries(initial_storage, entries).unwrap();
    let initial_num_leaves = smt.num_leaves();
    let initial_num_entries = smt.num_entries();
    let key = Word::new([ONE, ONE, Felt::new_unchecked(20_000), Felt::new_unchecked(20_000)]);
    let new_value = Word::new([
        Felt::new_unchecked(2),
        Felt::new_unchecked(2),
        Felt::new_unchecked(2),
        Felt::new_unchecked(2),
    ]);
    let previous_value = smt.insert(key, new_value).unwrap();
    assert_eq!(previous_value, EMPTY_WORD);
    assert_eq!(smt.get_value(&key), new_value);
    assert_eq!(smt.num_leaves(), initial_num_leaves + 1);
    assert_eq!(smt.num_entries(), initial_num_entries + 1);
    let root = smt.root();
    let num_leaves = smt.num_leaves();
    let num_entries = smt.num_entries();

    let mut inner_nodes: Vec<InnerNodeInfo> =
        smt.inner_nodes().unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    inner_nodes.sort_by_key(|info| info.value);
    drop(smt);

    let reopened_storage = RocksDbStorage::open(RocksDbConfig::new(db_path)).unwrap();
    let smt = LargeSmt::<RocksDbStorage>::load(reopened_storage).unwrap();

    let mut inner_nodes_2: Vec<InnerNodeInfo> =
        smt.inner_nodes().unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    inner_nodes_2.sort_by_key(|info| info.value);

    assert_eq!(inner_nodes.len(), inner_nodes_2.len());
    assert_eq!(inner_nodes, inner_nodes_2);
    assert_eq!(smt.root(), root);
    assert_eq!(smt.num_leaves(), num_leaves);
    assert_eq!(smt.num_entries(), num_entries);
    assert_eq!(smt.get_value(&key), new_value);
}

#[test]
fn rocksdb_persistence_after_insert_batch_with_deletions() {
    // Create a tree with initial entries
    let entries = generate_entries(10_000);
    let unchanged_key = entries[1_500].0;
    let unchanged_value = entries[1_500].1;
    let updated_key = entries[1_501].0;
    let updated_value = Word::new([
        Felt::new_unchecked(3),
        Felt::new_unchecked(3),
        Felt::new_unchecked(3),
        Felt::new_unchecked(3),
    ]);
    let deleted_key = entries[100].0;
    let newly_inserted_key =
        Word::new([ONE, ONE, Felt::new_unchecked(20_000), Felt::new_unchecked(20_000 % 1000)]);
    let newly_inserted_value = Word::new([ONE, ONE, ONE, Felt::new_unchecked(20_000)]);

    let (initial_storage, temp_dir_guard) = setup_storage();
    let db_path = temp_dir_guard.path().to_path_buf();

    let mut smt = LargeSmt::<RocksDbStorage>::with_entries(initial_storage, entries).unwrap();

    // Create a batch that includes both insertions and deletions
    let mut batch_entries: Vec<(Word, Word)> = Vec::new();

    // Add new entries
    for i in 20_000..25_000 {
        let key = Word::new([
            ONE,
            ONE,
            Felt::new_unchecked(i as u64),
            Felt::new_unchecked(i as u64 % 1000),
        ]);
        let value = Word::new([ONE, ONE, ONE, Felt::new_unchecked(i as u64)]);
        batch_entries.push((key, value));
    }

    // Update an existing entry that is not deleted below
    batch_entries.push((updated_key, updated_value));

    // Delete some existing entries
    for i in 0..1000 {
        let key = Word::new([
            ONE,
            ONE,
            Felt::new_unchecked(i as u64),
            Felt::new_unchecked(i as u64 % 1000),
        ]);
        batch_entries.push((key, EMPTY_WORD));
    }

    smt.insert_batch(batch_entries).unwrap();
    let root = smt.root();

    let mut inner_nodes: Vec<InnerNodeInfo> =
        smt.inner_nodes().unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    inner_nodes.sort_by_key(|info| info.value);
    let num_leaves = smt.num_leaves();
    let num_entries = smt.num_entries();
    drop(smt);

    let reopened_storage = RocksDbStorage::open(RocksDbConfig::new(db_path)).unwrap();
    let smt = LargeSmt::<RocksDbStorage>::load(reopened_storage).unwrap();

    let mut inner_nodes_2: Vec<InnerNodeInfo> =
        smt.inner_nodes().unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    inner_nodes_2.sort_by_key(|info| info.value);
    let num_leaves_2 = smt.num_leaves();
    let num_entries_2 = smt.num_entries();

    assert_eq!(inner_nodes.len(), inner_nodes_2.len());
    assert_eq!(inner_nodes, inner_nodes_2);
    assert_eq!(num_leaves, num_leaves_2);
    assert_eq!(num_entries, num_entries_2);
    assert_eq!(smt.root(), root, "Tree reconstruction failed - root mismatch after deletions");
    assert_eq!(smt.get_value(&unchanged_key), unchanged_value);
    assert_eq!(smt.get_value(&newly_inserted_key), newly_inserted_value);
    assert_eq!(smt.get_value(&updated_key), updated_value);
    assert_eq!(smt.get_value(&deleted_key), EMPTY_WORD);
}

#[test]
fn rocksdb_load_with_root_validates_correctly() {
    let entries = generate_entries(1000);

    let (initial_storage, temp_dir_guard) = setup_storage();
    let db_path = temp_dir_guard.path().to_path_buf();

    let smt = LargeSmt::<RocksDbStorage>::with_entries(initial_storage, entries).unwrap();
    let expected_root = smt.root();
    drop(smt);

    // Reopen with the correct expected root
    let reopened_storage = RocksDbStorage::open(RocksDbConfig::new(db_path)).unwrap();
    let smt = LargeSmt::load_with_root(reopened_storage, expected_root)
        .expect("Should successfully open with correct root");

    assert_eq!(smt.root(), expected_root);
}

#[test]
fn rocksdb_load_with_root_mismatch_returns_error() {
    let entries = generate_entries(1000);

    let (initial_storage, temp_dir_guard) = setup_storage();
    let db_path = temp_dir_guard.path().to_path_buf();

    let smt = LargeSmt::<RocksDbStorage>::with_entries(initial_storage, entries).unwrap();
    let actual_root = smt.root();
    drop(smt);

    // Try to reopen with a wrong root
    let wrong_root = Word::new([ONE; 4]);
    assert_ne!(wrong_root, actual_root, "Test requires different roots");

    let reopened_storage = RocksDbStorage::open(RocksDbConfig::new(db_path)).unwrap();
    let result = LargeSmt::load_with_root(reopened_storage, wrong_root);

    assert!(result.is_err(), "Should fail with wrong root");
    match result.unwrap_err() {
        LargeSmtError::RootMismatch { expected, actual } => {
            assert_eq!(expected, wrong_root);
            assert_eq!(actual, actual_root);
        },
        other => panic!("Expected RootMismatch error, got {other:?}"),
    }
}

#[test]
fn rocksdb_load_skips_validation() {
    let entries = generate_entries(1000);

    let (initial_storage, temp_dir_guard) = setup_storage();
    let db_path = temp_dir_guard.path().to_path_buf();

    let smt = LargeSmt::<RocksDbStorage>::with_entries(initial_storage, entries).unwrap();
    let expected_root = smt.root();
    drop(smt);

    // load should succeed
    let reopened_storage = RocksDbStorage::open(RocksDbConfig::new(db_path)).unwrap();
    let smt =
        LargeSmt::load(reopened_storage).expect("Should successfully open without validation");

    assert_eq!(smt.root(), expected_root);
}

#[test]
fn rocksdb_iter_leaves_returns_error_for_corrupt_leaf() {
    let entries = generate_entries(1);
    let leaf_index = entries[0].0[3].as_canonical_u64();

    let (initial_storage, temp_dir_guard) = setup_storage();
    let db_path = temp_dir_guard.path().to_path_buf();

    let smt = LargeSmt::<RocksDbStorage>::with_entries(initial_storage, entries).unwrap();
    drop(smt);

    corrupt_leaf_value(&db_path, leaf_index);

    let storage = RocksDbStorage::open(RocksDbConfig::new(db_path)).unwrap();
    let result = storage.iter_leaves().unwrap().collect::<Result<Vec<_>, StorageError>>();

    assert!(
        matches!(result, Err(StorageError::Value(_))),
        "expected corrupt leaf deserialization to fail, got {result:?}",
    );
}

#[test]
fn rocksdb_iter_subtrees_returns_error_for_corrupt_subtree() {
    let entries = generate_entries(1000);

    let (initial_storage, temp_dir_guard) = setup_storage();
    let db_path = temp_dir_guard.path().to_path_buf();

    let smt = LargeSmt::<RocksDbStorage>::with_entries(initial_storage, entries).unwrap();
    drop(smt);

    corrupt_first_subtree_value(&db_path);

    let storage = RocksDbStorage::open(RocksDbConfig::new(db_path)).unwrap();
    let result = storage.iter_subtrees().unwrap().collect::<Result<Vec<_>, StorageError>>();

    assert!(
        matches!(result, Err(StorageError::Subtree(_))),
        "expected corrupt subtree deserialization to fail, got {result:?}",
    );
}

#[test]
fn rocksdb_new_fails_on_non_empty_storage() {
    let entries = generate_entries(1000);

    let (initial_storage, temp_dir_guard) = setup_storage();
    let db_path = temp_dir_guard.path().to_path_buf();

    // Create a tree with data
    let smt = LargeSmt::<RocksDbStorage>::with_entries(initial_storage, entries).unwrap();
    drop(smt);

    // Reopen storage and try to use new() - should fail
    let reopened_storage = RocksDbStorage::open(RocksDbConfig::new(db_path)).unwrap();
    let result = LargeSmt::new(reopened_storage);

    assert!(result.is_err(), "new() should fail on non-empty storage");
    match result.unwrap_err() {
        LargeSmtError::StorageNotEmpty => {},
        other => panic!("Expected StorageNotEmpty error, got {other:?}"),
    }
}

// Tests entry/leaf counts through the full lifecycle of a leaf:
// Empty -> Single -> Multiple -> Single -> Empty
#[test]
fn rocksdb_entry_count_through_leaf_lifecycle() {
    let (storage, temp_dir_guard) = setup_storage();
    let db_path = temp_dir_guard.path().to_path_buf();

    let mut smt = LargeSmt::new(storage).unwrap();

    // Two keys that map to the same leaf
    let key1 = Word::new([ZERO, ZERO, ZERO, ZERO]);
    let key2 = Word::new([ONE, ZERO, ZERO, ZERO]);
    let value = Word::new([ONE, ONE, ONE, ONE]);

    // Initial state: empty
    assert_eq!(smt.num_entries(), 0);
    assert_eq!(smt.num_leaves(), 0);

    // Add first key: Empty -> Single
    let mutations = smt.compute_mutations([(key1, value)]).unwrap();
    smt.apply_mutations(mutations).unwrap();
    assert_eq!(smt.num_entries(), 1, "should have 1 entry after first insert");
    assert_eq!(smt.num_leaves(), 1, "should have 1 leaf after first insert");

    // Add second key to same leaf: Single -> Multiple
    let mutations = smt.compute_mutations([(key2, value)]).unwrap();
    smt.apply_mutations(mutations).unwrap();
    assert_eq!(smt.num_entries(), 2, "should have 2 entries after second insert");
    assert_eq!(smt.num_leaves(), 1, "should still have 1 leaf (now Multiple)");

    // Remove first key: Multiple -> Single
    let mutations = smt.compute_mutations([(key1, EMPTY_WORD)]).unwrap();
    smt.apply_mutations(mutations).unwrap();
    assert_eq!(smt.num_entries(), 1, "should have 1 entry after removal from Multiple");
    assert_eq!(smt.num_leaves(), 1, "should still have 1 leaf (now Single)");

    // Remove second key: Single -> Empty
    let mutations = smt.compute_mutations([(key2, EMPTY_WORD)]).unwrap();
    smt.apply_mutations(mutations).unwrap();
    assert_eq!(smt.num_entries(), 0, "should have 0 entries after removing all");
    assert_eq!(smt.num_leaves(), 0, "should have 0 leaves after removing all");

    // Verify persistence through the lifecycle
    drop(smt);
    let storage = RocksDbStorage::open(RocksDbConfig::new(&db_path)).unwrap();
    let smt = LargeSmt::load(storage).unwrap();

    assert_eq!(smt.num_entries(), 0, "persisted entry count should be 0");
    assert_eq!(smt.num_leaves(), 0, "persisted leaf count should be 0");
}

#[test]
fn rocksdb_inner_nodes_match_full_smt() {
    use miden_crypto::merkle::smt::Smt;

    let entries = generate_entries(1000);
    let control_smt = Smt::with_entries(entries.clone()).unwrap();

    let (storage, _tmp) = setup_storage();
    let large_smt = LargeSmt::<RocksDbStorage>::with_entries(storage, entries).unwrap();

    let mut control_nodes: Vec<InnerNodeInfo> = control_smt.inner_nodes().collect();
    let mut rocksdb_nodes: Vec<InnerNodeInfo> = large_smt
        .inner_nodes()
        .unwrap()
        .try_fold(Vec::new(), |mut acc, info| {
            acc.push(info?);
            LargeSmtResult::Ok(acc)
        })
        .unwrap();
    control_nodes.sort_by_key(|info| info.value);
    rocksdb_nodes.sort_by_key(|info| info.value);

    assert_eq!(control_nodes.len(), rocksdb_nodes.len());
    assert_eq!(control_nodes, rocksdb_nodes);
}
