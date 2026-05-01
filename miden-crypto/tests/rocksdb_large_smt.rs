use miden_crypto::{
    EMPTY_WORD, Felt, ONE, Word, ZERO,
    merkle::{
        InnerNodeInfo,
        smt::{LargeSmt, LargeSmtError, RocksDbConfig, RocksDbSnapshotStorage, RocksDbStorage},
    },
};
use tempfile::TempDir;

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

    let mut inner_nodes: Vec<InnerNodeInfo> = smt.inner_nodes().unwrap().collect();
    inner_nodes.sort_by_key(|info| info.value);
    drop(smt);

    let reopened_storage = RocksDbStorage::open(RocksDbConfig::new(db_path)).unwrap();
    let smt = LargeSmt::<RocksDbStorage>::load(reopened_storage).unwrap();

    let mut inner_nodes_2: Vec<InnerNodeInfo> = smt.inner_nodes().unwrap().collect();
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
    let key = Word::new([ONE, ONE, ONE, ONE]);
    let new_value = Word::new([
        Felt::new_unchecked(2),
        Felt::new_unchecked(2),
        Felt::new_unchecked(2),
        Felt::new_unchecked(2),
    ]);
    smt.insert(key, new_value).unwrap();
    let root = smt.root();

    let mut inner_nodes: Vec<InnerNodeInfo> = smt.inner_nodes().unwrap().collect();
    inner_nodes.sort_by_key(|info| info.value);
    drop(smt);

    let reopened_storage = RocksDbStorage::open(RocksDbConfig::new(db_path)).unwrap();
    let smt = LargeSmt::<RocksDbStorage>::load(reopened_storage).unwrap();

    let mut inner_nodes_2: Vec<InnerNodeInfo> = smt.inner_nodes().unwrap().collect();
    inner_nodes_2.sort_by_key(|info| info.value);

    assert_eq!(inner_nodes.len(), inner_nodes_2.len());
    assert_eq!(inner_nodes, inner_nodes_2);
    assert_eq!(smt.root(), root);
}

#[test]
fn rocksdb_persistence_after_insert_batch_with_deletions() {
    // Create a tree with initial entries
    let entries = generate_entries(10_000);

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

    let mut inner_nodes: Vec<InnerNodeInfo> = smt.inner_nodes().unwrap().collect();
    inner_nodes.sort_by_key(|info| info.value);
    let num_leaves = smt.num_leaves();
    let num_entries = smt.num_entries();
    drop(smt);

    let reopened_storage = RocksDbStorage::open(RocksDbConfig::new(db_path)).unwrap();
    let smt = LargeSmt::<RocksDbStorage>::load(reopened_storage).unwrap();

    let mut inner_nodes_2: Vec<InnerNodeInfo> = smt.inner_nodes().unwrap().collect();
    inner_nodes_2.sort_by_key(|info| info.value);
    let num_leaves_2 = smt.num_leaves();
    let num_entries_2 = smt.num_entries();

    assert_eq!(inner_nodes.len(), inner_nodes_2.len());
    assert_eq!(inner_nodes, inner_nodes_2);
    assert_eq!(num_leaves, num_leaves_2);
    assert_eq!(num_entries, num_entries_2);
    assert_eq!(smt.root(), root, "Tree reconstruction failed - root mismatch after deletions");
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
