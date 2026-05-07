use alloc::{collections::BTreeSet, vec::Vec};

use rand::{RngExt, prelude::IteratorRandom, rng};

use super::{IN_MEMORY_DEPTH, MemoryStorage, SmtStorage, SmtStorageReader};
use crate::{
    EMPTY_WORD, Felt, ONE, Word,
    merkle::{
        InnerNodeInfo,
        smt::{
            LargeSmt, LeafIndex, SMT_DEPTH, SmtLeaf,
            full::{Smt, concurrent::COLS_PER_SUBTREE},
        },
    },
};

fn generate_entries(pair_count: u64) -> Vec<(Word, Word)> {
    (0..pair_count)
        .map(|i| {
            let leaf_index = ((i as f64 / pair_count as f64) * (pair_count as f64)) as u64;
            let key =
                Word::new([ONE, ONE, Felt::new_unchecked(i), Felt::new_unchecked(leaf_index)]);
            let value = Word::new([ONE, ONE, ONE, Felt::new_unchecked(i)]);
            (key, value)
        })
        .collect()
}

fn generate_updates(entries: Vec<(Word, Word)>, updates: usize) -> Vec<(Word, Word)> {
    const REMOVAL_PROBABILITY: f64 = 0.2;
    let mut rng = rng();
    assert!(
        entries.iter().map(|(key, _)| key).collect::<BTreeSet<_>>().len() == entries.len(),
        "Input entries contain duplicate keys!"
    );
    let mut sorted_entries: Vec<(Word, Word)> = entries
        .into_iter()
        .sample(&mut rng, updates)
        .into_iter()
        .map(|(key, _)| {
            let value = if rng.random_bool(REMOVAL_PROBABILITY) {
                EMPTY_WORD
            } else {
                Word::new([ONE, ONE, ONE, Felt::new_unchecked(rng.random())])
            };
            (key, value)
        })
        .collect();
    sorted_entries.sort_by_key(|(key, _)| key[3].as_canonical_u64());
    sorted_entries
}

fn create_equivalent_smts_for_testing<S: SmtStorage>(
    storage: S,
    entries: Vec<(Word, Word)>,
) -> (Smt, LargeSmt<S>) {
    let control_smt = Smt::with_entries(entries.clone()).unwrap();
    let large_smt = LargeSmt::<S>::with_entries(storage, entries).unwrap();
    (control_smt, large_smt)
}

#[test]
fn test_smt_get_value() {
    let storage = MemoryStorage::new();
    let key_1: Word = Word::from([ONE, ONE, ONE, ONE]);
    let key_2: Word = Word::from([2_u32, 2_u32, 2_u32, 2_u32]);

    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);
    let smt = LargeSmt::<_>::with_entries(storage, [(key_1, value_1), (key_2, value_2)]).unwrap();

    let returned_value_1 = smt.get_value(&key_1);
    let returned_value_2 = smt.get_value(&key_2);

    assert_eq!(value_1, returned_value_1);
    assert_eq!(value_2, returned_value_2);

    let key_no_value = Word::from([42_u32, 42_u32, 42_u32, 42_u32]);
    assert_eq!(EMPTY_WORD, smt.get_value(&key_no_value));
}

#[test]
fn test_equivalent_roots() {
    let storage = MemoryStorage::new();
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(storage, entries);
    assert_eq!(control_smt.root(), large_smt.root());
}

#[test]
fn test_equivalent_openings() {
    let storage = MemoryStorage::new();
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(storage, entries.clone());

    for (key, _) in entries {
        assert_eq!(control_smt.open(&key), large_smt.open(&key));
    }
}

#[test]
fn test_equivalent_entry_sets() {
    let storage = MemoryStorage::new();
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(storage, entries);

    let mut entries_control_smt_owned: Vec<(Word, Word)> = control_smt.entries().copied().collect();
    let mut entries_large_smt: Vec<(Word, Word)> = large_smt.entries().unwrap().collect();

    entries_control_smt_owned.sort_by_key(|k| k.0);
    entries_large_smt.sort_by_key(|k| k.0);

    assert_eq!(entries_control_smt_owned, entries_large_smt);
    assert_eq!(control_smt.num_leaves(), large_smt.num_leaves());
    assert_eq!(control_smt.num_entries(), large_smt.num_entries());
}

#[test]
fn test_equivalent_leaf_sets() {
    let storage = MemoryStorage::new();
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(storage, entries);

    let mut leaves_control_smt: Vec<(LeafIndex<SMT_DEPTH>, SmtLeaf)> =
        control_smt.leaves().map(|(idx, leaf_ref)| (idx, leaf_ref.clone())).collect();
    let mut leaves_large_smt: Vec<(LeafIndex<SMT_DEPTH>, SmtLeaf)> =
        large_smt.leaves().unwrap().collect();

    leaves_control_smt.sort_by_key(|k| k.0);
    leaves_large_smt.sort_by_key(|k| k.0);

    assert_eq!(leaves_control_smt.len(), leaves_large_smt.len());
    assert_eq!(leaves_control_smt, leaves_large_smt);
    assert_eq!(control_smt.num_leaves(), large_smt.num_leaves());
    assert_eq!(control_smt.num_entries(), large_smt.num_entries());
}

#[test]
fn test_equivalent_inner_nodes() {
    let storage = MemoryStorage::new();
    let entries = generate_entries(1000);
    let (control_smt, large_smt) = create_equivalent_smts_for_testing(storage, entries);

    let mut control_smt_inner_nodes: Vec<InnerNodeInfo> = control_smt.inner_nodes().collect();
    let mut large_smt_inner_nodes: Vec<InnerNodeInfo> = large_smt.inner_nodes().unwrap().collect();

    control_smt_inner_nodes.sort_by_key(|info| info.value);
    large_smt_inner_nodes.sort_by_key(|info| info.value);

    assert_eq!(control_smt_inner_nodes.len(), large_smt_inner_nodes.len());
    assert_eq!(control_smt_inner_nodes, large_smt_inner_nodes);
}

#[test]
fn test_compute_mutations() {
    let storage = MemoryStorage::new();
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;
    let entries = generate_entries(PAIR_COUNT);

    let control_smt = Smt::with_entries(entries.clone()).unwrap();
    let large_tree = LargeSmt::<_>::with_entries(storage, entries.clone()).unwrap();

    let updates = generate_updates(entries, 1000);
    let control_mutations = control_smt.compute_mutations(updates.clone()).unwrap();
    let mutations = large_tree.compute_mutations(updates).unwrap();
    assert_eq!(mutations.root(), control_mutations.root());
    assert_eq!(mutations.old_root(), control_mutations.old_root());
    assert_eq!(mutations.node_mutations(), control_mutations.node_mutations());
    assert_eq!(mutations.new_pairs(), control_mutations.new_pairs());
}

#[test]
fn test_empty_smt() {
    let storage = MemoryStorage::new();
    let large_smt = LargeSmt::<_>::new(storage).expect("Failed to create empty SMT");

    let empty_control_smt = Smt::new();
    assert_eq!(large_smt.root(), empty_control_smt.root(), "Empty SMT root mismatch");

    let random_key =
        Word::from([ONE, Felt::from_u32(2_u32), Felt::from_u32(3_u32), Felt::from_u32(4_u32)]);
    assert_eq!(
        large_smt.get_value(&random_key),
        EMPTY_WORD,
        "get_value on empty SMT should return EMPTY_WORD"
    );

    assert_eq!(large_smt.entries().unwrap().count(), 0, "Empty SMT should have no entries");
    assert_eq!(large_smt.leaves().unwrap().count(), 0, "Empty SMT should have no leaves");
    assert_eq!(
        large_smt.inner_nodes().unwrap().count(),
        0,
        "Empty SMT should have no inner nodes"
    );
}

#[test]
fn test_single_entry_smt() {
    let storage = MemoryStorage::new();
    let key = Word::new([ONE, ONE, ONE, ONE]);
    let value = Word::new([ONE; Word::NUM_ELEMENTS]);

    let mut smt = LargeSmt::<_>::with_entries(storage, [(key, value)]).unwrap();

    let control_smt_single = Smt::with_entries([(key, value)]).unwrap();
    assert_eq!(smt.root(), control_smt_single.root(), "Single entry SMT root mismatch");

    assert_eq!(smt.get_value(&key), value, "get_value for existing key failed");

    let other_key = Word::from([2_u32, 2_u32, 2_u32, 2_u32]);
    assert_eq!(smt.get_value(&other_key), EMPTY_WORD, "get_value for non-existing key failed");

    let entries: Vec<_> = smt.entries().unwrap().collect();
    assert_eq!(entries.len(), 1, "Single entry SMT should have one entry");
    assert_eq!(entries[0], (key, value), "Single entry SMT entry mismatch");

    let new_value = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);
    let mutations = smt.compute_mutations(vec![(key, new_value)]).unwrap();

    assert_eq!(
        smt.open(&key),
        control_smt_single.open(&key),
        "Opening before mutations mismatch"
    );

    smt.apply_mutations(mutations).unwrap();

    let control_smt_updated = Smt::with_entries([(key, new_value)]).unwrap();
    assert_eq!(smt.root(), control_smt_updated.root(), "Updated SMT root mismatch");
    assert_eq!(smt.get_value(&key), new_value, "get_value after update failed");

    assert_eq!(
        smt.open(&key),
        control_smt_updated.open(&key),
        "Opening after mutations mismatch"
    );

    let mutations_delete = smt.compute_mutations(vec![(key, EMPTY_WORD)]).unwrap();
    smt.apply_mutations(mutations_delete).unwrap();

    let empty_control_smt = Smt::new();
    assert_eq!(smt.root(), empty_control_smt.root(), "SMT root after deletion mismatch");
    assert_eq!(smt.get_value(&key), EMPTY_WORD, "get_value after deletion failed");
    assert_eq!(smt.entries().unwrap().count(), 0, "SMT should have no entries after deletion");
}

#[test]
fn test_duplicate_key_insertion() {
    let storage = MemoryStorage::new();
    let key = Word::from([ONE, ONE, ONE, ONE]);
    let value1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);

    let entries = vec![(key, value1), (key, value2)];

    let result = LargeSmt::<_>::with_entries(storage, entries);
    assert!(result.is_err(), "Expected an error when inserting duplicate keys");
}

#[test]
fn test_compute_mutations_rejects_duplicate_keys() {
    let storage = MemoryStorage::new();
    let smt = LargeSmt::<_>::with_entries(storage, vec![]).unwrap();

    let key = Word::from([ONE, ONE, ONE, ONE]);
    let value = Word::new([ONE; Word::NUM_ELEMENTS]);

    let entries = vec![(key, value), (key, value)];
    let result = smt.compute_mutations(entries);
    assert!(
        result.is_err(),
        "Expected an error when computing mutations with duplicate keys"
    );
}

#[test]
fn test_compute_mutations_rejects_interleaved_duplicate_keys() {
    let storage = MemoryStorage::new();
    let smt = LargeSmt::<_>::with_entries(storage, vec![]).unwrap();

    // Two different keys that map to the same leaf (same most significant felt)
    let key_1 = Word::from([ONE, ONE, ONE, Felt::new_unchecked(42)]);
    let key_2 = Word::from([
        Felt::new_unchecked(2),
        Felt::new_unchecked(2),
        Felt::new_unchecked(2),
        Felt::new_unchecked(42),
    ]);

    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);
    let value_3 = Word::new([Felt::from_u32(3_u32); Word::NUM_ELEMENTS]);

    // k1 appears at positions 0 and 2, interleaved with k2
    let entries = vec![(key_1, value_1), (key_2, value_2), (key_1, value_3)];
    let result = smt.compute_mutations(entries);
    assert!(
        result.is_err(),
        "Expected an error when computing mutations with interleaved duplicate keys"
    );
}

#[test]
fn test_insert_batch_rejects_duplicate_keys() {
    let storage = MemoryStorage::new();
    let mut smt = LargeSmt::<_>::with_entries(storage, vec![]).unwrap();

    let key = Word::from([ONE, ONE, ONE, ONE]);
    let value1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);

    let entries = vec![(key, value1), (key, value2)];
    let result = smt.insert_batch(entries);
    assert!(result.is_err(), "Expected an error when inserting batch with duplicate keys");
}

#[test]
fn test_delete_entry() {
    let storage = MemoryStorage::new();
    let key1 = Word::new([ONE, ONE, ONE, ONE]);
    let value1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let key2 = Word::from([2_u32, 2_u32, 2_u32, 2_u32]);
    let value2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);
    let key3 = Word::from([3_u32, 3_u32, 3_u32, 3_u32]);
    let value3 = Word::new([Felt::from_u32(3_u32); Word::NUM_ELEMENTS]);

    let initial_entries = vec![(key1, value1), (key2, value2), (key3, value3)];

    let mut smt = LargeSmt::<_>::with_entries(storage, initial_entries).unwrap();

    let mutations = smt.compute_mutations(vec![(key2, EMPTY_WORD)]).unwrap();
    smt.apply_mutations(mutations).unwrap();

    assert_eq!(
        smt.get_value(&key2),
        EMPTY_WORD,
        "get_value for deleted key should be EMPTY_WORD"
    );

    let current_entries: Vec<_> = smt.entries().unwrap().collect();
    assert!(
        !current_entries.iter().any(|(k, _v)| k == &key2),
        "Deleted key should not be in entries"
    );
    assert_eq!(current_entries.len(), 2, "SMT should have 2 entries after deletion");

    assert_eq!(smt.get_value(&key1), value1, "Value for key1 changed after deleting key2");
    assert_eq!(smt.get_value(&key3), value3, "Value for key3 changed after deleting key2");

    let remaining_entries = vec![(key1, value1), (key3, value3)];
    let control_smt_after_delete = Smt::with_entries(remaining_entries).unwrap();
    assert_eq!(smt.root(), control_smt_after_delete.root(), "SMT root mismatch after deletion");
}

#[test]
fn test_insert_entry() {
    let storage = MemoryStorage::new();
    let initial_entries = generate_entries(100);

    let mut large_smt = LargeSmt::<_>::with_entries(storage, initial_entries.clone()).unwrap();
    let mut control_smt = Smt::with_entries(initial_entries.clone()).unwrap();

    assert_eq!(large_smt.num_entries(), control_smt.num_entries(), "Number of entries mismatch");
    assert_eq!(large_smt.num_leaves(), control_smt.num_leaves(), "Number of leaves mismatch");

    let new_key = Word::from([100_u32, 100_u32, 100_u32, 100_u32]);
    let new_value = Word::new([Felt::from_u32(100_u32); Word::NUM_ELEMENTS]);

    let old_value = large_smt.insert(new_key, new_value).unwrap();
    let control_old_value = control_smt.insert(new_key, new_value).unwrap();
    assert_eq!(old_value, control_old_value, "Old values mismatch");
    assert_eq!(old_value, EMPTY_WORD, "Expected empty value");

    assert_eq!(large_smt.num_entries(), control_smt.num_entries(), "Number of entries mismatch");
    assert_eq!(large_smt.num_leaves(), control_smt.num_leaves(), "Number of leaves mismatch");

    assert_eq!(large_smt.get_value(&new_key), new_value, "Value mismatch");
    assert_eq!(control_smt.get_value(&new_key), new_value, "Value mismatch");

    assert_eq!(large_smt.root(), control_smt.root(), "Roots don't match after insert");

    let large_proof = large_smt.open(&new_key);
    let control_proof = control_smt.open(&new_key);
    assert_eq!(large_proof, control_proof, "Proofs don't match");

    for (key, _) in initial_entries {
        let large_proof = large_smt.open(&key);
        let control_proof = control_smt.open(&key);
        assert_eq!(large_proof, control_proof, "Proofs don't match for original key: {key:?}");
    }
}

#[test]
fn test_mutations_revert() {
    let storage = MemoryStorage::new();
    let mut smt = LargeSmt::<_>::new(storage).unwrap();

    let key_1: Word = Word::new([ONE, ONE, ONE, Felt::new_unchecked(1)]);
    let key_2: Word = Word::new([
        Felt::new_unchecked(2),
        Felt::new_unchecked(2),
        Felt::new_unchecked(2),
        Felt::new_unchecked(2),
    ]);
    let key_3: Word = Word::new([
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(3),
    ]);

    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([Felt::from_u32(2_u32); Word::NUM_ELEMENTS]);
    let value_3 = Word::new([Felt::from_u32(3_u32); Word::NUM_ELEMENTS]);

    smt.insert(key_1, value_1).unwrap();
    smt.insert(key_2, value_2).unwrap();

    let mutations = smt
        .compute_mutations(vec![(key_1, EMPTY_WORD), (key_2, value_1), (key_3, value_3)])
        .unwrap();

    let original_root = smt.root();
    let revert = smt.apply_mutations_with_reversion(mutations).unwrap();
    assert_eq!(revert.old_root, smt.root(), "reverse mutations old root did not match");
    assert_eq!(revert.root(), original_root, "reverse mutations new root did not match");

    smt.apply_mutations(revert).unwrap();

    assert_eq!(
        smt.root(),
        original_root,
        "SMT with applied revert mutations did not match original SMT"
    );
}

#[test]
fn test_insert_batch_matches_compute_apply() {
    let storage1 = MemoryStorage::new();
    let storage2 = MemoryStorage::new();

    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;
    let entries = generate_entries(PAIR_COUNT);

    // Create two identical trees
    let mut tree1 = LargeSmt::with_entries(storage1, entries.clone()).unwrap();
    let mut tree2 = LargeSmt::with_entries(storage2, entries.clone()).unwrap();

    // Generate updates
    let updates = generate_updates(entries, 1000);

    // Compute_mutations + apply_mutations
    let mutations = tree1.compute_mutations(updates.clone()).unwrap();
    let root1_before = tree1.root();
    tree1.apply_mutations(mutations).unwrap();
    let root1_after = tree1.root();

    // Insert_batch
    let root2_before = tree2.root();
    let root2_after = tree2.insert_batch(updates.clone()).unwrap();

    // Roots match at each step
    assert_eq!(root1_before, root2_before, "Initial roots should match");
    assert_eq!(root1_after, root2_after, "Final roots should match");

    // All values match
    for (key, _) in updates {
        let val1 = tree1.get_value(&key);
        let val2 = tree2.get_value(&key);
        assert_eq!(val1, val2, "Values should match for key {key:?}");
    }

    // Verify metadata
    assert_eq!(tree1.num_leaves(), tree2.num_leaves());
    assert_eq!(tree1.num_entries(), tree2.num_entries());
}

#[test]
fn test_insert_batch_empty_tree() {
    let storage = MemoryStorage::new();
    let mut smt = LargeSmt::new(storage).unwrap();

    let entries = vec![
        (
            Word::new([
                Felt::new_unchecked(1),
                Felt::new_unchecked(0),
                Felt::new_unchecked(0),
                Felt::new_unchecked(0),
            ]),
            Word::new([
                Felt::new_unchecked(10),
                Felt::new_unchecked(20),
                Felt::new_unchecked(30),
                Felt::new_unchecked(40),
            ]),
        ),
        (
            Word::new([
                Felt::new_unchecked(2),
                Felt::new_unchecked(0),
                Felt::new_unchecked(0),
                Felt::new_unchecked(0),
            ]),
            Word::new([
                Felt::new_unchecked(11),
                Felt::new_unchecked(22),
                Felt::new_unchecked(33),
                Felt::new_unchecked(44),
            ]),
        ),
    ];

    let new_root = smt.insert_batch(entries.clone()).unwrap();
    use crate::merkle::EmptySubtreeRoots;
    assert_ne!(new_root, *EmptySubtreeRoots::entry(SMT_DEPTH, 0));

    // Verify values were inserted
    for (key, value) in entries {
        assert_eq!(smt.get_value(&key), value);
    }
}

#[test]
fn test_insert_batch_with_deletions() {
    let storage = MemoryStorage::new();
    let mut smt = LargeSmt::new(storage).unwrap();

    // Initial data
    let key_1 = Word::new([ONE, ONE, ONE, Felt::new_unchecked(1)]);
    let key_2 = Word::new([
        Felt::new_unchecked(2),
        Felt::new_unchecked(2),
        Felt::new_unchecked(2),
        Felt::new_unchecked(2),
    ]);
    let key_3 = Word::new([
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(3),
    ]);

    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let value_2 = Word::new([Felt::new_unchecked(2); Word::NUM_ELEMENTS]);
    let value_3 = Word::new([Felt::new_unchecked(3); Word::NUM_ELEMENTS]);

    smt.insert(key_1, value_1).unwrap();
    smt.insert(key_2, value_2).unwrap();

    let initial_root = smt.root();

    // Batch update with insertions and deletions
    let updates = vec![(key_1, EMPTY_WORD), (key_2, value_1), (key_3, value_3)];

    let new_root = smt.insert_batch(updates).unwrap();
    assert_ne!(new_root, initial_root);

    // Verify the state
    assert_eq!(smt.get_value(&key_1), EMPTY_WORD);
    assert_eq!(smt.get_value(&key_2), value_1);
    assert_eq!(smt.get_value(&key_3), value_3);
}

#[test]
fn test_insert_batch_no_mutations() {
    let storage = MemoryStorage::new();
    let mut smt = LargeSmt::new(storage).unwrap();

    let key_1 = Word::new([ONE, ONE, ONE, Felt::new_unchecked(1)]);
    let value_1 = Word::new([ONE; Word::NUM_ELEMENTS]);

    smt.insert(key_1, value_1).unwrap();
    let root_before = smt.root();

    // Insert the same value again (no change)
    let root_after = smt.insert_batch(vec![(key_1, value_1)]).unwrap();

    assert_eq!(root_before, root_after);
}

#[test]
fn test_insert_batch_large_dataset() {
    // Test insert_batch with a large dataset
    let storage = MemoryStorage::new();
    let mut smt = LargeSmt::new(storage).unwrap();

    const LARGE_COUNT: u64 = COLS_PER_SUBTREE * 128;
    let entries = generate_entries(LARGE_COUNT);

    let new_root = smt.insert_batch(entries.clone()).unwrap();
    use crate::merkle::EmptySubtreeRoots;
    assert_ne!(new_root, *EmptySubtreeRoots::entry(SMT_DEPTH, 0));

    // Spot check some values
    for (key, value) in entries.iter().step_by(100) {
        assert_eq!(smt.get_value(key), *value);
    }

    assert_eq!(smt.num_entries(), LARGE_COUNT as usize);
}

// IN-MEMORY LAYOUT TESTS
// ================================================================================================

#[test]
fn test_flat_layout_index_zero_unused_in_instance() {
    use crate::merkle::Poseidon2;

    let storage = MemoryStorage::new();
    let mut smt = LargeSmt::<_>::new(storage).unwrap();

    let in_memory_nodes = smt.in_memory_nodes();

    // Index 0 should always be EMPTY_WORD (unused)
    assert_eq!(in_memory_nodes[0], EMPTY_WORD, "Index 0 should be EMPTY_WORD (unused)");

    let key = Word::new([ONE, ONE, ONE, Felt::new_unchecked(1)]);
    let value = Word::new([
        Felt::new_unchecked(42),
        Felt::new_unchecked(43),
        Felt::new_unchecked(44),
        Felt::new_unchecked(45),
    ]);
    smt.insert(key, value).unwrap();

    let in_memory_nodes = smt.in_memory_nodes();
    assert_eq!(in_memory_nodes[0], EMPTY_WORD, "Index 0 should be EMPTY_WORD (unused)");

    // The root hash is computed from children at indices 2 and 3
    let computed_root = Poseidon2::merge(&[in_memory_nodes[2], in_memory_nodes[3]]);
    assert_eq!(computed_root, smt.root(), "Root should equal hash(children[2], children[3])");
}

#[test]
fn test_flat_layout_after_insertion() {
    use crate::merkle::{EmptySubtreeRoots, Poseidon2};

    // Insert a value and verify the flat layout is updated correctly
    let storage = MemoryStorage::new();
    let mut smt = LargeSmt::<_>::new(storage).unwrap();

    let key = Word::new([ONE, ONE, ONE, Felt::new_unchecked(1)]);
    let value = Word::new([
        Felt::new_unchecked(42),
        Felt::new_unchecked(43),
        Felt::new_unchecked(44),
        Felt::new_unchecked(45),
    ]);

    smt.insert(key, value).unwrap();

    let in_memory_nodes = smt.in_memory_nodes();

    // Index 0 should still be unused
    assert_eq!(in_memory_nodes[0], EMPTY_WORD, "Index 0 should remain EMPTY_WORD");

    let depth_1_empty = *EmptySubtreeRoots::entry(SMT_DEPTH, 1);
    let changed = in_memory_nodes[2] != depth_1_empty || in_memory_nodes[3] != depth_1_empty;
    assert!(changed, "At least one of root's children should have changed after insertion");

    // Verify root can be computed from children at indices 2 and 3
    let computed_root = Poseidon2::merge(&[in_memory_nodes[2], in_memory_nodes[3]]);
    assert_eq!(
        computed_root,
        smt.root(),
        "Root should equal hash of children at indices 2 and 3"
    );
}

#[test]
fn test_flat_layout_children_relationship() {
    use crate::merkle::{EmptySubtreeRoots, NodeIndex, Poseidon2};

    // Insert multiple values and verify parent-child relationships in the flat layout
    let storage = MemoryStorage::new();
    let mut smt = LargeSmt::<_>::new(storage).unwrap();

    // Generate random leaf indices
    let mut rng = rng();
    let num_samples = 50;
    let leaf_indices: Vec<u64> =
        (0..num_samples).map(|_| rng.random::<u64>() % (1 << 20)).collect();

    for leaf_value in &leaf_indices {
        let key = Word::new([ONE, ONE, ONE, Felt::new_unchecked(*leaf_value)]);
        let value = Word::new([Felt::new_unchecked(*leaf_value * 10); 4]);
        smt.insert(key, value).unwrap();
    }

    let in_memory_nodes = smt.in_memory_nodes();

    // Verify root separately (depth 0, value 0, memory_idx 1)
    let root_left = in_memory_nodes[2];
    let root_right = in_memory_nodes[3];
    let root_hash = Poseidon2::merge(&[root_left, root_right]);
    assert_eq!(root_hash, smt.root(), "Root hash should match computed hash from children");

    for &leaf_value in &leaf_indices {
        // Trace path from depth 1 down to in-memory depth
        for depth in 1..IN_MEMORY_DEPTH {
            let node_value = leaf_value >> (SMT_DEPTH - depth);
            let node_idx = NodeIndex::new(depth, node_value).unwrap();
            let memory_idx = super::to_memory_index(&node_idx);

            // Get children from flat layout
            let left_child = in_memory_nodes[memory_idx * 2];
            let right_child = in_memory_nodes[memory_idx * 2 + 1];

            // Calculate expected empty hash for children at this depth
            let child_depth = depth + 1;
            let empty_hash = *EmptySubtreeRoots::entry(SMT_DEPTH, child_depth);

            // Determine which child is on the path to our leaf
            let is_right_child = ((leaf_value >> (SMT_DEPTH - depth - 1)) & 1) == 1;

            // Select the child on the path and verify it's non-empty
            let child_on_path = if is_right_child { right_child } else { left_child };
            assert_ne!(
                child_on_path, empty_hash,
                "Child on path should be non-empty at depth {depth}, value {node_value} (on path to leaf {leaf_value})"
            );

            // Verify the parent-child hash relationship
            let node_hash = Poseidon2::merge(&[left_child, right_child]);
            assert_eq!(
                in_memory_nodes[memory_idx], node_hash,
                "Stored hash at memory_idx {memory_idx} should match computed hash from children at depth {depth}, value {node_value}"
            );
        }
    }
}

/// Verifies that a snapshot produced by `MemoryStorage::reader()` returns correct depth-24 roots
/// from `get_depth24()`, and that loading a `LargeSmt` from that snapshot reconstructs the same
/// root as the original tree.
#[test]
fn test_memory_storage_snapshot_depth24() {
    use crate::merkle::NodeIndex;

    let entries = generate_entries(50);
    let storage = MemoryStorage::new();
    let smt = LargeSmt::<MemoryStorage>::with_entries(storage, entries).unwrap();
    let expected_root = smt.root();

    let snapshot = smt.storage.reader().unwrap();

    // The depth-24 entries must be non-empty for a non-empty tree.
    let depth24 = snapshot.get_depth24().unwrap();
    assert!(!depth24.is_empty(), "snapshot must expose depth-24 roots for a non-empty tree");

    // Every returned entry must sit exactly at IN_MEMORY_DEPTH.
    for (position, _hash) in &depth24 {
        let index = NodeIndex::new(IN_MEMORY_DEPTH, *position).unwrap();
        assert_eq!(
            index.depth(),
            IN_MEMORY_DEPTH,
            "depth-24 entry at position {position} has wrong depth"
        );
    }

    // Loading a LargeSmt from the snapshot must reproduce the same root.
    let reloaded = LargeSmt::<_>::load(snapshot).unwrap();
    assert_eq!(
        reloaded.root(),
        expected_root,
        "root reconstructed from snapshot must match the original"
    );
}

#[test]
fn reader_shares_in_memory_top_until_writer_mutates() {
    let entries = generate_entries(1000);
    let storage = MemoryStorage::new();
    let mut smt = LargeSmt::<MemoryStorage>::with_entries(storage, entries).unwrap();

    let reader = smt.reader().unwrap();
    let reader_root = reader.root();
    assert_eq!(smt.in_memory_nodes().as_ptr(), reader.in_memory_nodes().as_ptr());

    let key = Word::new([ONE, ONE, Felt::new_unchecked(10_000), Felt::new_unchecked(10_000)]);
    let value = Word::new([ONE, ONE, ONE, Felt::new_unchecked(10_000)]);
    smt.insert(key, value).unwrap();

    assert_ne!(smt.in_memory_nodes().as_ptr(), reader.in_memory_nodes().as_ptr());
    assert_ne!(smt.root(), reader_root);
    assert_eq!(reader.root(), reader_root);
}

#[test]
fn clone_shares_in_memory_top_until_mutation() {
    let entries = generate_entries(1000);
    let storage = MemoryStorage::new();
    let smt = LargeSmt::<MemoryStorage>::with_entries(storage, entries).unwrap();

    let mut clone = smt.clone();
    let original_root = smt.root();
    assert_eq!(smt.in_memory_nodes().as_ptr(), clone.in_memory_nodes().as_ptr());

    let key = Word::new([ONE, ONE, Felt::new_unchecked(10_001), Felt::new_unchecked(10_001)]);
    let value = Word::new([ONE, ONE, ONE, Felt::new_unchecked(10_001)]);
    clone.insert(key, value).unwrap();

    assert_ne!(smt.in_memory_nodes().as_ptr(), clone.in_memory_nodes().as_ptr());
    assert_eq!(smt.root(), original_root);
    assert_ne!(clone.root(), original_root);
}
