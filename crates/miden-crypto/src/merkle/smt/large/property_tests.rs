use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use proptest::prelude::*;

use super::MemoryStorage;
use crate::{
    EMPTY_WORD, Felt, ONE, Word, ZERO,
    merkle::smt::{LargeSmt, LeafIndex, SMT_DEPTH},
};

// GENERATORS
// ================================================================================================

fn arb_felt() -> impl Strategy<Value = Felt> {
    prop_oneof![any::<u64>().prop_map(Felt::new_unchecked), Just(ZERO), Just(ONE),]
}

fn arb_word() -> impl Strategy<Value = Word> {
    prop::array::uniform4(arb_felt()).prop_map(Word::new)
}

/// Generates unique key-value pairs
fn arb_entries(min_size: usize, max_size: usize) -> impl Strategy<Value = Vec<(Word, Word)>> {
    prop::collection::vec((arb_word(), arb_word()), min_size..=max_size).prop_map(move |entries| {
        // Ensure uniqueness of entries as `LargeSmt::with_entries` returns an error if multiple
        // values exist for the same key.
        let mut used_indices = BTreeSet::new();
        let mut used_keys = BTreeSet::new();
        let mut result = Vec::new();

        for (key, value) in entries {
            let leaf_index = LeafIndex::<SMT_DEPTH>::from(key).position();
            if used_indices.insert(leaf_index) && used_keys.insert(key) {
                result.push((key, value));
            }
        }

        result
    })
}

/// Generates updates based on existing entries.
fn arb_updates(
    existing_entries: Vec<(Word, Word)>,
    min_updates: usize,
    max_updates: usize,
) -> impl Strategy<Value = Vec<(Word, Word)>> {
    let existing_keys: Vec<Word> = existing_entries.iter().map(|(k, _)| *k).collect();
    let has_existing = !existing_keys.is_empty();

    // Generate raw update params: (is_new_key, is_deletion, idx_seed, random_key, random_val)
    prop::collection::vec(
        (any::<bool>(), any::<bool>(), any::<usize>(), arb_word(), arb_word()),
        min_updates..=max_updates,
    )
    .prop_map(move |raw_updates| {
        let mut updates = BTreeMap::new();

        for (is_new_key, is_deletion, idx_seed, rand_key, rand_val) in raw_updates {
            let key = if has_existing && !is_new_key {
                // Update existing key
                existing_keys[idx_seed % existing_keys.len()]
            } else {
                // Use random key
                rand_key
            };

            // Determine value
            let value = if is_deletion { EMPTY_WORD } else { rand_val };

            updates.insert(key, value);
        }

        updates.into_iter().collect()
    })
}

// TESTS
// ================================================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn prop_insert_batch_matches_compute_apply(
        (initial_entries, updates) in arb_entries(1, 100)
            .prop_flat_map(|entries| {
                let updates = arb_updates(entries.clone(), 1, 50);
                (Just(entries), updates)
            })
    ) {
        run_insert_batch_matches_compute_apply(initial_entries, updates)?;
    }
}

fn run_insert_batch_matches_compute_apply(
    initial_entries: Vec<(Word, Word)>,
    updates: Vec<(Word, Word)>,
) -> Result<(), TestCaseError> {
    let storage1 = MemoryStorage::new();
    let storage2 = MemoryStorage::new();

    // Create two identical trees
    let mut tree1 = LargeSmt::with_entries(storage1, initial_entries.clone()).unwrap();
    let mut tree2 = LargeSmt::with_entries(storage2, initial_entries.clone()).unwrap();
    let root1 = tree1.root();
    let root2 = tree2.root();

    // Compute mutations -> apply mutations
    let mutations = tree1.compute_mutations(updates.clone()).unwrap();
    tree1.apply_mutations(mutations).unwrap();
    let new_root1 = tree1.root();

    // Insert_batch
    let new_root2 = tree2.insert_batch(updates.clone()).unwrap();

    // Verification

    // Roots match at each step
    prop_assert_eq!(root1, root2, "Initial roots should match");
    prop_assert_eq!(new_root1, new_root2, "Final roots should match");

    // Verify all touched keys have correct values in both trees
    for (key, _) in updates {
        let val1 = tree1.get_value(&key);
        let val2 = tree2.get_value(&key);
        prop_assert_eq!(val1, val2, "Values should match for key {:?}", key);
    }

    // Verify all initial keys (if not updated) are still consistent
    for (key, _) in initial_entries {
        let val1 = tree1.get_value(&key);
        let val2 = tree2.get_value(&key);
        prop_assert_eq!(val1, val2, "Values for initial keys should match");
    }

    // Verify metadata
    prop_assert_eq!(tree1.num_leaves(), tree2.num_leaves());
    prop_assert_eq!(tree1.num_entries(), tree2.num_entries());

    Ok(())
}
