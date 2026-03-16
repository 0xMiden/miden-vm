#![cfg(test)]
//! This module contains the property tests for the SMT forest.

use alloc::vec::Vec;

use itertools::Itertools;
use proptest::prelude::*;

use crate::{
    EMPTY_WORD,
    merkle::smt::{
        ForestInMemoryBackend, LargeSmtForest, Smt, TreeEntry, TreeId,
        large_forest::test_utils::{
            arbitrary_batch, arbitrary_lineage, arbitrary_version, to_fail,
        },
    },
};

// ENTRIES
// ================================================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    /// This test ensures that the `entries` iterator for the forest always returns the exact same
    /// values as the `entries` iterator over a basic SMT with the same state.
    #[test]
    fn entries_correct(
        lineage in arbitrary_lineage(),
        version in arbitrary_version(),
        entries_v1 in arbitrary_batch(),
        entries_v2 in arbitrary_batch(),
    ) {
        // We now create a forest and add the lineage to it using the first set of entries.
        let mut forest = LargeSmtForest::new(ForestInMemoryBackend::new()).map_err(to_fail)?;
        forest.add_lineage(lineage, version, entries_v1.clone()).map_err(to_fail)?;
        let tree_info =
            forest.update_tree(lineage, version + 1, entries_v2.clone()).map_err(to_fail)?;

        // We then create two auxiliary trees to work with, to compare our results against.
        let mut tree_v1 = Smt::new();
        let tree_v1_mutations =
            tree_v1.compute_mutations(Vec::from(entries_v1).into_iter()).map_err(to_fail)?;
        tree_v1.apply_mutations(tree_v1_mutations).map_err(to_fail)?;

        let mut tree_v2 = tree_v1.clone();
        let tree_v2_mutations =
            tree_v2.compute_mutations(Vec::from(entries_v2).into_iter()).map_err(to_fail)?;
        tree_v2.apply_mutations(tree_v2_mutations.clone()).map_err(to_fail)?;

        // Iterating over the historical version of the lineage in the forest should produce exactly
        // the same entries as iterating over V1 of our test tree.
        let old_version = TreeId::new(lineage, version);
        let forest_entries = forest
            .entries(old_version)
            .map_err(to_fail)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(to_fail)?
            .into_iter()
            .sorted()
            .collect_vec();
        let tree_entries = tree_v1
            .entries()
            .map(|(k, v)| TreeEntry { key: *k, value: *v })
            .sorted()
            .collect_vec();
        prop_assert_eq!(forest_entries, tree_entries);

        // Iterating over the newest version of the lineage in the forest should provide exactly the
        // same entries as iterating over V2 of our test tree.
        let current_version = if tree_v2_mutations.is_empty() {
            TreeId::new(lineage, version)
        } else {
            TreeId::new(lineage, tree_info.version())
        };
        let forest_entries = forest
            .entries(current_version)
            .map_err(to_fail)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(to_fail)?
            .into_iter()
            .sorted()
            .collect_vec();
        let tree_entries = tree_v2
            .entries()
            .map(|(k, v)| TreeEntry { key: *k, value: *v })
            .sorted()
            .collect_vec();
        prop_assert_eq!(forest_entries, tree_entries);
    }

    /// This test ensures that the `entries` iterator for the forest will never return entries where
    /// the value is the empty word.
    #[test]
    fn entries_never_yields_empty_values(
        lineage in arbitrary_lineage(),
        version in arbitrary_version(),
        entries_v1 in arbitrary_batch(),
        entries_v2 in arbitrary_batch(),
    ) {
        // We now create a forest and add the lineage to it using the first set of entries.
        let mut forest = LargeSmtForest::new(ForestInMemoryBackend::new()).map_err(to_fail)?;
        let root_1 = forest.add_lineage(lineage, version, entries_v1.clone()).map_err(to_fail)?;
        let root_2 = forest.update_tree(lineage, version + 1, entries_v2.clone()).map_err(to_fail)?;

        // Iterating over the historical version of the lineage in the forest should produce exactly
        // the same entries as iterating over V1 of our test tree.
        let old_version = TreeId::new(lineage, version);
        let entries = forest
            .entries(old_version)
            .map_err(to_fail)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(to_fail)?;
        prop_assert!(entries.iter().all(|e| e.value != EMPTY_WORD), "EMPTY_WORD entry encountered");

        // Iterating over the newest version of the lineage in the forest should provide exactly the
        // same entries as iterating over V2 of our test tree.
        let current_version = if root_1 == root_2 {
            TreeId::new(lineage, version)
        } else {
            TreeId::new(lineage, root_2.version())
        };
        let entries = forest
            .entries(current_version)
            .map_err(to_fail)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(to_fail)?;
        prop_assert!(entries.iter().all(|e| e.value != EMPTY_WORD), "EMPTY_WORD entry encountered");
    }
}
