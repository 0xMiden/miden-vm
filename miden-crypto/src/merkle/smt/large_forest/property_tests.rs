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

    // ENTRIES
    // ============================================================================================

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

    // ADD LINEAGES
    // ============================================================================================

    /// This test ensures that `add_lineages` produces the same results as adding each lineage
    /// individually via `add_lineage`.
    #[test]
    fn add_lineages_matches_repeated_add_lineage(
        lineages in prop::collection::vec(arbitrary_lineage(), 0..10)
            .prop_map(|v| v.into_iter().unique().collect::<Vec<_>>()),
        version in arbitrary_version(),
        entries in prop::collection::vec(arbitrary_batch(), 0..10),
    ) {
        // Build a forest update batch containing all lineages with their respective entries.
        let mut batch = crate::merkle::smt::SmtForestUpdateBatch::empty();
        for (i, lineage) in lineages.iter().enumerate() {
            if let Some(entry_batch) = entries.get(i) {
                *batch.operations(*lineage) = entry_batch.clone();
            } else {
                batch.operations(*lineage);
            }
        }

        // Add all lineages at once via add_lineages.
        let mut forest_batch = LargeSmtForest::new(ForestInMemoryBackend::new()).map_err(to_fail)?;
        let batch_results = forest_batch.add_lineages(version, batch).map_err(to_fail)?;

        // Add each lineage individually via add_lineage.
        let mut forest_individual = LargeSmtForest::new(ForestInMemoryBackend::new()).map_err(to_fail)?;
        let mut individual_results = Vec::new();
        for (i, lineage) in lineages.iter().enumerate() {
            let entry_batch = entries.get(i).cloned().unwrap_or_default();
            let result = forest_individual.add_lineage(*lineage, version, entry_batch).map_err(to_fail)?;
            individual_results.push(result);
        }

        // Both should yield the same number of results.
        prop_assert_eq!(batch_results.len(), individual_results.len());

        // For each lineage, verify the roots match and get returns the same values.
        for (i, lineage) in lineages.iter().enumerate() {
            let batch_root = batch_results.iter().find(|r| r.lineage() == *lineage);
            let individual_root = &individual_results[i];

            let batch_root = batch_root.unwrap();
            prop_assert_eq!(batch_root.root(), individual_root.root());
            prop_assert_eq!(batch_root.version(), individual_root.version());

            // Verify get returns the same values for all keys in the entries.
            let tree = TreeId::new(*lineage, version);
            if let Some(entry_batch) = entries.get(i) {
                for op in entry_batch.clone().into_iter() {
                    let batch_val = forest_batch.get(tree, op.key()).map_err(to_fail)?;
                    let individual_val = forest_individual.get(tree, op.key()).map_err(to_fail)?;
                    prop_assert_eq!(batch_val, individual_val);
                }
            }
        }
    }
}
