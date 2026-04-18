#![cfg(test)]
//! This module contains the property tests for the SMT forest.

use alloc::vec::Vec;

use itertools::Itertools;
use proptest::prelude::*;

use crate::{
    EMPTY_WORD, Word,
    merkle::smt::{
        Backend, ForestConfig, ForestInMemoryBackend, ForestOperation, LargeSmtForest,
        LargeSmtForestError, LineageId, RootInfo, Smt, SmtForestUpdateBatch, SmtUpdateBatch,
        TreeId,
        large_forest::test_utils::{
            apply_batch, arbitrary_batch, arbitrary_distinct_lineages, arbitrary_lineage,
            arbitrary_non_empty_word, arbitrary_version, arbitrary_word, assert_lineage_metadata,
            assert_tree_queries_match, batch_keys, build_tree, sorted_forest_entries,
            sorted_tree_entries, to_fail,
        },
    },
};

// PROPERTY TESTS
// ================================================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    /// This test validates constructor behavior when loading from a pre-populated backend. The
    /// forest should load the latest tree state, but not reconstruct historical versions.
    #[test]
    fn new_loads_latest_backend_state_without_history(
        (lineage_1, lineage_2) in arbitrary_distinct_lineages(),
        version in arbitrary_version(),
        entries_1 in arbitrary_batch(),
        entries_2 in arbitrary_batch(),
        updates_1 in arbitrary_batch(),
        query_key in arbitrary_word(),
    ) {
        let mut backend = ForestInMemoryBackend::new();
        backend.add_lineage(lineage_1, version, entries_1.clone()).map_err(to_fail)?;
        backend.add_lineage(lineage_2, version, entries_2.clone()).map_err(to_fail)?;
        backend.update_tree(lineage_1, version + 1, updates_1.clone()).map_err(to_fail)?;

        let forest = LargeSmtForest::new(backend).map_err(to_fail)?;

        let tree_1_v1 = build_tree(entries_1.clone())?;
        let mut expected_tree_1 = tree_1_v1.clone();
        apply_batch(&mut expected_tree_1, updates_1.clone())?;
        let expected_tree_2 = build_tree(entries_2.clone())?;
        let latest_version_1 = if expected_tree_1.root() == tree_1_v1.root() {
            version
        } else {
            version + 1
        };

        let mut sample_keys = batch_keys(&entries_1);
        sample_keys.extend(batch_keys(&entries_2));
        sample_keys.extend(batch_keys(&updates_1));
        sample_keys.push(query_key);
        sample_keys.sort();
        sample_keys.dedup();

        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage_1, latest_version_1),
            &expected_tree_1,
            &sample_keys,
            true,
        )?;
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage_2, version),
            &expected_tree_2,
            &sample_keys,
            true,
        )?;
        prop_assert_eq!(forest.lineage_count(), 2);
        prop_assert_eq!(forest.tree_count(), 2);
        prop_assert_eq!(forest.latest_version(lineage_1), Some(latest_version_1));
        prop_assert_eq!(forest.latest_root(lineage_1), Some(expected_tree_1.root()));
        let expected_root_info = if latest_version_1 == version {
            RootInfo::Missing
        } else {
            RootInfo::LatestVersion(expected_tree_1.root())
        };
        prop_assert_eq!(
            forest.root_info(TreeId::new(lineage_1, version + 1)),
            expected_root_info
        );
    }

    /// This test validates history retention under custom configuration and the semantics of
    /// explicit truncation.
    #[test]
    fn with_config_and_truncate_limit_retained_versions(
        lineage in arbitrary_lineage(),
        version in arbitrary_version(),
        key_1 in arbitrary_word(),
        key_2 in arbitrary_word(),
        key_3 in arbitrary_word(),
        key_4 in arbitrary_word(),
        value_1 in arbitrary_non_empty_word(),
        value_2 in arbitrary_non_empty_word(),
        value_3 in arbitrary_non_empty_word(),
        value_4 in arbitrary_non_empty_word(),
    ) {
        prop_assume!(key_1 != key_2 && key_1 != key_3 && key_1 != key_4);
        prop_assume!(key_2 != key_3 && key_2 != key_4);
        prop_assume!(key_3 != key_4);

        let config = ForestConfig::default().with_max_history_versions(2);
        let mut forest =
            LargeSmtForest::with_config(ForestInMemoryBackend::new(), config).map_err(to_fail)?;
        forest
            .add_lineage(
                lineage,
                version,
                SmtUpdateBatch::new([ForestOperation::insert(key_1, value_1)].into_iter()),
            )
            .map_err(to_fail)?;
        forest
            .update_tree(
                lineage,
                version + 1,
                SmtUpdateBatch::new([ForestOperation::insert(key_2, value_2)].into_iter()),
            )
            .map_err(to_fail)?;
        forest
            .update_tree(
                lineage,
                version + 2,
                SmtUpdateBatch::new([ForestOperation::insert(key_3, value_3)].into_iter()),
            )
            .map_err(to_fail)?;
        forest
            .update_tree(
                lineage,
                version + 3,
                SmtUpdateBatch::new([ForestOperation::insert(key_4, value_4)].into_iter()),
            )
            .map_err(to_fail)?;

        let mut tree_v1 = Smt::new();
        apply_batch(
            &mut tree_v1,
            SmtUpdateBatch::new([ForestOperation::insert(key_1, value_1)].into_iter()),
        )?;
        let mut tree_v2 = tree_v1.clone();
        apply_batch(
            &mut tree_v2,
            SmtUpdateBatch::new([ForestOperation::insert(key_2, value_2)].into_iter()),
        )?;
        let mut tree_v3 = tree_v2.clone();
        apply_batch(
            &mut tree_v3,
            SmtUpdateBatch::new([ForestOperation::insert(key_3, value_3)].into_iter()),
        )?;
        let mut tree_v4 = tree_v3.clone();
        apply_batch(
            &mut tree_v4,
            SmtUpdateBatch::new([ForestOperation::insert(key_4, value_4)].into_iter()),
        )?;

        let sample_keys = vec![key_1, key_2, key_3, key_4];
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage, version + 2),
            &tree_v3,
            &sample_keys,
            true,
        )?;
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage, version + 3),
            &tree_v4,
            &sample_keys,
            true,
        )?;
        prop_assert_eq!(forest.latest_version(lineage), Some(version + 3));
        prop_assert_eq!(forest.latest_root(lineage), Some(tree_v4.root()));
        prop_assert_eq!(
            forest.root_info(TreeId::new(lineage, version + 3)),
            RootInfo::LatestVersion(tree_v4.root())
        );
        prop_assert_eq!(
            forest.root_info(TreeId::new(lineage, version + 2)),
            RootInfo::HistoricalVersion(tree_v3.root())
        );
        prop_assert_eq!(forest.root_info(TreeId::new(lineage, version)), RootInfo::Missing);

        forest.truncate(version + 2);
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage, version + 2),
            &tree_v3,
            &sample_keys,
            true,
        )?;
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage, version + 3),
            &tree_v4,
            &sample_keys,
            true,
        )?;
        prop_assert_eq!(forest.latest_version(lineage), Some(version + 3));
        prop_assert_eq!(
            forest.root_info(TreeId::new(lineage, version + 3)),
            RootInfo::LatestVersion(tree_v4.root())
        );
        prop_assert_eq!(
            forest.root_info(TreeId::new(lineage, version + 2)),
            RootInfo::HistoricalVersion(tree_v3.root())
        );
        prop_assert_eq!(forest.root_info(TreeId::new(lineage, version + 1)), RootInfo::Missing);

        forest.truncate(version + 3);
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage, version + 3),
            &tree_v4,
            &sample_keys,
            true,
        )?;
        prop_assert_eq!(forest.latest_version(lineage), Some(version + 3));
        prop_assert_eq!(forest.latest_root(lineage), Some(tree_v4.root()));
        prop_assert_eq!(
            forest.root_info(TreeId::new(lineage, version + 3)),
            RootInfo::LatestVersion(tree_v4.root())
        );
        prop_assert_eq!(forest.root_info(TreeId::new(lineage, version + 2)), RootInfo::Missing);
    }

    /// This test cross-checks the core query APIs (`get`, `open`, `entries`, `entry_count`) and the
    /// associated metadata APIs against a reference SMT model across current and historical versions.
    #[test]
    fn queries_and_metadata_match_reference_model(
        lineage in arbitrary_lineage(),
        version in arbitrary_version(),
        entries_v1 in arbitrary_batch(),
        entries_v2 in arbitrary_batch(),
        random_key in arbitrary_word(),
    ) {
        let mut forest = LargeSmtForest::new(ForestInMemoryBackend::new()).map_err(to_fail)?;
        let add_result =
            forest.add_lineage(lineage, version, entries_v1.clone()).map_err(to_fail)?;
        let update_result =
            forest.update_tree(lineage, version + 1, entries_v2.clone()).map_err(to_fail)?;

        let tree_v1 = build_tree(entries_v1.clone())?;
        let mut tree_current = tree_v1.clone();
        apply_batch(&mut tree_current, entries_v2.clone())?;

        let mut sample_keys = batch_keys(&entries_v1);
        sample_keys.extend(batch_keys(&entries_v2));
        sample_keys.push(random_key);
        sample_keys.sort();
        sample_keys.dedup();

        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage, version),
            &tree_v1,
            &sample_keys,
            true,
        )?;
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage, update_result.version()),
            &tree_current,
            &sample_keys,
            true,
        )?;

        let expected_versions = if tree_current.root() == tree_v1.root() {
            vec![(version, tree_v1.root())]
        } else {
            vec![(version, add_result.root()), (version + 1, tree_current.root())]
        };

        assert_lineage_metadata(&forest, lineage, &expected_versions)?;
        prop_assert_eq!(forest.lineage_count(), 1);
        prop_assert_eq!(forest.tree_count(), expected_versions.len());
        prop_assert_eq!(
            forest.roots().map(|root| (root.lineage(), root.value())).sorted().collect_vec(),
            expected_versions.iter().map(|(_, root)| (lineage, *root)).sorted().collect_vec()
        );

        let unknown_lineage = LineageId::new([0xAA; 32]);
        prop_assume!(unknown_lineage != lineage);
        prop_assert_eq!(forest.latest_version(unknown_lineage), None);
        prop_assert_eq!(forest.latest_root(unknown_lineage), None);
        prop_assert!(forest.lineage_roots(unknown_lineage).is_none());
        prop_assert_eq!(forest.root_info(TreeId::new(lineage, version + 2)), RootInfo::Missing);
        prop_assert_eq!(forest.root_info(TreeId::new(unknown_lineage, version)), RootInfo::Missing);
    }

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
        let mut forest = LargeSmtForest::new(ForestInMemoryBackend::new()).map_err(to_fail)?;
        forest.add_lineage(lineage, version, entries_v1.clone()).map_err(to_fail)?;
        let tree_info =
            forest.update_tree(lineage, version + 1, entries_v2.clone()).map_err(to_fail)?;

        let tree_v1 = build_tree(entries_v1)?;
        let mut tree_v2 = tree_v1.clone();
        apply_batch(&mut tree_v2, entries_v2)?;

        let old_version = TreeId::new(lineage, version);
        prop_assert_eq!(
            sorted_forest_entries(&forest, old_version)?,
            sorted_tree_entries(&tree_v1)
        );

        let current_version = TreeId::new(lineage, tree_info.version());
        prop_assert_eq!(
            sorted_forest_entries(&forest, current_version)?,
            sorted_tree_entries(&tree_v2)
        );
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
        let mut forest = LargeSmtForest::new(ForestInMemoryBackend::new()).map_err(to_fail)?;
        forest.add_lineage(lineage, version, entries_v1).map_err(to_fail)?;
        let tree_info = forest.update_tree(lineage, version + 1, entries_v2).map_err(to_fail)?;

        let old_version = TreeId::new(lineage, version);
        let old_entries = forest
            .entries(old_version)
            .map_err(to_fail)?
            .collect::<crate::merkle::smt::large_forest::Result<Vec<_>>>()
            .map_err(to_fail)?;
        prop_assert!(old_entries.iter().all(|entry| entry.value != EMPTY_WORD));

        let current_version = TreeId::new(lineage, tree_info.version());
        let current_entries = forest
            .entries(current_version)
            .map_err(to_fail)?
            .collect::<crate::merkle::smt::large_forest::Result<Vec<_>>>()
            .map_err(to_fail)?;
        prop_assert!(current_entries.iter().all(|entry| entry.value != EMPTY_WORD));
    }

    /// This test validates single-lineage mutation semantics, including duplicate additions, bad
    /// version updates, and no-op updates preserving the observable forest state.
    #[test]
    fn add_lineage_and_update_tree_preserve_state_on_failures(
        lineage in arbitrary_lineage(),
        version in arbitrary_version(),
        initial_entries in arbitrary_batch(),
        extra_entries in arbitrary_batch(),
        random_key in arbitrary_word(),
    ) {
        let mut forest = LargeSmtForest::new(ForestInMemoryBackend::new()).map_err(to_fail)?;
        forest.add_lineage(lineage, version, initial_entries.clone()).map_err(to_fail)?;
        let reference = build_tree(initial_entries.clone())?;

        let mut sample_keys = batch_keys(&initial_entries);
        sample_keys.extend(batch_keys(&extra_entries));
        sample_keys.push(random_key);
        sample_keys.sort();
        sample_keys.dedup();

        let duplicate = forest.add_lineage(lineage, version + 1, extra_entries.clone());
        let is_duplicate = matches!(
            duplicate,
            Err(LargeSmtForestError::DuplicateLineage(l)) if l == lineage
        );
        prop_assert!(is_duplicate);
        assert_lineage_metadata(&forest, lineage, &[(version, reference.root())])?;
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage, version),
            &reference,
            &sample_keys,
            true,
        )?;
        prop_assert_eq!(forest.lineage_count(), 1);
        prop_assert_eq!(forest.tree_count(), 1);
        prop_assert_eq!(forest.root_info(TreeId::new(lineage, version + 1)), RootInfo::Missing);
        prop_assert_eq!(
            forest.roots().map(|root| (root.lineage(), root.value())).collect_vec(),
            vec![(lineage, reference.root())]
        );

        let bad_version = forest.update_tree(lineage, version, extra_entries);
        let is_bad_version = matches!(
            bad_version,
            Err(LargeSmtForestError::BadVersion { provided, latest }) if provided == version && latest == version
        );
        prop_assert!(is_bad_version);
        assert_lineage_metadata(&forest, lineage, &[(version, reference.root())])?;
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage, version),
            &reference,
            &sample_keys,
            true,
        )?;
        prop_assert_eq!(forest.root_info(TreeId::new(lineage, version + 1)), RootInfo::Missing);
        prop_assert_eq!(
            forest.roots().map(|root| (root.lineage(), root.value())).collect_vec(),
            vec![(lineage, reference.root())]
        );

        let no_op = forest
            .update_tree(lineage, version + 1, SmtUpdateBatch::empty())
            .map_err(to_fail)?;
        prop_assert_eq!(no_op.version(), version);
        prop_assert_eq!(no_op.root(), reference.root());
        assert_lineage_metadata(&forest, lineage, &[(version, reference.root())])?;
        prop_assert_eq!(forest.tree_count(), 1);
        prop_assert_eq!(forest.root_info(TreeId::new(lineage, version + 1)), RootInfo::Missing);
    }

    /// This test validates batch updates across multiple lineages and ensures invalid batches do
    /// not partially modify forest state.
    #[test]
    fn update_forest_matches_reference_model_and_preserves_state_on_error(
        (lineage_1, lineage_2) in arbitrary_distinct_lineages(),
        version in arbitrary_version(),
        entries_1 in arbitrary_batch(),
        entries_2 in arbitrary_batch(),
        updates_1 in arbitrary_batch(),
        updates_2 in arbitrary_batch(),
        query_key in arbitrary_word(),
    ) {
        let mut forest = LargeSmtForest::new(ForestInMemoryBackend::new()).map_err(to_fail)?;
        forest.add_lineage(lineage_1, version, entries_1.clone()).map_err(to_fail)?;
        forest.add_lineage(lineage_2, version, entries_2.clone()).map_err(to_fail)?;

        let tree_1_v1 = build_tree(entries_1.clone())?;
        let tree_2_v1 = build_tree(entries_2.clone())?;

        let mut expected_tree_1 = tree_1_v1.clone();
        let mut expected_tree_2 = tree_2_v1.clone();
        apply_batch(&mut expected_tree_1, updates_1.clone())?;
        apply_batch(&mut expected_tree_2, updates_2.clone())?;

        let mut forest_updates = SmtForestUpdateBatch::empty();
        forest_updates.add_operations(
            lineage_1,
            updates_1.clone().consume().into_iter(),
        );
        forest_updates.add_operations(
            lineage_2,
            updates_2.clone().consume().into_iter(),
        );
        let results = forest.update_forest(version + 1, forest_updates).map_err(to_fail)?;
        prop_assert_eq!(results.len(), 2);

        let mut sample_keys = batch_keys(&entries_1);
        sample_keys.extend(batch_keys(&entries_2));
        sample_keys.extend(batch_keys(&updates_1));
        sample_keys.extend(batch_keys(&updates_2));
        sample_keys.push(query_key);
        sample_keys.sort();
        sample_keys.dedup();

        let versions_1 = if expected_tree_1.root() == tree_1_v1.root() {
            vec![(version, tree_1_v1.root())]
        } else {
            vec![(version, tree_1_v1.root()), (version + 1, expected_tree_1.root())]
        };
        let versions_2 = if expected_tree_2.root() == tree_2_v1.root() {
            vec![(version, tree_2_v1.root())]
        } else {
            vec![(version, tree_2_v1.root()), (version + 1, expected_tree_2.root())]
        };

        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage_1, versions_1.last().expect("non-empty").0),
            &expected_tree_1,
            &sample_keys,
            true,
        )?;
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage_2, versions_2.last().expect("non-empty").0),
            &expected_tree_2,
            &sample_keys,
            true,
        )?;
        assert_lineage_metadata(&forest, lineage_1, &versions_1)?;
        assert_lineage_metadata(&forest, lineage_2, &versions_2)?;

        let roots = forest
            .roots()
            .map(|root| (root.lineage(), root.value()))
            .sorted()
            .collect_vec();
        let mut expected_roots =
            versions_1.iter().map(|(_, root)| (lineage_1, *root)).collect_vec();
        expected_roots.extend(versions_2.iter().map(|(_, root)| (lineage_2, *root)));
        expected_roots.sort();
        prop_assert_eq!(roots, expected_roots.clone());
        prop_assert_eq!(forest.lineage_count(), 2);
        prop_assert_eq!(forest.tree_count(), versions_1.len() + versions_2.len());

        let unknown_lineage = LineageId::new([0x55; 32]);
        prop_assume!(unknown_lineage != lineage_1 && unknown_lineage != lineage_2);
        let mut invalid_updates = SmtForestUpdateBatch::empty();
        let invalid_value = Word::from([1u32, 1, 1, 1]);
        invalid_updates.add_operations(
            lineage_1,
            SmtUpdateBatch::new([ForestOperation::insert(query_key, invalid_value)].into_iter())
                .consume()
                .into_iter(),
        );
        invalid_updates
            .operations(unknown_lineage)
            .add_insert(query_key, invalid_value);
        let invalid_result = forest.update_forest(version + 2, invalid_updates);
        prop_assert!(invalid_result.is_err());

        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage_1, versions_1.last().expect("non-empty").0),
            &expected_tree_1,
            &sample_keys,
            true,
        )?;
        assert_tree_queries_match(
            &forest,
            TreeId::new(lineage_2, versions_2.last().expect("non-empty").0),
            &expected_tree_2,
            &sample_keys,
            true,
        )?;
        assert_lineage_metadata(&forest, lineage_1, &versions_1)?;
        assert_lineage_metadata(&forest, lineage_2, &versions_2)?;
        prop_assert_eq!(forest.lineage_count(), 2);
        prop_assert_eq!(forest.tree_count(), versions_1.len() + versions_2.len());
        let roots_after_error = forest
            .roots()
            .map(|root| (root.lineage(), root.value()))
            .sorted()
            .collect_vec();
        prop_assert_eq!(roots_after_error, expected_roots.clone());
        prop_assert_eq!(
            forest.root_info(TreeId::new(lineage_1, version + 2)),
            RootInfo::Missing
        );
        prop_assert_eq!(
            forest.root_info(TreeId::new(lineage_2, version + 2)),
            RootInfo::Missing
        );
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
        let mut batch = SmtForestUpdateBatch::empty();
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
