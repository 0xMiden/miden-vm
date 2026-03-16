#![cfg(test)]
//! This module contains the property tests for the persistent backend of the Large SMT forest.

use alloc::vec::Vec;

use itertools::Itertools;
use proptest::prelude::*;

use super::tests::default_backend;
use crate::{
    EMPTY_WORD,
    merkle::smt::{
        Backend, Smt, SmtForestUpdateBatch, SmtUpdateBatch, TreeWithRoot,
        large_forest::test_utils::{
            arbitrary_batch, arbitrary_lineage, arbitrary_version, arbitrary_word,
        },
    },
};

// TESTS
// ================================================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn open_correct(
        lineage in arbitrary_lineage(),
        version in arbitrary_version(),
        entries in arbitrary_batch(),
        random_key in arbitrary_word(),
    ) {
        let (_file, mut backend) = default_backend()?;

        // We can add the lineage to the backend.
        backend.add_lineage(lineage, version, entries.clone())?;

        // And construct a normal tree to compare against.
        let mut tree = Smt::new();
        let tree_mutations = tree.compute_mutations(Vec::from(entries.clone()).into_iter())?;
        tree.apply_mutations(tree_mutations)?;

        // We should get the same opening from the backend and from the tree, for a random key.
        let backend_opening = backend.open(lineage, random_key)?;
        let tree_opening = tree.open(&random_key);
        prop_assert_eq!(backend_opening, tree_opening);

        // And this should be true for all keys.
        for op in entries.into_iter() {
            let key = op.key();
            let backend_opening = backend.open(lineage, key)?;
            let tree_opening = tree.open(&key);
            prop_assert_eq!(backend_opening, tree_opening);
        }
    }

    #[test]
    fn get_correct(
        lineage in arbitrary_lineage(),
        version in arbitrary_version(),
        entries in arbitrary_batch(),
        random_key in arbitrary_word(),
    ) {
        let (_file, mut backend) = default_backend()?;

        // We can add the lineage to the backend.
        backend.add_lineage(lineage, version, entries.clone())?;

        // And construct a normal tree to compare against.
        let mut tree = Smt::new();
        let tree_mutations = tree.compute_mutations(Vec::from(entries.clone()).into_iter())?;
        tree.apply_mutations(tree_mutations)?;

        // We should get the same opening from the backend and from the tree, for a random key.
        let backend_opening =
            backend.get(lineage, random_key)?.unwrap_or(EMPTY_WORD);
        let tree_opening = tree.get_value(&random_key);
        prop_assert_eq!(backend_opening, tree_opening);

        // And this should be true for all keys.
        for op in entries.into_iter() {
            let (key, value) = op.into();
            let backend_opening = backend.get(lineage, key)?;
            prop_assert_eq!(backend_opening, if value == EMPTY_WORD { None } else { Some(value) });
            let tree_opening = tree.get_value(&key);
            prop_assert_eq!(backend_opening.unwrap_or(EMPTY_WORD), tree_opening);
        }
    }

    #[test]
    fn version_correct(
        lineage in arbitrary_lineage(),
        version in arbitrary_version(),
        entries_v1 in arbitrary_batch(),
        entries_v2 in arbitrary_batch(),
    ) {
        let (_file, mut backend) = default_backend()?;

        // We can add the lineage to the backend, and we should always get the provided version back.
        backend.add_lineage(lineage, version, entries_v1.clone())?;
        prop_assert_eq!(backend.version(lineage)?, version);

        // We're going to need an auxiliary tree to check the behavior.
        let mut tree = Smt::new();
        let muts_1 =tree.compute_mutations(Vec::from(entries_v1.clone()).into_iter())?;
        tree.apply_mutations(muts_1)?;
        let muts_2 =tree.compute_mutations(Vec::from(entries_v2.clone()).into_iter())?;

        // If we then update that lineage, we should still get the new version back.
        backend.update_tree(lineage, version + 1, entries_v2)?;

        if muts_2.is_empty() {
            prop_assert_eq!(backend.version(lineage)?, version);
        } else {
            prop_assert_eq!(backend.version(lineage)?, version + 1);
        }
    }

    #[test]
    fn lineages_correct(
        lineages in prop::collection::vec(arbitrary_lineage(), 0..30),
        version in arbitrary_version(),
    ) {
        let (_file, mut backend) = default_backend()?;

        // We should be able to add all the lineages to the backend as long as they are unique.
        let lineages = lineages.into_iter().unique().sorted().collect_vec();

        for lineage in &lineages {
            backend.add_lineage(*lineage, version, SmtUpdateBatch::empty())?;
        }

        // And we should always be able to get the same lineages back.
        let returned_lineages = backend.lineages()?.sorted().collect_vec();
        prop_assert_eq!(returned_lineages, lineages);
    }

    #[test]
    fn trees_correct(
        lineages in prop::collection::vec(arbitrary_lineage(), 10),
        version in arbitrary_version(),
        entries in prop::collection::vec(arbitrary_batch(), 10),
    ) {
        let (_file, mut backend) = default_backend()?;

        // We should be able to add all the lineages to the backend as long as they are unique.
        let lineages = lineages.into_iter().unique().sorted().collect_vec();
        let pairs = lineages.into_iter().zip(entries).collect_vec();
        let count = pairs.len();

        for (lineage, entries) in &pairs {
            backend.add_lineage(*lineage, version, entries.clone())?;
        }

        // We should be able to get the correct root data for each tree.
        for (lineage, entries) in pairs {
            let mut tree = Smt::new();
            let tree_muts = tree.compute_mutations(Vec::from(entries).into_iter())?;
            tree.apply_mutations(tree_muts)?;

            prop_assert_eq!(backend.trees()?.count(), count);
            prop_assert!(
                backend.trees()?.contains(&TreeWithRoot::new(lineage, version, tree.root()))
            );
        }
    }

    #[test]
    fn entry_count_correct(
        lineages in prop::collection::vec(arbitrary_lineage(), 10),
        version in arbitrary_version(),
        entries in prop::collection::vec(arbitrary_batch(), 10)
    ) {
        let (_file, mut backend) = default_backend()?;

        let pairs = lineages.into_iter().unique().sorted().zip(entries).collect_vec();
        let (target_lineage, target_entries) = pairs[0].clone();

        // Each lineage should be able to be added to the backend.
        for (lineage, entries) in pairs {
            backend.add_lineage(lineage, version, entries.clone())?;
        }

        // And then construct an auxiliary tree to mirror it.
        let mut tree = Smt::new();
        let tree_mutations = tree.compute_mutations(Vec::from(target_entries).into_iter())?;
        tree.apply_mutations(tree_mutations)?;

        // And we should have the same number of entries in each.
        let backend_entries = backend.entry_count(target_lineage)?;
        let tree_entries = tree.num_entries();
        prop_assert_eq!(backend_entries, tree_entries);
    }

    #[test]
    fn entries_correct(
        lineages in prop::collection::vec(arbitrary_lineage(), 10),
        version in arbitrary_version(),
        entries in prop::collection::vec(arbitrary_batch(), 10)
    ) {
        let (_file, mut backend) = default_backend()?;

        let pairs = lineages.into_iter().unique().sorted().zip(entries).collect_vec();
        let (target_lineage, target_entries) = pairs[0].clone();

        // Each lineage should be able to be added to the backend.
        for (lineage, entries) in pairs {
            backend.add_lineage(lineage, version, entries.clone())?;
        }

        // And then construct an auxiliary tree to mirror it.
        let mut tree = Smt::new();
        let tree_mutations =
            tree.compute_mutations(Vec::from(target_entries).into_iter())?;
        tree.apply_mutations(tree_mutations)?;

        // And we should have the same number of entries in each.
        let backend_entries = backend
            .entries(target_lineage)?
            .map(|e| e.map(|e| (e.key, e.value)))
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .sorted()
            .collect_vec();
        let tree_entries = tree.entries().copied().sorted().collect_vec();
        prop_assert_eq!(backend_entries, tree_entries);
    }

    #[test]
    fn add_lineage_correct(
        lineage in arbitrary_lineage(),
        version in arbitrary_version(),
        entries in arbitrary_batch()
    ) {
        let (_file, mut backend) = default_backend()?;

        // We can add the lineage to the backend.
        let root = backend.add_lineage(lineage, version, entries.clone())?;

        // And create a normal tree to compare against.
        let mut tree = Smt::new();
        let tree_mutations =tree.compute_mutations(Vec::from(entries.clone()).into_iter())?;
        tree.apply_mutations(tree_mutations)?;

        // The root should return the same results as that.
        prop_assert_eq!(root.root(), tree.root());
        prop_assert_eq!(root.version(), version);
        prop_assert_eq!(root.lineage(), lineage);

        // And we should only see that one lineage.
        prop_assert_eq!(backend.lineages()?.count(), 1);
        prop_assert!(backend.lineages()?.contains(&lineage));
    }

    #[test]
    fn update_lineage_correct(
        lineage_1 in arbitrary_lineage(),
        lineage_2 in arbitrary_lineage(),
        version in arbitrary_version(),
        entries_1_1 in arbitrary_batch(),
        entries_1_2 in arbitrary_batch(),
        entries_2_1 in arbitrary_batch()
    ) {
        let (_file, mut backend) = default_backend()?;

        // We add two lineages with initial values.
        let root_1 = backend.add_lineage(lineage_1, version, entries_1_1.clone())?;
        let root_2 = backend.add_lineage(lineage_2, version, entries_2_1)?;

        // We should see these roots in the trees iterator.
        prop_assert!(backend.trees()?.contains(&root_1));
        prop_assert!(backend.trees()?.contains(&root_2));
        prop_assert_eq!(backend.trees()?.count(), 2);

        // And create an auxiliary tree to check things are correct.
        let mut tree = Smt::new();
        let tree_mutations =
            tree.compute_mutations(Vec::from(entries_1_1).into_iter())?;
        tree.apply_mutations(tree_mutations)?;
        prop_assert_eq!(root_1.root(), tree.root());

        // We then update lineage 1.
        let backend_reversion =backend.update_tree(lineage_1, version + 1, entries_1_2.clone())?;

        // And our auxiliary tree to check.
        let tree_mutations =tree.compute_mutations(Vec::from(entries_1_2).into_iter())?;
        let is_empty = tree_mutations.is_empty();
        let tree_reversion = tree.apply_mutations_with_reversion(tree_mutations)?;

        // Our reversions should be the same, and we should no longer see the previous root.
        prop_assert_eq!(&backend_reversion, &tree_reversion);
        prop_assert_eq!(backend.trees()?.count(), 2);
        prop_assert!(backend.trees()?.contains(&root_2));

        if is_empty {
            prop_assert!(backend.trees()?.contains(&root_1));
        } else {
            prop_assert!(backend.trees()?.contains(
                &TreeWithRoot::new(lineage_1, version + 1, backend_reversion.old_root))
            );
            prop_assert!(!backend.trees()?.contains(&root_1));
        }
    }

    #[test]
    fn update_forest_correct(
        lineages in prop::collection::vec(arbitrary_lineage(), 0..30),
        version in arbitrary_version(),
        entries_v1 in prop::collection::vec(arbitrary_batch(), 0..30),
        entries_v2 in prop::collection::vec(arbitrary_batch(), 0..30),
    ) {
        let (_file, mut backend) = default_backend()?;

        let triples = lineages.into_iter().unique().zip(entries_v1).zip(entries_v2).collect_vec();

        // We should be able to add every lineage initially.
        let updates = triples.into_iter().map(|((lineage, entries_v1), entries_v2)| {
            let root = backend.add_lineage(lineage, version, entries_v1.clone())?;

            let mut tree = Smt::new();
            let tree_mutations = tree.compute_mutations(Vec::from(entries_v1).into_iter())?;
            tree.apply_mutations(tree_mutations)?;

            prop_assert_eq!(root.root(), tree.root());

            Ok((lineage, entries_v2, tree))
        }).collect::<Result<Vec<_>, _>>()?;

        // Let's pull our data apart.
        let (inputs, tree_reversions) = updates
          .into_iter()
          .map(|(lineage, entries, mut tree)| {
            let mutations = tree.compute_mutations(Vec::from(entries.clone()).into_iter()).unwrap();
            let reversion = tree.apply_mutations_with_reversion(mutations).unwrap();
            ((lineage, entries), (lineage, reversion))
          })
          .unzip::<_, _, Vec<_>, Vec<_>>();

        // And then we should be able to correctly update all of them in one go.
        let mut update_batch = SmtForestUpdateBatch::empty();
        inputs.into_iter().for_each(|(lineage, updates)| {
            *update_batch.operations(lineage) = updates;
        });

        let backend_reversions = backend.update_forest(version + 1, update_batch)?;

        for (lineage, reversion) in tree_reversions {
            prop_assert_eq!(
                backend_reversions
                    .iter()
                    .find_map(|(l, r)| if *l == lineage { Some(r) } else { None }),
                Some(&reversion)
            );
        }
    }
}
