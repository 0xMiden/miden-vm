#![cfg(test)]
//! This module contains the handwritten tests of the functionality for the SMT forest. These tests
//! are for the basic functionality, and are intended to test the portion of the logic that is
//! backend-independent and lives purely in the forest. To that end, it uses
//! [`ForestInMemoryBackend`] to do so.
//!
//! Wherever possible, these tests rely on the correctness of the existing [`Smt`] implementation.
//! It is used as a point of comparison to avoid the need to hard-code specific values and scenarios
//! for the trees, instead allowing us to compare things directly.

use alloc::vec::Vec;

use assert_matches::assert_matches;

use super::{Config, Result, test_utils::UNUSED_ENTRY_COUNT};
use crate::{
    EMPTY_WORD, Map, Set, Word,
    merkle::{
        EmptySubtreeRoots,
        smt::{
            Backend, ForestInMemoryBackend, ForestOperation, LargeSmtForest, LargeSmtForestError,
            RootInfo, Smt, SmtForestUpdateBatch, SmtUpdateBatch, TreeId, VersionId,
            large_forest::{
                LineageData,
                history::{ChangedKeys, History, NodeChanges},
                root::{LineageId, TreeEntry, TreeWithRoot},
                test_utils::FallibleEntriesBackend,
            },
        },
    },
    rand::test_utils::{ContinuousRng, rand_value},
};

// TYPE ALIASES
// ================================================================================================

/// We only care about testing with the in-memory backend here for correct functionality.
type Forest = LargeSmtForest<ForestInMemoryBackend>;

// CONSTRUCTION TESTS
// ================================================================================================

#[test]
fn new() -> Result<()> {
    // Constructing a forest using the default constructor should yield the default configuration.
    let backend = ForestInMemoryBackend::new();
    let forest = Forest::new(backend)?;

    // We can just sanity-check the configuration to ensure that things started up right.
    let config = forest.get_config();

    assert_eq!(config.max_history_versions(), 10);

    Ok(())
}

#[test]
fn with_config() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let forest = Forest::with_config(backend, Config::default().with_max_history_versions(30))?;

    // Let us sanity check using the config again.
    let config = forest.get_config();

    assert_eq!(config.max_history_versions(), 30);

    Ok(())
}

// BASIC QUERIES TESTS
// ================================================================================================

#[test]
fn roots() -> Result<()> {
    // We start by constructing our forest.
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x96; 32]);

    // We add a number of lineages to the forest, some of which have the same _root_ value.
    let version_1: VersionId = rng.value();
    let lineage_1: LineageId = rng.value();
    let lineage_2: LineageId = rng.value();
    let lineage_3: LineageId = rng.value();

    let root_1 = forest.add_lineage(lineage_1, version_1, SmtUpdateBatch::default())?;
    assert_eq!(
        root_1,
        TreeWithRoot::new(lineage_1, version_1, *EmptySubtreeRoots::entry(64, 0))
    );
    let root_2 = forest.add_lineage(lineage_2, version_1, SmtUpdateBatch::default())?;
    assert_eq!(
        root_2,
        TreeWithRoot::new(lineage_2, version_1, *EmptySubtreeRoots::entry(64, 0))
    );
    let root_3 = forest.add_lineage(lineage_3, version_1, SmtUpdateBatch::default())?;
    assert_eq!(
        root_3,
        TreeWithRoot::new(lineage_3, version_1, *EmptySubtreeRoots::entry(64, 0))
    );

    // We then update one of them to make sure it ends up with a historical root as well.
    let k1: Word = rng.value();
    let v1: Word = rng.value();
    let k2: Word = rng.value();
    let v2: Word = rng.value();

    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k1, v1);
    operations.add_insert(k2, v2);

    let version_2: VersionId = version_1 + 1;
    let root_4 = forest.update_tree(lineage_1, version_2, operations)?;

    // We can now check that the roots iterator contains the items we expect.
    let roots = forest.roots().collect::<Vec<_>>();
    assert_eq!(roots.len(), 4);
    assert!(roots.contains(&root_1.into()));
    assert!(roots.contains(&root_2.into()));
    assert!(roots.contains(&root_3.into()));
    assert!(roots.contains(&root_4.into()));

    Ok(())
}

#[test]
fn latest_version() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x69; 32]);

    // Let's add some trees to the forest. Two are empty and one is added with data.
    let version_1: VersionId = rng.value();
    let version_2: VersionId = version_1 + 1;
    let version_3: VersionId = version_2 + 1;

    let lineage_1: LineageId = rng.value();
    let lineage_2: LineageId = rng.value();
    let lineage_3: LineageId = rng.value();

    let k1: Word = rng.value();
    let v1: Word = rng.value();
    let k2: Word = rng.value();
    let v2: Word = rng.value();

    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k1, v1);
    operations.add_insert(k2, v2);

    forest.add_lineage(lineage_1, version_1, SmtUpdateBatch::default())?;
    forest.add_lineage(lineage_2, version_1, SmtUpdateBatch::default())?;
    forest.add_lineage(lineage_3, version_1, operations)?;

    // Now let's update one of the empty ones twice...
    let k3: Word = rng.value();
    let v3: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k3, v3);
    forest.update_tree(lineage_1, version_2, operations)?;

    let k4: Word = rng.value();
    let v4: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k4, v4);
    forest.update_tree(lineage_1, version_3, operations)?;

    // ...and the non-empty one once with a non-contiguous version.
    let k5: Word = rng.value();
    let v5: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k5, v5);
    forest.update_tree(lineage_3, version_3, operations)?;

    // Now let's query the latest version for all of them.
    assert_eq!(forest.latest_version(lineage_1).unwrap(), version_3);
    assert_eq!(forest.latest_version(lineage_2).unwrap(), version_1);
    assert_eq!(forest.latest_version(lineage_3).unwrap(), version_3);

    // Finally, if we look for a lineage that doesn't exist, we should get `None` back.
    let ne_lineage: LineageId = rng.value();
    assert!(forest.latest_version(ne_lineage).is_none());

    Ok(())
}

#[test]
fn lineage_roots() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x42; 32]);

    // Let's add a lineage to the forest and update it a few times.
    let lineage: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let version_2 = version_1 + 1;
    let version_3 = version_2 + 1;
    let root_1 = forest.add_lineage(lineage, version_1, SmtUpdateBatch::default())?;

    let k1: Word = rng.value();
    let v1: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k1, v1);
    let root_2 = forest.update_tree(lineage, version_2, operations)?;

    let k2: Word = rng.value();
    let v2: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k2, v2);
    let root_3 = forest.update_tree(lineage, version_3, operations)?;

    // Now we can query for the roots in this lineage.
    let lineage_roots = forest
        .lineage_roots(lineage)
        .expect("Existing lineage should have roots")
        .collect::<Vec<_>>();
    assert_eq!(lineage_roots.len(), 3);

    // For this method, the contract insists that it is ordered from newer roots in the lineage to
    // older roots.
    assert_eq!(lineage_roots[0], root_3.root());
    assert_eq!(lineage_roots[1], root_2.root());
    assert_eq!(lineage_roots[2], root_1.root());

    // If, however, we query for the roots of a non-existent lineage, we should get `None` back.
    let ne_lineage: LineageId = rng.value();
    assert!(forest.lineage_roots(ne_lineage).is_none());

    Ok(())
}

#[test]
fn latest_root() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x97; 32]);

    // Let's add a lineage to the forest.
    let lineage: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let version_2 = version_1 + 1;
    let root_1 = forest.add_lineage(lineage, version_1, SmtUpdateBatch::default())?;

    // We can get its latest root.
    assert_eq!(forest.latest_root(lineage), Some(root_1.root()));

    // And then update it...
    let k1: Word = rng.value();
    let v1: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k1, v1);
    let root_2 = forest.update_tree(lineage, version_2, operations)?;

    // ...to check that we get the updated root.
    assert_eq!(forest.latest_root(lineage), Some(root_2.root()));

    // However, if we query for a nonexistent lineage, we should get `None` back.
    let ne_lineage: LineageId = rng.value();
    assert!(forest.latest_root(ne_lineage).is_none());

    Ok(())
}

#[test]
fn tree_count() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x67; 32]);

    // A newly-initialized forest should know about only the trees that its backend knows about.
    assert_eq!(forest.tree_count(), forest.get_backend().trees()?.count());

    // Now let's add some trees.
    let lineage_1: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let version_2 = version_1 + 1;
    let version_3 = version_2 + 1;
    forest.add_lineage(lineage_1, version_1, SmtUpdateBatch::default())?;

    let k1: Word = rng.value();
    let v1: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k1, v1);
    forest.update_tree(lineage_1, version_2, operations)?;

    let k2: Word = rng.value();
    let v2: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(k2, v2);
    forest.update_tree(lineage_1, version_3, operations)?;

    let lineage_2: LineageId = rng.value();
    forest.add_lineage(lineage_2, version_1, SmtUpdateBatch::default())?;

    // As there are two current trees and two historical versions, we should see four trees total.
    assert_eq!(forest.tree_count(), 4);

    Ok(())
}

#[test]
fn lineage_count() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x64; 32]);

    // A newly-initialized forest should know about only the lineages that its backend knows about.
    assert_eq!(forest.lineage_count(), forest.get_backend().lineages()?.count());

    // So now let's add some lineages.
    let version: VersionId = rng.value();
    let lineage_1: LineageId = rng.value();
    forest.add_lineage(lineage_1, version, SmtUpdateBatch::default())?;
    let lineage_2: LineageId = rng.value();
    forest.add_lineage(lineage_2, version, SmtUpdateBatch::default())?;
    let lineage_3: LineageId = rng.value();
    forest.add_lineage(lineage_3, version, SmtUpdateBatch::default())?;

    // We should see three lineages.
    assert_eq!(forest.lineage_count(), 3);

    // This should stay the same if we update a tree.
    let operations =
        SmtUpdateBatch::new([ForestOperation::insert(rng.value(), rng.value())].into_iter());
    forest.update_tree(lineage_1, version + 1, operations)?;
    assert_eq!(forest.lineage_count(), 3);

    Ok(())
}

#[test]
fn root_info() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x32; 32]);

    // Let's start by adding a lineage and updating it.
    let lineage_1: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let operations =
        SmtUpdateBatch::new([ForestOperation::insert(rng.value(), rng.value())].into_iter());
    let historical_root = forest.add_lineage(lineage_1, version_1, operations)?;

    let version_2 = version_1 + 1;
    let operations =
        SmtUpdateBatch::new([ForestOperation::insert(rng.value(), rng.value())].into_iter());
    let current_root = forest.update_tree(lineage_1, version_2, operations)?;

    // When we query for a root (lineage_1, version_1), we should get back HistoricalVersion.
    assert_eq!(
        forest.root_info(TreeId::new(lineage_1, version_1)),
        RootInfo::HistoricalVersion(historical_root.root())
    );

    // When we query for a root (lineage_1, version_2), we should get back LatestVersion.
    assert_eq!(
        forest.root_info(TreeId::new(lineage_1, version_2)),
        RootInfo::LatestVersion(current_root.root())
    );

    // When we query for a nonexistent version in an existing lineage we should get back Missing.
    let version_3 = version_2 + 1;
    assert_eq!(forest.root_info(TreeId::new(lineage_1, version_3)), RootInfo::Missing);

    // As we should also get back when the lineage doesn't exist.
    let lineage_2: LineageId = rng.value();
    assert_eq!(forest.root_info(TreeId::new(lineage_2, version_1)), RootInfo::Missing);

    Ok(())
}

// QUERIES TESTS
// ================================================================================================

#[test]
fn open() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x08; 32]);

    // When we query for a tree with a lineage that is not known by the forest, we should get an
    // error back.
    let missing_lineage: LineageId = rng.value();
    let missing_version: VersionId = rng.value();
    let missing_key: Word = rng.value();

    let result = forest.open(TreeId::new(missing_lineage, missing_version), missing_key);
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), LargeSmtForestError::UnknownLineage(l) if l == missing_lineage);

    // Now let's add an (empty) lineage to the forest.
    let lineage_1: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let key_1: Word = rng.value();
    let value_1_v1: Word = rng.value();
    let key_2: Word = rng.value();
    let value_2_v1: Word = rng.value();
    forest.add_lineage(
        lineage_1,
        version_1,
        SmtUpdateBatch::new(
            [
                ForestOperation::insert(key_1, value_1_v1),
                ForestOperation::insert(key_2, value_2_v1),
            ]
            .into_iter(),
        ),
    )?;

    // If we query for a tree with a known lineage but unknown version, we should also get an error
    // back.
    let missing_tree = TreeId::new(lineage_1, missing_version);
    let result = forest.open(missing_tree, missing_key);
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), LargeSmtForestError::UnknownTree(t) if t == missing_tree);

    // We should also get an error back if we query for a version that is NEWER than the
    // latest-known version.
    let too_new_version = version_1 + 1;
    let too_new_tree = TreeId::new(lineage_1, too_new_version);
    let result = forest.open(too_new_tree, missing_key);
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), LargeSmtForestError::UnknownTree(t) if t == too_new_tree);

    // Let's set up a basic SMT to compare the forest's openings again for correctness.
    let mut tree_v1 = Smt::new();
    tree_v1.insert(key_1, value_1_v1)?;
    tree_v1.insert(key_2, value_2_v1)?;

    // And get a random opening on the initial tree.
    let random_key: Word = rng.value();
    let forest_opening = forest.open(TreeId::new(lineage_1, version_1), random_key)?;
    let tree_v1_opening = tree_v1.open(&random_key);
    assert_eq!(forest_opening, tree_v1_opening);

    // Now let's make some modifications to the tree.
    let version_2: VersionId = rng.value();
    let value_1_v2: Word = rng.value();
    let key_3: Word = rng.value();
    let value_3_v1: Word = rng.value();
    forest.update_tree(
        lineage_1,
        version_2,
        SmtUpdateBatch::new(
            [
                ForestOperation::insert(key_1, value_1_v2),
                ForestOperation::insert(key_3, value_3_v1),
                ForestOperation::remove(key_2),
            ]
            .into_iter(),
        ),
    )?;

    // And mirror it on our tree.
    let mut tree_v2 = tree_v1.clone();
    tree_v2.insert(key_1, value_1_v2)?;
    tree_v2.insert(key_3, value_3_v1)?;
    tree_v2.insert(key_2, EMPTY_WORD)?;

    // These two should again produce the same opening when we query for the latest version.
    let random_key: Word = rng.value();
    let forest_opening = forest.open(TreeId::new(lineage_1, version_2), random_key)?;
    let tree_v2_opening = tree_v2.open(&random_key);
    assert_eq!(forest_opening, tree_v2_opening);

    // Most importantly, however, we should get the same opening from the forest when querying a
    // historical tree version as we do from the actual tree.
    let forest_opening = forest.open(TreeId::new(lineage_1, version_1), random_key)?;
    let tree_v1_opening = tree_v1.open(&random_key);
    assert_eq!(forest_opening, tree_v1_opening);

    Ok(())
}

#[test]
fn get() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x12; 32]);

    // When we query for a tree with a lineage that is not known by the forest, we should get an
    // error back.
    let missing_lineage: LineageId = rng.value();
    let missing_version: VersionId = rng.value();
    let missing_key: Word = rng.value();

    let result = forest.get(TreeId::new(missing_lineage, missing_version), missing_key);
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), LargeSmtForestError::UnknownLineage(l) if l == missing_lineage);

    // Now let's add an (empty) lineage to the forest.
    let lineage_1: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let key_1: Word = rng.value();
    let value_1_v1: Word = rng.value();
    let key_2: Word = rng.value();
    let value_2_v1: Word = rng.value();
    forest.add_lineage(
        lineage_1,
        version_1,
        SmtUpdateBatch::new(
            [
                ForestOperation::insert(key_1, value_1_v1),
                ForestOperation::insert(key_2, value_2_v1),
            ]
            .into_iter(),
        ),
    )?;

    // If we query for a tree with a known lineage but unknown version, we should also get an error
    // back.
    let missing_tree = TreeId::new(lineage_1, missing_version);
    let result = forest.get(missing_tree, missing_key);
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), LargeSmtForestError::UnknownTree(t) if t == missing_tree);

    // We should also get an error back if we query for a version that is NEWER than the
    // latest-known version.
    let too_new_version = version_1 + 1;
    let too_new_tree = TreeId::new(lineage_1, too_new_version);
    let result = forest.get(too_new_tree, missing_key);
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), LargeSmtForestError::UnknownTree(t) if t == too_new_tree);

    // If we query for a key that has never been inserted we want to get back `None`.
    let tree_v1 = TreeId::new(lineage_1, version_1);
    let non_inserted_key: Word = rng.value();
    assert!(forest.get(tree_v1, non_inserted_key)?.is_none());

    // But if we query for a key that has been, we should get back the corresponding value.
    assert_eq!(forest.get(tree_v1, key_1)?, Some(value_1_v1));
    assert_eq!(forest.get(tree_v1, key_2)?, Some(value_2_v1));

    // Now let's add another version.
    let version_2: VersionId = version_1 + 1;
    let value_1_v2: Word = rng.value();
    let key_3: Word = rng.value();
    let value_3_v1: Word = rng.value();
    forest.update_tree(
        lineage_1,
        version_2,
        SmtUpdateBatch::new(
            [
                ForestOperation::insert(key_1, value_1_v2),
                ForestOperation::insert(key_3, value_3_v1),
            ]
            .into_iter(),
        ),
    )?;

    // When we query at the new version we should see the updated values for all extant keys.
    let tree_v2 = TreeId::new(lineage_1, version_2);
    assert_eq!(forest.get(tree_v2, key_1)?, Some(value_1_v2));
    assert_eq!(forest.get(tree_v2, key_2)?, Some(value_2_v1));
    assert_eq!(forest.get(tree_v2, key_3)?, Some(value_3_v1));

    // But if we query for the older version we should still see the older values.
    assert_eq!(forest.get(tree_v1, key_1)?, Some(value_1_v1));
    assert_eq!(forest.get(tree_v1, key_2)?, Some(value_2_v1));
    assert!(forest.get(tree_v1, key_3)?.is_none());

    Ok(())
}

#[test]
fn entry_count() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x22; 32]);

    // Let's start by adding a lineage with some values.
    let lineage_1: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let key_1: Word = rng.value();
    let value_1_v1: Word = rng.value();
    let key_2: Word = rng.value();
    let value_2_v1: Word = rng.value();
    let mut key_3: Word = rng.value();
    key_3[3] = key_1[3];
    let value_3_v1: Word = rng.value();

    let mut operations = SmtUpdateBatch::empty();
    operations.add_insert(key_1, value_1_v1);
    operations.add_insert(key_2, value_2_v1);
    operations.add_insert(key_3, value_3_v1);

    forest.add_lineage(lineage_1, version_1, operations)?;

    // We'll also update this so we have a historical version in play to be sure things work.
    let version_2: VersionId = version_1 + 1;
    let value_1_v2: Word = rng.value();
    let mut key_4: Word = rng.value();
    key_4[3] = key_2[3];
    let value_4_v1: Word = rng.value();

    let mut operations = SmtUpdateBatch::empty();
    operations.add_remove(key_3);
    operations.add_insert(key_1, value_1_v2);
    operations.add_insert(key_4, value_4_v1);

    forest.update_tree(lineage_1, version_2, operations)?;

    // If we try and get the entry count over a lineage that does not exist we should see an error.
    let ne_lineage: LineageId = rng.value();
    match forest.entry_count(TreeId::new(ne_lineage, version_1)) {
        Err(e) => assert_matches!(e, LargeSmtForestError::UnknownLineage(l) if l == ne_lineage),
        Ok(_) => panic!("Result was not an error"),
    };

    // Similarly, if we try and get the entry count for a nonexistent version in an existing lineage
    // we should also see an error.
    let tree = TreeId::new(lineage_1, version_1 - 1);
    match forest.entry_count(tree) {
        Err(e) => assert_matches!(e, LargeSmtForestError::UnknownTree(t) if t == tree),
        Ok(_) => panic!("Result was not an error"),
    };

    // We should also get an error back if we query for a version that is NEWER than the
    // latest-known version.
    let too_new_version = version_2 + 1;
    let too_new_tree = TreeId::new(lineage_1, too_new_version);
    let result = forest.entry_count(too_new_tree);
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), LargeSmtForestError::UnknownTree(t) if t == too_new_tree);

    // If we query for extant trees we should see the correct count regardless of whether it is the
    // current tree or a historical tree.
    assert_eq!(forest.entry_count(TreeId::new(lineage_1, version_1))?, 3);
    assert_eq!(forest.entry_count(TreeId::new(lineage_1, version_2))?, 3);

    Ok(())
}

#[test]
fn entry_count_historical_across_versions() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x23; 32]);

    let lineage: LineageId = rng.value();
    let version_1: VersionId = rng.value();

    // Version 1: Insert 2 entries.
    let key_1: Word = rng.value();
    let value_1: Word = rng.value();
    let key_2: Word = rng.value();
    let value_2: Word = rng.value();

    let mut ops = SmtUpdateBatch::empty();
    ops.add_insert(key_1, value_1);
    ops.add_insert(key_2, value_2);
    forest.add_lineage(lineage, version_1, ops)?;

    // Version 2: Insert 1 more entry (total 3).
    let version_2 = version_1 + 1;
    let key_3: Word = rng.value();
    let value_3: Word = rng.value();

    let mut ops = SmtUpdateBatch::empty();
    ops.add_insert(key_3, value_3);
    forest.update_tree(lineage, version_2, ops)?;

    // Version 3: Remove 1 entry (total 2).
    let version_3 = version_2 + 1;
    let mut ops = SmtUpdateBatch::empty();
    ops.add_remove(key_1);
    forest.update_tree(lineage, version_3, ops)?;

    // Verify entry counts for all versions.
    assert_eq!(forest.entry_count(TreeId::new(lineage, version_1))?, 2);
    assert_eq!(forest.entry_count(TreeId::new(lineage, version_2))?, 3);
    assert_eq!(forest.entry_count(TreeId::new(lineage, version_3))?, 2);

    Ok(())
}

#[test]
fn entry_count_historical_across_versions_via_update_forest() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x24; 32]);

    // Set up two lineages so we exercise the update_forest path (which updates multiple lineages
    // in a single batch).
    let lineage_a: LineageId = rng.value();
    let lineage_b: LineageId = rng.value();
    let version_1: VersionId = rng.value();

    // Version 1: lineage_a gets 2 entries, lineage_b gets 1 entry.
    let a_key_1: Word = rng.value();
    let a_value_1: Word = rng.value();
    let a_key_2: Word = rng.value();
    let a_value_2: Word = rng.value();
    let b_key_1: Word = rng.value();
    let b_value_1: Word = rng.value();

    let mut ops_a = SmtUpdateBatch::empty();
    ops_a.add_insert(a_key_1, a_value_1);
    ops_a.add_insert(a_key_2, a_value_2);
    forest.add_lineage(lineage_a, version_1, ops_a)?;

    let mut ops_b = SmtUpdateBatch::empty();
    ops_b.add_insert(b_key_1, b_value_1);
    forest.add_lineage(lineage_b, version_1, ops_b)?;

    // Version 2 via update_forest: add 1 entry to lineage_a (total 3), add 2 entries to
    // lineage_b (total 3).
    let version_2 = version_1 + 1;
    let a_key_3: Word = rng.value();
    let a_value_3: Word = rng.value();
    let b_key_2: Word = rng.value();
    let b_value_2: Word = rng.value();
    let b_key_3: Word = rng.value();
    let b_value_3: Word = rng.value();

    let mut batch = SmtForestUpdateBatch::empty();
    batch.operations(lineage_a).add_insert(a_key_3, a_value_3);
    batch.operations(lineage_b).add_insert(b_key_2, b_value_2);
    batch.operations(lineage_b).add_insert(b_key_3, b_value_3);
    forest.update_forest(version_2, batch)?;

    // Version 3 via update_forest: remove 1 entry from lineage_a (total 2), add 1 entry to
    // lineage_b (total 4).
    let version_3 = version_2 + 1;
    let b_key_4: Word = rng.value();
    let b_value_4: Word = rng.value();

    let mut batch = SmtForestUpdateBatch::empty();
    batch.operations(lineage_a).add_remove(a_key_1);
    batch.operations(lineage_b).add_insert(b_key_4, b_value_4);
    forest.update_forest(version_3, batch)?;

    // Verify historical entry counts for lineage_a.
    assert_eq!(forest.entry_count(TreeId::new(lineage_a, version_1))?, 2);
    assert_eq!(forest.entry_count(TreeId::new(lineage_a, version_2))?, 3);
    assert_eq!(forest.entry_count(TreeId::new(lineage_a, version_3))?, 2);

    // Verify historical entry counts for lineage_b.
    assert_eq!(forest.entry_count(TreeId::new(lineage_b, version_1))?, 1);
    assert_eq!(forest.entry_count(TreeId::new(lineage_b, version_2))?, 3);
    assert_eq!(forest.entry_count(TreeId::new(lineage_b, version_3))?, 4);

    Ok(())
}

#[test]
fn entries() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x47; 32]);

    // Let's start by adding a lineage with some values.
    let lineage_1: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let key_1: Word = rng.value();
    let value_1_v1: Word = rng.value();
    let key_2: Word = rng.value();
    let value_2_v1: Word = rng.value();
    let mut key_3: Word = rng.value();
    key_3[3] = key_1[3];
    let value_3_v1: Word = rng.value();

    let mut operations = SmtUpdateBatch::empty();
    operations.add_insert(key_1, value_1_v1);
    operations.add_insert(key_2, value_2_v1);
    operations.add_insert(key_3, value_3_v1);

    forest.add_lineage(lineage_1, version_1, operations)?;

    // We'll also update this so we have a historical version in play to be sure things work.
    let version_2: VersionId = version_1 + 1;
    let value_1_v2: Word = rng.value();
    let mut key_4: Word = rng.value();
    key_4[3] = key_2[3];
    let value_4_v1: Word = rng.value();

    let mut operations = SmtUpdateBatch::empty();
    operations.add_remove(key_3);
    operations.add_insert(key_1, value_1_v2);
    operations.add_insert(key_4, value_4_v1);

    forest.update_tree(lineage_1, version_2, operations)?;

    // If we try and get entries over a lineage that does not exist we should see an error.
    let ne_lineage: LineageId = rng.value();
    match forest.entries(TreeId::new(ne_lineage, version_1)) {
        Err(e) => assert_matches!(e, LargeSmtForestError::UnknownLineage(l) if l == ne_lineage),
        Ok(_) => panic!("Result was not an error"),
    };

    // Similarly, if we try and get entries for a nonexistent version in an existing lineage we
    // should also see an error.
    let tree = TreeId::new(lineage_1, version_1 - 1);
    match forest.entries(tree) {
        Err(e) => assert_matches!(e, LargeSmtForestError::UnknownTree(t) if t == tree),
        Ok(_) => panic!("Result was not an error"),
    };

    // We should also get an error back if we query for a version that is NEWER than the
    // latest-known version.
    let too_new_version = version_2 + 1;
    let too_new_tree = TreeId::new(lineage_1, too_new_version);
    match forest.entries(too_new_tree) {
        Err(e) => assert_matches!(e, LargeSmtForestError::UnknownTree(t) if t == too_new_tree),
        Ok(_) => panic!("Result was not an error"),
    }

    // Grabbing the entries for the latest version in a lineage should do the right thing.
    let current_tree = TreeId::new(lineage_1, version_2);
    let current_entries = forest.entries(current_tree)?.collect::<Result<Vec<_>>>()?;
    assert_eq!(current_entries.len(), 3);
    assert!(current_entries.contains(&TreeEntry { key: key_1, value: value_1_v2 }));
    assert!(current_entries.contains(&TreeEntry { key: key_2, value: value_2_v1 }));
    assert!(current_entries.contains(&TreeEntry { key: key_4, value: value_4_v1 }));
    assert!(!current_entries.contains(&TreeEntry { key: key_3, value: value_3_v1 }));

    // If we ask for a historical version, things are more complex but should still work.
    let historical_tree = TreeId::new(lineage_1, version_1);
    let historical_entries = forest.entries(historical_tree)?.collect::<Result<Vec<_>>>()?;
    assert_eq!(historical_entries.len(), 3);
    assert!(historical_entries.contains(&TreeEntry { key: key_1, value: value_1_v1 }));
    assert!(historical_entries.contains(&TreeEntry { key: key_2, value: value_2_v1 }));
    assert!(historical_entries.contains(&TreeEntry { key: key_3, value: value_3_v1 }));
    assert!(!historical_entries.contains(&TreeEntry { key: key_4, value: value_4_v1 }));

    Ok(())
}

#[test]
fn forest_overlays_correctly() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = LargeSmtForest::new(backend)?;

    // We can just make some arbitrary values here for demonstration.
    let key_1 = Word::parse("0x42").unwrap();
    let value_1 = Word::parse("0x80").unwrap();
    let key_2 = Word::parse("0xAB").unwrap();
    let value_2 = Word::parse("0xCD").unwrap();

    // Operations are most cleanly specified using a builder.
    let mut operations = SmtUpdateBatch::empty();
    operations.add_insert(key_1, value_1);
    operations.add_insert(key_2, value_2);

    // To add a new lineage we also need to give it a lineage ID, and a version.
    let lineage = LineageId::new([0x42; 32]);
    let version_1 = 1;

    // Now we can add the lineage to the forest!
    forest.add_lineage(lineage, version_1, operations)?;

    // Let's make another arbitrary value.
    let key_3 = Word::parse("0x67").unwrap();
    let value_3 = Word::parse("0x96").unwrap();

    // And build a batch of operations again.
    let mut operations = SmtUpdateBatch::empty();
    operations.add_insert(key_3, value_3);
    operations.add_remove(key_1);

    // Now we can simply update the tree all in one go with our changes.
    let version_2 = version_1 + 1;
    forest.update_tree(lineage, version_2, operations)?;

    // As discussed above, trees are identified by a combination of their lineage and version.
    let old_tree = TreeId::new(lineage, version_1);
    let current_tree = TreeId::new(lineage, version_2);

    // The first really useful query is `open`, which gets the opening for the specified key. We can
    // get openings for the current tree AND the historical trees.
    assert!(forest.open(old_tree, key_1).is_ok());
    assert!(forest.open(current_tree, key_3).is_ok());

    // We can also just `get` the value associated with a key, which returns `None` if the key is
    // not populated.
    assert_eq!(forest.get(old_tree, key_1)?, Some(value_1));
    assert_eq!(forest.get(current_tree, key_3)?, Some(value_3));
    assert!(forest.get(current_tree, key_1)?.is_none());

    // We can also get an iterator over all the entries in the tree.
    let entries_old = forest.entries(old_tree)?.collect::<Result<Vec<_>>>()?;
    let entries_current = forest.entries(current_tree)?.collect::<Result<Vec<_>>>()?;
    assert!(entries_old.contains(&TreeEntry { key: key_1, value: value_1 }));
    assert!(entries_old.contains(&TreeEntry { key: key_2, value: value_2 }));
    assert!(!entries_old.contains(&TreeEntry { key: key_3, value: value_3 }));
    assert!(!entries_current.contains(&TreeEntry { key: key_1, value: value_1 }));
    assert!(entries_current.contains(&TreeEntry { key: key_2, value: value_2 }));
    assert!(entries_current.contains(&TreeEntry { key: key_3, value: value_3 }));

    Ok(())
}

#[test]
fn entries_never_returns_empty_entry() -> Result<()> {
    // We risk yielding empty entries in a few situations, but all of those situations involve
    // iterating over the history on its own. Let's go through them one by one.
    //
    // For more detailed testing of this behavior, see the `property_tests`.
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x44; 32]);

    // The FIRST such situation is when the iterator contains _only_ historical entries in its
    // remaining tail. We can produce such a state by adding an empty lineage and then setting
    // values in that lineage.
    let lineage_1: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    forest.add_lineage(lineage_1, version_1, SmtUpdateBatch::empty())?;

    // We now set values in that lineage.
    let version_2 = version_1 + 1;
    let key_1: Word = rng.value();
    let value_1: Word = rng.value();
    let key_2: Word = rng.value();
    let value_2: Word = rng.value();
    let operations = SmtUpdateBatch::new(
        [ForestOperation::insert(key_1, value_1), ForestOperation::insert(key_2, value_2)]
            .into_iter(),
    );
    forest.update_tree(lineage_1, version_2, operations)?;

    // At this point, we should see an empty iterator for entries if we query in the history.
    let historical_tree = TreeId::new(lineage_1, version_1);
    assert_eq!(forest.entries(historical_tree)?.count(), 0);

    // The SECOND scenario is where only some entries are added, so we end up with entire leaves
    // that are history only and contain empty values.
    let lineage_2: LineageId = rng.value();
    let key_1 = Word::from([1u32, 0, 0, 42]);
    let value_1: Word = rng.value();
    forest.add_lineage(
        lineage_2,
        version_1,
        SmtUpdateBatch::new([ForestOperation::insert(key_1, value_1)].into_iter()),
    )?;

    // Now we add an update to a different leaf.
    let key_2 = Word::from([2u32, 0, 0, 43]);
    let value_2: Word = rng.value();
    forest.update_tree(
        lineage_2,
        version_2,
        SmtUpdateBatch::new([ForestOperation::insert(key_2, value_2)].into_iter()),
    )?;

    // Now, when we query for entries on the historical version, we should only see one entry, and
    // no entries should be the empty word.
    let historical_tree = TreeId::new(lineage_2, version_1);
    let entries = forest.entries(historical_tree)?.collect::<Result<Vec<_>>>()?;
    assert_eq!(entries.len(), 1);
    assert!(entries.iter().all(|e| e.value != EMPTY_WORD));

    // The third scenario is where entries are added within a shared leaf, where we should only see
    // the historical leaf entries and not their reversions.
    let lineage_3: LineageId = rng.value();
    let key_1 = Word::from([1u32, 0, 0, 42]);
    let value_1: Word = rng.value();
    forest.add_lineage(
        lineage_3,
        version_1,
        SmtUpdateBatch::new([ForestOperation::insert(key_1, value_1)].into_iter()),
    )?;

    // We now add an update in the same leaf.
    let key_2 = Word::from([2u32, 0, 0, 42]);
    let value_2: Word = rng.value();
    forest.update_tree(
        lineage_3,
        version_2,
        SmtUpdateBatch::new([ForestOperation::insert(key_2, value_2)].into_iter()),
    )?;

    // Now when we query the historical version, we should only see one entry, and no reversions.
    let historical_tree = TreeId::new(lineage_3, version_1);
    let entries = forest.entries(historical_tree)?.collect::<Result<Vec<_>>>()?;
    assert_eq!(entries.len(), 1);
    assert!(entries.iter().all(|e| e.value != EMPTY_WORD));

    Ok(())
}

#[test]
fn entries_history_empty_values_do_not_reorder() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x55; 32]);

    let lineage: LineageId = rng.value();
    let version_1: VersionId = rng.value();

    let key_a = Word::from([2u32, 0, 0, 42]);
    let value_a: Word = rng.value();
    let key_c = Word::from([3u32, 0, 0, 42]);
    let value_c_v1: Word = rng.value();

    forest.add_lineage(
        lineage,
        version_1,
        SmtUpdateBatch::new(
            [
                ForestOperation::insert(key_a, value_a),
                ForestOperation::insert(key_c, value_c_v1),
            ]
            .into_iter(),
        ),
    )?;

    let version_2 = version_1 + 1;
    let key_b = Word::from([1u32, 0, 0, 42]);
    let value_b: Word = rng.value();
    let value_c_v2: Word = rng.value();

    forest.update_tree(
        lineage,
        version_2,
        SmtUpdateBatch::new(
            [
                ForestOperation::insert(key_b, value_b),
                ForestOperation::insert(key_c, value_c_v2),
            ]
            .into_iter(),
        ),
    )?;

    let historical_tree = TreeId::new(lineage, version_1);
    let entries = forest.entries(historical_tree)?.collect::<Result<Vec<_>>>()?;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0], TreeEntry { key: key_a, value: value_a });
    assert_eq!(entries[1], TreeEntry { key: key_c, value: value_c_v1 });
    assert!(entries.iter().all(|e| e.value != EMPTY_WORD));

    Ok(())
}

// SINGLE-TREE MODIFIER TESTS
// ================================================================================================

#[test]
fn add_lineage() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x42; 32]);

    // We can add an initial lineage to the forest, starting with no changes from the default tree.
    let lineage: LineageId = rng.value();
    let version: VersionId = rng.value();
    let result = forest.add_lineage(lineage, version, SmtUpdateBatch::default());
    assert!(result.is_ok());

    // This should yield the correct value, which we'll check using a Smt.
    let tree = Smt::new();

    let result = result?;
    assert_eq!(result.root(), tree.root());
    assert_eq!(result.lineage(), lineage);
    assert_eq!(result.version(), version);

    // The newly-added lineage should also not be listed as having a non-empty history.
    assert!(!forest.get_non_empty_histories().contains(&lineage));

    // If we try and add a duplicated lineage again, we should get an error.
    let result = forest.add_lineage(lineage, version, SmtUpdateBatch::default());
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), LargeSmtForestError::DuplicateLineage(l) if l == lineage);

    Ok(())
}

#[test]
fn update_tree() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x69; 32]);

    // Let's start by adding a lineage to the forest...
    let lineage_1: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let key_1: Word = rng.value();
    let value_1: Word = rng.value();

    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(key_1, value_1);

    let result = forest.add_lineage(lineage_1, version_1, operations)?;

    // ... and creating an auxiliary tree with the same value to check consistency.
    let mut tree = Smt::new();
    tree.insert(key_1, value_1)?;

    assert_eq!(result.root(), tree.root());

    // Initially, this new lineage should not be listed as having a non-empty history.
    assert!(!forest.get_non_empty_histories().contains(&lineage_1));

    // If we try and update a lineage that is unknown, we should see an error.
    let unknown_lineage: LineageId = rng.value();
    let result = forest.update_tree(unknown_lineage, version_1, SmtUpdateBatch::default());
    assert!(result.is_err());
    assert_matches!(
        result.unwrap_err(),
        LargeSmtForestError::UnknownLineage(l) if l == unknown_lineage
    );

    // If we add a version that is older than the latest known version for that lineage, we should
    // see an error.
    let older_version = version_1 - 1;
    let result = forest.update_tree(lineage_1, older_version, SmtUpdateBatch::default());
    assert!(result.is_err());
    assert_matches!(
        result.unwrap_err(),
        LargeSmtForestError::BadVersion { provided, latest }
            if provided == older_version && latest == version_1
    );

    // Let's create some data and actually add it.
    let key_2: Word = rng.value();
    let value_2: Word = rng.value();
    let key_3: Word = rng.value();
    let value_3: Word = rng.value();

    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(key_2, value_2);
    operations.add_insert(key_3, value_3);
    operations.add_remove(key_1);

    let version_2: VersionId = rng.value();
    let result = forest.update_tree(lineage_1, version_2, operations)?;

    // And we can check this against the tree.
    let mutations =
        tree.compute_mutations(vec![(key_1, EMPTY_WORD), (key_2, value_2), (key_3, value_3)])?;
    tree.apply_mutations(mutations)?;

    assert_eq!(result.root(), tree.root());

    // And we should also now have a history version that corresponds to the previous version, which
    // we are going to get at via some test helpers.
    let history = forest.get_history(lineage_1);
    assert_eq!(history.num_versions(), 1);

    // If we query for each value, we should see the correct reversions.
    let view = history.get_view_at(version_1)?;

    assert_eq!(view.value(&key_1), Some(value_1));
    assert_eq!(view.value(&key_2), Some(EMPTY_WORD));
    assert_eq!(view.value(&key_3), Some(EMPTY_WORD));

    // We should also now see this lineage listed as having a non-empty history.
    assert!(forest.get_non_empty_histories().contains(&lineage_1));

    // Finally, if we provide an update that does not change the tree, the method should succeed but
    // not result in any state changes.
    assert_eq!(forest.lineage_roots(lineage_1).unwrap().count(), 2);
    let empty_ops = SmtUpdateBatch::default();
    let version_3 = version_2 + 1;
    forest.update_tree(lineage_1, version_3, empty_ops)?;
    assert_eq!(forest.lineage_roots(lineage_1).unwrap().count(), 2);
    let history = forest.get_history(lineage_1);
    assert_eq!(history.num_versions(), 1);

    Ok(())
}

// MULTI-TREE MODIFIER TESTS
// ================================================================================================

#[test]
fn add_lineages() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0xa1; 32]);

    // An empty batch should return an empty result and leave the forest unchanged.
    let version: VersionId = rng.value();
    let empty_batch = SmtForestUpdateBatch::empty();
    let results = forest.add_lineages(version, empty_batch)?;
    assert!(results.is_empty());

    // We can add multiple distinct lineages at once, each with their own data.
    let lineage_1: LineageId = rng.value();
    let lineage_2: LineageId = rng.value();
    let lineage_3: LineageId = rng.value();

    let l1_key: Word = rng.value();
    let l1_value: Word = rng.value();
    let l2_key: Word = rng.value();
    let l2_value: Word = rng.value();

    let mut batch = SmtForestUpdateBatch::empty();
    batch.operations(lineage_1).add_insert(l1_key, l1_value);
    batch.operations(lineage_2).add_insert(l2_key, l2_value);
    batch.operations(lineage_3); // empty lineage — should still be added

    let results = forest.add_lineages(version, batch)?;
    assert_eq!(results.len(), 3);

    // Verify roots match reference Smt trees.
    let mut tree_1 = Smt::new();
    tree_1.insert(l1_key, l1_value)?;
    let mut tree_2 = Smt::new();
    tree_2.insert(l2_key, l2_value)?;
    let tree_3 = Smt::new();

    assert!(
        results.iter().any(|r| r.lineage() == lineage_1
            && r.root() == tree_1.root()
            && r.version() == version)
    );
    assert!(
        results.iter().any(|r| r.lineage() == lineage_2
            && r.root() == tree_2.root()
            && r.version() == version)
    );
    assert!(
        results.iter().any(|r| r.lineage() == lineage_3
            && r.root() == tree_3.root()
            && r.version() == version)
    );

    // Verify lineage_data is populated via root_info.
    assert_eq!(
        forest.root_info(TreeId::new(lineage_1, version)),
        RootInfo::LatestVersion(tree_1.root())
    );
    assert_eq!(
        forest.root_info(TreeId::new(lineage_2, version)),
        RootInfo::LatestVersion(tree_2.root())
    );
    assert_eq!(
        forest.root_info(TreeId::new(lineage_3, version)),
        RootInfo::LatestVersion(tree_3.root())
    );

    // New lineages should have empty histories.
    assert!(!forest.get_non_empty_histories().contains(&lineage_1));
    assert!(!forest.get_non_empty_histories().contains(&lineage_2));
    assert!(!forest.get_non_empty_histories().contains(&lineage_3));

    // Adding a batch that contains an already-known lineage should fail with DuplicateLineage.
    let lineage_4: LineageId = rng.value();
    let mut dup_batch = SmtForestUpdateBatch::empty();
    dup_batch.operations(lineage_1); // already exists
    dup_batch.operations(lineage_4); // new

    let result = forest.add_lineages(version, dup_batch);
    assert!(result.is_err());
    assert_matches!(
        result.unwrap_err(),
        LargeSmtForestError::DuplicateLineage(l) if l == lineage_1
    );

    // The failed batch should not have added lineage_4.
    assert_eq!(forest.root_info(TreeId::new(lineage_4, version)), RootInfo::Missing);

    Ok(())
}

#[test]
fn update_forest() -> Result<()> {
    let backend = ForestInMemoryBackend::new();
    let mut forest = Forest::new(backend)?;
    let mut rng = ContinuousRng::new([0x69; 32]);

    // Let's start by adding a few empty lineages to the forest, just so we have a starting point.
    // Adding all of these should succeed as they are disjoint lineages.
    let version_1: VersionId = rng.value();
    let lineage_1: LineageId = rng.value();
    let lineage_2: LineageId = rng.value();
    let lineage_3: LineageId = rng.value();
    let lineage_4: LineageId = rng.value();

    let l1_r1 = forest.add_lineage(lineage_1, version_1, SmtUpdateBatch::default())?;
    let l2_r1 = forest.add_lineage(lineage_2, version_1, SmtUpdateBatch::default())?;
    let l3_r1 = forest.add_lineage(lineage_3, version_1, SmtUpdateBatch::default())?;
    let l4_r1 = forest.add_lineage(lineage_4, version_1, SmtUpdateBatch::default())?;

    // Let's compose some updates.
    let l1_key_1: Word = rng.value();
    let l1_value_1: Word = rng.value();
    let l2_key_1: Word = rng.value();
    let l2_value_1: Word = rng.value();
    let l3_key_1: Word = rng.value();
    let l3_value_1: Word = rng.value();
    let l4_key_1: Word = rng.value();
    let l4_value_1: Word = rng.value();

    // First we want to test the case where we refer to a lineage that doesn't exist. In this case,
    // we should get an error.
    let ne_lineage: LineageId = rng.value();
    let version_bad = version_1 - 1;
    let version_2 = version_1 + 1;
    let mut operations_ne_lineage = SmtForestUpdateBatch::empty();
    operations_ne_lineage.operations(lineage_1).add_insert(l1_key_1, l1_value_1);
    operations_ne_lineage.operations(lineage_2).add_insert(l2_key_1, l2_value_1);
    operations_ne_lineage.operations(lineage_3).add_insert(l3_key_1, l3_value_1);
    operations_ne_lineage.operations(lineage_4).add_insert(l4_key_1, l4_value_1);
    let operations_basic = operations_ne_lineage.clone();
    operations_ne_lineage.operations(ne_lineage);

    let result = forest.update_forest(version_2, operations_ne_lineage);
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), LargeSmtForestError::UnknownLineage(l) if l == ne_lineage);

    // When a precondition check like this fails, we should also have unchanged state.
    assert_eq!(
        forest.root_info(TreeId::new(lineage_1, version_1)),
        RootInfo::LatestVersion(l1_r1.root())
    );
    assert_eq!(
        forest.root_info(TreeId::new(lineage_2, version_1)),
        RootInfo::LatestVersion(l2_r1.root())
    );
    assert_eq!(
        forest.root_info(TreeId::new(lineage_3, version_1)),
        RootInfo::LatestVersion(l3_r1.root())
    );
    assert_eq!(
        forest.root_info(TreeId::new(lineage_4, version_1)),
        RootInfo::LatestVersion(l4_r1.root())
    );

    // We also want to test that we get an error when we ask for a bad version transition.
    let result = forest.update_forest(version_bad, operations_basic.clone());
    assert!(result.is_err());
    assert_matches!(
        result.unwrap_err(),
        LargeSmtForestError::BadVersion { provided, latest }
            if provided == version_bad && latest == version_1
    );

    // This should also leave the internal state unchanged.
    assert_eq!(
        forest.root_info(TreeId::new(lineage_1, version_1)),
        RootInfo::LatestVersion(l1_r1.root())
    );
    assert_eq!(
        forest.root_info(TreeId::new(lineage_2, version_1)),
        RootInfo::LatestVersion(l2_r1.root())
    );
    assert_eq!(
        forest.root_info(TreeId::new(lineage_3, version_1)),
        RootInfo::LatestVersion(l3_r1.root())
    );
    assert_eq!(
        forest.root_info(TreeId::new(lineage_4, version_1)),
        RootInfo::LatestVersion(l4_r1.root())
    );

    // When a batch goes ahead successfully we should just get back the new roots to the trees,
    // which can be associated by their lineages.
    let roots = forest.update_forest(version_2, operations_basic)?;
    assert_eq!(roots.len(), 4);

    // We can check that the updates went correctly by using auxiliary trees, and checking the
    // values in the returned roots.
    let mut tree_1 = Smt::new();
    tree_1.insert(l1_key_1, l1_value_1)?;
    let mut tree_2 = Smt::new();
    tree_2.insert(l2_key_1, l2_value_1)?;
    let mut tree_3 = Smt::new();
    tree_3.insert(l3_key_1, l3_value_1)?;
    let mut tree_4 = Smt::new();
    tree_4.insert(l4_key_1, l4_value_1)?;

    assert!(roots.iter().any(|e| e.root() == tree_1.root()
        && e.version() == version_2
        && e.lineage() == lineage_1));
    assert!(roots.iter().any(|e| e.root() == tree_2.root()
        && e.version() == version_2
        && e.lineage() == lineage_2));
    assert!(roots.iter().any(|e| e.root() == tree_3.root()
        && e.version() == version_2
        && e.lineage() == lineage_3));
    assert!(roots.iter().any(|e| e.root() == tree_4.root()
        && e.version() == version_2
        && e.lineage() == lineage_4));

    // We also want to see that each of the updated lineages is now listed as having a non-empty
    // history.
    assert!(forest.get_non_empty_histories().contains(&lineage_1));
    assert!(forest.get_non_empty_histories().contains(&lineage_2));
    assert!(forest.get_non_empty_histories().contains(&lineage_3));
    assert!(forest.get_non_empty_histories().contains(&lineage_4));

    // We also want to see that if a batch is processed that does not result in changes for a given
    // tree, no state changes are made to that lineage. We check both the case where there are
    // operations that result in no changes, and where no operations are specified.
    let version_3 = version_2 + 1;
    let key_5: Word = rng.value();
    let value_5: Word = rng.value();
    let mut operations_with_nop = SmtForestUpdateBatch::empty();
    operations_with_nop.operations(lineage_1).add_insert(l1_key_1, l1_value_1);
    operations_with_nop.operations(lineage_2);
    operations_with_nop.operations(lineage_3).add_insert(key_5, value_5);

    // Before we make these batches happen, let's check where things stand.
    assert_eq!(forest.lineage_roots(lineage_1).unwrap().count(), 2);
    assert_eq!(forest.lineage_roots(lineage_2).unwrap().count(), 2);
    assert_eq!(forest.lineage_roots(lineage_3).unwrap().count(), 2);
    assert_eq!(forest.lineage_roots(lineage_4).unwrap().count(), 2);

    // Then we should apply the batch.
    let roots = forest.update_forest(version_3, operations_with_nop)?;
    assert_eq!(roots.len(), 3);

    // And for the no-op or unchanged cases we should not have new roots.
    assert_eq!(forest.lineage_roots(lineage_1).unwrap().count(), 2);
    assert_eq!(forest.lineage_roots(lineage_2).unwrap().count(), 2);
    assert_eq!(forest.lineage_roots(lineage_3).unwrap().count(), 3);
    assert_eq!(forest.lineage_roots(lineage_4).unwrap().count(), 2);

    Ok(())
}

// TRUNCATION
// ================================================================================================

#[test]
fn truncate_removes_emptied_lineages_from_non_empty_histories() {
    let lineage: LineageId = rand_value();
    let root: Word = rand_value();

    // Build a lineage with one historical version at version 5, and a latest version of 10.
    let mut history = History::empty(4);
    let nodes = NodeChanges::default();
    let changed_keys = ChangedKeys::default();
    history
        .add_version(rand_value(), 5, nodes, changed_keys, UNUSED_ENTRY_COUNT)
        .unwrap();
    assert_eq!(history.num_versions(), 1);

    let lineage_data = LineageData {
        history,
        latest_version: 10,
        latest_root: root,
    };

    let mut lineage_map = Map::default();
    lineage_map.insert(lineage, lineage_data);

    let mut non_empty = Set::default();
    non_empty.insert(lineage);

    let mut forest = LargeSmtForest {
        config: Config::default(),
        backend: ForestInMemoryBackend::new(),
        lineage_data: lineage_map,
        non_empty_histories: non_empty,
    };

    // Sanity: the lineage is tracked as having a non-empty history.
    assert!(forest.non_empty_histories.contains(&lineage));

    // Truncate to a version >= latest_version, which clears the history entirely.
    forest.truncate(10);

    // The lineage's history should now be empty, and it must have been removed from the set.
    assert!(
        !forest.non_empty_histories.contains(&lineage),
        "emptied lineage must be removed from non_empty_histories after truncation"
    );
}

#[test]
fn truncate_retains_non_empty_lineages_in_non_empty_histories() {
    let lineage: LineageId = rand_value();
    let root: Word = rand_value();

    // Build a lineage with two historical versions (5 and 8), latest version 15.
    let mut history = History::empty(4);
    let nodes = NodeChanges::default();
    let changed_keys = ChangedKeys::default();
    history
        .add_version(rand_value(), 5, nodes.clone(), changed_keys.clone(), UNUSED_ENTRY_COUNT)
        .unwrap();
    history
        .add_version(rand_value(), 8, nodes.clone(), changed_keys.clone(), UNUSED_ENTRY_COUNT)
        .unwrap();
    assert_eq!(history.num_versions(), 2);

    let lineage_data = LineageData {
        history,
        latest_version: 15,
        latest_root: root,
    };

    let mut lineage_map = Map::new();
    lineage_map.insert(lineage, lineage_data);

    let mut non_empty = Set::default();
    non_empty.insert(lineage);

    let mut forest = LargeSmtForest {
        config: Config::default(),
        backend: ForestInMemoryBackend::new(),
        lineage_data: lineage_map,
        non_empty_histories: non_empty,
    };

    // Truncate to version 7: removes versions older than 7, but version 8 should remain.
    // Since version < latest_version (15), LineageData::truncate returns false.
    forest.truncate(7);

    // The history still has data, so the lineage must stay in non_empty_histories.
    assert!(
        forest.non_empty_histories.contains(&lineage),
        "lineage with remaining history must stay in non_empty_histories"
    );
}

// ENTRIES UNHAPPY PATH TESTS
// ================================================================================================

#[test]
fn entries_with_fallible_backend() -> Result<()> {
    let backend = FallibleEntriesBackend::new();
    let mut forest = LargeSmtForest::new(backend)?;
    let mut rng = ContinuousRng::new([0xfa; 32]);

    // Add a lineage with more than 3 entries so we can verify that entries beyond the failure
    // point are never returned.
    let lineage: LineageId = rng.value();
    let version: VersionId = rng.value();
    let key_1: Word = rng.value();
    let value_1: Word = rng.value();
    let key_2: Word = rng.value();
    let value_2: Word = rng.value();
    let key_3: Word = rng.value();
    let value_3: Word = rng.value();
    let key_4: Word = rng.value();
    let value_4: Word = rng.value();
    let key_5: Word = rng.value();
    let value_5: Word = rng.value();

    let mut operations = SmtUpdateBatch::empty();
    operations.add_insert(key_1, value_1);
    operations.add_insert(key_2, value_2);
    operations.add_insert(key_3, value_3);
    operations.add_insert(key_4, value_4);
    operations.add_insert(key_5, value_5);

    forest.add_lineage(lineage, version, operations)?;

    // Query entries on the current version (WithoutHistory path).
    let tree_id = TreeId::new(lineage, version);
    let mut iter = forest.entries(tree_id)?;

    // First two items should be Ok.
    let first = iter.next();
    assert!(matches!(first, Some(Ok(_))), "expected first item to be Some(Ok(...))");
    let second = iter.next();
    assert!(matches!(second, Some(Ok(_))), "expected second item to be Some(Ok(...))");

    // Third item should be the simulated error.
    let third = iter.next();
    assert_matches!(&third, Some(Err(LargeSmtForestError::Unspecified(msg))) if msg == "simulated read failure");

    // After faulting, the iterator must yield None — the remaining entries (4th, 5th) are never
    // returned.
    assert!(iter.next().is_none(), "expected None after error");
    assert!(iter.next().is_none(), "expected iterator to remain exhausted");

    Ok(())
}

#[test]
fn entry_count_historical_bypasses_fallible_entries_iterator() -> Result<()> {
    let backend = FallibleEntriesBackend::new();
    let mut forest = LargeSmtForest::new(backend)?;
    let mut rng = ContinuousRng::new([0xfb; 32]);

    // Add a lineage with 5 entries at version V1.
    let lineage: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let key_1: Word = rng.value();
    let value_1: Word = rng.value();
    let key_2: Word = rng.value();
    let value_2: Word = rng.value();
    let key_3: Word = rng.value();
    let value_3: Word = rng.value();
    let key_4: Word = rng.value();
    let value_4: Word = rng.value();
    let key_5: Word = rng.value();
    let value_5: Word = rng.value();

    let mut operations = SmtUpdateBatch::empty();
    operations.add_insert(key_1, value_1);
    operations.add_insert(key_2, value_2);
    operations.add_insert(key_3, value_3);
    operations.add_insert(key_4, value_4);
    operations.add_insert(key_5, value_5);

    forest.add_lineage(lineage, version_1, operations)?;

    // Update the tree at V2 so V1 becomes historical.
    let version_2: VersionId = version_1 + 1;
    let key_6: Word = rng.value();
    let value_6: Word = rng.value();
    let mut operations = SmtUpdateBatch::empty();
    operations.add_insert(key_6, value_6);
    forest.update_tree(lineage, version_2, operations)?;

    // Query entry_count for the historical version V1.
    // With the stored entry count optimization, this no longer iterates through entries,
    // so it succeeds even with a fallible backend.
    let result = forest.entry_count(TreeId::new(lineage, version_1));
    assert_eq!(result?, 5);

    Ok(())
}
