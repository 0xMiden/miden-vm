#![cfg(test)]
//! This module contains the basic functional tests for the persistent backend for the SMT forest.
//!
//! Rather than hard-code specific values for the trees, these tests rely on the correctness of the
//! existing [`Smt`] implementation, comparing the results of the persistent backend against it
//! wherever relevant.

use alloc::vec::Vec;

use assert_matches::assert_matches;
use itertools::Itertools;
use tempfile::{TempDir, tempdir};

use super::{PersistentBackend, Result};
use crate::{
    EMPTY_WORD, Word,
    merkle::smt::{
        Backend, BackendError, LineageId, Smt, SmtForestUpdateBatch, SmtUpdateBatch, TreeEntry,
        TreeWithRoot, VersionId, large_forest::backend::persistent::config::Config,
    },
    rand::test_utils::ContinuousRng,
};

// UTILITIES
// ================================================================================================

/// Builds an empty persistent backend that contains no data at a random temporary file path that
/// will be subject to clean up.
///
/// It returns the temporary directory handle as well so that it can be ensured to live for the
/// lifetime of the caller's scope at a minimum.
///
/// It is necessary to explicitly hold onto the returned directory until the end of the scope in
/// order to ensure correct cleanup behavior.
pub fn default_backend() -> Result<(TempDir, PersistentBackend)> {
    let temp_path = tempdir()?;
    let config = Config::new(temp_path.path())?;
    let backend = PersistentBackend::load(config)?;

    Ok((temp_path, backend))
}

// CONSTRUCTION
// ================================================================================================

#[test]
fn load_empty() -> Result<()> {
    // Construction of a backend passing a new path in the config will initialize the backend with
    // no data.
    let temp_path = tempdir()?;
    let config = Config::new(temp_path.path())?;
    let backend = PersistentBackend::load(config)?;

    // This means that it should have no lineages, and no trees.
    assert!(backend.lineages.is_empty());
    assert_eq!(backend.trees()?.count(), 0);

    Ok(())
}

#[test]
fn load_extant() -> Result<()> {
    // We start by creating an empty backend and populating it with some lineages.
    let (path, mut backend) = default_backend()?;
    let mut rng = ContinuousRng::new([0x42; 32]);
    let version: VersionId = rng.value();

    let lineage_1: LineageId = rng.value();
    let l1_k1: Word = rng.value();
    let l1_v1: Word = rng.value();
    let l1_k2: Word = rng.value();
    let l1_v2: Word = rng.value();
    let l1_batch = SmtUpdateBatch::from([(l1_k1, l1_v1), (l1_k2, l1_v2)].into_iter());

    let lineage_2: LineageId = rng.value();
    let l2_k1: Word = rng.value();
    let l2_v1: Word = rng.value();
    let l2_k2: Word = rng.value();
    let l2_v2: Word = rng.value();
    let l2_batch = SmtUpdateBatch::from([(l2_k1, l2_v1), (l2_k2, l2_v2)].into_iter());

    let root_1 = backend.add_lineage(lineage_1, version, l1_batch)?;
    let root_2 = backend.add_lineage(lineage_2, version, l2_batch)?;

    // We check the values against reference SMTs.
    let tree_1 = Smt::with_entries([(l1_k1, l1_v1), (l1_k2, l1_v2)].into_iter())?;
    let tree_2 = Smt::with_entries([(l2_k1, l2_v1), (l2_k2, l2_v2)].into_iter())?;

    assert_eq!(root_1.root(), tree_1.root());
    assert_eq!(root_2.root(), tree_2.root());

    // We can check that certain things are true now.
    assert_eq!(backend.lineages()?.count(), 2);
    assert_eq!(backend.trees()?.count(), 2);

    // Next we force it to close, which will leave our data on disk with a forced sync.
    drop(backend);

    // We should then be able to re-open it again at the same path.
    let backend = PersistentBackend::load(Config::new(path.path())?)?;

    // And more importantly it should have the same data.
    assert_eq!(backend.lineages()?.count(), 2);
    assert_eq!(backend.trees()?.count(), 2);
    assert!(backend.lineages()?.contains(&lineage_1));
    assert!(backend.lineages()?.contains(&lineage_2));
    assert_eq!(backend.version(lineage_1)?, version);
    assert_eq!(backend.version(lineage_2)?, version);
    assert!(backend.trees()?.contains(&root_1));
    assert!(backend.trees()?.contains(&root_2));

    // And we should be able to perform openings on it...
    let l1_opening = backend.open(lineage_1, l1_k1)?;
    let t1_opening = tree_1.open(&l1_k1);
    assert_eq!(l1_opening, t1_opening);

    let l2_opening = backend.open(lineage_2, l2_k1)?;
    let t2_opening = tree_2.open(&l2_k1);
    assert_eq!(l2_opening, t2_opening);

    // ...as well as get...
    let l1_value = backend.get(lineage_1, l1_k2)?;
    let t1_value = tree_1.get_value(&l1_k2);
    assert_eq!(l1_value, Some(t1_value));

    let l2_value = backend.get(lineage_2, l2_k1)?;
    let t2_value = tree_2.get_value(&l2_k1);
    assert_eq!(l2_value, Some(t2_value));

    // ...and entries.
    let l1_entries = backend
        .entries(lineage_1)?
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .sorted()
        .collect_vec();
    let t1_entries = tree_1
        .entries()
        .sorted()
        .map(|(k, v)| TreeEntry { key: *k, value: *v })
        .collect_vec();
    assert_eq!(l1_entries, t1_entries);

    let l2_entries = backend
        .entries(lineage_2)?
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .sorted()
        .collect_vec();
    let t2_entries = tree_2
        .entries()
        .sorted()
        .map(|(k, v)| TreeEntry { key: *k, value: *v })
        .collect_vec();
    assert_eq!(l2_entries, t2_entries);

    Ok(())
}

// BACKEND TRAIT
// ================================================================================================

#[test]
fn open() -> Result<()> {
    let (_file, mut backend) = default_backend()?;
    let mut rng = ContinuousRng::new([0xab; 32]);

    // When we `open` for a lineage that has never been added to the backend, it should yield an
    // error.
    let ne_lineage: LineageId = rng.value();
    let random_key: Word = rng.value();
    let result = backend.open(ne_lineage, random_key);
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), BackendError::UnknownLineage(l) if l == ne_lineage);

    // Let's now add a tree with a few items in it to the forest.
    let lineage_1: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let key_1: Word = rng.value();
    let value_1: Word = rng.value();
    let key_2: Word = rng.value();
    let value_2: Word = rng.value();

    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(key_1, value_1);
    operations.add_insert(key_2, value_2);

    backend.add_lineage(lineage_1, version_1, operations)?;

    // We also want to match this against a reference merkle tree to check correctness, so let's
    // create that now.
    let mut tree = Smt::new();
    tree.insert(key_1, value_1)?;
    tree.insert(key_2, value_2)?;

    // Let's first get the backend's opening for a key that hasn't been inserted. This should still
    // return properly, and should match the opening provided by the reference tree.
    let backend_result = backend.open(lineage_1, random_key)?;
    let smt_result = tree.open(&random_key);
    assert_eq!(backend_result, smt_result);

    // It should also generate correct openings for both of the inserted values.
    assert_eq!(backend.open(lineage_1, key_1)?, tree.open(&key_1));
    assert_eq!(backend.open(lineage_1, key_2)?, tree.open(&key_2));

    Ok(())
}

#[test]
fn get() -> Result<()> {
    let (_file, mut backend) = default_backend()?;
    let mut rng = ContinuousRng::new([0x67; 32]);

    // When we `get` for a lineage that has never been added to the backend, it should yield an
    // error.
    let ne_lineage: LineageId = rng.value();
    let random_key: Word = rng.value();
    let result = backend.get(ne_lineage, random_key);
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), BackendError::UnknownLineage(l) if l == ne_lineage);

    // Let's now add a tree with a few items in it to the forest.
    let lineage_1: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let key_1: Word = rng.value();
    let value_1: Word = rng.value();
    let key_2: Word = rng.value();
    let value_2: Word = rng.value();

    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(key_1, value_1);
    operations.add_insert(key_2, value_2);

    backend.add_lineage(lineage_1, version_1, operations)?;

    // We also want to match this against a reference merkle tree to check correctness, so let's
    // create that now.
    let mut tree = Smt::new();
    tree.insert(key_1, value_1)?;
    tree.insert(key_2, value_2)?;

    // Let's first get the backend's result for a key that hasn't been inserted. This should return
    // `None` in our case.
    assert!(backend.get(lineage_1, random_key)?.is_none());

    // It should also provide correct values for both of the inserted values.
    assert_eq!(backend.get(lineage_1, key_1)?.unwrap(), tree.get_value(&key_1));
    assert_eq!(backend.get(lineage_1, key_2)?.unwrap(), tree.get_value(&key_2));

    Ok(())
}

#[test]
fn version() -> Result<()> {
    let (_file, mut backend) = default_backend()?;
    let mut rng = ContinuousRng::new([0x52; 32]);

    // Getting the version for a lineage that the backend doesn't know about should yield an error.
    let ne_lineage: LineageId = rng.value();
    let result = backend.version(ne_lineage);
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), BackendError::UnknownLineage(l) if l == ne_lineage);

    // Let's now shove a tree into the backend.
    let lineage_1: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let key_1: Word = rng.value();
    let value_1: Word = rng.value();
    let key_2: Word = rng.value();
    let value_2: Word = rng.value();

    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(key_1, value_1);
    operations.add_insert(key_2, value_2);

    backend.add_lineage(lineage_1, version_1, operations)?;

    // The forest should return the correct version if asked for the version of the lineage.
    assert_eq!(backend.version(lineage_1)?, version_1);

    Ok(())
}

#[test]
fn lineages() -> Result<()> {
    let (_file, mut backend) = default_backend()?;
    let mut rng = ContinuousRng::new([0x96; 32]);

    // Initially there should be no lineages.
    assert_eq!(backend.lineages()?.count(), 0);

    // We'll use the same data for each tree here to simplify the test.
    let key_1: Word = rng.value();
    let value_1: Word = rng.value();
    let key_2: Word = rng.value();
    let value_2: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(key_1, value_1);
    operations.add_insert(key_2, value_2);

    let version: VersionId = rng.value();

    // Let's start by adding one lineage and checking that the iterator contains it.
    let lineage_1: LineageId = rng.value();
    backend.add_lineage(lineage_1, version, operations.clone())?;
    assert_eq!(backend.lineages()?.count(), 1);
    assert!(backend.lineages()?.contains(&lineage_1));

    // We add another
    let lineage_2: LineageId = rng.value();
    backend.add_lineage(lineage_2, version, operations.clone())?;
    assert_eq!(backend.lineages()?.count(), 2);
    assert!(backend.lineages()?.contains(&lineage_1));
    assert!(backend.lineages()?.contains(&lineage_2));

    // And yet another
    let lineage_3: LineageId = rng.value();
    backend.add_lineage(lineage_3, version, operations.clone())?;
    assert_eq!(backend.lineages()?.count(), 3);
    assert!(backend.lineages()?.contains(&lineage_1));
    assert!(backend.lineages()?.contains(&lineage_2));
    assert!(backend.lineages()?.contains(&lineage_3));

    Ok(())
}

#[test]
fn trees() -> Result<()> {
    let (_file, mut backend) = default_backend()?;
    let mut rng = ContinuousRng::new([0x4a; 32]);

    // Initially there should be no lineages.
    assert_eq!(backend.lineages()?.count(), 0);

    // We need individual trees and versions here to check on the roots, so let's add our first
    // tree.
    let key_1_1: Word = rng.value();
    let value_1_1: Word = rng.value();
    let key_1_2: Word = rng.value();
    let value_1_2: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(key_1_1, value_1_1);
    operations.add_insert(key_1_2, value_1_2);

    let lineage_1: LineageId = rng.value();
    let version_1: VersionId = rng.value();

    backend.add_lineage(lineage_1, version_1, operations)?;

    let mut tree_1 = Smt::new();
    tree_1.insert(key_1_1, value_1_1)?;
    tree_1.insert(key_1_2, value_1_2)?;

    // With one tree added we should only see one root.
    assert_eq!(backend.trees()?.count(), 1);
    assert!(
        backend
            .trees()?
            .contains(&TreeWithRoot::new(lineage_1, version_1, tree_1.root()))
    );

    // Let's add another tree.
    let key_2_1: Word = rng.value();
    let value_2_1: Word = rng.value();
    let key_2_2: Word = rng.value();
    let value_2_2: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(key_2_1, value_2_1);
    operations.add_insert(key_2_2, value_2_2);

    let lineage_2: LineageId = rng.value();
    let version_2: VersionId = rng.value();

    backend.add_lineage(lineage_2, version_2, operations)?;

    let mut tree_2 = Smt::new();
    tree_2.insert(key_2_1, value_2_1)?;
    tree_2.insert(key_2_2, value_2_2)?;

    // With two added we should see two roots.
    assert_eq!(backend.trees()?.count(), 2);
    assert!(
        backend
            .trees()?
            .contains(&TreeWithRoot::new(lineage_1, version_1, tree_1.root()))
    );
    assert!(
        backend
            .trees()?
            .contains(&TreeWithRoot::new(lineage_2, version_2, tree_2.root()))
    );

    // Let's add one more, just as a sanity check.
    let key_3_1: Word = rng.value();
    let value_3_1: Word = rng.value();
    let key_3_2: Word = rng.value();
    let value_3_2: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(key_3_1, value_3_1);
    operations.add_insert(key_3_2, value_3_2);

    let lineage_3: LineageId = rng.value();
    let version_3: VersionId = rng.value();

    backend.add_lineage(lineage_3, version_3, operations)?;

    let mut tree_3 = Smt::new();
    tree_3.insert(key_3_1, value_3_1)?;
    tree_3.insert(key_3_2, value_3_2)?;

    // With that added, we should see three.
    assert_eq!(backend.trees()?.count(), 3);
    assert!(
        backend
            .trees()?
            .contains(&TreeWithRoot::new(lineage_1, version_1, tree_1.root()))
    );
    assert!(
        backend
            .trees()?
            .contains(&TreeWithRoot::new(lineage_2, version_2, tree_2.root()))
    );
    assert!(
        backend
            .trees()?
            .contains(&TreeWithRoot::new(lineage_3, version_3, tree_3.root()))
    );

    Ok(())
}

#[test]
fn entry_count() -> Result<()> {
    let (_file, mut backend) = default_backend()?;
    let mut rng = ContinuousRng::new([0x01; 32]);

    // It should yield an error for a lineage that doesn't exist.
    let ne_lineage: LineageId = rng.value();
    let result = backend.entry_count(ne_lineage);
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), BackendError::UnknownLineage(l) if l == ne_lineage);

    let version: VersionId = rng.value();

    // Let's start by adding a new lineage with an entirely empty tree.
    let lineage_1: LineageId = rng.value();
    backend.add_lineage(lineage_1, version, SmtUpdateBatch::default())?;

    // When queried, this should yield zero entries.
    assert_eq!(backend.entry_count(lineage_1)?, 0);

    // Now let's modify that tree to add entries.
    let key_1_1: Word = rng.value();
    let value_1_1: Word = rng.value();
    let key_1_2: Word = rng.value();
    let value_1_2: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(key_1_1, value_1_1);
    operations.add_insert(key_1_2, value_1_2);

    backend.update_tree(lineage_1, version, operations)?;

    // Now if we query we should get two entries.
    assert_eq!(backend.entry_count(lineage_1)?, 2);

    Ok(())
}

#[test]
fn entries() -> Result<()> {
    let (_file, mut backend) = default_backend()?;
    let mut rng = ContinuousRng::new([0xa0; 32]);

    // It should yield an error for a lineage that doesn't exist.
    let ne_lineage: LineageId = rng.value();
    let result = backend.entries(ne_lineage);
    assert!(result.is_err());
    match result {
        Err(BackendError::UnknownLineage(l)) => {
            assert_eq!(l, ne_lineage);
        },
        _ => panic!("Incorrect result encountered"),
    }
    drop(result); // Forget the borrow.

    let version: VersionId = rng.value();

    // If we add an empty lineage, the iterator should yield no items.
    let lineage_1: LineageId = rng.value();
    backend.add_lineage(lineage_1, version, SmtUpdateBatch::default())?;
    assert_eq!(backend.entries(lineage_1)?.count(), 0);

    // So let's add some entries.
    let key_1_1: Word = rng.value();
    let value_1_1: Word = rng.value();
    let key_1_2: Word = rng.value();
    let value_1_2: Word = rng.value();
    let mut key_1_3: Word = rng.value();
    key_1_3[3] = key_1_1[3];
    let value_1_3: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(key_1_1, value_1_1);
    operations.add_insert(key_1_2, value_1_2);
    operations.add_insert(key_1_3, value_1_3);
    backend.update_tree(lineage_1, version, operations)?;

    // Now, the iterator should yield the expected three items.
    let entries = backend.entries(lineage_1)?.collect::<Result<Vec<_>>>()?;
    assert_eq!(entries.len(), 3);
    assert!(entries.contains(&TreeEntry { key: key_1_1, value: value_1_1 }));
    assert!(entries.contains(&TreeEntry { key: key_1_2, value: value_1_2 }));
    assert!(entries.contains(&TreeEntry { key: key_1_3, value: value_1_3 }));

    Ok(())
}

#[test]
fn add_lineage() -> Result<()> {
    let (_file, mut backend) = default_backend()?;
    let mut rng = ContinuousRng::new([0x49; 32]);
    let version: VersionId = rng.value();

    // We should be able to add a lineage without actually changing the empty tree.
    let lineage_1: LineageId = rng.value();
    backend.add_lineage(lineage_1, version, SmtUpdateBatch::default())?;
    assert_eq!(backend.entry_count(lineage_1)?, 0);

    // Adding a lineage with a duplicate lineage identifier should yield an error.
    let result = backend.add_lineage(lineage_1, version, SmtUpdateBatch::default());
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), BackendError::DuplicateLineage(l) if l == lineage_1);

    // But we should also be able to add lineages that _contain data_ from the get-go.
    let key_2_1: Word = rng.value();
    let value_2_1: Word = rng.value();
    let key_2_2: Word = rng.value();
    let value_2_2: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(key_2_1, value_2_1);
    operations.add_insert(key_2_2, value_2_2);

    let lineage_2: LineageId = rng.value();
    let root = backend.add_lineage(lineage_2, version, operations)?;
    assert_eq!(backend.entry_count(lineage_2)?, 2);

    // Let's build an auxiliary tree to check this.
    let mut tree = Smt::new();
    tree.insert(key_2_1, value_2_1)?;
    tree.insert(key_2_2, value_2_2)?;

    // Check we get the right values for the root.
    assert_eq!(root.root(), tree.root());

    Ok(())
}

#[test]
fn update_tree() -> Result<()> {
    let (_file, mut backend) = default_backend()?;
    let mut rng = ContinuousRng::new([0x49; 32]);

    // Updating a lineage that does not exist should result in an error.
    let ne_lineage: LineageId = rng.value();
    let result = backend.update_tree(ne_lineage, rng.value(), SmtUpdateBatch::default());
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), BackendError::UnknownLineage(l) if l == ne_lineage);

    // So let's add an actual lineage.
    let key_1_1: Word = rng.value();
    let value_1_1: Word = rng.value();
    let key_1_2: Word = rng.value();
    let value_1_2: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(key_1_1, value_1_1);
    operations.add_insert(key_1_2, value_1_2);
    let lineage_1: LineageId = rng.value();
    let version_1: VersionId = rng.value();

    backend.add_lineage(lineage_1, version_1, operations)?;

    // And check that it agrees with a standard tree.
    let mut tree_1 = Smt::new();
    tree_1.insert(key_1_1, value_1_1)?;
    tree_1.insert(key_1_2, value_1_2)?;

    assert_eq!(backend.trees()?.count(), 1);
    assert!(backend.trees()?.any(|e| e.root() == tree_1.root()));

    // Now let's add another node to the tree! Note that reusing the same version does not matter;
    // version consistency is enforced by the FOREST and not the backend.
    let version_2 = version_1 + 1;
    let key_1_3: Word = rng.value();
    let value_1_3: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(key_1_3, value_1_3);
    let backend_revs_1 = backend.update_tree(lineage_1, version_2, operations)?;
    assert_eq!(backend.trees()?.count(), 1);

    // And we can check against our other tree for consistency again.
    let mutations = tree_1.compute_mutations([(key_1_3, value_1_3)].into_iter())?;
    let tree_revs_1 = tree_1.apply_mutations_with_reversion(mutations)?;

    assert!(backend.trees()?.any(|e| e.root() == tree_1.root()));
    assert_eq!(backend_revs_1, tree_revs_1);

    // Now let's try a remove operation.
    let version_3 = version_2 + 1;
    let mut operations = SmtUpdateBatch::default();
    operations.add_remove(key_1_2);
    let backend_revs_2 = backend.update_tree(lineage_1, version_3, operations)?;

    // And check it against our other tree for consistency.
    let mutations = tree_1.compute_mutations([(key_1_2, EMPTY_WORD)])?;
    let tree_revs_2 = tree_1.apply_mutations_with_reversion(mutations)?;
    assert_eq!(backend.trees()?.count(), 1);
    assert!(backend.trees()?.any(|e| e.root() == tree_1.root()));
    assert_eq!(backend_revs_2, tree_revs_2);

    Ok(())
}

#[test]
fn update_forest() -> Result<()> {
    let (_file, mut backend) = default_backend()?;
    let mut rng = ContinuousRng::new([0x51; 32]);
    let version: VersionId = rng.value();

    // Let's start by adding two trees to the forest.
    let lineage_1: LineageId = rng.value();
    let key_1_1: Word = rng.value();
    let value_1_1: Word = rng.value();
    let key_1_2: Word = rng.value();
    let value_1_2: Word = rng.value();
    let mut operations_1 = SmtUpdateBatch::default();
    operations_1.add_insert(key_1_1, value_1_1);
    operations_1.add_insert(key_1_2, value_1_2);

    let lineage_2: LineageId = rng.value();
    let key_2_1: Word = rng.value();
    let value_2_1: Word = rng.value();
    let mut operations_2 = SmtUpdateBatch::default();
    operations_2.add_insert(key_2_1, value_2_1);

    backend.add_lineage(lineage_1, version, operations_1)?;
    backend.add_lineage(lineage_2, version, operations_2)?;

    // Let's replicate them with SMTs to check correctness.
    let mut tree_1 = Smt::new();
    tree_1.insert(key_1_1, value_1_1)?;
    tree_1.insert(key_1_2, value_1_2)?;

    let mut tree_2 = Smt::new();
    tree_2.insert(key_2_1, value_2_1)?;

    // At this point we should have two trees in the forest, and their roots should match the trees
    // we're checking against.
    assert_eq!(backend.trees()?.count(), 2);
    assert!(backend.trees()?.any(|e| e.root() == tree_1.root()));
    assert!(backend.trees()?.any(|e| e.root() == tree_2.root()));

    // Let's do a batch modification to start with, doing an insert into both trees.
    let key_1_3: Word = rng.value();
    let value_1_3: Word = rng.value();
    let key_2_2: Word = rng.value();
    let value_2_2: Word = rng.value();

    let mut forest_ops = SmtForestUpdateBatch::empty();
    forest_ops.operations(lineage_1).add_insert(key_1_3, value_1_3);
    forest_ops.operations(lineage_2).add_insert(key_2_2, value_2_2);

    backend.update_forest(version, forest_ops)?;

    // We can check these results against our trees.
    tree_1.insert(key_1_3, value_1_3)?;
    tree_2.insert(key_2_2, value_2_2)?;

    assert_eq!(backend.trees()?.count(), 2);
    assert!(backend.trees()?.any(|e| e.root() == tree_1.root()));
    assert!(backend.trees()?.any(|e| e.root() == tree_2.root()));

    // We should see an error when performing operations on a lineage that does not exist...
    let ne_lineage: LineageId = rng.value();
    let key_1_4: Word = rng.value();
    let value_1_4: Word = rng.value();

    let mut forest_ops = SmtForestUpdateBatch::empty();
    forest_ops.operations(lineage_1).add_insert(key_1_4, value_1_4);
    forest_ops.operations(ne_lineage).add_insert(key_1_4, value_1_4);

    let result = backend.update_forest(version, forest_ops);
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), BackendError::UnknownLineage(l) if l == ne_lineage);

    // ... but it should also leave the existing data unchanged.
    assert_eq!(backend.trees()?.count(), 2);
    assert!(backend.trees()?.any(|e| e.root() == tree_1.root()));
    assert!(backend.trees()?.any(|e| e.root() == tree_2.root()));

    Ok(())
}
