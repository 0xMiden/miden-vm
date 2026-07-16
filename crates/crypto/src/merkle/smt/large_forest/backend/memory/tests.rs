#![cfg(test)]
//! This module contains the tests for the in-memory backend for the SMT forest.
//!
//! Rather than hard-code specific values for the trees, these tests rely on the correctness of the
//! existing [`Smt`] implementation, comparing the results of the in-memory backend against it
//! wherever relevant.

use alloc::vec::Vec;

use assert_matches::assert_matches;
use itertools::Itertools;

use crate::{
    EMPTY_WORD, Word,
    merkle::smt::{
        Backend, BackendError, BackendReader, Smt, SmtForestUpdateBatch, SmtUpdateBatch, VersionId,
        large_forest::{
            InMemoryBackend,
            backend::Result,
            root::{LineageId, TreeEntry, TreeWithRoot},
        },
    },
    rand::test_utils::ContinuousRng,
};

// CONSTRUCTION
// ================================================================================================

#[test]
fn new() -> Result<()> {
    let backend = InMemoryBackend::new();

    // A newly created in-memory backend should not know about any lineages.
    assert_eq!(backend.lineages()?.count(), 0);

    // It should similarly not know about any trees.
    assert_eq!(backend.trees()?.count(), 0);

    Ok(())
}

// BACKEND TRAIT
// ================================================================================================

#[test]
fn open() -> Result<()> {
    let mut backend = InMemoryBackend::new();
    let mut rng = ContinuousRng::new([0x42; 32]);

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
    let mut backend = InMemoryBackend::new();
    let mut rng = ContinuousRng::new([0x71; 32]);

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
    let mut backend = InMemoryBackend::new();
    let mut rng = ContinuousRng::new([0x96; 32]);

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
    let mut backend = InMemoryBackend::new();
    let mut rng = ContinuousRng::new([0x91; 32]);

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
    let mut backend = InMemoryBackend::new();
    let mut rng = ContinuousRng::new([0x91; 32]);

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
    let mut backend = InMemoryBackend::new();
    let mut rng = ContinuousRng::new([0x67; 32]);

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
    let mut backend = InMemoryBackend::new();
    let mut rng = ContinuousRng::new([0x67; 32]);

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
    let mut backend = InMemoryBackend::new();
    let mut rng = ContinuousRng::new([0x76; 32]);
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
fn add_lineages() -> Result<()> {
    let mut backend = InMemoryBackend::new();
    let mut rng = ContinuousRng::new([0xa1; 32]);

    // An empty batch should return an empty result and leave the backend unchanged.
    let version: VersionId = rng.value();
    let result = backend.add_lineages(version, SmtForestUpdateBatch::empty())?;
    assert!(result.is_empty());
    assert_eq!(backend.lineages()?.count(), 0);
    assert_eq!(backend.trees()?.count(), 0);

    // A single lineage with two inserts should work correctly.
    let lineage_1: LineageId = rng.value();
    let key_1_1: Word = rng.value();
    let value_1_1: Word = rng.value();
    let key_1_2: Word = rng.value();
    let value_1_2: Word = rng.value();

    let mut batch = SmtForestUpdateBatch::empty();
    batch.operations(lineage_1).add_insert(key_1_1, value_1_1);
    batch.operations(lineage_1).add_insert(key_1_2, value_1_2);

    let result = backend.add_lineages(version, batch)?;
    assert_eq!(result.len(), 1);

    let mut ref_tree_1 = Smt::new();
    ref_tree_1.insert(key_1_1, value_1_1)?;
    ref_tree_1.insert(key_1_2, value_1_2)?;

    assert_eq!(result[0].1.root(), ref_tree_1.root());
    assert_eq!(backend.get(lineage_1, key_1_1)?, Some(value_1_1));
    assert_eq!(backend.get(lineage_1, key_1_2)?, Some(value_1_2));

    // Reset backend for multi-lineage test.
    let mut backend = InMemoryBackend::new();

    let lineage_a: LineageId = rng.value();
    let lineage_b: LineageId = rng.value();
    let lineage_c: LineageId = rng.value();

    let key_a_1: Word = rng.value();
    let value_a_1: Word = rng.value();
    let key_a_2: Word = rng.value();
    let value_a_2: Word = rng.value();
    let key_b_1: Word = rng.value();
    let value_b_1: Word = rng.value();
    let key_b_2: Word = rng.value();
    let value_b_2: Word = rng.value();
    let key_c_1: Word = rng.value();
    let value_c_1: Word = rng.value();
    let key_c_2: Word = rng.value();
    let value_c_2: Word = rng.value();

    let mut batch = SmtForestUpdateBatch::empty();
    batch.operations(lineage_a).add_insert(key_a_1, value_a_1);
    batch.operations(lineage_a).add_insert(key_a_2, value_a_2);
    batch.operations(lineage_b).add_insert(key_b_1, value_b_1);
    batch.operations(lineage_b).add_insert(key_b_2, value_b_2);
    batch.operations(lineage_c).add_insert(key_c_1, value_c_1);
    batch.operations(lineage_c).add_insert(key_c_2, value_c_2);

    let result = backend.add_lineages(version, batch)?;
    assert_eq!(result.len(), 3);

    // Build reference trees and verify roots.
    let mut ref_a = Smt::new();
    ref_a.insert(key_a_1, value_a_1)?;
    ref_a.insert(key_a_2, value_a_2)?;

    let mut ref_b = Smt::new();
    ref_b.insert(key_b_1, value_b_1)?;
    ref_b.insert(key_b_2, value_b_2)?;

    let mut ref_c = Smt::new();
    ref_c.insert(key_c_1, value_c_1)?;
    ref_c.insert(key_c_2, value_c_2)?;

    // Find each lineage in the results and check the root.
    let root_a = result.iter().find(|(l, _)| *l == lineage_a).unwrap().1.root();
    let root_b = result.iter().find(|(l, _)| *l == lineage_b).unwrap().1.root();
    let root_c = result.iter().find(|(l, _)| *l == lineage_c).unwrap().1.root();
    assert_eq!(root_a, ref_a.root());
    assert_eq!(root_b, ref_b.root());
    assert_eq!(root_c, ref_c.root());
    assert_eq!(backend.lineages()?.count(), 3);

    // Cross-lineage gets should work correctly.
    assert_eq!(backend.get(lineage_a, key_a_1)?, Some(value_a_1));
    assert_eq!(backend.get(lineage_b, key_b_2)?, Some(value_b_2));
    assert_eq!(backend.get(lineage_c, key_c_1)?, Some(value_c_1));

    // Verify gets spanning all three lineages.
    assert_eq!(backend.get(lineage_a, key_a_1)?, Some(value_a_1));
    assert_eq!(backend.get(lineage_b, key_b_1)?, Some(value_b_1));
    assert_eq!(backend.get(lineage_c, key_c_2)?, Some(value_c_2));

    // Duplicate lineage error and atomicity: pre-add one lineage, then try a batch containing it.
    let mut backend = InMemoryBackend::new();
    let existing_lineage: LineageId = rng.value();
    let new_lineage: LineageId = rng.value();

    let mut ops = SmtUpdateBatch::default();
    ops.add_insert(rng.value(), rng.value());
    backend.add_lineage(existing_lineage, version, ops)?;
    let backend_before = backend.clone();

    let mut batch = SmtForestUpdateBatch::empty();
    batch.operations(existing_lineage).add_insert(rng.value(), rng.value());
    batch.operations(new_lineage).add_insert(rng.value(), rng.value());

    let result = backend.add_lineages(version, batch);
    assert!(result.is_err());
    assert_matches!(
        result.unwrap_err(),
        BackendError::DuplicateLineage(l) if l == existing_lineage
    );

    // Backend state should be unchanged (atomicity).
    assert_eq!(backend, backend_before);

    Ok(())
}

#[test]
fn update_tree() -> Result<()> {
    let mut backend = InMemoryBackend::new();
    let mut rng = ContinuousRng::new([0x76; 32]);

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
    let key_1_3: Word = rng.value();
    let value_1_3: Word = rng.value();
    let mut operations = SmtUpdateBatch::default();
    operations.add_insert(key_1_3, value_1_3);
    let backend_revs_1 = backend.update_tree(lineage_1, version_1, operations)?;

    // And we can check against our other tree for consistency again.
    let mutations = tree_1.compute_mutations([(key_1_3, value_1_3)])?;
    let tree_revs_1 = tree_1.apply_mutations_with_reversion(mutations)?;
    assert_eq!(backend.trees()?.count(), 1);
    assert!(backend.trees()?.any(|e| e.root() == tree_1.root()));
    assert_eq!(backend_revs_1, tree_revs_1);

    // Now let's try a remove operation.
    let mut operations = SmtUpdateBatch::default();
    operations.add_remove(key_1_2);
    let backend_revs_2 = backend.update_tree(lineage_1, version_1, operations)?;

    // And check it against our other tree for consistency.
    let mutations = tree_1.compute_mutations([(key_1_2, EMPTY_WORD)])?;
    let tree_revs_2 = tree_1.apply_mutations_with_reversion(mutations)?;
    assert_eq!(backend.trees()?.count(), 1);
    assert!(backend.trees()?.any(|e| e.root() == tree_1.root()));
    assert_eq!(backend_revs_2, tree_revs_2);

    Ok(())
}

#[test]
fn apply_mutations_returns_reversion_data() -> Result<()> {
    let mut backend = InMemoryBackend::new();
    let mut rng = ContinuousRng::new([0x77; 32]);

    let lineage: LineageId = rng.value();
    let version_1: VersionId = rng.value();
    let version_2: VersionId = rng.value();
    let key_1: Word = rng.value();
    let value_1: Word = rng.value();
    let key_2: Word = rng.value();
    let value_2: Word = rng.value();
    let value_3: Word = rng.value();

    let mut initial = SmtUpdateBatch::default();
    initial.add_insert(key_1, value_1);
    initial.add_insert(key_2, value_2);
    backend.add_lineage(lineage, version_1, initial)?;

    let mut reference = Smt::new();
    reference.insert(key_1, value_1)?;
    reference.insert(key_2, value_2)?;
    let old_entry_count = reference.num_entries();

    let mut updates = SmtUpdateBatch::default();
    updates.add_insert(key_2, value_3);
    let expected_forward = reference.compute_mutations([(key_2, value_3)])?;
    let expected_reverse = reference.apply_mutations_with_reversion(expected_forward)?;

    let mut batch = SmtForestUpdateBatch::empty();
    batch.operations(lineage).add_operations(updates.into_iter());
    let (_, prepared) = backend.compute_mutations(version_2, batch)?;
    let applied = backend.apply_mutations(prepared)?;

    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].lineage(), lineage);
    assert_eq!(applied[0].old_entry_count(), old_entry_count);
    assert_eq!(applied[0].reverse(), &expected_reverse);
    assert_eq!(backend.version(lineage)?, version_2);
    assert!(backend.trees()?.any(|tree| tree.root() == reference.root()));

    Ok(())
}

#[test]
fn apply_mutations_rejects_stale_prepared_update() -> Result<()> {
    let mut backend = InMemoryBackend::new();
    let mut rng = ContinuousRng::new([0xa5; 32]);

    let lineage: LineageId = rng.value();
    let key_1: Word = rng.value();
    let value_1: Word = rng.value();
    let key_2: Word = rng.value();
    let value_2: Word = rng.value();
    let key_3: Word = rng.value();
    let value_3: Word = rng.value();

    let mut initial = SmtUpdateBatch::default();
    initial.add_insert(key_1, value_1);
    backend.add_lineage(lineage, 1, initial)?;

    let mut stale_updates = SmtUpdateBatch::default();
    stale_updates.add_insert(key_2, value_2);
    let mut stale_batch = SmtForestUpdateBatch::empty();
    stale_batch.operations(lineage).add_operations(stale_updates.into_iter());
    let (_visible, stale_prepared) = backend.compute_mutations(2, stale_batch)?;

    let mut intervening_updates = SmtUpdateBatch::default();
    intervening_updates.add_insert(key_3, value_3);
    backend.update_tree(lineage, 2, intervening_updates)?;

    assert!(
        backend.apply_mutations(stale_prepared).is_err(),
        "stale prepared mutations must not apply after the lineage root changes"
    );

    Ok(())
}

#[test]
fn update_forest() -> Result<()> {
    let mut backend = InMemoryBackend::new();
    let mut rng = ContinuousRng::new([0x76; 32]);
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
