#![cfg(test)]
//! The functional tests for the history component.

use alloc::vec::Vec;

use super::{
    super::test_utils::UNUSED_ENTRY_COUNT, ChangedKeys, History, NodeChanges, error::Result,
};
use crate::{
    EMPTY_WORD, Felt, Word,
    field::PrimeCharacteristicRing,
    merkle::{
        NodeIndex,
        smt::{LeafIndex, Smt, VersionId},
    },
    rand::test_utils::ContinuousRng,
};

// TESTS
// ================================================================================================

#[test]
fn empty() {
    let history = History::empty(5);
    assert_eq!(history.num_versions(), 0);
    assert_eq!(history.max_versions(), 5);
}

#[test]
fn roots() -> Result<()> {
    let mut rng = ContinuousRng::new([0x12; 32]);

    // Set up our test state
    let nodes = NodeChanges::default();
    let changed_keys = ChangedKeys::default();
    let mut history = History::empty(2);
    let root_1: Word = rng.value();
    let root_2: Word = rng.value();
    history.add_version(root_1, 0, nodes.clone(), changed_keys.clone(), UNUSED_ENTRY_COUNT)?;
    history.add_version(root_2, 1, nodes.clone(), changed_keys.clone(), UNUSED_ENTRY_COUNT)?;

    // We should be able to get all the roots.
    let roots = history.roots().collect::<Vec<_>>();
    assert_eq!(roots.len(), 2);
    assert!(roots.contains(&root_1));
    assert!(roots.contains(&root_2));

    Ok(())
}

#[test]
fn find_latest_corresponding_version() -> Result<()> {
    let mut rng = ContinuousRng::new([0x14; 32]);

    // Start by setting up our test data.
    let nodes = NodeChanges::default();
    let changed_keys = ChangedKeys::default();
    let mut history = History::empty(5);

    let v1 = 10;
    let v2 = 20;
    let v3 = 30;
    let v4 = 31;
    let v5 = 45;

    history.add_version(
        rng.value(),
        v1,
        nodes.clone(),
        changed_keys.clone(),
        UNUSED_ENTRY_COUNT,
    )?;
    history.add_version(
        rng.value(),
        v2,
        nodes.clone(),
        changed_keys.clone(),
        UNUSED_ENTRY_COUNT,
    )?;
    history.add_version(
        rng.value(),
        v3,
        nodes.clone(),
        changed_keys.clone(),
        UNUSED_ENTRY_COUNT,
    )?;
    history.add_version(
        rng.value(),
        v4,
        nodes.clone(),
        changed_keys.clone(),
        UNUSED_ENTRY_COUNT,
    )?;
    history.add_version(
        rng.value(),
        v5,
        nodes.clone(),
        changed_keys.clone(),
        UNUSED_ENTRY_COUNT,
    )?;

    // When we query for a version that is older than the oldest in the history we should get an
    // error.
    assert!(history.find_latest_corresponding_version(0).is_err());
    assert!(history.find_latest_corresponding_version(9).is_err());

    // When we query for the oldest version we should get its index.
    assert_eq!(history.find_latest_corresponding_version(v1), Ok(0));

    // And that goes for any other known version
    assert_eq!(history.find_latest_corresponding_version(v2), Ok(1));
    assert_eq!(history.find_latest_corresponding_version(v3), Ok(2));
    assert_eq!(history.find_latest_corresponding_version(v4), Ok(3));
    assert_eq!(history.find_latest_corresponding_version(v5), Ok(4));

    // But we can also query for versions in between.
    assert_eq!(history.find_latest_corresponding_version(11), Ok(0));
    assert_eq!(history.find_latest_corresponding_version(19), Ok(0));
    assert_eq!(history.find_latest_corresponding_version(21), Ok(1));
    assert_eq!(history.find_latest_corresponding_version(29), Ok(1));
    assert_eq!(history.find_latest_corresponding_version(32), Ok(3));
    assert_eq!(history.find_latest_corresponding_version(44), Ok(3));
    assert_eq!(history.find_latest_corresponding_version(46), Ok(4));

    Ok(())
}

#[test]
fn add_version() -> Result<()> {
    let nodes = NodeChanges::default();
    let changed_keys = ChangedKeys::default();
    let mut rng = ContinuousRng::new([0x15; 32]);

    // We start with an empty state, and we should be able to add deltas up until the limit we
    // set.
    let mut history = History::empty(2);
    assert_eq!(history.num_versions(), 0);
    assert_eq!(history.max_versions(), 2);

    let root_1: Word = rng.value();
    let id_1 = 0;
    history.add_version(root_1, id_1, nodes.clone(), changed_keys.clone(), UNUSED_ENTRY_COUNT)?;
    assert_eq!(history.num_versions(), 1);

    let root_2: Word = rng.value();
    let id_2 = 1;
    history.add_version(root_2, id_2, nodes.clone(), changed_keys.clone(), UNUSED_ENTRY_COUNT)?;
    assert_eq!(history.num_versions(), 2);

    // At this point, adding any version should remove the oldest.
    let root_3: Word = rng.value();
    let id_3 = 2;
    history.add_version(root_3, id_3, nodes.clone(), changed_keys.clone(), UNUSED_ENTRY_COUNT)?;
    assert_eq!(history.num_versions(), 2);

    // If we then query for that first version it won't be there anymore, but the other two
    // should.
    assert!(history.get_view_at(id_1).is_err());
    assert!(history.get_view_at(id_2).is_ok());
    assert!(history.get_view_at(id_3).is_ok());

    // If we try and add a version with a non-monotonic version number, we should see an error.
    assert!(
        history
            .add_version(root_3, id_1, nodes, changed_keys.clone(), UNUSED_ENTRY_COUNT)
            .is_err()
    );

    Ok(())
}

#[test]
fn add_version_from_mutation_set() -> Result<()> {
    let mut rng = ContinuousRng::new([0x16; 32]);

    // We start by producing values.
    let l1_k1: Word = rng.value();
    let leaf_1_ix = LeafIndex::from(l1_k1);
    let l1_v1: Word = rng.value();
    let mut l1_k2: Word = rng.value();
    l1_k2[3] = Felt::from_u64(leaf_1_ix.position());
    let l1_v2: Word = rng.value();

    let l2_k1: Word = rng.value();
    let leaf_2_ix = LeafIndex::from(l2_k1);
    let l2_v1: Word = rng.value();
    let mut l2_k2: Word = rng.value();
    l2_k2[3] = Felt::from_u64(leaf_2_ix.position());
    let l2_v2: Word = rng.value();

    // We produce a changeset by applying these changes to a merkle tree to put things back in the
    // right state.
    let tree = Smt::new();
    let mutations = tree
        .compute_mutations([(l1_k1, l1_v1), (l1_k2, l1_v2), (l2_k1, l2_v1), (l2_k2, l2_v2)])
        .expect("Failed to compute mutations");

    // We then set up our history and apply it.
    let mut history = History::empty(2);
    let version: VersionId = rng.value();

    history.add_version_from_mutation_set(version, mutations, UNUSED_ENTRY_COUNT)?;

    // Now we can check that it did things correctly.
    let view = history.get_view_at(version)?;
    assert_eq!(view.value(&l1_k1), Some(l1_v1));
    assert_eq!(view.value(&l1_k2), Some(l1_v2));
    assert_eq!(view.value(&l2_k1), Some(l2_v1));
    assert_eq!(view.value(&l2_k2), Some(l2_v2));

    Ok(())
}

#[test]
fn truncate() -> Result<()> {
    let mut rng = ContinuousRng::new([0x17; 32]);

    // Start by setting up the test data
    let mut history = History::empty(4);

    let nodes = NodeChanges::default();
    let changed_keys = ChangedKeys::default();

    let root_1: Word = rng.value();
    let id_1 = 5;
    history.add_version(root_1, id_1, nodes.clone(), changed_keys.clone(), UNUSED_ENTRY_COUNT)?;

    let root_2: Word = rng.value();
    let id_2 = 10;
    history.add_version(root_2, id_2, nodes.clone(), changed_keys.clone(), UNUSED_ENTRY_COUNT)?;

    let root_3: Word = rng.value();
    let id_3 = 15;
    history.add_version(root_3, id_3, nodes.clone(), changed_keys.clone(), UNUSED_ENTRY_COUNT)?;

    let root_4: Word = rng.value();
    let id_4 = 20;
    history.add_version(root_4, id_4, nodes.clone(), changed_keys.clone(), UNUSED_ENTRY_COUNT)?;

    assert_eq!(history.num_versions(), 4);

    // If we truncate to the oldest version or before, nothing should be removed.
    assert_eq!(history.truncate(0), 0);
    assert_eq!(history.num_versions(), 4);
    assert_eq!(history.truncate(4), 0);
    assert_eq!(history.num_versions(), 4);
    assert_eq!(history.truncate(id_1), 0);
    assert_eq!(history.num_versions(), 4);

    // If we truncate to a specific known version, it should remove all previous versions.
    assert_eq!(history.truncate(id_2), 1);
    assert_eq!(history.num_versions(), 3);

    // If we truncate to a version that is not known, the newest relevant version should be
    // retained.
    assert_eq!(history.truncate(16), 1);
    assert_eq!(history.num_versions(), 2);

    // If we truncate to a version beyond the newest known, only that should be retained.
    assert_eq!(history.truncate(25), 1);
    assert_eq!(history.num_versions(), 1);

    Ok(())
}

#[test]
fn clear() -> Result<()> {
    let mut rng = ContinuousRng::new([0x18; 32]);

    // Start by setting up the test data
    let mut history = History::empty(4);

    let nodes = NodeChanges::default();
    let changed_keys = ChangedKeys::default();

    let root_1: Word = rng.value();
    let id_1 = 0;
    history.add_version(root_1, id_1, nodes.clone(), changed_keys.clone(), UNUSED_ENTRY_COUNT)?;

    let root_2: Word = rng.value();
    let id_2 = 1;
    history.add_version(root_2, id_2, nodes.clone(), changed_keys.clone(), UNUSED_ENTRY_COUNT)?;

    assert_eq!(history.num_versions(), 2);

    // We can clear the history entirely in one go.
    history.clear();
    assert_eq!(history.num_versions(), 0);

    Ok(())
}

#[test]
fn view_at() -> Result<()> {
    // Starting in an empty state we should be able to add deltas up until the limit we set.
    let mut history = History::empty(3);
    let mut rng = ContinuousRng::new([0x19; 32]);
    assert_eq!(history.num_versions(), 0);
    assert_eq!(history.max_versions(), 3);

    // We can add an initial version with some changes in both nodes and leaves.
    let root_1: Word = rng.value();
    let id_1 = 3;
    let mut nodes_1 = NodeChanges::default();
    let n1_value: Word = rng.value();
    let n2_value: Word = rng.value();
    nodes_1.insert(NodeIndex::new(2, 1).unwrap(), n1_value);
    nodes_1.insert(NodeIndex::new(8, 128).unwrap(), n2_value);

    let mut changed_1 = ChangedKeys::default();

    let l1_e1_key: Word = rng.value();
    let l1_e1_value: Word = rng.value();
    changed_1.insert(l1_e1_key, l1_e1_value);

    let l2_e1_key: Word = rng.value();
    let l2_e1_value: Word = rng.value();
    let leaf_2_ix = LeafIndex::from(l2_e1_key);
    let mut l2_e2_key: Word = rng.value();
    l2_e2_key[3] = Felt::from_u64(leaf_2_ix.position());
    let l2_e2_value: Word = rng.value();
    changed_1.insert(l2_e1_key, l2_e1_value);
    changed_1.insert(l2_e2_key, l2_e2_value);

    history.add_version(root_1, id_1, nodes_1.clone(), changed_1.clone(), 3)?;
    assert_eq!(history.num_versions(), 1);

    // We then add another version that overlaps with the older version.
    let root_2: Word = rng.value();
    let id_2 = 5;

    let mut nodes_2 = NodeChanges::default();
    let n3_value: Word = rng.value();
    let n4_value: Word = rng.value();
    nodes_2.insert(NodeIndex::new(2, 1).unwrap(), n3_value);
    nodes_2.insert(NodeIndex::new(10, 256).unwrap(), n4_value);

    let mut changed_2 = ChangedKeys::default();

    let leaf_3_ix = leaf_2_ix;
    let mut l3_e1_key: Word = rng.value();
    l3_e1_key[3] = Felt::from_u64(leaf_3_ix.position());
    let l3_e1_value: Word = rng.value();
    changed_2.insert(l3_e1_key, l3_e1_value);
    history.add_version(root_2, id_2, nodes_2.clone(), changed_2.clone(), 7)?;
    assert_eq!(history.num_versions(), 2);

    // And another version for the sake of the test.
    let root_3: Word = rng.value();
    let id_3 = 6;

    let mut nodes_3 = NodeChanges::default();
    let n5_value: Word = rng.value();
    nodes_3.insert(NodeIndex::new(30, 1).unwrap(), n5_value);

    let mut changed_3 = ChangedKeys::default();

    let l4_e1_key: Word = rng.value();
    let l4_e1_value: Word = rng.value();
    changed_3.insert(l4_e1_key, l4_e1_value);

    let l1n_e1_key = l1_e1_key;
    let l1n_e1_value: Word = rng.value();
    changed_3.insert(l1n_e1_key, l1n_e1_value);

    history.add_version(root_3, id_3, nodes_3.clone(), changed_3.clone(), 15)?;
    assert_eq!(history.num_versions(), 3);

    // At this point, we can grab a view into the history. If we grab something older than the
    // history knows about we should get an error.
    assert!(history.get_view_at(2).is_err());

    // If we grab something valid, then we should get the right results. Let's grab the oldest
    // possible version to test the overlay logic.
    let view = history.get_view_at(id_1)?;
    assert_eq!(view.entry_count(), 3);

    // Getting a node in the targeted version should just return it.
    assert_eq!(view.node_value(&NodeIndex::new(2, 1).unwrap()), Some(&n1_value));
    assert_eq!(view.node_value(&NodeIndex::new(8, 128).unwrap()), Some(&n2_value));

    // Getting a node that is _not_ in the targeted delta directly should search through the
    // versions in between the targeted version at the current tree and return the oldest value
    // it can find for it.
    assert_eq!(view.node_value(&NodeIndex::new(10, 256).unwrap()), Some(&n4_value));
    assert_eq!(view.node_value(&NodeIndex::new(30, 1).unwrap()), Some(&n5_value));

    // Getting a node that doesn't exist in ANY versions should return none.
    assert!(view.node_value(&NodeIndex::new(45, 100).unwrap()).is_none());

    // Getting a leaf from the targeted version will compose with other (newer) deltas to yield the
    // correct changes. The first test here checks that a value updated in a newer delta is
    // nevertheless reverted to the correct value.
    assert_eq!(view.value(&l1_e1_key), Some(l1_e1_value));

    // This test checks that the delta for a single value correctly combines non-overlapping key
    // reversions.
    assert_eq!(view.value(&l2_e1_key), Some(l2_e1_value));
    assert_eq!(view.value(&l2_e2_key), Some(l2_e2_value));

    // But getting a value that is not in the target delta directly should result in the same
    // traversal.
    assert_eq!(view.value(&l4_e1_key), Some(l4_e1_value));

    // And getting a value that does not exist in any of the versions should return an empty delta.
    assert!(view.value(&rng.value()).is_none());

    // Finally, getting a full value from a compact leaf should yield the value directly from
    // the target version if the target version overlays it AND contains it.
    assert_eq!(view.value(&l1_e1_key), Some(l1_e1_value));
    assert_eq!(view.value(&l2_e1_key), Some(l2_e1_value));
    assert_eq!(view.value(&l2_e2_key), Some(l2_e2_value));

    // If the leaf is not overlaid, then the lookup should go up the chain just as in the other
    // cases.
    assert_eq!(view.value(&l4_e1_key), Some(l4_e1_value));

    // But if nothing is found, it should just return None;
    let ne_key: Word = rng.value();
    assert!(view.value(&ne_key).is_none());

    // We can also get views for versions that are not directly contained, such as a version newer
    // than the newest. This should just use the newest version to service the query.
    let view = history.get_view_at(7)?;
    assert_eq!(view.node_value(&NodeIndex::new_unchecked(30, 1)), Some(&n5_value));
    assert!(view.node_value(&NodeIndex::new_unchecked(30, 2)).is_none());
    assert_eq!(view.entry_count(), 15);

    Ok(())
}

// SMT INTEGRATION TESTS
// ================================================================================================

/// Tests History integration using real SMT mutations.
///
/// This test creates an actual SMT, computes mutations via the SMT API,
/// and verifies that History correctly tracks the resulting node and leaf changes.
#[test]
fn history_from_smt_non_overlapping() -> Result<()> {
    let mut rng = ContinuousRng::new([0x1a; 32]);

    // Create an empty SMT
    let mut smt = Smt::new();
    let initial_root = smt.root();

    // Generate test key-value pairs
    let key_1: Word = rng.value();
    let value_1: Word = rng.value();
    let key_2: Word = rng.value();
    let value_2: Word = rng.value();

    // Create history to track versions
    let mut history = History::empty(3);

    // Version 0: Insert first key-value pair using real SMT mutation while getting the reversion
    // set for the history.
    let mutations_v0 = smt.compute_mutations(vec![(key_1, value_1)]).unwrap();
    let reversion_set = smt.apply_mutations_with_reversion(mutations_v0).unwrap();
    let root_v0 = smt.root();
    // Before this mutation the tree was empty, so the entry count for version 0 is 0.
    history.add_version_from_mutation_set(0, reversion_set, 0)?;
    assert_eq!(history.num_versions(), 1);

    // Version 1: Insert second key-value pair
    let mutations_v1 = smt.compute_mutations(vec![(key_2, value_2)]).unwrap();
    let reversion_set = smt.apply_mutations_with_reversion(mutations_v1).unwrap();
    let root_v1 = smt.root();
    // Before this mutation the tree had 1 entry (key_1), so the entry count for version 1 is 1.
    history.add_version_from_mutation_set(1, reversion_set, 1)?;

    // Verify the roots for older states are tracked correctly in the history.
    assert!(history.is_known_root(initial_root));
    assert!(history.is_known_root(root_v0));

    // And that the latest root of the tree is not.
    assert!(!history.is_known_root(root_v1));

    // We can start by checking that version 0 performs the correct reversion operations,
    // encompassing _both_ changes made to obtain the current version.
    let view_v0 = history.get_view_at(0)?;
    assert_eq!(view_v0.value(&key_1), Some(EMPTY_WORD));
    assert_eq!(view_v0.value(&key_2), Some(EMPTY_WORD));
    assert_eq!(view_v0.entry_count(), 0);

    // When we query version 1 it should only make revert one change on top of the current tree.
    let view_v1 = history.get_view_at(1)?;
    assert_eq!(view_v1.value(&key_2), Some(EMPTY_WORD));
    assert_eq!(view_v1.entry_count(), 1);

    // Verify querying a non-existent key returns None
    let nonexistent_key: Word = rng.value();
    assert!(view_v1.value(&nonexistent_key).is_none());

    Ok(())
}

/// Tests History with SMT value updates (replacing existing values).
#[test]
fn history_from_smt_overlapping() -> Result<()> {
    let mut rng = ContinuousRng::new([0x1b; 32]);
    let mut smt = Smt::new();

    let key: Word = rng.value();
    let value_v0: Word = rng.value();
    let value_v1: Word = rng.value();

    let mut history = History::empty(2);

    // Version 0: Insert initial value
    let mutations_v0 = smt.compute_mutations(vec![(key, value_v0)]).unwrap();
    let reversion_set = smt.apply_mutations_with_reversion(mutations_v0).unwrap();
    // Before this mutation the tree was empty, so the entry count for version 0 is 0.
    history.add_version_from_mutation_set(0, reversion_set, 0)?;

    // Version 1: Update to new value
    let mutations_v1 = smt.compute_mutations(vec![(key, value_v1)]).unwrap();
    let reversion_set = smt.apply_mutations_with_reversion(mutations_v1).unwrap();
    // Before this mutation the tree had 1 entry (key), so the entry count for version 1 is 1.
    history.add_version_from_mutation_set(1, reversion_set, 1)?;

    // In version 0 we should have the correct (empty) value when reverted.
    let view_v0 = history.get_view_at(0)?;
    assert_eq!(view_v0.value(&key), Some(EMPTY_WORD));
    assert_eq!(view_v0.entry_count(), 0);

    // In version 1 we should have the value set in the transition to version 0.
    let view_v1 = history.get_view_at(1)?;
    assert_eq!(view_v1.value(&key), Some(value_v0));
    assert_eq!(view_v1.entry_count(), 1);

    Ok(())
}

#[test]
fn entry_count_single_version() -> Result<()> {
    let mut rng = ContinuousRng::new([0x1c; 32]);
    let mut history = History::empty(3);

    let root: Word = rng.value();
    history.add_version(root, 0, NodeChanges::default(), ChangedKeys::default(), 42)?;

    let view = history.get_view_at(0)?;
    assert_eq!(view.entry_count(), 42);

    Ok(())
}

#[test]
fn entry_count_multiple_versions() -> Result<()> {
    let mut rng = ContinuousRng::new([0x1d; 32]);
    let mut history = History::empty(5);

    // Add versions with different entry counts.
    history.add_version(rng.value(), 0, NodeChanges::default(), ChangedKeys::default(), 0)?;
    history.add_version(rng.value(), 1, NodeChanges::default(), ChangedKeys::default(), 5)?;
    history.add_version(rng.value(), 2, NodeChanges::default(), ChangedKeys::default(), 3)?;
    history.add_version(rng.value(), 3, NodeChanges::default(), ChangedKeys::default(), 10)?;

    assert_eq!(history.get_view_at(0)?.entry_count(), 0);
    assert_eq!(history.get_view_at(1)?.entry_count(), 5);
    assert_eq!(history.get_view_at(2)?.entry_count(), 3);
    assert_eq!(history.get_view_at(3)?.entry_count(), 10);

    Ok(())
}

#[test]
fn entry_count_after_eviction() -> Result<()> {
    let mut rng = ContinuousRng::new([0x1e; 32]);
    let mut history = History::empty(2);

    // Add 3 versions to a history that can hold only 2, causing eviction of the oldest.
    history.add_version(rng.value(), 0, NodeChanges::default(), ChangedKeys::default(), 1)?;
    history.add_version(rng.value(), 1, NodeChanges::default(), ChangedKeys::default(), 5)?;
    history.add_version(rng.value(), 2, NodeChanges::default(), ChangedKeys::default(), 10)?;

    // Version 0 should have been evicted.
    assert!(history.get_view_at(0).is_err());

    // The remaining versions should still have the correct entry counts.
    assert_eq!(history.get_view_at(1)?.entry_count(), 5);
    assert_eq!(history.get_view_at(2)?.entry_count(), 10);

    Ok(())
}

#[test]
fn entry_count_after_truncation() -> Result<()> {
    let mut rng = ContinuousRng::new([0x1f; 32]);
    let mut history = History::empty(4);

    history.add_version(rng.value(), 5, NodeChanges::default(), ChangedKeys::default(), 2)?;
    history.add_version(rng.value(), 10, NodeChanges::default(), ChangedKeys::default(), 7)?;
    history.add_version(rng.value(), 15, NodeChanges::default(), ChangedKeys::default(), 12)?;

    // Truncate to version 10, removing version 5.
    history.truncate(10);
    assert_eq!(history.num_versions(), 2);

    // The surviving versions should retain their entry counts.
    assert_eq!(history.get_view_at(10)?.entry_count(), 7);
    assert_eq!(history.get_view_at(15)?.entry_count(), 12);

    Ok(())
}

#[test]
fn entry_count_reaches_zero_through_removals() -> Result<()> {
    let mut rng = ContinuousRng::new([0x20; 32]);
    let mut history = History::empty(4);

    // Simulate a tree that gains entries and then has them all removed.
    history.add_version(rng.value(), 0, NodeChanges::default(), ChangedKeys::default(), 0)?;
    history.add_version(rng.value(), 1, NodeChanges::default(), ChangedKeys::default(), 3)?;
    history.add_version(rng.value(), 2, NodeChanges::default(), ChangedKeys::default(), 1)?;
    history.add_version(rng.value(), 3, NodeChanges::default(), ChangedKeys::default(), 0)?;

    assert_eq!(history.get_view_at(0)?.entry_count(), 0);
    assert_eq!(history.get_view_at(1)?.entry_count(), 3);
    assert_eq!(history.get_view_at(2)?.entry_count(), 1);
    assert_eq!(history.get_view_at(3)?.entry_count(), 0);

    Ok(())
}
