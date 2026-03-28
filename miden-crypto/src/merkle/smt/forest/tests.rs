use assert_matches::assert_matches;
use itertools::Itertools;

use super::{EmptySubtreeRoots, MerkleError, SmtForest, Word};
use crate::{
    EMPTY_WORD, Felt, ONE, ZERO,
    merkle::{
        int_to_node,
        smt::{SMT_DEPTH, SmtProofError},
    },
};

// TESTS
// ================================================================================================

#[test]
fn test_insert_root_not_in_store() -> Result<(), MerkleError> {
    let mut forest = SmtForest::new();
    let word = Word::new([ONE; Word::NUM_ELEMENTS]);
    assert_matches!(
        forest.insert(word, word, word),
        Err(MerkleError::RootNotInStore(_)),
        "The forest is empty, so only empty root is valid"
    );

    Ok(())
}

#[test]
fn test_insert_root_empty() -> Result<(), MerkleError> {
    let mut forest = SmtForest::new();
    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let key = Word::new([ZERO; Word::NUM_ELEMENTS]);
    let value = Word::new([ONE; Word::NUM_ELEMENTS]);
    assert_eq!(
        forest.insert(empty_tree_root, key, value)?,
        Word::new([
            Felt::new(14568730562832515847),
            Felt::new(18252916646450022498),
            Felt::new(41434158889285279),
            Felt::new(9206344219167471937),
        ]),
    );
    Ok(())
}

#[test]
fn test_insert_multiple_values() -> Result<(), MerkleError> {
    let mut forest = SmtForest::new();

    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let key = Word::new([ZERO; Word::NUM_ELEMENTS]);
    let value = Word::new([ONE; Word::NUM_ELEMENTS]);
    let new_root = forest.insert(empty_tree_root, key, value)?;
    assert_eq!(
        new_root,
        Word::new([
            Felt::new(14568730562832515847),
            Felt::new(18252916646450022498),
            Felt::new(41434158889285279),
            Felt::new(9206344219167471937),
        ]),
    );

    let new_root = forest.insert(new_root, key, value)?;
    assert_eq!(
        new_root,
        Word::new([
            Felt::new(14568730562832515847),
            Felt::new(18252916646450022498),
            Felt::new(41434158889285279),
            Felt::new(9206344219167471937),
        ]),
    );

    // Inserting the same key-value pair again should return the same root
    let root_duplicate = forest.insert(new_root, key, value)?;
    assert_eq!(new_root, root_duplicate);

    let key2 = Word::new([ZERO, ONE, ZERO, ONE]);
    let new_root = forest.insert(new_root, key2, value)?;
    assert_eq!(
        new_root,
        Word::new([
            Felt::new(8331046026464464586),
            Felt::new(2235589849047307808),
            Felt::new(16989070170732558432),
            Felt::new(14827437307365892589),
        ])
    );

    Ok(())
}

#[test]
fn test_batch_insert() -> Result<(), MerkleError> {
    let forest = SmtForest::new();

    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

    let values = vec![
        (Word::new([ZERO; Word::NUM_ELEMENTS]), Word::new([ONE; Word::NUM_ELEMENTS])),
        (Word::new([ZERO, ONE, ZERO, ONE]), Word::new([ONE; Word::NUM_ELEMENTS])),
        (Word::new([ZERO, ONE, ZERO, ZERO]), Word::new([ONE; Word::NUM_ELEMENTS])),
    ];

    values.into_iter().permutations(3).for_each(|values| {
        let mut forest = forest.clone();
        let new_root = forest.batch_insert(empty_tree_root, values.clone()).unwrap();

        assert_eq!(
            new_root,
            Word::new([
                Felt::new(10190519849202762248),
                Felt::new(435931819697066051),
                Felt::new(16151289788138594836),
                Felt::new(9391498722098326251),
            ])
        );

        for (key, value) in values {
            let proof = forest.open(new_root, key).unwrap();
            proof.verify_presence(&key, &value, &new_root).unwrap();
        }
    });

    Ok(())
}

#[test]
fn test_open_root_not_in_store() -> Result<(), MerkleError> {
    let forest = SmtForest::new();
    let word = Word::new([ONE; Word::NUM_ELEMENTS]);
    assert_matches!(
        forest.open(word, word),
        Err(MerkleError::RootNotInStore(_)),
        "The forest is empty, so only empty root is valid"
    );

    Ok(())
}

#[test]
fn test_open_root_in_store() -> Result<(), MerkleError> {
    let mut forest = SmtForest::new();

    let root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let root = forest.insert(
        root,
        Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0)]),
        int_to_node(1),
    )?;
    let root = forest.insert(
        root,
        Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(1)]),
        int_to_node(2),
    )?;
    let root = forest.insert(
        root,
        Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(2)]),
        int_to_node(3),
    )?;

    let proof =
        forest.open(root, Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(2)]))?;
    proof
        .verify_presence(
            &Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(2)]),
            &int_to_node(3),
            &root,
        )
        .expect("proof should verify membership");

    Ok(())
}

#[test]
fn test_empty_word_removes_key() -> Result<(), MerkleError> {
    let mut forest = SmtForest::new();
    let empty_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let key = Word::from([1_u32; Word::NUM_ELEMENTS]);
    let value = Word::from([2_u32; Word::NUM_ELEMENTS]);

    let root_with_value = forest.insert(empty_root, key, value)?;
    let root_after_remove = forest.insert(root_with_value, key, EMPTY_WORD)?;

    assert_eq!(root_after_remove, empty_root);
    assert!(!forest.leaves.contains_key(&key));

    let proof = forest.open(root_after_remove, key)?;
    proof.verify_unset(&key, &root_after_remove).unwrap();

    Ok(())
}

#[test]
fn test_multiple_versions_of_same_key() -> Result<(), MerkleError> {
    // Verify that when we insert multiple values for the same key,
    // we can still open valid proofs for all historical roots.
    let mut forest = SmtForest::new();

    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let key = Word::new([ZERO; Word::NUM_ELEMENTS]);

    // Insert the same key with different values, creating multiple roots
    let value1 = Word::new([ONE; Word::NUM_ELEMENTS]);
    let root1 = forest.insert(empty_tree_root, key, value1)?;

    let value2 = Word::new([Felt::new(2); Word::NUM_ELEMENTS]);
    let root2 = forest.insert(root1, key, value2)?;

    let value3 = Word::new([Felt::new(3); Word::NUM_ELEMENTS]);
    let root3 = forest.insert(root2, key, value3)?;

    // All three roots should be different
    assert_ne!(root1, root2);
    assert_ne!(root2, root3);
    assert_ne!(root1, root3);

    // Open proofs for each historical root and verify them
    let proof1 = forest.open(root1, key)?;
    proof1
        .verify_presence(&key, &value1, &root1)
        .expect("Proof for root1 should verify with value1");

    let proof2 = forest.open(root2, key)?;
    proof2
        .verify_presence(&key, &value2, &root2)
        .expect("Proof for root2 should verify with value2");

    let proof3 = forest.open(root3, key)?;
    proof3
        .verify_presence(&key, &value3, &root3)
        .expect("Proof for root3 should verify with value3");

    // Wrong values cannot be verified - should return ValueMismatch
    assert_matches!(
        proof1.verify_presence(&key, &value2, &root1),
        Err(SmtProofError::ValueMismatch { .. }),
        "Proof for root1 should not verify with value2"
    );

    assert_matches!(
        proof3.verify_presence(&key, &value1, &root3),
        Err(SmtProofError::ValueMismatch { .. }),
        "Proof for root3 should not verify with value1"
    );

    Ok(())
}

#[test]
fn test_pop_roots() -> Result<(), MerkleError> {
    let mut forest = SmtForest::new();

    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let key = Word::new([ZERO; Word::NUM_ELEMENTS]);
    let value = Word::new([ONE; Word::NUM_ELEMENTS]);
    let root = forest.insert(empty_tree_root, key, value)?;

    assert_eq!(forest.roots.len(), 1);
    assert_eq!(forest.leaves.len(), 1);

    forest.pop_smts(vec![root]);

    assert_eq!(forest.roots.len(), 0);
    assert_eq!(forest.leaves.len(), 0);

    Ok(())
}

#[test]
fn test_pop_and_reinsert_same_tree() -> Result<(), MerkleError> {
    let mut forest = SmtForest::new();

    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let key = Word::new([ZERO; Word::NUM_ELEMENTS]);
    let value = Word::new([ONE; Word::NUM_ELEMENTS]);

    // Insert a key, then pop the tree
    let root1 = forest.insert(empty_tree_root, key, value)?;
    forest.pop_smts(vec![root1]);

    // Re-insert the same key-value pair (produces the same tree hashes)
    let root2 = forest.insert(empty_tree_root, key, value)?;
    assert_eq!(root1, root2, "same key-value must produce the same root");

    // Verify the proof is valid
    let proof = forest.open(root2, key)?;
    proof.verify_presence(&key, &value, &root2).unwrap();

    // Pop again — without the fix this would panic due to rc underflow
    forest.pop_smts(vec![root2]);

    assert_eq!(forest.roots.len(), 0);
    assert_eq!(forest.leaves.len(), 0);

    Ok(())
}

#[test]
fn test_removing_empty_smt_from_forest() {
    let mut forest = SmtForest::new();
    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let non_empty_root = Word::new([ONE; Word::NUM_ELEMENTS]);

    // Popping zero SMTs from forest should be a no-op (no panic or error)
    forest.pop_smts(vec![]);

    // Popping a non-existent root should be a no-op (no panic or error)
    forest.pop_smts(vec![non_empty_root]);

    // Popping the empty root should be a no-op (no panic or error)
    forest.pop_smts(vec![empty_tree_root]);
}

#[test]
fn test_empty_root_never_removed() -> Result<(), MerkleError> {
    // Verify that the empty tree root is never registered in self.roots and that
    // popping it does not corrupt the store.
    let mut forest = SmtForest::new();
    let empty_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let key = Word::new([ZERO; Word::NUM_ELEMENTS]);
    let value = Word::new([ONE; Word::NUM_ELEMENTS]);

    // batch_insert with no entries returns the empty root — it must not be registered
    let root = forest.batch_insert(empty_root, vec![])?;
    assert_eq!(root, empty_root);

    // Popping the empty root would corrupt the store if it were in self.roots.
    forest.pop_smts(vec![empty_root]);

    // The forest should still be fully functional
    let new_root = forest.insert(empty_root, key, value)?;
    let proof = forest.open(new_root, key)?;
    assert!(proof.verify_presence(&key, &value, &new_root).is_ok());

    Ok(())
}
