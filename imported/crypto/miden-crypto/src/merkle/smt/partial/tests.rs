use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use assert_matches::assert_matches;
use itertools::Itertools;
use proptest::prelude::*;
use rand::{Rng, RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;

use super::{PartialSmt, SMT_DEPTH, serialization::property_tests::arbitrary_valid_word};
use crate::{
    EMPTY_WORD, Felt, ONE, Word, ZERO,
    merkle::{
        EmptySubtreeRoots, MerkleError,
        smt::{Smt, SmtLeaf},
    },
    rand::test_utils::ContinuousRng,
    utils::{Deserializable, Serializable},
};
// Note: Word's Arbitrary implementation is in word/mod.rs, gated by cfg(any(test, feature =
// "testing"))

/// Helper to generate a random Word from a seeded RNG.
/// This is used for deterministic tests that need reproducible sequences of random values.
fn random_word<R: Rng>(rng: &mut R) -> Word {
    Word::new([
        Felt::new_unchecked(rng.random::<u64>() % Felt::ORDER),
        Felt::new_unchecked(rng.random::<u64>() % Felt::ORDER),
        Felt::new_unchecked(rng.random::<u64>() % Felt::ORDER),
        Felt::new_unchecked(rng.random::<u64>() % Felt::ORDER),
    ])
}

/// Tests that a partial SMT constructed from a root is well-behaved, and returns expected
/// values.
#[test]
fn partial_smt_new_with_no_entries() {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let key0 = random_word(&mut rng);
    let value0 = random_word(&mut rng);
    let full = Smt::with_entries([(key0, value0)]).unwrap();

    let partial_smt = PartialSmt::new(full.root());

    assert!(!partial_smt.tracks_leaves());
    assert_eq!(partial_smt.num_entries(), 0);
    assert_eq!(partial_smt.num_leaves(), 0);
    assert_eq!(partial_smt.entries().count(), 0);
    assert_eq!(partial_smt.leaves().count(), 0);
    assert_eq!(partial_smt.root(), full.root());
}

/// Tests that a PartialSmt with a non-empty root but no proofs cannot track or update keys.
#[test]
fn partial_smt_non_empty_root_no_proofs() {
    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
    let key = random_word(&mut rng);
    let value = random_word(&mut rng);
    let full = Smt::with_entries([(key, value)]).unwrap();

    // Create partial with non-empty root but don't add any proofs
    let mut partial = PartialSmt::new(full.root());

    // Can't get value for key with value - not trackable without proofs
    assert!(partial.get_value(&key).is_err());

    // Can't insert for key with value - not trackable
    assert!(partial.insert(key, value).is_err());

    // Can't get value for empty key either - still not trackable
    let empty_key = random_word(&mut rng);
    assert!(partial.get_value(&empty_key).is_err());

    // Can't insert at empty key - not trackable
    assert!(partial.insert(empty_key, value).is_err());
}

/// Tests that a basic PartialSmt can be built from a full one and that inserting or removing
/// values whose merkle path were added to the partial SMT results in the same root as the
/// equivalent update in the full tree.
#[test]
fn partial_smt_insert_and_remove() {
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
    let key0 = random_word(&mut rng);
    let key1 = random_word(&mut rng);
    let key2 = random_word(&mut rng);
    // A key for which we won't add a value so it will be empty.
    let key_empty = random_word(&mut rng);

    let value0 = random_word(&mut rng);
    let value1 = random_word(&mut rng);
    let value2 = random_word(&mut rng);

    let mut kv_pairs = vec![(key0, value0), (key1, value1), (key2, value2)];

    // Add more random leaves.
    kv_pairs.reserve(1000);
    for _ in 0..1000 {
        let key = random_word(&mut rng);
        let value = random_word(&mut rng);
        kv_pairs.push((key, value));
    }

    let mut full = Smt::with_entries(kv_pairs).unwrap();

    // Constructing a partial SMT from proofs succeeds.
    // ----------------------------------------------------------------------------------------

    let proof0 = full.open(&key0);
    let proof2 = full.open(&key2);
    let proof_empty = full.open(&key_empty);

    assert!(proof_empty.leaf().is_empty());

    let mut partial = PartialSmt::from_proofs([proof0, proof2, proof_empty]).unwrap();

    assert_eq!(full.root(), partial.root());
    assert_eq!(partial.get_value(&key0).unwrap(), value0);
    let error = partial.get_value(&key1).unwrap_err();
    assert_matches!(error, MerkleError::UntrackedKey(_));
    assert_eq!(partial.get_value(&key2).unwrap(), value2);

    // Insert new values for added keys with empty and non-empty values.
    // ----------------------------------------------------------------------------------------

    let new_value0 = random_word(&mut rng);
    let new_value2 = random_word(&mut rng);
    // A non-empty value for the key that was previously empty.
    let new_value_empty_key = random_word(&mut rng);

    full.insert(key0, new_value0).unwrap();
    full.insert(key2, new_value2).unwrap();
    full.insert(key_empty, new_value_empty_key).unwrap();

    partial.insert(key0, new_value0).unwrap();
    partial.insert(key2, new_value2).unwrap();
    // This updates a key whose value was previously empty.
    partial.insert(key_empty, new_value_empty_key).unwrap();

    assert_eq!(full.root(), partial.root());
    assert_eq!(partial.get_value(&key0).unwrap(), new_value0);
    assert_eq!(partial.get_value(&key2).unwrap(), new_value2);
    assert_eq!(partial.get_value(&key_empty).unwrap(), new_value_empty_key);

    // Remove an added key.
    // ----------------------------------------------------------------------------------------

    full.insert(key0, EMPTY_WORD).unwrap();
    partial.insert(key0, EMPTY_WORD).unwrap();

    assert_eq!(full.root(), partial.root());
    assert_eq!(partial.get_value(&key0).unwrap(), EMPTY_WORD);

    // Check if returned openings are the same in partial and full SMT.
    // ----------------------------------------------------------------------------------------

    // This is a key whose value is empty since it was removed.
    assert_eq!(full.open(&key0), partial.open(&key0).unwrap());
    // This is a key whose value is non-empty.
    assert_eq!(full.open(&key2), partial.open(&key2).unwrap());

    // Attempting to update a key whose merkle path was not added is an error.
    // ----------------------------------------------------------------------------------------

    let error = partial.clone().insert(key1, random_word(&mut rng)).unwrap_err();
    assert_matches!(error, MerkleError::UntrackedKey(_));

    let error = partial.insert(key1, EMPTY_WORD).unwrap_err();
    assert_matches!(error, MerkleError::UntrackedKey(_));
}

/// Test that we can add an SmtLeaf::Multiple variant to a partial SMT.
#[test]
fn partial_smt_multiple_leaf_success() {
    let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
    // key0 and key1 have the same felt at index 3 so they will be placed in the same leaf.
    let key0 = Word::from([ZERO, ZERO, ZERO, ONE]);
    let key1 = Word::from([ONE, ONE, ONE, ONE]);
    let key2 = random_word(&mut rng);

    let value0 = random_word(&mut rng);
    let value1 = random_word(&mut rng);
    let value2 = random_word(&mut rng);

    let full = Smt::with_entries([(key0, value0), (key1, value1), (key2, value2)]).unwrap();

    // Make sure our assumption about the leaf being a multiple is correct.
    let SmtLeaf::Multiple(_) = full.get_leaf(&key0) else {
        panic!("expected full tree to produce multiple leaf")
    };

    let proof0 = full.open(&key0);
    let proof2 = full.open(&key2);

    let partial = PartialSmt::from_proofs([proof0, proof2]).unwrap();

    assert_eq!(partial.root(), full.root());

    assert_eq!(partial.get_leaf(&key0).unwrap(), full.get_leaf(&key0));
    // key1 is present in the partial tree because it is part of the proof of key0.
    assert_eq!(partial.get_leaf(&key1).unwrap(), full.get_leaf(&key1));
    assert_eq!(partial.get_leaf(&key2).unwrap(), full.get_leaf(&key2));
}

/// Tests that adding proofs to a partial SMT whose roots are not the same will result in an
/// error.
///
/// This test uses only empty values in the partial SMT.
#[test]
fn partial_smt_root_mismatch_on_empty_values() {
    let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
    let key0 = random_word(&mut rng);
    let key1 = random_word(&mut rng);
    let key2 = random_word(&mut rng);

    let value0 = EMPTY_WORD;
    let value1 = random_word(&mut rng);
    let value2 = EMPTY_WORD;

    let kv_pairs = vec![(key0, value0)];

    let mut full = Smt::with_entries(kv_pairs).unwrap();

    // This proof will become stale after the tree is modified.
    let stale_proof = full.open(&key2);

    // Insert a non-empty value so the root actually changes.
    full.insert(key1, value1).unwrap();
    full.insert(key2, value2).unwrap();

    // Construct a partial SMT against the latest root.
    let mut partial = PartialSmt::new(full.root());

    // Adding the stale proof should fail as its root is different.
    let err = partial.add_proof(stale_proof).unwrap_err();
    assert_matches!(err, MerkleError::ConflictingRoots { .. });
}

/// Tests that adding proofs to a partial SMT whose roots are not the same will result in an
/// error.
///
/// This test uses only non-empty values in the partial SMT.
#[test]
fn partial_smt_root_mismatch_on_non_empty_values() {
    let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
    let key0 = random_word(&mut rng);
    let key1 = random_word(&mut rng);
    let key2 = random_word(&mut rng);

    let value0 = random_word(&mut rng);
    let value1 = random_word(&mut rng);
    let value2 = random_word(&mut rng);

    let kv_pairs = vec![(key0, value0), (key1, value1)];

    let mut full = Smt::with_entries(kv_pairs).unwrap();

    // This proof will become stale after the tree is modified.
    let stale_proof = full.open(&key0);

    // Insert a value so the root changes.
    full.insert(key2, value2).unwrap();

    // Construct a partial SMT against the latest root.
    let mut partial = PartialSmt::new(full.root());

    // Adding the stale proof should fail as its root is different.
    let err = partial.add_proof(stale_proof).unwrap_err();
    assert_matches!(err, MerkleError::ConflictingRoots { .. });
}

/// Tests that from_proofs fails when the proofs roots do not match.
#[test]
fn partial_smt_from_proofs_fails_on_root_mismatch() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let key0 = random_word(&mut rng);
    let key1 = random_word(&mut rng);

    let value0 = random_word(&mut rng);
    let value1 = random_word(&mut rng);

    let mut full = Smt::with_entries([(key0, value0)]).unwrap();

    // This proof will become stale after the tree is modified.
    let stale_proof = full.open(&key0);

    // Insert a value so the root changes.
    full.insert(key1, value1).unwrap();

    // Construct a partial SMT against the latest root.
    let err = PartialSmt::from_proofs([full.open(&key1), stale_proof]).unwrap_err();
    assert_matches!(err, MerkleError::ConflictingRoots { .. });
}

/// Tests that a basic PartialSmt's iterator APIs return the expected values.
#[test]
fn partial_smt_iterator_apis() {
    let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
    let key0 = random_word(&mut rng);
    let key1 = random_word(&mut rng);
    let key2 = random_word(&mut rng);
    // A key for which we won't add a value so it will be empty.
    let key_empty = random_word(&mut rng);

    let value0 = random_word(&mut rng);
    let value1 = random_word(&mut rng);
    let value2 = random_word(&mut rng);

    let mut kv_pairs = vec![(key0, value0), (key1, value1), (key2, value2)];

    // Add more random leaves.
    kv_pairs.reserve(1000);
    for _ in 0..1000 {
        let key = random_word(&mut rng);
        let value = random_word(&mut rng);
        kv_pairs.push((key, value));
    }

    let full = Smt::with_entries(kv_pairs).unwrap();

    // Construct a partial SMT from proofs.
    // ----------------------------------------------------------------------------------------

    let proof0 = full.open(&key0);
    let proof2 = full.open(&key2);
    let proof_empty = full.open(&key_empty);

    assert!(proof_empty.leaf().is_empty());

    let proofs = [proof0, proof2, proof_empty];
    let partial = PartialSmt::from_proofs(proofs.clone()).unwrap();

    assert!(partial.tracks_leaves());
    assert_eq!(full.root(), partial.root());
    // There should be 2 non-empty entries.
    assert_eq!(partial.num_entries(), 2);
    // There should be 2 leaves (empty leaves are not stored).
    assert_eq!(partial.num_leaves(), 2);

    // The leaves API should only return tracked but non-empty leaves.
    // ----------------------------------------------------------------------------------------

    // Construct the sorted vector of leaves that should be yielded by the partial SMT.
    let expected_leaves: BTreeMap<_, _> =
        [SmtLeaf::new_single(key0, value0), SmtLeaf::new_single(key2, value2)]
            .into_iter()
            .map(|leaf| (leaf.index(), leaf))
            .collect();

    let actual_leaves = partial
        .leaves()
        .map(|(idx, leaf)| (idx, leaf.clone()))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(actual_leaves.len(), expected_leaves.len());
    assert_eq!(actual_leaves, expected_leaves);

    // The num_leaves API should return the count of explicitly stored leaves.
    // ----------------------------------------------------------------------------------------

    // We added 3 proofs but empty leaves are not stored, so num_leaves should be 2.
    assert_eq!(partial.num_leaves(), 2);

    // The entries of the merkle paths from the proofs should exist as children of inner nodes
    // in the partial SMT.
    // ----------------------------------------------------------------------------------------

    let partial_inner_nodes: BTreeSet<_> =
        partial.inner_nodes().flat_map(|node| [node.left, node.right]).collect();
    let empty_subtree_roots: BTreeSet<_> = (0..SMT_DEPTH)
        .map(|depth| *EmptySubtreeRoots::entry(SMT_DEPTH, depth))
        .collect();

    for merkle_path in proofs.into_iter().map(|proof| proof.into_parts().0) {
        for (idx, digest) in merkle_path.into_iter().enumerate() {
            assert!(
                partial_inner_nodes.contains(&digest) || empty_subtree_roots.contains(&digest),
                "failed at idx {idx}"
            );
        }
    }
}

/// Test that the default partial SMT's tracks_leaves method returns `false`.
#[test]
fn partial_smt_tracks_leaves() {
    assert!(!PartialSmt::default().tracks_leaves());
}

/// `PartialSmt` serde round-trip when constructed from just a root.
#[test]
fn partial_smt_with_empty_leaves_serialization_roundtrip() {
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    let partial_smt = PartialSmt::new(random_word(&mut rng));
    assert_eq!(partial_smt, PartialSmt::read_from_bytes(&partial_smt.to_bytes()).unwrap());
}

/// `PartialSmt` serde round-trip. Also tests conversion from SMT.
#[test]
fn partial_smt_serialization_roundtrip() {
    let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
    let key = random_word(&mut rng);
    let val = random_word(&mut rng);

    let key_1 = random_word(&mut rng);
    let val_1 = random_word(&mut rng);

    let key_2 = random_word(&mut rng);
    let val_2 = random_word(&mut rng);

    let smt: Smt = Smt::with_entries([(key, val), (key_1, val_1), (key_2, val_2)]).unwrap();

    let partial_smt = PartialSmt::from_proofs([smt.open(&key)]).unwrap();

    assert_eq!(partial_smt.root(), smt.root());
    assert_matches!(partial_smt.open(&key_1), Err(MerkleError::UntrackedKey(_)));
    assert_matches!(partial_smt.open(&key), Ok(_));

    let bytes = partial_smt.to_bytes();
    let decoded = PartialSmt::read_from_bytes(&bytes).unwrap();

    assert_eq!(partial_smt.num_entries, decoded.num_entries);
    assert_eq!(partial_smt.root(), decoded.root());

    assert_eq!(partial_smt, decoded);
}

/// Tests that add_path correctly updates num_entries for increasing entry counts.
///
/// Note that decreasing counts are not possible with the current API.
#[test]
fn partial_smt_add_proof_num_entries() {
    let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
    // key0 and key1 have the same felt at index 3 so they will be placed in the same leaf.
    let key0 = Word::from([ZERO, ZERO, ZERO, ONE]);
    let key1 = Word::from([ONE, ONE, ONE, ONE]);
    let key2 = Word::from([ONE, ONE, ONE, Felt::new_unchecked(5)]);
    let value0 = random_word(&mut rng);
    let value1 = random_word(&mut rng);
    let value2 = random_word(&mut rng);

    let full = Smt::with_entries([(key0, value0), (key1, value1), (key2, value2)]).unwrap();
    let mut partial = PartialSmt::new(full.root());

    // Add the multi-entry leaf
    partial.add_proof(full.open(&key0)).unwrap();
    assert_eq!(partial.num_entries(), 2);

    // Add the single-entry leaf
    partial.add_proof(full.open(&key2)).unwrap();
    assert_eq!(partial.num_entries(), 3);

    // Setting a value to the empty word removes decreases the number of entries.
    partial.insert(key0, Word::empty()).unwrap();
    assert_eq!(partial.num_entries(), 2);
}

/// Tests implicit tracking of empty subtrees based on the visualization from PR #375.
///
/// ```text
///              g (root)
///            /      \
///          e          f
///         / \        / \
///        a   b      c   d
///       /\ /\      /\  /\
///      0 1 2 3    4 5 6 7
/// ```
///
/// State:
/// - Subtree f is entirely empty.
/// - Key 1 has a value and a proof in the partial SMT.
/// - Key 3 has a value but is missing from the partial SMT (making node b non-empty).
/// - Keys 0, 2, 4, 5, 6, 7 are empty.
///
/// Expected:
/// - Key 1: CAN update (explicitly tracked via proof)
/// - Key 0: CAN update (under same parent 'a' as key 1, provably empty)
/// - Keys 4, 5, 6, 7: CAN update (in empty subtree f, provably empty)
/// - Keys 2, 3: CANNOT update (under non-empty node b, only have its hash)
#[test]
fn partial_smt_tracking_visualization() {
    // Situation in the diagram mapped to depth-64 SMT.
    const LEAF_0: u64 = 0;
    const LEAF_1: u64 = 1 << 61;
    const LEAF_2: u64 = 1 << 62;
    const LEAF_3: u64 = (1 << 62) | (1 << 61);
    const LEAF_4: u64 = 1 << 63;
    const LEAF_5: u64 = (1 << 63) | (1 << 61);
    const LEAF_6: u64 = (1 << 63) | (1 << 62);
    const LEAF_7: u64 = (1 << 63) | (1 << 62) | (1 << 61);

    let key_0 = Word::from([ZERO, ZERO, ZERO, Felt::new_unchecked(LEAF_0)]);
    let key_1 = Word::from([ZERO, ZERO, ZERO, Felt::new_unchecked(LEAF_1)]);
    let key_2 = Word::from([ZERO, ZERO, ZERO, Felt::new_unchecked(LEAF_2)]);
    let key_3 = Word::from([ZERO, ZERO, ZERO, Felt::new_unchecked(LEAF_3)]);
    let key_4 = Word::from([ZERO, ZERO, ZERO, Felt::new_unchecked(LEAF_4)]);
    let key_5 = Word::from([ZERO, ZERO, ZERO, Felt::new_unchecked(LEAF_5)]);
    let key_6 = Word::from([ZERO, ZERO, ZERO, Felt::new_unchecked(LEAF_6)]);
    let key_7 = Word::from([ZERO, ZERO, ZERO, Felt::new_unchecked(LEAF_7)]);

    let mut rng = ChaCha20Rng::from_seed([12u8; 32]);

    // Create full SMT with keys 1 and 3 (key_3 makes node b non-empty)
    let mut full =
        Smt::with_entries([(key_1, random_word(&mut rng)), (key_3, random_word(&mut rng))])
            .unwrap();

    // Create partial SMT with ONLY the proof for key 1
    let proof_1 = full.open(&key_1);
    let mut partial = PartialSmt::from_proofs([proof_1]).unwrap();
    assert_eq!(full.root(), partial.root());

    // Key 1: CAN update (explicitly tracked via proof)
    let new_value_1 = random_word(&mut rng);
    full.insert(key_1, new_value_1).unwrap();
    partial.insert(key_1, new_value_1).unwrap();
    assert_eq!(full.root(), partial.root());

    // Key 0: CAN update (under same parent 'a' as key 1, empty)
    let value_0 = random_word(&mut rng);
    full.insert(key_0, value_0).unwrap();
    partial.insert(key_0, value_0).unwrap();
    assert_eq!(full.root(), partial.root());

    // Key 4: CAN update (in empty subtree f)
    let value_4 = random_word(&mut rng);
    full.insert(key_4, value_4).unwrap();
    partial.insert(key_4, value_4).unwrap();
    assert_eq!(full.root(), partial.root());

    // Note: After inserting key 4, subtree f is no longer empty, but keys 5, 6, 7
    // remain trackable through the inner nodes created by previous inserts.

    // Key 5: CAN update
    let value_5 = random_word(&mut rng);
    full.insert(key_5, value_5).unwrap();
    partial.insert(key_5, value_5).unwrap();
    assert_eq!(full.root(), partial.root());

    // Key 6: CAN update
    let value_6 = random_word(&mut rng);
    full.insert(key_6, value_6).unwrap();
    partial.insert(key_6, value_6).unwrap();
    assert_eq!(full.root(), partial.root());

    // Key 7: CAN update
    let value_7 = random_word(&mut rng);
    full.insert(key_7, value_7).unwrap();
    partial.insert(key_7, value_7).unwrap();
    assert_eq!(full.root(), partial.root());

    // Key 2: CANNOT update (under non-empty node b, only have its hash)
    let result = partial.insert(key_2, random_word(&mut rng));
    assert_matches!(result, Err(MerkleError::UntrackedKey(_)));

    // Key 3: CANNOT update (has data but no proof in partial SMT)
    let result = partial.insert(key_3, random_word(&mut rng));
    assert_matches!(result, Err(MerkleError::UntrackedKey(_)));

    // Verify roots still match (failed inserts should not modify partial SMT)
    assert_eq!(full.root(), partial.root());
}

#[test]
fn partial_smt_implicit_empty_tree() {
    let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
    let mut full = Smt::new();
    let mut partial = PartialSmt::new(full.root());

    let key = random_word(&mut rng);
    let value = random_word(&mut rng);

    full.insert(key, value).unwrap();
    // Can insert into empty partial SMT (implicitly tracked)
    partial.insert(key, value).unwrap();

    assert_eq!(full.root(), partial.root());
    assert_eq!(partial.get_value(&key).unwrap(), value);
}

#[test]
fn partial_smt_implicit_insert_and_remove() {
    let mut rng = ChaCha20Rng::from_seed([14u8; 32]);
    let mut full = Smt::new();
    let mut partial = PartialSmt::new(full.root());

    let key = random_word(&mut rng);
    let value = random_word(&mut rng);

    // Insert into implicitly tracked leaf
    full.insert(key, value).unwrap();
    partial.insert(key, value).unwrap();
    assert_eq!(full.root(), partial.root());

    // Remove the value we just inserted
    full.insert(key, EMPTY_WORD).unwrap();
    partial.insert(key, EMPTY_WORD).unwrap();
    assert_eq!(full.root(), partial.root());
    assert_eq!(partial.get_value(&key).unwrap(), EMPTY_WORD);
    assert_eq!(partial.num_entries(), 0);
    // Empty leaves are removed from storage
    assert_eq!(partial.num_leaves(), 0);
}

/// Tests that deserialization fails when an inner node hash is inconsistent with its parent.
#[test]
fn partial_smt_deserialize_invalid_inner_node() {
    let mut rng = ChaCha20Rng::from_seed([15u8; 32]);
    let key = random_word(&mut rng);
    let value = random_word(&mut rng);
    let smt = Smt::with_entries([(key, value)]).unwrap();

    let proof = smt.open(&key);
    let mut partial = PartialSmt::new(smt.root());
    partial.add_proof(proof).unwrap();

    // Serialize and tamper with inner node data
    let mut bytes = partial.to_bytes();

    // The inner node data is at the end of the serialization.
    // Flip a byte in the inner node section to corrupt it.
    let last_idx = bytes.len() - 1;
    bytes[last_idx] ^= 0xff;

    let result = PartialSmt::read_from_bytes(&bytes);
    assert!(result.is_err());
}

/// Tests that deserialization fails when a leaf hash is inconsistent with its parent inner
/// node.
#[test]
fn partial_smt_deserialize_invalid_leaf() {
    let mut rng = ChaCha20Rng::from_seed([16u8; 32]);
    let key = random_word(&mut rng);
    let value = random_word(&mut rng);
    let smt = Smt::with_entries([(key, value)]).unwrap();

    let proof = smt.open(&key);
    let mut partial = PartialSmt::new(smt.root());
    partial.add_proof(proof).unwrap();

    // Serialize the partial SMT
    let bytes = partial.to_bytes();

    // Find where the leaf data starts (after root and leaves count).
    // Root is 32 bytes, leaves count is 8 bytes, leaf position is 8 bytes.
    // Tamper with leaf value data (after position).
    // Byte position to flip.
    let leaf_value_offset = 32 + 8 + 8 + 10;
    let mut tampered_bytes = bytes;
    // Flip a byte in the leaf value data to corrupt it.
    tampered_bytes[leaf_value_offset] ^= 0xff;

    let result = PartialSmt::read_from_bytes(&tampered_bytes);
    assert!(result.is_err());
}

/// Tests that deserialization fails when the root is inconsistent with the inner nodes.
#[test]
fn partial_smt_deserialize_invalid_root() {
    let mut rng = ChaCha20Rng::from_seed([17u8; 32]);
    let key = random_word(&mut rng);
    let value = random_word(&mut rng);
    let smt = Smt::with_entries([(key, value)]).unwrap();

    let proof = smt.open(&key);
    let mut partial = PartialSmt::new(smt.root());
    partial.add_proof(proof).unwrap();

    // Serialize and tamper with root (first 32 bytes)
    let mut bytes = partial.to_bytes();
    bytes[0] ^= 0xff;

    let result = PartialSmt::read_from_bytes(&bytes);
    assert!(result.is_err());
}

/// Tests that deserialization fails when leaves count is tampered to be smaller.
#[test]
fn partial_smt_deserialize_leaves_count_smaller() {
    let mut rng = ChaCha20Rng::from_seed([18u8; 32]);
    let key = random_word(&mut rng);
    let value = random_word(&mut rng);
    let smt = Smt::with_entries([(key, value)]).unwrap();

    let proof = smt.open(&key);
    let mut partial = PartialSmt::new(smt.root());
    partial.add_proof(proof).unwrap();

    let mut bytes = partial.to_bytes();

    // Tamper the leaves count to be smaller by one
    let leaves_count_offset = 32;
    let count =
        u64::from_le_bytes(bytes[leaves_count_offset..leaves_count_offset + 8].try_into().unwrap());
    let tampered_count = count.saturating_sub(1);
    bytes[leaves_count_offset..leaves_count_offset + 8]
        .copy_from_slice(&tampered_count.to_le_bytes());

    let result = PartialSmt::read_from_bytes(&bytes);
    assert!(result.is_err());
}

/// Tests that deserialization fails when leaves count is tampered to be larger.
#[test]
fn partial_smt_deserialize_leaves_count_larger() {
    let mut rng = ChaCha20Rng::from_seed([19u8; 32]);
    let key = random_word(&mut rng);
    let value = random_word(&mut rng);
    let smt = Smt::with_entries([(key, value)]).unwrap();

    let proof = smt.open(&key);
    let mut partial = PartialSmt::new(smt.root());
    partial.add_proof(proof).unwrap();

    let mut bytes = partial.to_bytes();

    // Tamper the leaves count to be larger by one
    let leaves_count_offset = 32;
    let count =
        u64::from_le_bytes(bytes[leaves_count_offset..leaves_count_offset + 8].try_into().unwrap());
    let tampered_count = count + 1;
    bytes[leaves_count_offset..leaves_count_offset + 8]
        .copy_from_slice(&tampered_count.to_le_bytes());

    let result = PartialSmt::read_from_bytes(&bytes);
    assert!(result.is_err());
}

// UNIQUE NODES TESTS
// ================================================================================================

#[test]
fn unique_nodes_roundtrips() {
    let mut rng = ContinuousRng::new([0x96; 32]);

    // Set up our tree, starting as an empty tree root and then inserting a few values.
    let mut tree = PartialSmt::new(*EmptySubtreeRoots::entry(SMT_DEPTH, 0));
    for _ in 0..200 {
        tree.insert(rng.value(), rng.value()).unwrap();
    }

    // We then convert it to its representation as unique nodes.
    let uniques = tree.to_unique_nodes();

    // The leaves in the unique representation should be exactly the same leaves as were stored by
    // the original tree.
    let original_leaves = tree
        .leaves()
        .sorted_by_key(|(k, _)| *k)
        .map(|(k, v)| (k.position(), v.clone()))
        .collect::<Vec<_>>();
    let unique_leaves = uniques
        .leaves
        .iter()
        .sorted_by_key(|(k, _)| *k)
        .map(|(k, v)| (*k, v.clone()))
        .collect::<Vec<_>>();
    assert_eq!(unique_leaves, original_leaves);

    // Finally, the unique representation should result in the same tree.
    let reconstituted_tree =
        PartialSmt::from_unique_nodes(uniques).expect("No data corruption has occurred in memory");
    assert_eq!(reconstituted_tree, tree);
}

#[test]
fn unique_nodes_of_exclusion_proofs_roundtrips() {
    let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
    let key = random_word(&mut rng);
    let val = random_word(&mut rng);
    let key_1 = random_word(&mut rng);
    let val_1 = random_word(&mut rng);
    let key_2 = random_word(&mut rng);
    let val_2 = random_word(&mut rng);
    let missing_key = random_word(&mut rng);
    let smt: Smt = Smt::with_entries([(key, val), (key_1, val_1), (key_2, val_2)]).unwrap();

    let partial_smt = PartialSmt::from_proofs([smt.open(&missing_key)]).unwrap();
    let unique_nodes = partial_smt.to_unique_nodes();
    let decoded = PartialSmt::from_unique_nodes(unique_nodes).unwrap();

    assert_eq!(partial_smt, decoded);
}

#[test]
fn unique_nodes_serialization_roundtrips() {
    let mut rng = ContinuousRng::new([0xab; 32]);

    // Set up our tree, starting as an empty tree root and then inserting a few values.
    let mut tree = PartialSmt::new(*EmptySubtreeRoots::entry(SMT_DEPTH, 0));
    for _ in 0..200 {
        tree.insert(rng.value(), rng.value()).unwrap();
    }

    // We then check that the serialization round-trips correctly.
    assert_eq!(PartialSmt::read_from_bytes(&tree.to_bytes()), Ok(tree));
}

// PROPTEST-BASED TESTS
// ================================================================================================
// These tests use proptest's Arbitrary trait, which is no_std compatible with the `alloc` feature.

proptest! {
    /// Conversion to and from unique nodes should always round-trip to the same tree.
    #[test]
    fn prop_unique_nodes_roundtrips(
        kv_pairs in prop::collection::vec((arbitrary_valid_word(), arbitrary_valid_word()), 0..100),
    ) {
        let mut smt = PartialSmt::new(*EmptySubtreeRoots::entry(SMT_DEPTH, 0));

        for (k, v) in kv_pairs {
            smt.insert(k, v)?;
        }

        let unique = smt.to_unique_nodes();
        let result = PartialSmt::from_unique_nodes(unique)?;

        prop_assert_eq!(result, smt);
    }

    /// Deserialization of the serialized blob should always result in the same value.
    #[test]
    fn prop_serde_roundtrips(
        kv_pairs in prop::collection::vec((arbitrary_valid_word(), arbitrary_valid_word()), 0..100),
    ) {
        let mut smt = PartialSmt::new(*EmptySubtreeRoots::entry(SMT_DEPTH, 0));

        for (k, v) in kv_pairs {
            smt.insert(k, v)?;
        }

        let bytes = smt.to_bytes();
        let result = PartialSmt::read_from_bytes(&bytes)?;

        prop_assert_eq!(result, smt);
    }

    /// Property test: inserting a value into an empty partial SMT and then reading it back
    /// should return the same value.
    #[test]
    fn prop_partial_smt_insert_roundtrip(key: Word, value: Word) {
        // Skip empty values as they have special semantics
        prop_assume!(value != EMPTY_WORD);

        let mut full = Smt::new();
        let mut partial = PartialSmt::new(full.root());

        full.insert(key, value).unwrap();
        partial.insert(key, value).unwrap();

        prop_assert_eq!(full.root(), partial.root());
        prop_assert_eq!(partial.get_value(&key).unwrap(), value);
    }

    /// Property test: serialization roundtrip for partial SMT constructed from an empty tree.
    #[test]
    fn prop_partial_smt_empty_serialization_roundtrip(root: Word) {
        let partial_smt = PartialSmt::new(root);
        let bytes = partial_smt.to_bytes();
        let decoded = PartialSmt::read_from_bytes(&bytes).unwrap();
        prop_assert_eq!(partial_smt, decoded);
    }
}
