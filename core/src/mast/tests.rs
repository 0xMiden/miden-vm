use alloc::{collections::BTreeSet, vec::Vec};

use miden_crypto::rand::test_utils::prng_array;
use proptest::prelude::*;

use crate::{
    Felt, WORD_SIZE, Word,
    chiplets::hasher,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DynNode, DynNodeBuilder, MastForest,
        MastForestContributor, MastNodeExt,
    },
    operations::Operation,
    program::{Kernel, ProgramInfo},
    serde::{Deserializable, Serializable},
};

#[test]
fn dyn_hash_is_correct() {
    let expected_constant =
        hasher::merge_in_domain(&[Word::default(), Word::default()], DynNode::DYN_DOMAIN);

    let mut forest = MastForest::new();
    let dyn_node_id = DynNodeBuilder::new_dyn().add_to_forest(&mut forest).unwrap();
    let dyn_node = forest.get_node_by_id(dyn_node_id).unwrap().unwrap_dyn();
    assert_eq!(expected_constant, dyn_node.digest());
}

proptest! {
    #[test]
    fn arbitrary_program_info_serialization_works(
        kernel_count in prop::num::u8::ANY,
        ref seed in any::<[u8; 32]>()
    ) {
        let program_hash = digest_from_seed(*seed);
        let kernel: Vec<Word> = (0..kernel_count)
            .scan(*seed, |seed, _| {
                *seed = prng_array(*seed);
                Some(digest_from_seed(*seed))
            })
            .collect();
        let kernel = Kernel::new(&kernel).unwrap();
        let program_info = ProgramInfo::new(program_hash, kernel);
        let bytes = program_info.to_bytes();
        let deser = ProgramInfo::read_from_bytes(&bytes).unwrap();
        assert_eq!(program_info, deser);
    }
}

// MAST FOREST COMPACTION TESTS
// ================================================================================================

/// Tests comprehensive mast forest compaction across duplicate nodes.
#[test]
fn test_mast_forest_compaction_comprehensive() {
    let mut forest = MastForest::new();

    let bb1 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    let bb2 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(bb1);
    forest.make_root(bb2);

    assert_eq!(forest.num_procedures(), 2);
    assert_eq!(forest.num_nodes(), 2);

    let (forest, _root_map) = forest.compact();

    assert_eq!(forest.num_nodes(), 1);
    assert_eq!(forest.num_procedures(), 1);
}

#[test]
fn test_compaction_independent() {
    let mut forest = MastForest::new();

    // Create two identical nodes.
    let node1 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    let node2 = BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(node1);
    forest.make_root(node2);

    // Verify initial state has duplicate nodes
    assert_eq!(forest.num_nodes(), 2);
    assert_eq!(forest.num_procedures(), 2);

    // Compact only (should merge the two identical nodes)
    let (forest, _root_map) = forest.compact();

    // Verify nodes were merged
    assert_eq!(forest.num_nodes(), 1);
    assert_eq!(forest.num_procedures(), 1);
}

#[test]
fn test_commitment_caching() {
    let mut forest = MastForest::new();

    // Create some nodes
    let node1 = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    let node2 = BasicBlockNodeBuilder::new(vec![Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();

    forest.make_root(node1);

    // First access: commitment is computed and cached
    let commitment1 = forest.commitment();
    assert_ne!(commitment1, Word::from([Felt::ZERO; 4]));

    // Second access: same commitment should be returned (from cache)
    let commitment2 = forest.commitment();
    assert_eq!(commitment1, commitment2);

    // Mutate the forest by adding a new root
    forest.make_root(node2);

    // After mutation, commitment should be different (cache was invalidated and recomputed)
    let commitment3 = forest.commitment();
    assert_ne!(commitment1, commitment3);

    // Accessing again should return the same cached value
    let commitment4 = forest.commitment();
    assert_eq!(commitment3, commitment4);

    // Test that advice_map mutations don't invalidate the cache
    forest.advice_map_mut().insert(Word::from([Felt::ZERO; 4]), vec![]);
    let commitment5 = forest.commitment();
    assert_eq!(
        commitment3, commitment5,
        "advice_map mutation should not invalidate commitment cache"
    );

    // Test that remove_nodes invalidates the cache
    let nodes_to_remove = BTreeSet::new();
    forest.remove_nodes(&nodes_to_remove); // Empty set, but still calls the method
    let commitment7 = forest.commitment();
    // Since we didn't actually remove anything, commitment should still be the same
    assert_eq!(commitment3, commitment7);
}

#[test]
fn remove_nodes_skips_removed_procedure_roots() {
    let mut forest = MastForest::new();
    let removed_root = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    let retained_root = BasicBlockNodeBuilder::new(vec![Operation::Mul])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(removed_root);
    forest.make_root(retained_root);

    let mut nodes_to_remove = BTreeSet::new();
    nodes_to_remove.insert(removed_root);
    let id_remappings = forest.remove_nodes(&nodes_to_remove);
    let retained_root = id_remappings[&retained_root];

    assert_eq!(forest.procedure_roots(), &[retained_root]);
}

#[test]
#[should_panic(expected = "cannot remove node")]
fn remove_nodes_rejects_nodes_referenced_by_retained_parents() {
    let mut forest = MastForest::new();
    let child = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    let parent = CallNodeBuilder::new(child).add_to_forest(&mut forest).unwrap();
    forest.make_root(parent);

    let mut nodes_to_remove = BTreeSet::new();
    nodes_to_remove.insert(child);
    forest.remove_nodes(&nodes_to_remove);
}

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

fn digest_from_seed(seed: [u8; 32]) -> Word {
    let mut digest = [Felt::ZERO; WORD_SIZE];
    digest.iter_mut().enumerate().for_each(|(i, d)| {
        *d = <[u8; 8]>::try_from(&seed[i * 8..(i + 1) * 8])
            .map(u64::from_le_bytes)
            .map(Felt::new_unchecked)
            .unwrap()
    });
    digest.into()
}
