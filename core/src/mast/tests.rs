use alloc::{collections::BTreeSet, vec::Vec};

use miden_crypto::rand::test_utils::prng_array;
use proptest::prelude::*;

use crate::{
    Felt, WORD_SIZE, Word,
    advice::AdviceMap,
    chiplets::hasher,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DynNode, DynNodeBuilder, ExternalNodeBuilder,
        JoinNodeBuilder, MastForest, MastForestContributor, MastForestError, MastNodeExt,
        MastNodeId,
    },
    operations::Operation,
    program::{KernelDescriptor, ProgramInfo},
    serde::{Deserializable, Serializable},
    utils::IndexVec,
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
        let kernel = KernelDescriptor::new(&kernel).unwrap();
        let program_info = ProgramInfo::new(program_hash, kernel);
        let bytes = program_info.to_bytes();
        let deser = ProgramInfo::read_from_bytes(&bytes).unwrap();
        assert_eq!(program_info, deser);
    }
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

    // Test that advice map changes recompute the forest commitment.
    forest = forest.with_advice_map(AdviceMap::from_iter([(Word::from([Felt::ZERO; 4]), vec![])]));
    let commitment5 = forest.commitment();
    assert_ne!(
        commitment3, commitment5,
        "advice_map changes should affect the forest commitment"
    );

    // Test that remove_nodes invalidates the cache
    let nodes_to_remove = BTreeSet::new();
    forest.remove_nodes(&nodes_to_remove); // Empty set, but still calls the method
    let commitment7 = forest.commitment();
    // Since we didn't actually remove anything, commitment should still be the same
    assert_eq!(commitment5, commitment7);
}

#[test]
fn mast_forest_commitment_separates_interface_and_dependencies() {
    let mut first = MastForest::new();
    let first_root = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut first)
        .unwrap();
    first.make_root(first_root);
    ExternalNodeBuilder::new(Word::new([
        Felt::new_unchecked(1),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ]))
    .add_to_forest(&mut first)
    .unwrap();

    let (first, _) =
        MastForest::from_raw_parts_with_id_map(first.nodes, first.roots, first.advice_map).unwrap();

    let mut second = MastForest::new();
    let second_root = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut second)
        .unwrap();
    second.make_root(second_root);
    ExternalNodeBuilder::new(Word::new([
        Felt::new_unchecked(2),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ]))
    .add_to_forest(&mut second)
    .unwrap();
    let (second, _) =
        MastForest::from_raw_parts_with_id_map(second.nodes, second.roots, second.advice_map)
            .unwrap();

    assert_eq!(first.interface_commitment(), second.interface_commitment());
    assert_ne!(first.dependency_commitment(), second.dependency_commitment());
    assert_ne!(first.commitment(), second.commitment());
}

#[test]
fn from_raw_parts_canonicalizes_dense_node_order() {
    let mut forest = MastForest::new();
    let block = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    let high = Word::new([Felt::new_unchecked(9), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    let low = Word::new([Felt::new_unchecked(3), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    let high_external = ExternalNodeBuilder::new(high).add_to_forest(&mut forest).unwrap();
    let low_external = ExternalNodeBuilder::new(low).add_to_forest(&mut forest).unwrap();
    let join = JoinNodeBuilder::new([block, high_external]).add_to_forest(&mut forest).unwrap();
    forest.make_root(join);
    forest.make_root(low_external);

    let finalized =
        MastForest::from_raw_parts(forest.nodes, forest.roots, forest.advice_map).unwrap();

    assert_eq!(finalized[MastNodeId::new_unchecked(0)].digest(), low);
    assert_eq!(finalized[MastNodeId::new_unchecked(1)].digest(), high);
    assert!(finalized[MastNodeId::new_unchecked(2)].is_basic_block());
    let join = finalized[MastNodeId::new_unchecked(3)].unwrap_join();
    assert_eq!(join.first(), MastNodeId::new_unchecked(2));
    assert_eq!(join.second(), MastNodeId::new_unchecked(1));
    assert_eq!(
        finalized.procedure_roots(),
        &[MastNodeId::new_unchecked(3), MastNodeId::new_unchecked(0)]
    );
}

#[test]
fn from_raw_parts_topologically_orders_internal_nodes() {
    let mut source = MastForest::new();
    let left = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut source)
        .unwrap();
    let right = BasicBlockNodeBuilder::new(vec![Operation::Mul])
        .add_to_forest(&mut source)
        .unwrap();
    let join = JoinNodeBuilder::new([left, right]).add_to_forest(&mut source).unwrap();

    let mut nodes = IndexVec::new();
    nodes
        .push(
            JoinNodeBuilder::new([MastNodeId::new_unchecked(1), MastNodeId::new_unchecked(2)])
                .with_digest(source[join].digest())
                .build_linked()
                .unwrap()
                .into(),
        )
        .unwrap();
    nodes.push(source[left].clone()).unwrap();
    nodes.push(source[right].clone()).unwrap();

    let finalized =
        MastForest::from_raw_parts(nodes, vec![MastNodeId::new_unchecked(0)], AdviceMap::default())
            .unwrap();

    assert!(finalized[MastNodeId::new_unchecked(0)].is_basic_block());
    assert!(finalized[MastNodeId::new_unchecked(1)].is_basic_block());
    let join = finalized[MastNodeId::new_unchecked(2)].unwrap_join();
    assert_eq!(join.first(), MastNodeId::new_unchecked(0));
    assert_eq!(join.second(), MastNodeId::new_unchecked(1));
    assert_eq!(finalized.procedure_roots(), &[MastNodeId::new_unchecked(2)]);
}

#[test]
fn from_raw_parts_rejects_duplicate_external_digests() {
    let mut forest = MastForest::new();
    let duplicate = Word::new([Felt::new_unchecked(3), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    ExternalNodeBuilder::new(duplicate).add_to_forest(&mut forest).unwrap();
    ExternalNodeBuilder::new(duplicate).add_to_forest(&mut forest).unwrap();

    let result = MastForest::from_raw_parts(forest.nodes, forest.roots, forest.advice_map);

    assert!(matches!(
        result,
        Err(MastForestError::InvalidNodeOrder { reason, .. })
            if reason.contains("external node digests must be strictly increasing")
    ));
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
