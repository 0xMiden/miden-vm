#![cfg(test)]
//! Contains the property tests for the new serialization mechanism for the `PartialSmt` type.

use alloc::vec::Vec;

use miden_field::{Felt, Word};
use miden_serde_utils::{Deserializable, Serializable};
use proptest::prelude::*;

use crate::{
    Map,
    merkle::smt::{LeafIndex, NodeValue, SmtLeaf, UniqueNodes},
};
// GENERATORS
// ================================================================================================

/// Generates an arbitrary [`Felt`] that is guaranteed to be valid.
fn arbitrary_valid_felt() -> impl Strategy<Value = Felt> {
    any::<u64>().prop_filter_map("Out of bounds for Felt", |e| Felt::new(e).ok())
}

/// Generates an arbitrary [`Word`] that is guaranteed to consist of only valid `Felt`s.
pub fn arbitrary_valid_word() -> impl Strategy<Value = Word> {
    prop::array::uniform4(arbitrary_valid_felt()).prop_map(Word::new)
}

impl Arbitrary for NodeValue {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(NodeValue::EmptySubtreeRoot),
            arbitrary_valid_word().prop_map(NodeValue::Present)
        ]
        .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

/// Generates an arbitrary node for the given `level` in the tree, ensuring that the index is in
/// bounds.
fn arbitrary_node_for_level(level: u8) -> impl Strategy<Value = (u64, NodeValue)> + Clone {
    let limit = 2u64.pow(level as u32);

    (0..limit).prop_flat_map(|i| (Just(i), any::<NodeValue>())).prop_filter_map(
        "Invalid node index for level",
        move |(i, v)| {
            if i < 2u64.pow(level as u32) { Some((i, v)) } else { None }
        },
    )
}

/// Generates a set of arbitrary nodes for the given `level` in the tree, ensuring that the indices
/// are in bounds.
fn arbitrary_nodes_for_level(level: u8) -> impl Strategy<Value = Vec<(u64, NodeValue)>> + Clone {
    prop::collection::vec(arbitrary_node_for_level(level), 0..=100)
}

/// Generates a set of arbitrary nodes for a random depth.
fn arbitrary_nodes_for_depth(
    level: u8,
) -> impl Strategy<Value = (u8, Vec<(u64, NodeValue)>)> + Clone {
    (Just(level), arbitrary_nodes_for_level(level))
}

/// Generates an arbitrary set of nodes.
fn arbitrary_nodes() -> impl Strategy<Value = Map<u8, Vec<(u64, NodeValue)>>> {
    prop::collection::vec(1u8..64, 0..=1000)
        .prop_flat_map(|depths| {
            depths.into_iter().map(arbitrary_nodes_for_depth).collect::<Vec<_>>()
        })
        .prop_map(|nodes| nodes.into_iter().collect::<Map<_, _>>())
}

/// Generates a leaf with a single, arbitrary entry.
fn arbitrary_single_leaf() -> impl Strategy<Value = SmtLeaf> {
    (arbitrary_valid_word(), arbitrary_valid_word())
        .prop_map(|(key, value)| SmtLeaf::new_single(key, value))
}

/// Generates a leaf with multiple entries, all ensured to share the same leaf index.
fn arbitrary_multi_leaf() -> impl Strategy<Value = SmtLeaf> {
    prop::collection::vec((arbitrary_valid_word(), arbitrary_valid_word()), 2..=64).prop_map(
        |pairs| {
            let Some((first_key, _)) = pairs.first() else {
                panic!("Minimum requested length is 2 but the pairs vec was empty.")
            };

            let index = LeafIndex::from(*first_key);
            SmtLeaf::new_multiple(
                pairs
                    .into_iter()
                    .map(|(mut key, value)| {
                        key.d = Felt::new_unchecked(index.position());
                        (key, value)
                    })
                    .collect::<Vec<_>>(),
            )
            .expect("All keys have the same leaf index by construction")
        },
    )
}

/// Generates an arbitrary `SmtLeaf`.
fn arbitrary_leaf() -> impl Strategy<Value = SmtLeaf> {
    prop_oneof![
        any::<u64>().prop_map(|i| SmtLeaf::new_empty(LeafIndex::new_max_depth(i))),
        arbitrary_single_leaf(),
        arbitrary_multi_leaf(),
    ]
}

/// Generates an arbitrary number of leaves.
pub fn arbitrary_leaves() -> impl Strategy<Value = Vec<(u64, SmtLeaf)>> {
    prop::collection::vec(arbitrary_leaf(), 0..100).prop_map(|leaves| {
        leaves
            .into_iter()
            .map(|l| {
                let index = l.index().position();
                (index, l)
            })
            .collect::<Vec<_>>()
    })
}

/// Generates arbitrary value-only leaves.
pub fn arbitrary_value_only_leaves() -> impl Strategy<Value = Vec<(u64, Word)>> {
    prop::collection::vec((any::<u64>(), arbitrary_valid_word()), 0..100)
}

// UNIQUE NODES TESTS
// ================================================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn unique_nodes_serialization_always_roundtrips(
        root in arbitrary_valid_word(),
        nodes in arbitrary_nodes(),
        leaves in arbitrary_leaves(),
        value_only_leaves in arbitrary_value_only_leaves(),
    ) {
        let value = UniqueNodes { root, nodes, leaves, value_only_leaves };
        let serialized = value.to_bytes();
        let result = UniqueNodes::read_from_bytes(serialized.as_slice());

        prop_assert_eq!(result, Ok(value));
    }
}

// NODE VALUE TESTS
// ================================================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100_000))]

    #[test]
    fn node_value_serialization_always_roundtrips(
        value in any::<NodeValue>()
    ) {
        let serialized = value.to_bytes();
        let result = NodeValue::read_from_bytes(serialized.as_slice());

        prop_assert_eq!(result, Ok(value));
    }
}
