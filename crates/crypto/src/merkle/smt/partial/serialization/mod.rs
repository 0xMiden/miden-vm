//! This module contains a system for producing compact serialized representations of the
//! `PartialSmt` data structure, intended to reduce data sent over the wire through de-duplication.

pub mod property_tests;
mod tests;

use alloc::{collections::BTreeMap, string::ToString};

use miden_field::Word;
use miden_serde_utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};

use crate::merkle::{
    EmptySubtreeRoots, NodeIndex,
    smt::{LeafIndex, SMT_DEPTH, SmtLeaf},
};

// UNIQUE NODES
// ================================================================================================

/// A representation of a partial SMT that contains only the unique nodes in the tree, designed for
/// better efficiency when sending data across the wire.
///
/// It _explicitly_ does not need to contain a fully-realized SMT, and instead may contain some
/// subset of a full tree. It contains the minimal set of data necessary to reconstruct its input.
///
/// # Versioning
///
/// Note that this structure is explicitly **not intended to be versioned**. This structure should
/// be used as part of a broader serialization solution that does include this if necessary.
///
/// # Serialization
///
/// Deserialization requires nonempty levels with increasing depths and increasing map positions.
/// It validates node indices, checks embedded leaf indices, and rejects overlap between the leaf
/// maps. Serializing a value with mismatched leaf indices or overlapping leaf maps panics.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub struct UniqueNodes {
    /// The expected root of the tree after reconstruction.
    ///
    /// This primarily exists as a sanity check, taking little extra space but ensuring that we can
    /// detect more possible cases of corruption.
    pub root: Word,

    /// The nodes that make up the tree itself.
    ///
    /// It maps each node index to its hash. Empty subtree roots are represented by absence.
    pub nodes: BTreeMap<NodeIndex, Word>,

    /// The leaves of the tree.
    ///
    /// It only stores the populated leaves, keyed on their index.
    pub leaves: BTreeMap<u64, SmtLeaf>,

    /// The leaves for which we only have the hash value, and not the actual leaf value.
    ///
    /// We keep these separately to the `leaves` as storing them this way is more compact.
    pub value_only_leaves: BTreeMap<u64, Word>,
}

impl UniqueNodes {
    /// Creates an empty `UniqueNodes` with no nodes or leaves in it.
    pub fn empty() -> Self {
        Self {
            root: *EmptySubtreeRoots::entry(SMT_DEPTH, 0),
            nodes: BTreeMap::new(),
            leaves: BTreeMap::new(),
            value_only_leaves: BTreeMap::new(),
        }
    }

    /// Returns the hash of the leaf at `position`, or its canonical empty hash when absent.
    pub fn get_leaf_hash(&self, position: u64) -> Word {
        self.leaves
            .get(&position)
            .map(SmtLeaf::hash)
            .or_else(|| self.value_only_leaves.get(&position).copied())
            .unwrap_or_else(|| SmtLeaf::new_empty(LeafIndex::new_max_depth(position)).hash())
    }

    /// Returns the hash of the node at `index`, or its canonical empty root when absent.
    pub fn get_node_hash(&self, index: NodeIndex) -> Word {
        self.nodes
            .get(&index)
            .copied()
            .unwrap_or_else(|| *EmptySubtreeRoots::entry(SMT_DEPTH, index.depth()))
    }

    /// Checks embedded leaf positions and exclusivity of the leaf maps.
    pub(super) fn validate(&self) -> Result<(), DeserializationError> {
        for (&position, leaf) in &self.leaves {
            if self.value_only_leaves.contains_key(&position) {
                return Err(DeserializationError::InvalidValue(format!(
                    "Leaf position {position} appears in both leaf maps"
                )));
            }
            if position != leaf.index().position() {
                return Err(DeserializationError::InvalidValue(format!(
                    "Node index {position} did not match the embedded leaf index {}",
                    leaf.index().position()
                )));
            }
        }

        Ok(())
    }
}

impl Default for UniqueNodes {
    fn default() -> Self {
        Self::empty()
    }
}

impl Serializable for UniqueNodes {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.validate().expect("cannot serialize invalid UniqueNodes");

        // First we write the expected root into the buffer.
        self.root.write_into(target);

        // `NodeIndex` sorts first by depth and then by position. Since `nodes` is a `BTreeMap`, all
        // nodes at the same depth are next to each other and can be written as one level.
        let mut levels = self.nodes.iter().peekable();
        let level_count = self
            .nodes
            .keys()
            .map(NodeIndex::depth)
            .fold((0, None), |(count, previous), depth| {
                (count + u64::from(previous != Some(depth)), Some(depth))
            })
            .0;
        target.write(level_count);

        while let Some((index, _)) = levels.peek() {
            let depth = index.depth();
            target.write(depth);
            let level_node_count =
                levels.clone().take_while(|(index, _)| index.depth() == depth).count();
            target.write(level_node_count as u64);
            for (index, value) in levels.by_ref().take(level_node_count) {
                target.write(index.position());
                target.write(value);
            }
        }

        // The leaves themselves come next.
        let leaf_count = self.leaves.len() as u64;
        target.write(leaf_count);
        target.write_many(self.leaves.iter());

        // And the value-only leaves bring up the rear.
        let value_only_leaf_count = self.value_only_leaves.len() as u64;
        target.write(value_only_leaf_count);
        target.write_many(self.value_only_leaves.iter());
    }
}

impl Deserializable for UniqueNodes {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // The first item is the 32 bytes containing the expected root of the tree after
        // reconstruction.
        let root = Word::read_from(source)?;

        // We first have to read the count of levels.
        let level_count = source.read_u64()?;
        let mut nodes = BTreeMap::new();
        let mut previous_depth = None;

        // Next we have that many levels to read, but each is of a variable size.
        for _ in 0..level_count {
            let depth = source.read_u8()?;
            if let Some(previous) = previous_depth
                && depth <= previous
            {
                return Err(DeserializationError::InvalidValue(format!(
                    "Level depth {depth} does not exceed previous depth {previous}"
                )));
            }
            previous_depth = Some(depth);
            let node_count = source.read_u64()?;
            if node_count == 0 {
                return Err(DeserializationError::InvalidValue(format!(
                    "Empty node level at depth {depth}"
                )));
            }
            let mut previous_position = None;
            for _ in 0..node_count {
                let position = source.read_u64()?;
                if let Some(previous) = previous_position
                    && position < previous
                {
                    return Err(DeserializationError::InvalidValue(format!(
                        "Node position {position} precedes {previous} at depth {depth}"
                    )));
                }
                previous_position = Some(position);
                let index = NodeIndex::new(depth, position)
                    .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;
                let value = source.read()?;
                if nodes.insert(index, value).is_some() {
                    return Err(DeserializationError::InvalidValue(format!(
                        "Duplicate node position {position} at depth {depth}"
                    )));
                }
            }
        }

        // Next we need the number of leaves.
        let leaf_count = source.read_u64()?;
        let mut leaves = BTreeMap::new();
        let mut previous_position = None;

        // And then we have to read that many leaves.
        for _ in 0..leaf_count {
            let (position, leaf) = source.read()?;
            if let Some(previous) = previous_position
                && position < previous
            {
                return Err(DeserializationError::InvalidValue(format!(
                    "Leaf position {position} precedes {previous}"
                )));
            }
            previous_position = Some(position);
            if leaves.insert(position, leaf).is_some() {
                return Err(DeserializationError::InvalidValue(format!(
                    "Duplicate leaf position {position}"
                )));
            }
        }

        // Finally we read the number of value-only leaves...
        let value_only_leaf_count = source.read_u64()?;
        let mut value_only_leaves = BTreeMap::new();
        let mut previous_position = None;

        // ... and read that many.
        for _ in 0..value_only_leaf_count {
            let (position, value) = source.read()?;
            if let Some(previous) = previous_position
                && position < previous
            {
                return Err(DeserializationError::InvalidValue(format!(
                    "Value-only leaf position {position} precedes {previous}"
                )));
            }
            previous_position = Some(position);
            if value_only_leaves.insert(position, value).is_some() {
                return Err(DeserializationError::InvalidValue(format!(
                    "Duplicate value-only leaf position {position}"
                )));
            }
        }

        let unique_nodes = Self { root, nodes, leaves, value_only_leaves };
        unique_nodes.validate()?;
        Ok(unique_nodes)
    }
}

// ARBITRARY (proptest)
// ================================================================================================

#[cfg(any(test, feature = "arbitrary"))]
mod unique_nodes_arbitrary {
    use alloc::collections::BTreeMap;

    use proptest::prelude::*;

    use super::UniqueNodes;
    use crate::{
        Felt, Word,
        merkle::{NodeIndex, smt::Smt},
    };

    impl Arbitrary for UniqueNodes {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            // The reader validates each node index against its declared depth
            // (NodeIndex::new(depth, position)); bound positions to their depth by construction.
            // BTreeMap deduplication keeps every map key unique; empty maps are valid inputs.
            (
                any::<Word>(),
                proptest::collection::vec((0u8..=64, 0usize..=3), 0..=4),
                proptest::collection::vec((any::<Word>(), any::<Word>()), 0..=3),
                proptest::collection::vec(any::<u64>(), 0..=3),
            )
                .prop_map(|(root, levels, leaf_pairs, value_only_positions)| {
                    let mut nodes = BTreeMap::new();
                    for (depth, count) in levels {
                        let mask = if depth == 64 { u64::MAX } else { (1u64 << depth) - 1 };
                        for i in 0..count as u64 {
                            let position = i.wrapping_mul(0x9e37_79b9_7f4a_7c15) & mask;
                            // Arbitrary (non-zero-biased) hash: the wire carries node hashes
                            // verbatim, so the property detects a deserializer that swaps or
                            // zeroes them.
                            let hash: Word = [
                                Felt::from(i as u32 + 1),
                                Felt::from(depth as u32),
                                Felt::from(count as u32),
                                Felt::from(position as u32 % 7),
                            ]
                            .into();
                            nodes.insert(
                                NodeIndex::new(depth, position).expect("position fits the depth"),
                                hash,
                            );
                        }
                    }

                    // Leaves are sound by construction: materialize a real Smt and take its
                    // actual leaves, keyed by their embedded index (the reader cross-validates
                    // the position against the leaf's embedded index).
                    let entries: BTreeMap<Word, Word> = leaf_pairs.into_iter().collect();
                    let smt = Smt::with_entries(entries).expect("keys are distinct");
                    let leaves: BTreeMap<u64, crate::merkle::smt::SmtLeaf> = smt
                        .leaves()
                        .map(|(index, leaf)| (index.position(), leaf.clone()))
                        .collect();

                    let value_only_leaves: BTreeMap<u64, Word> = value_only_positions
                        .into_iter()
                        .filter(|position| !leaves.contains_key(position))
                        .map(|p| {
                            let hash: Word = [
                                Felt::from(p as u32),
                                Felt::from((p as u32).wrapping_add(1)),
                                Felt::from((p as u32).wrapping_add(2)),
                                Felt::from((p as u32).wrapping_add(3)),
                            ]
                            .into();
                            (p, hash)
                        })
                        .collect();
                    Self { root, nodes, leaves, value_only_leaves }
                })
                .boxed()
        }
    }
}
