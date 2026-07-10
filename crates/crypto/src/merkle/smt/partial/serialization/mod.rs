//! This module contains a system for producing compact serialized representations of the
//! `PartialSmt` data structure, intended to reduce data sent over the wire through de-duplication.

pub mod property_tests;
mod tests;

use alloc::{string::ToString, vec::Vec};
use core::mem::size_of;

use miden_field::{Felt, FeltFromIntError, Word};
use miden_serde_utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};

use crate::{
    Map,
    merkle::{
        EmptySubtreeRoots,
        smt::{SMT_DEPTH, SmtLeaf},
    },
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
/// The serialization and deserialization process does not validate that node or leaf indices are
/// valid for their level. This is the responsibility of the client of this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniqueNodes {
    /// The expected root of the tree after reconstruction.
    ///
    /// This primarily exists as a sanity check, taking little extra space but ensuring that we can
    /// detect more possible cases of corruption.
    pub root: Word,

    /// The nodes that make up the tree itself.
    ///
    /// It maps the node depth to a vector containing all the nodes at that depth, ensuring that no
    /// data that can be reasonably reconstructed is stored.
    pub nodes: Map<u8, Vec<(u64, NodeValue)>>,

    /// The leaves of the tree.
    ///
    /// It only stores the populated leaves, keyed on their index.
    pub leaves: Vec<(u64, SmtLeaf)>,

    /// The leaves for which we only have the hash value, and not the actual leaf value.
    ///
    /// We keep these separately to the `leaves` as storing them this way is more compact.
    pub value_only_leaves: Vec<(u64, Word)>,
}

impl UniqueNodes {
    /// Creates an empty `UniqueNodes` with no nodes or leaves in it.
    pub fn empty() -> Self {
        Self {
            root: *EmptySubtreeRoots::entry(SMT_DEPTH, 0),
            nodes: Map::default(),
            leaves: Vec::default(),
            value_only_leaves: Vec::default(),
        }
    }
}

impl Default for UniqueNodes {
    fn default() -> Self {
        Self::empty()
    }
}

impl Serializable for UniqueNodes {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // First we write the expected root into the buffer.
        self.root.write_into(target);

        // We write the length as u64 to ensure portability.
        let node_count = self.nodes.len() as u64;
        target.write(node_count);

        // We then write each of the pairs of (u8, Vec<...>) independently.
        for (depth, nodes) in self.nodes.iter() {
            target.write(depth);
            let node_count = nodes.len() as u64;
            target.write(node_count);
            target.write_many(nodes.iter());
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
        let mut nodes = Map::new();

        // Next we have that many levels to read, but each is of a variable size.
        for _ in 0..level_count {
            let depth = source.read_u8()?;
            let node_count = source.read_u64()?;
            let level_nodes = source
                .read_many_iter(node_count.try_into().map_err(|_| {
                    DeserializationError::InvalidValue(format!("Node count {node_count} overflow"))
                })?)?
                .collect::<Result<Vec<_>, _>>()?;
            nodes.insert(depth, level_nodes);
        }

        // Next we need the number of leaves.
        let leaf_count = source.read_u64()?;
        let mut leaves = Vec::new();

        // And then we have to read that many leaves.
        for _ in 0..leaf_count {
            leaves.push(source.read()?);
        }

        // Finally we read the number of value-only leaves...
        let value_only_leaf_count = source.read_u64()?;
        let mut value_only_leaves = Vec::new();

        // ... and read that many.
        for _ in 0..value_only_leaf_count {
            value_only_leaves.push(source.read()?);
        }

        Ok(Self { root, nodes, leaves, value_only_leaves })
    }
}

// NODE VALUE
// ================================================================================================

/// The value of a node in the serialized representation.
///
/// # Serialization
///
/// This enum can be in one of two cases: empty, or containing a Word. The naïve serialization would
/// use a flag to indicate the variant, costing at least a byte to avoid the need for potentially
/// expensive unaligned accesses.
///
/// [`Word`], however, consists of four `Felt`s, each of which occupies the Goldilocks field. This
/// provides a niche in each of those `Felt`s that allows us to not require the extra byte when
/// serializing a true value. As we assume that real values are more common than empty subtree roots
/// by their very nature, making an empty root take 8 bytes instead of 1 is a smaller cost to pay
/// than an extra byte for each populated node.
///
/// To that end, we encode the type as follows:
///
/// - For `Self::EmptySubtreeRoot` we encode the LE bytes for [`u64::MAX`], which exceeds the field
///   order and hence serves as a sentinel value using the niche.
/// - For `Self::Present` we simply encode the word as its four component felts. As none of the
///   felts can take a value exceeding [`Felt::ORDER`], we can immediately disambiguate between this
///   case and the one above.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeValue {
    /// The node is the head of an empty subtree at the depth given by the outer map in
    /// [`UniqueNodes`].
    EmptySubtreeRoot,

    /// The node's value is the provided hash.
    Present(Word),
}

impl Serializable for NodeValue {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            NodeValue::EmptySubtreeRoot => target.write_u64(u64::MAX),
            NodeValue::Present(w) => w.write_into(target),
        }
    }
}

impl Deserializable for NodeValue {
    fn min_serialized_size() -> usize {
        size_of::<u64>()
    }

    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let first_value = source.read_u64()?;

        let to_e = |e: FeltFromIntError| DeserializationError::InvalidValue(e.to_string());

        if first_value == u64::MAX {
            Ok(Self::EmptySubtreeRoot)
        } else {
            // We start by reading the rest of the bytes here to make sure that we have enough data
            // before actually deserializing.
            let remaining_values: [u64; Word::NUM_ELEMENTS - 1] = source.read()?;

            let felts = [
                Felt::new(first_value).map_err(to_e)?,
                Felt::new(remaining_values[0]).map_err(to_e)?,
                Felt::new(remaining_values[1]).map_err(to_e)?,
                Felt::new(remaining_values[2]).map_err(to_e)?,
            ];

            Ok(Self::Present(Word::new(felts)))
        }
    }
}
