use alloc::collections::BTreeMap;

use super::{PartialSmt, SMT_DEPTH, UniqueNodes};
use crate::{
    Word,
    merkle::{NodeIndex, smt::SmtLeaf},
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

/// A versioned, shared-node transport for openings against one SMT root.
///
/// Unlike independent paths, this shares common branches using [`UniqueNodes`]. Format version 1
/// writes `SMTWITNS`, a version byte, the root, frontier nodes, complete leaves, and hash-only
/// leaves. Collections use the standard variable-length count. Frontier entries are `(NodeIndex,
/// Word)`; hash-only entries are `(u64, Word)`. Complete leaves use [`SmtLeaf`] encoding, including
/// their position only once. Maps must be in strictly increasing key order.
///
/// This is an opt-in transport, not a replacement for the general Merkle store or the existing
/// unversioned [`PartialSmt`] and [`UniqueNodes`] encodings. Other versions are rejected.
/// Deserialization checks the wire structure; [`Self::into_partial_smt`] checks reconstructed
/// openings against the declared root and bounds reconstruction. A root-only witness carries no
/// openings to check. Use a budgeted reader for untrusted input as well.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub struct SmtWitness(UniqueNodes);

impl SmtWitness {
    const FORMAT_MAGIC: [u8; 8] = *b"SMTWITNS";
    const FORMAT_VERSION: u8 = 1;

    /// Authenticates and reconstructs the witness, rebuilding at most `max_reconstructed_nodes`
    /// parents. Shared parents count once; canonical empty parents also count, even though they
    /// are not retained. The limit bounds reconstruction work and retained inner nodes, not total
    /// allocator memory or the allocations made while decoding the wire representation.
    ///
    /// The resulting tree's `inner_nodes()` can be passed directly to `MerkleStore::extend`.
    /// Its `leaves()` provide the preimages needed by SMT advice-map consumers.
    ///
    /// # Errors
    /// Returns an error if reconstruction exceeds the limit or the reconstructed root is invalid.
    pub fn into_partial_smt(
        self,
        max_reconstructed_nodes: usize,
    ) -> Result<PartialSmt, DeserializationError> {
        PartialSmt::from_unique_nodes_with_limit(self.0, max_reconstructed_nodes)
    }
}

impl From<&PartialSmt> for SmtWitness {
    fn from(tree: &PartialSmt) -> Self {
        Self(tree.to_unique_nodes())
    }
}

impl Serializable for SmtWitness {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&Self::FORMAT_MAGIC);
        target.write_u8(Self::FORMAT_VERSION);
        self.0.root.write_into(target);
        self.0.nodes.write_into(target);
        target.write_usize(self.0.leaves.len());
        target.write_many(self.0.leaves.values());
        self.0.value_only_leaves.write_into(target);
    }
}

impl Deserializable for SmtWitness {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        if source.read_array::<8>()? != Self::FORMAT_MAGIC {
            return Err(DeserializationError::InvalidValue(
                "unsupported SMT witness format: expected a versioned encoding".into(),
            ));
        }
        let version = source.read_u8()?;
        if version != Self::FORMAT_VERSION {
            return Err(DeserializationError::InvalidValue(format!(
                "unsupported SMT witness version {version}"
            )));
        }
        let root = Word::read_from(source)?;
        let nodes: BTreeMap<NodeIndex, Word> = read_ordered_map(source)?;
        if nodes.keys().any(|index| index.depth() == 0 || index.depth() >= SMT_DEPTH) {
            return Err(DeserializationError::InvalidValue(
                "SMT witness frontier nodes must have depths 1..64".into(),
            ));
        }

        let leaf_count = source.read_usize()?;
        let mut leaves = BTreeMap::new();
        for leaf in source.read_many_iter::<SmtLeaf>(leaf_count)? {
            let leaf = leaf?;
            let position = leaf.index().position();
            if leaves.last_key_value().is_some_and(|(&previous, _)| position <= previous) {
                return Err(DeserializationError::InvalidValue(
                    "SMT witness leaf positions must be strictly increasing".into(),
                ));
            }
            leaves.insert(position, leaf);
        }
        let value_only_leaves = read_ordered_map(source)?;
        let nodes = UniqueNodes { root, nodes, leaves, value_only_leaves };
        nodes.validate()?;
        Ok(Self(nodes))
    }

    fn min_serialized_size() -> usize {
        8 + 1 + 32 + 3 // magic, version, root, and three minimum-length collection counts
    }
}

fn read_ordered_map<R: ByteReader, K: Deserializable + Ord, V: Deserializable>(
    source: &mut R,
) -> Result<BTreeMap<K, V>, DeserializationError> {
    let count = source.read_usize()?;
    let mut map = BTreeMap::new();
    for entry in source.read_many_iter::<(K, V)>(count)? {
        let (key, value) = entry?;
        if map.last_key_value().is_some_and(|(previous, _)| &key <= previous) {
            return Err(DeserializationError::InvalidValue(
                "SMT witness map keys must be strictly increasing".into(),
            ));
        }
        map.insert(key, value);
    }
    Ok(map)
}

#[cfg(any(test, feature = "arbitrary"))]
mod arbitrary {
    use proptest::prelude::*;

    use super::{PartialSmt, SmtWitness};

    impl Arbitrary for SmtWitness {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<PartialSmt>().prop_map(|tree| Self::from(&tree)).boxed()
        }
    }
}
