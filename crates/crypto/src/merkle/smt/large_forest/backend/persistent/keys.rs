//! This module contains the definition of the various key types necessary for querying the backing
//! persistent DB.

use miden_serde_utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};

use crate::merkle::{NodeIndex, smt::LineageId};

// LEAF KEY
// ================================================================================================

/// A key that uniquely identifies a leaf in the database.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub struct LeafKey {
    /// The lineage (and hence tree) to which the leaf belongs.
    pub lineage: LineageId,

    /// The logical index of the leaf within its parent tree.
    pub index: u64,
}

impl Serializable for LeafKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.lineage);
        target.write(self.index);
    }

    fn get_size_hint(&self) -> usize {
        size_of::<LineageId>() + size_of::<u64>()
    }
}

impl Deserializable for LeafKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let lineage = LineageId::read_from(source)?;
        let index = source.read_u64()?;

        Ok(Self { lineage, index })
    }
}

// SUBTREE KEY
// ================================================================================================

/// A key that uniquely identifies a subtree in the database.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub struct SubtreeKey {
    /// The lineage (and hence tree) to which the subtree belongs.
    pub lineage: LineageId,

    /// The node index of the root of the subtree.
    pub index: NodeIndex,
}

impl Serializable for SubtreeKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.lineage);
        target.write(self.index);
    }

    fn get_size_hint(&self) -> usize {
        size_of::<LineageId>() + size_of::<NodeIndex>()
    }
}

impl Deserializable for SubtreeKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let lineage = LineageId::read_from(source)?;
        let index = NodeIndex::read_from(source)?;

        Ok(Self { lineage, index })
    }
}

// ARBITRARY (proptest)
// ================================================================================================

#[cfg(any(test, feature = "arbitrary"))]
mod arbitrary {
    use proptest::prelude::*;

    use super::{LeafKey, LineageId, NodeIndex, SubtreeKey};

    impl Arbitrary for LeafKey {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            // Any (lineage, index) pair is a structurally valid database key.
            (any::<LineageId>(), any::<u64>())
                .prop_map(|(lineage, index)| Self { lineage, index })
                .boxed()
        }
    }

    impl Arbitrary for SubtreeKey {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            // Any (lineage, valid NodeIndex) pair is a structurally valid database key.
            (any::<LineageId>(), any::<NodeIndex>())
                .prop_map(|(lineage, index)| Self { lineage, index })
                .boxed()
        }
    }
}
