//! This module contains utility types for working with roots and trees as part of the forest.

#[cfg(feature = "serde")]
use miden_serde_utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};

#[cfg(test)]
use crate::rand::Randomizable;
use crate::{
    Word,
    merkle::smt::{LeafIndex, SMT_DEPTH},
};

// TYPES
// ================================================================================================

/// A root for a tree in the forest.
pub type RootValue = Word;

/// An identifier for the version of a tree in a given lineage
pub type VersionId = u64;

// LINEAGE ID
// ================================================================================================

/// An identifier for a lineage of trees.
///
/// This is an arbitrary, user-provided identifier that is used to disambiguate cases where trees in
/// distinct lineages are otherwise identical and have the same root.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LineageId([u8; 32]);

impl LineageId {
    /// Constructs a new lineage ID from the provided bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Display for LineageId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[")?;
        for i in 0..4 {
            let byte = self.0[i];
            write!(f, "{byte:x}, ")?;
        }
        write!(f, "...]")
    }
}

#[cfg(feature = "serde")]
impl Serializable for LineageId {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0)
    }

    fn get_size_hint(&self) -> usize {
        size_of_val(&self.0)
    }
}

#[cfg(feature = "serde")]
impl Deserializable for LineageId {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self(source.read_array()?))
    }
}

#[cfg(test)]
impl Randomizable for LineageId {
    const VALUE_SIZE: usize = size_of::<Self>();

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        let bytes = Randomizable::from_random_bytes(source)?;
        Some(Self::new(bytes))
    }
}

// TREE IDENTIFIER
// ================================================================================================

/// An identifier that is capable of uniquely referring to a tree in the forest.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TreeId {
    lineage: LineageId,
    version: VersionId,
}

/// The base API of the identifier.
impl TreeId {
    /// Constructs a new tree identifier for the tree with the specified `version` in the specified
    /// `lineage`.
    pub fn new(lineage: LineageId, version: VersionId) -> Self {
        Self { lineage, version }
    }

    /// Gets the tree's lineage from the identifier.
    pub fn lineage(&self) -> LineageId {
        self.lineage
    }

    /// Gets the tree's version from the identifier.
    pub fn version(&self) -> VersionId {
        self.version
    }
}

impl core::fmt::Display for TreeId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TreeId(lineage = {}, version = {})", self.lineage, self.version)
    }
}

#[cfg(test)]
impl Randomizable for TreeId {
    const VALUE_SIZE: usize = size_of::<Self>();

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        const LINEAGE_SIZE: usize = size_of::<LineageId>();
        const VERSION_SIZE: usize = size_of::<VersionId>();
        let domain = Randomizable::from_random_bytes(&source[0..LINEAGE_SIZE])?;
        let version =
            Randomizable::from_random_bytes(&source[LINEAGE_SIZE..LINEAGE_SIZE + VERSION_SIZE])?;
        Some(Self::new(domain, version))
    }
}

// UNIQUE ROOT
// ================================================================================================

/// A root in the forest that is anchored to a lineage.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UniqueRoot {
    lineage: LineageId,
    value: RootValue,
}

impl UniqueRoot {
    /// Constructs a new unique root with the provided `value` and `lineage`.
    pub fn new(lineage: LineageId, value: RootValue) -> Self {
        Self { lineage, value }
    }

    /// Gets the lineage in which the root is found.
    pub fn lineage(&self) -> LineageId {
        self.lineage
    }

    /// Gets the value of the tree root itself.
    pub fn value(&self) -> RootValue {
        self.value
    }
}

// TREE ID WITH ROOT
// ================================================================================================

/// The unique identifier for a given tree, along with the value of its root.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TreeWithRoot {
    id: TreeId,
    root: RootValue,
}

impl TreeWithRoot {
    /// Constructs a new tree identifier from the provided `lineage`, `version`, and `root`.
    pub fn new(lineage: LineageId, version: VersionId, root: RootValue) -> Self {
        let id = TreeId::new(lineage, version);
        Self { id, root }
    }

    /// Gets the tree's lineage.
    pub fn lineage(&self) -> LineageId {
        self.id.lineage
    }

    /// Gets the tree's version.
    pub fn version(&self) -> VersionId {
        self.id.version
    }

    /// Gets the tree's root value.
    pub fn root(&self) -> RootValue {
        self.root
    }
}

impl From<TreeWithRoot> for TreeId {
    fn from(value: TreeWithRoot) -> Self {
        value.id
    }
}

impl From<TreeWithRoot> for UniqueRoot {
    fn from(value: TreeWithRoot) -> Self {
        UniqueRoot::new(value.id.lineage, value.root)
    }
}

// ROOT INFO
// ================================================================================================

/// Information about the role that a queried root plays in the forest.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RootInfo {
    /// The queried root corresponds to a tree that is the latest version of a given tree in the
    /// forest.
    LatestVersion(RootValue),

    /// The queried root corresponds to a tree that is _not_ the latest version of a given tree in
    /// the forest.
    HistoricalVersion(RootValue),

    /// The queried root does not belong to any tree that the forest knows about.
    Missing,
}

// TREE ENTRY
// ================================================================================================

/// An entry in a given tree.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TreeEntry {
    pub key: Word,
    pub value: Word,
}
impl TreeEntry {
    pub fn index(&self) -> LeafIndex<SMT_DEPTH> {
        LeafIndex::from(self.key)
    }
}
