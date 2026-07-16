use crate::{
    Word,
    merkle::{MerkleError, MerkleProof, SparseMerklePath},
};

/// A container for a [crate::Word] value and its [SparseMerklePath] opening.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SimpleSmtProof {
    /// The node value opening for `path`.
    pub value: Word,
    /// The path from `value` to `root` (exclusive), using an efficient memory representation for
    /// empty nodes.
    pub path: SparseMerklePath,
}

impl SimpleSmtProof {
    /// Convenience function to construct a [SimpleSmtProof].
    ///
    /// `value` is the value `path` leads to, in the tree.
    pub fn new(value: Word, path: SparseMerklePath) -> Self {
        Self { value, path }
    }
}

impl From<(SparseMerklePath, Word)> for SimpleSmtProof {
    fn from((path, value): (SparseMerklePath, Word)) -> Self {
        SimpleSmtProof::new(value, path)
    }
}

impl TryFrom<MerkleProof> for SimpleSmtProof {
    type Error = MerkleError;

    /// # Errors
    ///
    /// This conversion returns [MerkleError::DepthTooBig] if the path length is greater than
    /// [`super::SMT_MAX_DEPTH`].
    fn try_from(other: MerkleProof) -> Result<Self, MerkleError> {
        let MerkleProof { value, path } = other;
        let path = SparseMerklePath::try_from(path)?;
        Ok(SimpleSmtProof { value, path })
    }
}

impl From<SimpleSmtProof> for MerkleProof {
    fn from(other: SimpleSmtProof) -> Self {
        let SimpleSmtProof { value, path } = other;
        MerkleProof { value, path: path.into() }
    }
}

impl PartialEq<MerkleProof> for SimpleSmtProof {
    fn eq(&self, rhs: &MerkleProof) -> bool {
        self.value == rhs.value && self.path == rhs.path
    }
}

impl PartialEq<SimpleSmtProof> for MerkleProof {
    fn eq(&self, rhs: &SimpleSmtProof) -> bool {
        rhs == self
    }
}
