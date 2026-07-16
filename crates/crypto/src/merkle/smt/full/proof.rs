use alloc::string::ToString;

use super::{SMT_DEPTH, SmtLeaf, SmtProofError, SparseMerklePath, Word};
use crate::{
    merkle::InnerNodeInfo,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

/// A proof which can be used to assert presence (or absence) of key-value pairs
/// in a [`super::Smt`] (Sparse Merkle Tree).
///
/// The proof consists of a sparse Merkle path and a leaf, which describes the node located at
/// the base of the path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtProof {
    /// The sparse Merkle path from the leaf to the root.
    path: SparseMerklePath,
    /// The leaf node containing one or more key-value pairs.
    leaf: SmtLeaf,
}

impl SmtProof {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new instance of [`SmtProof`] instantiated from the specified path and leaf.
    ///
    /// # Errors
    /// Returns an error if the path length does not match the expected [`SMT_DEPTH`],
    /// which would make the proof invalid.
    pub fn new(path: SparseMerklePath, leaf: SmtLeaf) -> Result<Self, SmtProofError> {
        let depth = path.depth();
        if depth != SMT_DEPTH {
            return Err(SmtProofError::InvalidMerklePathLength(depth as usize));
        }

        Ok(Self { path, leaf })
    }

    /// Returns a new instance of [`SmtProof`] instantiated from the specified path and leaf.
    ///
    /// The length of the path is not checked. Reserved for internal use.
    pub(in crate::merkle::smt) fn new_unchecked(path: SparseMerklePath, leaf: SmtLeaf) -> Self {
        Self { path, leaf }
    }

    // PROOF VERIFIER
    // --------------------------------------------------------------------------------------------

    /// Verifies that a [`super::Smt`] with the specified root contains the provided key-value pair.
    ///
    /// # Errors
    /// - [`SmtProofError::InvalidKeyForProof`] if the key maps to a different leaf index than this
    ///   proof's leaf.
    /// - [`SmtProofError::ConflictingRoots`] if the computed root doesn't match the expected root.
    /// - [`SmtProofError::ValueMismatch`] if the value doesn't match the value in the leaf.
    pub fn verify_presence(
        &self,
        key: &Word,
        value: &Word,
        root: &Word,
    ) -> Result<(), SmtProofError> {
        let value_in_leaf = self.leaf.get_value(key).ok_or(SmtProofError::InvalidKeyForProof)?;

        // Check root before value so that ValueMismatch implies the proof is valid
        let computed_root = self.compute_root();
        if computed_root != *root {
            return Err(SmtProofError::ConflictingRoots {
                expected_root: *root,
                actual_root: computed_root,
            });
        }

        if value_in_leaf != *value {
            return Err(SmtProofError::ValueMismatch { expected: *value, actual: value_in_leaf });
        }

        Ok(())
    }

    /// Verifies that a [`super::Smt`] with the specified root does not contain any value
    /// for the provided key (i.e., the key is unset).
    ///
    /// This is equivalent to calling `verify_presence(key, &EMPTY_WORD, root)`, but makes
    /// the intent clearer.
    ///
    /// # Errors
    /// - [`SmtProofError::InvalidKeyForProof`] if the key maps to a different leaf index than this
    ///   proof's leaf.
    /// - [`SmtProofError::ConflictingRoots`] if the computed root doesn't match the expected root.
    /// - [`SmtProofError::ValueMismatch`] if the key has a value in the tree (i.e., is not empty).
    pub fn verify_unset(&self, key: &Word, root: &Word) -> Result<(), SmtProofError> {
        self.verify_presence(key, &super::EMPTY_WORD, root)
    }

    /// Verifies that a specific key-value pair is not in the tree.
    ///
    /// This succeeds if the key exists with a different value, or if the key is unset.
    ///
    /// # Errors
    /// - [`SmtProofError::InvalidKeyForProof`] if the key maps to a different leaf index than this
    ///   proof's leaf.
    /// - [`SmtProofError::ConflictingRoots`] if the computed root doesn't match the expected root.
    /// - [`SmtProofError::ValuePresent`] if the key-value pair exists in the tree.
    pub fn verify_absence(
        &self,
        key: &Word,
        value: &Word,
        root: &Word,
    ) -> Result<(), SmtProofError> {
        match self.verify_presence(key, value, root) {
            // The key-value pair exists - absence verification fails
            Ok(()) => Err(SmtProofError::ValuePresent { key: *key, value: *value }),
            // Value is different - the pair is absent, success
            Err(SmtProofError::ValueMismatch { .. }) => Ok(()),
            // Other errors propagate as-is
            Err(e) => Err(e),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the value associated with the specific key according to this proof, or None if
    /// this proof does not contain a value for the specified key.
    ///
    /// A key-value pair generated by using this method should pass the `verify_presence()` check.
    pub fn get(&self, key: &Word) -> Option<Word> {
        self.leaf.get_value(key)
    }

    /// Computes the root of a [`super::Smt`] to which this proof resolves.
    pub fn compute_root(&self) -> Word {
        self.path
            .compute_root(self.leaf.index().position(), self.leaf.hash())
            .expect("failed to compute Merkle path root")
    }

    /// Returns the proof's sparse Merkle path.
    pub fn path(&self) -> &SparseMerklePath {
        &self.path
    }

    /// Returns the leaf associated with the proof.
    pub fn leaf(&self) -> &SmtLeaf {
        &self.leaf
    }

    /// Returns an iterator over every inner node of this proof's merkle path.
    pub fn authenticated_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.path
            .authenticated_nodes(self.leaf.index().position(), self.leaf.hash())
            .expect("leaf index is u64 and should be less than 2^SMT_DEPTH")
    }

    /// Consume the proof and returns its parts.
    pub fn into_parts(self) -> (SparseMerklePath, SmtLeaf) {
        (self.path, self.leaf)
    }
}

impl Serializable for SmtProof {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.path.write_into(target);
        self.leaf.write_into(target);
    }
}

impl Deserializable for SmtProof {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let path = SparseMerklePath::read_from(source)?;
        let leaf = SmtLeaf::read_from(source)?;

        Self::new(path, leaf).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}
