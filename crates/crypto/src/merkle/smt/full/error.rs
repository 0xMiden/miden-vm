use alloc::string::String;

use thiserror::Error;

use crate::{
    Word,
    merkle::smt::{LeafIndex, MAX_LEAF_ENTRIES, SMT_DEPTH},
};

// SMT LEAF ERROR
// =================================================================================================

/// Errors that can occur when constructing or validating SMT leaves.
#[derive(Debug, Error)]
pub enum SmtLeafError {
    /// Keys map to different leaf indices in a multiple-leaf structure.
    #[error(
        "multiple leaf requires all keys to map to the same leaf index but key1 {key_1} and key2 {key_2} map to different indices"
    )]
    /// A single leaf key maps to a different index than expected.
    InconsistentMultipleLeafKeys { key_1: Word, key_2: Word },
    #[error(
        "single leaf key {key} maps to leaf {actual_leaf_index} but was expected to map to leaf {expected_leaf_index}"
    )]
    InconsistentSingleLeafIndices {
        key: Word,
        expected_leaf_index: LeafIndex<SMT_DEPTH>,
        actual_leaf_index: LeafIndex<SMT_DEPTH>,
    },

    /// Supplied leaf index does not match the expected index for the provided keys.
    #[error(
        "supplied leaf index {leaf_index_supplied:?} does not match {leaf_index_from_keys:?} for multiple leaf"
    )]
    InconsistentMultipleLeafIndices {
        leaf_index_from_keys: LeafIndex<SMT_DEPTH>,
        leaf_index_supplied: LeafIndex<SMT_DEPTH>,
    },

    /// Multiple leaf requires at least two entries, but fewer were provided.
    #[error("multiple leaf requires at least two entries but only {0} were given")]
    MultipleLeafRequiresTwoEntries(usize),

    /// Multiple leaf contains more entries than the maximum allowed.
    #[error(
        "multiple leaf contains {actual} entries but the maximum allowed is {MAX_LEAF_ENTRIES}"
    )]
    TooManyLeafEntries { actual: usize },

    /// Elements could not be decoded into a leaf.
    #[error("decoding error: {0}")]
    DecodingError(String),
}

// SMT PROOF ERROR
// =================================================================================================

/// Errors that can occur when validating SMT proofs.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SmtProofError {
    /// The length of the provided Merkle path is not [`SMT_DEPTH`].
    #[error("merkle path length {0} does not match SMT depth {SMT_DEPTH}")]
    InvalidMerklePathLength(usize),

    /// The key maps to a different leaf index than the proof's leaf.
    #[error("key maps to a different leaf index than the proof")]
    InvalidKeyForProof,

    /// The value does not match the value in the leaf for the given key.
    #[error("value mismatch: expected {expected}, got {actual}")]
    ValueMismatch { expected: Word, actual: Word },

    /// The computed root does not match the expected root.
    #[error("expected merkle root {expected_root} found {actual_root}")]
    ConflictingRoots { expected_root: Word, actual_root: Word },

    /// The key-value pair exists in the tree.
    #[error("key-value pair exists in the tree: key {key}, value {value}")]
    ValuePresent { key: Word, value: Word },
}
