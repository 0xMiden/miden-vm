// Allow unused assignments - required by miette::Diagnostic derive macro
#![allow(unused_assignments)]

use alloc::vec::Vec;

use miden_utils_diagnostics::{Diagnostic, miette};

use crate::{Felt, Word, crypto::MerkleError};

#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum AdviceError {
    #[error("value for key {} already present in the advice map", key.to_hex())]
    #[diagnostic(help(
        "previous values at key were '{prev_values:?}'. Operation would have replaced them with '{new_values:?}'",
    ))]
    MapKeyAlreadyPresent {
        key: Word,
        prev_values: Vec<Felt>,
        new_values: Vec<Felt>,
    },
    #[error("advice map lookup failed: key {} not found", .key.to_hex())]
    #[diagnostic(help(
        "ensure the key was previously inserted via adv.push_mapval or the advice provider was properly initialized"
    ))]
    MapKeyNotFound { key: Word },
    #[error("advice stack is empty")]
    #[diagnostic(help(
        "advice stack operations require values to be pushed first via adv_push or through the advice provider"
    ))]
    StackReadFailed,
    #[error(
        "provided merkle tree {depth} is out of bounds and cannot be represented as an unsigned 8-bit integer"
    )]
    InvalidMerkleTreeDepth { depth: Felt },
    #[error("merkle tree node index {index} exceeds maximum for depth {depth}")]
    #[diagnostic(help("at this depth, valid indices range from 0 to 2^depth - 1"))]
    InvalidMerkleTreeNodeIndex { depth: Felt, index: Felt },
    #[error("merkle store does not contain the requested node")]
    #[diagnostic(help(
        "ensure the merkle tree was fully initialized and all required paths were inserted into the advice provider"
    ))]
    MerkleStoreLookupFailed(#[source] MerkleError),
    /// Note: This error currently never occurs, since `MerkleStore::merge_roots()` never fails.
    #[error("Merkle store backend merge failed")]
    MerkleStoreMergeFailed(#[source] MerkleError),
    #[error("Merkle store backend update failed")]
    MerkleStoreUpdateFailed(#[source] MerkleError),
}
