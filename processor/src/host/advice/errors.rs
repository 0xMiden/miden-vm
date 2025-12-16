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
    #[error("value for key {} not present in the advice map", .key.to_hex())]
    MapKeyNotFound { key: Word },
    #[error("advice stack read failed")]
    StackReadFailed,
    #[error(
        "provided merkle tree {depth} is out of bounds and cannot be represented as an unsigned 8-bit integer"
    )]
    InvalidMerkleTreeDepth { depth: Felt },
    #[error("provided node index {index} is out of bounds for a merkle tree node at depth {depth}")]
    InvalidMerkleTreeNodeIndex { depth: Felt, index: Felt },
    #[error("failed to lookup value in Merkle store")]
    MerkleStoreLookupFailed(#[source] MerkleError),
    /// Note: This error currently never occurs, since `MerkleStore::merge_roots()` never fails.
    #[error("Merkle store backend merge failed")]
    MerkleStoreMergeFailed(#[source] MerkleError),
    #[error("Merkle store backend update failed")]
    MerkleStoreUpdateFailed(#[source] MerkleError),
}
