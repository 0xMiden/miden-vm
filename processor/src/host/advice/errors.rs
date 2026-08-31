// Allow unused assignments - required by miette::Diagnostic derive macro
#![allow(unused_assignments)]

use alloc::vec::Vec;

use miden_core::deferred::PrecompileError;
use miden_utils_diagnostics::{Diagnostic, miette};

use crate::{Felt, Word, crypto::merkle::MerkleError};

#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum AdviceError {
    #[error(
        "value for key {} already present in the advice map: previous values were '{prev_values:?}', attempted replacement values were '{new_values:?}'",
        key.to_hex()
    )]
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
        "advice provider size budget exceeded: adding {added} bytes to the current {current} bytes would exceed the maximum of {max} bytes"
    )]
    SizeBudgetExceeded { current: usize, added: usize, max: usize },
    #[error("failed to initialize deferred state with the built-in precompile registry")]
    DeferredStateInitializationFailed(#[source] PrecompileError),
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
