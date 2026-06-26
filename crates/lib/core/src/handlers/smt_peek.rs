//! SMT_PEEK system event handler for the Miden VM.
//!
//! This handler implements the SMT_PEEK operation that pushes the value associated
//! with a specified key in a Sparse Merkle Tree defined by the specified root onto
//! the advice stack.

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use miden_core::{
    Felt, WORD_SIZE, Word,
    crypto::merkle::{EmptySubtreeRoots, SMT_DEPTH, Smt},
    events::EventName,
};
use miden_crypto::merkle::smt::{LeafIndex, SmtLeaf};
use miden_processor::{ProcessorState, advice::AdviceMutation, event::EventError};

/// Event name for the smt_peek operation.
pub const SMT_PEEK_EVENT_NAME: EventName =
    EventName::new("miden::core::collections::smt::smt_peek");

/// SMT_PEEK system event handler.
///
/// Pushes onto the advice stack the value associated with the specified key in a Sparse
/// Merkle Tree defined by the specified root.
///
/// If no value was previously associated with the specified key, [ZERO; 4] is pushed onto
/// the advice stack.
///
/// Inputs:
///   Operand stack: [event_id, KEY, ROOT, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [VALUE, ...]
///
/// # Errors
/// Returns an error if the provided Merkle root doesn't exist on the advice provider.
///
/// # Panics
/// Will panic as unimplemented if the target depth is `64`.
pub fn handle_smt_peek(process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
    let empty_leaf = EmptySubtreeRoots::entry(SMT_DEPTH, SMT_DEPTH);
    // fetch the arguments from the operand stack
    // Stack at emit: [event_id, KEY, ROOT, ...] where KEY and ROOT are structural words.
    let key = process.get_stack_word(1);
    let root = process.get_stack_word(5);

    // get the node from the SMT for the specified key; this node can be either a leaf node,
    // or a root of an empty subtree at the returned depth
    // K[3] is used as the leaf index (most significant in BE ordering)
    let depth = Felt::new_unchecked(SMT_DEPTH as u64);
    let leaf_index = LeafIndex::<SMT_DEPTH>::from(key);
    let node = process.advice_provider().get_tree_node(root, depth, key[3]).map_err(|err| {
        SmtPeekError::AdviceProviderError {
            message: format!("Failed to get tree node: {err}"),
        }
    })?;

    let path = process.advice_provider().get_merkle_path(root, depth, key[3]).map_err(|err| {
        SmtPeekError::AdviceProviderError {
            message: format!("Failed to get Merkle path: {err}"),
        }
    })?;
    path.verify(leaf_index.position(), node, &root).map_err(|err| {
        SmtPeekError::SmtNodeNotAuthenticated {
            root,
            node,
            leaf_index,
            message: err.to_string(),
        }
    })?;

    if node == *empty_leaf {
        // if the node is a root of an empty subtree, then there is no value associated with
        // the specified key
        let mutation = AdviceMutation::extend_stack(Smt::EMPTY_VALUE);
        Ok(vec![mutation])
    } else {
        let leaf_preimage = get_smt_leaf_preimage(process, node, leaf_index)?;

        for (key_in_leaf, value_in_leaf) in leaf_preimage {
            if key == key_in_leaf {
                // Found key - push value associated with key, and return
                let mutation = AdviceMutation::extend_stack(value_in_leaf);
                return Ok(vec![mutation]);
            }
        }

        // if we can't find any key in the leaf that matches `key`, it means no value is
        // associated with `key`
        let mutation = AdviceMutation::extend_stack(Smt::EMPTY_VALUE);
        Ok(vec![mutation])
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Retrieves the preimage of an SMT leaf node from the advice provider.
fn get_smt_leaf_preimage(
    process: &ProcessorState,
    node: Word,
    leaf_index: LeafIndex<SMT_DEPTH>,
) -> Result<Vec<(Word, Word)>, SmtPeekError> {
    let kv_pairs = process
        .advice_provider()
        .get_mapped_values(&node)
        .ok_or(SmtPeekError::SmtNodeNotFound { node })?;

    if kv_pairs.len() % (WORD_SIZE * 2) != 0 {
        return Err(SmtPeekError::InvalidSmtNodePreimage { node, preimage_len: kv_pairs.len() });
    }

    let leaf = SmtLeaf::try_from_elements(kv_pairs, leaf_index)
        .map_err(|err| SmtPeekError::InvalidSmtLeafPreimage { node, message: err.to_string() })?;

    // This repeats the check added to `SmtLeaf::try_from_elements` in
    // https://github.com/0xMiden/crypto/pull/1076. Remove it after miden-vm depends on a
    // miden-crypto release that includes that fix.
    if leaf.index() != leaf_index {
        return Err(SmtPeekError::SmtLeafIndexMismatch {
            node,
            expected_leaf_index: leaf_index,
            actual_leaf_index: leaf.index(),
        });
    }

    let leaf_hash = leaf.hash();
    if leaf_hash != node {
        return Err(SmtPeekError::SmtNodePreimageMismatch { node, computed: leaf_hash });
    }

    Ok(leaf.into_entries())
}

// ERROR TYPES
// ================================================================================================

/// Error types that can occur during SMT_PEEK operations.
#[derive(Debug, thiserror::Error)]
pub enum SmtPeekError {
    /// Advice provider operation failed.
    #[error("advice provider error: {message}")]
    AdviceProviderError { message: String },

    /// SMT node not found in the advice provider.
    #[error("SMT node not found: {node:?}")]
    SmtNodeNotFound { node: Word },

    /// SMT node does not authenticate to the requested root.
    #[error(
        "SMT node {node:?} at leaf index {leaf_index} is not authenticated by root {root:?}: {message}"
    )]
    SmtNodeNotAuthenticated {
        root: Word,
        node: Word,
        leaf_index: LeafIndex<SMT_DEPTH>,
        message: String,
    },

    /// SMT node preimage has invalid length.
    #[error("invalid SMT node preimage length for node {node:?}: got {preimage_len}, expected multiple of {}", WORD_SIZE * 2)]
    InvalidSmtNodePreimage { node: Word, preimage_len: usize },

    /// SMT leaf preimage could not be decoded.
    #[error("invalid SMT leaf preimage for node {node:?}: {message}")]
    InvalidSmtLeafPreimage { node: Word, message: String },

    /// SMT leaf preimage belongs to a different leaf index.
    #[error(
        "SMT leaf preimage index mismatch for node {node:?}: expected {expected_leaf_index}, got {actual_leaf_index}"
    )]
    SmtLeafIndexMismatch {
        node: Word,
        expected_leaf_index: LeafIndex<SMT_DEPTH>,
        actual_leaf_index: LeafIndex<SMT_DEPTH>,
    },

    /// SMT leaf preimage does not hash to the authenticated node.
    #[error("SMT leaf preimage hash mismatch for node {node:?}: computed {computed:?}")]
    SmtNodePreimageMismatch { node: Word, computed: Word },
}
