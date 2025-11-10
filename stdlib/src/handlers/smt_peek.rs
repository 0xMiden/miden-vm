//! SMT_PEEK system event handler for the Miden VM.
//!
//! This handler implements the SMT_PEEK operation that pushes the value associated
//! with a specified key in a Sparse Merkle Tree defined by the specified root onto
//! the advice stack.

use alloc::{format, string::String, vec, vec::Vec};

use miden_core::{
    EventName, Felt, WORD_SIZE, Word,
    crypto::merkle::{EmptySubtreeRoots, SMT_DEPTH, Smt},
};
use miden_processor::{AdviceMutation, EventError, ProcessState};

/// Event name for the smt_peek operation.
pub const SMT_PEEK_EVENT_NAME: EventName = EventName::new("stdlib::collections::smt::smt_peek");

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
pub fn handle_smt_peek(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
    let empty_leaf = EmptySubtreeRoots::entry(SMT_DEPTH, SMT_DEPTH);
    // fetch the arguments from the operand stack
    let key = process.get_stack_word_be(1);
    let root = process.get_stack_word_be(5);

    // get the node from the SMT for the specified key; this node can be either a leaf node,
    // or a root of an empty subtree at the returned depth
    let node = process
        .advice_provider()
        .get_tree_node(root, Felt::new(SMT_DEPTH as u64), key[3])
        .map_err(|err| SmtPeekError::AdviceProviderError {
            message: format!("Failed to get tree node: {}", err),
        })?;

    if node == *empty_leaf {
        // if the node is a root of an empty subtree, then there is no value associated with
        // the specified key
        let mutation = AdviceMutation::extend_stack(Smt::EMPTY_VALUE.into_iter().rev());
        Ok(vec![mutation])
    } else {
        let leaf_preimage = get_smt_leaf_preimage(process, node)?;

        for (key_in_leaf, value_in_leaf) in leaf_preimage {
            if key == key_in_leaf {
                // Found key - push value associated with key, and return
                let mutation = AdviceMutation::extend_stack(value_in_leaf.into_iter().rev());
                return Ok(vec![mutation]);
            }
        }

        // if we can't find any key in the leaf that matches `key`, it means no value is
        // associated with `key`
        let mutation = AdviceMutation::extend_stack(Smt::EMPTY_VALUE.into_iter().rev());
        Ok(vec![mutation])
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Retrieves the preimage of an SMT leaf node from the advice provider.
fn get_smt_leaf_preimage(
    process: &ProcessState,
    node: Word,
) -> Result<Vec<(Word, Word)>, SmtPeekError> {
    let kv_pairs = process
        .advice_provider()
        .get_mapped_values(&node)
        .ok_or(SmtPeekError::SmtNodeNotFound { node })?;

    if kv_pairs.len() % (WORD_SIZE * 2) != 0 {
        return Err(SmtPeekError::InvalidSmtNodePreimage { node, preimage_len: kv_pairs.len() });
    }

    Ok(kv_pairs
        .chunks_exact(WORD_SIZE * 2)
        .map(|kv_chunk| {
            let key = [kv_chunk[0], kv_chunk[1], kv_chunk[2], kv_chunk[3]];
            let value = [kv_chunk[4], kv_chunk[5], kv_chunk[6], kv_chunk[7]];

            (key.into(), value.into())
        })
        .collect())
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

    /// SMT node preimage has invalid length.
    #[error("invalid SMT node preimage length for node {node:?}: got {preimage_len}, expected multiple of {}", WORD_SIZE * 2)]
    InvalidSmtNodePreimage { node: Word, preimage_len: usize },
}
