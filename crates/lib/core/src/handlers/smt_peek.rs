//! SMT_PEEK system event handler for the Miden VM.
//!
//! This handler implements the SMT_PEEK operation that pushes the value associated
//! with a specified key in a Sparse Merkle Tree defined by the specified root onto
//! the advice stack.

use alloc::{format, string::String, vec::Vec};

use miden_core::{
    WORD_SIZE, Word,
    crypto::merkle::{EmptySubtreeRoots, NodeIndex, SMT_DEPTH, Smt},
    events::EventName,
};
use miden_event_handler::{AdviceRecorder, EventContext, EventError, InvocationKind};

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
/// This is a fast, untrusted lookup. The handler reads a node and leaf preimage from the advice
/// provider, but it does not verify a Merkle path from `ROOT` to that node. It also does not prove
/// that the decoded value is committed under `ROOT`.
///
/// Caller code must verify the returned value before relying on it. The expected pattern is to call
/// `smt::peek`, then later call `smt::set`, and compare the old value returned by `smt::set` with
/// the value returned by `smt::peek`. That lets a program avoid doing the same Merkle path
/// verification twice.
///
/// Inputs:
///   Operand stack: [KEY, ROOT, ...]
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
pub fn handle_smt_peek(
    context: EventContext,
    advice: &mut AdviceRecorder<'_>,
) -> Result<(), EventError> {
    context.kind().require(InvocationKind::Event)?;
    let empty_leaf = EmptySubtreeRoots::entry(SMT_DEPTH, SMT_DEPTH);
    // fetch the arguments from the operand stack
    // Event payload: [KEY, ROOT, ...] where KEY and ROOT are structural words.
    let key = context.stack_word(0);
    let root = context.stack_word(4);

    // get the node from the SMT for the specified key; this node can be either a leaf node,
    // or a root of an empty subtree at the returned depth
    // K[3] is used as the leaf index (most significant in BE ordering)
    let index = NodeIndex::new(SMT_DEPTH, key[3].as_canonical_u64())
        .expect("every u64 position is valid at depth 64");
    let node =
        context
            .merkle_node(root, index)
            .map_err(|err| SmtPeekError::AdviceProviderError {
                message: format!("Failed to get tree node: {err}"),
            })?;

    let value = if node == *empty_leaf {
        Smt::EMPTY_VALUE
    } else {
        get_smt_leaf_preimage(context, node)?
            .into_iter()
            .find_map(|(candidate, value)| (candidate == key).then_some(value))
            .unwrap_or(Smt::EMPTY_VALUE)
    };
    // MASM consumes the structural word using adv_loadw or adv_pushw.
    advice.prepend_stack(value.as_elements().iter().copied());
    Ok(())
}

// HELPER FUNCTIONS
// ================================================================================================

/// Retrieves the preimage of an SMT leaf node from the advice provider.
fn get_smt_leaf_preimage(
    context: EventContext,
    node: Word,
) -> Result<Vec<(Word, Word)>, SmtPeekError> {
    let kv_pairs = context
        .advice_map()
        .get(&node)
        .map(AsRef::as_ref)
        .ok_or(SmtPeekError::SmtNodeNotFound { node })?;

    if kv_pairs.len() % (WORD_SIZE * 2) != 0 {
        return Err(SmtPeekError::InvalidSmtNodePreimage { node, preimage_len: kv_pairs.len() });
    }

    #[allow(clippy::chunks_exact_to_as_chunks)]
    Ok(kv_pairs
        .as_chunks::<{ WORD_SIZE * 2 }>()
        .0
        .iter()
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
