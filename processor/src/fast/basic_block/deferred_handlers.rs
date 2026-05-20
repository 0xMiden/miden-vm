//! System-event glue for the deferred-DAG subsystem.
//!
//! Reads operand-stack inputs for `DeferredRegister`, `DeferredEvaluate` and
//! `DeferredRegisterChunk` (see [`miden_core::events::sys_events`]) and dispatches into the
//! installed [`miden_core::deferred::PrecompileRegistry`].

use alloc::vec::Vec;

use miden_core::{
    Felt, Word, ZERO,
    deferred::{Digest, Node, NodeType, Payload, PrecompileError, Tag},
};

use super::SystemEventError;
use crate::{MemoryError, advice::AdviceError, fast::FastProcessor};

// STACK LAYOUT — `DeferredRegister`
// ================================================================================================
// `[event_id, PAYLOAD_LO, PAYLOAD_HI, TAG, ...]` — Poseidon2 sponge layout so MASM can feed the
// 12 felts directly into one `hperm` to compute the node's digest.

/// Stack offset of the payload's low half — the topmost word below the event ID.
const DEFERRED_PAYLOAD_LO_OFFSET: usize = 1;
/// Stack offset of the payload's high half (next word below the low half).
const DEFERRED_PAYLOAD_HI_OFFSET: usize = 5;
/// Stack offset of the deferred tag — the third word below the event ID.
const DEFERRED_TAG_OFFSET: usize = 9;

// STACK LAYOUT — `DeferredEvaluate`
// ================================================================================================
// `[event_id, NODE_DIGEST, ...]` — the node must already be registered in `DeferredState`; the
// handler looks it up by digest and reduces it via the precompile registry.

/// Stack offset of the node digest (4-felt word at positions 1..5).
const DEFERRED_NODE_DIGEST_OFFSET: usize = 1;

// STACK LAYOUT — `DeferredRegisterChunk`
// ================================================================================================
// `[event_id, TAG, ptr, ...]` — no payload (`n` is decoded out of the tag, so the chunk's bulk
// content size is fully determined by the precompile's tag layout).

/// Stack offset of the chunk tag (4-felt word at positions 1..5).
const CHUNK_TAG_OFFSET: usize = 1;
/// Stack offset of the chunk pointer (single felt at position 5).
const CHUNK_PTR_OFFSET: usize = 5;

/// Reads `(tag, payload)` from the operand stack at the `DeferredRegister` / `DeferredEvaluate`
/// layout.
fn read_tag_and_payload(processor: &FastProcessor) -> (Tag, Payload) {
    let lo = processor.stack_get_word(DEFERRED_PAYLOAD_LO_OFFSET);
    let hi = processor.stack_get_word(DEFERRED_PAYLOAD_HI_OFFSET);
    let tag_word = processor.stack_get_word(DEFERRED_TAG_OFFSET);
    let tag = Tag::from_word([tag_word[0], tag_word[1], tag_word[2], tag_word[3]]);
    let payload = Payload::new([lo[0], lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3]]);
    (tag, payload)
}

/// Builds an expression-bodied `Node` for the given `(tag, payload)`. Returns
/// `PrecompileError::InvalidNode` if the tag decodes to a chunk body — chunks must be registered
/// via `adv.register_deferred_chunk`, not `adv.register_deferred`.
fn build_standard_node(
    node_type: NodeType,
    tag: Tag,
    payload: Payload,
) -> Result<Node, PrecompileError> {
    match node_type {
        // Both Value and Binary live in `Payload::Expression` at the in-memory level — the
        // 8-felt payload is the same; the precompile decides whether the bytes encode raw data
        // (Value) or two child digests (Binary) when it reduces.
        NodeType::Value | NodeType::Binary => Ok(Node::expression(tag, payload)),
        NodeType::Chunks(_) => Err(PrecompileError::InvalidNode),
    }
}

/// Handles `SystemEvent::DeferredRegister`. Reads `(tag, payload)` off the operand stack, asks
/// the precompile registry to decode the tag, constructs the matching `Node`, and registers it.
///
/// Pushes the registered node's digest onto the advice stack so MASM can chain it into
/// downstream nodes (e.g. as a child digest of a Binary op) or into `log_precompile` without
/// having to recompute the digest in-circuit.
pub(super) fn handle_deferred_register(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let (tag, payload) = read_tag_and_payload(processor);
    let (state, precompiles) = processor.deferred_view_mut();
    let node_type = precompiles.decode(tag)?;
    let node = build_standard_node(node_type, tag, payload)?;
    let digest = state.register(precompiles, node)?;
    processor.advice.push_stack_word(&digest)?;
    Ok(())
}

/// Handles `SystemEvent::DeferredEvaluate`. Reads a node digest off the operand stack, looks
/// the node up in `DeferredState`, reduces it via the precompile registry, and pushes the
/// canonical onto the advice stack.
///
/// The referenced node must already be interned — programs typically call
/// `adv.register_deferred` / `adv.register_deferred_chunk` first to register the node and
/// obtain its digest from the advice stack.
///
/// Advice-stack contract, driven by the canonical's shape:
/// - **Predicate result** (canonical is the TRUE node, detected via [`Node::is_true_node`]):
///   nothing is pushed. A failed predicate surfaces as `PrecompileError::AssertionFailed` before
///   this point.
/// - **Expression canonicals**: the 12 felts of the canonical `(payload, tag)` are pushed in
///   `[PAYLOAD_LO, PAYLOAD_HI, TAG]` order (top-down). MASM recovers each word with `adv_pushw`.
/// - **Chunk canonicals** (e.g. self-evaluating chunk leaves like a 16-felt digest): all `n` chunks
///   are pushed in `[chunk[0]_LO, chunk[0]_HI, chunk[1]_LO, ..., TAG]` order (top-down) so MASM
///   recovers each word in natural sequence.
pub(super) fn handle_deferred_evaluate(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let digest_word = processor.stack_get_word(DEFERRED_NODE_DIGEST_OFFSET);
    let digest: Digest =
        Word::new([digest_word[0], digest_word[1], digest_word[2], digest_word[3]]);

    let (state, precompiles) = processor.deferred_view_mut();
    let node = state.get(&digest)?.clone();
    let canonical = state.evaluate(precompiles, node)?;

    // Predicates reduce to the TRUE node — by contract the advice stack is untouched.
    if canonical.is_true_node() {
        return Ok(());
    }

    // Push canonical body: TAG deepest, then payload words so the natural-order word is on top.
    processor.advice.push_stack_word(&Word::new(canonical.tag.as_word()))?;
    match &canonical.payload {
        Payload::Expression(f) => {
            let hi = Word::new([f[4], f[5], f[6], f[7]]);
            let lo = Word::new([f[0], f[1], f[2], f[3]]);
            processor.advice.push_stack_word(&hi)?;
            processor.advice.push_stack_word(&lo)?;
        },
        Payload::Chunk(chunks) => {
            // Push chunks deepest-last so chunk[0]_LO ends up on top of the advice stack.
            for chunk in chunks.iter().rev() {
                let hi = Word::new([chunk[4], chunk[5], chunk[6], chunk[7]]);
                let lo = Word::new([chunk[0], chunk[1], chunk[2], chunk[3]]);
                processor.advice.push_stack_word(&hi)?;
                processor.advice.push_stack_word(&lo)?;
            }
        },
    }
    Ok(())
}

/// Handles `SystemEvent::DeferredRegisterChunk`. Reads `(tag, ptr)` off the operand stack, asks
/// the precompile registry to decode `n` from the tag, reads `8n` felts from memory at `ptr`,
/// and registers a chunk node carrying that bulk data.
///
/// Pushes the registered node's digest onto the advice stack so MASM can chain it into
/// downstream nodes or into `log_precompile` without having to recompute the chunk-linear-hash
/// digest in-circuit (which would be `n` Poseidon2 permutations).
///
/// Validation:
/// - `ptr` must fit in `u32`.
/// - `ptr` must be word-aligned (`ptr % 4 == 0`).
/// - `ptr + 8n` must not overflow `u32`.
/// - `8n` must not exceed the processor's `max_adv_map_value_size` (re-used as the bulk-data cap
///   for now; sized for the same "do not let a single event explode memory" concern).
pub(super) fn handle_deferred_register_chunk(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let tag_word = processor.stack_get_word(CHUNK_TAG_OFFSET);
    let tag = Tag::from_word([tag_word[0], tag_word[1], tag_word[2], tag_word[3]]);
    let ptr = processor.stack_get(CHUNK_PTR_OFFSET).as_canonical_u64();

    // Decode `n` from the tag before any memory reads — the precompile is the source of truth
    // for chunk length, and reading otherwise would let a malformed tag waste work.
    let n = {
        let (_state, precompiles) = processor.deferred_view_mut();
        match precompiles.decode(tag)? {
            NodeType::Chunks(n) => n,
            NodeType::Value | NodeType::Binary => {
                return Err(PrecompileError::InvalidNode.into());
            },
        }
    };

    // Bounds + alignment validation.
    if ptr > u32::MAX as u64 {
        return Err(MemoryError::AddressOutOfBounds { addr: ptr }.into());
    }
    if !ptr.is_multiple_of(4) {
        return Err(
            MemoryError::UnalignedWordAccess { addr: ptr as u32, ctx: processor.ctx }.into()
        );
    }
    let total = 8u64 * n as u64;
    let end = ptr + total;
    if end > u32::MAX as u64 {
        return Err(MemoryError::AddressOutOfBounds { addr: end }.into());
    }
    let max_value_size = processor.options.max_adv_map_value_size();
    if total as usize > max_value_size {
        return Err(AdviceError::AdvMapValueSizeExceeded {
            size: total as usize,
            max: max_value_size,
        }
        .into());
    }

    // Read `n` rate-sized chunks from memory.
    let ctx = processor.ctx;
    let mut chunks: Vec<[Felt; 8]> = Vec::with_capacity(n as usize);
    for k in 0..n {
        let base = ptr as u32 + k * 8;
        let mut chunk = [ZERO; 8];
        for (i, felt) in chunk.iter_mut().enumerate() {
            *felt = processor.memory().read_element_impl(ctx, base + i as u32).unwrap_or(ZERO);
        }
        chunks.push(chunk);
    }

    let (state, precompiles) = processor.deferred_view_mut();
    let digest = state.register(precompiles, Node::chunk(tag, chunks))?;
    processor.advice.push_stack_word(&digest)?;
    Ok(())
}
