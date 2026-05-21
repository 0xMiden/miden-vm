//! System-event glue for the deferred-DAG subsystem.
//!
//! Reads operand-stack inputs for `DeferredRegister`, `DeferredEvaluate` and
//! `DeferredRegisterChunk` (see [`miden_core::events::sys_events`]) and dispatches into the
//! installed [`miden_core::deferred::PrecompileRegistry`].

use alloc::vec::Vec;

use miden_core::{
    Felt, ZERO,
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
// handler looks it up by digest, reduces it via the precompile registry, records the canonical in
// the advice map keyed by `CANONICAL_DIGEST`, and pushes `CANONICAL_DIGEST` to advice.

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

/// Reads `(tag, payload)` from the operand stack at the `DeferredRegister` layout.
fn read_tag_and_payload(processor: &FastProcessor) -> (Tag, Payload) {
    let lo = processor.stack_get_word(DEFERRED_PAYLOAD_LO_OFFSET);
    let hi = processor.stack_get_word(DEFERRED_PAYLOAD_HI_OFFSET);
    let tag = Tag::from_word(processor.stack_get_word(DEFERRED_TAG_OFFSET).into());
    let payload = Payload::new([lo[0], lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3]]);
    (tag, payload)
}

/// Handles `SystemEvent::DeferredRegister`. Reads `(tag, payload)` off the operand stack and
/// registers an expression node; `register` validates the tag via the precompile registry and
/// rejects chunk-bodied tags (those go through `adv.register_deferred_chunk`).
///
/// Pushes the registered node's digest onto the advice stack so MASM can chain it into
/// downstream nodes (e.g. as a child digest of a Join op) or into a transcript-logging step
/// without having to recompute the digest in-circuit.
pub(super) fn handle_deferred_register(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let (tag, payload) = read_tag_and_payload(processor);
    let (state, precompiles) = processor.deferred_view_mut();
    let digest = state.register(precompiles, Node::expression(tag, payload))?;
    processor.advice.push_stack_word(&digest)?;
    Ok(())
}

/// Handles `SystemEvent::DeferredEvaluate`. Reads a node digest off the operand stack, looks
/// the node up in `DeferredState`, reduces it via the precompile registry, records the canonical
/// in the advice map keyed by the canonical's own digest, then pushes that digest to the advice
/// stack.
///
/// The referenced digest must resolve in deferred state (registered node or memoized prior
/// evaluation input). Programs typically call `adv.register_deferred` /
/// `adv.register_deferred_chunk` first and obtain the digest from the advice stack.
///
/// Advice contract — uniform across every node shape:
/// - **Advice stack**: pushes `CANONICAL_DIGEST` (the reduced node's own digest).
/// - **Advice map key**: `CANONICAL_DIGEST`.
/// - **Advice map value**: the canonical serialized as `tag || payload`, in natural (felt-index)
///   order:
///   - **Expression canonicals**: 4 tag felts followed by the 8 payload felts (12 total).
///   - **Chunk canonicals**: 4 tag felts followed by every chunk's 8 felts (`8n + 4` total).
/// - **Predicates** are not special-cased: the canonical is the TRUE node, which serializes to the
///   12 felts of `Node::TRUE` like any other expression. A failed predicate has already surfaced as
///   `PrecompileError::AssertionFailed` before this point, so a recorded entry means the predicate
///   verified.
pub(super) fn handle_deferred_evaluate(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let digest: Digest = processor.stack_get_word(DEFERRED_NODE_DIGEST_OFFSET);

    let (state, precompiles) = processor.deferred_view_mut();
    let canonical = state.evaluate_digest(precompiles, digest)?;

    let canonical_digest = canonical.digest();

    // Serialize the canonical as `tag || payload` and record it in the advice map under the
    // canonical's own digest. `insert_into_map` is idempotent for an identical re-evaluation and
    // rejects a conflicting prior entry.
    let mut value: Vec<Felt> = Vec::new();
    value.extend_from_slice(&canonical.tag.as_word());
    match &canonical.payload {
        Payload::Expression(f) => value.extend_from_slice(f),
        Payload::Chunk(chunks) => {
            for chunk in chunks.iter() {
                value.extend_from_slice(chunk);
            }
        },
    }
    processor.advice.insert_into_map(canonical_digest, value)?;
    processor.advice.push_stack_word(&canonical_digest)?;
    Ok(())
}

/// Handles `SystemEvent::DeferredRegisterChunk`. Reads `(tag, ptr)` off the operand stack, asks
/// the precompile registry to decode `n` from the tag, reads `8n` felts from memory at `ptr`,
/// and registers a chunk node carrying that bulk data.
///
/// Pushes the registered node's digest onto the advice stack so MASM can chain it into
/// downstream nodes or into a transcript-logging step without having to recompute the
/// chunk-linear-hash digest in-circuit (which would be `n` Poseidon2 permutations).
///
/// Validation:
/// - `ptr` must fit in `u32`.
/// - `ptr` must be word-aligned (`ptr % 4 == 0`).
/// - `ptr + 8n` must not overflow `u32`.
/// - `8n` must not exceed the processor's `max_adv_map_value_size` (re-used as the bulk-data cap,
///   sized for the same "do not let a single event explode memory" concern).
pub(super) fn handle_deferred_register_chunk(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let tag = Tag::from_word(processor.stack_get_word(CHUNK_TAG_OFFSET).into());
    let ptr = processor.stack_get(CHUNK_PTR_OFFSET).as_canonical_u64();

    // Decode `n` from the tag before any memory reads — the precompile is the source of truth
    // for chunk length, and reading otherwise would let a malformed tag waste work.
    let n = {
        let (_state, precompiles) = processor.deferred_view_mut();
        match precompiles.decode(tag)? {
            NodeType::Chunks(n) => n,
            NodeType::Value | NodeType::Join => {
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
