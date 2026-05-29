//! Processor glue for deferred-DAG system events.
//!
//! These handlers keep the processor agnostic to precompile semantics: they read VM inputs,
//! update deferred state, and delegate validation/reduction to the installed registry.

use alloc::vec::Vec;

use miden_core::{
    Felt, ZERO,
    deferred::{Digest, Node, NodeType, Payload, PrecompileError, Tag},
};

use super::SystemEventError;
use crate::{MemoryError, advice::AdviceError, fast::FastProcessor};

fn check_deferred_budget(num_elements: usize, max: usize) -> Result<(), SystemEventError> {
    if num_elements > max {
        return Err(SystemEventError::DeferredStateTooLarge { num_elements, max });
    }
    Ok(())
}

// STACK LAYOUT — `DeferredRegister`
// ================================================================================================
// `[event_id, PAYLOAD_LO, PAYLOAD_HI, TAG, ...]` — Poseidon2 sponge layout so MASM can feed the
// 12 felts directly into one `hperm` to compute the node's digest.

/// Stack offset of the payload's low half below the event id.
const DEFERRED_PAYLOAD_LO_OFFSET: usize = 1;
/// Stack offset of the payload's high half.
const DEFERRED_PAYLOAD_HI_OFFSET: usize = 5;
/// Stack offset of the deferred tag word.
const DEFERRED_TAG_OFFSET: usize = 9;

// STACK LAYOUT — `DeferredEvaluate`
// ================================================================================================
// `[event_id, NODE_DIGEST, ...]` — the node must already be registered in `DeferredState`; the
// handler looks it up by digest, reduces it via the precompile registry, interns the canonical,
// and pushes the canonical's `tag || payload` felts onto the advice stack.

/// Stack offset of the committed node digest.
const DEFERRED_NODE_DIGEST_OFFSET: usize = 1;

// STACK LAYOUT — `DeferredRegisterChunk`
// ================================================================================================
// `[event_id, TAG, ptr, ...]` — no payload (`n` is decoded out of the tag, so the chunk's bulk
// content size is fully determined by the precompile's tag layout).

/// Stack offset of the chunk tag word.
const CHUNK_TAG_OFFSET: usize = 1;
/// Stack offset of the memory pointer for chunk data.
const CHUNK_PTR_OFFSET: usize = 5;

/// Reads the expression node described by the deferred-register stack layout.
fn read_tag_and_payload(processor: &FastProcessor) -> (Tag, Payload) {
    let lo = processor.stack_get_word(DEFERRED_PAYLOAD_LO_OFFSET);
    let hi = processor.stack_get_word(DEFERRED_PAYLOAD_HI_OFFSET);
    let tag = Tag::from_word(processor.stack_get_word(DEFERRED_TAG_OFFSET).into());
    let payload = Payload::new([lo[0], lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3]]);
    (tag, payload)
}

/// Handles expression-node registration for deferred computation.
///
/// The event only commits the node; predicate truth is checked later by evaluation or transcript
/// rehydration. The MASM wrapper binds the digest in-circuit, so the host cannot supply an
/// unconstrained commitment through advice.
pub(super) fn handle_deferred_register(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let (tag, payload) = read_tag_and_payload(processor);
    let max_deferred_elements = processor.options.max_deferred_elements();
    let (state, precompiles) = processor.deferred_view_mut();
    state.register(precompiles, Node::expression(tag, payload))?;
    check_deferred_budget(state.num_elements(), max_deferred_elements)
}

/// Handles deferred-node evaluation and returns the canonical node as advice.
///
/// The digest must already be committed in deferred state; memo hits are allowed only after that
/// membership check. The advice output is `tag || payload` in felt-index order and is intentionally
/// unbound: callers that depend on it must re-hash it in-circuit and log a predicate that
/// rehydration will verify.
pub(super) fn handle_deferred_evaluate(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let digest: Digest = processor.stack_get_word(DEFERRED_NODE_DIGEST_OFFSET);

    let max_deferred_elements = processor.options.max_deferred_elements();
    let (state, precompiles) = processor.deferred_view_mut();
    let canonical = state.evaluate_digest(precompiles, digest)?;
    check_deferred_budget(state.num_elements(), max_deferred_elements)?;

    // Serialize the canonical as `tag || payload` in natural order.
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

    // Push felts in reverse so the front of the advice stack is `value[0]` (TAG): successive
    // `adv_pushw` reads then yield TAG, PAYLOAD_LO, PAYLOAD_HI, … in natural order.
    for &felt in value.iter().rev() {
        processor.advice.push_stack(felt)?;
    }
    Ok(())
}

/// Handles chunk-node registration for deferred computation.
///
/// The tag, not the stack, is the source of truth for chunk count. The same memory range is hashed
/// by the MASM wrapper in-circuit, binding the commitment to memory contents while this handler
/// enforces alignment, bounds, and bulk-data limits.
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
            // `Chunks` is `NonZeroU32`, so a 0-chunk tag has already been rejected by `decode`.
            NodeType::Chunks(n) => n.get(),
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
    let end = ptr
        .checked_add(total)
        .ok_or(MemoryError::AddressOutOfBounds { addr: u64::MAX })?;
    if end > u32::MAX as u64 {
        return Err(MemoryError::AddressOutOfBounds { addr: end }.into());
    }
    let max_deferred_elements = processor.options.max_deferred_elements();
    let chunk_elements = (n as usize)
        .checked_mul(8)
        .and_then(|payload_elements| payload_elements.checked_add(4))
        .unwrap_or(usize::MAX);
    let projected = processor
        .deferred_state()
        .num_elements()
        .checked_add(chunk_elements)
        .unwrap_or(usize::MAX);
    check_deferred_budget(projected, max_deferred_elements)?;

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
    state.register(precompiles, Node::chunk(tag, chunks))?;
    check_deferred_budget(state.num_elements(), max_deferred_elements)
}
