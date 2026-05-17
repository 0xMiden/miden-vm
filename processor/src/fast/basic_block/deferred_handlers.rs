//! System-event glue for the deferred-DAG subsystem.
//!
//! Reads operand-stack inputs for `DeferredRegister`, `DeferredEvaluate` and
//! `DeferredRegisterChunk` (see [`miden_core::events::sys_events`]) and dispatches into the
//! installed [`miden_core::deferred::Schema`].

use alloc::vec::Vec;

use miden_core::{
    Felt, Word, ZERO,
    deferred::{Node, NodePayload, NodeType, Payload, SchemaError, TRUE_TAG, Tag},
};

use super::SystemEventError;
use crate::{MemoryError, advice::AdviceError, fast::FastProcessor};

// STACK LAYOUT — `DeferredRegister` and `DeferredEvaluate`
// ================================================================================================
// `[event_id, PAYLOAD_LO, PAYLOAD_HI, TAG, ...]` — Poseidon2 sponge layout so MASM can feed the
// 12 felts directly into one `hperm` to compute the node's digest.

/// Stack offset of the payload's low half — the topmost word below the event ID.
const DEFERRED_PAYLOAD_LO_OFFSET: usize = 1;
/// Stack offset of the payload's high half (next word below the low half).
const DEFERRED_PAYLOAD_HI_OFFSET: usize = 5;
/// Stack offset of the deferred tag — the third word below the event ID.
const DEFERRED_TAG_OFFSET: usize = 9;

// STACK LAYOUT — `DeferredRegisterChunk`
// ================================================================================================
// `[event_id, TAG, ptr, ...]` — no payload (`n` is decoded out of the tag, so the chunk's bulk
// content size is fully determined by the schema's tag layout).

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
    let tag: Tag = [tag_word[0], tag_word[1], tag_word[2], tag_word[3]];
    let payload = Payload::new([lo[0], lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3]]);
    (tag, payload)
}

/// Builds an expression-bodied `Node` for the given `(tag, payload)`. Returns
/// `SchemaError::InvalidNode` if the tag decodes to a chunk body — chunks must be registered via
/// `adv.register_deferred_chunk`, not `adv.register_deferred`.
fn build_standard_node(
    node_type: NodeType,
    tag: Tag,
    payload: Payload,
) -> Result<Node, SchemaError> {
    match node_type {
        // Both Value and Binary live in `NodePayload::Expression` at the in-memory level — the
        // 8-felt payload is the same; the schema decides whether the bytes encode raw data
        // (Value) or two child digests (Binary) when it reduces.
        NodeType::Value | NodeType::Binary => Ok(Node::expression(tag, payload)),
        NodeType::Chunks(_) => Err(SchemaError::InvalidNode),
    }
}

/// Handles `SystemEvent::DeferredRegister`. Reads `(tag, payload)` off the operand stack, asks the
/// schema to decode the tag, constructs the matching `Node`, and registers it.
pub(super) fn handle_deferred_register(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let (tag, payload) = read_tag_and_payload(processor);
    let (state, schema) = processor.deferred_view_mut();
    let info = schema.decode(tag)?;
    let node = build_standard_node(info.node_type, tag, payload)?;
    let _ = state.register(schema, node)?;
    Ok(())
}

/// Handles `SystemEvent::DeferredEvaluate`. Reads `(tag, payload)` off the operand stack and asks
/// the schema to reduce it.
///
/// Advice-stack contract, driven by `decode(tag).evaluates_to`:
/// - **Predicates** (`evaluates_to == TRUE_TAG`): canonical is the TRUE node — nothing is pushed.
///   A mismatch surfaces as `SchemaError::AssertionFailed`.
/// - **Producing tags** (everything else): the 12 felts of the canonical `(payload, tag)` are
///   pushed in `[PAYLOAD_LO, PAYLOAD_HI, TAG]` order (top-down), matching the operand-stack
///   input layout — MASM can recover each word with `adv_pushw`.
/// - **Chunk canonicals**: out of scope for v1; schemas canonicalise chunks to expression
///   digest-leaves inside their `reduce`, so this arm is unreachable in practice.
pub(super) fn handle_deferred_evaluate(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let (tag, payload) = read_tag_and_payload(processor);
    let (state, schema) = processor.deferred_view_mut();
    let info = schema.decode(tag)?;
    let node = build_standard_node(info.node_type, tag, payload)?;
    let canonical = state.evaluate(schema, node)?;

    // Predicates reduce to the TRUE node — by contract the advice stack is untouched.
    if info.evaluates_to == TRUE_TAG {
        return Ok(());
    }

    let payload = match &canonical.payload {
        NodePayload::Expression(p) => p,
        // Chunk-as-canonical: out of scope (schemas should canonicalise chunks to expression
        // digest-leaves inside their `reduce`).
        NodePayload::Chunk(_) => return Ok(()),
    };

    let payload_hi = Word::new([payload.0[4], payload.0[5], payload.0[6], payload.0[7]]);
    let payload_lo = Word::new([payload.0[0], payload.0[1], payload.0[2], payload.0[3]]);
    // Push deepest first so `payload_lo` ends up on top. `push_stack_word` reverses element
    // order so an `adv_pushw` on the MASM side recovers each word in structural order.
    processor.advice.push_stack_word(&Word::new(canonical.tag))?;
    processor.advice.push_stack_word(&payload_hi)?;
    processor.advice.push_stack_word(&payload_lo)?;
    Ok(())
}

/// Handles `SystemEvent::DeferredRegisterChunk`. Reads `(tag, ptr)` off the operand stack, asks
/// the schema to decode `n` from the tag, reads `8n` felts from memory at `ptr`, and registers a
/// chunk node carrying that bulk data.
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
    let tag: Tag = [tag_word[0], tag_word[1], tag_word[2], tag_word[3]];
    let ptr = processor.stack_get(CHUNK_PTR_OFFSET).as_canonical_u64();

    // Decode `n` from the tag before any memory reads — the schema is the source of truth for
    // chunk length, and reading otherwise would let a malformed tag waste work.
    let n = {
        let (_state, schema) = processor.deferred_view_mut();
        match schema.decode(tag)?.node_type {
            NodeType::Chunks(n) => n,
            NodeType::Value | NodeType::Binary => return Err(SchemaError::InvalidNode.into()),
        }
    };

    // Bounds + alignment validation.
    if ptr > u32::MAX as u64 {
        return Err(MemoryError::AddressOutOfBounds { addr: ptr }.into());
    }
    if !ptr.is_multiple_of(4) {
        return Err(MemoryError::UnalignedWordAccess {
            addr: ptr as u32,
            ctx: processor.ctx,
        }
        .into());
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

    let (state, schema) = processor.deferred_view_mut();
    let _ = state.register(schema, Node::chunk(tag, chunks))?;
    Ok(())
}
