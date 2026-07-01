//! Processor glue for deferred-DAG system events.
//!
//! These handlers keep the processor agnostic to precompile semantics: they read VM inputs,
//! update deferred state, and delegate validation/evaluation to the installed registry.

use alloc::vec::Vec;

use miden_core::{
    Word, ZERO,
    deferred::{DataChunk, DeferredError, Digest, Node, NodeType, PrecompileError, Tag},
};

use super::SystemEventError;
use crate::{AdviceProvider, MemoryError, fast::FastProcessor};

// STACK LAYOUT — `DeferredRegister`
// ================================================================================================
// `[event_id, PAYLOAD_LO, PAYLOAD_HI, TAG, ...]` — Poseidon2 sponge layout so MASM can feed the
// 12 felts directly into one `hperm` to compute the node's digest. `TAG` is one word (4 felts).
// The eight payload felts are one 8-felt data chunk, `lhs || rhs` child digests for a join, or
// one `lhs || rhs` pair for a pair-list node. Exact `Tag::CHUNKS` (`[2, 0, 0, 0]`) is
// framework-owned opaque data; malformed id-2 tags are rejected.

/// Stack offset of the payload's low half below the event id.
const DEFERRED_PAYLOAD_LO_OFFSET: usize = 1;
/// Stack offset of the payload's high half.
const DEFERRED_PAYLOAD_HI_OFFSET: usize = 5;
/// Stack offset of the deferred tag word.
const DEFERRED_TAG_OFFSET: usize = 9;

// STACK LAYOUT — `DeferredEvaluate*`
// ================================================================================================
// `[event_id, NODE_DIGEST, ...]` — the node must already be registered in `DeferredState`; the
// handlers evaluate it to a canonical digest and push the requested canonical node component(s)
// onto the advice stack. Payload chunks are arranged for `adv_pushw adv_pushw` ergonomics: the two
// pushes leave the chunk's LOW word on top of the operand stack, with HIGH beneath it. The full
// event emits the tag first in advice-pop order, so `adv_pushw adv_pushw adv_pushw` leaves
// `[PAYLOAD_LO, PAYLOAD_HI, TAG, ...]` for a single 8-felt payload.

/// Stack offset of the registered node digest.
const DEFERRED_NODE_DIGEST_OFFSET: usize = 1;

// STACK LAYOUT — `DeferredRegisterData`
// ================================================================================================
// `[event_id, TAG, ptr, n_chunks, ...]` — no stack-resident payload. `TAG` is one word
// (4 felts), and `n_chunks` is the number of 8-felt payload chunks to read from memory at `ptr`.
// Data and pair-list nodes use that explicit chunk count; exact `Tag::CHUNKS` (`[2, 0, 0, 0]`)
// is framework-owned opaque data. Join nodes require `n_chunks == 1`.

/// Stack offset of the data tag word.
const DATA_TAG_OFFSET: usize = 1;
/// Stack offset of the memory pointer for the node payload.
const DATA_PTR_OFFSET: usize = 5;
/// Stack offset of the number of 8-felt payload chunks to read from memory.
const DATA_N_CHUNKS_OFFSET: usize = 6;

/// Number of field elements occupied by a deferred node tag.
const TAG_NUM_ELEMENTS: usize = 4;
/// Number of field elements in one rate-sized deferred payload block.
const PAYLOAD_BLOCK_NUM_ELEMENTS: usize = 8;

/// Returns the storage footprint of `tag || n` 8-felt payload blocks.
fn payload_node_num_elements(n_blocks: u32) -> usize {
    (n_blocks as usize)
        .checked_mul(PAYLOAD_BLOCK_NUM_ELEMENTS)
        .and_then(|payload_elements| payload_elements.checked_add(TAG_NUM_ELEMENTS))
        .unwrap_or(usize::MAX)
}

/// Stack-resident registration of an operand-stack deferred node.
///
/// The tag decodes to one [`DataChunk`] (8 field elements), a join payload containing two 4-felt
/// child digests, or a one-pair pair-list payload containing `lhs || rhs`. Exact [`Tag::CHUNKS`]
/// (`[2, 0, 0, 0]`) forms a framework-owned opaque data node; other id-2 tags are malformed and
/// reject during tag decode. TRUE is not accepted. Tags that semantically require more than one
/// data chunk or pair still form a
/// one-chunk/one-pair node here; precompile-specific evaluation rejects the semantic length
/// mismatch. Registration is delegated to [`miden_core::deferred::DeferredState::register`], so
/// semantic failures, including false predicates, surface immediately. This event does not return
/// the node digest; any proof-relevant caller must compute that digest in-circuit from the same tag
/// and payload.
pub(super) fn handle_deferred_register(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let lo = processor.stack_get_word(DEFERRED_PAYLOAD_LO_OFFSET);
    let hi = processor.stack_get_word(DEFERRED_PAYLOAD_HI_OFFSET);
    let tag = Tag::from_word(processor.stack_get_word(DEFERRED_TAG_OFFSET).into());
    let block: DataChunk = [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3]];

    // Decode the tag before shaping the payload so the host commits the structurally correct node.
    let node = match processor.deferred_state().decode(tag)? {
        NodeType::Data if tag == Tag::CHUNKS => {
            Node::chunks(Vec::from([block])).map_err(PrecompileError::from)?
        },
        NodeType::Data => Node::value(tag, block).map_err(PrecompileError::from)?,
        NodeType::Join => {
            let lhs = Digest::new([block[0], block[1], block[2], block[3]]);
            let rhs = Digest::new([block[4], block[5], block[6], block[7]]);
            Node::join(tag, lhs, rhs).map_err(PrecompileError::from)?
        },
        NodeType::PairList => {
            let lhs = Digest::new([block[0], block[1], block[2], block[3]]);
            let rhs = Digest::new([block[4], block[5], block[6], block[7]]);
            Node::try_pair_list(tag, vec![(lhs, rhs)]).map_err(PrecompileError::from)?
        },
        NodeType::True => return Err(PrecompileError::InvalidNode.into()),
    };
    processor.deferred_state_mut().register(node)?;
    Ok(())
}

/// Handles deferred-node evaluation and returns the canonical tag and payload as advice.
///
/// The digest must already be registered in
/// [`miden_core::deferred::DeferredState`]. The handler evaluates it with
/// [`miden_core::deferred::DeferredState::evaluate_digest`] and pushes the canonical node's tag and
/// payload. The tag is first in advice-pop order, followed by the payload in the same word ordering
/// used by [`handle_deferred_evaluate_payload`]. TRUE emits only `Tag::TRUE`.
pub(super) fn handle_deferred_evaluate(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let canonical_node = evaluate_canonical_node(processor)?;
    push_evaluated_payload(&mut processor.advice, &canonical_node)?;
    push_evaluated_tag(&mut processor.advice, &canonical_node)?;
    Ok(())
}

/// Handles deferred-node evaluation and returns only the canonical tag as advice.
pub(super) fn handle_deferred_evaluate_tag(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let canonical_node = evaluate_canonical_node(processor)?;
    push_evaluated_tag(&mut processor.advice, &canonical_node)?;
    Ok(())
}

/// Handles deferred-node evaluation and returns only the canonical payload as advice.
///
/// This preserves the original payload-only behavior for payload-only consumers. Data payloads emit
/// two advice words per 8-felt chunk. Because both the advice stack and operand stack
/// are LIFO, each chunk is placed on advice as HIGH then LOW (and chunks are processed in reverse
/// before front-pushing) so `adv_pushw adv_pushw` leaves `[LOW, HIGH, ...]` on the operand stack
/// for that chunk. Join payloads use the same convention for their two words, leaving
/// `[lhs, rhs, ...]` after two `adv_pushw`s. TRUE emits no advice. These advice values are
/// intentionally unbound: proof-relevant callers must bind
/// them to circuit-visible data before relying on them.
pub(super) fn handle_deferred_evaluate_payload(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let canonical_node = evaluate_canonical_node(processor)?;
    push_evaluated_payload(&mut processor.advice, &canonical_node)?;
    Ok(())
}

/// Evaluates the digest on the operand stack and returns the registered canonical node.
fn evaluate_canonical_node(processor: &mut FastProcessor) -> Result<Node, SystemEventError> {
    let digest: Digest = processor.stack_get_word(DEFERRED_NODE_DIGEST_OFFSET);
    let canonical_digest = processor.deferred_state_mut().evaluate_digest(digest)?;
    processor
        .deferred_state()
        .get_node(&canonical_digest)
        .cloned()
        .ok_or(PrecompileError::MissingNode.into())
}

/// Pushes `node`'s canonical tag onto the advice stack.
fn push_evaluated_tag(advice: &mut AdviceProvider, node: &Node) -> Result<(), SystemEventError> {
    let tag = Word::from(node.tag().as_word());
    advice.push_stack_word(&tag)?;
    Ok(())
}

/// Pushes `node`'s canonical payload onto the advice stack in `adv_pushw`-ergonomic order.
fn push_evaluated_payload(
    advice: &mut AdviceProvider,
    node: &Node,
) -> Result<(), SystemEventError> {
    // `AdviceProvider::push_stack_word` front-pushes, while `adv_pushw` pushes each consumed word
    // onto the operand stack. Push payload blocks from the back, preserving LOW/HIGH order within
    // each block, so repeated `adv_pushw`s leave later blocks above earlier blocks.
    for chunk in node.payload().as_chunks().iter().rev() {
        let [lo0, lo1, lo2, lo3, hi0, hi1, hi2, hi3] = *chunk;
        advice.push_stack_word(&Word::new([lo0, lo1, lo2, lo3]))?;
        advice.push_stack_word(&Word::new([hi0, hi1, hi2, hi3]))?;
    }
    Ok(())
}

/// Handles memory-backed registration of a deferred node.
///
/// The tag is the source of truth for the framework payload shape, while the operand-stack
/// `n_chunks` value is the source of truth for the memory range. Data nodes read exactly
/// `n_chunks` [`DataChunk`] values (8 field elements each); exact [`Tag::CHUNKS`]
/// (`[2, 0, 0, 0]`) registers those chunks as framework-owned opaque data, while other data tags
/// remain precompile-owned. Pair-list nodes interpret chunks as `lhs || rhs` pairs. Join nodes
/// require `n_chunks == 1` and interpret the one chunk as `lhs || rhs`. TRUE is not accepted. After
/// checking word alignment, address bounds, and a cheap
/// state-size precheck, registration and semantic evaluation are delegated to
/// [`miden_core::deferred::DeferredState::register`], so registration failures surface during this
/// event. This event does not return the node digest; any proof-relevant caller must compute that
/// digest in-circuit from the same tag and memory range using the digest rule for the decoded
/// payload shape.
pub(super) fn handle_deferred_register_data(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let tag = Tag::from_word(processor.stack_get_word(DATA_TAG_OFFSET).into());
    let ptr = processor.stack_get(DATA_PTR_OFFSET).as_canonical_u64();
    let n_chunks_felt = processor.stack_get(DATA_N_CHUNKS_OFFSET).as_canonical_u64();
    let n = u32::try_from(n_chunks_felt).map_err(|_| PrecompileError::InvalidNode)?;
    if n == 0 {
        return Err(PrecompileError::InvalidNode.into());
    }

    // Decode the tag before any memory reads. The precompile is the source of truth for payload
    // shape, but data/pair-list lengths are semantic and checked during registration/evaluation.
    let node_type = processor.deferred_state().decode(tag)?;
    match node_type {
        NodeType::Data | NodeType::PairList => {},
        NodeType::Join if n == 1 => {},
        NodeType::Join | NodeType::True => {
            return Err(PrecompileError::InvalidNode.into());
        },
    }

    // Reject nodes that can never fit in the configured deferred-state budget before
    // reading memory. Remaining-budget accounting still belongs to `DeferredState::register`,
    // because only inserting the node into `nodes` tells us whether this registration is an
    // idempotent duplicate (which must remain free).
    let num_elements = payload_node_num_elements(n);
    let max_deferred_elements = processor.options.max_deferred_elements();
    if num_elements > max_deferred_elements {
        return Err(PrecompileError::from(DeferredError::DeferredStateTooLarge {
            num_elements,
            max: max_deferred_elements,
        })
        .into());
    }

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
    // Read `n` rate-sized payload blocks from memory.
    let ctx = processor.ctx;
    let mut chunks: Vec<DataChunk> = Vec::with_capacity(n as usize);
    for k in 0..n {
        let base = ptr as u32 + k * 8;
        let mut chunk = [ZERO; 8];
        for (i, felt) in chunk.iter_mut().enumerate() {
            *felt = processor.memory().read_element_impl(ctx, base + i as u32).unwrap_or(ZERO);
        }
        chunks.push(chunk);
    }

    let node = match node_type {
        NodeType::Data if tag == Tag::CHUNKS => {
            Node::chunks(chunks).map_err(PrecompileError::from)?
        },
        NodeType::Data => Node::try_data(tag, chunks).map_err(PrecompileError::from)?,
        NodeType::Join => {
            let block = chunks.into_iter().next().ok_or(PrecompileError::InvalidNode)?;
            let lhs = Digest::new([block[0], block[1], block[2], block[3]]);
            let rhs = Digest::new([block[4], block[5], block[6], block[7]]);
            Node::join(tag, lhs, rhs).map_err(PrecompileError::from)?
        },
        NodeType::PairList => {
            Node::try_pair_list_chunks(tag, chunks).map_err(PrecompileError::from)?
        },
        NodeType::True => unreachable!("TRUE was rejected before memory reads"),
    };
    processor.deferred_state_mut().register(node)?;
    Ok(())
}
