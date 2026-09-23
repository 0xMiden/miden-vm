//! Processor glue for deferred-DAG system events.
//!
//! These handlers keep the processor agnostic to precompile semantics: they read VM inputs,
//! update deferred state, and delegate validation/evaluation to the installed registry.

use alloc::vec::Vec;

use miden_core::{
    Word, ZERO,
    deferred::{
        DEFERRED_CHUNKS_DOMAIN, DataChunk, DeferredError, Digest, EidosFrame,
        MAX_DEFERRED_ELEMENTS, Node, NodeType, PrecompileError,
    },
};

use super::SystemEventError;
use crate::{AdviceProvider, MemoryError, fast::FastProcessor};

// STACK LAYOUT — `DeferredRegister`
// ================================================================================================
// `[event_id, CV, PAYLOAD_LO, PAYLOAD_HI, ...]`; `CV` is the framed initial Eidos chaining word
// used by the VM to hash the same payload. The handler recovers the unique semantic frame from it.
// The eight payload felts form one compression block. The payload is one
// 8-felt data chunk, `lhs || rhs` child digests for a precompile-owned join, or one `lhs || rhs`
// pair for a pair-list node. Framework-owned AND nodes are not accepted by this generic event.

/// Stack offset of the initial Eidos chaining word.
const DEFERRED_CV_OFFSET: usize = 1;
/// Stack offset of the payload's low half below the event id.
const DEFERRED_PAYLOAD_LO_OFFSET: usize = 5;
/// Stack offset of the payload's high half.
const DEFERRED_PAYLOAD_HI_OFFSET: usize = 9;

// STACK LAYOUT — `DeferredEvaluate*`
// ================================================================================================
// `[event_id, NODE_DIGEST, ...]` — the node must already be registered in `DeferredState`; the
// handlers evaluate it to a canonical digest and push the requested canonical node component(s)
// onto the advice stack. Payload chunks are arranged for `adv_pushw adv_pushw` ergonomics: the two
// pushes leave the chunk's LOW word on top of the operand stack, with HIGH beneath it. The full
// event emits the frame first in advice-pop order, so `adv_pushw adv_pushw adv_pushw` leaves
// `[PAYLOAD_LO, PAYLOAD_HI, FRAME, ...]` for a single 8-felt payload. All `DeferredEvaluate*`
// outputs are unbound host hints; proof-relevant callers must relate them with VM instructions to
// values established independently of that advice.

/// Stack offset of the registered node digest.
const DEFERRED_NODE_DIGEST_OFFSET: usize = 1;

// STACK LAYOUT — `DeferredRegisterData`
// ================================================================================================
// `[event_id, n_chunks, CV, ptr, ...]` — no stack-resident payload. `CV` is the framed initial
// Eidos chaining word and `n_chunks` is the number of 8-felt payload chunks to read from memory at
// `ptr`. Data and pair-list nodes use that explicit chunk count. Precompile-owned join nodes
// require `n_chunks == 1`.

/// Stack offset of the data node's initial Eidos chaining word.
const DATA_CV_OFFSET: usize = 2;
/// Stack offset of the memory pointer for the node payload.
const DATA_PTR_OFFSET: usize = 6;
/// Stack offset of the number of 8-felt payload chunks to read from memory.
const DATA_N_CHUNKS_OFFSET: usize = 1;

/// Number of field elements occupied by a deferred node frame.
const FRAME_NUM_ELEMENTS: usize = 4;
/// Number of field elements in one deferred payload block.
const PAYLOAD_BLOCK_NUM_ELEMENTS: usize = 8;

/// Returns the storage footprint of `frame || n` 8-felt payload blocks.
fn payload_node_num_elements(n_blocks: u32) -> usize {
    (n_blocks as usize)
        .checked_mul(PAYLOAD_BLOCK_NUM_ELEMENTS)
        .and_then(|payload_elements| payload_elements.checked_add(FRAME_NUM_ELEMENTS))
        .unwrap_or(usize::MAX)
}

/// Stack-resident registration of an operand-stack deferred node.
///
/// The frame decodes to one [`DataChunk`] (8 field elements), a precompile-owned join payload
/// containing two 4-felt child digests, or a one-pair pair-list payload containing `lhs || rhs`.
/// Framework-owned AND and TRUE nodes are not accepted. Frames that semantically require more than
/// one data chunk or pair still form a one-chunk or one-pair node here; precompile-specific
/// evaluation rejects the semantic length mismatch.
/// Registration is delegated to [`miden_core::deferred::DeferredState::register`], so
/// semantic failures, including false predicates, surface immediately. The stack arguments are
/// part of the VM execution trace, but the event does not constrain the host-side registration.
/// This event does not return the node digest; any proof-relevant caller must compute it with VM
/// instructions from the exact same initial chaining word and payload.
pub(super) fn handle_deferred_register(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let lo = processor.stack_get_word(DEFERRED_PAYLOAD_LO_OFFSET);
    let hi = processor.stack_get_word(DEFERRED_PAYLOAD_HI_OFFSET);
    let frame = decode_frame_from_cv(processor.stack_get_word(DEFERRED_CV_OFFSET))?;
    let block: DataChunk = [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3]];

    // Decode the frame before shaping the payload so the host commits the structurally correct
    // node.
    let node = match processor.deferred_state().decode(frame)? {
        NodeType::Data if frame.domain().as_felt() == DEFERRED_CHUNKS_DOMAIN => {
            let node = Node::chunks(Vec::from([block])).map_err(PrecompileError::from)?;
            if node.frame() != Some(frame) {
                return Err(PrecompileError::InvalidNode.into());
            }
            node
        },
        NodeType::Data => Node::value(frame, block).map_err(PrecompileError::from)?,
        NodeType::Join => {
            let lhs = Digest::new([block[0], block[1], block[2], block[3]]);
            let rhs = Digest::new([block[4], block[5], block[6], block[7]]);
            Node::join(frame, lhs, rhs).map_err(PrecompileError::from)?
        },
        NodeType::PairList => {
            let lhs = Digest::new([block[0], block[1], block[2], block[3]]);
            let rhs = Digest::new([block[4], block[5], block[6], block[7]]);
            Node::try_pair_list(frame, vec![(lhs, rhs)]).map_err(PrecompileError::from)?
        },
        NodeType::True => return Err(PrecompileError::InvalidNode.into()),
    };
    processor.deferred_state_mut().register(node)?;
    Ok(())
}

/// Handles deferred-node evaluation and returns the canonical frame and payload as advice.
///
/// The digest must already be registered in
/// [`miden_core::deferred::DeferredState`]. The handler evaluates it with
/// [`miden_core::deferred::DeferredState::evaluate_digest`] and pushes the canonical node's frame
/// and payload. The frame is first in advice-pop order, followed by the payload in the same word
/// ordering used by [`handle_deferred_evaluate_payload`]. TRUE emits one zero word.
pub(super) fn handle_deferred_evaluate(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let canonical_node = evaluate_canonical_node(processor)?;
    push_evaluated_payload(&mut processor.advice, &canonical_node)?;
    push_evaluated_frame(&mut processor.advice, &canonical_node)?;
    Ok(())
}

/// Handles deferred-node evaluation and returns only the canonical frame as advice.
pub(super) fn handle_deferred_evaluate_frame(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let canonical_node = evaluate_canonical_node(processor)?;
    push_evaluated_frame(&mut processor.advice, &canonical_node)?;
    Ok(())
}

/// Handles deferred-node evaluation and returns only the canonical payload as advice.
///
/// This preserves the original payload-only behavior for payload-only consumers. Data payloads emit
/// two advice words per 8-felt chunk. Because both the advice stack and operand stack
/// are LIFO, each chunk is placed on advice as HIGH then LOW (and chunks are processed in reverse
/// before front-pushing) so `adv_pushw adv_pushw` leaves `[LOW, HIGH, ...]` on the operand stack
/// for that chunk. Join payloads use the same convention for their two words, leaving
/// `[lhs, rhs, ...]` after two `adv_pushw`s. TRUE emits no advice.
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

/// Pushes `node`'s canonical frame onto the advice stack.
fn push_evaluated_frame(advice: &mut AdviceProvider, node: &Node) -> Result<(), SystemEventError> {
    let frame = node.frame().map(EidosFrame::as_word).unwrap_or_default();
    advice.push_stack_word(&frame)?;
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
/// The frame is the source of truth for the framework payload shape, while the operand-stack
/// `n_chunks` value is the source of truth for the memory range. Data nodes read exactly
/// `n_chunks` [`DataChunk`] values (8 field elements each). Pair-list nodes interpret chunks as
/// `lhs || rhs` pairs. Precompile-owned join nodes require `n_chunks == 1` and interpret the one
/// chunk as `lhs || rhs`. Framework-owned AND and TRUE nodes are not accepted. After checking word
/// alignment, address bounds, and a cheap state-size precheck, registration and semantic evaluation
/// are delegated to [`miden_core::deferred::DeferredState::register`], so registration failures
/// surface during this event.
///
/// The stack-supplied CV, pointer, and chunk count are visible in the VM execution trace, but the
/// direct host memory reads below do not add AIR memory constraints. Thus, the event alone does not
/// tie the registered chunks to VM memory. Any proof-relevant caller must compute the node digest
/// with VM instructions from the same CV and ordered chunk sequence; the shared `register_mem`
/// MASM wrapper does so by hashing the exact same range.
pub(super) fn handle_deferred_register_data(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let frame = decode_frame_from_cv(processor.stack_get_word(DATA_CV_OFFSET))?;
    let ptr = processor.stack_get(DATA_PTR_OFFSET).as_canonical_u64();
    let n_chunks_felt = processor.stack_get(DATA_N_CHUNKS_OFFSET).as_canonical_u64();
    let n = u32::try_from(n_chunks_felt).map_err(|_| PrecompileError::InvalidNode)?;
    if n == 0 {
        return Err(PrecompileError::InvalidNode.into());
    }

    // Decode the frame before any memory reads. The precompile is the source of truth for payload
    // shape, but data/pair-list lengths are semantic and checked during registration/evaluation.
    let node_type = processor.deferred_state().decode(frame)?;
    match node_type {
        NodeType::Data | NodeType::PairList => {},
        NodeType::Join if n == 1 => {},
        NodeType::Join | NodeType::True => {
            return Err(PrecompileError::InvalidNode.into());
        },
    }

    // Reject nodes that can never fit in the fixed deferred-state budget before
    // reading memory. Remaining-budget accounting still belongs to `DeferredState::register`,
    // because only inserting the node into `nodes` tells us whether this registration is an
    // idempotent duplicate (which must remain free).
    let num_elements = payload_node_num_elements(n);
    if num_elements > MAX_DEFERRED_ELEMENTS {
        return Err(PrecompileError::from(DeferredError::DeferredStateTooLarge {
            num_elements,
            max: MAX_DEFERRED_ELEMENTS,
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
    // Read `n` eight-Felt payload blocks from memory.
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
        NodeType::Data if frame.domain().as_felt() == DEFERRED_CHUNKS_DOMAIN => {
            let node = Node::chunks(chunks).map_err(PrecompileError::from)?;
            if node.frame() != Some(frame) {
                return Err(PrecompileError::InvalidNode.into());
            }
            node
        },
        NodeType::Data => Node::try_data(frame, chunks).map_err(PrecompileError::from)?,
        NodeType::Join => {
            let block = chunks.into_iter().next().ok_or(PrecompileError::InvalidNode)?;
            let lhs = Digest::new([block[0], block[1], block[2], block[3]]);
            let rhs = Digest::new([block[4], block[5], block[6], block[7]]);
            Node::join(frame, lhs, rhs).map_err(PrecompileError::from)?
        },
        NodeType::PairList => {
            Node::try_pair_list_chunks(frame, chunks).map_err(PrecompileError::from)?
        },
        NodeType::True => unreachable!("TRUE was rejected before memory reads"),
    };
    processor.deferred_state_mut().register(node)?;
    Ok(())
}

fn decode_frame_from_cv(cv: Word) -> Result<EidosFrame, SystemEventError> {
    EidosFrame::from_initial_chaining_word(cv).ok_or_else(|| PrecompileError::InvalidNode.into())
}

#[cfg(test)]
mod tests {
    use miden_core::{
        Felt,
        deferred::{DEFERRED_AND_FRAME, EidosFrame, deferred_chunks_frame},
        program::{StackInputs, domain::DomainTag},
    };
    use miden_precompiles::Keccak256Precompile;

    use super::*;

    #[test]
    fn register_rejects_framework_and_frames() {
        let malformed_and = EidosFrame::new(DEFERRED_AND_FRAME.domain(), [1, 0, 0]);

        for (name, frame, exact) in [
            ("exact AND frame", DEFERRED_AND_FRAME, true),
            ("parameterized AND-domain frame", malformed_and, false),
        ] {
            let mut stack = vec![ZERO];
            stack.extend(frame.initial_chaining_word());
            stack.extend([ZERO; 8]);
            let mut processor =
                FastProcessor::new(StackInputs::new(&stack).expect("valid test stack"));

            let error = match handle_deferred_register(&mut processor) {
                Ok(()) => panic!("{name} should be rejected"),
                Err(error) => error,
            };
            let SystemEventError::Deferred(error) = error else {
                panic!("{name} returned the wrong error class: {error}");
            };
            if exact {
                assert!(
                    matches!(error.root(), PrecompileError::Other(DeferredError::InvalidFrame)),
                    "{name} returned {error}",
                );
            } else {
                assert!(
                    matches!(error.root(), PrecompileError::InvalidNode),
                    "{name} returned {error}",
                );
            }
        }
    }

    #[test]
    fn register_data_rejects_framework_and_frames() {
        let malformed_and = EidosFrame::new(DEFERRED_AND_FRAME.domain(), [1, 0, 0]);

        for (name, frame, exact) in [
            ("exact AND frame", DEFERRED_AND_FRAME, true),
            ("parameterized AND-domain frame", malformed_and, false),
        ] {
            let mut stack = vec![ZERO, Felt::ONE];
            stack.extend(frame.initial_chaining_word());
            stack.push(ZERO);
            let mut processor =
                FastProcessor::new(StackInputs::new(&stack).expect("valid test stack"));

            let error = match handle_deferred_register_data(&mut processor) {
                Ok(()) => panic!("{name} should be rejected"),
                Err(error) => error,
            };
            let SystemEventError::Deferred(error) = error else {
                panic!("{name} returned the wrong error class: {error}");
            };
            if exact {
                assert!(
                    matches!(error.root(), PrecompileError::Other(DeferredError::InvalidFrame)),
                    "{name} returned {error}",
                );
            } else {
                assert!(
                    matches!(error.root(), PrecompileError::InvalidNode),
                    "{name} returned {error}",
                );
            }
        }
    }

    #[test]
    fn register_data_rejects_invalid_or_inconsistent_frames() {
        let mut malformed_cv = deferred_chunks_frame(1).initial_chaining_word().into_elements();
        malformed_cv[0] += Felt::new_unchecked(1 << 32);

        let unregistered_domain =
            DomainTag::from_u32(0x10ff_fe01).expect("test tag uses an allocated namespace");
        let unregistered_frame = EidosFrame::new(unregistered_domain, [0; 3]);

        let cases = [
            ("malformed fixed CV lane", 1, Word::new(malformed_cv)),
            ("unregistered domain", 1, unregistered_frame.initial_chaining_word()),
            (
                "CHUNKS frame/count mismatch",
                2,
                deferred_chunks_frame(1).initial_chaining_word(),
            ),
            (
                "fixed one-block domain with two blocks",
                2,
                Keccak256Precompile::assert_frame(0).initial_chaining_word(),
            ),
        ];

        for (name, n_chunks, cv) in cases {
            let mut stack = vec![ZERO, Felt::from_u32(n_chunks)];
            stack.extend(cv);
            stack.push(ZERO);
            let mut processor =
                FastProcessor::new(StackInputs::new(&stack).expect("valid test stack"));

            let error = match handle_deferred_register_data(&mut processor) {
                Ok(()) => panic!("{name} should be rejected"),
                Err(error) => error,
            };
            let SystemEventError::Deferred(error) = error else {
                panic!("{name} returned the wrong error class: {error}");
            };
            assert!(
                matches!(error.root(), PrecompileError::InvalidNode),
                "{name} returned {error}",
            );
        }
    }
}
