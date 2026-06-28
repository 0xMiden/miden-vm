//! Processor glue for deferred-DAG system events.
//!
//! These handlers keep the processor agnostic to precompile semantics: they read VM inputs,
//! update deferred state, and delegate validation/evaluation to the installed registry.

use alloc::vec::Vec;

#[cfg(test)]
use miden_core::deferred::PrecompileRegistry;
use miden_core::{
    Word, ZERO,
    deferred::{
        DataChunk, DeferredError, Digest, Node, NodeType, PrecompileError, TRUE_DIGEST, Tag,
    },
};

use super::SystemEventError;
use crate::{AdviceProvider, MemoryError, fast::FastProcessor};

// STACK LAYOUT — `DeferredRegister`
// ================================================================================================
// `[event_id, PAYLOAD_LO, PAYLOAD_HI, TAG, ...]` — Poseidon2 sponge layout so MASM can feed the
// 12 felts directly into one `hperm` to compute the node's digest. `TAG` is one word (4 felts).
// The eight payload felts are either one 8-felt data chunk, or `lhs || rhs` child digests for a
// join.

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
// `[event_id, TAG, ptr, ...]` — no stack-resident payload. `TAG` is one word (4 felts), and its
// decoded shape determines how many felts are read from memory at `ptr`: 8 felts for a join, or
// 8 * n felts for a data payload with n chunks.

/// Stack offset of the data tag word.
const DATA_TAG_OFFSET: usize = 1;
/// Stack offset of the memory pointer for the node payload.
const DATA_PTR_OFFSET: usize = 5;

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
/// The tag decodes to either one [`DataChunk`] (8 field elements) or a join payload containing two
/// 4-felt child digests. TRUE and multi-chunk data tags are not accepted by this stack-resident
/// event because memory-backed payloads use `adv.register_deferred_data`. Registration is
/// delegated to [`miden_core::deferred::DeferredState::register`], so semantic failures, including
/// false predicates, surface immediately. If the node evaluates to TRUE, the event logs it into the
/// deferred root. This event does not return the node digest; any proof-relevant caller must
/// compute that digest in-circuit from the same tag and payload.
pub(super) fn handle_deferred_register(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let lo = processor.stack_get_word(DEFERRED_PAYLOAD_LO_OFFSET);
    let hi = processor.stack_get_word(DEFERRED_PAYLOAD_HI_OFFSET);
    let tag = Tag::from_word(processor.stack_get_word(DEFERRED_TAG_OFFSET).into());
    let block: DataChunk = [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3]];

    // Decode the tag before shaping the payload so the host commits the structurally correct node.
    let node = match processor.deferred_state().decode(tag)? {
        NodeType::Data(n) if n.get() == 1 => {
            Node::value(tag, block).map_err(PrecompileError::from)?
        },
        NodeType::Join => {
            let lhs = Digest::new([block[0], block[1], block[2], block[3]]);
            let rhs = Digest::new([block[4], block[5], block[6], block[7]]);
            Node::join(tag, lhs, rhs).map_err(PrecompileError::from)?
        },
        NodeType::Data(_) | NodeType::True => return Err(PrecompileError::InvalidNode.into()),
    };
    register_and_log_true_statement(processor, node)?;
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
/// for that chunk. Join payloads use the same convention for their two child digest words, leaving
/// `[lhs, rhs, ...]` after two `adv_pushw`s. TRUE emits no advice. These advice values are
/// intentionally unbound: proof-relevant callers must bind them to circuit-visible data before
/// relying on them.
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
/// The tag, not the stack, is the source of truth for the payload shape. For data tags, the tag
/// determines how many [`DataChunk`] values (8 field elements each) are read from memory at
/// `ptr`. For join tags, the handler reads exactly 8 field elements and interprets them as
/// `lhs || rhs`. TRUE is not accepted. After checking word alignment, address bounds, and a
/// cheap state-size precheck, registration and semantic evaluation are delegated to
/// [`miden_core::deferred::DeferredState::register`], so registration failures surface during this
/// event. If the node evaluates to TRUE, the event logs it into the deferred root. This event does
/// not return the node digest; any proof-relevant caller must compute that digest in-circuit from
/// the same tag and memory range using the digest rule for the decoded payload shape.
pub(super) fn handle_deferred_register_data(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let tag = Tag::from_word(processor.stack_get_word(DATA_TAG_OFFSET).into());
    let ptr = processor.stack_get(DATA_PTR_OFFSET).as_canonical_u64();

    // Decode the tag before any memory reads. The precompile is the source of truth for payload
    // shape and for rejecting oversized data tags. `Data` is `NonZeroU32`, so a 0-chunk tag has
    // already been rejected by the registry.
    let node_type = processor.deferred_state().decode(tag)?;
    let n = match node_type {
        NodeType::Data(n) => n.get(),
        NodeType::Join => 1,
        NodeType::True => return Err(PrecompileError::InvalidNode.into()),
    };

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
        NodeType::Data(_) => Node::try_data(tag, chunks).map_err(PrecompileError::from)?,
        NodeType::Join => {
            let block = chunks.into_iter().next().ok_or(PrecompileError::InvalidNode)?;
            let lhs = Digest::new([block[0], block[1], block[2], block[3]]);
            let rhs = Digest::new([block[4], block[5], block[6], block[7]]);
            Node::join(tag, lhs, rhs).map_err(PrecompileError::from)?
        },
        NodeType::True => unreachable!("TRUE was rejected before memory reads"),
    };
    register_and_log_true_statement(processor, node)?;
    Ok(())
}

fn register_and_log_true_statement(
    processor: &mut FastProcessor,
    node: Node,
) -> Result<Digest, SystemEventError> {
    let digest = processor.deferred_state_mut().register(node)?;
    if processor.deferred_state_mut().evaluate_digest(digest)? == TRUE_DIGEST {
        processor.deferred_state_mut().log_statement(digest)?;
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use miden_core::{Felt, deferred::TRUE_DIGEST, testing::precompile::Hash};

    use super::*;
    use crate::{ExecutionOptions, StackInputs, processor::Processor};

    /// A processor with the given deferred element budget.
    fn processor_with_budget(max_deferred_elements: usize) -> FastProcessor {
        let options = ExecutionOptions::default().with_max_deferred_elements(max_deferred_elements);
        FastProcessor::new_with_options(StackInputs::default(), Default::default(), options)
            .expect("default advice inputs fit the configured limits")
    }

    fn test_precompiles() -> PrecompileRegistry {
        PrecompileRegistry::default().with_precompile(Hash)
    }

    fn bind_precompiles(
        processor: FastProcessor,
        precompiles: PrecompileRegistry,
    ) -> FastProcessor {
        processor
            .with_deferred_precompiles(precompiles)
            .expect("test precompile initialization should fit the configured deferred budget")
    }

    fn write_data_stack(processor: &mut FastProcessor, tag: Tag, ptr: u32) {
        for (i, felt) in tag.as_word().iter().enumerate() {
            processor.stack_write(DATA_TAG_OFFSET + i, *felt);
        }
        processor.stack_write(DATA_PTR_OFFSET, Felt::from_u32(ptr));
    }

    fn write_data_memory(processor: &mut FastProcessor, ptr: u32, chunks: &[DataChunk]) {
        for (i, felt) in chunks.iter().flatten().enumerate() {
            processor
                .memory
                .write_element(processor.ctx, Felt::from_u32(ptr + i as u32), *felt)
                .unwrap();
        }
    }

    fn chunk(seed: u32) -> DataChunk {
        core::array::from_fn(|i| Felt::from_u32(seed + i as u32))
    }

    fn expected_evaluate_advice_stack(chunks: &[DataChunk]) -> Vec<Felt> {
        let mut expected = Vec::new();
        for chunk in chunks {
            expected.extend_from_slice(&chunk[4..8]);
            expected.extend_from_slice(&chunk[0..4]);
        }
        expected
    }

    fn expected_full_evaluate_advice_stack(node: &Node, chunks: &[DataChunk]) -> Vec<Felt> {
        let mut expected = Vec::new();
        expected.extend_from_slice(&node.tag().as_word());
        expected.extend_from_slice(&expected_evaluate_advice_stack(chunks));
        expected
    }

    fn write_evaluate_stack(processor: &mut FastProcessor, digest: Digest) {
        for (i, felt) in digest.as_elements().iter().enumerate() {
            processor.stack_write(DEFERRED_NODE_DIGEST_OFFSET + i, *felt);
        }
    }

    fn processor_with_registered_node(node: Node) -> FastProcessor {
        let mut processor = bind_precompiles(processor_with_budget(128), test_precompiles());
        processor.deferred_state_mut().register(node.clone()).unwrap();
        write_evaluate_stack(&mut processor, node.digest());
        processor
    }

    #[test]
    fn evaluated_payload_advice_omits_tag_and_orders_single_chunk_for_two_pushes() {
        let mut processor = processor_with_budget(64);
        let chunk = chunk(10);
        let node = Hash::digest_node(chunk);

        push_evaluated_payload(&mut processor.advice, &node).unwrap();

        assert_eq!(processor.advice_provider().stack(), expected_evaluate_advice_stack(&[chunk]));
        assert!(
            !processor.advice_provider().stack().starts_with(&node.tag().as_word()),
            "evaluate advice must not include the node tag"
        );
    }

    #[test]
    fn evaluated_payload_advice_preserves_multi_chunk_order_with_lifo_word_swaps() {
        let mut processor = processor_with_budget(128);
        let chunks = vec![chunk(1), chunk(20), chunk(40)];
        let node = Node::try_data(Hash::preimage_tag(Hash::BYTES_PER_CHUNK * 3), chunks.clone())
            .expect("test node is valid data");

        push_evaluated_payload(&mut processor.advice, &node).unwrap();

        assert_eq!(processor.advice_provider().stack(), expected_evaluate_advice_stack(&chunks));
    }

    #[test]
    fn payload_only_handler_preserves_existing_single_chunk_ordering() {
        let chunk = chunk(10);
        let node = Hash::digest_node(chunk);
        let mut processor = processor_with_registered_node(node);

        handle_deferred_evaluate_payload(&mut processor).unwrap();

        assert_eq!(processor.advice_provider().stack(), expected_evaluate_advice_stack(&[chunk]));
    }

    #[test]
    fn tag_only_handler_emits_canonical_tag() {
        let chunk = chunk(20);
        let node = Hash::digest_node(chunk);
        let expected = node.tag().as_word().to_vec();
        let mut processor = processor_with_registered_node(node);

        handle_deferred_evaluate_tag(&mut processor).unwrap();

        assert_eq!(processor.advice_provider().stack(), expected);
    }

    #[test]
    fn full_handler_emits_tag_then_payload_for_three_pushes() {
        let chunk = chunk(30);
        let node = Hash::digest_node(chunk);
        let expected = expected_full_evaluate_advice_stack(&node, &[chunk]);
        let mut processor = processor_with_registered_node(node);

        handle_deferred_evaluate(&mut processor).unwrap();

        assert_eq!(processor.advice_provider().stack(), expected);
    }

    #[test]
    fn true_evaluation_behavior_matches_variant_semantics() {
        let mut payload_processor = processor_with_budget(64);
        write_evaluate_stack(&mut payload_processor, TRUE_DIGEST);
        handle_deferred_evaluate_payload(&mut payload_processor).unwrap();
        assert_eq!(payload_processor.advice_provider().stack(), Vec::<Felt>::new());

        let expected_tag = Tag::TRUE.as_word().to_vec();

        let mut tag_processor = processor_with_budget(64);
        write_evaluate_stack(&mut tag_processor, TRUE_DIGEST);
        handle_deferred_evaluate_tag(&mut tag_processor).unwrap();
        assert_eq!(tag_processor.advice_provider().stack(), expected_tag);

        let mut full_processor = processor_with_budget(64);
        write_evaluate_stack(&mut full_processor, TRUE_DIGEST);
        handle_deferred_evaluate(&mut full_processor).unwrap();
        assert_eq!(full_processor.advice_provider().stack(), expected_tag);
    }

    #[test]
    fn duplicate_data_registration_at_limit_is_free() {
        let chunks = vec![core::array::from_fn(|i| Felt::from_u32(1 + i as u32))];
        let tag = Hash::preimage_tag(Hash::BYTES_PER_CHUNK);
        let ptr = 0;
        let exact_budget =
            payload_node_num_elements(chunks.len() as u32) + payload_node_num_elements(1);
        let precompiles = test_precompiles();
        let mut processor = bind_precompiles(processor_with_budget(exact_budget), precompiles);
        write_data_memory(&mut processor, ptr, &chunks);

        write_data_stack(&mut processor, tag, ptr);
        handle_deferred_register_data(&mut processor).unwrap();

        write_data_stack(&mut processor, tag, ptr);
        handle_deferred_register_data(&mut processor).unwrap();
    }

    /// Lay out `DeferredRegister`'s `[event_id, PAYLOAD_LO, PAYLOAD_HI, TAG, ...]` operand stack.
    fn write_register_stack(processor: &mut FastProcessor, tag: Tag, payload: [Felt; 8]) {
        for (i, felt) in payload.iter().enumerate() {
            processor.stack_write(DEFERRED_PAYLOAD_LO_OFFSET + i, *felt);
        }
        for (i, felt) in tag.as_word().iter().enumerate() {
            processor.stack_write(DEFERRED_TAG_OFFSET + i, *felt);
        }
    }

    #[test]
    fn register_data_accepts_join_payload_from_memory() {
        let mut processor = bind_precompiles(processor_with_budget(64), test_precompiles());
        let digest_payload = [Felt::from_u32(7); 8];

        write_register_stack(&mut processor, Hash::digest_tag(), digest_payload);
        handle_deferred_register(&mut processor).unwrap();
        let child = Hash::digest_node(digest_payload).digest();

        let ptr = 0;
        let mut join_payload = [ZERO; 8];
        join_payload[..4].copy_from_slice(child.as_elements());
        join_payload[4..].copy_from_slice(child.as_elements());
        write_data_memory(&mut processor, ptr, &[join_payload]);

        write_data_stack(&mut processor, Hash::eq_tag(), ptr);
        handle_deferred_register_data(&mut processor).unwrap();

        let join = Hash::eq_node(child, child).digest();
        let canonical = processor.deferred_state_mut().evaluate_digest(join).unwrap();
        assert_eq!(canonical, TRUE_DIGEST);
    }

    #[test]
    fn register_past_budget_is_rejected() {
        // Budget = 12 elements = exactly one value node (4 tag + 8 payload).
        let mut processor = bind_precompiles(processor_with_budget(12), test_precompiles());

        // The first node fills the budget exactly.
        write_register_stack(&mut processor, Hash::digest_tag(), [Felt::from_u32(1); 8]);
        handle_deferred_register(&mut processor).unwrap();

        // A second, distinct node needs 12 more elements, but the first insertion left none.
        write_register_stack(&mut processor, Hash::digest_tag(), [Felt::from_u32(2); 8]);
        let err = handle_deferred_register(&mut processor).unwrap_err();
        assert!(matches!(
            err,
            SystemEventError::Deferred(ref err)
                if matches!(
                    err.root(),
                    PrecompileError::Other(DeferredError::DeferredStateTooLarge {
                        num_elements: 12,
                        max: 0,
                    })
                )
        ));
    }

    #[test]
    fn register_data_over_budget_is_rejected_before_reading_memory() {
        // A near-`u32::MAX` byte count decodes to ~125M chunks. Without the pre-read budget check
        // the handler would attempt a multi-GB `Vec::with_capacity` before failing; the pre-check
        // rejects it on the projected element count alone, so this test stays cheap.
        let mut processor = bind_precompiles(processor_with_budget(16), test_precompiles());
        let n_bytes = 4_000_000_000u32;
        let expected = payload_node_num_elements(Hash::n_data_chunks(n_bytes));

        write_data_stack(&mut processor, Hash::preimage_tag(n_bytes), 0);
        let err = handle_deferred_register_data(&mut processor).unwrap_err();
        assert!(matches!(
            err,
            SystemEventError::Deferred(ref err)
                if matches!(
                    err.root(),
                    PrecompileError::Other(DeferredError::DeferredStateTooLarge {
                        num_elements,
                        max: 16,
                    }) if *num_elements == expected
                )
        ));
    }

    #[test]
    fn register_data_rejects_unaligned_pointer() {
        // A non-word-aligned pointer is rejected as an alignment error before any memory read.
        let mut processor = bind_precompiles(processor_with_budget(64), test_precompiles());

        write_data_stack(&mut processor, Hash::preimage_tag(Hash::BYTES_PER_CHUNK), 1);
        let err = handle_deferred_register_data(&mut processor).unwrap_err();
        assert!(matches!(err, SystemEventError::Memory(MemoryError::UnalignedWordAccess { .. })));
    }
}
