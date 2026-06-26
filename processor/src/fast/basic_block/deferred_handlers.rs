//! Processor glue for deferred-DAG system events.
//!
//! These handlers keep the processor agnostic to precompile semantics: they read VM inputs,
//! update deferred state, and delegate validation/evaluation to the installed registry.

use alloc::vec::Vec;

#[cfg(test)]
use miden_core::deferred::PrecompileRegistry;
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
// The eight payload felts are one 8-felt data chunk, `lhs || rhs` child digests for a join, one
// `lhs || rhs` pair for a pair-list node, or `child_digest || params` for a unary node. Exact
// `Tag::CHUNKS` (`[2, 0, 0, 0]`) is framework-owned opaque data; malformed id-2 tags are rejected.
// Unary `params` are literal payload data, not tag args.

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
// is framework-owned opaque data. Join and unary nodes require `n_chunks == 1`.

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
/// child digests, a one-pair pair-list payload containing `lhs || rhs`, or a unary payload
/// containing `child_digest || params`. Exact [`Tag::CHUNKS`] (`[2, 0, 0, 0]`) forms a
/// framework-owned opaque data node; other id-2 tags are malformed and reject during tag decode.
/// For unary nodes, `params` is a literal payload word and is separate from [`Tag::args`]. TRUE is
/// not accepted. Tags that semantically require more than one data chunk or pair still form a
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
        NodeType::Unary => {
            let child = Digest::new([block[0], block[1], block[2], block[3]]);
            let params = Word::new([block[4], block[5], block[6], block[7]]);
            Node::unary(tag, child, params).map_err(PrecompileError::from)?
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
/// for that chunk. Join and unary payloads use the same convention for their two words: join leaves
/// `[lhs, rhs, ...]`, and unary leaves `[child_digest, params, ...]` after two `adv_pushw`s. TRUE
/// emits no advice. These advice values are intentionally unbound: proof-relevant callers must bind
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
/// remain precompile-owned. Pair-list nodes interpret chunks as `lhs || rhs` pairs. Join and unary
/// nodes require `n_chunks == 1` and interpret the one chunk as `lhs || rhs` or
/// `child_digest || params` respectively, where unary `params` is literal payload data rather than
/// [`Tag::args`]. TRUE is not accepted. After checking word alignment, address bounds, and a cheap
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
        NodeType::Join | NodeType::Unary if n == 1 => {},
        NodeType::Join | NodeType::Unary | NodeType::True => {
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
        NodeType::Unary => {
            let block = chunks.into_iter().next().ok_or(PrecompileError::InvalidNode)?;
            let child = Digest::new([block[0], block[1], block[2], block[3]]);
            let params = Word::new([block[4], block[5], block[6], block[7]]);
            Node::unary(tag, child, params).map_err(PrecompileError::from)?
        },
        NodeType::PairList => {
            Node::try_pair_list_chunks(tag, chunks).map_err(PrecompileError::from)?
        },
        NodeType::True => unreachable!("TRUE was rejected before memory reads"),
    };
    processor.deferred_state_mut().register(node)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use miden_core::{
        Felt,
        deferred::{DeferredContext, Payload, Precompile, TRUE_DIGEST, precompile_id},
        testing::precompile::Hash,
    };

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

    fn test_precompiles_with_unary() -> PrecompileRegistry {
        PrecompileRegistry::default()
            .with_precompile(Hash)
            .with_precompile(UnaryFixture)
    }

    fn test_precompiles_with_pair_list() -> PrecompileRegistry {
        PrecompileRegistry::default()
            .with_precompile(Hash)
            .with_precompile(PairListFixture)
    }

    #[derive(Debug, Clone, Copy)]
    struct UnaryFixture;

    impl UnaryFixture {
        const NAME: &'static str = "processor-unary-fixture";

        fn id() -> Felt {
            precompile_id(Self::NAME)
        }

        fn tag() -> Tag {
            Tag::precompile(Self::id(), [ZERO; 3]).expect("fixture id is precompile-owned")
        }
    }

    impl Precompile for UnaryFixture {
        fn name(&self) -> &'static str {
            Self::NAME
        }

        fn id(&self) -> Felt {
            Self::id()
        }

        fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
            (args == [ZERO; 3]).then_some(NodeType::Unary)
        }

        fn evaluate(
            &self,
            _args: [Felt; 3],
            payload: &Payload,
            context: &mut DeferredContext<'_>,
        ) -> Result<Node, PrecompileError> {
            let (child, _params) = payload.as_unary()?;
            context.get_node(&child).ok_or(PrecompileError::MissingNode)?;
            Ok(Node::TRUE)
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct PairListFixture;

    impl PairListFixture {
        const NAME: &'static str = "processor-pair-list-fixture";

        fn id() -> Felt {
            precompile_id(Self::NAME)
        }

        fn tag(n: u32) -> Tag {
            Tag::precompile(Self::id(), [Felt::from_u32(n), ZERO, ZERO])
                .expect("fixture id is precompile-owned")
        }
    }

    impl Precompile for PairListFixture {
        fn name(&self) -> &'static str {
            Self::NAME
        }

        fn id(&self) -> Felt {
            Self::id()
        }

        fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
            if args[1] != ZERO || args[2] != ZERO {
                return None;
            }
            u32::try_from(args[0].as_canonical_u64()).ok().and_then(NodeType::pair_list)
        }

        fn evaluate(
            &self,
            args: [Felt; 3],
            payload: &Payload,
            context: &mut DeferredContext<'_>,
        ) -> Result<Node, PrecompileError> {
            let n = u32::try_from(args[0].as_canonical_u64())
                .map_err(|_| PrecompileError::InvalidNode)? as usize;
            let pairs = payload.as_pair_list()?;
            if pairs.len() != n {
                return Err(DeferredError::InvalidPayload.into());
            }
            for (lhs, rhs) in pairs {
                context.get_node(&lhs).ok_or(PrecompileError::MissingNode)?;
                context.get_node(&rhs).ok_or(PrecompileError::MissingNode)?;
            }
            Ok(Node::TRUE)
        }
    }

    fn bind_precompiles(
        processor: FastProcessor,
        precompiles: PrecompileRegistry,
    ) -> FastProcessor {
        processor
            .with_deferred_precompiles(precompiles)
            .expect("test precompile initialization should fit the configured deferred budget")
    }

    fn write_data_stack(processor: &mut FastProcessor, tag: Tag, ptr: u32, n_chunks: u64) {
        for (i, felt) in tag.as_word().iter().enumerate() {
            processor.stack_write(DATA_TAG_OFFSET + i, *felt);
        }
        processor.stack_write(DATA_PTR_OFFSET, Felt::from_u32(ptr));
        processor.stack_write(
            DATA_N_CHUNKS_OFFSET,
            Felt::new(n_chunks).expect("test chunk count fits in the field"),
        );
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

    fn unary_payload(child: Digest, params: Word) -> DataChunk {
        let mut payload = [ZERO; 8];
        payload[..4].copy_from_slice(child.as_elements());
        payload[4..].copy_from_slice(params.as_elements());
        payload
    }

    fn pair_payload(lhs: Digest, rhs: Digest) -> DataChunk {
        let mut payload = [ZERO; 8];
        payload[..4].copy_from_slice(lhs.as_elements());
        payload[4..].copy_from_slice(rhs.as_elements());
        payload
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

        write_data_stack(&mut processor, tag, ptr, chunks.len() as u64);
        handle_deferred_register_data(&mut processor).unwrap();

        write_data_stack(&mut processor, tag, ptr, chunks.len() as u64);
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
    fn stack_register_accepts_single_framework_chunks_chunk() {
        let mut processor = processor_with_budget(64);
        let block = chunk(10);
        let expected = Node::chunks(vec![block]).expect("test CHUNKS node is valid");
        let digest = expected.digest();

        write_register_stack(&mut processor, Tag::CHUNKS, block);
        handle_deferred_register(&mut processor).unwrap();

        assert_eq!(processor.deferred_state().get_node(&digest), Some(&expected));
        assert_eq!(processor.deferred_state_mut().evaluate_digest(digest).unwrap(), digest);
    }

    #[test]
    fn register_data_accepts_framework_chunks_from_memory() {
        let mut processor = processor_with_budget(64);
        let chunks = vec![chunk(1), chunk(20)];
        let expected = Node::chunks(chunks.clone()).expect("test CHUNKS node is valid");
        let digest = expected.digest();
        let ptr = 0;
        write_data_memory(&mut processor, ptr, &chunks);

        write_data_stack(&mut processor, Tag::CHUNKS, ptr, chunks.len() as u64);
        handle_deferred_register_data(&mut processor).unwrap();

        assert_eq!(processor.deferred_state().get_node(&digest), Some(&expected));
        assert_eq!(processor.deferred_state_mut().evaluate_digest(digest).unwrap(), digest);
    }

    #[test]
    fn register_data_rejects_zero_framework_chunks() {
        let mut processor = processor_with_budget(64);

        write_data_stack(&mut processor, Tag::CHUNKS, 0, 0);
        let err = handle_deferred_register_data(&mut processor).unwrap_err();
        assert!(
            matches!(err, SystemEventError::Deferred(ref err) if matches!(err.root(), PrecompileError::InvalidNode))
        );
    }

    #[test]
    fn register_handlers_reject_malformed_framework_chunks_tags() {
        let malformed = Tag::from_word([Tag::CHUNKS.id(), Felt::from_u32(1), ZERO, ZERO]);

        let mut stack_processor = processor_with_budget(64);
        write_register_stack(&mut stack_processor, malformed, chunk(5));
        let err = handle_deferred_register(&mut stack_processor).unwrap_err();
        assert!(
            matches!(err, SystemEventError::Deferred(ref err) if matches!(err.root(), PrecompileError::InvalidNode))
        );

        let mut memory_processor = processor_with_budget(64);
        write_data_stack(&mut memory_processor, malformed, 0, 1);
        let err = handle_deferred_register_data(&mut memory_processor).unwrap_err();
        assert!(
            matches!(err, SystemEventError::Deferred(ref err) if matches!(err.root(), PrecompileError::InvalidNode))
        );
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

        write_data_stack(&mut processor, Hash::eq_tag(), ptr, 1);
        handle_deferred_register_data(&mut processor).unwrap();

        let join = Hash::eq_node(child, child).digest();
        let canonical = processor.deferred_state_mut().evaluate_digest(join).unwrap();
        assert_eq!(canonical, TRUE_DIGEST);
    }

    #[test]
    fn register_handlers_accept_unary_payload_with_literal_params() {
        let mut processor =
            bind_precompiles(processor_with_budget(128), test_precompiles_with_unary());
        let digest_payload = [Felt::from_u32(7); 8];

        write_register_stack(&mut processor, Hash::digest_tag(), digest_payload);
        handle_deferred_register(&mut processor).unwrap();
        let child = Hash::digest_node(digest_payload).digest();

        let stack_params = Word::new([Felt::from_u32(20), Felt::from_u32(21), ZERO, ZERO]);
        assert!(processor.deferred_state().get_node(&stack_params).is_none());
        write_register_stack(
            &mut processor,
            UnaryFixture::tag(),
            unary_payload(child, stack_params),
        );
        handle_deferred_register(&mut processor).unwrap();
        let stack_unary = Node::unary(UnaryFixture::tag(), child, stack_params).unwrap().digest();
        assert_eq!(
            processor.deferred_state_mut().evaluate_digest(stack_unary).unwrap(),
            TRUE_DIGEST
        );
        assert!(processor.deferred_state().get_node(&stack_params).is_none());

        let memory_params = Word::new([Felt::from_u32(30), Felt::from_u32(31), ZERO, ZERO]);
        assert!(processor.deferred_state().get_node(&memory_params).is_none());
        let ptr = 0;
        write_data_memory(&mut processor, ptr, &[unary_payload(child, memory_params)]);
        write_data_stack(&mut processor, UnaryFixture::tag(), ptr, 1);
        handle_deferred_register_data(&mut processor).unwrap();
        let memory_unary = Node::unary(UnaryFixture::tag(), child, memory_params).unwrap().digest();
        assert_eq!(
            processor.deferred_state_mut().evaluate_digest(memory_unary).unwrap(),
            TRUE_DIGEST
        );
        assert!(processor.deferred_state().get_node(&memory_params).is_none());
    }

    #[test]
    fn register_handlers_accept_pair_list_payloads() {
        let mut processor =
            bind_precompiles(processor_with_budget(256), test_precompiles_with_pair_list());
        let digest_payload_a = [Felt::from_u32(7); 8];
        let digest_payload_b = [Felt::from_u32(11); 8];

        write_register_stack(&mut processor, Hash::digest_tag(), digest_payload_a);
        handle_deferred_register(&mut processor).unwrap();
        let child_a = Hash::digest_node(digest_payload_a).digest();

        write_register_stack(&mut processor, Hash::digest_tag(), digest_payload_b);
        handle_deferred_register(&mut processor).unwrap();
        let child_b = Hash::digest_node(digest_payload_b).digest();

        write_register_stack(
            &mut processor,
            PairListFixture::tag(1),
            pair_payload(child_a, child_b),
        );
        handle_deferred_register(&mut processor).unwrap();
        let stack_pair_list =
            Node::try_pair_list(PairListFixture::tag(1), vec![(child_a, child_b)])
                .unwrap()
                .digest();
        assert_eq!(
            processor.deferred_state_mut().evaluate_digest(stack_pair_list).unwrap(),
            TRUE_DIGEST
        );

        let ptr = 0;
        let chunks = vec![pair_payload(child_a, child_b), pair_payload(child_b, child_a)];
        write_data_memory(&mut processor, ptr, &chunks);
        write_data_stack(&mut processor, PairListFixture::tag(2), ptr, chunks.len() as u64);
        handle_deferred_register_data(&mut processor).unwrap();
        let memory_pair_list = Node::try_pair_list(
            PairListFixture::tag(2),
            vec![(child_a, child_b), (child_b, child_a)],
        )
        .unwrap()
        .digest();
        assert_eq!(
            processor.deferred_state_mut().evaluate_digest(memory_pair_list).unwrap(),
            TRUE_DIGEST
        );
    }

    #[test]
    fn stack_register_pair_list_semantic_mismatch_is_rejected() {
        let mut processor =
            bind_precompiles(processor_with_budget(256), test_precompiles_with_pair_list());
        let digest_payload = [Felt::from_u32(7); 8];

        write_register_stack(&mut processor, Hash::digest_tag(), digest_payload);
        handle_deferred_register(&mut processor).unwrap();
        let child = Hash::digest_node(digest_payload).digest();

        write_register_stack(&mut processor, PairListFixture::tag(2), pair_payload(child, child));
        let err = handle_deferred_register(&mut processor).unwrap_err();
        assert!(
            matches!(err, SystemEventError::Deferred(ref err) if matches!(err.root(), PrecompileError::Other(DeferredError::InvalidPayload)))
        );
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
        // A large explicit chunk count would require a multi-MB payload. Without the pre-read
        // budget check the handler would allocate/read before failing; the pre-check
        // rejects it on the projected element count alone, so this test stays cheap.
        let mut processor = bind_precompiles(processor_with_budget(16), test_precompiles());
        let n_chunks = 1_000_000u32;
        let n_bytes = n_chunks * Hash::BYTES_PER_CHUNK;
        let expected = payload_node_num_elements(n_chunks);

        write_data_stack(&mut processor, Hash::preimage_tag(n_bytes), 0, n_chunks as u64);
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
    fn register_data_rejects_zero_chunks() {
        let mut processor = bind_precompiles(processor_with_budget(64), test_precompiles());

        write_data_stack(&mut processor, Hash::preimage_tag(Hash::BYTES_PER_CHUNK), 0, 0);
        let err = handle_deferred_register_data(&mut processor).unwrap_err();
        assert!(
            matches!(err, SystemEventError::Deferred(ref err) if matches!(err.root(), PrecompileError::InvalidNode))
        );
    }

    #[test]
    fn register_data_rejects_chunk_count_outside_u32() {
        let mut processor = bind_precompiles(processor_with_budget(64), test_precompiles());

        write_data_stack(
            &mut processor,
            Hash::preimage_tag(Hash::BYTES_PER_CHUNK),
            0,
            u32::MAX as u64 + 1,
        );
        let err = handle_deferred_register_data(&mut processor).unwrap_err();
        assert!(
            matches!(err, SystemEventError::Deferred(ref err) if matches!(err.root(), PrecompileError::InvalidNode))
        );
    }

    #[test]
    fn register_data_rejects_memory_range_out_of_bounds() {
        let mut processor = bind_precompiles(processor_with_budget(64), test_precompiles());
        let ptr = u32::MAX - 3;

        write_data_stack(&mut processor, Hash::preimage_tag(Hash::BYTES_PER_CHUNK), ptr, 1);
        let err = handle_deferred_register_data(&mut processor).unwrap_err();
        assert!(matches!(err, SystemEventError::Memory(MemoryError::AddressOutOfBounds { .. })));
    }

    #[test]
    fn register_data_join_and_unary_require_one_chunk() {
        let mut join_processor = bind_precompiles(processor_with_budget(64), test_precompiles());
        write_data_stack(&mut join_processor, Hash::eq_tag(), 0, 2);
        let err = handle_deferred_register_data(&mut join_processor).unwrap_err();
        assert!(
            matches!(err, SystemEventError::Deferred(ref err) if matches!(err.root(), PrecompileError::InvalidNode))
        );

        let mut unary_processor =
            bind_precompiles(processor_with_budget(64), test_precompiles_with_unary());
        write_data_stack(&mut unary_processor, UnaryFixture::tag(), 0, 2);
        let err = handle_deferred_register_data(&mut unary_processor).unwrap_err();
        assert!(
            matches!(err, SystemEventError::Deferred(ref err) if matches!(err.root(), PrecompileError::InvalidNode))
        );
    }

    #[test]
    fn register_data_pair_list_semantic_mismatch_is_rejected() {
        let mut processor =
            bind_precompiles(processor_with_budget(256), test_precompiles_with_pair_list());
        let digest_payload = [Felt::from_u32(7); 8];

        write_register_stack(&mut processor, Hash::digest_tag(), digest_payload);
        handle_deferred_register(&mut processor).unwrap();
        let child = Hash::digest_node(digest_payload).digest();

        let ptr = 0;
        let chunks = vec![pair_payload(child, child)];
        write_data_memory(&mut processor, ptr, &chunks);
        write_data_stack(&mut processor, PairListFixture::tag(2), ptr, chunks.len() as u64);
        let err = handle_deferred_register_data(&mut processor).unwrap_err();
        assert!(
            matches!(err, SystemEventError::Deferred(ref err) if matches!(err.root(), PrecompileError::Other(DeferredError::InvalidPayload)))
        );
    }

    #[test]
    fn register_data_rejects_unaligned_pointer() {
        // A non-word-aligned pointer is rejected as an alignment error before any memory read.
        let mut processor = bind_precompiles(processor_with_budget(64), test_precompiles());

        write_data_stack(&mut processor, Hash::preimage_tag(Hash::BYTES_PER_CHUNK), 1, 1);
        let err = handle_deferred_register_data(&mut processor).unwrap_err();
        assert!(matches!(err, SystemEventError::Memory(MemoryError::UnalignedWordAccess { .. })));
    }
}
