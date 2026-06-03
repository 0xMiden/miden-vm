//! Processor glue for deferred-DAG system events.
//!
//! These handlers keep the processor agnostic to precompile semantics: they read VM inputs,
//! update deferred state, and delegate validation/evaluation to the installed registry.

use alloc::vec::Vec;

#[cfg(test)]
use miden_core::deferred::PrecompileRegistry;
use miden_core::{
    ZERO,
    deferred::{DataChunk, Digest, Node, NodeType, PrecompileError, Tag},
};

use super::SystemEventError;
use crate::{MemoryError, fast::FastProcessor};

// STACK LAYOUT — `DeferredRegister`
// ================================================================================================
// `[event_id, PAYLOAD_LO, PAYLOAD_HI, TAG, ...]` — Poseidon2 sponge layout so MASM can feed the
// 12 felts directly into one `hperm` to compute the node's digest. The eight payload felts are a
// single data chunk for a `Data(1)` value, or `lhs || rhs` child digests for a join.

/// Stack offset of the payload's low half below the event id.
const DEFERRED_PAYLOAD_LO_OFFSET: usize = 1;
/// Stack offset of the payload's high half.
const DEFERRED_PAYLOAD_HI_OFFSET: usize = 5;
/// Stack offset of the deferred tag word.
const DEFERRED_TAG_OFFSET: usize = 9;

// STACK LAYOUT — `DeferredEvaluate`
// ================================================================================================
// `[event_id, NODE_DIGEST, ...]` — the node must already be registered in `DeferredState`; the
// handler calls `DeferredState::evaluate` by digest and pushes the canonical's `Node::to_felts()`
// onto the advice stack.

/// Stack offset of the registered node digest.
const DEFERRED_NODE_DIGEST_OFFSET: usize = 1;

// STACK LAYOUT — `DeferredRegisterData`
// ================================================================================================
// `[event_id, TAG, ptr, ...]` — no payload (`n` is decoded out of the tag, so the data payload's
// size is fully determined by the precompile's tag layout).

/// Stack offset of the data tag word.
const DATA_TAG_OFFSET: usize = 1;
/// Stack offset of the memory pointer for the data payload.
const DATA_PTR_OFFSET: usize = 5;

/// Number of field elements occupied by a deferred node tag.
const TAG_NUM_ELEMENTS: usize = 4;
/// Number of field elements in one deferred data chunk.
const DATA_CHUNK_NUM_ELEMENTS: usize = 8;

/// Returns the storage footprint of a `Data(n)` node: `tag || n data chunks`.
fn data_node_num_elements(n_chunks: u32) -> usize {
    (n_chunks as usize)
        .checked_mul(DATA_CHUNK_NUM_ELEMENTS)
        .and_then(|payload_elements| payload_elements.checked_add(TAG_NUM_ELEMENTS))
        .unwrap_or(usize::MAX)
}

/// Stack-resident registration of a one-block deferred node.
///
/// The tag decodes to either a `Data(1)` value or a join over the eight payload felts; TRUE and
/// multi-chunk data tags are rejected (bulk data uses `adv.register_deferred_data`). Registration
/// is eager: semantic failures, including false predicates, surface immediately. The MASM wrapper
/// binds the original digest in-circuit, so the host cannot supply an unconstrained commitment
/// through advice.
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
    processor.deferred_state_mut().register(node)?;
    Ok(())
}

/// Handles deferred-node evaluation and returns the canonical node as advice.
///
/// The digest must already be registered in deferred state. The advice output is
/// [`Node::to_felts`] (`tag || payload`) and is intentionally unbound: callers that depend on it
/// must re-hash it in-circuit and log a predicate that rehydration will verify. The canonical TRUE
/// node emits only its four tag felts.
pub(super) fn handle_deferred_evaluate(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let digest: Digest = processor.stack_get_word(DEFERRED_NODE_DIGEST_OFFSET);

    let canonical = processor.deferred_state_mut().evaluate(digest)?;
    let felts = canonical.to_felts();

    // Push felts in reverse so the front of the advice stack is `felts[0]` (TAG): successive
    // `adv_pushw` reads then yield TAG, then each payload chunk / child word in natural order.
    for &felt in felts.iter().rev() {
        processor.advice.push_stack(felt)?;
    }
    Ok(())
}

/// Handles memory-resident registration of a bulk-data deferred node.
///
/// The tag, not the stack, is the source of truth for the data chunk count. Only `Data(n)` tags are
/// valid here; TRUE and joins are rejected. The same memory range is hashed by the MASM wrapper
/// in-circuit, binding the commitment to memory contents while this handler enforces alignment,
/// bounds, and bulk-data limits. Semantic evaluation and final budget checks are delegated to
/// `DeferredState::register`, so registration failures surface during this event.
pub(super) fn handle_deferred_register_data(
    processor: &mut FastProcessor,
) -> Result<(), SystemEventError> {
    let tag = Tag::from_word(processor.stack_get_word(DATA_TAG_OFFSET).into());
    let ptr = processor.stack_get(DATA_PTR_OFFSET).as_canonical_u64();

    // Decode `n` from the tag before any memory reads — the precompile is the source of truth for
    // data length and for rejecting oversized data tags. `Data` is `NonZeroU32`, so a 0-chunk tag
    // has already been rejected by the registry.
    let n = match processor.deferred_state().decode(tag)? {
        NodeType::Data(n) => n.get(),
        NodeType::True | NodeType::Join => return Err(PrecompileError::InvalidNode.into()),
    };

    // Reject data nodes that can never fit in the configured deferred-state budget before
    // reading memory. Remaining-budget accounting still belongs to `DeferredState::register`,
    // because only inserting the node into `nodes` tells us whether this registration is an
    // idempotent duplicate (which must remain free).
    let num_elements = data_node_num_elements(n);
    let max_deferred_elements = processor.options.max_deferred_elements();
    if num_elements > max_deferred_elements {
        return Err(SystemEventError::DeferredStateTooLarge {
            num_elements,
            max: max_deferred_elements,
        });
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
    // Read `n` rate-sized data chunks from memory.
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

    let node = Node::try_data(tag, chunks).map_err(PrecompileError::from)?;
    processor.deferred_state_mut().register(node)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use miden_core::{Felt, testing::precompile::Hash};

    use super::*;
    use crate::{ExecutionOptions, StackInputs};

    /// A processor with the given deferred element budget.
    fn processor_with_budget(max_deferred_elements: usize) -> FastProcessor {
        let options = ExecutionOptions::default().with_max_deferred_elements(max_deferred_elements);
        FastProcessor::new_with_options(StackInputs::default(), Default::default(), options)
            .expect("default advice inputs fit the configured limits")
    }

    fn test_precompiles() -> PrecompileRegistry {
        PrecompileRegistry::default().with_precompile(Hash)
    }

    fn bind_precompiles(processor: &mut FastProcessor, precompiles: PrecompileRegistry) {
        processor
            .register_deferred_precompiles(precompiles)
            .expect("test precompile initialization should fit the configured deferred budget");
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

    #[test]
    fn duplicate_data_registration_at_limit_is_free() {
        let chunks = vec![core::array::from_fn(|i| Felt::from_u32(1 + i as u32))];
        let tag = Hash::preimage_tag(Hash::BYTES_PER_CHUNK);
        let ptr = 0;
        let exact_budget = data_node_num_elements(chunks.len() as u32) + data_node_num_elements(1);
        let precompiles = test_precompiles();
        let mut processor = processor_with_budget(exact_budget);
        bind_precompiles(&mut processor, precompiles);
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
    fn register_past_budget_is_rejected() {
        // Budget = 12 elements = exactly one value node (4 tag + 8 payload).
        let mut processor = processor_with_budget(12);
        bind_precompiles(&mut processor, test_precompiles());

        // The first node fills the budget exactly.
        write_register_stack(&mut processor, Hash::digest_tag(), [Felt::from_u32(1); 8]);
        handle_deferred_register(&mut processor).unwrap();

        // A second, distinct node needs 12 more elements, but the first insertion left none.
        write_register_stack(&mut processor, Hash::digest_tag(), [Felt::from_u32(2); 8]);
        let err = handle_deferred_register(&mut processor).unwrap_err();
        assert!(matches!(
            err,
            SystemEventError::DeferredStateTooLarge { num_elements: 12, max: 0 }
        ));
    }

    #[test]
    fn register_data_over_budget_is_rejected_before_reading_memory() {
        // A near-`u32::MAX` byte count decodes to ~125M chunks. Without the pre-read budget check
        // the handler would attempt a multi-GB `Vec::with_capacity` before failing; the pre-check
        // rejects it on the projected element count alone, so this test stays cheap.
        let mut processor = processor_with_budget(16);
        bind_precompiles(&mut processor, test_precompiles());
        let n_bytes = 4_000_000_000u32;
        let expected = data_node_num_elements(Hash::n_data_chunks(n_bytes));

        write_data_stack(&mut processor, Hash::preimage_tag(n_bytes), 0);
        let err = handle_deferred_register_data(&mut processor).unwrap_err();
        assert!(matches!(
            err,
            SystemEventError::DeferredStateTooLarge { num_elements, max: 16 } if num_elements == expected
        ));
    }
}
