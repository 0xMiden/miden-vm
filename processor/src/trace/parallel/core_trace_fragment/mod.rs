use miden_air::{
    Felt,
    trace::{RowIndex, decoder::NUM_OP_BITS},
};
use miden_core::{
    field::{PrimeCharacteristicRing, PrimeField64},
    mast::BasicBlockNode,
    operations::OPCODE_PUSH,
};

use super::{super::chiplets::CircuitEvaluation, CORE_TRACE_WIDTH};
use crate::{
    ContextId, errors::AceEvalError, fast::eval_circuit_fast, processor::MemoryInterface,
    tracer::Tracer,
};

#[cfg(test)]
mod tests;

// CORE TRACE FRAGMENT
// ================================================================================================

/// The columns of the main trace fragment. These consist of the system, decoder, and stack columns.
///
/// A fragment is a collection of columns of length `fragment_size` or less. Only the last fragment
/// is allowed to be shorter than `fragment_size`.
#[derive(Debug)]
pub struct CoreTraceFragment<'a> {
    pub columns: [&'a mut [Felt]; CORE_TRACE_WIDTH],
}

// HELPERS
// ================================================================================================

/// Identical to `[chiplets::ace::eval_circuit]` but adapted for use with
/// `[CoreTraceFragmentGenerator]`.
pub(crate) fn eval_circuit_parallel_(
    ctx: ContextId,
    ptr: Felt,
    clk: RowIndex,
    num_vars: Felt,
    num_eval: Felt,
    memory: &mut impl MemoryInterface,
    tracer: &mut impl Tracer,
) -> Result<CircuitEvaluation, AceEvalError> {
    // Delegate to the fast implementation with the processor's memory interface.
    // This eliminates ~70 lines of duplicated code while maintaining identical functionality.
    eval_circuit_fast(ctx, ptr, clk, num_vars, num_eval, memory, tracer)
}

// BASIC BLOCK CONTEXT
// ================================================================================================

/// Keeps track of the info needed to decode a currently executing BASIC BLOCK. The info includes:
/// - Operations which still need to be executed in the current group. The operations are encoded as
///   opcodes (7 bits) appended one after another into a single field element, with the next
///   operation to be executed located at the least significant position.
/// - Number of operation groups left to be executed in the entire BASIC BLOCK.
#[derive(Debug, Default)]
pub struct BasicBlockContext {
    pub current_op_group: Felt,
    pub group_count_in_block: Felt,
}

impl BasicBlockContext {
    /// Initializes a `BasicBlockContext` for the case where execution starts at the beginning of an
    /// operation batch (i.e. at a SPAN or RESPAN row).
    pub(crate) fn new_at_batch_start(
        basic_block_node: &BasicBlockNode,
        batch_index: usize,
    ) -> Self {
        let current_batch = &basic_block_node.op_batches()[batch_index];

        Self {
            current_op_group: current_batch.groups()[0],
            group_count_in_block: Felt::new(
                basic_block_node
                    .op_batches()
                    .iter()
                    .skip(batch_index)
                    .map(|batch| batch.num_groups())
                    .sum::<usize>() as u64,
            ),
        }
    }

    /// Given that a trace fragment can start executing from the middle of a basic block, we need to
    /// initialize the `BasicBlockContext` correctly to reflect the state of the decoder at that
    /// point. This function does that initialization.
    ///
    /// Recall that `BasicBlockContext` keeps track of the state needed to correctly fill in the
    /// decoder columns associated with a SPAN of operations (i.e. a basic block). This function
    /// takes in a basic block node, the index of the current operation batch within that block,
    /// and the index of the current operation within that batch, and initializes the
    /// `BasicBlockContext` accordingly. In other words, it figures out how many operations are
    /// left in the current operation group, and how many operation groups are left in the basic
    /// block, given that we are starting execution from the specified operation.
    pub(crate) fn new_at_op(
        basic_block_node: &BasicBlockNode,
        batch_index: usize,
        op_idx_in_batch: usize,
    ) -> Self {
        let op_batches = basic_block_node.op_batches();
        let (current_op_group_idx, op_idx_in_group) = op_batches[batch_index]
            .op_idx_in_batch_to_group(op_idx_in_batch)
            .expect("invalid batch");

        let current_op_group = {
            // Note: this here relies on NOOP's opcode to be 0, since `current_op_group_idx` could
            // point to an op group that contains a NOOP inserted at runtime (i.e.
            // padding at the end of the batch), and hence not encoded in the basic
            // block directly. But since NOOP's opcode is 0, this works out correctly
            // (since empty groups are also represented by 0).
            let current_op_group = op_batches[batch_index].groups()[current_op_group_idx];

            // Shift out all operations that are already executed in this group.
            //
            // Note: `group_ops_left` encodes the bits of the operations left to be executed after
            // the current one, and so we would expect to shift `NUM_OP_BITS` by
            // `op_idx_in_group + 1`. However, we will apply that shift right before
            // writing to the trace, so we only shift by `op_idx_in_group` here.
            Felt::new(current_op_group.as_canonical_u64() >> (NUM_OP_BITS * op_idx_in_group))
        };

        let group_count_in_block = {
            let total_groups = basic_block_node.num_op_groups();

            // Count groups consumed by completed batches (all batches before current one).
            let mut groups_consumed = 0;
            for op_batch in op_batches.iter().take(batch_index) {
                groups_consumed += op_batch.num_groups().next_power_of_two();
            }

            // We run through previous operations of our current op group, and increment the number
            // of groups consumed for each operation that has an immediate value
            {
                // Note: This is a hacky way of doing this because `OpBatch` doesn't store the
                // information of which operation belongs to which group.
                let mut current_op_group =
                    op_batches[batch_index].groups()[current_op_group_idx].as_canonical_u64();
                for _ in 0..op_idx_in_group {
                    let current_op = (current_op_group & 0b1111111) as u8;
                    if current_op == OPCODE_PUSH {
                        groups_consumed += 1;
                    }

                    current_op_group >>= NUM_OP_BITS; // Shift to the next operation in the group
                }
            }

            // Add the number of complete groups before the current group in this batch. Add 1 to
            // account for the current group (since `num_groups_left` is the number of groups left
            // *after* being done with the current group)
            groups_consumed += current_op_group_idx + 1;

            Felt::from_u32((total_groups - groups_consumed) as u32)
        };

        Self { current_op_group, group_count_in_block }
    }

    /// Removes the operation that was just executed from the current operation group.
    pub(crate) fn remove_operation_from_current_op_group(&mut self) {
        let prev_op_group = self.current_op_group.as_canonical_u64();
        self.current_op_group = Felt::new(prev_op_group >> NUM_OP_BITS);

        debug_assert!(
            prev_op_group >= self.current_op_group.as_canonical_u64(),
            "op group underflow"
        );
    }
}
