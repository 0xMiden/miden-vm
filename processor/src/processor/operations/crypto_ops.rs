use miden_air::trace::{
    decoder::NUM_USER_OP_HELPERS,
    log_precompile::{STATE_CAP_RANGE, STATE_RATE_0_RANGE, STATE_RATE_1_RANGE},
};
use miden_core::{
    Felt, ONE, QuadFelt, Word, ZERO, chiplets::hasher::STATE_WIDTH, mast::MastForest,
    stack::MIN_STACK_DEPTH, utils::range,
};

use crate::{
    ErrorContext, ExecutionError,
    fast::Tracer,
    processor::{
        AdviceProviderInterface, HasherInterface, MemoryInterface, OperationHelperRegisters,
        Processor, StackInterface, SystemInterface,
    },
};

// CRYPTOGRAPHIC OPERATIONS
// ================================================================================================

/// Performs a hash permutation operation.
/// Applies Rescue Prime Optimized permutation to the top 12 elements of the stack.
#[inline(always)]
pub(super) fn op_hperm<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> [Felt; NUM_USER_OP_HELPERS] {
    let state_range = range(MIN_STACK_DEPTH - STATE_WIDTH, STATE_WIDTH);

    // Compute the hash of the input
    let input_state: [Felt; STATE_WIDTH] = processor.stack().top()[state_range.clone()]
        .try_into()
        .expect("state range expected to be 12 elements");
    let (addr, output_state) = processor.hasher().permute(input_state);

    // Write the hash back to the stack
    processor.stack().top_mut()[state_range].copy_from_slice(&output_state);

    // Record the hasher permutation
    tracer.record_hasher_permute(input_state, output_state);

    P::HelperRegisters::op_hperm_registers(addr)
}

/// Verifies a Merkle path.
#[inline(always)]
pub(super) fn op_mpverify<P: Processor>(
    processor: &mut P,
    err_code: Felt,
    program: &MastForest,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], ExecutionError> {
    let clk = processor.system().clk();

    // read node value, depth, index and root value from the stack
    let node = processor.stack().get_word(0);
    let depth = processor.stack().get(4);
    let index = processor.stack().get(5);
    let root = processor.stack().get_word(6);

    // get a Merkle path from the advice provider for the specified root and node index
    let path = processor
        .advice_provider()
        .get_merkle_path(root, &depth, &index)
        .map_err(|err| ExecutionError::advice_error(err, clk, err_ctx))?;

    tracer.record_hasher_build_merkle_root(node, path.as_ref(), index, root);

    // verify the path
    let addr = processor.hasher().verify_merkle_root(root, node, path.as_ref(), index, || {
        // If the hasher doesn't compute the same root (using the same path),
        // then it means that `node` is not the value currently in the tree at `index`
        let err_msg = program.resolve_error_message(err_code);
        ExecutionError::merkle_path_verification_failed(
            node, index, root, err_code, err_msg, err_ctx,
        )
    })?;

    Ok(P::HelperRegisters::op_merkle_path_registers(addr))
}

#[inline(always)]
pub(super) fn op_mrupdate<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], ExecutionError> {
    let clk = processor.system().clk();

    // read old node value, depth, index, tree root and new node values from the stack
    let old_value = processor.stack().get_word(0);
    let depth = processor.stack().get(4);
    let index = processor.stack().get(5);
    let claimed_old_root = processor.stack().get_word(6);
    let new_value = processor.stack().get_word(10);

    // update the node at the specified index in the Merkle tree specified by the old root, and
    // get a Merkle path to it. The length of the returned path is expected to match the
    // specified depth. If the new node is the root of a tree, this instruction will append the
    // whole sub-tree to this node.
    let path = processor
        .advice_provider()
        .update_merkle_node(claimed_old_root, &depth, &index, new_value)
        .map_err(|err| ExecutionError::advice_error(err, clk, err_ctx))?;

    if let Some(path) = &path {
        // TODO(plafer): return error instead of asserting
        assert_eq!(path.len(), depth.as_int() as usize);
    }

    let (addr, new_root) = processor.hasher().update_merkle_root(
        claimed_old_root,
        old_value,
        new_value,
        path.as_ref(),
        index,
        || {
            ExecutionError::merkle_path_verification_failed(
                old_value,
                index,
                claimed_old_root,
                ZERO,
                None,
                err_ctx,
            )
        },
    )?;
    tracer.record_hasher_update_merkle_root(
        old_value,
        new_value,
        path.as_ref(),
        index,
        claimed_old_root,
        new_root,
    );

    // Replace the old node value with computed new root; everything else remains the same.
    processor.stack().set_word(0, &new_root);

    Ok(P::HelperRegisters::op_merkle_path_registers(addr))
}

/// Evaluates a polynomial using Horner's method (base field).
///
/// In this implementation, we replay the recorded operations and compute the result.
#[inline(always)]
pub(super) fn op_horner_eval_base<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], ExecutionError> {
    // Constants from the original implementation
    const ALPHA_ADDR_INDEX: usize = 13;
    const ACC_HIGH_INDEX: usize = 14;
    const ACC_LOW_INDEX: usize = 15;

    let clk = processor.system().clk();
    let ctx = processor.system().ctx();

    // Read the evaluation point alpha from memory
    let alpha = {
        let addr = processor.stack().get(ALPHA_ADDR_INDEX);
        let eval_point_0 = processor
            .memory()
            .read_element(ctx, addr, err_ctx)
            .map_err(ExecutionError::MemoryError)?;
        let eval_point_1 = processor
            .memory()
            .read_element(ctx, addr + ONE, err_ctx)
            .map_err(ExecutionError::MemoryError)?;

        tracer.record_memory_read_element(eval_point_0, addr, ctx, clk);

        tracer.record_memory_read_element(eval_point_1, addr + ONE, ctx, clk);

        QuadFelt::new(eval_point_0, eval_point_1)
    };

    // Read the coefficients from the stack (top 8 elements)
    let coef: [Felt; 8] = core::array::from_fn(|i| processor.stack().get(i));

    let c0 = QuadFelt::from(coef[0]);
    let c1 = QuadFelt::from(coef[1]);
    let c2 = QuadFelt::from(coef[2]);
    let c3 = QuadFelt::from(coef[3]);
    let c4 = QuadFelt::from(coef[4]);
    let c5 = QuadFelt::from(coef[5]);
    let c6 = QuadFelt::from(coef[6]);
    let c7 = QuadFelt::from(coef[7]);

    // Read the current accumulator
    let acc =
        QuadFelt::new(processor.stack().get(ACC_LOW_INDEX), processor.stack().get(ACC_HIGH_INDEX));

    // Level 1: tmp0 = (acc * α + c₇) * α + c₆
    let tmp0 = (acc * alpha + c7) * alpha + c6;

    // Level 2: tmp1 = ((tmp0 * α + c₅) * α + c₄) * α + c₃
    let tmp1 = ((tmp0 * alpha + c5) * alpha + c4) * alpha + c3;

    // Level 3: acc' = ((tmp1 * α + c₂) * α + c₁) * α + c₀
    let acc_new = ((tmp1 * alpha + c2) * alpha + c1) * alpha + c0;

    // Update the accumulator values on the stack
    let acc_new_base_elements = acc_new.to_base_elements();
    processor.stack().set(ACC_HIGH_INDEX, acc_new_base_elements[1]);
    processor.stack().set(ACC_LOW_INDEX, acc_new_base_elements[0]);

    // Return the user operation helpers
    Ok([
        alpha.to_base_elements()[0],
        alpha.to_base_elements()[1],
        tmp1.to_base_elements()[0],
        tmp1.to_base_elements()[1],
        tmp0.to_base_elements()[0],
        tmp0.to_base_elements()[1],
    ])
}

// LOG PRECOMPILE OPERATION
// ================================================================================================

/// Logs a precompile event by absorbing `TAG` and `COMM` into the precompile sponge
/// capacity.
///
/// Stack transition:
/// `[COMM, TAG, PAD, ...] -> [R1, R0, CAP_NEXT, ...]`
///
/// Where:
/// - The hasher computes: `[CAP_NEXT, R0, R1] = Rpo([CAP_PREV, TAG, COMM])`
/// - `CAP_PREV` is the previous sponge capacity provided non-deterministically via helper
///   registers.
#[inline(always)]
pub(super) fn op_log_precompile<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> [Felt; NUM_USER_OP_HELPERS] {
    // Read TAG and COMM from stack
    let comm = processor.stack().get_word(0);
    let tag = processor.stack().get_word(4);

    // Get the current precompile sponge capacity
    let cap_prev = processor.precompile_transcript_state();

    // Build the full 12-element hasher state for RPO permutation
    // State layout: [CAP_PREV, TAG, COMM]
    let mut hasher_state: [Felt; STATE_WIDTH] = [ZERO; 12];
    hasher_state[STATE_CAP_RANGE].copy_from_slice(cap_prev.as_slice());
    hasher_state[STATE_RATE_0_RANGE].copy_from_slice(tag.as_slice());
    hasher_state[STATE_RATE_1_RANGE].copy_from_slice(comm.as_slice());

    // Perform the RPO permutation
    let (addr, output_state) = processor.hasher().permute(hasher_state);

    // Extract CAP_NEXT (first 4 elements), R0 (next 4 elements), R1 (last 4 elements)
    let cap_next: Word = output_state[STATE_CAP_RANGE.clone()]
        .try_into()
        .expect("cap_next slice has length 4");

    // Update the processor's precompile sponge capacity
    processor.set_precompile_transcript_state(cap_next);

    // Write the output to the stack (top 12 elements): [R1, R0, CAP_NEXT, ...]
    // The stack stores elements in reverse order relative to the permutation output.
    for i in 0..STATE_WIDTH {
        processor.stack().set(i, output_state[STATE_WIDTH - 1 - i]);
    }

    // Record the hasher permutation for trace generation
    tracer.record_hasher_permute(hasher_state, output_state);

    // Return helper registers containing the hasher address and CAP_PREV
    // Convert cap_prev Word to array for the helper registers
    P::HelperRegisters::op_log_precompile_registers(addr, cap_prev)
}

/// Evaluates a polynomial using Horner's method (extension field).
///
/// In this implementation, we replay the recorded operations and compute the result.
#[inline(always)]
pub(super) fn op_horner_eval_ext<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], ExecutionError> {
    // Constants from the original implementation
    const ALPHA_ADDR_INDEX: usize = 13;
    const ACC_HIGH_INDEX: usize = 14;
    const ACC_LOW_INDEX: usize = 15;

    let clk = processor.system().clk();
    let ctx = processor.system().ctx();

    // Read the coefficients from the stack as extension field elements (4 QuadFelt elements)
    // Stack layout: [c3_1, c3_0, c2_1, c2_0, c1_1, c1_0, c0_1, c0_0, ...]
    let coef = [
        QuadFelt::new(processor.stack().get(1), processor.stack().get(0)), // c0: (c0_0, c0_1)
        QuadFelt::new(processor.stack().get(3), processor.stack().get(2)), // c1: (c1_0, c1_1)
        QuadFelt::new(processor.stack().get(5), processor.stack().get(4)), // c2: (c2_0, c2_1)
        QuadFelt::new(processor.stack().get(7), processor.stack().get(6)), // c3: (c3_0, c3_1)
    ];

    // Read the evaluation point alpha from memory
    let (alpha, k0, k1) = {
        let addr = processor.stack().get(ALPHA_ADDR_INDEX);
        let word = processor
            .memory()
            .read_word(ctx, addr, clk, err_ctx)
            .map_err(ExecutionError::MemoryError)?;
        tracer.record_memory_read_word(
            word,
            addr,
            processor.system().ctx(),
            processor.system().clk(),
        );

        (QuadFelt::new(word[0], word[1]), word[2], word[3])
    };

    // Read the current accumulator
    let acc_old = QuadFelt::new(
        processor.stack().get(ACC_LOW_INDEX),  // acc0
        processor.stack().get(ACC_HIGH_INDEX), // acc1
    );

    // Compute the temporary accumulator (first 2 coefficients: c0, c1)
    let acc_tmp = coef.iter().rev().take(2).fold(acc_old, |acc, coef| *coef + alpha * acc);

    // Compute the final accumulator (remaining 2 coefficients: c2, c3)
    let acc_new = coef.iter().rev().skip(2).fold(acc_tmp, |acc, coef| *coef + alpha * acc);

    // Update the accumulator values on the stack
    let acc_new_base_elements = acc_new.to_base_elements();
    processor.stack().set(ACC_HIGH_INDEX, acc_new_base_elements[1]);
    processor.stack().set(ACC_LOW_INDEX, acc_new_base_elements[0]);

    // Return the user operation helpers
    Ok(P::HelperRegisters::op_horner_eval_registers(alpha, k0, k1, acc_tmp))
}
