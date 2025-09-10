use miden_air::trace::decoder::NUM_USER_OP_HELPERS;
use miden_core::{
    Felt, QuadFelt, ZERO, chiplets::hasher::STATE_WIDTH, mast::MastForest, stack::MIN_STACK_DEPTH,
    utils::range,
};

use crate::{
    ErrorContext, ExecutionError,
    fast::Tracer,
    processor::{
        AdviceProviderInterface, HasherInterface, MemoryInterface, OperationHelperRegisters,
        Processor, StackInterface, SystemInterface,
    },
};

/// Performs a hash permutation operation.
/// Applies Rescue Prime Optimized permutation to the top 12 elements of the stack.
#[inline(always)]
pub(super) fn op_hperm<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> [Felt; NUM_USER_OP_HELPERS] {
    let state_range = range(MIN_STACK_DEPTH - STATE_WIDTH, STATE_WIDTH);

    // Compute the hash of the input
    let (addr, hashed_state) = {
        let input_state: [Felt; STATE_WIDTH] = processor.stack().top()[state_range.clone()]
            .try_into()
            .expect("state range expected to be 12 elements");

        processor.hasher().permute(input_state)
    };

    // Write the hash back to the stack
    processor.stack().top_mut()[state_range].copy_from_slice(&hashed_state);

    // Record the hasher permutation
    tracer.record_hasher_permute(hashed_state);

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

    tracer.record_hasher_build_merkle_root(path.as_ref(), root);

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
    let old_node = processor.stack().get_word(0);
    let depth = processor.stack().get(4);
    let index = processor.stack().get(5);
    let claimed_old_root = processor.stack().get_word(6);
    let new_node = processor.stack().get_word(10);

    // update the node at the specified index in the Merkle tree specified by the old root, and
    // get a Merkle path to it. The length of the returned path is expected to match the
    // specified depth. If the new node is the root of a tree, this instruction will append the
    // whole sub-tree to this node.
    let path = processor
        .advice_provider()
        .update_merkle_node(claimed_old_root, &depth, &index, new_node)
        .map_err(|err| ExecutionError::advice_error(err, clk, err_ctx))?;

    if let Some(path) = &path {
        // TODO(plafer): return error instead of asserting
        assert_eq!(path.len(), depth.as_int() as usize);
    }

    let (addr, new_root) = processor.hasher().update_merkle_root(
        claimed_old_root,
        old_node,
        new_node,
        path.as_ref(),
        index,
        || {
            ExecutionError::merkle_path_verification_failed(
                old_node,
                index,
                claimed_old_root,
                ZERO,
                None,
                err_ctx,
            )
        },
    )?;
    tracer.record_hasher_update_merkle_root(path.as_ref(), claimed_old_root, new_root);

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

    // Read the coefficients from the stack (top 8 elements)
    let coef: [Felt; 8] = core::array::from_fn(|i| processor.stack().get(i));

    // Read the evaluation point alpha from memory
    let (alpha, k0, k1) = {
        let addr = processor.stack().get(ALPHA_ADDR_INDEX);
        let word = processor
            .memory()
            .read_word(ctx, addr, clk, err_ctx)
            .map_err(ExecutionError::MemoryError)?;
        tracer.record_memory_read_word(word, addr);

        (QuadFelt::new(word[0], word[1]), word[2], word[3])
    };

    // Read the current accumulator
    let acc_old =
        QuadFelt::new(processor.stack().get(ACC_LOW_INDEX), processor.stack().get(ACC_HIGH_INDEX));

    // Compute the temporary accumulator (first 4 coefficients)
    let acc_tmp = coef
        .iter()
        .rev()
        .take(4)
        .fold(acc_old, |acc, coef| QuadFelt::from(*coef) + alpha * acc);

    // Compute the final accumulator (remaining 4 coefficients)
    let acc_new = coef
        .iter()
        .rev()
        .skip(4)
        .fold(acc_tmp, |acc, coef| QuadFelt::from(*coef) + alpha * acc);

    // Update the accumulator values on the stack
    let acc_new_base_elements = acc_new.to_base_elements();
    processor.stack().set(ACC_HIGH_INDEX, acc_new_base_elements[1]);
    processor.stack().set(ACC_LOW_INDEX, acc_new_base_elements[0]);

    // Return the user operation helpers
    Ok(P::HelperRegisters::op_horner_eval_registers(alpha, k0, k1, acc_tmp))
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
        tracer.record_memory_read_word(word, addr);

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
