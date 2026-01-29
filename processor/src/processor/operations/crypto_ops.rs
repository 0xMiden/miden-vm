use alloc::boxed::Box;

use miden_air::trace::{
    decoder::NUM_USER_OP_HELPERS,
    log_precompile::{STATE_CAP_RANGE, STATE_RATE_0_RANGE, STATE_RATE_1_RANGE},
};
use miden_core::{
    Felt, Word, ZERO,
    chiplets::hasher::STATE_WIDTH,
    field::{BasedVectorSpace, PrimeField64, QuadFelt},
    mast::MastForest,
};

use super::{DOUBLE_WORD_SIZE, WORD_SIZE_FELT};
use crate::{
    ONE,
    errors::{CryptoError, MerklePathVerificationFailedInner, OperationError},
    fast::Tracer,
    operations::utils::validate_dual_word_stream_addrs,
    processor::{
        AdviceProviderInterface, HasherInterface, MemoryInterface, OperationHelperRegisters,
        Processor, StackInterface, SystemInterface,
    },
};

#[cfg(test)]
mod tests;

// CRYPTOGRAPHIC OPERATIONS
// ================================================================================================

/// Performs a hash permutation operation.
/// Applies Poseidon2 permutation to the top 12 elements of the stack.
///
/// Stack layout:
/// ```text
/// stack[0..4]   = R1 word (rate word 1)      → state[0..4]
/// stack[4..8]   = R2 word (rate word 2)      → state[4..8]
/// stack[8..12]  = CAP word (capacity)        → state[8..12]
/// ```
///
/// The top of the stack (`get(0)`) maps to `state[0]`, giving the sponge state
/// `[R1, R2, CAP]` where R1[0] is at the top of the stack.
#[inline(always)]
pub(super) fn op_hperm<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> [Felt; NUM_USER_OP_HELPERS] {
    // Build sponge state from stack: state[i] = stack.get(i)
    // Read first 8 elements using get_double_word, then remaining 4 elements
    let double_word: [Felt; 8] = processor.stack().get_double_word(0);
    let word: Word = processor.stack().get_word(8);
    let input_state: [Felt; STATE_WIDTH] = [
        double_word[0],
        double_word[1],
        double_word[2],
        double_word[3],
        double_word[4],
        double_word[5],
        double_word[6],
        double_word[7],
        word[0],
        word[1],
        word[2],
        word[3],
    ];

    // Apply Poseidon2 permutation
    let (addr, output_state) = processor.hasher().permute(input_state);

    // Write result back to stack (state[0] at top).
    let r0: Word = output_state[STATE_RATE_0_RANGE].try_into().expect("r0 slice has length 4");
    let r1: Word = output_state[STATE_RATE_1_RANGE].try_into().expect("r1 slice has length 4");
    let cap: Word = output_state[STATE_CAP_RANGE].try_into().expect("cap slice has length 4");
    processor.stack().set_word(0, &r0);
    processor.stack().set_word(4, &r1);
    processor.stack().set_word(8, &cap);

    tracer.record_hasher_permute(input_state, output_state);
    P::HelperRegisters::op_hperm_registers(addr)
}

/// Verifies that a Merkle path from the specified node resolves to the specified root. The
/// stack is expected to be arranged as follows (from the top):
/// - value of the node, 4 elements.
/// - depth of the node, 1 element; this is expected to be the depth of the Merkle tree
/// - index of the node, 1 element.
/// - root of the tree, 4 elements.
///
/// To perform the operation we do the following:
/// 1. Look up the Merkle path in the advice provider for the specified tree root.
/// 2. Use the hasher to compute the root of the Merkle path for the specified node.
/// 3. Verify that the computed root is equal to the root provided via the stack.
/// 4. Copy the stack state over to the next clock cycle with no changes.
///
/// # Errors
/// Returns an error if:
/// - Merkle tree for the specified root cannot be found in the advice provider.
/// - The specified depth is either zero or greater than the depth of the Merkle tree identified by
///   the specified root.
/// - Path to the node at the specified depth and index is not known to the advice provider.
#[inline(always)]
pub(super) fn op_mpverify<P: Processor>(
    processor: &mut P,
    err_code: Felt,
    program: &MastForest,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], CryptoError> {
    // read node value, depth, index and root value from the stack
    let node = processor.stack().get_word(0);
    let depth = processor.stack().get(4);
    let index = processor.stack().get(5);
    let root = processor.stack().get_word(6);

    // get a Merkle path from the advice provider for the specified root and node index
    let path = processor.advice_provider().get_merkle_path(root, depth, index)?;

    tracer.record_hasher_build_merkle_root(node, path.as_ref(), index, root);

    // verify the path
    let addr = processor.hasher().verify_merkle_root(root, node, path.as_ref(), index, || {
        // If the hasher doesn't compute the same root (using the same path),
        // then it means that `node` is not the value currently in the tree at `index`
        let err_msg = program.resolve_error_message(err_code);
        OperationError::MerklePathVerificationFailed {
            inner: Box::new(MerklePathVerificationFailedInner {
                value: node,
                index,
                root,
                err_code,
                err_msg,
            }),
        }
    })?;

    Ok(P::HelperRegisters::op_merkle_path_registers(addr))
}

/// Computes a new root of a Merkle tree where a node at the specified index is updated to
/// the specified value. The stack is expected to be arranged as follows (from the top):
/// - old value of the node, 4 elements.
/// - depth of the node, 1 element; this is expected to be the depth of the Merkle tree.
/// - index of the node, 1 element.
/// - current root of the tree, 4 elements.
/// - new value of the node, 4 elements.
///
/// To perform the operation we do the following:
/// 1. Update the node at the specified index in the Merkle tree with the specified root, and get
///    the Merkle path to it.
/// 2. Use the hasher to update the root of the Merkle path for the specified node. For this we need
///    to provide the old and the new node value.
/// 3. Verify that the computed old root is equal to the input root provided via the stack.
/// 4. Replace the old node value with the computed new root.
///
/// The Merkle path for the node is expected to be provided by the prover non-deterministically
/// (via the advice provider). At the end of the operation, the old node value is replaced with
/// the new roots value computed based on the provided path. Everything else on the stack
/// remains the same.
///
/// The original Merkle tree is cloned before the update is performed, and thus, after the
/// operation, the advice provider will keep track of both the old and the new trees.
///
/// # Errors
/// Returns an error if:
/// - Merkle tree for the specified root cannot be found in the advice provider.
/// - The specified depth is either zero or greater than the depth of the Merkle tree identified by
///   the specified root.
/// - Path to the node at the specified depth and index is not known to the advice provider.
#[inline(always)]
pub(super) fn op_mrupdate<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], CryptoError> {
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
    let path = processor.advice_provider().update_merkle_node(
        claimed_old_root,
        depth,
        index,
        new_value,
    )?;

    if let Some(path) = &path
        && path.len() != depth.as_canonical_u64() as usize
    {
        return Err(OperationError::InvalidMerklePathLength { path_len: path.len(), depth }.into());
    }

    let (addr, new_root) = processor.hasher().update_merkle_root(
        claimed_old_root,
        old_value,
        new_value,
        path.as_ref(),
        index,
        || OperationError::MerklePathVerificationFailed {
            inner: Box::new(MerklePathVerificationFailedInner {
                value: old_value,
                index,
                root: claimed_old_root,
                err_code: ZERO,
                err_msg: None,
            }),
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

    // Replace the old node value with computed new root.
    processor.stack().set_word(0, &new_root);

    Ok(P::HelperRegisters::op_merkle_path_registers(addr))
}

// HORNER-BASED POLYNOMIAL EVALUATION OPERATIONS
// ================================================================================================

/// Performs 8 steps of the Horner evaluation method on a polynomial with coefficients over
/// the base field using a 3-level computation to reduce constraint degree.
///
/// The computation processes 8 base field coefficients from the stack using Horner's method.
/// If we denote the values at stack positions 0..7 as `s[0]..s[7]`, the computation is:
///
/// - Level 1: tmp0 = (acc * α + s[0]) * α + s[1]
/// - Level 2: tmp1 = ((tmp0 * α + s[2]) * α + s[3]) * α + s[4]
/// - Level 3: acc' = ((tmp1 * α + s[5]) * α + s[6]) * α + s[7]
///
/// This evaluates the polynomial:
///
/// P(X) := s[0] * X^7 + s[1] * X^6 + s[2] * X^5 + s[3] * X^4 + s[4] * X^3 + s[5] * X^2 + s[6] * X +
/// s[7]
///
/// where s[0] is the highest-degree coefficient and s[7] is the constant term.
///
/// The instruction can be used to compute the evaluation of polynomials of arbitrary degree
/// by repeated invocations interleaved with any operation that loads the next batch of 8
/// coefficients on the top of the operand stack, i.e., `mem_stream` or `adv_pipe`.
///
/// The stack transition of the instruction can be visualized as follows:
///
/// Input:
///
/// +------+------+------+------+------+------+------+------+---+---+---+---+---+----------+------+------+
/// | s[0] | s[1] | s[2] | s[3] | s[4] | s[5] | s[6] | s[7] | - | - | - | - | - |alpha_addr| acc1 | acc0 |
/// +------+------+------+------+------+------+------+------+---+---+---+---+---+----------+------+------+
///   (X^7)  (X^6)  (X^5)  (X^4)  (X^3)  (X^2)  (X^1)  (X^0)
///
/// Output:
///
/// +------+------+------+------+------+------+------+------+---+---+---+---+---+----------+-------+-------+
/// | s[0] | s[1] | s[2] | s[3] | s[4] | s[5] | s[6] | s[7] | - | - | - | - | - |alpha_addr| acc1' | acc0' |
/// +------+------+------+------+------+------+------+------+---+---+---+---+---+----------+-------+-------+
///
/// Here:
///
/// 1. s[i] for i in 0..=7 is the coefficient at stack position i. s[0] is the highest-degree
///    coefficient (X^7) and s[7] is the constant term (X^0).
/// 2. (acc0, acc1) is a quadratic extension field element accumulating the Horner evaluation.
///    (acc0', acc1') is the updated accumulator after processing this batch.
/// 3. alpha_addr is the memory address of the evaluation point α = (α₀, α₁). The operation reads α₀
///    from alpha_addr and α₁ from alpha_addr + 1.
///
/// The instruction uses helper registers to store intermediate values:
/// - h₀, h₁: evaluation point α = (α₀, α₁)
/// - h₂, h₃: Level 2 intermediate result tmp1
/// - h₄, h₅: Level 1 intermediate result tmp0
#[inline(always)]
pub(super) fn op_horner_eval_base<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], crate::MemoryError> {
    // Stack positions: low coefficient closer to top (lower index)
    const ALPHA_ADDR_INDEX: usize = 13;
    const ACC_LOW_INDEX: usize = 14;
    const ACC_HIGH_INDEX: usize = 15;

    let clk = processor.system().clk();
    let ctx = processor.system().ctx();

    // Read the evaluation point alpha from memory
    let alpha = {
        let addr = processor.stack().get(ALPHA_ADDR_INDEX);
        let eval_point_0 = processor.memory().read_element(ctx, addr)?;
        let eval_point_1 = processor.memory().read_element(ctx, addr + ONE)?;

        tracer.record_memory_read_element(eval_point_0, addr, ctx, clk);

        tracer.record_memory_read_element(eval_point_1, addr + ONE, ctx, clk);

        QuadFelt::from_basis_coefficients_fn(|i: usize| [eval_point_0, eval_point_1][i])
    };

    // Read the coefficients from the stack (top 8 elements)
    let coef: [Felt; 8] = processor.stack().get_double_word(0);

    let c0 = QuadFelt::from(coef[0]);
    let c1 = QuadFelt::from(coef[1]);
    let c2 = QuadFelt::from(coef[2]);
    let c3 = QuadFelt::from(coef[3]);
    let c4 = QuadFelt::from(coef[4]);
    let c5 = QuadFelt::from(coef[5]);
    let c6 = QuadFelt::from(coef[6]);
    let c7 = QuadFelt::from(coef[7]);

    // Read the current accumulator (LE: low at lower index)
    let acc_low = processor.stack().get(ACC_LOW_INDEX);
    let acc_high = processor.stack().get(ACC_HIGH_INDEX);
    let acc = QuadFelt::from_basis_coefficients_fn(|i: usize| [acc_low, acc_high][i]);

    // Level 1: tmp0 = (acc * α + c₀) * α + c₁
    let tmp0 = (acc * alpha + c0) * alpha + c1;

    // Level 2: tmp1 = ((tmp0 * α + c₂) * α + c₃) * α + c₄
    let tmp1 = ((tmp0 * alpha + c2) * alpha + c3) * alpha + c4;

    // Level 3: acc' = ((tmp1 * α + c₅) * α + c₆) * α + c₇
    let acc_new = ((tmp1 * alpha + c5) * alpha + c6) * alpha + c7;

    // Update the accumulator values on the stack (LE: low at lower index)
    let acc_new_base_elements = acc_new.as_basis_coefficients_slice();
    processor.stack().set(ACC_HIGH_INDEX, acc_new_base_elements[1]);
    processor.stack().set(ACC_LOW_INDEX, acc_new_base_elements[0]);

    // Return the user operation helpers
    Ok(P::HelperRegisters::op_horner_eval_base_registers(alpha, tmp0, tmp1))
}

/// Performs 4 steps of the Horner evaluation method on a polynomial with coefficients over
/// the quadratic extension field.
///
/// The computation processes 4 extension field coefficients from the stack using Horner's method.
/// If we denote the QuadFelt values at stack positions (0,1), (2,3), (4,5), (6,7) as
/// `s[0]..s[3]`, the computation is:
///
/// - Level 1: acc_tmp = (acc * α + s[0]) * α + s[1]
/// - Level 2: acc' = ((acc_tmp * α + s[2]) * α + s[3]
///
/// This evaluates the polynomial:
///
/// P(X) := s[0] * X^3 + s[1] * X^2 + s[2] * X + s[3]
///
/// where s[0] is the highest-degree coefficient and s[3] is the constant term.
///
/// The instruction can be used to compute the evaluation of polynomials of arbitrary degree
/// by repeated invocations interleaved with any operation that loads the next batch of 4
/// coefficients on the top of the operand stack, i.e., `mem_stream` or `adv_pipe`.
///
/// The stack transition of the instruction can be visualized as follows:
///
/// Input:
///
/// +-------+-------+-------+-------+-------+-------+-------+-------+---+---+---+---+---+----------+------+------+
/// | s0_lo | s0_hi | s1_lo | s1_hi | s2_lo | s2_hi | s3_lo | s3_hi | - | - | - | - | - |alpha_addr| acc0 | acc1 |
/// +-------+-------+-------+-------+-------+-------+-------+-------+---+---+---+---+---+----------+------+------+
///   (X^3)           (X^2)           (X^1)           (X^0)
///
/// Output:
///
/// +-------+-------+-------+-------+-------+-------+-------+-------+---+---+---+---+---+----------+-------+-------+
/// | s0_lo | s0_hi | s1_lo | s1_hi | s2_lo | s2_hi | s3_lo | s3_hi | - | - | - | - | - |alpha_addr| acc0' | acc1' |
/// +-------+-------+-------+-------+-------+-------+-------+-------+---+---+---+---+---+----------+-------+-------+
///
/// Here:
///
/// 1. s[i] = (si_lo, si_hi) for i in 0..=3 is the extension field coefficient at stack position
///    2*i. s[0] is the highest-degree coefficient (X^3) and s[3] is the constant term (X^0).
/// 2. (acc0, acc1) is a quadratic extension field element accumulating the Horner evaluation.
///    (acc0', acc1') is the updated accumulator after processing this batch.
/// 3. alpha_addr is the memory address of the evaluation point α = (α₀, α₁).
///
/// The instruction uses helper registers to hold α and the intermediate value acc_tmp.
#[inline(always)]
pub(super) fn op_horner_eval_ext<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<[Felt; NUM_USER_OP_HELPERS], crate::MemoryError> {
    // Stack positions: low coefficient closer to top (lower index)
    const ALPHA_ADDR_INDEX: usize = 13;
    const ACC_LOW_INDEX: usize = 14;
    const ACC_HIGH_INDEX: usize = 15;

    let clk = processor.system().clk();
    let ctx = processor.system().ctx();

    // Read the coefficients from the stack as extension field elements (4 QuadFelt elements)
    // Stack layout: [s0_lo, s0_hi, s1_lo, s1_hi, s2_lo, s2_hi, s3_lo, s3_hi, ...]
    // s[0] at stack[0,1] is highest degree (X^3), s[3] at stack[6,7] is constant (X^0)
    let coef: [QuadFelt; 4] = core::array::from_fn(|j| {
        let lo = processor.stack().get(2 * j);
        let hi = processor.stack().get(2 * j + 1);
        QuadFelt::from_basis_coefficients_fn(|i: usize| [lo, hi][i])
    });

    // Read the evaluation point alpha from memory
    let (alpha, k0, k1) = {
        let addr = processor.stack().get(ALPHA_ADDR_INDEX);
        let word = processor.memory().read_word(ctx, addr, clk)?;
        tracer.record_memory_read_word(
            word,
            addr,
            processor.system().ctx(),
            processor.system().clk(),
        );

        (
            QuadFelt::from_basis_coefficients_fn(|i: usize| [word[0], word[1]][i]),
            word[2],
            word[3],
        )
    };

    // Read the current accumulator (LE: low at lower index)
    let acc_low = processor.stack().get(ACC_LOW_INDEX);
    let acc_high = processor.stack().get(ACC_HIGH_INDEX);
    let acc_old = QuadFelt::from_basis_coefficients_fn(|i: usize| [acc_low, acc_high][i]);

    // Compute the temporary accumulator (first 2 coefficients from stack)
    // Process coef[0], coef[1] (highest degree coefficients)
    let acc_tmp = coef.iter().take(2).fold(acc_old, |acc, coef| *coef + alpha * acc);

    // Compute the final accumulator (remaining 2 coefficients)
    // Process coef[2], coef[3] (lower degree coefficients)
    let acc_new = coef.iter().skip(2).fold(acc_tmp, |acc, coef| *coef + alpha * acc);

    // Update the accumulator values on the stack (LE: low at lower index)
    let acc_new_base_elements = acc_new.as_basis_coefficients_slice();
    processor.stack().set(ACC_HIGH_INDEX, acc_new_base_elements[1]);
    processor.stack().set(ACC_LOW_INDEX, acc_new_base_elements[0]);

    // Return the user operation helpers
    Ok(P::HelperRegisters::op_horner_eval_ext_registers(alpha, k0, k1, acc_tmp))
}

// LOG PRECOMPILE OPERATION
// ================================================================================================

/// Logs a precompile event by absorbing `TAG` and `COMM` into the precompile sponge
/// capacity.
///
/// Stack transition:
/// `[COMM, TAG, PAD, ...] -> [R0, R1, CAP_NEXT, ...]`
///
/// Where:
/// - The hasher computes: `[R0, R1, CAP_NEXT] = Poseidon2([COMM, TAG, CAP_PREV])`
/// - `CAP_PREV` is the previous sponge capacity provided non-deterministically via helper
///   registers.
/// - Stack elements are in LSB-first order (structural order).
#[inline(always)]
pub(super) fn op_log_precompile<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> [Felt; NUM_USER_OP_HELPERS] {
    // Read COMM and TAG from the stack
    let comm: Word = processor.stack().get_word(0);
    let tag: Word = processor.stack().get_word(4);

    // Get the current precompile sponge capacity
    let cap_prev = processor.precompile_transcript_state();

    // Build the full 12-element hasher state for Poseidon2 permutation
    // State layout: [RATE0 = COMM, RATE1 = TAG, CAPACITY = CAP_PREV]
    let mut hasher_state: [Felt; STATE_WIDTH] = [ZERO; 12];
    hasher_state[STATE_RATE_0_RANGE].copy_from_slice(comm.as_slice());
    hasher_state[STATE_RATE_1_RANGE].copy_from_slice(tag.as_slice());
    hasher_state[STATE_CAP_RANGE].copy_from_slice(cap_prev.as_slice());

    // Perform the Poseidon2 permutation
    let (addr, output_state) = processor.hasher().permute(hasher_state);

    // Extract R0, R1 and CAP_NEXT from the output state
    let r0: Word = output_state[STATE_RATE_0_RANGE.clone()]
        .try_into()
        .expect("r0 slice has length 4");
    let r1: Word = output_state[STATE_RATE_1_RANGE.clone()]
        .try_into()
        .expect("r1 slice has length 4");
    let cap_next: Word = output_state[STATE_CAP_RANGE.clone()]
        .try_into()
        .expect("cap_next slice has length 4");

    // Update the processor's precompile sponge capacity
    processor.set_precompile_transcript_state(cap_next);

    // Write the output to the stack (top 12 elements): [R0, R1, CAP_NEXT, ...].
    processor.stack().set_word(0, &r0);
    processor.stack().set_word(4, &r1);
    processor.stack().set_word(8, &cap_next);

    // Record the hasher permutation for trace generation
    tracer.record_hasher_permute(hasher_state, output_state);

    // Return helper registers containing the hasher address and CAP_PREV
    P::HelperRegisters::op_log_precompile_registers(addr, cap_prev)
}

// STREAM CIPHER OPERATION
// ================================================================================================

/// Encrypts data from source memory to destination memory using Poseidon2 sponge keystream.
///
/// This operation performs AEAD encryption by:
/// 1. Loading 8 elements (2 words) from source memory at stack[12]
/// 2. Adding each element to the corresponding rate element (stack[0..7])
/// 3. Writing the resulting ciphertext to destination memory at stack[13]
/// 4. Updating stack[0..7] with the ciphertext (becomes new rate for next hperm)
/// 5. Preserving capacity (stack[8..11])
/// 6. Incrementing both source and destination pointers by 8
///
/// Stack transition:
/// [rate(8), cap(4), src_ptr, dst_ptr, ...] -> [ciphertext(8), cap(4), src_ptr+8, dst_ptr+8,
/// ...]
#[inline(always)]
pub(super) fn op_crypto_stream<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<(), crate::MemoryError> {
    // Stack layout: [rate(8), capacity(4), src_ptr, dst_ptr, ...]
    const SRC_PTR_IDX: usize = 12;
    const DST_PTR_IDX: usize = 13;

    let ctx = processor.system().ctx();
    let clk = processor.system().clk();

    // Get source and destination pointers
    let src_addr = processor.stack().get(SRC_PTR_IDX);
    let dst_addr = processor.stack().get(DST_PTR_IDX);

    // Validate address ranges and check for overlap using half-open intervals.
    validate_dual_word_stream_addrs(src_addr, dst_addr, ctx, clk)?;

    // Load plaintext from source memory (2 words = 8 elements)
    let src_addr_word2 = src_addr + WORD_SIZE_FELT;
    let plaintext_word1 = processor.memory().read_word(ctx, src_addr, clk)?;
    tracer.record_memory_read_word(plaintext_word1, src_addr, ctx, clk);

    let plaintext_word2 = processor.memory().read_word(ctx, src_addr_word2, clk)?;
    tracer.record_memory_read_word(plaintext_word2, src_addr_word2, ctx, clk);

    // Get rate (keystream) from stack[0..7]
    let rate: [Felt; 8] = processor.stack().get_double_word(0);

    // Encrypt: ciphertext = plaintext + rate (element-wise addition in field)
    let ciphertext_word1 = [
        plaintext_word1[0] + rate[0],
        plaintext_word1[1] + rate[1],
        plaintext_word1[2] + rate[2],
        plaintext_word1[3] + rate[3],
    ]
    .into();
    let ciphertext_word2 = [
        plaintext_word2[0] + rate[4],
        plaintext_word2[1] + rate[5],
        plaintext_word2[2] + rate[6],
        plaintext_word2[3] + rate[7],
    ]
    .into();

    // Write ciphertext to destination memory
    let dst_addr_word2 = dst_addr + WORD_SIZE_FELT;
    processor.memory().write_word(ctx, dst_addr, clk, ciphertext_word1)?;
    tracer.record_memory_write_word(ciphertext_word1, dst_addr, ctx, clk);

    processor.memory().write_word(ctx, dst_addr_word2, clk, ciphertext_word2)?;
    tracer.record_memory_write_word(ciphertext_word2, dst_addr_word2, ctx, clk);

    // Update stack[0..7] with ciphertext (becomes new rate for next hperm)
    processor.stack().set_word(0, &ciphertext_word1);
    processor.stack().set_word(4, &ciphertext_word2);

    // Increment pointers by 8 (2 words)
    processor.stack().set(SRC_PTR_IDX, src_addr + DOUBLE_WORD_SIZE);
    processor.stack().set(DST_PTR_IDX, dst_addr + DOUBLE_WORD_SIZE);

    Ok(())
}
