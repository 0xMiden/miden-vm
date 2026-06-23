use alloc::boxed::Box;

use miden_air::trace::chiplets::hasher::{Hasher, STATE_WIDTH};
use miden_core::chiplets::blakeg;

use super::{DOUBLE_WORD_SIZE, WORD_SIZE_FELT};
use crate::{
    BaseHost, ContextId, ExecutionError, Felt, MemoryError, ONE, RowIndex, Word, ZERO,
    errors::{
        CryptoError, MapExecErrWithOpIdx, MerklePathVerificationFailedInner, OperationError,
        PackageSourceDebugContext,
    },
    field::{BasedVectorSpace, QuadFelt},
    processor::{
        AdviceProviderInterface, HasherInterface, MemoryInterface, Processor, StackInterface,
        SystemInterface,
    },
    tracer::{OperationHelperRegisters, Tracer},
};

#[cfg(test)]
mod tests;

// CRYPTOGRAPHIC OPERATIONS
// ================================================================================================

/// Reads the 12-element BlakeG state window from the top of the stack.
#[inline(always)]
fn read_hasher_state<P: Processor>(processor: &P) -> [Felt; STATE_WIDTH] {
    let double_word: [Felt; 8] = processor.stack().get_double_word(0);
    let word: Word = processor.stack().get_word(8);
    [
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
    ]
}

/// Applies one BlakeG compression and writes only the next chaining value.
///
/// Stack transition: `[block(8), cv(4), ...] -> [block(8), cv'(4), ...]`.
#[inline(always)]
pub(super) fn op_bcompress<P: Processor, T: Tracer>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, OperationError> {
    let input_state = read_hasher_state(processor);
    let (addr, output_state) = processor.hasher().bcompress(input_state)?;

    let cv_next: Word = output_state[Hasher::DIGEST_RANGE]
        .try_into()
        .expect("digest slice has length 4");
    processor.stack_mut().set_word(8, &cv_next);

    tracer.record_hasher_bcompress(input_state, output_state);
    Ok(OperationHelperRegisters::BCompress { addr })
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
pub(super) fn op_mpverify<P: Processor, T: Tracer>(
    processor: &mut P,
    err_code: Felt,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, CryptoError> {
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
        OperationError::MerklePathVerificationFailed {
            inner: Box::new(MerklePathVerificationFailedInner {
                value: node,
                index,
                root,
                err_code,
                err_msg: None,
            }),
        }
    })?;

    Ok(OperationHelperRegisters::MerklePath { addr })
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
pub(super) fn op_mrupdate<P: Processor, T: Tracer>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, CryptoError> {
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
    let path = processor.advice_provider_mut().update_merkle_node(
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
    processor.stack_mut().set_word(0, &new_root);

    Ok(OperationHelperRegisters::MerklePath { addr })
}

// HORNER-BASED POLYNOMIAL EVALUATION OPERATIONS
// ================================================================================================

/// Performs 8 steps of the Horner evaluation method on a polynomial with coefficients over
/// the base field using a 3-level computation to reduce constraint degree.
///
/// The computation processes 8 base field coefficients from the stack using Horner's method.
/// If we denote the values at stack positions 0..7 as `s[0]..s[7]`, the computation is:
///
/// - Level 1: tmp0 = (acc * alpha + s[0]) * alpha + s[1]
/// - Level 2: tmp1 = ((tmp0 * alpha + s[2]) * alpha + s[3]) * alpha + s[4]
/// - Level 3: acc' = ((tmp1 * alpha + s[5]) * alpha + s[6]) * alpha + s[7]
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
/// 3. alpha_addr is the memory address of the evaluation point alpha = (alpha0, alpha1). The
///    operation reads alpha0 from alpha_addr and alpha1 from alpha_addr + 1.
///
/// The instruction uses helper registers to store intermediate values:
/// - h0, h1: evaluation point alpha = (alpha0, alpha1)
/// - h2, h3: Level 2 intermediate result tmp1
/// - h4, h5: Level 1 intermediate result tmp0
#[inline(always)]
pub(super) fn op_horner_eval_base<P: Processor, T: Tracer>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, MemoryError> {
    // Stack positions: low coefficient closer to top (lower index)
    const ALPHA_ADDR_INDEX: usize = 13;
    const ACC_LOW_INDEX: usize = 14;
    const ACC_HIGH_INDEX: usize = 15;

    let clk = processor.system().clock();
    let ctx = processor.system().ctx();

    // Read the evaluation point alpha from memory
    let alpha = {
        let addr = processor.stack().get(ALPHA_ADDR_INDEX);
        let eval_point_0 = processor.memory_mut().read_element(ctx, addr)?;
        let eval_point_1 = processor.memory_mut().read_element(ctx, addr + ONE)?;

        tracer.record_memory_read_element_pair(
            eval_point_0,
            addr,
            eval_point_1,
            addr + ONE,
            ctx,
            clk,
        );

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

    // Level 1: tmp0 = (acc * alpha + c0) * alpha + c1
    let tmp0 = (acc * alpha + c0) * alpha + c1;

    // Level 2: tmp1 = ((tmp0 * alpha + c2) * alpha + c3) * alpha + c4
    let tmp1 = ((tmp0 * alpha + c2) * alpha + c3) * alpha + c4;

    // Level 3: acc' = ((tmp1 * alpha + c5) * alpha + c6) * alpha + c7
    let acc_new = ((tmp1 * alpha + c5) * alpha + c6) * alpha + c7;

    // Update the accumulator values on the stack (LE: low at lower index)
    let acc_new_base_elements = acc_new.as_basis_coefficients_slice();
    processor.stack_mut().set(ACC_HIGH_INDEX, acc_new_base_elements[1]);
    processor.stack_mut().set(ACC_LOW_INDEX, acc_new_base_elements[0]);

    // Return the user operation helpers
    Ok(OperationHelperRegisters::HornerEvalBase { alpha, tmp0, tmp1 })
}

/// Performs 4 steps of the Horner evaluation method on a polynomial with coefficients over
/// the quadratic extension field.
///
/// The computation processes 4 extension field coefficients from the stack using Horner's method.
/// If we denote the QuadFelt values at stack positions (0,1), (2,3), (4,5), (6,7) as
/// `s[0]..s[3]`, the computation is:
///
/// - Level 1: acc_tmp = (acc * alpha + s[0]) * alpha + s[1]
/// - Level 2: acc' = ((acc_tmp * alpha + s[2]) * alpha + s[3]
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
/// 3. alpha_addr is the memory address of the evaluation point alpha = (alpha0, alpha1).
///
/// The instruction uses helper registers to hold alpha and the intermediate value acc_tmp.
#[inline(always)]
pub(super) fn op_horner_eval_ext<P: Processor, T: Tracer>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, MemoryError> {
    // Stack positions: low coefficient closer to top (lower index)
    const ALPHA_ADDR_INDEX: usize = 13;
    const ACC_LOW_INDEX: usize = 14;
    const ACC_HIGH_INDEX: usize = 15;

    let clk = processor.system().clock();
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
        let word = processor.memory_mut().read_word(ctx, addr, clk)?;
        tracer.record_memory_read_word(
            word,
            addr,
            processor.system().ctx(),
            processor.system().clock(),
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
    processor.stack_mut().set(ACC_HIGH_INDEX, acc_new_base_elements[1]);
    processor.stack_mut().set(ACC_LOW_INDEX, acc_new_base_elements[0]);

    // Return the user operation helpers
    Ok(OperationHelperRegisters::HornerEvalExt { alpha, k0, k1, acc_tmp })
}

// LOG PRECOMPILE OPERATION
// ================================================================================================

/// Folds a precomputed statement into the rolling precompile-transcript state.
///
/// Stack transition:
/// `[_, STMNT, ...] -> [STATE_NEW, STMNT, ...]`
///
/// - Hasher computes `merge(STATE_PREV, STMNT)` with the Eidos two-to-one chaining value;
///   `STATE_NEW` is the digest word of the output.
/// - `STATE_PREV` is the previous rolling state, threaded internally and exposed to constraints via
///   helper registers.
/// - `STMNT` lives at stack[4..8] so the chiplet bus's beta^6..beta^9 products share with BCOMPRESS.
#[inline(always)]
pub(super) fn op_log_precompile<P: Processor, T: Tracer>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, OperationError> {
    let stmnt: Word = processor.stack().get_word(4);
    let state_prev = processor.system().precompile_transcript_state();

    // Hasher input: [STATE_PREV, STMNT, Eidos merge CV].
    let mut hasher_state: [Felt; STATE_WIDTH] = [ZERO; 12];
    hasher_state[Hasher::RATE0_RANGE].copy_from_slice(state_prev.as_slice());
    hasher_state[Hasher::RATE1_RANGE].copy_from_slice(stmnt.as_slice());
    hasher_state[Hasher::CAPACITY_RANGE]
        .copy_from_slice(blakeg::two_to_one_chaining_word(0).as_slice());

    let (addr, output_state) = processor.hasher().bcompress(hasher_state)?;

    let state_new: Word = output_state[Hasher::DIGEST_RANGE].try_into().unwrap();

    processor.system_mut().set_precompile_transcript_state(state_new);

    processor.stack_mut().set_word(0, &state_new);

    tracer.record_hasher_bcompress(hasher_state, output_state);

    Ok(OperationHelperRegisters::LogPrecompile { addr, state_prev })
}

// STREAM CIPHER OPERATION
// ================================================================================================

#[derive(Debug)]
pub(super) enum AeadStreamError {
    Memory(MemoryError),
    Operation(OperationError),
}

impl From<MemoryError> for AeadStreamError {
    fn from(err: MemoryError) -> Self {
        Self::Memory(err)
    }
}

impl From<OperationError> for AeadStreamError {
    fn from(err: OperationError) -> Self {
        Self::Operation(err)
    }
}

impl<T> MapExecErrWithOpIdx<T> for Result<T, AeadStreamError> {
    fn map_exec_err_with_op_idx(self) -> Result<T, ExecutionError> {
        match self {
            Ok(result) => Ok(result),
            Err(AeadStreamError::Memory(err)) => {
                Result::<T, MemoryError>::Err(err).map_exec_err_with_op_idx()
            },
            Err(AeadStreamError::Operation(err)) => {
                Result::<T, OperationError>::Err(err).map_exec_err_with_op_idx()
            },
        }
    }

    fn map_exec_err_with_package_source_op_idx(
        self,
        context: Option<PackageSourceDebugContext<'_>>,
        host: &impl BaseHost,
        op_idx: usize,
    ) -> Result<T, ExecutionError> {
        match self {
            Ok(result) => Ok(result),
            Err(AeadStreamError::Memory(err)) => Result::<T, MemoryError>::Err(err)
                .map_exec_err_with_package_source_op_idx(context, host, op_idx),
            Err(AeadStreamError::Operation(err)) => Result::<T, OperationError>::Err(err)
                .map_exec_err_with_package_source_op_idx(context, host, op_idx),
        }
    }
}

/// Encrypts two memory words with a BlakeG-XOF keystream.
///
/// Stack transition:
/// `[K_CTR(4), counter, src_ptr, dst_ptr, remaining, ...]`
/// to `[K_CTR(4), counter+1, src_ptr+8, dst_ptr+16, remaining-1, ...]`.
#[inline(always)]
pub(super) fn op_aead_stream<P: Processor, T: Tracer>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, AeadStreamError> {
    const K_CTR_IDX: usize = 0;
    const COUNTER_IDX: usize = 4;
    const SRC_PTR_IDX: usize = 5;
    const DST_PTR_IDX: usize = 6;
    const REMAINING_IDX: usize = 7;

    let ctx = processor.system().ctx();
    let clk = processor.system().clock();

    let k_ctr = processor.stack().get_word(K_CTR_IDX);
    let counter = processor.stack().get(COUNTER_IDX);
    let src_addr = processor.stack().get(SRC_PTR_IDX);
    let dst_addr = processor.stack().get(DST_PTR_IDX);
    let counter_next = counter + ONE;
    let remaining_next = processor.stack().get(REMAINING_IDX) - ONE;

    let input_state = [
        counter, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, k_ctr[0], k_ctr[1], k_ctr[2], k_ctr[3],
    ];
    let keystream = processor.hasher().compress_aead_xof(ctx, clk, input_state)?;
    tracer.record_hasher_aead_xof(ctx, clk, input_state);

    validate_aead_stream_addrs(src_addr, dst_addr, ctx, clk)?;

    // Each 4-row stream half emits a read interaction, so the trace records each source word twice.
    let plaintext0 = processor.memory_mut().read_word(ctx, src_addr, clk)?;
    let plaintext0_dup = processor.memory_mut().read_word(ctx, src_addr, clk)?;
    let plaintext1 = processor.memory_mut().read_word(ctx, src_addr + WORD_SIZE_FELT, clk)?;
    let plaintext1_dup = processor.memory_mut().read_word(ctx, src_addr + WORD_SIZE_FELT, clk)?;
    debug_assert_eq!(plaintext0, plaintext0_dup);
    debug_assert_eq!(plaintext1, plaintext1_dup);
    let plaintext = [plaintext0, plaintext1];

    let mut ciphertext = [ZERO; 16];
    for i in 0..8 {
        let (lo, hi) = blakeg::unpack(plaintext[i / 4][i % 4]);
        ciphertext[2 * i] = Felt::from_u32(lo ^ keystream[2 * i].as_canonical_u64() as u32);
        ciphertext[2 * i + 1] = Felt::from_u32(hi ^ keystream[2 * i + 1].as_canonical_u64() as u32);
    }

    for word_idx in 0..4 {
        let base = 4 * word_idx;
        let word: Word = [
            ciphertext[base],
            ciphertext[base + 1],
            ciphertext[base + 2],
            ciphertext[base + 3],
        ]
        .into();
        processor.memory_mut().write_word(
            ctx,
            dst_addr + Felt::new_unchecked((4 * word_idx) as u64),
            clk,
            word,
        )?;
    }

    tracer.record_aead_stream(plaintext, src_addr, keystream, ciphertext, dst_addr, ctx, clk);

    processor.stack_mut().set(COUNTER_IDX, counter_next);
    processor.stack_mut().set(SRC_PTR_IDX, src_addr + DOUBLE_WORD_SIZE);
    processor.stack_mut().set(DST_PTR_IDX, dst_addr + Felt::new_unchecked(16));
    processor.stack_mut().set(REMAINING_IDX, remaining_next);

    Ok(OperationHelperRegisters::Empty)
}

/// Validates the source and destination ranges used by `aead_stream`.
///
/// The source range is `[src, src+8)`, and the destination range is `[dst, dst+16)`.
#[inline(always)]
fn validate_aead_stream_addrs(
    src_addr: Felt,
    dst_addr: Felt,
    ctx: ContextId,
    clk: RowIndex,
) -> Result<(), MemoryError> {
    // Convert to u32 and check end-exclusive bounds.
    let src_addr_u64 = src_addr.as_canonical_u64();
    let dst_addr_u64 = dst_addr.as_canonical_u64();

    let src_addr_u32 = u32::try_from(src_addr_u64)
        .map_err(|_| MemoryError::AddressOutOfBounds { addr: src_addr_u64 })?;
    let src_end = src_addr_u32
        .checked_add(8)
        .ok_or(MemoryError::AddressOutOfBounds { addr: src_addr_u64 })?;

    let dst_addr_u32 = u32::try_from(dst_addr_u64)
        .map_err(|_| MemoryError::AddressOutOfBounds { addr: dst_addr_u64 })?;
    let dst_end = dst_addr_u32
        .checked_add(16)
        .ok_or(MemoryError::AddressOutOfBounds { addr: dst_addr_u64 })?;

    if src_addr_u32 < dst_end && dst_addr_u32 < src_end {
        let offending_addr = [dst_addr_u32, dst_addr_u32 + 4, dst_addr_u32 + 8, dst_addr_u32 + 12]
            .into_iter()
            .find(|addr| *addr >= src_addr_u32 && *addr < src_end)
            .unwrap_or(dst_addr_u32);
        return Err(MemoryError::IllegalMemoryAccess {
            ctx,
            addr: offending_addr,
            clk: Felt::from(clk),
        });
    }

    Ok(())
}
