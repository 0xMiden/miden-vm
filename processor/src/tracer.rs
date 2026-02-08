use alloc::sync::Arc;

use miden_air::trace::{RowIndex, chiplets::hasher::STATE_WIDTH, decoder::NUM_USER_OP_HELPERS};
use miden_core::{
    Felt, Word, ZERO,
    crypto::merkle::MerklePath,
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64, QuadFelt},
    mast::{MastForest, MastNodeId},
};

use crate::{
    ContextId,
    continuation_stack::{Continuation, ContinuationStack},
    trace::{chiplets::CircuitEvaluation, utils::split_u32_into_u16},
};

// TRACER TRAIT
// ================================================================================================

/// A trait for tracing the execution of a processor.
///
/// Allows for recording different aspects of the processor's execution. For example, the
/// [`crate::FastProcessor::execute_for_trace`] execution mode needs to build a
/// [`crate::fast::execution_tracer::TraceGenerationContext`] which records information necessary to
/// build the trace at each clock cycle.
///
/// A useful mental model to differentiate between the processor and the tracer is:
/// - Processor: maintains and mutates the state of the VM components (system, stack, memory, etc)
///   as execution progresses
/// - Tracer: records auxiliary information *derived from* the processor state
pub trait Tracer {
    type Processor;

    /// Signals the start of a new clock cycle, guaranteed to be called at the start of the clock
    /// cycle, before any mutations to the processor state is made. For example, it is safe to
    /// access the processor's stack and memory state as they are before executing the operation at
    /// the current clock cycle.
    ///
    /// `continuation` represents what is to be executed at the beginning of this clock cycle, while
    /// `continuation_stack` represents whatever comes after execution `continuation`.
    ///
    /// The following continuations do not occur at the start of a clock cycle, and hence will never
    /// be passed to this method:
    /// - Continuation::FinishExternal: because external nodes are resolved before starting a clock
    ///   cycle,
    /// - Continuation::EnterForest: because entering a new forest does not consume a clock cycle,
    /// - Continuation::AfterExitDecorators and Continuation::AfterExitDecoratorsBasicBlock: because
    ///   after-exit decorators are executed at the end of an `END` operation; never at the start of
    ///   a clock cycle
    ///
    /// Additionally, [miden_core::mast::ExternalNode] nodes are guaranteed to be resolved before
    /// this method is called.
    fn start_clock_cycle(
        &mut self,
        processor: &Self::Processor,
        continuation: Continuation,
        continuation_stack: &ContinuationStack,
        current_forest: &Arc<MastForest>,
    );

    /// Signals the end of a clock cycle, guaranteed to be called before incrementing the system
    /// clock, and after all mutations to the processor state have been applied.
    ///
    /// Implementations should use this method to finalize any tracing information related to the
    /// just-completed clock cycle.
    ///
    /// The `current_forest` parameter is guaranteed to be the same as the one passed to
    /// [Tracer::start_clock_cycle] for the same clock cycle.
    fn finalize_clock_cycle(
        &mut self,
        processor: &Self::Processor,
        op_helper_registers: OperationHelperRegisters,
        current_forest: &Arc<MastForest>,
    );

    /// Records and replays the resolutions of [crate::host::Host::get_mast_forest].
    ///
    /// Note that when execution encounters a [miden_core::mast::ExternalNode], the external node
    /// gets resolved to the MAST node it refers to in the new MAST forest, without consuming the
    /// clock cycle (or writing anything to the trace). Hence, a clock cycle where execution
    /// encounters an external node effectively has 2 nodes associated with it.
    /// [Tracer::start_clock_cycle] is called on the resolved node (i.e. *not* the external node).
    /// This method is called on the external node before it is resolved, and hence is guaranteed to
    /// be called before [Tracer::start_clock_cycle] for clock cycles involving an external node.
    fn record_mast_forest_resolution(&mut self, node_id: MastNodeId, forest: &Arc<MastForest>);

    // HASHER METHODS
    // --------------------------------------------------------------------------------------------

    /// Records the result of a call to `Hasher::permute()`.
    fn record_hasher_permute(
        &mut self,
        input_state: [Felt; STATE_WIDTH],
        output_state: [Felt; STATE_WIDTH],
    );

    /// Records the result of a call to `Hasher::build_merkle_root()`.
    ///
    /// The `path` is an `Option` to support environments where the `Hasher` is not present, such as
    /// in the context of parallel trace generation.
    fn record_hasher_build_merkle_root(
        &mut self,
        node: Word,
        path: Option<&MerklePath>,
        index: Felt,
        output_root: Word,
    );

    /// Records the result of a call to `Hasher::update_merkle_root()`.
    ///
    /// The `path` is an `Option` to support environments where the `Hasher` is not present, such as
    /// in the context of parallel trace generation.
    fn record_hasher_update_merkle_root(
        &mut self,
        old_value: Word,
        new_value: Word,
        path: Option<&MerklePath>,
        index: Felt,
        old_root: Word,
        new_root: Word,
    );

    // MEMORY METHODS
    // --------------------------------------------------------------------------------------------

    /// Records the element read from memory at the given address.
    fn record_memory_read_element(
        &mut self,
        element: Felt,
        addr: Felt,
        ctx: ContextId,
        clk: RowIndex,
    );

    /// Records the word read from memory at the given address.
    fn record_memory_read_word(&mut self, word: Word, addr: Felt, ctx: ContextId, clk: RowIndex);

    /// Records the element written to memory at the given address.
    fn record_memory_write_element(
        &mut self,
        element: Felt,
        addr: Felt,
        ctx: ContextId,
        clk: RowIndex,
    );

    /// Records the word written to memory at the given address.
    fn record_memory_write_word(&mut self, word: Word, addr: Felt, ctx: ContextId, clk: RowIndex);

    // ADVICE PROVIDER METHODS
    // --------------------------------------------------------------------------------------------

    /// Records the value returned by a [crate::host::advice::AdviceProvider::pop_stack] operation.
    fn record_advice_pop_stack(&mut self, value: Felt);
    /// Records the value returned by a [crate::host::advice::AdviceProvider::pop_stack_word]
    /// operation.
    fn record_advice_pop_stack_word(&mut self, word: Word);
    /// Records the value returned by a [crate::host::advice::AdviceProvider::pop_stack_dword]
    /// operation.
    fn record_advice_pop_stack_dword(&mut self, words: [Word; 2]);

    // U32 METHODS
    // --------------------------------------------------------------------------------------------

    /// Records the operands of a u32and operation.
    fn record_u32and(&mut self, a: Felt, b: Felt);

    /// Records the operands of a u32xor operation.
    fn record_u32xor(&mut self, a: Felt, b: Felt);

    /// Records the high and low 32-bit limbs of the result of a u32 operation for the purposes of
    /// the range checker. This is expected to result in four 16-bit range checks.
    fn record_u32_range_checks(&mut self, clk: RowIndex, u32_lo: Felt, u32_hi: Felt);

    // KERNEL METHODS
    // --------------------------------------------------------------------------------------------

    /// Records the procedure hash of a syscall.
    fn record_kernel_proc_access(&mut self, proc_hash: Word);

    // ACE CHIPLET METHODS
    // --------------------------------------------------------------------------------------------

    /// Records the evaluation of a circuit.
    fn record_circuit_evaluation(&mut self, clk: RowIndex, circuit_eval: CircuitEvaluation);

    // MISCELLANEOUS
    // --------------------------------------------------------------------------------------------

    /// Signals that the stack depth is incremented as a result of pushing a new element.
    fn increment_stack_size(&mut self, processor: &Self::Processor);

    /// Signals that the stack depth is decremented as a result of popping an element off the stack.
    ///
    /// Note that if the stack depth is already [miden_core::program::MIN_STACK_DEPTH], then the
    /// stack depth is unchanged; the top element is popped off, and a ZERO is shifted in at the
    /// bottom.
    fn decrement_stack_size(&mut self);

    /// Signals the start of a new execution context, as a result of a CALL, SYSCALL or DYNCALL
    /// operation being executed.
    fn start_context(&mut self);

    /// Signals the end of an execution context, as a result of an END operation associated with a
    /// CALL, SYSCALL or DYNCALL.
    fn restore_context(&mut self);
}

// OPERATION HELPER REGISTERS
// ================================================================================================

/// Captures the auxiliary values produced by an operation that are needed to populate the
/// "user operation helper" columns of the execution trace.
///
/// Most operations do not require helper registers and use [`Empty`](Self::Empty). For those
/// that do, the variant records the minimal set of values from which
/// [`to_user_op_helpers`](Self::to_user_op_helpers) can derive the full
/// `[Felt; NUM_USER_OP_HELPERS]` array written into the trace.
#[derive(Debug, Clone)]
pub enum OperationHelperRegisters {
    /// Helper for the `EQ` operation, which pops two stack elements and pushes ONE if they are
    /// equal, ZERO otherwise.
    ///
    /// - `stack_second`: the element at stack position 1 (i.e. the second element) *before* the
    ///   operation.
    /// - `stack_first`: the element at stack position 0 (i.e. the top element) *before* the
    ///   operation.
    ///
    /// The helper register is set to `(stack_first - stack_second)^{-1}` when the values differ,
    /// or ZERO when they are equal.
    Eq { stack_second: Felt, stack_first: Felt },
    /// Helper for the `U32SPLIT` operation, which splits a field element into its low and high
    /// 32-bit limbs.
    ///
    /// - `lo`: the low 32-bit limb of the top stack element.
    /// - `hi`: the high 32-bit limb of the top stack element.
    ///
    /// The helper registers are populated with the four 16-bit limbs of `lo` and `hi` (used for
    /// range checking), plus the overflow flag `(u32::MAX - hi)^{-1}`.
    U32Split { lo: Felt, hi: Felt },
    /// Helper for the `EQZ` operation, which pushes ONE if the top element is zero, ZERO
    /// otherwise.
    ///
    /// - `top`: the value at the top of the stack *before* the operation.
    ///
    /// The helper register is set to `top^{-1}` when `top` is nonzero, or ZERO when `top` is
    /// zero.
    Eqz { top: Felt },
    /// Helper for the `EXPACC` operation, which performs a single step of binary exponentiation.
    ///
    /// - `acc_update_val`: the value by which the accumulator is multiplied in this step. Equals
    ///   `base` when the least-significant bit of the exponent is 1, or ONE otherwise.
    Expacc { acc_update_val: Felt },
    /// Helper for the `FRI_EXT2FOLD4` operation, which folds 4 query values during a FRI layer
    /// reduction.
    ///
    /// - `ev`: evaluation point `alpha / x`, where `alpha` is the verifier challenge and `x` is the
    ///   domain point.
    /// - `es`: `ev^2`, i.e. `(alpha / x)^2`.
    /// - `x`: the domain point, computed as `poe * tau_factor * DOMAIN_OFFSET`.
    /// - `x_inv`: the multiplicative inverse of `x`.
    FriExt2Fold4 {
        ev: QuadFelt,
        es: QuadFelt,
        x: Felt,
        x_inv: Felt,
    },
    /// Helper for the `U32ADD` operation, which adds two u32 values and splits the result into
    /// a 32-bit sum and a carry bit.
    ///
    /// - `sum`: the low 32-bit part of `a + b`.
    /// - `carry`: the high 32-bit part of `a + b` (0 or 1).
    ///
    /// The helper registers hold the four 16-bit limbs of `sum` and `carry`.
    U32Add { sum: Felt, carry: Felt },
    /// Helper for the `U32ADD3` operation, which adds three u32 values and splits the result
    /// into a 32-bit sum and a carry.
    ///
    /// - `sum`: the low 32-bit part of `a + b + c`.
    /// - `carry`: the high 32-bit part of `a + b + c`.
    ///
    /// The helper registers hold the four 16-bit limbs of `sum` and `carry`.
    U32Add3 { sum: Felt, carry: Felt },
    /// Helper for the `U32SUB` operation, which computes `a - b` for two u32 values and pushes
    /// the difference and a borrow flag.
    ///
    /// - `second_new`: the 32-bit difference `a - b` (truncated to 32 bits, i.e. the value placed
    ///   at stack position 1 after the operation).
    ///
    /// The helper registers hold the two 16-bit limbs of `second_new`.
    U32Sub { second_new: Felt },
    /// Helper for the `U32MUL` operation, which multiplies two u32 values and splits the result
    /// into low and high 32-bit limbs.
    ///
    /// - `lo`: the low 32-bit limb of `a * b`.
    /// - `hi`: the high 32-bit limb of `a * b`.
    ///
    /// The helper registers hold the four 16-bit limbs of `lo` and `hi`, plus the overflow flag
    /// `(u32::MAX - hi)^{-1}`.
    U32Mul { lo: Felt, hi: Felt },
    /// Helper for the `U32MADD` operation, which computes `a * b + c` for three u32 values and
    /// splits the result into low and high 32-bit limbs.
    ///
    /// - `lo`: the low 32-bit limb of `a * b + c`.
    /// - `hi`: the high 32-bit limb of `a * b + c`.
    ///
    /// The helper registers hold the four 16-bit limbs of `lo` and `hi`, plus the overflow flag
    /// `(u32::MAX - hi)^{-1}`.
    U32Madd { lo: Felt, hi: Felt },
    /// Helper for the `U32DIV` operation, which divides `a` by `b` and pushes the quotient and
    /// remainder.
    ///
    /// - `lo`: `numerator - quotient`, used to range-check that `quotient <= numerator`.
    /// - `hi`: `denominator - remainder - 1`, used to range-check that `remainder < denominator`.
    ///
    /// The helper registers hold the four 16-bit limbs of `lo` and `hi`.
    U32Div { lo: Felt, hi: Felt },
    /// Helper for the `U32ASSERT2` operation, which asserts that the top two stack elements are
    /// valid u32 values.
    ///
    /// - `first`: the element at stack position 0 (top).
    /// - `second`: the element at stack position 1.
    ///
    /// The helper registers hold the four 16-bit limbs of `second` and `first` (used for range
    /// checking).
    U32Assert2 { first: Felt, second: Felt },
    /// Helper for the `HPERM` operation, which applies a Poseidon2 permutation to the top 12
    /// stack elements.
    ///
    /// - `addr`: the address in the hasher chiplet where the permutation is recorded.
    HPerm { addr: Felt },
    /// Helper for Merkle path operations (`MPVERIFY` and `MRUPDATE`), which verify or update a
    /// node in a Merkle tree.
    ///
    /// - `addr`: the address in the hasher chiplet where the Merkle path computation is recorded.
    MerklePath { addr: Felt },
    /// Helper for the `HORNER_EVAL_BASE` operation, which performs 8 steps of Horner evaluation
    /// on a polynomial with base-field coefficients.
    ///
    /// - `alpha`: the evaluation point, read from memory.
    /// - `tmp0`: Level 1 intermediate result: `(acc * alpha + c0) * alpha + c1`.
    /// - `tmp1`: Level 2 intermediate result: `((tmp0 * alpha + c2) * alpha + c3) * alpha + c4`.
    HornerEvalBase {
        alpha: QuadFelt,
        tmp0: QuadFelt,
        tmp1: QuadFelt,
    },
    /// Helper for the `HORNER_EVAL_EXT` operation, which performs 4 steps of Horner evaluation
    /// on a polynomial with extension-field coefficients.
    ///
    /// - `alpha`: the evaluation point, read from memory.
    /// - `k0`, `k1`: auxiliary values read from the same memory word as `alpha` (elements 2 and 3
    ///   of the word).
    /// - `acc_tmp`: the intermediate accumulator after processing the first 2 (highest-degree)
    ///   coefficients: `(acc * alpha + s[0]) * alpha + s[1]`.
    HornerEvalExt {
        alpha: QuadFelt,
        k0: Felt,
        k1: Felt,
        acc_tmp: QuadFelt,
    },
    /// Helper for the `LOG_PRECOMPILE` operation, which absorbs `TAG` and `COMM` into the
    /// precompile sponge via a Poseidon2 permutation.
    ///
    /// - `addr`: the address in the hasher chiplet where the permutation is recorded.
    /// - `cap_prev`: the previous sponge capacity word, provided non-deterministically and used as
    ///   the capacity input to the permutation.
    LogPrecompile { addr: Felt, cap_prev: Word },
    /// No helper registers are needed for this operation. All helper columns are set to ZERO.
    Empty,
}

impl OperationHelperRegisters {
    pub fn to_user_op_helpers(&self) -> [Felt; NUM_USER_OP_HELPERS] {
        match self {
            Self::Eq { stack_second, stack_first } => {
                let h0 = if stack_second == stack_first {
                    ZERO
                } else {
                    (*stack_first - *stack_second).inverse()
                };

                [h0, ZERO, ZERO, ZERO, ZERO, ZERO]
            },
            Self::U32Split { lo, hi } => {
                let (t1, t0) = split_u32_into_u16(lo.as_canonical_u64());
                let (t3, t2) = split_u32_into_u16(hi.as_canonical_u64());
                let m = (Felt::from_u32(u32::MAX) - *hi).try_inverse().unwrap_or(ZERO);

                [
                    Felt::from_u16(t0),
                    Felt::from_u16(t1),
                    Felt::from_u16(t2),
                    Felt::from_u16(t3),
                    m,
                    ZERO,
                ]
            },
            Self::Eqz { top } => {
                let h0 = top.try_inverse().unwrap_or(ZERO);

                [h0, ZERO, ZERO, ZERO, ZERO, ZERO]
            },
            Self::Expacc { acc_update_val } => [*acc_update_val, ZERO, ZERO, ZERO, ZERO, ZERO],
            Self::FriExt2Fold4 { ev, es, x, x_inv } => {
                let ev_felts = ev.as_basis_coefficients_slice();
                let es_felts = es.as_basis_coefficients_slice();

                [ev_felts[0], ev_felts[1], es_felts[0], es_felts[1], *x, *x_inv]
            },
            Self::U32Add { sum, carry } => {
                let (t1, t0) = split_u32_into_u16(sum.as_canonical_u64());
                let (t3, t2) = split_u32_into_u16(carry.as_canonical_u64());

                [
                    Felt::from_u16(t0),
                    Felt::from_u16(t1),
                    Felt::from_u16(t2),
                    Felt::from_u16(t3),
                    ZERO,
                    ZERO,
                ]
            },
            Self::U32Add3 { sum, carry } => {
                let (t1, t0) = split_u32_into_u16(sum.as_canonical_u64());
                let (t3, t2) = split_u32_into_u16(carry.as_canonical_u64());

                [
                    Felt::from_u16(t0),
                    Felt::from_u16(t1),
                    Felt::from_u16(t2),
                    Felt::from_u16(t3),
                    ZERO,
                    ZERO,
                ]
            },
            Self::U32Sub { second_new } => {
                let (t1, t0) = split_u32_into_u16(second_new.as_canonical_u64());

                [Felt::from_u16(t0), Felt::from_u16(t1), ZERO, ZERO, ZERO, ZERO]
            },
            Self::U32Mul { lo, hi } => {
                let (t1, t0) = split_u32_into_u16(lo.as_canonical_u64());
                let (t3, t2) = split_u32_into_u16(hi.as_canonical_u64());
                let m = (Felt::from_u32(u32::MAX) - *hi).try_inverse().unwrap_or(ZERO);

                [
                    Felt::from_u16(t0),
                    Felt::from_u16(t1),
                    Felt::from_u16(t2),
                    Felt::from_u16(t3),
                    m,
                    ZERO,
                ]
            },
            Self::U32Madd { lo, hi } => {
                let (t1, t0) = split_u32_into_u16(lo.as_canonical_u64());
                let (t3, t2) = split_u32_into_u16(hi.as_canonical_u64());
                let m = (Felt::from_u32(u32::MAX) - *hi).try_inverse().unwrap_or(ZERO);

                [
                    Felt::from_u16(t0),
                    Felt::from_u16(t1),
                    Felt::from_u16(t2),
                    Felt::from_u16(t3),
                    m,
                    ZERO,
                ]
            },
            Self::U32Div { lo, hi } => {
                let (t1, t0) = split_u32_into_u16(lo.as_canonical_u64());
                let (t3, t2) = split_u32_into_u16(hi.as_canonical_u64());

                [
                    Felt::from_u16(t0),
                    Felt::from_u16(t1),
                    Felt::from_u16(t2),
                    Felt::from_u16(t3),
                    ZERO,
                    ZERO,
                ]
            },
            Self::U32Assert2 { first, second } => {
                let (t1, t0) = split_u32_into_u16(second.as_canonical_u64());
                let (t3, t2) = split_u32_into_u16(first.as_canonical_u64());

                [
                    Felt::from_u16(t0),
                    Felt::from_u16(t1),
                    Felt::from_u16(t2),
                    Felt::from_u16(t3),
                    ZERO,
                    ZERO,
                ]
            },
            Self::HPerm { addr } => [*addr, ZERO, ZERO, ZERO, ZERO, ZERO],
            Self::MerklePath { addr } => [*addr, ZERO, ZERO, ZERO, ZERO, ZERO],
            Self::HornerEvalBase { alpha, tmp0, tmp1 } => [
                alpha.as_basis_coefficients_slice()[0],
                alpha.as_basis_coefficients_slice()[1],
                tmp1.as_basis_coefficients_slice()[0],
                tmp1.as_basis_coefficients_slice()[1],
                tmp0.as_basis_coefficients_slice()[0],
                tmp0.as_basis_coefficients_slice()[1],
            ],
            Self::HornerEvalExt { alpha, k0, k1, acc_tmp } => [
                alpha.as_basis_coefficients_slice()[0],
                alpha.as_basis_coefficients_slice()[1],
                *k0,
                *k1,
                acc_tmp.as_basis_coefficients_slice()[0],
                acc_tmp.as_basis_coefficients_slice()[1],
            ],
            Self::LogPrecompile { addr, cap_prev } => {
                [*addr, cap_prev[0], cap_prev[1], cap_prev[2], cap_prev[3], ZERO]
            },
            Self::Empty => [ZERO; NUM_USER_OP_HELPERS],
        }
    }
}
