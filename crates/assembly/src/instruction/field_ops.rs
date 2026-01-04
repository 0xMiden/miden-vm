use miden_assembly_syntax::{
    Felt, ParsingError,
    debuginfo::{SourceSpan, Span},
    diagnostics::{RelatedError, RelatedLabel, Report},
};
use miden_core::{
    Operation::*,
    field::{Field, PrimeField64},
    sys_events::SystemEvent,
};

use super::BasicBlockBuilder;
use crate::{MAX_EXP_BITS, ONE, ProcedureContext, ZERO};

/// Field element representing TWO in the base field of the VM.
const TWO: Felt = Felt::new(2);

// ASSERTIONS
// ================================================================================================

/// Asserts that the top two words in the stack are equal.
///
/// VM cycles: 11 cycles
pub fn assertw(span_builder: &mut BasicBlockBuilder, err_code: Felt) {
    span_builder.push_ops([
        MovUp4,
        Eq,
        Assert(err_code),
        MovUp3,
        Eq,
        Assert(err_code),
        MovUp2,
        Eq,
        Assert(err_code),
        Eq,
        Assert(err_code),
    ]);
}

// BASIC ARITHMETIC OPERATIONS
// ================================================================================================

/// Appends a sequence of operations to add an immediate value to the value at the top of the
/// stack. Specifically, the sequences are:
/// - if imm = 0: NOOP
/// - else if imm = 1: INCR
/// - else if imm = 2: INCR INCR
/// - otherwise: PUSH(imm) ADD
pub fn add_imm(span_builder: &mut BasicBlockBuilder, imm: Felt) {
    if imm == ZERO {
        span_builder.push_op(Noop);
    } else if imm == ONE {
        span_builder.push_op(Incr);
    } else if imm == TWO {
        span_builder.push_ops([Incr, Incr]);
    } else {
        span_builder.push_ops([Push(imm), Add]);
    }
}

/// Appends a sequence of operations to subtract an immediate value from the value at the top of the
/// stack. Specifically, the sequences are:
/// - if imm = 0: NOOP
/// - otherwise: PUSH(-imm) ADD
pub fn sub_imm(span_builder: &mut BasicBlockBuilder, imm: Felt) {
    if imm == ZERO {
        span_builder.push_op(Noop);
    } else {
        span_builder.push_ops([Push(-imm), Add]);
    }
}

/// Appends a sequence of operations to multiply the value at the top of the stack by an immediate
/// value. Specifically, the sequences are:
/// - if imm = 0: DROP PAD
/// - else if imm = 1: NOOP
/// - otherwise: PUSH(imm) MUL
pub fn mul_imm(span_builder: &mut BasicBlockBuilder, imm: Felt) {
    if imm == ZERO {
        span_builder.push_ops([Drop, Pad]);
    } else if imm == ONE {
        span_builder.push_op(Noop);
    } else {
        span_builder.push_ops([Push(imm), Mul]);
    }
}

/// Appends a sequence of operations to divide the value at the top of the stack by an immediate
/// value. Specifically, the sequences are:
/// - if imm = 0: Returns an error
/// - else if imm = 1: NOOP
/// - otherwise: PUSH(1/imm) MUL
///
/// # Errors
/// Returns an error if the immediate value is ZERO.
pub fn div_imm(
    span_builder: &mut BasicBlockBuilder,
    proc_ctx: &mut ProcedureContext,
    imm: Span<Felt>,
) -> Result<(), Report> {
    if imm == ZERO {
        let source_span = imm.span();
        let source_file = proc_ctx.source_manager().get(source_span.source_id()).ok();
        let error = Report::new(ParsingError::DivisionByZero { span: source_span });
        return Err(if let Some(source_file) = source_file {
            RelatedError::new(error.with_source_code(source_file)).into()
        } else {
            RelatedError::new(error).into()
        });
    } else if imm == ONE {
        span_builder.push_op(Noop);
    } else {
        span_builder.push_ops([Push(imm.into_inner().inverse()), Mul]);
    }
    Ok(())
}

// POWER OF TWO OPERATION
// ================================================================================================

/// Appends a sequence of operations to raise value 2 to the power specified by the element at the
/// top of the stack.
///
/// VM cycles: 16 cycles
pub fn pow2(span_builder: &mut BasicBlockBuilder) {
    append_pow2_op(span_builder);
}

/// Appends relevant operations to the span_builder block for the computation of power of 2.
///
/// VM cycles: 16 cycles
pub fn append_pow2_op(span_builder: &mut BasicBlockBuilder) {
    // push base 2 onto the stack: [exp, ...] -> [2, exp, ...]
    span_builder.push_op(Push(2_u8.into()));
    // introduce initial value of acc onto the stack: [2, exp, ...] -> [1, 2, exp, ...]
    span_builder.push_ops([Pad, Incr]);
    // arrange the top of the stack for EXPACC operation: [1, 2, exp, ...] -> [0, 2, 1, exp, ...]
    span_builder.push_ops([Swap, Pad]);
    // calling expacc instruction 6 times
    span_builder.push_ops([Expacc, Expacc, Expacc, Expacc, Expacc, Expacc]);
    // drop the top two elements bit and exp value of the latest bit.
    span_builder.push_ops([Drop, Drop]);
    // taking `b` to the top and asserting if it's equal to ZERO after all the right shifts.
    span_builder.push_ops([Swap, Eqz, Assert(ZERO)]);
}

// EXPONENTIATION OPERATION
// ================================================================================================

/// Appends a sequence of operations to compute b^e where e is the value at the top of the stack
/// and b is the value second from the top of the stack.
///
/// num_pow_bits parameter is expected to contain the number of bits needed to encode value e. If
/// this assumption is not satisfied, the operation will fail at runtime.
///
/// VM cycles: 9 + num_pow_bits
///
/// # Errors
/// Returns an error if num_pow_bits is greater than 64.
pub fn exp(
    span_builder: &mut BasicBlockBuilder,
    proc_ctx: &ProcedureContext,
    num_pow_bits: u8,
    span: SourceSpan,
) -> Result<(), Report> {
    if num_pow_bits > MAX_EXP_BITS {
        return Err(RelatedLabel::error("invalid argument")
            .with_labeled_span(span, "this instruction argument is out of range")
            .with_help(format!("value must be in the range 0..={MAX_EXP_BITS}"))
            .with_source_file(proc_ctx.source_manager().get(span.source_id()).ok())
            .into());
    }

    // arranging the stack to prepare it for expacc instruction.
    span_builder.push_ops([Pad, Incr, MovUp2, Pad]);

    // calling expacc instruction n times.
    span_builder.push_op_many(Expacc, num_pow_bits as usize);

    // drop the top two elements exp_lsb and base value of the last iteration.
    span_builder.push_ops([Drop, Drop]);

    // taking `b` to the top and asserting if it's equal to ZERO after all the right shifts.
    span_builder.push_ops([Swap, Eqz, Assert(ZERO)]);
    Ok(())
}

/// Appends a sequence of operations to compute b^pow where b is the value at the top of the stack.
///
/// VM cycles per mode:
/// - pow = 0: 3 cycles
/// - pow = 1: 1 cycles
/// - pow = 2: 2 cycles
/// - pow = 3: 4 cycles
/// - pow = 4: 6 cycles
/// - pow = 5: 8 cycles
/// - pow = 6: 10 cycles
/// - pow = 7: 12 cycles
/// - pow > 7: 9 + Ceil(log2(pow))
pub fn exp_imm(
    span_builder: &mut BasicBlockBuilder,
    proc_ctx: &ProcedureContext,
    pow: Felt,
    span: SourceSpan,
) -> Result<(), Report> {
    if pow.as_canonical_u64() <= 7 {
        perform_exp_for_small_power(span_builder, pow.as_canonical_u64());
        Ok(())
    } else {
        // compute the bits length of the exponent
        let num_pow_bits = (64 - pow.as_canonical_u64().leading_zeros()) as u8;

        // pushing the exponent onto the stack.
        span_builder.push_op(Push(pow));

        exp(span_builder, proc_ctx, num_pow_bits, span)
    }
}

/// If the immediate value of the `exp` instruction is less than 8, then, it is be cheaper to
/// compute the exponentiation of the base to the power imm using `dup` and `mul` instructions.
///
/// The expected starting state of the stack (from the top) is: [b, ...].
///
/// After these operations, the stack state will be: [b^pow, ...], where b is the immediate value
/// and b is less than 8.
///
/// VM cycles per mode:
/// - pow = 0: 3 cycles
/// - pow = 1: 1 cycles
/// - pow = 2: 2 cycles
/// - pow = 3: 4 cycles
/// - pow = 4: 6 cycles
/// - pow = 5: 8 cycles
/// - pow = 6: 10 cycles
/// - pow = 7: 12 cycles
fn perform_exp_for_small_power(span_builder: &mut BasicBlockBuilder, pow: u64) {
    match pow {
        0 => {
            span_builder.push_op(Drop);
            span_builder.push_op(Pad);
            span_builder.push_op(Incr);
        },
        1 => span_builder.push_op(Noop), // TODO: show warning?
        2 => {
            span_builder.push_op(Dup0);
            span_builder.push_op(Mul);
        },
        3 => {
            span_builder.push_op_many(Dup0, 2);
            span_builder.push_op_many(Mul, 2);
        },
        4 => {
            span_builder.push_op_many(Dup0, 3);
            span_builder.push_op_many(Mul, 3);
        },
        5 => {
            span_builder.push_op_many(Dup0, 4);
            span_builder.push_op_many(Mul, 4);
        },
        6 => {
            span_builder.push_op_many(Dup0, 5);
            span_builder.push_op_many(Mul, 5);
        },
        7 => {
            span_builder.push_op_many(Dup0, 6);
            span_builder.push_op_many(Mul, 6);
        },
        _ => unreachable!("pow must be less than 8"),
    }
}

// LOGARITHMIC OPERATIONS
// ================================================================================================

/// Appends a sequence of operations to calculate the base 2 integer logarithm of the stack top
/// element, using non-deterministic technique (i.e. it takes help of advice provider).
///
/// This operation takes 44 VM cycles.
///
/// # Errors
/// Returns an error if the logarithm argument (top stack element) equals ZERO.
pub fn ilog2(block_builder: &mut BasicBlockBuilder) {
    block_builder.push_system_event(SystemEvent::ILog2);
    block_builder.push_op(AdvPop); // [ilog2, n, ...]

    // compute the power-of-two for the value given in the advice tape (17 cycles)
    block_builder.push_op(Dup0);
    append_pow2_op(block_builder);
    // => [pow2, ilog2, n, ...]

    #[rustfmt::skip]
    let ops = [
        // split the words into u32 halves to use the bitwise operations (4 cycles)
        MovUp2, U32split, MovUp2, U32split,
        // => [pow2_high, pow2_low, n_high, n_low, ilog2, ...]

        // only one of the two halves in pow2 has a bit set, drop the other (9 cycles)
        Dup1, Eqz, Dup0, MovDn3,
        // => [drop_low, pow2_high, pow2_low, drop_low, n_high, n_low, ilog2, ...]
        CSwap, Drop, MovDn3, CSwap, Drop,
        // => [n_half, pow2_half, ilog2, ...]

        // set all bits to 1 lower than pow2_half (00010000 -> 00011111)
        Swap, Pad, Incr, Incr, Mul, Pad, Incr, Neg, Add,
        // => [pow2_half * 2 - 1, n_half, ilog2, ...]
        Dup1, U32and,
        // => [m, n_half, ilog2, ...] if ilog2 calculation was correct, m should be equal to n_half
        Eq, Assert(ZERO),
        // => [ilog2, ...]
    ];

    block_builder.push_ops(ops);
}

// COMPARISON OPERATIONS
// ================================================================================================

/// Appends a sequence of operations to check equality between the value at the top of the stack
/// and the provided immediate value. Specifically, the sequences are:
/// - if imm = 0: EQZ
/// - otherwise: PUSH(imm) EQ
pub fn eq_imm(span_builder: &mut BasicBlockBuilder, imm: Felt) {
    if imm == ZERO {
        span_builder.push_op(Eqz);
    } else {
        span_builder.push_ops([Push(imm), Eq]);
    }
}

/// Appends a sequence of operations to check inequality between the value at the top of the stack
/// and the provided immediate value. Specifically, the sequences are:
/// - if imm = 0: EQZ NOT
/// - otherwise: PUSH(imm) EQ NOT
pub fn neq_imm(span_builder: &mut BasicBlockBuilder, imm: Felt) {
    if imm == ZERO {
        span_builder.push_ops([Eqz, Not]);
    } else {
        span_builder.push_ops([Push(imm), Eq, Not]);
    }
}

/// Appends a sequence of operations to check equality between two words at the top of the stack.
///
/// This operation takes 15 VM cycles.
pub fn eqw(span_builder: &mut BasicBlockBuilder) {
    span_builder.push_ops([
        // duplicate first pair of for comparison(4th elements of each word) in reverse order
        // to avoid using dup.8 after stack shifting(dup.X where X > 7, takes more VM cycles )
        Dup7, Dup4, Eq,
        // continue comparison pair by pair using bitwise AND for EQ results
        Dup7, Dup4, Eq, And, Dup6, Dup3, Eq, And, Dup5, Dup2, Eq, And,
    ]);
}

/// Appends a sequence of operations to pop the top 2 elements off the stack and do a "less
/// than" comparison. The stack is expected to be arranged as [b, a, ...] (from the top). A value
/// of 1 is pushed onto the stack if a < b. Otherwise, 0 is pushed.
///
/// This operation takes 14 VM cycles.
pub fn lt(span_builder: &mut BasicBlockBuilder) {
    // Split both elements into high and low bits
    // 3 cycles
    split_elements(span_builder);

    // compare the high bit values and put comparison result flags on the stack for eq and lt
    // then reorder in preparation for the low-bit comparison (a_lo < b_lo)
    // 6 cycles
    check_lt_high_bits(span_builder);

    // check a_lo < b_lo, resulting in 1 if true and 0 otherwise
    // 3 cycles
    check_lt(span_builder);

    // combine low-bit and high-bit results
    // 2 cycles
    set_result(span_builder);
}

/// Appends a sequence of operations to pop the top 2 elements off the stack and do a "less
/// than or equal" comparison. The stack is expected to be arranged as [b, a, ...] (from the top).
/// A value of 1 is pushed onto the stack if a <= b. Otherwise, 0 is pushed.
///
/// This operation takes 15 VM cycles.
pub fn lte(span_builder: &mut BasicBlockBuilder) {
    // Split both elements into high and low bits
    // 3 cycles
    split_elements(span_builder);

    // compare the high bit values and put comparison result flags on the stack for eq and lt
    // then reorder in preparation for the low-bit comparison (a_lo <= b_lo)
    // 6 cycles
    check_lt_high_bits(span_builder);

    // check a_lo <= b_lo, resulting in 1 if true and 0 otherwise
    // 4 cycles
    check_lte(span_builder);

    // combine low-bit and high-bit results
    // 2 cycles
    set_result(span_builder);
}

/// Appends a sequence of operations to pop the top 2 elements off the stack and do a "greater
/// than" comparison. The stack is expected to be arranged as [b, a, ...] (from the top). A value
/// of 1 is pushed onto the stack if a > b. Otherwise, 0 is pushed.
///
/// This operation takes 15 VM cycles.
pub fn gt(span_builder: &mut BasicBlockBuilder) {
    // Split both elements into high and low bits
    // 3 cycles
    split_elements(span_builder);

    // compare the high bit values and put comparison result flags on the stack for eq and gt
    // then reorder in preparation for the low-bit comparison (b_lo < a_lo)
    // 7 cycles
    check_gt_high_bits(span_builder);

    // check b_lo < a_lo, resulting in 1 if true and 0 otherwise
    // 3 cycles
    check_lt(span_builder);

    // combine low-bit and high-bit results
    // 2 cycles
    set_result(span_builder);
}

/// Appends a sequence of operations to pop the top 2 elements off the stack and do a "greater
/// than or equal" comparison. The stack is expected to be arranged as [b, a, ...] (from the top).
/// A value of 1 is pushed onto the stack if a >= b. Otherwise, 0 is pushed.
///
/// This operation takes 16 VM cycles.
pub fn gte(span_builder: &mut BasicBlockBuilder) {
    // Split both elements into high and low bits
    // 3 cycles
    split_elements(span_builder);

    // compare the high bit values and put comparison result flags on the stack for eq and gt
    // then reorder in preparation for the low-bit comparison (b_lo <= a_lo)
    // 7 cycles
    check_gt_high_bits(span_builder);

    // check b_lo <= a_lo, resulting in 1 if true and 0 otherwise
    // 4 cycles
    check_lte(span_builder);

    // combine low-bit and high-bit results
    // 2 cycles
    set_result(span_builder);
}

/// Checks if the top element in the stack is an odd number or not.
///
/// Vm cycles: 5
pub fn is_odd(span_builder: &mut BasicBlockBuilder) {
    span_builder.push_ops([U32split, Drop, Pad, Incr, U32and]);
}

// COMPARISON OPERATION HELPER FUNCTIONS
// ================================================================================================

/// Splits the top 2 elements on the stack into low and high 32-bit values and swaps their order.
/// The expected starting state of the stack (from the top) is: [b, a, ...].
///
/// After these operations, the stack state will be: [a_hi, a_lo, b_hi, b_lo, ...].
///
/// This operation takes 3 cycles.
fn split_elements(span_builder: &mut BasicBlockBuilder) {
    // stack: [b, a, ...] => [b_hi, b_lo, a, ...]
    span_builder.push_op(U32split);
    // => [a, b_hi, b_lo, ...]
    span_builder.push_op(MovUp2);
    // => [a_hi, a_lo, b_hi, b_lo, ...]
    span_builder.push_op(U32split);
}

/// Appends operations to the span_builder block to simultaneously check both the "less than"
/// condition (a < b) and equality (a = b) and push a separate flag onto the stack for each result.
///
/// The expected stack (from the top) is: [b, a, ...].
/// - Pushes 1 on the stack if a < b and 0 otherwise.
/// - Pushes 1 on the stack if a = b and 0 otherwise.
///
/// The resulting stack after this operation is: [eq_flag, lt_flag, ...].
///
/// This operation takes 3 cycles.
fn check_lt_and_eq(span_builder: &mut BasicBlockBuilder) {
    // calculate a - b
    // stack: [b, a, ...] => [underflow_flag, result, ...]
    span_builder.push_op(U32sub);
    // after the u32sub operation we can be in one of 3 states:
    // - [1, result > 0] - this means that we underflowed (a < b)
    // - [0, result > 0] - this means that we didn't underflow (a > b)
    // - [0, result = 0] - this means that comparing values are equal (a = b)
    //
    // The situation of `[1, 0]` is impossible because we can't reach 0 with underflow: subtracting
    // maximum type value from minimum value (which is 0) will result in 1, so to reach 0 we need
    // to subtract value that is bigger than the maximum type value, which is impossible.
    // For example `0u64.wrapping_sub(u64::MAX) = 1`, but `0u64.wrapping_sub(u64::MAX + 1)` is
    // impossible.
    span_builder.push_ops([Swap, Eqz]);
}

/// This is a helper function for comparison operations that perform a less-than check a < b
/// between two field elements a and b. It expects both elements to be already split into upper and
/// lower 32-bit values and arranged on the stack (from the top) as:
/// [a_hi, a_lo, bi_hi, b_lo, ...].
///
/// It pops the high bit values of both elements, compares them, and pushes 2 flags: one for
/// less-than and one for equality. Then it moves the flags down the stack, leaving the low bits at
/// the top of the stack in the orientation required for a less-than check of the low bit values
/// (a_lo < b_lo).
///
/// After this operation, the stack will look as follows (from the top):
/// - b_lo
/// - a_lo
/// - hi_flag_eq: 1 if the high bit values were equal; 0 otherwise
/// - hi_flag_lt: 1 if a's high-bit values were less than b's (a_hi < b_hi); 0 otherwise
///
/// This operation takes 6 cycles.
fn check_lt_high_bits(span_builder: &mut BasicBlockBuilder) {
    // reorder the stack to check a_hi < b_hi
    span_builder.push_op(MovUp2);

    // simultaneously check a_hi < b_hi and a_hi = b_hi, resulting in:
    // - an equality flag of 1 if a_hi = b_hi and 0 otherwise (at stack[0])
    // - a less-than flag of 1 if a_hi > b_hi and 0 otherwise (at stack[1])
    check_lt_and_eq(span_builder);

    // reorder the stack to prepare for low-bit comparison (a_lo < b_lo)
    span_builder.push_ops([MovUp2, MovUp3]);
}

/// Appends operations to the span_builder block to emulate a "less than" conditional and check that
/// a < b for a starting stack of [b, a, ...]. Pops both elements and leaves 1 on the stack if a < b
/// and 0 otherwise.
///
/// This is implemented with the VM's U32SUB op, which performs a subtraction and leaves the
/// result and an underflow flag on the stack. When a < b, a - b will underflow, so the less-than
/// condition will be true if the underflow flag is set.
///
/// This operation takes 3 cycles.
fn check_lt(span_builder: &mut BasicBlockBuilder) {
    // calculate a - b
    // stack: [b, a, ...] => [underflow_flag, result, ...]
    span_builder.push_op(U32sub);

    // drop the result, since it's not needed
    span_builder.push_ops([Swap, Drop]);
}

/// This is a helper function to combine the high-bit and low-bit comparison checks into a single
/// result flag.
///
/// Since we're working with a 64-bit field modulus, we need to ensure that valid field elements
/// represented by > 32 bits are still compared properly. High bit comparisons take precedence, so
/// we only care about the result of the low-bit value comparison when the high bits were equal.
///
/// The stack is expected to be arranged as follows (from the top):
/// - low-bit comparison flag: 1 if the lt/lte/gt/gte condition being checked was true; 0 otherwise
/// - high-bit equality flag: 1 if the high bits were equal; 0 otherwise
/// - high-bit comparison flag: 1 if the lt/gt condition being checked was true; 0 otherwise
///
/// This function takes 2 cycles.
fn set_result(span_builder: &mut BasicBlockBuilder) {
    // check if high bits are equal AND low bit comparison condition was true
    span_builder.push_op(And);

    // Set the result flag if the above check passed OR the high-bit comparison was true
    span_builder.push_op(Or);
}

/// Appends operations to the span_builder block to emulate a "less than or equal" conditional and
/// check that a <= b for a starting stack of [b, a, ...]. Pops both elements and leaves 1 on the
/// stack if a <= b and 0 otherwise.
///
/// This is implemented with the VM's U32SUB op, which performs a subtraction and leaves the
/// result and an underflow flag on the stack. When a < b, a - b will underflow, so the less-than
/// condition will be true if the underflow flag is set. The equal condition will be true if
/// there was no underflow and the result is 0.
///
/// This function takes 4 cycles.
fn check_lte(span_builder: &mut BasicBlockBuilder) {
    // calculate a - b
    // stack: [b, a, ...] => [underflow_flag, result, ...]
    span_builder.push_op(U32sub);

    // check the result
    span_builder.push_ops([Swap, Eqz]);

    // set the lte flag if the underflow flag was set or the result was 0
    span_builder.push_op(Or);
}

/// This is a helper function for comparison operations that perform a greater-than check a > b
/// between two field elements a and b. It expects both elements to be already split into upper and
/// lower 32-bit values and arranged on the stack (from the top) as:
/// [a_hi, a_lo, bi_hi, b_lo, ...].
///
/// We pop the high bit values of both elements, compare them, and push 2 flags: one for
/// greater-than and one for equality. Then we move the flags down the stack, leaving the low bits
/// at the top of the stack in the orientation required for a greater-than check of the low bit
/// values (a_lo > b_lo).
///
/// After this operation, the stack will look as follows (from the top):
/// - a_lo
/// - b_lo
/// - hi_flag_eq: 1 if the high bit values were equal; 0 otherwise
/// - hi_flag_gt: 1 if a's high-bit values were greater than b's (a_hi > b_hi); 0 otherwise
///
/// This function takes 7 cycles.
fn check_gt_high_bits(span_builder: &mut BasicBlockBuilder) {
    // reorder the stack to check b_hi < a_hi
    span_builder.push_ops([Swap, MovDn2]);

    // simultaneously check b_hi < a_hi and b_hi = a_hi, resulting in:
    // - an equality flag of 1 if a_hi = b_hi and 0 otherwise (at stack[0])
    // - a greater-than flag of 1 if a_hi > b_hi and 0 otherwise (at stack[1])
    check_lt_and_eq(span_builder);

    // reorder the stack to prepare for low-bit comparison (b_lo < a_lo)
    span_builder.push_ops([MovUp3, MovUp3]);
}
