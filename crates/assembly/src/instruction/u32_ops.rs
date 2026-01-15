use miden_assembly_syntax::{
    ParsingError,
    debuginfo::{SourceSpan, Span},
    diagnostics::{RelatedLabel, Report},
};
use miden_core::{
    Felt,
    Operation::{self, *},
    ZERO,
    field::PrimeCharacteristicRing,
    sys_events::SystemEvent,
};

use super::{field_ops::append_pow2_op, push_u32_value};
use crate::{
    MAX_U32_ROTATE_VALUE, MAX_U32_SHIFT_VALUE, ProcedureContext,
    basic_block_builder::BasicBlockBuilder,
};

/// This enum is intended to determine the mode of operation passed to the parsing function
#[derive(PartialEq, Eq)]
pub enum U32OpMode {
    Wrapping,
    Overflowing,
}

// CONVERSIONS AND TESTS
// ================================================================================================

/// Translates u32testw assembly instruction to VM operations.
///
/// Implemented by executing DUP U32SPLIT DROP EQZ on each element in the word
/// and combining the results using AND operation (total of 19 VM cycles)
/// U32split outputs [lo, hi] with lo on top, so we drop lo and check if hi is zero.
pub fn u32testw(span_builder: &mut BasicBlockBuilder) {
    #[rustfmt::skip]
    let ops = [
        // Test the fourth element
        Dup3, U32split, Drop, Eqz,

        // Test the third element
        Dup3, U32split, Drop, Eqz, And,

         // Test the second element
        Dup2, U32split, Drop, Eqz, And,

        // Test the first element
        Dup1, U32split, Drop, Eqz, And,
    ];
    span_builder.push_ops(ops);
}

/// Translates u32assertw assembly instruction to VM operations.
///
/// Implemented by executing `U32ASSERT2` on each pair of elements in the word.
/// Total of 6 VM cycles.
pub fn u32assertw(span_builder: &mut BasicBlockBuilder, err_code: Felt) {
    #[rustfmt::skip]
    let ops = [
        // Test the first and the second elements
        U32assert2(err_code),

        // Move 3 and 4 to the top of the stack
        MovUp3, MovUp3,

        // Test them
        U32assert2(err_code),

        // Move the elements back into place
        MovUp3, MovUp3,
    ];
    span_builder.push_ops(ops);
}

// ARITHMETIC OPERATIONS
// ================================================================================================

/// Translates u32add assembly instructions to VM operations.
///
/// The base operation is `U32ADD`, but depending on the mode, additional operations may be
/// inserted. Please refer to the docs of `handle_arithmetic_operation` for more details.
///
/// VM cycles per mode:
/// - u32wrapping_add: 3 cycles
/// - u32wrapping_add.b: 4 cycles
/// - u32overflowing_add: 1 cycles
/// - u32overflowing_add.b: 2 cycles
pub fn u32add(span_builder: &mut BasicBlockBuilder, op_mode: U32OpMode, imm: Option<u32>) {
    handle_arithmetic_operation(span_builder, U32add, op_mode, imm);
}

/// Translates u32sub assembly instructions to VM operations.
///
/// The base operation is `U32SUB`, but depending on the mode, additional operations may be
/// inserted. Please refer to the docs of `handle_arithmetic_operation` for more details.
///
/// VM cycles per mode:
/// - u32wrapping_sub: 2 cycles
/// - u32wrapping_sub.b: 3 cycles
/// - u32overflowing_sub: 1 cycles
/// - u32overflowing_sub.b: 2 cycles
pub fn u32sub(span_builder: &mut BasicBlockBuilder, op_mode: U32OpMode, imm: Option<u32>) {
    handle_arithmetic_operation(span_builder, U32sub, op_mode, imm);
}

/// Translates u32mul assembly instructions to VM operations.
///
/// The base operation is `U32MUL`, but depending on the mode, additional operations may be
/// inserted. Please refer to the docs of `handle_arithmetic_operation` for more details.
///
/// VM cycles per mode:
/// - u32wrapping_mul: 2 cycles
/// - u32wrapping_mul.b: 3 cycles
/// - u32widening_mul: 1 cycles
/// - u32widening_mul.b: 2 cycles
pub fn u32mul(span_builder: &mut BasicBlockBuilder, op_mode: U32OpMode, imm: Option<u32>) {
    handle_arithmetic_operation(span_builder, U32mul, op_mode, imm);
}

/// Translates u32div assembly instructions to VM operations.
///
/// VM cycles per mode:
/// - u32div: 2 cycles
/// - u32div.b:
///    - 4 cycles if b is 1
///    - 3 cycles if b is not 1
pub fn u32div(
    span_builder: &mut BasicBlockBuilder,
    proc_ctx: &ProcedureContext,
    imm: Option<Span<u32>>,
) -> Result<(), Report> {
    handle_division(span_builder, proc_ctx, imm)?;
    // U32div outputs [remainder, quotient], drop remainder to keep quotient
    span_builder.push_op(Drop);
    Ok(())
}

/// Translates u32mod assembly instructions to VM operations.
///
/// VM cycles per mode:
/// - u32mod: 3 cycles
/// - u32mod.b:
///    - 5 cycles if b is 1
///    - 4 cycles if b is not 1
pub fn u32mod(
    span_builder: &mut BasicBlockBuilder,
    proc_ctx: &ProcedureContext,
    imm: Option<Span<u32>>,
) -> Result<(), Report> {
    handle_division(span_builder, proc_ctx, imm)?;
    // U32div outputs [remainder, quotient], swap and drop to keep remainder
    span_builder.push_ops([Swap, Drop]);
    Ok(())
}

/// Translates u32divmod assembly instructions to VM operations.
///
/// VM cycles per mode:
/// - u32divmod: 1 cycle
/// - u32divmod.b:
///    - 3 cycles if b is 1
///    - 2 cycles if b is not 1
pub fn u32divmod(
    span_builder: &mut BasicBlockBuilder,
    proc_ctx: &ProcedureContext,
    imm: Option<Span<u32>>,
) -> Result<(), Report> {
    handle_division(span_builder, proc_ctx, imm)
}

// BITWISE OPERATIONS
// ================================================================================================

/// Translates u32not assembly instruction to VM operations.
///
/// The reason this method works is because 2^32 -1 provides a bit mask of ones, which after
/// subtracting the element, flips the bits of the original value to perform a bitwise NOT.
///
/// This takes 5 VM cycles.
pub fn u32not(span_builder: &mut BasicBlockBuilder) {
    #[rustfmt::skip]
    let ops = [
        // Perform the operation: compute MAX - value
        // U32sub computes second - top (a - b for [b, a]), so we need [value, MAX, ...]
        Push(Felt::from_u32(u32::MAX)),
        U32assert2(ZERO),
        Swap,
        U32sub,

        // Drop the underflow flag
        Drop,
    ];
    span_builder.push_ops(ops);
}

/// Translates u32shl assembly instructions to VM operations.
///
/// The operation is implemented by putting a power of 2 on the stack, then multiplying it with
/// the value to be shifted and splitting the result.
///
/// VM cycles per mode:
/// - u32shl: 19 cycles
/// - u32shl.b: 4 cycles
pub fn u32shl(
    span_builder: &mut BasicBlockBuilder,
    proc_ctx: &ProcedureContext,
    imm: Option<u8>,
    span: SourceSpan,
) -> Result<(), Report> {
    prepare_bitwise::<MAX_U32_SHIFT_VALUE>(span_builder, proc_ctx, imm, span)?;
    if imm != Some(0) {
        // U32mul outputs [lo, hi], swap before drop to keep lo (the shifted value)
        span_builder.push_ops([U32mul, Swap, Drop]);
    }
    Ok(())
}

/// Translates u32shr assembly instructions to VM operations.
///
/// The operation is implemented by putting a power of 2 on the stack, then dividing the value to
/// be shifted by it and returning the quotient.
///
/// VM cycles per mode:
/// - u32shr: 20 cycles
/// - u32shr.b: 5 cycles
pub fn u32shr(
    span_builder: &mut BasicBlockBuilder,
    proc_ctx: &ProcedureContext,
    imm: Option<u8>,
    span: SourceSpan,
) -> Result<(), Report> {
    prepare_bitwise::<MAX_U32_SHIFT_VALUE>(span_builder, proc_ctx, imm, span)?;
    if imm != Some(0) {
        // After prepare_bitwise, stack is [2^b, value, ...]
        // U32div takes [divisor, dividend] and computes dividend/divisor (second/top)
        // So with [2^b, value], it computes value / 2^b = value >> b
        // U32div outputs [remainder, quotient], drop remainder to keep quotient
        span_builder.push_ops([U32div, Drop]);
    }
    Ok(())
}

/// Translates u32rotl assembly instructions to VM operations.
///
/// The base operation is implemented by putting a power of 2 on the stack, then multiplying the
/// value to be shifted by it and adding the overflow limb to the shifted limb.
///
/// VM cycles per mode:
/// - u32rotl: 18 cycles
/// - u32rotl.b: 3 cycles
pub fn u32rotl(
    span_builder: &mut BasicBlockBuilder,
    proc_ctx: &ProcedureContext,
    imm: Option<u8>,
    span: SourceSpan,
) -> Result<(), Report> {
    prepare_bitwise::<MAX_U32_ROTATE_VALUE>(span_builder, proc_ctx, imm, span)?;
    if imm != Some(0) {
        span_builder.push_ops([U32mul, Add]);
    }
    Ok(())
}

/// Translates u32rotr assembly instructions to VM operations.
///
/// The base operation is implemented by multiplying the value to be shifted by 2^(32-b), where
/// b is the shift amount, then adding the overflow limb to the shifted limb.
///
/// VM cycles per mode:
/// - u32rotr: 22 cycles
/// - u32rotr.b: 3 cycles
pub fn u32rotr(
    span_builder: &mut BasicBlockBuilder,
    proc_ctx: &ProcedureContext,
    imm: Option<u8>,
    span: SourceSpan,
) -> Result<(), Report> {
    match imm {
        Some(0) => {
            // if rotation is performed by 0, do nothing (Noop)
            span_builder.push_op(Noop);
        },
        Some(imm) => {
            if imm == 0 || imm > MAX_U32_ROTATE_VALUE {
                return Err(RelatedLabel::error("invalid argument")
                    .with_labeled_span(span, "this instruction argument is out of range")
                    .with_help(format!("value must be in the range 0..={MAX_U32_ROTATE_VALUE}"))
                    .with_source_file(proc_ctx.source_manager().get(span.source_id()).ok())
                    .into());
            }
            span_builder.push_op(Push(Felt::new(1 << (32 - imm))));
            span_builder.push_ops([U32mul, Add]);
        },
        None => {
            // Compute 32 - b, where b is rotation amount on top of stack
            // Stack: [b, ...], push 32 to get [32, b, ...], swap to get [b, 32, ...]
            // U32sub computes second - top = 32 - b
            span_builder.push_ops([Push(Felt::new(32)), Swap, U32sub, Drop]);
            append_pow2_op(span_builder);
            span_builder.push_ops([Mul, U32split, Add]);
        },
    }
    Ok(())
}

/// Translates u32popcnt assembly instructions to VM operations.
///
/// This operation takes 32 cycles.
pub fn u32popcnt(span_builder: &mut BasicBlockBuilder) {
    #[rustfmt::skip]
    let ops = [
        // i = i - ((i >> 1) & 0x55555555);
        // U32div computes second/top. Stack: [i, ...], push 2 to get [2, i, ...].
        // U32div gives i/2. Output [remainder, quotient], drop remainder to keep quotient.
        Dup0,
        Push(Felt::new(1 << 1)), U32div, Drop,
        Push(Felt::new(0x55555555)),
        U32and,
        // U32sub computes second - top. Stack: [masked, i], gives i - masked
        U32sub, Drop,
        // i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
        Dup0,
        Push(Felt::new(1 << 2)), U32div, Drop,
        Push(Felt::new(0x33333333)),
        U32and,
        Swap,
        Push(Felt::new(0x33333333)),
        U32and,
        // U32add outputs [sum, carry], swap to drop carry and keep sum
        U32add, Swap, Drop,
        // i = (i + (i >> 4)) & 0x0F0F0F0F;
        Dup0,
        Push(Felt::new(1 << 4)), U32div, Drop,
        // U32add outputs [sum, carry], swap to drop carry and keep sum
        U32add, Swap, Drop,
        Push(Felt::new(0x0F0F0F0F)),
        U32and,
        // return (i * 0x01010101) >> 24;
        // U32mul outputs [lo, hi], swap before drop to keep lo
        Push(Felt::new(0x01010101)),
        U32mul, Swap, Drop,
        Push(Felt::new(1 << 24)), U32div, Drop
    ];
    span_builder.push_ops(ops);
}

/// Translates `u32clz` assembly instruction to VM operations. `u32clz` counts the number of
/// leading zeros of the value using non-deterministic technique (i.e. it takes help of advice
/// provider).
///
/// This operation takes 41 VM cycles.
pub fn u32clz(block_builder: &mut BasicBlockBuilder) {
    block_builder.push_system_event(SystemEvent::U32Clz);
    block_builder.push_op(AdvPop); // [clz, n, ...]

    verify_clz(block_builder);
}

/// Translates `u32ctz` assembly instruction to VM operations. `u32ctz` counts the number of
/// trailing zeros of the value using non-deterministic technique (i.e. it takes help of advice
/// provider).
///
/// This operation takes 34 VM cycles.
pub fn u32ctz(block_builder: &mut BasicBlockBuilder) {
    block_builder.push_system_event(SystemEvent::U32Ctz);
    block_builder.push_op(AdvPop); // [ctz, n, ...]

    verify_ctz(block_builder);
}

/// Translates `u32clo` assembly instruction to VM operations. `u32clo` counts the number of
/// leading ones of the value using non-deterministic technique (i.e. it takes help of advice
/// provider).
///
/// This operation takes 40 VM cycles.
pub fn u32clo(block_builder: &mut BasicBlockBuilder) {
    block_builder.push_system_event(SystemEvent::U32Clo);
    block_builder.push_op(AdvPop); // [clo, n, ...]

    verify_clo(block_builder);
}

/// Translates `u32cto` assembly instruction to VM operations. `u32cto` counts the number of
/// trailing ones of the value using non-deterministic technique (i.e. it takes help of advice
/// provider).
///
/// This operation takes 33 VM cycles.
pub fn u32cto(block_builder: &mut BasicBlockBuilder) {
    block_builder.push_system_event(SystemEvent::U32Cto);
    block_builder.push_op(AdvPop); // [cto, n, ...]

    verify_cto(block_builder);
}

/// Specifically handles these specific inputs per the spec.
/// - Wrapping: does not check if the inputs are u32 values; overflow or underflow bits are
///   discarded.
/// - Overflowing: does not check if the inputs are u32 values; overflow or underflow bits are
///   pushed onto the stack.
fn handle_arithmetic_operation(
    block_builder: &mut BasicBlockBuilder,
    op: Operation,
    op_mode: U32OpMode,
    imm: Option<u32>,
) {
    if let Some(imm) = imm {
        push_u32_value(block_builder, imm);
    }

    block_builder.push_op(op);

    // in the wrapping mode, drop overflow/carry bits
    if matches!(op_mode, U32OpMode::Wrapping) {
        // U32add outputs [sum, carry] with sum on top - swap to drop carry and keep sum
        // U32mul outputs [lo, hi] with lo on top - swap to drop hi and keep lo
        // U32sub outputs [borrow, diff] with borrow on top - just drop borrow to keep diff
        if matches!(op, U32mul | U32add) {
            block_builder.push_ops([Swap, Drop]);
        } else {
            block_builder.push_op(Drop);
        }
    }
}

/// Handles common parts of u32div, u32mod, and u32divmod operations, including handling of
/// immediate parameters.
fn handle_division(
    block_builder: &mut BasicBlockBuilder,
    proc_ctx: &ProcedureContext,
    imm: Option<Span<u32>>,
) -> Result<(), Report> {
    if let Some(imm) = imm {
        if imm == 0 {
            let imm_span = imm.span();
            let source_file = proc_ctx.source_manager().get(imm_span.source_id()).ok();
            let error = Report::new(ParsingError::DivisionByZero { span: imm_span });
            return if let Some(source_file) = source_file {
                Err(error.with_source_code(source_file))
            } else {
                Err(error)
            };
        }
        push_u32_value(block_builder, imm.into_inner());
    }

    block_builder.push_op(U32div);
    Ok(())
}

// BITWISE OPERATIONS - HELPERS
// ================================================================================================

/// Mutate the first two elements of the stack from `[b, a, ..]` into `[2^b, a, ..]`, with `b`
/// either as a provided immediate value, or as an element that already exists in the stack.
fn prepare_bitwise<const MAX_VALUE: u8>(
    block_builder: &mut BasicBlockBuilder,
    proc_ctx: &ProcedureContext,
    imm: Option<u8>,
    span: SourceSpan,
) -> Result<(), Report> {
    match imm {
        Some(0) => {
            // if shift/rotation is performed by 0, do nothing (Noop)
            block_builder.push_op(Noop);
        },
        Some(imm) => {
            if imm == 0 || imm > MAX_VALUE {
                return Err(RelatedLabel::error("invalid argument")
                    .with_labeled_span(span, "this instruction argument is out of range")
                    .with_help(format!("value must be in the range 0..={MAX_VALUE}"))
                    .with_source_file(proc_ctx.source_manager().get(span.source_id()).ok())
                    .into());
            }
            block_builder.push_op(Push(Felt::new(1 << imm)));
        },
        None => {
            append_pow2_op(block_builder);
        },
    }
    Ok(())
}

/// Appends relevant operations to the span block for the correctness check of the `U32Clz`
/// system event.
/// The idea is to compare the actual value with a bitmask consisting of `clz` leading ones to
/// check that every bit in `clz` leading bits is zero and `1` additional one to check that
/// `clz + 1`'th leading bit is one:
/// ```text
/// 000000000...000100...10 <-- actual value
/// └─ clz zeros ─┘
///
/// 1111111111...11100...00 <-- bitmask
/// └─  clz ones ─┘│
///                └─ additional one
/// ```
/// After applying a `u32and` bit operation on this values the result's leading `clz` bits should
/// be zeros, otherwise there were some ones in initial value's `clz` leading bits, and therefore
/// `clz` value is incorrect. `clz + 1`'th leading bit of the result should be one, otherwise this
/// bit in the initial value wasn't one and `clz` value is incorrect:
/// ```text
///  0000...00|1|10...10
/// &
///  1111...11|1|00...00
///  ↓↓↓↓   ↓↓ ↓
///  0000...00|1|00...00
/// ```
///
/// ---
/// The stack is expected to be arranged as follows (from the top):
/// - number of the leading zeros (`clz`), 1 element
/// - value for which we count the number of leading zeros (`n`), 1 element
///
/// After the operations are executed, the stack will be arranged as follows:
/// - number of the leading zeros (`clz`), 1 element
///
/// `[clz, n, ... ] -> [clz, ... ]`
///
/// VM cycles: 41
fn verify_clz(block_builder: &mut BasicBlockBuilder) {
    // [clz, n, ...]
    #[rustfmt::skip]
    let ops_group_1 = [
        Push(Felt::from_u8(32)), Dup1, Neg, Add // [32 - clz, clz, n, ...]
    ];
    block_builder.push_ops(ops_group_1);

    append_pow2_op(block_builder); // [pow2(32 - clz), clz, n, ...]

    #[rustfmt::skip]
    let ops_group_2 = [
        // 1. Obtain a mask for all `32 - clz` trailing bits
        //
        // #=> [2^(32 - clz) - 1, clz, n]
        Push(Felt::from_u8(1)), Neg, Add,
        // 2. Compute a value that represents setting the first non-zero bit to 1, i.e. if there
        // are 2 leading zeros, this would set the 3rd most significant bit to 1, with all other
        // bits set to zero.
        //
        // NOTE: This first step is an intermediate computation.
        //
        // #=> [(2^(32 - clz) - 1) / 2, clz, n, ...]
        // U32div computes second/top. Stack: [mask, ...], push 2 to get [2, mask, ...].
        // U32div gives mask/2. Output [remainder, quotient], drop remainder to keep quotient.
        Push(Felt::from_u8(2)), U32div, Drop,
        // Save the intermediate result of dividing by 2 for reuse in the next step
        //
        // #=> [((2^(32 - clz) - 1) / 2) + 1, (2^(32 - clz) - 1) / 2, clz, n, ...]
        Dup0, Incr,
        // 3. Obtain a mask for `clz + 1` leading bits
        //
        // #=> [u32::MAX - (2^(32 - clz) - 1 / 2), ((2^(32 - clz) - 1) / 2) + 1, clz, n, ...]
        Push(Felt::from_u32(u32::MAX)), MovUp2, Neg, Add,
        // 4. Set zero flag if input was zero, and apply the mask to the input value
        //
        // #=> [n & mask, (2^(32 - clz) - 1 / 2) + 1, clz, is_zero]
        Dup3, Eqz, MovDn3, MovUp4, U32and,
        // 6. Assert that the masked input, and the mask representing `clz` leading zeros, followed
        // by at least one trailing one, if `clz < 32`, are equal; OR that the input was zero if `clz`
        // is 32.
        Eq, MovUp2, Or, Assert(ZERO),
    ];

    block_builder.push_ops(ops_group_2);
}

/// Appends relevant operations to the span block for the correctness check of the `U32Clo`
/// system event.
/// The idea is to compare the actual value with a bitmask consisting of `clo` leading ones to
/// check that every bit in `clo` leading bits is one and `1` additional one to check that
/// `clo + 1`'th leading bit is zero:
/// ```text
/// 11111111...111010...10 <-- actual value
/// └─ clo ones ─┘
///
/// 111111111...11100...00 <-- bitmask
/// └─ clo ones ─┘│
///               └─ additional one
/// ```
/// After applying a `u32and` bit operation on this values the result's leading `clo` bits should
/// be ones, otherwise there were some zeros in initial value's `clo` leading bits, and therefore
/// `clo` value is incorrect. `clo + 1`'th leading bit of the result should be zero, otherwise this
/// bit in the initial value wasn't zero and `clo` value is incorrect:
/// ```text
///  1111...11|0|10...10
/// &
///  1111...11|1|00...00
///  ↓↓↓↓   ↓↓ ↓
///  1111...11|0|00...00
/// ```
///
/// ---
/// The stack is expected to be arranged as follows (from the top):
/// - number of the leading ones (`clo`), 1 element
/// - value for which we count the number of leading ones (`n`), 1 element
///
/// After the operations are executed, the stack will be arranged as follows:
/// - number of the leading ones (`clo`), 1 element
///
/// `[clo, n, ... ] -> [clo, ... ]`
///
/// VM cycles: 39
fn verify_clo(block_builder: &mut BasicBlockBuilder) {
    // [clo, n, ...]
    #[rustfmt::skip]
    let ops_group_1 = [
        Push(Felt::from_u8(32)), Dup1, Neg, Add // [32 - clo, clo, n, ...]
    ];
    block_builder.push_ops(ops_group_1);

    append_pow2_op(block_builder); // [pow2(32 - clo), clo, n, ...]

    #[rustfmt::skip]
    let ops_group_2 = [
        // 1. Obtain a mask for all `32 - clo` trailing bits
        //
        // #=> [2^(32 - clo) - 1, clo, n]
        Push(Felt::from_u8(1)), Neg, Add,
        // 2. Obtain a mask for `32 - clo - 1` trailing bits
        //
        // #=> [(2^(32 - clo) - 1) / 2, 2^(32 - clo) - 1, clo, n]
        // U32div computes second/top. Stack: [mask, ...], Dup0 push 2 to get [2, mask, mask, ...].
        // U32div gives mask/2. Output [remainder, quotient], drop remainder to keep quotient.
        Dup0, Push(Felt::from_u8(2)), U32div, Drop,
        // 3. Invert the mask from Step 2, to get one that covers `clo + 1` leading bits
        //
        // #=> [u32::MAX - ((2^(32 - clo) - 1) / 2), 2^(32 - clo) - 1, clo, n]
        Push(Felt::from_u32(u32::MAX)), Swap, Neg, Add,
        // 4. Apply the mask to the input value
        //
        // #=> [n & mask, 2^(32 - clo) - 1, clo]
        MovUp3, U32and,
        // 5. Invert the mask from Step 1, to get one  that covers `clo` leading bits
        //
        // #=> [u32::MAX - 2^(32 - clo) - 1, n & mask, clo]
        Push(Felt::from_u32(u32::MAX)), MovUp2, Neg, Add,
        // 6. Assert that the masked input, and the mask representing `clo` leading ones, are equal
        Eq, Assert(ZERO),
    ];

    block_builder.push_ops(ops_group_2);
}

/// Appends relevant operations to the span block for the correctness check of the `U32Ctz`
/// system event.
/// The idea is to compare the actual value with a bitmask consisting of `ctz` trailing ones to
/// check that every bit in `ctz` trailing bits is zero and `1` additional one to check that
/// `ctz + 1`'th trailing bit is one:
/// ```text
/// 10..001000000000000000 <-- actual value
///        └─ ctz zeros ─┘
///
/// 00..0011111111111...11 <-- bitmask
///       │└─  ctz ones ─┘
///       └─ additional one
/// ```
/// After applying a `u32and` bit operation on this values the result's trailing `ctz` bits should
/// be zeros, otherwise there were some ones in initial value's `ctz` trailing bits, and therefore
/// `ctz` value is incorrect. `ctz + 1`'th trailing bit of the result should be one, otherwise this
/// bit in the initial value wasn't one and `ctz` value is incorrect:
/// ```text
///  10...10|1|00...00
/// &
///  00...00|1|11...11
/// =        ↓ ↓↓   ↓↓
///  00...00|1|00...00
/// ```
///
/// ---
/// The stack is expected to be arranged as follows (from the top):
/// - number of the trailing zeros (`ctz`), 1 element
/// - value for which we count the number of trailing zeros (`n`), 1 element
///
/// After the operations are executed, the stack will be arranged as follows:
/// - number of the trailing zeros (`ctz`), 1 element
///
/// `[ctz, n, ... ] -> [ctz, ... ]`
///
/// VM cycles: 33
fn verify_ctz(block_builder: &mut BasicBlockBuilder) {
    // [ctz, n, ...]
    #[rustfmt::skip]
    let ops_group_1 = [
        Swap, Dup1, // [ctz, n, ctz, ...]
    ];
    block_builder.push_ops(ops_group_1);

    append_pow2_op(block_builder); // [pow2(ctz), n, ctz, ...]

    #[rustfmt::skip]
    let ops_group_2 = [
        Dup0, // [pow2(ctz), pow2(ctz), n, ctz, ...]
        // pow2(ctz) is equal to all zeros with only one on the `ctz`'th trailing position

        Pad, Incr, Neg, Add, // [pow2(ctz) - 1, pow2(ctz), n, ctz, ...]

        Swap, U32split, Swap, Drop, // [pow2(ctz), pow2(ctz) - 1, n, ctz, ...]
                                    // U32split outputs [lo, hi], we need lo (the u32 part)
                                    // We need to drop the high bits of `pow2(ctz)` because if `ctz`
                                    // equals 32 `pow2(ctz)` will exceed the u32. Also in that case there
                                    // is no need to check the dividing one, since it is absent (value is
                                    // all 0's).

        Dup0, MovUp2, Add, // [bit_mask, pow2(ctz), n, ctz]
                           // 00..001111111111...11 <-- bitmask
                           //       │└─ ctz ones ─┘
                           //       └─ additional one

        MovUp2, U32and, // [m, pow2(ctz), ctz]
                        // If calcualtion of `ctz` is correct, m should be equal to
                        // pow2(ctz)

        Eq, Assert(ZERO), // [ctz, ...]
    ];

    block_builder.push_ops(ops_group_2);
}

/// Appends relevant operations to the span block for the correctness check of the `U32Cto`
/// system event.
/// The idea is to compare the actual value with a bitmask consisting of `cto` trailing ones to
/// check that every bit in `cto` trailing bits is one and `1` additional one to check that
/// `cto + 1`'th trailing bit is zero:
/// ```text
/// 10..01011111111111111 <-- actual value
///        └─ cto ones ─┘
///
/// 00..001111111111...11 <-- bitmask
///       │└─ cto ones ─┘
///       └─ additional one
/// ```
/// After applying a `u32and` bit operation on this values the result's trailing `cto` bits should
/// be ones, otherwise there were some zeros in initial value's `cto` trailing bits, and therefore
/// `cto` value is incorrect. `cto + 1`'th trailing bit of the result should be zero, otherwise
/// this bit in the initial value wasn't zero and `cto` value is incorrect:
/// ```text
///  10...11|0|11...11
/// &
///  00...00|1|11...11
/// =        ↓ ↓↓   ↓↓
///  00...00|0|11...11
/// ```
///
/// ---
/// The stack is expected to be arranged as follows (from the top):
/// - number of the trailing ones (`cto`), 1 element
/// - value for which we count the number of trailing zeros (`n`), 1 element
///
/// After the operations are executed, the stack will be arranged as follows:
/// - number of the trailing zeros (`cto`), 1 element
///
/// `[cto, n, ... ] -> [cto, ... ]`
///
/// VM cycles: 32
fn verify_cto(block_builder: &mut BasicBlockBuilder) {
    // [cto, n, ...]
    #[rustfmt::skip]
    let ops_group_1 = [
        Swap, Dup1, // [cto, n, cto, ...]
    ];
    block_builder.push_ops(ops_group_1);

    append_pow2_op(block_builder); // [pow2(cto), n, cto, ...]

    #[rustfmt::skip]
    let ops_group_2 = [
        Dup0, // [pow2(cto), pow2(cto), n, cto, ...]
              // pow2(cto) is equal to all zeros with only one on the `cto`'th trailing position

        Pad, Incr, Neg, Add, // [pow2(cto) - 1, pow2(cto), n, cto, ...]

        Swap, U32split, Swap, Drop, // [pow2(cto), pow2(cto) - 1, n, cto, ...]
                                    // U32split outputs [lo, hi], we need lo (the u32 part)
                                    // We need to drop the high bits of `pow2(cto)` because if `cto`
                                    // equals 32 `pow2(cto)` will exceed the u32. Also in that case there
                                    // is no need to check the dividing zero, since it is absent (value
                                    // is all 1's).

        Dup1, Add, // [bit_mask, pow2(cto) - 1, n, cto]
                   // 00..001111111111...11 <-- bitmask
                   //       │└─ cto ones ─┘
                   //       └─ additional one

        MovUp2, U32and, // [m, pow2(cto) - 1, cto]
                        // If calcualtion of `cto` is correct, m should be equal to
                        // pow2(cto) - 1

        Eq, Assert(ZERO), // [cto, ...]
    ];

    block_builder.push_ops(ops_group_2);
}

// COMPARISON OPERATIONS
// ================================================================================================

/// Translates u32lt assembly instruction to VM operations.
///
/// This operation takes:
/// - 3 cycles without immediate value.
/// - 4 cycles with immediate value.
pub fn u32lt(block_builder: &mut BasicBlockBuilder) {
    compute_lt(block_builder);
}

/// Translates u32lte assembly instruction to VM operations.
///
/// This operation takes:
/// - 5 cycles without immediate value.
/// - 6 cycles with immediate value.
pub fn u32lte(block_builder: &mut BasicBlockBuilder) {
    // Compute the lt with reversed number to get a gt check
    block_builder.push_op(Swap);
    compute_lt(block_builder);

    // Flip the final results to get the lte results.
    block_builder.push_op(Not);
}

/// Translates u32gt assembly instruction to VM operations.
///
/// This operation takes:
/// - 4 cycles without immediate value.
/// - 5 cycles with immediate value.
pub fn u32gt(block_builder: &mut BasicBlockBuilder) {
    // Reverse the numbers so we can get a gt check.
    block_builder.push_op(Swap);

    compute_lt(block_builder);
}

/// Translates u32gte assembly instruction to VM operations.
///
/// This operation takes:
/// - 4 cycles without immediate value.
/// - 5 cycles with immediate value.
pub fn u32gte(block_builder: &mut BasicBlockBuilder) {
    compute_lt(block_builder);

    // Flip the final results to get the gte results.
    block_builder.push_op(Not);
}

/// Translates u32min assembly instruction to VM operations.
///
/// Specifically, we subtract the top value from the second to the top value (U32SUB), check the
/// underflow flag (EQZ), and perform a conditional swap (CSWAP) to have the max number in front.
/// Then we finally drop the top element to keep the min.
///
/// This operation takes:
/// - 8 cycles without immediate value.
/// - 9 cycles with immediate value.
pub fn u32min(block_builder: &mut BasicBlockBuilder) {
    compute_max_and_min(block_builder);

    // Drop the max and keep the min
    block_builder.push_op(Drop);
}

/// Translates u32max assembly instruction to VM operations.
///
/// Specifically, we subtract the top value from the second to the top value (U32SUB), check the
/// underflow flag (EQZ), and perform a conditional swap (CSWAP) to have the max number in front.
/// Then we finally drop the 2nd element to keep the max.
///
/// This operation takes:
/// - 9 cycles without immediate value.
/// - 10 cycles with immediate value.
pub fn u32max(block_builder: &mut BasicBlockBuilder) {
    compute_max_and_min(block_builder);

    // Drop the min and keep the max
    block_builder.push_ops([Swap, Drop]);
}

// COMPARISON OPERATIONS - HELPERS
// ================================================================================================

/// Inserts the VM operations to check if the second element is less than
/// the top element. This takes 3 cycles.
fn compute_lt(block_builder: &mut BasicBlockBuilder) {
    // For stack [b, a, ...], U32sub computes second - top = a - b.
    // If a < b, borrow = 1. Output is [borrow, diff, ...].
    // Swap drop to return just the borrow flag.
    block_builder.push_ops([U32sub, Swap, Drop])
}

/// Duplicate the top two elements in the stack and determine the min and max between them.
///
/// The maximum number will be at the top of the stack and minimum will be at the 2nd index.
fn compute_max_and_min(block_builder: &mut BasicBlockBuilder) {
    // Copy top two elements of the stack.
    block_builder.push_ops([Dup1, Dup1]);

    #[rustfmt::skip]
    block_builder.push_ops([
        // For stack [b, a, ...], U32sub computes second - top = a - b.
        // If a < b, borrow = 1. Output is [borrow, diff, ...].
        // Swap drop to get just the borrow flag.
        U32sub, Swap, Drop,

        // Check the underflow flag, if it's zero
        // then the second number is equal or larger than the first.
        Eqz, CSwap,
    ]);
}
