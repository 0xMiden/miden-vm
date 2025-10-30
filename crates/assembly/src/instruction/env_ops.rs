use core::ops::Range;

use miden_assembly_syntax::{
    Felt,
    ast::Immediate,
    debuginfo::{SourceSpan, Spanned},
    diagnostics::Report,
    parser::{ParsingError, WordValue},
};
use miden_core::Operation::*;

use super::{BasicBlockBuilder, mem_ops::local_to_absolute_addr, push_felt};
use crate::ProcedureContext;

// CONSTANT INPUTS
// ================================================================================================

/// Appends `PUSH` operation to the basic block to push provided constant value onto the stack.
///
/// In cases when the immediate value is 0, `PUSH` operation is replaced with `PAD`. Also, in cases
/// when immediate value is 1, `PUSH` operation is replaced with `PAD INCR` because in most cases
/// this will be more efficient than doing a `PUSH`.
pub fn push_one<T>(imm: T, block_builder: &mut BasicBlockBuilder)
where
    T: Into<Felt>,
{
    push_felt(block_builder, imm.into());
}

/// Appends `PUSH` operations to the basic block to push two or more provided constant values onto
/// the stack, up to a maximum of 16 values.
///
/// In cases when the immediate value is 0, `PUSH` operation is replaced with `PAD`. Also, in cases
/// when immediate value is 1, `PUSH` operation is replaced with `PAD INCR` because in most cases
/// this will be more efficient than doing a `PUSH`.
pub fn push_many<T>(imms: &[T], block_builder: &mut BasicBlockBuilder)
where
    T: Into<Felt> + Copy,
{
    imms.iter().for_each(|imm| push_felt(block_builder, (*imm).into()));
}

/// Appends `PUSH` operations to the basic block using the [Felt]s obtained from the Word value
/// using the provided range.
///
/// In cases when the immediate value is 0, `PUSH` operation is replaced with `PAD`. Also, in cases
/// when immediate value is 1, `PUSH` operation is replaced with `PAD INCR` because in most cases
/// this will be more efficient than doing a `PUSH`.
///
/// # Errors
/// Returns an error if:
/// - The provided [`IntValue`] is not a [`IntValue::Word`].
/// - The provided range is malformed.
pub fn push_word_slice(
    imm: &Immediate<WordValue>,
    range: &Range<usize>,
    block_builder: &mut BasicBlockBuilder,
) -> Result<(), Report> {
    let v = imm.expect_value();
    match v.0.get(range.clone()) {
        // invalid range case (i.e. [8..5])
        None => {
            return Err(Report::new(ParsingError::InvalidRange {
                span: imm.span(),
                range: range.clone(),
            }));
        },
        // empty range case (i.e. [2..2])
        Some([]) => {
            return Err(Report::new(ParsingError::EmptySlice {
                span: imm.span(),
                range: range.clone(),
            }));
        },
        Some(values) => push_many(values, block_builder),
    }

    Ok(())
}

// ENVIRONMENT INPUTS
// ================================================================================================

/// Appends a sequence of operations to the span needed for executing locaddr.i instruction. This
/// consists of putting i onto the stack and then executing LOCADDR operation.
///
/// # Errors
/// Returns an error if index is greater than the number of procedure locals.
pub fn locaddr(
    block_builder: &mut BasicBlockBuilder,
    index: u16,
    proc_ctx: &ProcedureContext,
    instr_span: SourceSpan,
) -> Result<(), Report> {
    local_to_absolute_addr(block_builder, proc_ctx, index, proc_ctx.num_locals(), true, instr_span)
}

/// Appends CALLER operation to the span which puts the hash of the function which created the
/// latest execution context.
pub fn caller(block_builder: &mut BasicBlockBuilder) {
    block_builder.push_op(Caller);
}
