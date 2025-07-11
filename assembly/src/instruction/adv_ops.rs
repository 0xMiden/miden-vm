use miden_assembly_syntax::{
    debuginfo::SourceSpan,
    diagnostics::{RelatedLabel, Report},
};
use miden_core::Operation;

use super::BasicBlockBuilder;
use crate::{ADVICE_READ_LIMIT, ProcedureContext};

// NON-DETERMINISTIC (ADVICE) INPUTS
// ================================================================================================

/// Appends the number of ADVPOP operations specified by the instruction's immediate value to the
/// span. This pops the specified number of elements from the advice stack and pushes them onto the
/// operand stack.
///
/// # Errors
/// Returns an error if the specified number of values to pushed is smaller than 1 or greater
/// than 16.
pub fn adv_push(
    block_builder: &mut BasicBlockBuilder,
    proc_ctx: &ProcedureContext,
    n: u8,
    span: SourceSpan,
) -> Result<(), Report> {
    let min = 1;
    let max = ADVICE_READ_LIMIT;

    if n < min || n > max {
        return Err(RelatedLabel::error("invalid argument")
            .with_labeled_span(span, "this instruction argument is out of range")
            .with_help(format!("value must be in the range {min}..={max}"))
            .with_source_file(proc_ctx.source_manager().get(span.source_id()).ok())
            .into());
    }

    block_builder.push_op_many(Operation::AdvPop, n as usize);
    Ok(())
}
