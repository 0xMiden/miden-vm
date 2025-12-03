use miden_core::WORD_SIZE;

use crate::{ProcedureContext, ast::DebugOptions, diagnostics::Report};

/// Compiles the AST representation of a `debug` instruction into its VM representation.
///
/// This function does not currently return any errors, but may in the future.
///
/// See [crate::Assembler] for an overview of AST compilation.
pub fn compile_options(
    options: &DebugOptions,
    proc_ctx: &ProcedureContext,
) -> Result<miden_core::DebugOptions, Report> {
    type Ast = DebugOptions;
    type Vm = miden_core::DebugOptions;

    // Use word-aligned num_locals for address calculations (same alignment as frame pointer)
    let aligned_num_locals = proc_ctx.num_locals().next_multiple_of(WORD_SIZE as u16);

    // NOTE: these `ast::Immediate::expect_value()` calls *should* be safe, because by the time
    // we're compiling debug options all immediate-constant arguments should be resolved.
    let compiled = match options {
        Ast::StackAll => Vm::StackAll,
        Ast::StackTop(n) => Vm::StackTop(n.expect_value()),
        Ast::MemAll => Vm::MemAll,
        Ast::MemInterval(start, end) => Vm::MemInterval(start.expect_value(), end.expect_value()),
        Ast::LocalInterval(start, end) => {
            let (start, end) = (start.expect_value(), end.expect_value());
            Vm::LocalInterval(start, end, aligned_num_locals)
        },
        Ast::LocalRangeFrom(index) => {
            let index = index.expect_value();
            Vm::LocalInterval(index, index, aligned_num_locals)
        },
        Ast::LocalAll => {
            let end_exclusive = Ord::max(1, proc_ctx.num_locals());
            Vm::LocalInterval(0, end_exclusive - 1, aligned_num_locals)
        },
        Ast::AdvStackTop(n) => Vm::AdvStackTop(n.expect_value()),
    };

    Ok(compiled)
}
