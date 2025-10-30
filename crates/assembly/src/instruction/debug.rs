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

    // NOTE: these `ast::Immediate::expect_value()` calls *should* be safe, because by the time
    // we're compiling debug options all immediate-constant arguments should be resolved.
    let compiled = match options {
        Ast::StackAll => Vm::StackAll,
        Ast::StackTop(n) => Vm::StackTop(n.expect_value()),
        Ast::MemAll => Vm::MemAll,
        Ast::MemInterval(start, end) => Vm::MemInterval(start.expect_value(), end.expect_value()),
        Ast::LocalInterval(start, end) => {
            let (start, end) = (start.expect_value(), end.expect_value());
            Vm::LocalInterval(start, end, proc_ctx.num_locals())
        },
        Ast::LocalRangeFrom(index) => {
            let index = index.expect_value();
            Vm::LocalInterval(index, index, proc_ctx.num_locals())
        },
        Ast::LocalAll => {
            let end_exclusive = Ord::max(1, proc_ctx.num_locals());
            Vm::LocalInterval(0, end_exclusive - 1, proc_ctx.num_locals())
        },
        Ast::AdvStackTop(n) => Vm::AdvStackTop(n.expect_value()),
    };

    Ok(compiled)
}
