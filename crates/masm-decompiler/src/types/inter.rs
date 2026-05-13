//! Interprocedural type-summary inference.

use super::{
    declared_summary_for_proc_with_arity,
    intra::analyze_proc_types,
    stdlib,
    summary::{TypeSummary, TypeSummaryMap},
};
use crate::{
    SymbolPath,
    callgraph::CallGraph,
    frontend::{Program, Workspace},
    ir::Stmt,
    signature::{ProcSignature, SignatureMap},
};

/// Infer type summaries using procedures that have already been lifted.
///
/// Procedures are processed in callgraph bottom-up order. Unknown signatures or
/// missing lifted bodies produce opaque summaries.
pub fn infer_type_summaries_from_lifted<'a>(
    workspace: &Workspace,
    callgraph: &CallGraph,
    signatures: &SignatureMap,
    mut lifted_body: impl FnMut(&SymbolPath) -> Option<&'a [Stmt]>,
) -> TypeSummaryMap {
    let mut summaries = TypeSummaryMap::default();

    for node in callgraph.iter() {
        let proc_path = node.name();
        let summary = infer_summary_for_lifted_node(
            workspace,
            proc_path,
            signatures,
            &summaries,
            &mut lifted_body,
        );
        summaries.insert(proc_path.clone(), summary);
    }

    summaries
}

/// Infer a summary for one already-lifted procedure.
fn infer_summary_for_lifted_node<'a>(
    workspace: &Workspace,
    proc_path: &SymbolPath,
    signatures: &SignatureMap,
    callee_summaries: &TypeSummaryMap,
    lifted_body: &mut impl FnMut(&SymbolPath) -> Option<&'a [Stmt]>,
) -> TypeSummary {
    let Some(signature) = signatures.get(proc_path) else {
        return TypeSummary::opaque();
    };

    let (inputs, outputs) = match signature {
        ProcSignature::Known { public_inputs, outputs, .. } => (*public_inputs, *outputs),
        ProcSignature::Unknown => return TypeSummary::opaque(),
    };

    let Some((program, proc)) = workspace.lookup_proc_entry(proc_path) else {
        return TypeSummary::opaque_with_arity(inputs, outputs);
    };
    let declared_summary = declared_summary_for_proc_with_arity(program, proc, inputs, outputs);
    let Some(stmts) = lifted_body(proc_path) else {
        return declared_summary.unwrap_or_else(|| TypeSummary::opaque_with_arity(inputs, outputs));
    };

    infer_summary_from_stmts(
        workspace,
        program,
        proc_path,
        inputs,
        outputs,
        stmts,
        callee_summaries,
        declared_summary,
    )
}

/// Infer and refine a summary from a lifted procedure body.
fn infer_summary_from_stmts(
    workspace: &Workspace,
    program: &Program,
    proc_path: &SymbolPath,
    inputs: usize,
    outputs: usize,
    stmts: &[Stmt],
    callee_summaries: &TypeSummaryMap,
    declared_summary: Option<TypeSummary>,
) -> TypeSummary {
    let analysis = analyze_proc_types(inputs, outputs, stmts, callee_summaries);
    let raw_outputs = analysis.outputs.clone();
    let summary = stdlib::refine_known_outputs(workspace, program, proc_path, analysis);
    let summary = stdlib::refine_declared_inputs_when_outputs_exact(
        workspace,
        program,
        proc_path,
        summary,
        &raw_outputs,
        declared_summary.as_ref(),
    );
    stdlib::refine_known_inputs(workspace, program, proc_path, summary, declared_summary.as_ref())
}
