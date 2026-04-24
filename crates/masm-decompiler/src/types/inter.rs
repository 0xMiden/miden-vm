//! Interprocedural type-summary inference.

use miden_assembly_syntax::debuginfo::Spanned;

use super::{
    declared_summary_for_proc_with_arity,
    domain::{InferredType, TypeRequirement},
    intra::analyze_proc_types,
    summary::{TypeDiagnosticsMap, TypeSummary, TypeSummaryMap},
};
use crate::{
    callgraph::CallGraph,
    frontend::{Program, Workspace},
    lift,
    signature::{ProcSignature, SignatureMap},
    symbol::resolution::create_resolver,
};

/// Infer type summaries for all procedures in a workspace.
///
/// Procedures are processed in callgraph bottom-up order. Unknown signatures or
/// unsupported lifting patterns produce opaque summaries.
pub fn infer_type_summaries(
    workspace: &Workspace,
    callgraph: &CallGraph,
    signatures: &SignatureMap,
) -> (TypeSummaryMap, TypeDiagnosticsMap) {
    let mut summaries = TypeSummaryMap::default();
    let mut diagnostics = TypeDiagnosticsMap::default();

    for node in callgraph.iter() {
        let summary = infer_summary_for_node(
            workspace,
            node.name.as_str(),
            callgraph,
            signatures,
            &summaries,
            &mut diagnostics,
        );
        summaries.insert(node.name.clone(), summary);
    }

    (summaries, diagnostics)
}

/// Infer a summary for a single procedure.
fn infer_summary_for_node(
    workspace: &Workspace,
    fq_name: &str,
    _callgraph: &CallGraph,
    signatures: &SignatureMap,
    callee_summaries: &TypeSummaryMap,
    diagnostics: &mut TypeDiagnosticsMap,
) -> TypeSummary {
    let proc_path = crate::symbol::path::SymbolPath::new(fq_name.to_string());
    let Some(signature) = signatures.get(&proc_path) else {
        return TypeSummary::opaque();
    };

    let (inputs, outputs) = match signature {
        ProcSignature::Known { public_inputs, outputs, .. } => (*public_inputs, *outputs),
        ProcSignature::Unknown => return TypeSummary::opaque(),
    };

    let Some((program, proc)) = workspace.lookup_proc_entry(&proc_path) else {
        return TypeSummary::opaque_with_arity(inputs, outputs);
    };
    let declared_summary = declared_summary_for_proc_with_arity(program, proc, inputs, outputs);
    let visibility = proc.visibility();
    // Use the procedure name span rather than the full body span for
    // diagnostics. MASM procedures have implicit stack arguments, so
    // there is no explicit parameter list to point at.
    let proc_span = proc.name().span();
    let resolver = create_resolver(program.module(), workspace.source_manager());
    let stmts = match lift::lift_proc(proc, &proc_path, &resolver, signatures) {
        Ok(stmts) => stmts,
        Err(_err) => {
            return declared_summary
                .unwrap_or_else(|| TypeSummary::opaque_with_arity(inputs, outputs));
        },
    };

    let analysis = analyze_proc_types(
        &proc_path,
        inputs,
        outputs,
        visibility,
        proc_span,
        &stmts,
        callee_summaries,
    );
    if !analysis.diagnostics.is_empty() {
        diagnostics.insert(proc_path.clone(), analysis.diagnostics.clone());
    }
    let raw_outputs = analysis.summary.outputs.clone();
    let summary = refine_known_stdlib_outputs(workspace, program, &proc_path, analysis.summary);
    let summary = refine_trusted_declared_inputs_when_outputs_exact(
        workspace,
        program,
        &proc_path,
        summary,
        &raw_outputs,
        declared_summary.as_ref(),
    );
    refine_known_stdlib_inputs(workspace, program, &proc_path, summary, declared_summary.as_ref())
}

/// Refine trusted stdlib helpers to keep exact declared limb inputs.
///
/// This is limited to procedures whose inferred output surface already matches
/// an exact declared summary. That avoids pulling in broken source annotations
/// with mismatched arity while recovering intended `U32` limb preconditions for
/// trusted stdlib helpers such as equality and rotate/shift procedures.
fn refine_trusted_declared_inputs_when_outputs_exact(
    workspace: &Workspace,
    program: &Program,
    proc_path: &crate::symbol::path::SymbolPath,
    summary: TypeSummary,
    raw_outputs: &[InferredType],
    declared_summary: Option<&TypeSummary>,
) -> TypeSummary {
    if !is_trusted_stdlib_program(workspace, program, proc_path.as_str()) {
        return summary;
    }

    let Some(declared) = declared_summary else {
        return summary;
    };
    if raw_outputs != declared.outputs {
        return summary;
    }
    if !declared.inputs.iter().all(|req| *req == TypeRequirement::U32) {
        return summary;
    }

    TypeSummary::new_with_map(declared.inputs.clone(), summary.outputs, summary.output_input_map)
}

/// Refine output summaries for exact stdlib procedures whose return-limb
/// shapes are semantically fixed but currently widen through generic field
/// arithmetic in the local typer.
fn refine_known_stdlib_outputs(
    workspace: &Workspace,
    program: &Program,
    proc_path: &crate::symbol::path::SymbolPath,
    summary: TypeSummary,
) -> TypeSummary {
    if !is_trusted_stdlib_program(workspace, program, proc_path.as_str()) {
        return summary;
    }

    let refined_outputs = match proc_path.as_str() {
        "miden::core::math::u64::shr"
        | "miden::core::math::u64::rotl"
        | "miden::core::math::u64::rotr" => Some(vec![InferredType::U32, InferredType::U32]),
        "miden::core::math::u128::wrapping_mul" => {
            Some(vec![InferredType::U32, InferredType::U32, InferredType::U32, InferredType::U32])
        },
        "miden::core::math::u64::widening_mul" => {
            Some(vec![InferredType::U32, InferredType::U32, InferredType::U32, InferredType::U32])
        },
        "miden::core::math::u256::overflowing_sub" => Some(vec![
            InferredType::U32,
            InferredType::U32,
            InferredType::U32,
            InferredType::U32,
            InferredType::U32,
            InferredType::U32,
            InferredType::U32,
            InferredType::U32,
            InferredType::Bool,
        ]),
        _ => None,
    };

    let Some(outputs) = refined_outputs else {
        return summary;
    };
    if summary.outputs.len() != outputs.len() {
        return summary;
    }

    TypeSummary::new_with_map(summary.inputs, outputs, summary.output_input_map)
}

/// Refine audited stdlib helper inputs whose semantic surface is fixed by the
/// helper definition rather than recovered by the generic local typer.
fn refine_known_stdlib_inputs(
    workspace: &Workspace,
    program: &Program,
    proc_path: &crate::symbol::path::SymbolPath,
    summary: TypeSummary,
    declared_summary: Option<&TypeSummary>,
) -> TypeSummary {
    if !is_trusted_stdlib_program(workspace, program, proc_path.as_str()) {
        return summary;
    }

    let refined_inputs = match (proc_path.as_str(), declared_summary) {
        ("miden::core::math::u64::rotr", Some(TypeSummary { inputs, outputs, .. }))
            if inputs == &[TypeRequirement::U32, TypeRequirement::U32, TypeRequirement::U32]
                && outputs == &[InferredType::U32, InferredType::U32] =>
        {
            Some(inputs.clone())
        },
        _ => None,
    };

    let Some(inputs) = refined_inputs else {
        return summary;
    };
    if summary.inputs.len() != inputs.len() {
        return summary;
    }

    TypeSummary::new_with_map(inputs, summary.outputs, summary.output_input_map)
}

/// Return whether `program` was loaded from a trusted `miden::core` stdlib root.
fn is_trusted_stdlib_program(workspace: &Workspace, program: &Program, proc_path: &str) -> bool {
    const STDLIB_NAMESPACE: &str = "miden::core";

    workspace.roots().iter().any(|root| {
        root.trusted_stdlib
            && root.namespace == STDLIB_NAMESPACE
            && root.matches_module_path(proc_path)
            && program.source_path().starts_with(&root.path)
    })
}
