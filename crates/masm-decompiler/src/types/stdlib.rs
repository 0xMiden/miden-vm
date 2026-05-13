//! Trusted stdlib refinements for type-summary inference.

use super::{
    domain::{InferredType, TypeRequirement},
    summary::TypeSummary,
};
use crate::{
    SymbolPath,
    frontend::{Program, Workspace},
};

/// Refine trusted stdlib helpers to keep exact declared limb inputs.
///
/// This is limited to procedures whose inferred output surface already matches
/// an exact declared summary. That avoids pulling in broken source annotations
/// with mismatched arity while recovering intended `U32` limb preconditions for
/// trusted stdlib helpers such as equality and rotate/shift procedures.
pub(super) fn refine_declared_inputs_when_outputs_exact(
    workspace: &Workspace,
    program: &Program,
    proc_path: &SymbolPath,
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
pub(super) fn refine_known_outputs(
    workspace: &Workspace,
    program: &Program,
    proc_path: &SymbolPath,
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
pub(super) fn refine_known_inputs(
    workspace: &Workspace,
    program: &Program,
    proc_path: &SymbolPath,
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
