//! Call-summary transfer helpers for intraprocedural type inference.

use super::{domain::TypeFact, summary::TypeSummary};
use crate::ir::Var;

/// Resolve the type facts assigned to call results by a callee summary.
pub(super) fn result_types(
    summary: &TypeSummary,
    args: &[Var],
    result_count: usize,
    mut inferred_type_for_var: impl FnMut(&Var) -> TypeFact,
) -> Vec<TypeFact> {
    (0..result_count)
        .map(|idx| result_type_for_index(summary, args, idx, |arg| inferred_type_for_var(arg)))
        .collect()
}

/// Resolve argument requirements imposed by a known callee summary.
pub(super) fn arg_requirements<'a>(
    summary: &TypeSummary,
    args: &'a [Var],
) -> Vec<(&'a Var, TypeFact)> {
    if summary.is_opaque() {
        return Vec::new();
    }
    args.iter()
        .zip(summary.inputs.iter().copied())
        .map(|(arg, expected)| (arg, TypeFact::from_requirement(expected)))
        .collect()
}

/// Resolve the caller argument that feeds a passthrough callee result.
pub(super) fn passthrough_result_arg<'a>(
    summary: &TypeSummary,
    args: &'a [Var],
    result_index: usize,
) -> Option<&'a Var> {
    if summary.is_opaque() {
        return None;
    }
    let input_idx = summary.output_input_map.get(result_index).copied().flatten()?;
    // Summary input positions use 0=deepest, while call args use 0=topmost.
    args.len().checked_sub(1 + input_idx).and_then(|idx| args.get(idx))
}

/// Resolve argument requirements implied by required passthrough call results.
pub(super) fn passthrough_result_requirements<'a>(
    summary: &TypeSummary,
    args: &'a [Var],
    results: &[Var],
    mut requirement_for_var: impl FnMut(&Var) -> TypeFact,
) -> Vec<(&'a Var, TypeFact)> {
    results
        .iter()
        .enumerate()
        .filter_map(|(idx, result)| {
            let req = requirement_for_var(result);
            if req == TypeFact::Felt {
                return None;
            }
            passthrough_result_arg(summary, args, idx).map(|arg| (arg, req))
        })
        .collect()
}

fn result_type_for_index(
    summary: &TypeSummary,
    args: &[Var],
    result_index: usize,
    mut inferred_type_for_var: impl FnMut(&Var) -> TypeFact,
) -> TypeFact {
    if summary.is_opaque() {
        return TypeFact::Felt;
    }
    if let Some(arg) = passthrough_result_arg(summary, args, result_index) {
        return inferred_type_for_var(arg);
    }
    summary
        .outputs
        .get(result_index)
        .map(|ty| TypeFact::from_inferred_type(*ty))
        .unwrap_or(TypeFact::Felt)
}
