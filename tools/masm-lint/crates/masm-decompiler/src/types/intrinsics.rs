//! Intrinsic type-transfer helpers for intraprocedural type inference.

use super::domain::TypeFact;
use crate::{
    ir::Var,
    semantics::{
        IntrinsicOutputTypeShape, intrinsic_arg_requirements, intrinsic_base_name,
        intrinsic_output_type_shape,
    },
};

/// Resolve all output type facts for an intrinsic invocation.
pub(super) fn output_types(
    name: &str,
    output_count: usize,
    args: &[Var],
    mut inferred_type_for_var: impl FnMut(&Var) -> TypeFact,
) -> Vec<TypeFact> {
    (0..output_count)
        .map(|idx| output_type(name, idx, output_count, args, |arg| inferred_type_for_var(arg)))
        .collect()
}

/// Return the common proven fact established by a scalar equality assertion.
///
/// When `assert_eq(lhs, rhs)` succeeds, both operands must satisfy the
/// greatest lower bound of their already-proven facts.
pub(super) fn assert_eq_common_fact(
    name: &str,
    args: &[Var],
    mut inferred_type_for_var: impl FnMut(&Var) -> TypeFact,
) -> Option<TypeFact> {
    if intrinsic_base_name(name) != "assert_eq" || args.len() != 2 {
        return None;
    }

    let lhs = inferred_type_for_var(&args[0]);
    let rhs = inferred_type_for_var(&args[1]);
    let common = lhs.glb(rhs);
    (common != TypeFact::Felt).then_some(common)
}

/// Return argument requirements imposed by an intrinsic invocation.
pub(super) fn arg_requirements<'a>(
    name: &str,
    args: &'a [Var],
    result_count: usize,
    allow_proof_narrowing: bool,
    mut inferred_type_for_var: impl FnMut(&Var) -> TypeFact,
) -> Vec<(&'a Var, TypeFact)> {
    let mut requirements = Vec::new();

    let intrinsic_requirements = intrinsic_arg_requirements(name, args.len(), result_count);
    if let Some(range) = intrinsic_requirements.u32_args {
        requirements.extend(args[range].iter().filter_map(|arg| {
            (!inferred_type_for_var(arg).satisfies(TypeFact::U32)).then_some((arg, TypeFact::U32))
        }));
    }

    if allow_proof_narrowing
        && let Some(common_fact) = assert_eq_common_fact(name, args, &mut inferred_type_for_var)
    {
        requirements.extend(args.iter().map(|arg| (arg, common_fact)));
    }

    requirements
}

fn output_type(
    name: &str,
    output_index: usize,
    output_count: usize,
    args: &[Var],
    mut inferred_type_for_var: impl FnMut(&Var) -> TypeFact,
) -> TypeFact {
    match intrinsic_output_type_shape(name) {
        IntrinsicOutputTypeShape::Felt => TypeFact::Felt,
        IntrinsicOutputTypeShape::U32 => TypeFact::U32,
        IntrinsicOutputTypeShape::Bool => TypeFact::Bool,
        IntrinsicOutputTypeShape::U32WithTopBool => {
            if output_index + 1 == output_count {
                TypeFact::Bool
            } else {
                TypeFact::U32
            }
        },
        IntrinsicOutputTypeShape::BoolWithTopU32 => {
            if output_index + 1 == output_count {
                TypeFact::U32
            } else {
                TypeFact::Bool
            }
        },
        IntrinsicOutputTypeShape::U32WideningAdd3 => {
            if output_index + 1 == output_count {
                TypeFact::U32
            } else if args.iter().any(|arg| inferred_type_for_var(arg) == TypeFact::Bool) {
                TypeFact::Bool
            } else {
                TypeFact::U32
            }
        },
    }
}
