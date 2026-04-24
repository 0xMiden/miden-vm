//! Shared helpers for exact declared MASM type surfaces.

use std::collections::{HashMap, HashSet};

use miden_assembly_syntax::ast::{FunctionType, Procedure, TypeDecl, TypeExpr, types::Type};

use super::{
    domain::{InferredType, TypeRequirement},
    summary::TypeSummary,
};
use crate::frontend::Program;

/// Build an exact scalar type summary from a declared procedure signature.
///
/// Only declarations that map exactly onto the current scalar public surface
/// are supported. Unsupported declared types return `None`.
pub(crate) fn declared_summary_for_proc(
    program: &Program,
    proc: &Procedure,
) -> Option<TypeSummary> {
    let aliases = module_type_aliases(program);
    let signature = proc.signature()?;
    let input_parts = flatten_declared_signature_inputs(signature, &aliases)?;
    let output_parts = flatten_declared_signature_outputs(signature, &aliases)?;
    Some(TypeSummary::new(input_parts, output_parts))
}

/// Build an exact scalar type summary from a declared procedure signature when
/// its stack-cell arity matches the inferred procedure signature.
pub(crate) fn declared_summary_for_proc_with_arity(
    program: &Program,
    proc: &Procedure,
    inputs: usize,
    outputs: usize,
) -> Option<TypeSummary> {
    let summary = declared_summary_for_proc(program, proc)?;
    let input_parts = summary.inputs;
    let output_parts = summary.outputs;
    (input_parts.len() == inputs && output_parts.len() == outputs)
        .then_some(TypeSummary::new(input_parts, output_parts))
}

/// Collect module-local type aliases by their local names.
fn module_type_aliases(program: &Program) -> HashMap<String, TypeExpr> {
    program
        .module()
        .types()
        .filter_map(|decl| match decl {
            TypeDecl::Alias(alias) => Some((alias.name().to_string(), alias.ty.clone())),
            TypeDecl::Enum(_) => None,
        })
        .collect()
}

/// Flatten declared parameter types to top-of-stack-first requirements.
fn flatten_declared_signature_inputs(
    signature: &FunctionType,
    aliases: &HashMap<String, TypeExpr>,
) -> Option<Vec<TypeRequirement>> {
    let mut parts = Vec::new();
    for ty in &signature.args {
        parts.extend(flatten_declared_type_expr(ty, aliases, &mut HashSet::new())?);
    }
    parts.reverse();
    Some(parts.into_iter().map(declared_part_requirement).collect())
}

/// Flatten declared result types to top-of-stack-first inferred types.
fn flatten_declared_signature_outputs(
    signature: &FunctionType,
    aliases: &HashMap<String, TypeExpr>,
) -> Option<Vec<InferredType>> {
    let mut parts = Vec::new();
    for ty in &signature.results {
        parts.extend(flatten_declared_type_expr(ty, aliases, &mut HashSet::new())?);
    }
    parts.reverse();
    Some(parts.into_iter().map(declared_part_output).collect())
}

/// Expand a declared source-level type to stack-cell scalar parts.
///
/// Only types that can be represented exactly in the current scalar surface
/// are supported here. Anything else stays unsupported.
fn flatten_declared_type_expr(
    ty: &TypeExpr,
    aliases: &HashMap<String, TypeExpr>,
    seen_aliases: &mut HashSet<String>,
) -> Option<Vec<DeclaredScalarPart>> {
    match ty {
        TypeExpr::Primitive(ty) => {
            let parts = match ty.inner() {
                Type::I1 => vec![DeclaredScalarPart::Bool],
                Type::U32 => vec![DeclaredScalarPart::U32],
                Type::U64 => vec![DeclaredScalarPart::U32; 2],
                Type::U128 => vec![DeclaredScalarPart::U32; 4],
                Type::U256 => vec![DeclaredScalarPart::U32; 8],
                Type::Felt => vec![DeclaredScalarPart::Felt],
                _ => return None,
            };
            Some(parts)
        },
        TypeExpr::Struct(ty) => {
            let mut parts = Vec::new();
            for field in ty.fields.iter() {
                parts.extend(flatten_declared_type_expr(&field.ty, aliases, seen_aliases)?);
            }
            Some(parts)
        },
        TypeExpr::Ref(path) => {
            if path.len() != 1 {
                return None;
            }
            let alias_name = path.last()?.to_string();
            if !seen_aliases.insert(alias_name.clone()) {
                return None;
            }
            let resolved = aliases.get(&alias_name)?;
            let parts = flatten_declared_type_expr(resolved, aliases, seen_aliases);
            seen_aliases.remove(&alias_name);
            parts
        },
        TypeExpr::Ptr(_) | TypeExpr::Array(_) => None,
    }
}

/// Scalar stack-cell kinds supported by exact declared-signature projection.
#[derive(Clone, Copy)]
enum DeclaredScalarPart {
    Felt,
    U32,
    Bool,
}

/// Convert a declared scalar part to a caller-side requirement.
fn declared_part_requirement(part: DeclaredScalarPart) -> TypeRequirement {
    match part {
        DeclaredScalarPart::Felt => TypeRequirement::Felt,
        DeclaredScalarPart::U32 => TypeRequirement::U32,
        DeclaredScalarPart::Bool => TypeRequirement::Bool,
    }
}

/// Convert a declared scalar part to a callee-output guarantee.
fn declared_part_output(part: DeclaredScalarPart) -> InferredType {
    match part {
        DeclaredScalarPart::Felt => InferredType::Felt,
        DeclaredScalarPart::U32 => InferredType::U32,
        DeclaredScalarPart::Bool => InferredType::Bool,
    }
}
