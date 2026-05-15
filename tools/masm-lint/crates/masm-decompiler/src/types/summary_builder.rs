//! Final procedure type summary construction.

use std::collections::HashMap;

use super::{
    domain::{TypeFact, VarKey},
    origin::{self, Origin},
    summary::TypeSummary,
};
use crate::ir::{Stmt, Var};

/// Build the final procedure summary from inferred and required type facts.
pub(super) fn build_summary(
    input_count: usize,
    output_count: usize,
    stmts: &[Stmt],
    inferred: &HashMap<VarKey, TypeFact>,
    required: &HashMap<VarKey, TypeFact>,
    origins: &HashMap<VarKey, Origin>,
) -> TypeSummary {
    let mut inputs = Vec::with_capacity(input_count);
    for index in (0..input_count).rev() {
        let key = origin::input_var_key(index);
        let req = required.get(&key).copied().unwrap_or(TypeFact::Felt);
        inputs.push(req.to_requirement());
    }

    let mut outputs = Vec::with_capacity(output_count);
    let mut output_input_map = Vec::with_capacity(output_count);
    let return_values = find_return_values(stmts);
    for index in (0..output_count).rev() {
        let (ty, origin_input) = return_values
            .and_then(|values| values.get(index))
            .map(|var| output_type_and_origin(var, inferred, required, origins))
            .unwrap_or((TypeFact::Felt, None));
        outputs.push(ty.to_inferred_type());
        output_input_map.push(origin_input);
    }

    TypeSummary::new_with_map(inputs, outputs, output_input_map)
}

fn output_type_and_origin(
    var: &Var,
    inferred: &HashMap<VarKey, TypeFact>,
    required: &HashMap<VarKey, TypeFact>,
    origins: &HashMap<VarKey, Origin>,
) -> (TypeFact, Option<usize>) {
    let inferred = inferred_type_for_var(var, inferred);
    let key = VarKey::from_var(var);
    if let Some(Origin::Input(input_idx)) = origins.get(&key) {
        let input_key = origin::input_var_key(*input_idx);
        let input_req = required.get(&input_key).copied().unwrap_or(TypeFact::Felt);
        (inferred.glb(input_req), Some(*input_idx))
    } else {
        (inferred, None)
    }
}

fn find_return_values(stmts: &[Stmt]) -> Option<&[Var]> {
    for stmt in stmts {
        if let Stmt::Return { values, .. } = stmt {
            return Some(values);
        }
    }
    None
}

fn inferred_type_for_var(var: &Var, inferred: &HashMap<VarKey, TypeFact>) -> TypeFact {
    inferred.get(&VarKey::from_var(var)).copied().unwrap_or(TypeFact::Felt)
}
