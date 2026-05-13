//! Local-memory transfer helpers for unconstrained-advice analyses.

use masm_decompiler::analysis::{LocalAccessKind, Var};

use super::{domain::AdviceFact, env::Env, u32_domain::U32Validity};

/// Store a scalar local and preserve exact alias metadata when possible.
pub(super) fn apply_local_store(values: &[Var], index: u32, env: &mut Env) {
    let fact = AdviceFact::join_all(values.iter().map(|var| env.fact_for_var(var)));
    env.set_local_fact(index, fact);
    let validity = single_var(values)
        .map(|var| env.u32_validity_for_var(var))
        .unwrap_or(U32Validity::Unknown);
    env.set_local_u32_validity(index, validity);
    let identity = single_var(values).map(|var| env.identity_for_var(var));
    let witness = single_var(values).and_then(|var| env.zero_test_for_var(var));
    env.set_local_identity(index, identity);
    env.set_local_zero_test(index, witness);
}

/// Store a local word slot-by-slot.
pub(super) fn apply_local_store_word(
    kind: LocalAccessKind,
    values: &[Var],
    index: u32,
    env: &mut Env,
) {
    for (offset, value) in values.iter().enumerate() {
        let slot = match kind {
            // Canonical slot order follows ascending local-memory addresses.
            LocalAccessKind::WordBe => index + (values.len().saturating_sub(1) - offset) as u32,
            LocalAccessKind::WordLe => index + offset as u32,
            LocalAccessKind::Element => index,
        };
        env.set_local_fact(slot, env.fact_for_var(value));
        env.set_local_u32_validity(slot, env.u32_validity_for_var(value));
        env.set_local_identity(slot, None);
        env.set_local_zero_test(slot, None);
    }
}

/// Load a scalar local and restore exact alias metadata when available.
pub(super) fn apply_local_load_scalar(outputs: &[Var], index: u32, env: &mut Env) {
    let fact = env.fact_for_local(index);
    let identity = env.identity_for_local(index);
    let witness = env.zero_test_for_local(index);
    for output in outputs {
        env.set_var_fact(output, fact.clone());
        env.set_var_u32_validity(output, env.u32_validity_for_local(index));
        if let Some(identity) = identity.clone() {
            env.set_var_identity(output, identity);
        } else {
            env.clear_var_identity(output);
        }
        env.set_var_zero_test(output, witness.clone());
    }
}

/// Load a local word slot-by-slot, preserving stack order.
pub(super) fn apply_local_load_word(
    kind: LocalAccessKind,
    outputs: &[Var],
    index: u32,
    env: &mut Env,
) {
    for (offset, output) in outputs.iter().enumerate() {
        let slot = match kind {
            LocalAccessKind::WordBe => index + offset as u32,
            LocalAccessKind::WordLe => index + (outputs.len().saturating_sub(1) - offset) as u32,
            LocalAccessKind::Element => index,
        };
        env.set_var_fact(output, env.fact_for_local(slot));
        env.set_var_u32_validity(output, env.u32_validity_for_local(slot));
        env.clear_var_metadata(output);
    }
}

/// Return the sole variable in the slice, if there is exactly one.
fn single_var(vars: &[Var]) -> Option<&Var> {
    match vars {
        [var] => Some(var),
        _ => None,
    }
}
