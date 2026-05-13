//! Shared transfer helpers for unconstrained-advice analyses.

pub(super) use masm_decompiler::{
    INTRINSIC_ADV_PIPE, INTRINSIC_ADV_PUSH, INTRINSIC_ADV_PUSHW, INTRINSIC_MEM_STREAM,
    intrinsic_base_name, intrinsic_memory_address_arg_index, intrinsic_merkle_root_arg_range,
    intrinsic_nonzero_arg_index, intrinsic_positional_u32_arg_range,
    intrinsic_requires_u32_precondition,
};
use masm_decompiler::{Intrinsic, LocalAccessKind, LoopPhi, Stmt, Var};

use super::{domain::AdviceFact, u32_domain::U32Validity};
pub(super) use super::{
    env::Env,
    expr::{
        assign_expr_metadata, collect_expr_sink_fact, expr_is_proven_nonzero, expr_output_fact,
        expr_u32_validity, refine_if_envs,
    },
};
use crate::abstract_interp::{FixpointConfig, JoinSemiLattice, iterate_to_fixpoint};

/// Maximum number of loop-approximation passes.
pub(super) const MAX_LOOP_PASSES: usize = 32;

/// Seed input variables using the same numbering scheme as the lifting pass.
pub(super) fn seed_input_env(input_count: usize) -> Env {
    let mut env = Env::default();
    for depth in 0..input_count {
        let input_position = input_count - 1 - depth;
        let var = Var::new((depth as u64).into(), depth);
        env.set_var_fact(&var, AdviceFact::from_input(input_position));
    }
    env
}

/// Preserve metadata across a phi only when both sides agree on the fact being preserved.
pub(super) fn assign_phi_metadata(
    dest: &Var,
    lhs_var: &Var,
    lhs_env: &Env,
    rhs_var: &Var,
    rhs_env: &Env,
    env: &mut Env,
) {
    let lhs_identity = lhs_env.identity_for_var(lhs_var);
    let rhs_identity = rhs_env.identity_for_var(rhs_var);
    if lhs_identity == rhs_identity {
        env.set_var_identity(dest, lhs_identity);
    } else {
        env.clear_var_identity(dest);
    }

    let lhs_witness = lhs_env.zero_test_for_var(lhs_var);
    let rhs_witness = rhs_env.zero_test_for_var(rhs_var);
    if lhs_witness.is_some() && lhs_witness == rhs_witness {
        env.set_var_zero_test(dest, lhs_witness);
    } else {
        env.set_var_zero_test(dest, None);
    }

    env.set_var_u32_validity(
        dest,
        lhs_env
            .u32_validity_for_var(lhs_var)
            .join(rhs_env.u32_validity_for_var(rhs_var)),
    );
}

/// Join one loop-body evaluation back into the current abstract loop state.
pub(super) fn join_loop_head_env(
    loop_env: &Env,
    entry_env: &Env,
    body_env: &Env,
    phis: &[LoopPhi],
) -> Env {
    let mut next_env = loop_env.join(body_env);
    for phi in phis {
        let merged = entry_env.fact_for_var(&phi.init).join(&body_env.fact_for_var(&phi.step));
        next_env.set_var_fact(&phi.dest, merged);
        assign_phi_metadata(&phi.dest, &phi.init, entry_env, &phi.step, body_env, &mut next_env);
    }

    next_env
}

/// Loop-head state used while iterating to a stable environment.
#[derive(Clone)]
struct LoopHeadState<'a> {
    env: Env,
    entry_env: &'a Env,
    phis: &'a [LoopPhi],
}

impl<'a> LoopHeadState<'a> {
    /// Build the initial loop-head state from the loop entry environment.
    fn at_loop_head(entry_env: &'a Env, phis: &'a [LoopPhi]) -> Self {
        Self { env: entry_env.clone(), entry_env, phis }
    }

    /// Build the candidate state produced by one loop-body evaluation.
    fn from_body_env(body_env: Env, entry_env: &'a Env, phis: &'a [LoopPhi]) -> Self {
        Self { env: body_env, entry_env, phis }
    }

    /// Return a clone of the stabilized loop-head environment.
    fn env(&self) -> Env {
        self.env.clone()
    }
}

impl JoinSemiLattice for LoopHeadState<'_> {
    fn join_assign(&mut self, other: &Self) -> bool {
        let next_env = join_loop_head_env(&self.env, self.entry_env, &other.env, self.phis);
        let changed = self.env != next_env;
        self.env = next_env;
        changed
    }
}

/// Iterate a loop body to a stable loop-head environment.
pub(super) fn stabilized_loop_head_env(
    entry_env: &Env,
    phis: &[LoopPhi],
    mut eval_body: impl FnMut(Env) -> Env,
) -> Env {
    iterate_to_fixpoint(
        LoopHeadState::at_loop_head(entry_env, phis),
        FixpointConfig::new(MAX_LOOP_PASSES),
        |loop_env| {
            let body_env = eval_body(loop_env.env());
            LoopHeadState::from_body_env(body_env, entry_env, phis)
        },
    )
    .into_state()
    .env()
}

/// Refine the environment after `assertz` proves an `eq.0` witness is zero.
pub(super) fn refine_nonzero_from_intrinsic(intrinsic: &Intrinsic, env: &mut Env) {
    if intrinsic_base_name(&intrinsic.name) != "assertz" {
        return;
    }
    let Some(arg) = intrinsic.args.first() else {
        return;
    };
    let Some(witness) = env.zero_test_for_var(arg) else {
        return;
    };
    env.mark_identity_nonzero(witness.value_identity);
}

/// Apply the common provenance transfer semantics of one intrinsic statement.
pub(super) fn apply_intrinsic_effect(
    span: miden_debug_types::SourceSpan,
    intrinsic: &Intrinsic,
    env: &mut Env,
) {
    if matches!(intrinsic_base_name(&intrinsic.name), INTRINSIC_ADV_PUSH | INTRINSIC_ADV_PUSHW) {
        for result in &intrinsic.results {
            env.set_var_fact(result, AdviceFact::from_source(span));
            env.clear_var_metadata(result);
        }
        return;
    }

    match intrinsic_base_name(&intrinsic.name) {
        "u32assert" | "u32assert2" | "u32assertw" => {
            for arg in &intrinsic.args {
                env.sanitize_var(arg);
            }
        },
        "u32split" => {
            for (index, result) in intrinsic.results.iter().enumerate() {
                env.set_var_fact(result, AdviceFact::bottom());
                env.clear_var_metadata(result);
                if index == intrinsic.results.len().saturating_sub(1) {
                    env.set_var_u32_validity(result, U32Validity::ProvenU32);
                }
            }
        },
        "is_odd" => {
            for result in &intrinsic.results {
                env.set_var_fact(result, AdviceFact::bottom());
                env.clear_var_metadata(result);
            }
        },
        "u32testw" => {
            if let Some((flag, preserved)) = intrinsic.results.split_first() {
                env.set_var_fact(flag, AdviceFact::bottom());
                env.clear_var_metadata(flag);
                env.set_var_u32_validity(flag, U32Validity::ProvenU32);
                for (result, arg) in preserved.iter().zip(intrinsic.args.iter()) {
                    env.set_var_fact(result, env.fact_for_var(arg));
                    env.set_var_u32_validity(result, env.u32_validity_for_var(arg));
                    env.set_var_identity(result, env.identity_for_var(arg));
                    env.set_var_zero_test(result, env.zero_test_for_var(arg));
                }
            }
        },
        INTRINSIC_ADV_PIPE => {
            apply_adv_pipe_effect(span, intrinsic, env);
        },
        INTRINSIC_MEM_STREAM => {
            apply_mem_stream_effect(intrinsic, env);
        },
        "sdepth" => {
            for result in &intrinsic.results {
                env.set_var_fact(result, AdviceFact::bottom());
                env.clear_var_metadata(result);
            }
        },
        name if name.starts_with("locaddr") => {
            for result in &intrinsic.results {
                env.set_var_fact(result, AdviceFact::bottom());
                env.clear_var_metadata(result);
            }
        },
        _ if intrinsic_requires_u32_precondition(&intrinsic.name) => {
            for result in &intrinsic.results {
                env.set_var_fact(result, AdviceFact::bottom());
                env.clear_var_metadata(result);
                env.set_var_u32_validity(result, U32Validity::ProvenU32);
            }
        },
        _ => {
            let joined =
                AdviceFact::join_all(intrinsic.args.iter().map(|arg| env.fact_for_var(arg)));
            for result in &intrinsic.results {
                env.set_var_fact(result, joined.clone());
                env.clear_var_metadata(result);
            }
        },
    }
}

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

/// Return the statement span for a structured statement.
pub(super) fn stmt_span(stmt: &Stmt) -> miden_debug_types::SourceSpan {
    match stmt {
        Stmt::Assign { span, .. }
        | Stmt::MemLoad { span, .. }
        | Stmt::MemStore { span, .. }
        | Stmt::AdvLoad { span, .. }
        | Stmt::AdvStore { span, .. }
        | Stmt::LocalLoad { span, .. }
        | Stmt::LocalStore { span, .. }
        | Stmt::LocalStoreW { span, .. }
        | Stmt::Call { span, .. }
        | Stmt::Exec { span, .. }
        | Stmt::SysCall { span, .. }
        | Stmt::DynCall { span, .. }
        | Stmt::Intrinsic { span, .. }
        | Stmt::Repeat { span, .. }
        | Stmt::If { span, .. }
        | Stmt::While { span, .. }
        | Stmt::Return { span, .. } => *span,
    }
}

/// Return the sole variable in the slice, if there is exactly one.
pub(super) fn single_var(vars: &[Var]) -> Option<&Var> {
    match vars {
        [var] => Some(var),
        _ => None,
    }
}

/// Apply the custom transfer semantics of `mem_stream`.
fn apply_mem_stream_effect(intrinsic: &Intrinsic, env: &mut Env) {
    if intrinsic.args.len() == 13 && intrinsic.results.len() == 13 {
        let address = &intrinsic.args[12];
        env.set_var_fact(&intrinsic.results[0], env.fact_for_var(address));
        env.set_var_u32_validity(&intrinsic.results[0], U32Validity::Unknown);
        env.clear_var_metadata(&intrinsic.results[0]);

        for (offset, result) in intrinsic.results[1..5].iter().enumerate() {
            let preserved_input = &intrinsic.args[11 - offset];
            env.set_var_fact(result, env.fact_for_var(preserved_input));
            env.set_var_u32_validity(result, env.u32_validity_for_var(preserved_input));
            env.set_var_identity(result, env.identity_for_var(preserved_input));
            env.set_var_zero_test(result, env.zero_test_for_var(preserved_input));
        }

        for result in &intrinsic.results[5..] {
            env.set_var_fact(result, AdviceFact::bottom());
            env.clear_var_metadata(result);
        }
        return;
    }

    for result in &intrinsic.results {
        env.set_var_fact(result, AdviceFact::bottom());
        env.clear_var_metadata(result);
    }
}

/// Apply the custom transfer semantics of `adv_pipe`.
fn apply_adv_pipe_effect(
    span: miden_debug_types::SourceSpan,
    intrinsic: &Intrinsic,
    env: &mut Env,
) {
    if intrinsic.args.len() == 13 && intrinsic.results.len() == 13 {
        env.set_var_fact(&intrinsic.results[0], AdviceFact::bottom());
        env.clear_var_metadata(&intrinsic.results[0]);

        for (offset, result) in intrinsic.results[1..5].iter().enumerate() {
            let preserved_input = &intrinsic.args[11 - offset];
            env.set_var_fact(result, env.fact_for_var(preserved_input));
            env.set_var_u32_validity(result, env.u32_validity_for_var(preserved_input));
            env.set_var_identity(result, env.identity_for_var(preserved_input));
            env.set_var_zero_test(result, env.zero_test_for_var(preserved_input));
        }

        for result in &intrinsic.results[5..] {
            env.set_var_fact(result, AdviceFact::from_source(span));
            env.clear_var_metadata(result);
        }
        return;
    }

    for result in &intrinsic.results {
        env.set_var_fact(result, AdviceFact::from_source(span));
        env.clear_var_metadata(result);
    }
}
