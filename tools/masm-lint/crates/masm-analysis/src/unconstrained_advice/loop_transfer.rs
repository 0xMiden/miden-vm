//! Loop transfer helpers for unconstrained-advice analyses.

use masm_decompiler::analysis::{
    FixpointConfig, JoinSemiLattice, LoopPhi, Var, iterate_to_fixpoint,
};

use super::env::Env;

/// Maximum number of loop-approximation passes.
const MAX_LOOP_PASSES: usize = 32;

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
