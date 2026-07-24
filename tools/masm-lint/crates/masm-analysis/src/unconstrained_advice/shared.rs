//! Shared transfer helpers for unconstrained-advice analyses.

use masm_decompiler::analysis::{Stmt, Var};

use super::domain::AdviceFact;
pub(super) use super::{
    env::Env,
    expr::{
        assign_expr_metadata, collect_expr_sink_fact, expr_is_proven_nonzero, expr_output_fact,
        expr_u32_validity, refine_if_envs,
    },
    intrinsic_transfer::{apply_intrinsic_effect, refine_nonzero_from_intrinsic},
    local_transfer::{
        apply_local_load_scalar, apply_local_load_word, apply_local_store, apply_local_store_word,
    },
    loop_transfer::{assign_phi_metadata, join_loop_head_env, stabilized_loop_head_env},
};

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
