//! Generic statement walker for sink-detection passes.

use std::collections::HashMap;

use masm_decompiler::{LocalAccessKind, LoopPhi, Stmt, SymbolPath};

use super::{
    domain::AdviceFact,
    provenance::assign_call_results,
    shared::{
        Env, MAX_LOOP_PASSES, apply_intrinsic_effect, apply_local_load_scalar,
        apply_local_load_word, apply_local_store, apply_local_store_word, assign_expr_metadata,
        assign_phi_metadata, expr_output_fact, join_loop_head_env, refine_if_envs, seed_input_env,
    },
    summary::{AdviceDiagnostic, AdviceDiagnosticsMap, AdviceSummaryMap},
};
use crate::{
    abstract_interp::{FixpointConfig, JoinSemiLattice, iterate_to_fixpoint},
    prepared::PreparedProc,
};

/// Trait for passes that detect specific advice-reaching-sink patterns.
pub(super) trait SinkDetector {
    /// Inspect a statement before environment updates are applied.
    ///
    /// Return any diagnostics for sinks detected in this statement.
    fn check_stmt(&self, stmt: &Stmt, env: &Env) -> Vec<AdviceDiagnostic>;
}

/// Collect diagnostics for all procedures using a sink detector.
pub(super) fn collect_diagnostics<D: SinkDetector>(
    prepared: &HashMap<SymbolPath, PreparedProc>,
    provenance_summaries: &AdviceSummaryMap,
    make_detector: impl Fn(SymbolPath) -> D,
) -> AdviceDiagnosticsMap {
    let mut diagnostics = AdviceDiagnosticsMap::default();

    for (proc_path, proc) in prepared {
        let Some(stmts) = proc.stmts.as_deref() else {
            continue;
        };
        let detector = make_detector(proc_path.clone());
        let proc_diags = walk_procedure(&detector, provenance_summaries, proc.inputs, stmts);
        if !proc_diags.is_empty() {
            diagnostics.insert(proc_path.clone(), proc_diags);
        }
    }

    diagnostics
}

/// Walk one procedure body, collecting diagnostics from the detector.
fn walk_procedure<D: SinkDetector>(
    detector: &D,
    provenance_summaries: &AdviceSummaryMap,
    input_count: usize,
    stmts: &[Stmt],
) -> Vec<AdviceDiagnostic> {
    let env = seed_input_env(input_count);
    eval_block(detector, provenance_summaries, stmts, env).diagnostics
}

/// Result of evaluating a statement block.
struct EvalResult {
    env: Env,
    diagnostics: Vec<AdviceDiagnostic>,
}

/// Loop-head state used when sink walkers iterate to a stable environment.
///
/// The walker still collects diagnostics from a final pass over the stabilized loop-head
/// environment, but the fixpoint engine now owns the convergence bookkeeping.
#[derive(Clone)]
struct SinkLoopState<'a> {
    env: Env,
    entry_env: &'a Env,
    phis: &'a [LoopPhi],
}

impl<'a> SinkLoopState<'a> {
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

impl JoinSemiLattice for SinkLoopState<'_> {
    fn join_assign(&mut self, other: &Self) -> bool {
        let next_env = join_loop_head_env(&self.env, self.entry_env, &other.env, self.phis);
        let changed = self.env != next_env;
        self.env = next_env;
        changed
    }
}

/// Evaluate a statement block from top to bottom.
fn eval_block<D: SinkDetector>(
    detector: &D,
    summaries: &AdviceSummaryMap,
    stmts: &[Stmt],
    mut env: Env,
) -> EvalResult {
    let mut diagnostics = Vec::new();

    for stmt in stmts {
        let result = eval_stmt(detector, summaries, stmt, env);
        env = result.env;
        diagnostics.extend(result.diagnostics);
    }

    EvalResult { env, diagnostics }
}

/// Evaluate a single statement: check for sinks, then apply env updates.
fn eval_stmt<D: SinkDetector>(
    detector: &D,
    summaries: &AdviceSummaryMap,
    stmt: &Stmt,
    mut env: Env,
) -> EvalResult {
    let mut diagnostics = detector.check_stmt(stmt, &env);

    match stmt {
        Stmt::Assign { dest, expr, .. } => {
            let fact = expr_output_fact(expr, &env);
            env.set_var_fact(dest, fact);
            assign_expr_metadata(dest, expr, &mut env);
        },
        Stmt::AdvLoad { span, load } => {
            for output in &load.outputs {
                env.set_var_fact(output, AdviceFact::from_source(*span));
                env.clear_var_metadata(output);
            }
        },
        Stmt::AdvStore { .. } | Stmt::Return { .. } => {},
        Stmt::MemStore { .. } => {},
        Stmt::MemLoad { load, .. } => {
            for output in &load.outputs {
                env.set_var_fact(output, AdviceFact::bottom());
                env.clear_var_metadata(output);
            }
        },
        Stmt::LocalStore { store, .. } => {
            apply_local_store(&store.values, u32::from(store.index), &mut env);
        },
        Stmt::LocalStoreW { store, .. } => {
            apply_local_store_word(store.kind, &store.values, u32::from(store.index), &mut env);
        },
        Stmt::LocalLoad { load, .. } => match load.kind {
            LocalAccessKind::Element => {
                apply_local_load_scalar(&load.outputs, u32::from(load.index), &mut env);
            },
            LocalAccessKind::WordBe | LocalAccessKind::WordLe => {
                apply_local_load_word(load.kind, &load.outputs, u32::from(load.index), &mut env);
            },
        },
        Stmt::Call { call, .. } | Stmt::Exec { call, .. } | Stmt::SysCall { call, .. } => {
            assign_call_results(&mut env, &call.target, &call.args, &call.results, summaries);
        },
        Stmt::DynCall { results, .. } => {
            for result in results {
                env.set_var_fact(result, AdviceFact::bottom());
                env.clear_var_metadata(result);
            }
        },
        Stmt::Intrinsic { span, intrinsic } => {
            apply_intrinsic_effect(*span, intrinsic, &mut env);
        },
        Stmt::If { cond, then_body, else_body, phis, .. } => {
            let (then_env, else_env) = refine_if_envs(cond, &env);
            let then_result = eval_block(detector, summaries, then_body, then_env);
            let else_result = eval_block(detector, summaries, else_body, else_env);
            diagnostics.extend(then_result.diagnostics);
            diagnostics.extend(else_result.diagnostics);

            env = then_result.env.join(&else_result.env);
            for phi in phis {
                let merged = then_result
                    .env
                    .fact_for_var(&phi.then_var)
                    .join(&else_result.env.fact_for_var(&phi.else_var));
                env.set_var_fact(&phi.dest, merged);
                assign_phi_metadata(
                    &phi.dest,
                    &phi.then_var,
                    &then_result.env,
                    &phi.else_var,
                    &else_result.env,
                    &mut env,
                );
            }
        },
        Stmt::While { cond: _, body, phis, .. } => {
            let loop_result = eval_loop_block(detector, summaries, body, phis, env);
            env = loop_result.env;
            diagnostics.extend(loop_result.diagnostics);
        },
        Stmt::Repeat { body, phis, .. } => {
            let loop_result = eval_loop_block(detector, summaries, body, phis, env);
            env = loop_result.env;
            diagnostics.extend(loop_result.diagnostics);
        },
    }

    EvalResult { env, diagnostics }
}

/// Evaluate a structured loop body conservatively.
fn eval_loop_block<D: SinkDetector>(
    detector: &D,
    summaries: &AdviceSummaryMap,
    body: &[Stmt],
    phis: &[LoopPhi],
    entry_env: Env,
) -> EvalResult {
    let loop_state = iterate_to_fixpoint(
        SinkLoopState::at_loop_head(&entry_env, phis),
        FixpointConfig::new(MAX_LOOP_PASSES),
        |loop_env| {
            let body_result = eval_block(detector, summaries, body, loop_env.env());
            SinkLoopState::from_body_env(body_result.env, &entry_env, phis)
        },
    )
    .into_state();

    let body_result = eval_block(detector, summaries, body, loop_state.env());
    let diagnostics = body_result.diagnostics;
    let loop_env = join_loop_head_env(&loop_state.env(), &entry_env, &body_result.env, phis);

    EvalResult { env: loop_env, diagnostics }
}
