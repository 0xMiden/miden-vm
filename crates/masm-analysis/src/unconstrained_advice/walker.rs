//! Generic statement walker for advice capabilities.

use std::collections::{BTreeSet, HashMap};

use masm_decompiler::{Intrinsic, LocalAccessKind, LoopPhi, Stmt, SymbolPath};

use super::{
    domain::AdviceFact,
    provenance::assign_call_results,
    shared::{
        Env, apply_intrinsic_effect, apply_local_load_scalar, apply_local_load_word,
        apply_local_store, apply_local_store_word, assign_expr_metadata, assign_phi_metadata,
        expr_output_fact, join_loop_head_env, refine_if_envs, seed_input_env,
        stabilized_loop_head_env,
    },
    summary::{AdviceDiagnostic, AdviceDiagnosticsMap, AdviceSummaryMap},
};
use crate::prepared::PreparedProc;

/// Trait for advice-specific semantic hooks that run inside the shared walker.
pub(super) trait AdviceCapability {
    /// Inspect a statement before environment updates are applied.
    ///
    /// Return any diagnostics or summary requirements detected in this statement.
    fn check_stmt(&self, stmt: &Stmt, env: &Env) -> AdviceEffect;

    /// Refine the environment immediately before common intrinsic transfer is applied.
    fn before_intrinsic_transfer(&self, _intrinsic: &Intrinsic, _env: &mut Env) {}
}

/// Effects contributed by an advice capability while walking one statement.
#[derive(Debug, Clone, Default)]
pub(super) struct AdviceEffect {
    /// Diagnostics detected by the capability.
    diagnostics: Vec<AdviceDiagnostic>,
    /// Procedure input positions required by this capability's summary.
    required_inputs: BTreeSet<usize>,
}

impl AdviceEffect {
    /// Create an empty effect.
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Create an effect containing diagnostics only.
    pub(super) fn diagnostics(diagnostics: Vec<AdviceDiagnostic>) -> Self {
        Self {
            diagnostics,
            required_inputs: BTreeSet::new(),
        }
    }

    /// Add one diagnostic.
    pub(super) fn push_diagnostic(&mut self, diagnostic: AdviceDiagnostic) {
        self.diagnostics.push(diagnostic);
    }

    /// Add required procedure input positions.
    pub(super) fn extend_required_inputs(&mut self, inputs: impl IntoIterator<Item = usize>) {
        self.required_inputs.extend(inputs);
    }
}

/// Result of walking one procedure with an advice capability.
#[derive(Debug, Clone, Default)]
pub(super) struct AdviceWalkResult {
    /// Environment after walking the procedure body.
    pub(super) env: Env,
    /// Diagnostics emitted while walking the procedure.
    pub(super) diagnostics: Vec<AdviceDiagnostic>,
    /// Procedure input positions required by this capability's summary.
    pub(super) required_inputs: BTreeSet<usize>,
    /// Whether the walk encountered an opaque construct.
    pub(super) opaque: bool,
}

/// Collect diagnostics for all procedures using an advice capability.
pub(super) fn collect_diagnostics<C: AdviceCapability>(
    prepared: &HashMap<SymbolPath, PreparedProc>,
    provenance_summaries: &AdviceSummaryMap,
    make_capability: impl Fn(SymbolPath) -> C,
) -> AdviceDiagnosticsMap {
    let mut diagnostics = AdviceDiagnosticsMap::default();

    for (proc_path, proc) in prepared {
        let Some(stmts) = proc.stmts.as_deref() else {
            continue;
        };
        let capability = make_capability(proc_path.clone());
        let result = analyze_procedure(&capability, provenance_summaries, proc.inputs, stmts);
        if !result.diagnostics.is_empty() {
            diagnostics.insert(proc_path.clone(), result.diagnostics);
        }
    }

    diagnostics
}

/// Walk one procedure body with an advice capability.
pub(super) fn analyze_procedure<C: AdviceCapability>(
    capability: &C,
    provenance_summaries: &AdviceSummaryMap,
    input_count: usize,
    stmts: &[Stmt],
) -> AdviceWalkResult {
    let env = seed_input_env(input_count);
    let result = eval_block(capability, provenance_summaries, stmts, env);
    AdviceWalkResult {
        env: result.env,
        diagnostics: result.diagnostics,
        required_inputs: result.required_inputs,
        opaque: result.opaque,
    }
}

/// Result of evaluating a statement block.
struct EvalResult {
    env: Env,
    diagnostics: Vec<AdviceDiagnostic>,
    required_inputs: BTreeSet<usize>,
    opaque: bool,
}

/// Evaluate a statement block from top to bottom.
fn eval_block<C: AdviceCapability>(
    capability: &C,
    summaries: &AdviceSummaryMap,
    stmts: &[Stmt],
    mut env: Env,
) -> EvalResult {
    let mut diagnostics = Vec::new();
    let mut required_inputs = BTreeSet::new();
    let mut opaque = false;

    for stmt in stmts {
        let result = eval_stmt(capability, summaries, stmt, env);
        env = result.env;
        diagnostics.extend(result.diagnostics);
        required_inputs.extend(result.required_inputs);
        opaque |= result.opaque;
    }

    EvalResult {
        env,
        diagnostics,
        required_inputs,
        opaque,
    }
}

/// Evaluate a single statement: check capability diagnostics, then apply env updates.
fn eval_stmt<C: AdviceCapability>(
    capability: &C,
    summaries: &AdviceSummaryMap,
    stmt: &Stmt,
    mut env: Env,
) -> EvalResult {
    let effect = capability.check_stmt(stmt, &env);
    let mut diagnostics = effect.diagnostics;
    let mut required_inputs = effect.required_inputs;
    let mut opaque = false;

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
            opaque = true;
        },
        Stmt::Intrinsic { span, intrinsic } => {
            capability.before_intrinsic_transfer(intrinsic, &mut env);
            apply_intrinsic_effect(*span, intrinsic, &mut env);
        },
        Stmt::If { cond, then_body, else_body, phis, .. } => {
            let (then_env, else_env) = refine_if_envs(cond, &env);
            let then_result = eval_block(capability, summaries, then_body, then_env);
            let else_result = eval_block(capability, summaries, else_body, else_env);
            diagnostics.extend(then_result.diagnostics);
            diagnostics.extend(else_result.diagnostics);
            required_inputs.extend(then_result.required_inputs);
            required_inputs.extend(else_result.required_inputs);
            opaque |= then_result.opaque || else_result.opaque;

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
            let loop_result = eval_loop_block(capability, summaries, body, phis, env);
            env = loop_result.env;
            diagnostics.extend(loop_result.diagnostics);
            required_inputs.extend(loop_result.required_inputs);
            opaque |= loop_result.opaque;
        },
        Stmt::Repeat { body, phis, .. } => {
            let loop_result = eval_loop_block(capability, summaries, body, phis, env);
            env = loop_result.env;
            diagnostics.extend(loop_result.diagnostics);
            required_inputs.extend(loop_result.required_inputs);
            opaque |= loop_result.opaque;
        },
    }

    EvalResult {
        env,
        diagnostics,
        required_inputs,
        opaque,
    }
}

/// Evaluate a structured loop body conservatively.
fn eval_loop_block<C: AdviceCapability>(
    capability: &C,
    summaries: &AdviceSummaryMap,
    body: &[Stmt],
    phis: &[LoopPhi],
    entry_env: Env,
) -> EvalResult {
    let mut opaque = false;
    let loop_env = stabilized_loop_head_env(&entry_env, phis, |loop_env| {
        let body_result = eval_block(capability, summaries, body, loop_env);
        opaque |= body_result.opaque;
        body_result.env
    });

    let body_result = eval_block(capability, summaries, body, loop_env.clone());
    let diagnostics = body_result.diagnostics;
    let required_inputs = body_result.required_inputs;
    opaque |= body_result.opaque;
    let loop_env = join_loop_head_env(&loop_env, &entry_env, &body_result.env, phis);

    EvalResult {
        env: loop_env,
        diagnostics,
        required_inputs,
        opaque,
    }
}
