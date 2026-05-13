//! Generic statement walker for advice capabilities.

use std::collections::BTreeSet;

use masm_decompiler::{Intrinsic, LocalAccessKind, LoopPhi, Stmt, SymbolPath};

use super::{
    call_transfer::assign_call_results,
    domain::AdviceFact,
    shared::{
        Env, apply_intrinsic_effect, apply_local_load_scalar, apply_local_load_word,
        apply_local_store, apply_local_store_word, assign_expr_metadata, assign_phi_metadata,
        expr_output_fact, join_loop_head_env, refine_if_envs, seed_input_env,
        stabilized_loop_head_env,
    },
    summary::{AdviceDiagnostic, AdviceDiagnosticsMap, AdviceSummaryMap},
};
use crate::prepared::PreparedAnalysis;

/// Trait for advice-specific semantic hooks that run inside the shared walker.
pub(super) trait AdviceCapability {
    /// Capability-owned summary contribution accumulated while walking.
    type Summary: AdviceSummaryContribution;

    /// Inspect a statement before environment updates are applied.
    ///
    /// Return any diagnostics or summary contribution detected in this statement.
    fn check_stmt(&self, stmt: &Stmt, env: &Env) -> AdviceEffect<Self::Summary>;

    /// Refine the environment immediately before common intrinsic transfer is applied.
    fn before_intrinsic_transfer(&self, _intrinsic: &Intrinsic, _env: &mut Env) {}
}

/// Capability-owned summary contribution accumulated by the shared walker.
pub(super) trait AdviceSummaryContribution: Default {
    /// Merge another contribution from the same capability into this one.
    fn merge(&mut self, other: Self);
}

impl AdviceSummaryContribution for () {
    fn merge(&mut self, _other: Self) {}
}

impl AdviceSummaryContribution for BTreeSet<usize> {
    fn merge(&mut self, other: Self) {
        self.extend(other);
    }
}

/// Effects contributed by an advice capability while walking one statement.
#[derive(Debug, Clone, Default)]
pub(super) struct AdviceEffect<S: AdviceSummaryContribution = ()> {
    /// Diagnostics detected by the capability.
    diagnostics: Vec<AdviceDiagnostic>,
    /// Summary contribution detected by the capability.
    summary: S,
}

impl<S: AdviceSummaryContribution> AdviceEffect<S> {
    /// Create an empty effect.
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Create an effect containing diagnostics only.
    pub(super) fn diagnostics(diagnostics: Vec<AdviceDiagnostic>) -> Self {
        Self { diagnostics, summary: S::default() }
    }

    /// Add one diagnostic.
    pub(super) fn push_diagnostic(&mut self, diagnostic: AdviceDiagnostic) {
        self.diagnostics.push(diagnostic);
    }
}

impl AdviceEffect<BTreeSet<usize>> {
    /// Add required procedure input positions.
    pub(super) fn extend_required_inputs(&mut self, inputs: impl IntoIterator<Item = usize>) {
        self.summary.extend(inputs);
    }
}

/// Result of walking one procedure with an advice capability.
#[derive(Debug, Clone, Default)]
pub(super) struct AdviceWalkResult<S: AdviceSummaryContribution = ()> {
    /// Environment after walking the procedure body.
    pub(super) env: Env,
    /// Diagnostics emitted while walking the procedure.
    pub(super) diagnostics: Vec<AdviceDiagnostic>,
    /// Summary contribution accumulated by this capability.
    pub(super) summary: S,
    /// Whether the walk encountered an opaque construct.
    pub(super) opaque: bool,
}

/// Collect diagnostics for all procedures using an advice capability.
pub(super) fn collect_diagnostics<C: AdviceCapability>(
    prepared: &PreparedAnalysis,
    provenance_summaries: &AdviceSummaryMap,
    make_capability: impl Fn(SymbolPath) -> C,
) -> AdviceDiagnosticsMap {
    let mut diagnostics = AdviceDiagnosticsMap::default();

    for (proc_path, proc) in prepared.procs() {
        let Some(stmts) = proc.stmts() else {
            continue;
        };
        let capability = make_capability(proc_path.clone());
        let result = analyze_procedure(&capability, provenance_summaries, proc.inputs(), stmts);
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
) -> AdviceWalkResult<C::Summary> {
    let env = seed_input_env(input_count);
    let result = eval_block(capability, provenance_summaries, stmts, env);
    AdviceWalkResult {
        env: result.env,
        diagnostics: result.diagnostics,
        summary: result.summary,
        opaque: result.opaque,
    }
}

/// Result of evaluating a statement block.
struct EvalResult<S: AdviceSummaryContribution> {
    env: Env,
    diagnostics: Vec<AdviceDiagnostic>,
    summary: S,
    opaque: bool,
}

/// Evaluate a statement block from top to bottom.
fn eval_block<C: AdviceCapability>(
    capability: &C,
    summaries: &AdviceSummaryMap,
    stmts: &[Stmt],
    mut env: Env,
) -> EvalResult<C::Summary> {
    let mut diagnostics = Vec::new();
    let mut summary = C::Summary::default();
    let mut opaque = false;

    for stmt in stmts {
        let result = eval_stmt(capability, summaries, stmt, env);
        env = result.env;
        diagnostics.extend(result.diagnostics);
        summary.merge(result.summary);
        opaque |= result.opaque;
    }

    EvalResult { env, diagnostics, summary, opaque }
}

/// Evaluate a single statement: check capability diagnostics, then apply env updates.
fn eval_stmt<C: AdviceCapability>(
    capability: &C,
    summaries: &AdviceSummaryMap,
    stmt: &Stmt,
    mut env: Env,
) -> EvalResult<C::Summary> {
    let effect = capability.check_stmt(stmt, &env);
    let mut diagnostics = effect.diagnostics;
    let mut summary = effect.summary;
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
            summary.merge(then_result.summary);
            summary.merge(else_result.summary);
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
            summary.merge(loop_result.summary);
            opaque |= loop_result.opaque;
        },
        Stmt::Repeat { body, phis, .. } => {
            let loop_result = eval_loop_block(capability, summaries, body, phis, env);
            env = loop_result.env;
            diagnostics.extend(loop_result.diagnostics);
            summary.merge(loop_result.summary);
            opaque |= loop_result.opaque;
        },
    }

    EvalResult { env, diagnostics, summary, opaque }
}

/// Evaluate a structured loop body conservatively.
fn eval_loop_block<C: AdviceCapability>(
    capability: &C,
    summaries: &AdviceSummaryMap,
    body: &[Stmt],
    phis: &[LoopPhi],
    entry_env: Env,
) -> EvalResult<C::Summary> {
    let mut opaque = false;
    let loop_env = stabilized_loop_head_env(&entry_env, phis, |loop_env| {
        let body_result = eval_block(capability, summaries, body, loop_env);
        opaque |= body_result.opaque;
        body_result.env
    });

    let body_result = eval_block(capability, summaries, body, loop_env.clone());
    let diagnostics = body_result.diagnostics;
    let summary = body_result.summary;
    opaque |= body_result.opaque;
    let loop_env = join_loop_head_env(&loop_env, &entry_env, &body_result.env, phis);

    EvalResult {
        env: loop_env,
        diagnostics,
        summary,
        opaque,
    }
}
