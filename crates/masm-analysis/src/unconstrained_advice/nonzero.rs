//! Diagnostics and summaries for unconstrained advice reaching non-zero sinks.

use std::collections::{BTreeSet, HashMap};

use masm_decompiler::{
    BinOp, Expr, Intrinsic, LocalAccessKind, LoopPhi, Stmt, SymbolPath, UnOp, Var,
};

use super::{
    domain::AdviceFact,
    provenance::assign_call_results,
    shared::{
        Env, apply_intrinsic_effect, apply_local_load_scalar, apply_local_load_word,
        apply_local_store, apply_local_store_word, assign_expr_metadata, assign_phi_metadata,
        expr_is_proven_nonzero, expr_output_fact, join_loop_head_env, refine_if_envs,
        refine_nonzero_from_intrinsic, seed_input_env, stabilized_loop_head_env, stmt_span,
    },
    summary::{AdviceDiagnostic, AdviceDiagnosticsMap, AdviceSummaryMap, diagnostic_from_fact},
};
use crate::prepared::PreparedProc;

/// Summary of non-zero sink requirements for one procedure.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct NonZeroSummary {
    /// Input positions that may reach a `div` or `inv` sink without a local proof.
    required_inputs: BTreeSet<usize>,
    /// Whether this summary is opaque.
    unknown: bool,
}

impl NonZeroSummary {
    /// Create a known summary from required input positions.
    fn new(required_inputs: BTreeSet<usize>) -> Self {
        Self { required_inputs, unknown: false }
    }

    /// Create an opaque summary.
    fn unknown() -> Self {
        Self {
            required_inputs: BTreeSet::new(),
            unknown: true,
        }
    }

    /// Return true if the summary is opaque.
    fn is_unknown(&self) -> bool {
        self.unknown
    }
}

/// Map of non-zero summaries by procedure.
pub(super) type NonZeroSummaryMap = HashMap<SymbolPath, NonZeroSummary>;

/// Infer non-zero summaries and diagnostics using already-computed provenance summaries.
pub(super) fn infer_nonzero_summaries_and_diagnostics(
    callgraph: &masm_decompiler::CallGraph,
    prepared: &HashMap<SymbolPath, PreparedProc>,
    provenance_summaries: &AdviceSummaryMap,
) -> (NonZeroSummaryMap, AdviceDiagnosticsMap) {
    let mut summaries = NonZeroSummaryMap::default();
    let mut diagnostics = AdviceDiagnosticsMap::default();

    for node in callgraph.iter() {
        let Some(proc) = prepared.get(node.name()) else {
            summaries.insert(node.name().clone(), NonZeroSummary::unknown());
            continue;
        };
        let Some(stmts) = proc.stmts.as_deref() else {
            summaries.insert(node.name().clone(), NonZeroSummary::unknown());
            continue;
        };

        let analyzer =
            ProcNonZeroAnalyzer::new(node.name().clone(), provenance_summaries, &summaries);
        let result = analyzer.analyze(proc.inputs, stmts);
        if !result.diagnostics.is_empty() {
            diagnostics.insert(node.name().clone(), result.diagnostics);
        }
        summaries.insert(node.name().clone(), result.summary);
    }

    (summaries, diagnostics)
}

/// Result of non-zero analysis for one procedure.
#[derive(Debug, Clone)]
struct ProcNonZeroAnalysisResult {
    summary: NonZeroSummary,
    diagnostics: Vec<AdviceDiagnostic>,
}

/// Result of evaluating a statement block.
#[derive(Debug, Clone)]
struct EvalResult {
    env: Env,
    diagnostics: Vec<AdviceDiagnostic>,
    required_inputs: BTreeSet<usize>,
    opaque: bool,
}

/// Intraprocedural non-zero analyzer for one procedure.
struct ProcNonZeroAnalyzer<'a> {
    proc_path: SymbolPath,
    provenance_summaries: &'a AdviceSummaryMap,
    callee_summaries: &'a NonZeroSummaryMap,
}

impl<'a> ProcNonZeroAnalyzer<'a> {
    /// Construct a new non-zero analyzer.
    fn new(
        proc_path: SymbolPath,
        provenance_summaries: &'a AdviceSummaryMap,
        callee_summaries: &'a NonZeroSummaryMap,
    ) -> Self {
        Self {
            proc_path,
            provenance_summaries,
            callee_summaries,
        }
    }

    /// Analyze one procedure body.
    fn analyze(&self, input_count: usize, stmts: &[Stmt]) -> ProcNonZeroAnalysisResult {
        let env = seed_input_env(input_count);
        let result = self.eval_block(stmts, env);
        let summary = if result.opaque {
            NonZeroSummary::unknown()
        } else {
            NonZeroSummary::new(result.required_inputs)
        };

        ProcNonZeroAnalysisResult { summary, diagnostics: result.diagnostics }
    }

    /// Evaluate a statement block from top to bottom.
    fn eval_block(&self, stmts: &[Stmt], mut env: Env) -> EvalResult {
        let mut diagnostics = Vec::new();
        let mut required_inputs = BTreeSet::new();
        let mut opaque = false;

        for stmt in stmts {
            let result = self.eval_stmt(stmt, env);
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

    /// Evaluate a single statement.
    fn eval_stmt(&self, stmt: &Stmt, mut env: Env) -> EvalResult {
        let mut diagnostics = Vec::new();
        let mut required_inputs = BTreeSet::new();
        let mut opaque = false;

        match stmt {
            Stmt::Assign { span, dest, expr } => {
                let sink_fact = expr_nonzero_sink_fact(expr, &env);
                if sink_fact.has_concrete_sources() {
                    diagnostics.push(self.new_diagnostic(
                        *span,
                        "unconstrained advice reaches a divisor or `inv` input without a nearby non-zero check",
                        &sink_fact,
                    ));
                }
                required_inputs.extend(sink_fact.from_inputs.iter().copied());
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
            Stmt::AdvStore { .. } | Stmt::MemStore { .. } | Stmt::Return { .. } => {},
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
                    apply_local_load_word(
                        load.kind,
                        &load.outputs,
                        u32::from(load.index),
                        &mut env,
                    );
                },
            },
            Stmt::Call { span, call }
            | Stmt::Exec { span, call }
            | Stmt::SysCall { span, call } => {
                let call_result =
                    self.call_diagnostics_and_requirements(*span, &call.target, &call.args, &env);
                diagnostics.extend(call_result.diagnostics);
                required_inputs.extend(call_result.required_inputs);
                assign_call_results(
                    &mut env,
                    &call.target,
                    &call.args,
                    &call.results,
                    self.provenance_summaries,
                );
            },
            Stmt::DynCall { results, .. } => {
                for result in results {
                    env.set_var_fact(result, AdviceFact::bottom());
                    env.clear_var_metadata(result);
                }
                opaque = true;
            },
            Stmt::Intrinsic { span, intrinsic } => {
                let sink_fact = intrinsic_nonzero_sink_fact(intrinsic, &env);
                if sink_fact.has_concrete_sources() {
                    diagnostics.push(self.new_diagnostic(
                        *span,
                        "unconstrained advice reaches a divisor or `inv` input without a nearby non-zero check",
                        &sink_fact,
                    ));
                }
                required_inputs.extend(sink_fact.from_inputs.iter().copied());
                refine_nonzero_from_intrinsic(intrinsic, &mut env);
                apply_intrinsic_effect(*span, intrinsic, &mut env);
            },
            Stmt::If { cond, then_body, else_body, phis, .. } => {
                let sink_fact = expr_nonzero_sink_fact(cond, &env);
                if sink_fact.has_concrete_sources() {
                    diagnostics.push(self.new_diagnostic(
                        stmt_span(stmt),
                        "unconstrained advice reaches a divisor or `inv` input without a nearby non-zero check",
                        &sink_fact,
                    ));
                }
                required_inputs.extend(sink_fact.from_inputs.iter().copied());

                let (then_env, else_env) = refine_if_envs(cond, &env);
                let then_result = self.eval_block(then_body, then_env);
                let else_result = self.eval_block(else_body, else_env);
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
            Stmt::While { cond, body, phis, .. } => {
                let sink_fact = expr_nonzero_sink_fact(cond, &env);
                if sink_fact.has_concrete_sources() {
                    diagnostics.push(self.new_diagnostic(
                        stmt_span(stmt),
                        "unconstrained advice reaches a divisor or `inv` input without a nearby non-zero check",
                        &sink_fact,
                    ));
                }
                required_inputs.extend(sink_fact.from_inputs.iter().copied());
                let loop_result = self.eval_loop_block(body, phis, env);
                env = loop_result.env;
                diagnostics.extend(loop_result.diagnostics);
                required_inputs.extend(loop_result.required_inputs);
                opaque |= loop_result.opaque;
            },
            Stmt::Repeat { body, phis, .. } => {
                let loop_result = self.eval_loop_block(body, phis, env);
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
    fn eval_loop_block(&self, body: &[Stmt], phis: &[LoopPhi], entry_env: Env) -> EvalResult {
        let mut opaque = false;

        let mut loop_env = stabilized_loop_head_env(&entry_env, phis, |loop_env| {
            let body_result = self.eval_block(body, loop_env);
            opaque |= body_result.opaque;
            body_result.env
        });

        let body_result = self.eval_block(body, loop_env.clone());
        opaque |= body_result.opaque;
        let mut diagnostics = body_result.diagnostics;
        let mut required_inputs = body_result.required_inputs;
        loop_env = join_loop_head_env(&loop_env, &entry_env, &body_result.env, phis);

        EvalResult {
            env: loop_env,
            diagnostics: std::mem::take(&mut diagnostics),
            required_inputs: std::mem::take(&mut required_inputs),
            opaque,
        }
    }

    /// Create a diagnostic whose related source spans are derived from a fact.
    fn new_diagnostic(
        &self,
        span: miden_debug_types::SourceSpan,
        message: impl Into<String>,
        fact: &AdviceFact,
    ) -> AdviceDiagnostic {
        diagnostic_from_fact(self.proc_path.clone(), span, message, fact)
    }

    /// Emit call-site diagnostics and summary requirements for a callee non-zero precondition.
    fn call_diagnostics_and_requirements(
        &self,
        span: miden_debug_types::SourceSpan,
        target: &str,
        args: &[Var],
        env: &Env,
    ) -> CallResult {
        let Some(summary) = self.callee_summaries.get(&SymbolPath::new(target.to_string())) else {
            return CallResult::default();
        };
        if summary.is_unknown() {
            return CallResult::default();
        }

        let mut diagnostics = Vec::new();
        let mut required_inputs = BTreeSet::new();
        for index in &summary.required_inputs {
            let Some(arg) = args.get(*index) else {
                continue;
            };
            if env.is_var_nonzero(arg) {
                continue;
            }
            let arg_fact = env.fact_for_var(arg);
            if arg_fact.has_concrete_sources() {
                let callee = SymbolPath::new(target.to_string());
                let diagnostic = self.new_diagnostic(
                    span,
                    format!(
                        "argument {index} to `{callee}` may reach a divisor or `inv` input without a nearby non-zero check"
                    ),
                    &arg_fact,
                );
                diagnostics.push(diagnostic);
            }
            required_inputs.extend(arg_fact.from_inputs.iter().copied());
        }

        CallResult { diagnostics, required_inputs }
    }
}

/// Result of processing a non-zero-sensitive call.
#[derive(Debug, Clone, Default)]
struct CallResult {
    diagnostics: Vec<AdviceDiagnostic>,
    required_inputs: BTreeSet<usize>,
}

/// Return the advice fact feeding any intrinsic divisor input.
fn intrinsic_nonzero_sink_fact(intrinsic: &Intrinsic, env: &Env) -> AdviceFact {
    if !matches!(intrinsic.name.as_str(), "u32div" | "u32mod" | "u32divmod") {
        return AdviceFact::bottom();
    }

    let Some(divisor) = intrinsic.args.first().filter(|arg| !env.is_var_nonzero(arg)) else {
        return AdviceFact::bottom();
    };
    env.fact_for_var(divisor)
}

/// Return the advice fact feeding any divisor or `inv` input nested in this expression.
fn expr_nonzero_sink_fact(expr: &Expr, env: &Env) -> AdviceFact {
    match expr {
        Expr::Var(_) | Expr::True | Expr::False | Expr::Constant(_) | Expr::EqW { .. } => {
            AdviceFact::bottom()
        },
        Expr::Ternary { cond, then_expr, else_expr } => expr_nonzero_sink_fact(cond, env)
            .join(&expr_nonzero_sink_fact(then_expr, env))
            .join(&expr_nonzero_sink_fact(else_expr, env)),
        Expr::Unary(op, inner) => {
            let nested = expr_nonzero_sink_fact(inner, env);
            let sink = match op {
                UnOp::Inv if !expr_is_proven_nonzero(inner, env) => expr_output_fact(inner, env),
                _ => AdviceFact::bottom(),
            };
            nested.join(&sink)
        },
        Expr::Binary(op, lhs, rhs) => {
            let nested = expr_nonzero_sink_fact(lhs, env).join(&expr_nonzero_sink_fact(rhs, env));
            let sink = match op {
                BinOp::Div if !expr_is_proven_nonzero(rhs, env) => expr_output_fact(rhs, env),
                _ => AdviceFact::bottom(),
            };
            nested.join(&sink)
        },
    }
}
