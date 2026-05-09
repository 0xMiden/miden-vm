//! Diagnostics and summaries for unconstrained advice reaching non-zero sinks.

use std::collections::HashMap;

use masm_decompiler::{BinOp, Expr, Intrinsic, Stmt, SymbolPath, UnOp, Var};

use super::{
    domain::AdviceFact,
    shared::{
        Env, expr_is_proven_nonzero, expr_output_fact, intrinsic_nonzero_arg_index,
        refine_nonzero_from_intrinsic, stmt_span,
    },
    summary::{
        AdviceDiagnostic, AdviceDiagnosticsMap, AdviceSummary, AdviceSummaryMap,
        diagnostic_from_fact,
    },
    walker::{self, AdviceCapability, AdviceEffect},
};
use crate::prepared::PreparedProc;

/// Infer non-zero summaries and diagnostics using already-computed provenance summaries.
pub(super) fn infer_nonzero_summaries_and_diagnostics(
    callgraph: &masm_decompiler::CallGraph,
    prepared: &HashMap<SymbolPath, PreparedProc>,
    summaries: &mut AdviceSummaryMap,
) -> AdviceDiagnosticsMap {
    let mut diagnostics = AdviceDiagnosticsMap::default();

    for node in callgraph.iter() {
        let Some(proc) = prepared.get(node.name()) else {
            mark_nonzero_unknown(summaries, node.name());
            continue;
        };
        let Some(stmts) = proc.stmts.as_deref() else {
            mark_nonzero_unknown(summaries, node.name());
            continue;
        };

        let result = {
            let capability = NonZeroCapability::new(node.name().clone(), summaries);
            walker::analyze_procedure(&capability, summaries, proc.inputs, stmts)
        };
        if !result.diagnostics.is_empty() {
            diagnostics.insert(node.name().clone(), result.diagnostics);
        }
        let summary = summaries.entry(node.name().clone()).or_insert_with(AdviceSummary::unknown);
        if result.opaque {
            summary.set_nonzero_unknown();
        } else {
            summary.set_nonzero_requirements(result.required_inputs);
        }
    }

    diagnostics
}

/// Mark one procedure's non-zero summary as opaque.
fn mark_nonzero_unknown(summaries: &mut AdviceSummaryMap, proc_path: &SymbolPath) {
    summaries
        .entry(proc_path.clone())
        .or_insert_with(AdviceSummary::unknown)
        .set_nonzero_unknown();
}

/// Advice capability for unconstrained advice reaching non-zero sinks.
struct NonZeroCapability<'a> {
    proc_path: SymbolPath,
    callee_summaries: &'a AdviceSummaryMap,
}

impl<'a> NonZeroCapability<'a> {
    /// Construct a new non-zero capability.
    fn new(proc_path: SymbolPath, callee_summaries: &'a AdviceSummaryMap) -> Self {
        Self { proc_path, callee_summaries }
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

    /// Add diagnostics and summary requirements for a non-zero sink fact.
    fn add_sink_fact(
        &self,
        effect: &mut AdviceEffect,
        span: miden_debug_types::SourceSpan,
        message: impl Into<String>,
        fact: &AdviceFact,
    ) {
        let message = message.into();
        if fact.has_concrete_sources() {
            effect.push_diagnostic(self.new_diagnostic(span, message, fact));
        }
        effect.extend_required_inputs(fact.from_inputs.iter().copied());
    }

    /// Emit call-site diagnostics and summary requirements for a callee non-zero precondition.
    fn call_effect(
        &self,
        span: miden_debug_types::SourceSpan,
        target: &str,
        args: &[Var],
        env: &Env,
    ) -> AdviceEffect {
        let Some(summary) = self.callee_summaries.get(&SymbolPath::new(target.to_string())) else {
            return AdviceEffect::new();
        };
        if summary.nonzero_is_unknown() {
            return AdviceEffect::new();
        }

        let mut effect = AdviceEffect::new();
        for index in summary.nonzero_required_inputs() {
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
                effect.push_diagnostic(diagnostic);
            }
            effect.extend_required_inputs(arg_fact.from_inputs.iter().copied());
        }

        effect
    }
}

impl AdviceCapability for NonZeroCapability<'_> {
    fn check_stmt(&self, stmt: &Stmt, env: &Env) -> AdviceEffect {
        let mut effect = AdviceEffect::new();
        match stmt {
            Stmt::Assign { span, expr, .. } => {
                let sink_fact = expr_nonzero_sink_fact(expr, env);
                self.add_sink_fact(
                    &mut effect,
                    *span,
                    "unconstrained advice reaches a divisor or `inv` input without a nearby non-zero check",
                    &sink_fact,
                );
            },
            Stmt::Call { span, call }
            | Stmt::Exec { span, call }
            | Stmt::SysCall { span, call } => {
                effect = self.call_effect(*span, &call.target, &call.args, env);
            },
            Stmt::Intrinsic { span, intrinsic } => {
                let sink_fact = intrinsic_nonzero_sink_fact(intrinsic, env);
                self.add_sink_fact(
                    &mut effect,
                    *span,
                    "unconstrained advice reaches a divisor or `inv` input without a nearby non-zero check",
                    &sink_fact,
                );
            },
            Stmt::If { cond, .. } => {
                let sink_fact = expr_nonzero_sink_fact(cond, env);
                self.add_sink_fact(
                    &mut effect,
                    stmt_span(stmt),
                    "unconstrained advice reaches a divisor or `inv` input without a nearby non-zero check",
                    &sink_fact,
                );
            },
            Stmt::While { cond, .. } => {
                let sink_fact = expr_nonzero_sink_fact(cond, env);
                self.add_sink_fact(
                    &mut effect,
                    stmt_span(stmt),
                    "unconstrained advice reaches a divisor or `inv` input without a nearby non-zero check",
                    &sink_fact,
                );
            },
            Stmt::AdvLoad { .. }
            | Stmt::AdvStore { .. }
            | Stmt::MemStore { .. }
            | Stmt::MemLoad { .. }
            | Stmt::LocalStore { .. }
            | Stmt::LocalStoreW { .. }
            | Stmt::LocalLoad { .. }
            | Stmt::DynCall { .. }
            | Stmt::Repeat { .. }
            | Stmt::Return { .. } => {},
        }

        effect
    }

    fn before_intrinsic_transfer(&self, intrinsic: &Intrinsic, env: &mut Env) {
        refine_nonzero_from_intrinsic(intrinsic, env);
    }
}

/// Return the advice fact feeding any intrinsic divisor input.
fn intrinsic_nonzero_sink_fact(intrinsic: &Intrinsic, env: &Env) -> AdviceFact {
    let Some(index) = intrinsic_nonzero_arg_index(&intrinsic.name) else {
        return AdviceFact::bottom();
    };

    let Some(divisor) = intrinsic.args.get(index).filter(|arg| !env.is_var_nonzero(arg)) else {
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
