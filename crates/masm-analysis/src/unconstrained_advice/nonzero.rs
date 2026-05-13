//! Diagnostics and summaries for unconstrained advice reaching non-zero sinks.

use std::collections::BTreeSet;

use masm_decompiler::{BinOp, Expr, Intrinsic, Stmt, SymbolPath, UnOp, Var};

use super::{
    domain::AdviceFact,
    shared::{
        Env, collect_expr_sink_fact, expr_is_proven_nonzero, expr_output_fact,
        intrinsic_nonzero_arg_index, refine_nonzero_from_intrinsic, stmt_span,
    },
    summary::{AdviceDiagnosticContext, AdviceDiagnosticsMap, AdviceSummary, AdviceSummaryMap},
    walker::{self, AdviceCapability, AdviceEffect},
};
use crate::prepared::PreparedAnalysis;

/// Infer non-zero summaries and diagnostics using already-computed provenance summaries.
pub(super) fn infer_nonzero_summaries_and_diagnostics(
    prepared: &PreparedAnalysis,
    summaries: &mut AdviceSummaryMap,
) -> AdviceDiagnosticsMap {
    let mut diagnostics = AdviceDiagnosticsMap::default();

    for (proc_path, proc) in prepared.callgraph_procs() {
        let Some(proc) = proc else {
            mark_nonzero_unknown(summaries, proc_path);
            continue;
        };
        let Some(stmts) = proc.stmts() else {
            mark_nonzero_unknown(summaries, proc_path);
            continue;
        };

        let result = {
            let capability = NonZeroCapability::new(proc_path.clone(), summaries);
            walker::analyze_procedure(&capability, summaries, proc.inputs(), stmts)
        };
        if !result.diagnostics.is_empty() {
            diagnostics.insert(proc_path.clone(), result.diagnostics);
        }
        let summary = summaries.entry(proc_path.clone()).or_insert_with(AdviceSummary::unknown);
        if result.opaque {
            summary.set_nonzero_unknown();
        } else {
            summary.set_nonzero_requirements(result.summary);
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
    diagnostics: AdviceDiagnosticContext,
    callee_summaries: &'a AdviceSummaryMap,
}

impl<'a> NonZeroCapability<'a> {
    /// Construct a new non-zero capability.
    fn new(proc_path: SymbolPath, callee_summaries: &'a AdviceSummaryMap) -> Self {
        Self {
            diagnostics: AdviceDiagnosticContext::new(proc_path),
            callee_summaries,
        }
    }

    /// Add diagnostics and summary requirements for a non-zero sink fact.
    fn add_sink_fact(
        &self,
        effect: &mut AdviceEffect<BTreeSet<usize>>,
        span: miden_debug_types::SourceSpan,
        message: impl Into<String>,
        fact: &AdviceFact,
    ) {
        let message = message.into();
        if fact.has_concrete_sources() {
            effect.push_diagnostic(self.diagnostics.diagnostic_for_fact(span, message, fact));
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
    ) -> AdviceEffect<BTreeSet<usize>> {
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
                let diagnostic = self.diagnostics.diagnostic_for_fact(
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
    type Summary = BTreeSet<usize>;

    fn check_stmt(&self, stmt: &Stmt, env: &Env) -> AdviceEffect<Self::Summary> {
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
    collect_expr_sink_fact(expr, env, &nonzero_node_sink_fact)
}

/// Return the advice fact feeding a divisor or `inv` input at the current expression node.
fn nonzero_node_sink_fact(expr: &Expr, env: &Env) -> AdviceFact {
    match expr {
        Expr::Unary(UnOp::Inv, inner) if !expr_is_proven_nonzero(inner, env) => {
            expr_output_fact(inner, env)
        },
        Expr::Binary(BinOp::Div, _, rhs) if !expr_is_proven_nonzero(rhs, env) => {
            expr_output_fact(rhs, env)
        },
        Expr::Var(_)
        | Expr::True
        | Expr::False
        | Expr::Constant(_)
        | Expr::Ternary { .. }
        | Expr::Unary(..)
        | Expr::Binary(..)
        | Expr::EqW { .. } => AdviceFact::bottom(),
    }
}

#[cfg(test)]
mod tests {
    use masm_decompiler::{Constant, ValueId, Var};
    use miden_debug_types::{SourceId, SourceSpan};

    use super::*;

    fn var(id: u64) -> Var {
        Var::new(ValueId::from(id), id as usize)
    }

    fn span(start: u32) -> SourceSpan {
        SourceSpan::new(SourceId::new(0), start..start + 1)
    }

    #[test]
    fn nonzero_sink_fact_traverses_nested_ternary_unary_and_binary_expressions() {
        let divisor = var(0);
        let inverse_input = var(1);
        let clean = var(2);
        let divisor_span = span(20);
        let inverse_span = span(30);

        let mut env = Env::default();
        env.set_var_fact(&divisor, AdviceFact::from_source(divisor_span));
        env.set_var_fact(&inverse_input, AdviceFact::from_source(inverse_span));

        let expr = Expr::Binary(
            BinOp::Add,
            Box::new(Expr::Unary(
                UnOp::Neg,
                Box::new(Expr::Ternary {
                    cond: Box::new(Expr::Var(clean)),
                    then_expr: Box::new(Expr::Binary(
                        BinOp::Div,
                        Box::new(Expr::Constant(Constant::Felt(10))),
                        Box::new(Expr::Var(divisor)),
                    )),
                    else_expr: Box::new(Expr::Unary(UnOp::Inv, Box::new(Expr::Var(inverse_input)))),
                }),
            )),
            Box::new(Expr::Constant(Constant::Felt(1))),
        );

        let fact = expr_nonzero_sink_fact(&expr, &env);

        assert_eq!(fact.source_spans.len(), 2);
        assert!(fact.source_spans.contains(&divisor_span));
        assert!(fact.source_spans.contains(&inverse_span));
    }
}
