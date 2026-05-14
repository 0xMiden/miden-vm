//! Diagnostics for unconstrained advice reaching `U32` sinks.

use masm_decompiler::analysis::{
    BinOp, Expr, Intrinsic, Stmt, SymbolPath, TypeRequirement, UnOp, Var,
    intrinsic_arg_requirements,
};

use super::{
    domain::AdviceFact,
    effect::AdviceEffect,
    shared::{Env, collect_expr_sink_fact, expr_output_fact, expr_u32_validity, stmt_span},
    summary::{AdviceDiagnostic, AdviceDiagnosticContext, AdviceDiagnosticsMap, AdviceSummaryMap},
    walker::{self, AdviceCapability},
};
use crate::prepared::PreparedAnalysis;

/// Collect U32 diagnostics for all procedures using already-computed provenance summaries.
pub(super) fn collect_u32_diagnostics(
    prepared: &PreparedAnalysis,
    provenance_summaries: &AdviceSummaryMap,
) -> AdviceDiagnosticsMap {
    walker::collect_diagnostics(prepared, provenance_summaries, |proc_path| U32Capability {
        diagnostics: AdviceDiagnosticContext::new(proc_path),
        prepared,
    })
}

/// Intraprocedural U32 diagnostic collector for one procedure.
struct U32Capability<'a> {
    diagnostics: AdviceDiagnosticContext,
    prepared: &'a PreparedAnalysis,
}

impl AdviceCapability for U32Capability<'_> {
    type Summary = ();

    fn check_stmt(&self, stmt: &Stmt, env: &Env) -> AdviceEffect {
        let mut effect = AdviceEffect::new();

        match stmt {
            Stmt::Assign { span, expr, .. } => {
                let sink_fact = expr_u32_sink_fact(expr, env);
                if sink_fact.has_concrete_sources() {
                    effect.push_diagnostic(self.diagnostics.diagnostic_for_fact(
                        *span,
                        "unconstrained advice reaches a u32 operation",
                        &sink_fact,
                    ));
                }
            },
            Stmt::Call { span, call }
            | Stmt::Exec { span, call }
            | Stmt::SysCall { span, call } => {
                for diagnostic in self.call_diagnostics(*span, &call.target, &call.args, env) {
                    effect.push_diagnostic(diagnostic);
                }
            },
            Stmt::Intrinsic { span, intrinsic } => {
                let sink_fact = intrinsic_u32_sink_fact(intrinsic, env);
                if sink_fact.has_concrete_sources() {
                    effect.push_diagnostic(self.diagnostics.diagnostic_for_fact(
                        *span,
                        "unconstrained advice reaches a u32 intrinsic",
                        &sink_fact,
                    ));
                }
            },
            Stmt::If { cond, .. } => {
                let sink_fact = expr_u32_sink_fact(cond, env);
                if sink_fact.has_concrete_sources() {
                    effect.push_diagnostic(self.diagnostics.diagnostic_for_fact(
                        stmt_span(stmt),
                        "unconstrained advice reaches a u32 operation",
                        &sink_fact,
                    ));
                }
            },
            Stmt::While { cond, .. } => {
                let sink_fact = expr_u32_sink_fact(cond, env);
                if sink_fact.has_concrete_sources() {
                    effect.push_diagnostic(self.diagnostics.diagnostic_for_fact(
                        stmt_span(stmt),
                        "unconstrained advice reaches a u32 operation",
                        &sink_fact,
                    ));
                }
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
}

impl U32Capability<'_> {
    /// Emit diagnostics for call arguments whose callee expects `U32`.
    fn call_diagnostics(
        &self,
        span: miden_debug_types::SourceSpan,
        target: &str,
        args: &[Var],
        env: &Env,
    ) -> Vec<AdviceDiagnostic> {
        let Some(summary) = self.prepared.type_summary(&SymbolPath::new(target.to_string())) else {
            return Vec::new();
        };
        let mut diagnostics = Vec::new();
        for (index, (arg, expected)) in args.iter().zip(summary.inputs.iter()).enumerate() {
            let arg_fact = env.fact_for_var(arg);
            if *expected != TypeRequirement::U32
                || !arg_fact.has_concrete_sources()
                || env.u32_validity_for_var(arg).is_proven()
            {
                continue;
            }
            let callee = SymbolPath::new(target.to_string());
            let diagnostic = self.diagnostics.diagnostic_for_fact(
                span,
                format!(
                    "argument {index} to `{callee}` expects U32 and may contain unconstrained advice"
                ),
                &arg_fact,
            );
            diagnostics.push(diagnostic);
        }
        diagnostics
    }
}

/// Return the advice fact feeding any `U32` sink nested in this expression.
fn expr_u32_sink_fact(expr: &Expr, env: &Env) -> AdviceFact {
    collect_expr_sink_fact(expr, env, &u32_node_sink_fact)
}

/// Return the advice fact feeding a `U32` sink at the current expression node.
fn u32_node_sink_fact(expr: &Expr, env: &Env) -> AdviceFact {
    match expr {
        Expr::Unary(op, inner) => match op {
            UnOp::U32Not | UnOp::U32Clz | UnOp::U32Ctz | UnOp::U32Clo | UnOp::U32Cto => {
                u32_operand_fact(inner, env)
            },
            _ => AdviceFact::bottom(),
        },
        Expr::Binary(op, lhs, rhs) => match op {
            BinOp::U32And
            | BinOp::U32Or
            | BinOp::U32Xor
            | BinOp::U32Shl
            | BinOp::U32Shr
            | BinOp::U32Rotr
            | BinOp::U32Lt
            | BinOp::U32Lte
            | BinOp::U32Gt
            | BinOp::U32Gte
            | BinOp::U32WrappingAdd
            | BinOp::U32WrappingSub
            | BinOp::U32WrappingMul => u32_operand_fact(lhs, env).join(&u32_operand_fact(rhs, env)),
            BinOp::U32Exp => u32_operand_fact(rhs, env),
            _ => AdviceFact::bottom(),
        },
        Expr::Var(_)
        | Expr::True
        | Expr::False
        | Expr::Constant(_)
        | Expr::Ternary { .. }
        | Expr::EqW { .. } => AdviceFact::bottom(),
    }
}

/// Return the advice fact feeding a `U32` intrinsic sink.
fn intrinsic_u32_sink_fact(intrinsic: &Intrinsic, env: &Env) -> AdviceFact {
    let requirements =
        intrinsic_arg_requirements(&intrinsic.name, intrinsic.args.len(), intrinsic.results.len());
    let Some(range) = requirements.u32_args else {
        return AdviceFact::bottom();
    };

    AdviceFact::join_all(
        intrinsic.args[range]
            .iter()
            .filter(|&arg| !env.u32_validity_for_var(arg).is_proven())
            .map(|arg| env.fact_for_var(arg)),
    )
}

/// Return the advice fact for one operand only when it is not already proven `u32`.
fn u32_operand_fact(expr: &Expr, env: &Env) -> AdviceFact {
    if expr_u32_validity(expr, env).is_proven() {
        AdviceFact::bottom()
    } else {
        expr_output_fact(expr, env)
    }
}

#[cfg(test)]
mod tests {
    use masm_decompiler::analysis::{Constant, ValueId, Var};
    use miden_debug_types::{SourceId, SourceSpan};

    use super::*;

    fn var(id: u64) -> Var {
        Var::new(ValueId::from(id), id as usize)
    }

    fn span(start: u32) -> SourceSpan {
        SourceSpan::new(SourceId::new(0), start..start + 1)
    }

    #[test]
    fn u32_sink_fact_traverses_nested_ternary_unary_and_binary_expressions() {
        let advice = var(0);
        let clean = var(1);
        let advice_span = span(10);

        let mut env = Env::default();
        env.set_var_fact(&advice, AdviceFact::from_source(advice_span));

        let expr = Expr::Binary(
            BinOp::Add,
            Box::new(Expr::Unary(
                UnOp::Neg,
                Box::new(Expr::Ternary {
                    cond: Box::new(Expr::Var(clean.clone())),
                    then_expr: Box::new(Expr::Unary(
                        UnOp::Not,
                        Box::new(Expr::Binary(
                            BinOp::U32And,
                            Box::new(Expr::Var(advice.clone())),
                            Box::new(Expr::Var(clean)),
                        )),
                    )),
                    else_expr: Box::new(Expr::Constant(Constant::Felt(0))),
                }),
            )),
            Box::new(Expr::Constant(Constant::Felt(1))),
        );

        let fact = expr_u32_sink_fact(&expr, &env);

        assert_eq!(fact.source_spans.len(), 1);
        assert!(fact.source_spans.contains(&advice_span));
    }
}
