//! Diagnostics for unconstrained advice reaching `U32` sinks.

use std::collections::HashMap;

use masm_decompiler::{
    BinOp, Expr, Intrinsic, Stmt, SymbolPath, TypeRequirement, TypeSummaryMap, UnOp, Var,
};

use super::{
    domain::AdviceFact,
    shared::{
        Env, expr_output_fact, expr_u32_validity, intrinsic_requires_u32_precondition, stmt_span,
    },
    summary::{AdviceDiagnostic, AdviceDiagnosticsMap, AdviceSummaryMap, diagnostic_from_fact},
    walker::{self, SinkDetector},
};
use crate::prepared::PreparedProc;

/// Collect U32 diagnostics for all procedures using already-computed provenance summaries.
pub(super) fn collect_u32_diagnostics(
    prepared: &HashMap<SymbolPath, PreparedProc>,
    provenance_summaries: &AdviceSummaryMap,
    type_summaries: &TypeSummaryMap,
) -> AdviceDiagnosticsMap {
    walker::collect_diagnostics(prepared, provenance_summaries, |proc_path| U32Detector {
        proc_path,
        type_summaries,
    })
}

/// Intraprocedural U32 diagnostic collector for one procedure.
struct U32Detector<'a> {
    proc_path: SymbolPath,
    type_summaries: &'a TypeSummaryMap,
}

impl SinkDetector for U32Detector<'_> {
    fn check_stmt(&self, stmt: &Stmt, env: &Env) -> Vec<AdviceDiagnostic> {
        let mut diagnostics = Vec::new();

        match stmt {
            Stmt::Assign { span, expr, .. } => {
                let sink_fact = expr_u32_sink_fact(expr, env);
                if sink_fact.has_concrete_sources() {
                    diagnostics.push(self.new_diagnostic(
                        *span,
                        "unconstrained advice reaches a u32 operation",
                        &sink_fact,
                    ));
                }
            },
            Stmt::Call { span, call }
            | Stmt::Exec { span, call }
            | Stmt::SysCall { span, call } => {
                diagnostics.extend(self.call_diagnostics(*span, &call.target, &call.args, env));
            },
            Stmt::Intrinsic { span, intrinsic } => {
                let sink_fact = intrinsic_u32_sink_fact(intrinsic, env);
                if sink_fact.has_concrete_sources() {
                    diagnostics.push(self.new_diagnostic(
                        *span,
                        "unconstrained advice reaches a u32 intrinsic",
                        &sink_fact,
                    ));
                }
            },
            Stmt::If { cond, .. } => {
                let sink_fact = expr_u32_sink_fact(cond, env);
                if sink_fact.has_concrete_sources() {
                    diagnostics.push(self.new_diagnostic(
                        stmt_span(stmt),
                        "unconstrained advice reaches a u32 operation",
                        &sink_fact,
                    ));
                }
            },
            Stmt::While { cond, .. } => {
                let sink_fact = expr_u32_sink_fact(cond, env);
                if sink_fact.has_concrete_sources() {
                    diagnostics.push(self.new_diagnostic(
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

        diagnostics
    }
}

impl U32Detector<'_> {
    /// Create a diagnostic whose related source spans are derived from a fact.
    fn new_diagnostic(
        &self,
        span: miden_debug_types::SourceSpan,
        message: impl Into<String>,
        fact: &AdviceFact,
    ) -> AdviceDiagnostic {
        diagnostic_from_fact(self.proc_path.clone(), span, message, fact)
    }

    /// Emit diagnostics for call arguments whose callee expects `U32`.
    fn call_diagnostics(
        &self,
        span: miden_debug_types::SourceSpan,
        target: &str,
        args: &[Var],
        env: &Env,
    ) -> Vec<AdviceDiagnostic> {
        let Some(summary) = self.type_summaries.get(&SymbolPath::new(target.to_string())) else {
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
            let diagnostic = self.new_diagnostic(
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
    match expr {
        Expr::Var(_) | Expr::True | Expr::False | Expr::Constant(_) | Expr::EqW { .. } => {
            AdviceFact::bottom()
        },
        Expr::Ternary { cond, then_expr, else_expr } => expr_u32_sink_fact(cond, env)
            .join(&expr_u32_sink_fact(then_expr, env))
            .join(&expr_u32_sink_fact(else_expr, env)),
        Expr::Unary(op, inner) => match op {
            UnOp::U32Not | UnOp::U32Clz | UnOp::U32Ctz | UnOp::U32Clo | UnOp::U32Cto => {
                expr_u32_sink_fact(inner, env).join(&u32_operand_fact(inner, env))
            },
            _ => expr_u32_sink_fact(inner, env),
        },
        Expr::Binary(op, lhs, rhs) => {
            let nested = expr_u32_sink_fact(lhs, env).join(&expr_u32_sink_fact(rhs, env));
            let sink = match op {
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
                | BinOp::U32WrappingMul => {
                    u32_operand_fact(lhs, env).join(&u32_operand_fact(rhs, env))
                },
                BinOp::U32Exp => u32_operand_fact(rhs, env),
                _ => AdviceFact::bottom(),
            };
            nested.join(&sink)
        },
    }
}

/// Return the advice fact feeding a `U32` intrinsic sink.
fn intrinsic_u32_sink_fact(intrinsic: &Intrinsic, env: &Env) -> AdviceFact {
    if !intrinsic_requires_u32_precondition(&intrinsic.name) {
        return AdviceFact::bottom();
    }
    AdviceFact::join_all(
        intrinsic
            .args
            .iter()
            .filter(|arg| !env.u32_validity_for_var(arg).is_proven())
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
