//! Diagnostics for unconstrained advice reaching `U32` sinks.

use masm_decompiler::{
    SymbolPath,
    ir::{BinOp, Expr, Intrinsic, Stmt, UnOp},
    types::{TypeRequirement, TypeSummaryMap},
};

use super::{
    domain::AdviceFact,
    provenance::assign_call_results,
    shared::{
        Env, MAX_LOOP_PASSES, apply_intrinsic_effect, apply_local_load_scalar,
        apply_local_load_word, apply_local_store, apply_local_store_word, assign_expr_metadata,
        assign_phi_metadata, expr_output_fact, expr_u32_validity,
        intrinsic_requires_u32_precondition, refine_if_envs, seed_input_env, stmt_span,
    },
    summary::{
        AdviceDiagnostic, AdviceDiagnosticsMap, AdviceSinkKind, AdviceSummaryMap,
        CallArgumentRequirement,
    },
};

/// Collect U32 diagnostics for all procedures using already-computed provenance summaries.
pub(crate) fn collect_u32_diagnostics(
    prepared: &std::collections::HashMap<SymbolPath, super::inter::PreparedProc>,
    provenance_summaries: &AdviceSummaryMap,
    type_summaries: &TypeSummaryMap,
) -> AdviceDiagnosticsMap {
    let mut diagnostics = AdviceDiagnosticsMap::default();

    for (proc_path, proc) in prepared {
        let Some(stmts) = proc.stmts.as_deref() else {
            continue;
        };
        let analyzer =
            ProcU32Analyzer::new(proc_path.clone(), provenance_summaries, type_summaries);
        let proc_diags = analyzer.analyze(proc.inputs, stmts);
        if !proc_diags.is_empty() {
            diagnostics.insert(proc_path.clone(), proc_diags);
        }
    }

    diagnostics
}

/// Result of evaluating a statement block.
#[derive(Debug, Clone)]
struct EvalResult {
    env: Env,
    diagnostics: Vec<AdviceDiagnostic>,
}

/// Intraprocedural U32 diagnostic collector for one procedure.
struct ProcU32Analyzer<'a> {
    proc_path: SymbolPath,
    provenance_summaries: &'a AdviceSummaryMap,
    type_summaries: &'a TypeSummaryMap,
}

impl<'a> ProcU32Analyzer<'a> {
    /// Construct a new U32 analyzer.
    fn new(
        proc_path: SymbolPath,
        provenance_summaries: &'a AdviceSummaryMap,
        type_summaries: &'a TypeSummaryMap,
    ) -> Self {
        Self {
            proc_path,
            provenance_summaries,
            type_summaries,
        }
    }

    /// Analyze one procedure body.
    fn analyze(&self, input_count: usize, stmts: &[Stmt]) -> Vec<AdviceDiagnostic> {
        let env = seed_input_env(input_count);
        self.eval_block(stmts, env).diagnostics
    }

    /// Evaluate a statement block from top to bottom.
    fn eval_block(&self, stmts: &[Stmt], mut env: Env) -> EvalResult {
        let mut diagnostics = Vec::new();

        for stmt in stmts {
            let result = self.eval_stmt(stmt, env);
            env = result.env;
            diagnostics.extend(result.diagnostics);
        }

        EvalResult { env, diagnostics }
    }

    /// Evaluate a single statement.
    fn eval_stmt(&self, stmt: &Stmt, mut env: Env) -> EvalResult {
        let mut diagnostics = Vec::new();

        match stmt {
            Stmt::Assign { span, dest, expr } => {
                let sink_fact = expr_u32_sink_fact(expr, &env);
                if sink_fact.has_concrete_sources() {
                    diagnostics.push(self.new_diagnostic(
                        *span,
                        AdviceSinkKind::U32Expression,
                        "unconstrained advice reaches a u32 operation",
                        &sink_fact,
                    ));
                }
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
                masm_decompiler::ir::LocalAccessKind::Element => {
                    apply_local_load_scalar(&load.outputs, u32::from(load.index), &mut env);
                },
                masm_decompiler::ir::LocalAccessKind::WordBe
                | masm_decompiler::ir::LocalAccessKind::WordLe => {
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
                diagnostics.extend(self.call_diagnostics(*span, &call.target, &call.args, &env));
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
            },
            Stmt::Intrinsic { span, intrinsic } => {
                let sink_fact = intrinsic_u32_sink_fact(intrinsic, &env);
                if sink_fact.has_concrete_sources() {
                    diagnostics.push(self.new_diagnostic(
                        *span,
                        AdviceSinkKind::U32Intrinsic,
                        "unconstrained advice reaches a u32 intrinsic",
                        &sink_fact,
                    ));
                }
                apply_intrinsic_effect(*span, intrinsic, &mut env);
            },
            Stmt::If { cond, then_body, else_body, phis, .. } => {
                let sink_fact = expr_u32_sink_fact(cond, &env);
                if sink_fact.has_concrete_sources() {
                    diagnostics.push(self.new_diagnostic(
                        stmt_span(stmt),
                        AdviceSinkKind::U32Expression,
                        "unconstrained advice reaches a u32 operation",
                        &sink_fact,
                    ));
                }
                let (then_env, else_env) = refine_if_envs(cond, &env);
                let then_result = self.eval_block(then_body, then_env);
                let else_result = self.eval_block(else_body, else_env);
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
            Stmt::While { cond, body, phis, .. } => {
                let sink_fact = expr_u32_sink_fact(cond, &env);
                if sink_fact.has_concrete_sources() {
                    diagnostics.push(self.new_diagnostic(
                        stmt_span(stmt),
                        AdviceSinkKind::U32Expression,
                        "unconstrained advice reaches a u32 operation",
                        &sink_fact,
                    ));
                }
                let loop_result = self.eval_loop_block(body, phis, env);
                env = loop_result.env;
                diagnostics.extend(loop_result.diagnostics);
            },
            Stmt::Repeat { body, phis, .. } => {
                let loop_result = self.eval_loop_block(body, phis, env);
                env = loop_result.env;
                diagnostics.extend(loop_result.diagnostics);
            },
        }

        EvalResult { env, diagnostics }
    }

    /// Evaluate a structured loop body conservatively.
    fn eval_loop_block(
        &self,
        body: &[Stmt],
        phis: &[masm_decompiler::ir::LoopPhi],
        entry_env: Env,
    ) -> EvalResult {
        let mut loop_env = entry_env.clone();

        for _ in 0..MAX_LOOP_PASSES {
            let body_result = self.eval_block(body, loop_env.clone());

            let mut next_env = loop_env.join(&body_result.env);
            for phi in phis {
                let merged = entry_env
                    .fact_for_var(&phi.init)
                    .join(&body_result.env.fact_for_var(&phi.step));
                next_env.set_var_fact(&phi.dest, merged);
                assign_phi_metadata(
                    &phi.dest,
                    &phi.init,
                    &entry_env,
                    &phi.step,
                    &body_result.env,
                    &mut next_env,
                );
            }

            if next_env == loop_env {
                loop_env = next_env;
                break;
            }
            loop_env = next_env;
        }

        let body_result = self.eval_block(body, loop_env.clone());
        let mut diagnostics = body_result.diagnostics;
        loop_env = loop_env.join(&body_result.env);
        for phi in phis {
            let merged =
                entry_env.fact_for_var(&phi.init).join(&body_result.env.fact_for_var(&phi.step));
            loop_env.set_var_fact(&phi.dest, merged);
            assign_phi_metadata(
                &phi.dest,
                &phi.init,
                &entry_env,
                &phi.step,
                &body_result.env,
                &mut loop_env,
            );
        }

        EvalResult {
            env: loop_env,
            diagnostics: std::mem::take(&mut diagnostics),
        }
    }

    /// Create a diagnostic whose related source spans are derived from a fact.
    fn new_diagnostic(
        &self,
        span: miden_debug_types::SourceSpan,
        sink: AdviceSinkKind,
        message: impl Into<String>,
        fact: &AdviceFact,
    ) -> AdviceDiagnostic {
        let mut diagnostic = AdviceDiagnostic::new(self.proc_path.clone(), span, sink, message);
        diagnostic.origins = fact.source_spans.iter().copied().collect();
        diagnostic
    }

    /// Emit diagnostics for call arguments whose callee expects `U32`.
    fn call_diagnostics(
        &self,
        span: miden_debug_types::SourceSpan,
        target: &str,
        args: &[masm_decompiler::ir::Var],
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
            let mut diagnostic = self.new_diagnostic(
                span,
                AdviceSinkKind::CallArgument,
                format!(
                    "argument {index} to `{callee}` expects U32 and may contain unconstrained advice"
                ),
                &arg_fact,
            );
            diagnostic.callee = Some(callee);
            diagnostic.arg_index = Some(index);
            diagnostic.call_requirement = Some(CallArgumentRequirement::U32);
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
