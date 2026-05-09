//! Interprocedural provenance summaries for unconstrained advice.

use masm_decompiler::{LocalAccessKind, LoopPhi, Stmt, SymbolPath, Var};

use super::{
    shared::{
        Env, apply_intrinsic_effect, apply_local_load_scalar, apply_local_load_word,
        apply_local_store, apply_local_store_word, assign_expr_metadata, assign_phi_metadata,
        expr_output_fact, refine_if_envs, seed_input_env, stabilized_loop_head_env,
    },
    summary::{AdviceSummary, AdviceSummaryMap},
    u32_domain::U32Validity,
};

/// Analyze one lifted procedure and summarize which outputs may carry unconstrained advice.
pub(super) fn analyze_proc_provenance(
    input_count: usize,
    output_count: usize,
    stmts: &[Stmt],
    callee_summaries: &AdviceSummaryMap,
) -> AdviceSummary {
    let env = seed_input_env(input_count);
    let result = eval_block(stmts, env, callee_summaries);
    if result.opaque {
        AdviceSummary::unknown_with_arity(output_count)
    } else {
        build_summary(input_count, stmts, output_count, &result.env)
    }
}

/// Result of evaluating a statement block.
#[derive(Debug, Clone)]
struct EvalResult {
    env: Env,
    opaque: bool,
}

/// Build the final output summary from the return statement.
fn build_summary(
    input_count: usize,
    stmts: &[Stmt],
    output_count: usize,
    env: &Env,
) -> AdviceSummary {
    let Some(values) = stmts.iter().find_map(|stmt| match stmt {
        Stmt::Return { values, .. } => Some(values.as_slice()),
        _ => None,
    }) else {
        return AdviceSummary::new(vec![super::domain::AdviceFact::bottom(); output_count]);
    };

    let mut outputs = Vec::with_capacity(output_count);
    let mut u32_outputs = Vec::with_capacity(output_count);
    let mut forwarded_inputs = Vec::with_capacity(output_count);
    for index in (0..output_count).rev() {
        let fact = values
            .get(index)
            .map(|var| env.fact_for_var(var))
            .unwrap_or_else(super::domain::AdviceFact::bottom);
        let forwarded_input =
            values.get(index).and_then(|var| exact_forwarded_input(input_count, var, env));
        let direct_validity = values
            .get(index)
            .map(|var| env.u32_validity_for_var(var))
            .unwrap_or(U32Validity::Unknown);
        let forwarded_validity = forwarded_input
            .map(|input_position| {
                env.u32_validity_for_var(&input_var_for_position(input_count, input_position))
            })
            .unwrap_or(U32Validity::Unknown);
        let validity = if direct_validity.is_proven() || forwarded_validity.is_proven() {
            U32Validity::ProvenU32
        } else {
            U32Validity::Unknown
        };
        outputs.push(fact);
        u32_outputs.push(validity);
        forwarded_inputs.push(forwarded_input);
    }
    let u32_inputs = (0..input_count)
        .map(|input_position| input_var_for_position(input_count, input_position))
        .map(|input_var| env.u32_validity_for_var(&input_var))
        .collect();
    AdviceSummary::with_forwarding(outputs, u32_outputs, forwarded_inputs, u32_inputs)
}

/// Return the exact input position forwarded by an output, if the output aliases that input.
fn exact_forwarded_input(input_count: usize, output: &Var, env: &Env) -> Option<usize> {
    let output_identity = env.identity_for_var(output);
    (0..input_count).find(|&input_position| {
        env.identity_for_var(&input_var_for_position(input_count, input_position))
            == output_identity
    })
}

/// Return the synthetic SSA variable used for one lifted procedure input.
fn input_var_for_position(input_count: usize, input_position: usize) -> Var {
    let depth = input_count - 1 - input_position;
    Var::new((depth as u64).into(), depth)
}

/// Evaluate a statement block from top to bottom.
fn eval_block(stmts: &[Stmt], mut env: Env, callee_summaries: &AdviceSummaryMap) -> EvalResult {
    let mut opaque = false;

    for stmt in stmts {
        let result = eval_stmt(stmt, env, callee_summaries);
        env = result.env;
        opaque |= result.opaque;
    }

    EvalResult { env, opaque }
}

/// Evaluate a single statement.
fn eval_stmt(stmt: &Stmt, mut env: Env, callee_summaries: &AdviceSummaryMap) -> EvalResult {
    let mut opaque = false;

    match stmt {
        Stmt::Assign { dest, expr, .. } => {
            let fact = expr_output_fact(expr, &env);
            env.set_var_fact(dest, fact);
            assign_expr_metadata(dest, expr, &mut env);
        },
        Stmt::AdvLoad { span, load } => {
            for output in &load.outputs {
                env.set_var_fact(output, super::domain::AdviceFact::from_source(*span));
                env.clear_var_metadata(output);
            }
        },
        Stmt::AdvStore { .. } | Stmt::MemStore { .. } | Stmt::Return { .. } => {},
        Stmt::MemLoad { load, .. } => {
            for output in &load.outputs {
                env.set_var_fact(output, super::domain::AdviceFact::bottom());
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
            assign_call_results(
                &mut env,
                &call.target,
                &call.args,
                &call.results,
                callee_summaries,
            );
        },
        Stmt::DynCall { results, .. } => {
            for result in results {
                env.set_var_fact(result, super::domain::AdviceFact::bottom());
                env.clear_var_metadata(result);
            }
            opaque = true;
        },
        Stmt::Intrinsic { span, intrinsic } => {
            apply_intrinsic_effect(*span, intrinsic, &mut env);
        },
        Stmt::If { cond, then_body, else_body, phis, .. } => {
            let (then_env, else_env) = refine_if_envs(cond, &env);
            let then_result = eval_block(then_body, then_env, callee_summaries);
            let else_result = eval_block(else_body, else_env, callee_summaries);
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
        Stmt::While { body, phis, .. } | Stmt::Repeat { body, phis, .. } => {
            let loop_result = eval_loop_block(body, phis, env, callee_summaries);
            env = loop_result.env;
            opaque |= loop_result.opaque;
        },
    }

    EvalResult { env, opaque }
}

/// Evaluate a structured loop body conservatively.
fn eval_loop_block(
    body: &[Stmt],
    phis: &[LoopPhi],
    entry_env: Env,
    callee_summaries: &AdviceSummaryMap,
) -> EvalResult {
    let mut opaque = false;
    let env = stabilized_loop_head_env(&entry_env, phis, |loop_env| {
        let body_result = eval_block(body, loop_env, callee_summaries);
        opaque |= body_result.opaque;
        body_result.env
    });

    EvalResult { env, opaque }
}

/// Assign call-result facts by substituting caller arguments into callee summaries.
pub(super) fn assign_call_results(
    env: &mut Env,
    target: &str,
    args: &[Var],
    results: &[Var],
    callee_summaries: &AdviceSummaryMap,
) {
    let Some(summary) = callee_summaries.get(&SymbolPath::new(target.to_string())) else {
        clear_call_results(env, results);
        return;
    };
    if summary.is_unknown() {
        clear_call_results(env, results);
        return;
    }

    let arg_facts = args.iter().map(|arg| env.fact_for_var(arg)).collect::<Vec<_>>();
    let caller_arg_u32_validity =
        args.iter().map(|arg| env.u32_validity_for_var(arg)).collect::<Vec<_>>();
    for ((arg, summary_u32), caller_u32) in args
        .iter()
        .zip(summary.u32_inputs().iter())
        .zip(caller_arg_u32_validity.iter().copied())
    {
        env.set_var_u32_validity(
            arg,
            if summary_u32.is_proven() || caller_u32.is_proven() {
                U32Validity::ProvenU32
            } else {
                U32Validity::Unknown
            },
        );
    }
    for (((result, summary_fact), summary_u32), forwarded_input) in results
        .iter()
        .zip(summary.outputs.iter())
        .zip(summary.u32_outputs().iter())
        .zip(summary.forwarded_inputs().iter())
    {
        env.set_var_fact(result, substitute_output_fact(summary_fact, &arg_facts));
        let forwarded_arg = forwarded_input.and_then(|input_index| args.get(input_index));
        let forwarded_validity = forwarded_arg
            .map(|arg| env.u32_validity_for_var(arg))
            .unwrap_or(U32Validity::Unknown);
        env.set_var_u32_validity(
            result,
            if summary_u32.is_proven() || forwarded_validity.is_proven() {
                U32Validity::ProvenU32
            } else {
                U32Validity::Unknown
            },
        );
        if let Some(arg) = forwarded_arg {
            env.set_var_identity(result, env.identity_for_var(arg));
            env.set_var_zero_test(result, env.zero_test_for_var(arg));
        } else {
            env.clear_var_metadata(result);
        }
    }
    for result in results.iter().skip(summary.output_count()) {
        env.set_var_fact(result, super::domain::AdviceFact::bottom());
        env.clear_var_metadata(result);
    }
}

/// Clear call outputs when the callee is missing or opaque.
fn clear_call_results(env: &mut Env, results: &[Var]) {
    for result in results {
        env.set_var_fact(result, super::domain::AdviceFact::bottom());
        env.clear_var_metadata(result);
    }
}

/// Substitute caller argument facts into a callee output summary fact.
fn substitute_output_fact(
    summary_fact: &super::domain::AdviceFact,
    arg_facts: &[super::domain::AdviceFact],
) -> super::domain::AdviceFact {
    let mut substituted = super::domain::AdviceFact::bottom();
    substituted.source_spans = summary_fact.source_spans.clone();
    for input_index in &summary_fact.from_inputs {
        if let Some(arg_fact) = arg_facts.get(*input_index) {
            substituted = substituted.join(arg_fact);
        }
    }
    substituted
}
