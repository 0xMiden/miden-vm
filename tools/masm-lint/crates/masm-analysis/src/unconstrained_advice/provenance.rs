//! Interprocedural provenance summaries for unconstrained advice.

use masm_decompiler::analysis::{Stmt, Var};

use super::{
    effect::AdviceEffect,
    shared::Env,
    summary::{AdviceSummary, AdviceSummaryMap},
    u32_domain::U32Validity,
    walker::{self, AdviceCapability},
};

/// Analyze one lifted procedure and summarize which outputs may carry unconstrained advice.
pub(super) fn analyze_proc_provenance(
    input_count: usize,
    output_count: usize,
    stmts: &[Stmt],
    callee_summaries: &AdviceSummaryMap,
) -> AdviceSummary {
    let result =
        walker::analyze_procedure(&ProvenanceCapability, callee_summaries, input_count, stmts);
    if result.opaque {
        AdviceSummary::unknown_with_arity(output_count)
    } else {
        build_summary(input_count, stmts, output_count, &result.env)
    }
}

/// No-op capability used when the shared advice walker computes provenance summaries.
struct ProvenanceCapability;

impl AdviceCapability for ProvenanceCapability {
    type Summary = ();

    fn check_stmt(&self, _stmt: &Stmt, _env: &Env) -> AdviceEffect {
        AdviceEffect::new()
    }
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
