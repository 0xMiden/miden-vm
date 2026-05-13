//! Interprocedural call-result transfer for advice summaries.

use masm_decompiler::{SymbolPath, Var};

use super::{domain::AdviceFact, shared::Env, summary::AdviceSummaryMap, u32_domain::U32Validity};

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
        .zip(summary.output_facts().iter())
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
        env.set_var_fact(result, AdviceFact::bottom());
        env.set_var_u32_validity(result, U32Validity::Unknown);
        env.clear_var_metadata(result);
    }
}

/// Clear call outputs when the callee is missing or opaque.
fn clear_call_results(env: &mut Env, results: &[Var]) {
    for result in results {
        env.set_var_fact(result, AdviceFact::bottom());
        env.set_var_u32_validity(result, U32Validity::Unknown);
        env.clear_var_metadata(result);
    }
}

/// Substitute caller argument facts into a callee output summary fact.
fn substitute_output_fact(summary_fact: &AdviceFact, arg_facts: &[AdviceFact]) -> AdviceFact {
    let mut substituted = AdviceFact::bottom();
    substituted.source_spans = summary_fact.source_spans.clone();
    for input_index in &summary_fact.from_inputs {
        if let Some(arg_fact) = arg_facts.get(*input_index) {
            substituted = substituted.join(arg_fact);
        }
    }
    substituted
}

#[cfg(test)]
mod tests {
    use masm_decompiler::{SymbolPath, Var};

    use super::*;
    use crate::unconstrained_advice::{
        env::EqZeroWitness,
        summary::{AdviceSummary, AdviceSummaryMap},
    };

    fn var(id: u64) -> Var {
        Var::new(id.into(), id as usize)
    }

    #[test]
    fn assign_call_results_substitutes_provenance_and_forwarded_metadata() {
        let arg0 = var(0);
        let arg1 = var(1);
        let result0 = var(2);
        let result1 = var(3);
        let extra_result = var(4);

        let mut env = Env::default();
        env.set_var_fact(&arg0, AdviceFact::from_input(0));
        env.set_var_fact(&arg1, AdviceFact::from_input(1));
        env.set_var_u32_validity(&arg1, U32Validity::ProvenU32);
        env.set_var_u32_validity(&extra_result, U32Validity::ProvenU32);
        env.set_var_zero_test(
            &arg1,
            Some(EqZeroWitness {
                value_identity: env.identity_for_var(&arg0),
            }),
        );

        let mut summaries = AdviceSummaryMap::default();
        summaries.insert(
            SymbolPath::new("callee"),
            AdviceSummary::with_forwarding(
                vec![AdviceFact::from_input(1), AdviceFact::bottom()],
                vec![U32Validity::Unknown, U32Validity::ProvenU32],
                vec![Some(1), None],
                vec![U32Validity::Unknown, U32Validity::ProvenU32],
            ),
        );

        assign_call_results(
            &mut env,
            "callee",
            &[arg0.clone(), arg1.clone()],
            &[result0.clone(), result1.clone(), extra_result.clone()],
            &summaries,
        );

        assert_eq!(env.fact_for_var(&result0), AdviceFact::from_input(1));
        assert_eq!(env.identity_for_var(&result0), env.identity_for_var(&arg1));
        assert_eq!(env.zero_test_for_var(&result0), env.zero_test_for_var(&arg1));
        assert_eq!(env.u32_validity_for_var(&result0), U32Validity::ProvenU32);
        assert_eq!(env.u32_validity_for_var(&arg1), U32Validity::ProvenU32);

        assert_eq!(env.fact_for_var(&result1), AdviceFact::bottom());
        assert_eq!(env.u32_validity_for_var(&result1), U32Validity::ProvenU32);
        assert_eq!(env.zero_test_for_var(&result1), None);

        assert_eq!(env.fact_for_var(&extra_result), AdviceFact::bottom());
        assert_eq!(env.u32_validity_for_var(&extra_result), U32Validity::Unknown);
        assert_eq!(env.zero_test_for_var(&extra_result), None);
    }

    #[test]
    fn assign_call_results_clears_outputs_for_missing_summary() {
        let result = var(0);
        let mut env = Env::default();
        env.set_var_fact(&result, AdviceFact::from_input(0));
        env.set_var_u32_validity(&result, U32Validity::ProvenU32);

        assign_call_results(
            &mut env,
            "missing",
            &[],
            std::slice::from_ref(&result),
            &Default::default(),
        );

        assert_eq!(env.fact_for_var(&result), AdviceFact::bottom());
        assert_eq!(env.u32_validity_for_var(&result), U32Validity::Unknown);
    }
}
