//! Intrinsic transfer helpers for unconstrained-advice analyses.

use masm_decompiler::{
    INTRINSIC_ADV_PIPE, INTRINSIC_ADV_PUSH, INTRINSIC_ADV_PUSHW, INTRINSIC_MEM_STREAM, Intrinsic,
    intrinsic_base_name, intrinsic_requires_u32_precondition,
};

use super::{domain::AdviceFact, env::Env, u32_domain::U32Validity};

/// Refine the environment after `assertz` proves an `eq.0` witness is zero.
pub(super) fn refine_nonzero_from_intrinsic(intrinsic: &Intrinsic, env: &mut Env) {
    if intrinsic_base_name(&intrinsic.name) != "assertz" {
        return;
    }
    let Some(arg) = intrinsic.args.first() else {
        return;
    };
    let Some(witness) = env.zero_test_for_var(arg) else {
        return;
    };
    env.mark_identity_nonzero(witness.value_identity);
}

/// Apply the common provenance transfer semantics of one intrinsic statement.
pub(super) fn apply_intrinsic_effect(
    span: miden_debug_types::SourceSpan,
    intrinsic: &Intrinsic,
    env: &mut Env,
) {
    if matches!(intrinsic_base_name(&intrinsic.name), INTRINSIC_ADV_PUSH | INTRINSIC_ADV_PUSHW) {
        for result in &intrinsic.results {
            env.set_var_fact(result, AdviceFact::from_source(span));
            env.clear_var_metadata(result);
        }
        return;
    }

    match intrinsic_base_name(&intrinsic.name) {
        "u32assert" | "u32assert2" | "u32assertw" => {
            for arg in &intrinsic.args {
                env.sanitize_var(arg);
            }
        },
        "u32split" => {
            for (index, result) in intrinsic.results.iter().enumerate() {
                env.set_var_fact(result, AdviceFact::bottom());
                env.clear_var_metadata(result);
                if index == intrinsic.results.len().saturating_sub(1) {
                    env.set_var_u32_validity(result, U32Validity::ProvenU32);
                }
            }
        },
        "is_odd" => {
            for result in &intrinsic.results {
                env.set_var_fact(result, AdviceFact::bottom());
                env.clear_var_metadata(result);
            }
        },
        "u32testw" => {
            if let Some((flag, preserved)) = intrinsic.results.split_first() {
                env.set_var_fact(flag, AdviceFact::bottom());
                env.clear_var_metadata(flag);
                env.set_var_u32_validity(flag, U32Validity::ProvenU32);
                for (result, arg) in preserved.iter().zip(intrinsic.args.iter()) {
                    env.set_var_fact(result, env.fact_for_var(arg));
                    env.set_var_u32_validity(result, env.u32_validity_for_var(arg));
                    env.set_var_identity(result, env.identity_for_var(arg));
                    env.set_var_zero_test(result, env.zero_test_for_var(arg));
                }
            }
        },
        INTRINSIC_ADV_PIPE => {
            apply_adv_pipe_effect(span, intrinsic, env);
        },
        INTRINSIC_MEM_STREAM => {
            apply_mem_stream_effect(intrinsic, env);
        },
        "sdepth" => {
            for result in &intrinsic.results {
                env.set_var_fact(result, AdviceFact::bottom());
                env.clear_var_metadata(result);
            }
        },
        name if name.starts_with("locaddr") => {
            for result in &intrinsic.results {
                env.set_var_fact(result, AdviceFact::bottom());
                env.clear_var_metadata(result);
            }
        },
        _ if intrinsic_requires_u32_precondition(&intrinsic.name) => {
            for result in &intrinsic.results {
                env.set_var_fact(result, AdviceFact::bottom());
                env.clear_var_metadata(result);
                env.set_var_u32_validity(result, U32Validity::ProvenU32);
            }
        },
        _ => {
            let joined =
                AdviceFact::join_all(intrinsic.args.iter().map(|arg| env.fact_for_var(arg)));
            for result in &intrinsic.results {
                env.set_var_fact(result, joined.clone());
                env.clear_var_metadata(result);
            }
        },
    }
}

/// Apply the custom transfer semantics of `mem_stream`.
fn apply_mem_stream_effect(intrinsic: &Intrinsic, env: &mut Env) {
    if intrinsic.args.len() == 13 && intrinsic.results.len() == 13 {
        let address = &intrinsic.args[12];
        env.set_var_fact(&intrinsic.results[0], env.fact_for_var(address));
        env.set_var_u32_validity(&intrinsic.results[0], U32Validity::Unknown);
        env.clear_var_metadata(&intrinsic.results[0]);

        for (offset, result) in intrinsic.results[1..5].iter().enumerate() {
            let preserved_input = &intrinsic.args[11 - offset];
            env.set_var_fact(result, env.fact_for_var(preserved_input));
            env.set_var_u32_validity(result, env.u32_validity_for_var(preserved_input));
            env.set_var_identity(result, env.identity_for_var(preserved_input));
            env.set_var_zero_test(result, env.zero_test_for_var(preserved_input));
        }

        for result in &intrinsic.results[5..] {
            env.set_var_fact(result, AdviceFact::bottom());
            env.clear_var_metadata(result);
        }
        return;
    }

    for result in &intrinsic.results {
        env.set_var_fact(result, AdviceFact::bottom());
        env.clear_var_metadata(result);
    }
}

/// Apply the custom transfer semantics of `adv_pipe`.
fn apply_adv_pipe_effect(
    span: miden_debug_types::SourceSpan,
    intrinsic: &Intrinsic,
    env: &mut Env,
) {
    if intrinsic.args.len() == 13 && intrinsic.results.len() == 13 {
        env.set_var_fact(&intrinsic.results[0], AdviceFact::bottom());
        env.clear_var_metadata(&intrinsic.results[0]);

        for (offset, result) in intrinsic.results[1..5].iter().enumerate() {
            let preserved_input = &intrinsic.args[11 - offset];
            env.set_var_fact(result, env.fact_for_var(preserved_input));
            env.set_var_u32_validity(result, env.u32_validity_for_var(preserved_input));
            env.set_var_identity(result, env.identity_for_var(preserved_input));
            env.set_var_zero_test(result, env.zero_test_for_var(preserved_input));
        }

        for result in &intrinsic.results[5..] {
            env.set_var_fact(result, AdviceFact::from_source(span));
            env.clear_var_metadata(result);
        }
        return;
    }

    for result in &intrinsic.results {
        env.set_var_fact(result, AdviceFact::from_source(span));
        env.clear_var_metadata(result);
    }
}
