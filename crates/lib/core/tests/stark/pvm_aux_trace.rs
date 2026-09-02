//! Behavioral oracles for the PVM auxiliary-trace verifier hook.

use std::fmt::Write as _;

use miden_core::{
    Felt,
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt},
};
use miden_precompiles::{CurveId, UintDomain};

use super::pvm_layout_const;
use crate::helpers::read_memory_felt;

const AUX_TRACE_COM_PTR: u32 = 3_223_322_644;
const RANDOM_COIN_CV_PTR: u32 = 3_223_322_668;
const RANDOM_COIN_INPUT_LEN_PTR: u32 = 3_223_322_767;
const RANDOM_COIN_OUTPUT_LEN_PTR: u32 = 3_223_322_768;
const RANDOM_COIN_COUNTER_PTR: u32 = 3_223_322_769;
const INITIAL_CV: [u64; 4] = [19, 20, 21, 22];
const COMMITMENT: [u64; 4] = [31, 32, 33, 34];
const LOG_HEIGHTS: [u8; 10] = [8, 6, 7, 16, 5, 9, 10, 11, 12, 13];
const AUX_VALUE_WIDTHS: [usize; 10] = [1, 2, 1, 2, 1, 1, 1, 1, 1, 1];

fn setup_masm() -> String {
    let cv = INITIAL_CV;
    let mut heights = String::new();
    for (index, height) in LOG_HEIGHTS.into_iter().enumerate() {
        let offset = if index == 0 {
            String::new()
        } else {
            format!(" add.{index}")
        };
        writeln!(
            heights,
            "push.{height} exec.constants::air_trace_length_logs_ptr{offset} mem_store"
        )
        .expect("write height setup");
    }
    format!(
        r#"
        push.{cv3}.{cv2}.{cv1}.{cv0}
        exec.constants::random_coin_cv_ptr mem_storew_le dropw
        padw exec.constants::random_coin_output_word_ptr mem_storew_le dropw
        padw exec.constants::random_coin_block_ptr mem_storew_le dropw
        padw exec.constants::random_coin_block_ptr add.4 mem_storew_le dropw
        push.0 exec.constants::random_coin_input_len_ptr mem_store
        push.0 exec.constants::random_coin_output_len_ptr mem_store
        push.0 exec.constants::random_coin_counter_ptr mem_store
        {heights}
        "#,
        cv0 = cv[0],
        cv1 = cv[1],
        cv2 = cv[2],
        cv3 = cv[3],
    )
}

fn sampler_source() -> String {
    format!(
        r#"
        use miden::core::stark::constants
        use miden::core::stark::random_coin

        begin
            {}
            exec.random_coin::generate_aux_randomness
        end
        "#,
        setup_masm()
    )
}

fn hook_source() -> String {
    format!(
        r#"
        use miden::core::stark::constants
        use miden::core::sys::pvm::aux_trace

        begin
            {}
            exec.aux_trace::observe_aux_trace
        end
        "#,
        setup_masm()
    )
}

/// A deliberately straightforward transcript path: consume the same seven advice words through
/// the public buffered word API, compressing three complete Eidos blocks and buffering one word.
fn reference_source() -> String {
    format!(
        r#"
        use miden::core::stark::constants
        use miden::core::stark::random_coin
        use miden::core::sys::pvm::layout

        begin
            {}
            exec.random_coin::generate_aux_randomness

            padw adv_loadw
            exec.constants::aux_trace_com_ptr mem_storew_le
            exec.random_coin::observe_word
            padw adv_loadw
            exec.layout::aux_bus_boundary_ptr mem_storew_le
            exec.random_coin::observe_word

            padw adv_loadw
            exec.layout::aux_bus_boundary_ptr add.4 mem_storew_le
            exec.random_coin::observe_word
            padw adv_loadw
            exec.layout::aux_bus_boundary_ptr add.8 mem_storew_le
            exec.random_coin::observe_word

            padw adv_loadw
            exec.layout::aux_bus_boundary_ptr add.12 mem_storew_le
            exec.random_coin::observe_word
            padw adv_loadw
            exec.layout::aux_bus_boundary_ptr add.16 mem_storew_le
            exec.random_coin::observe_word
            padw adv_loadw
            exec.layout::aux_bus_boundary_ptr add.20 mem_storew_le
            exec.random_coin::observe_word
        end
        "#,
        setup_masm()
    )
}

fn sampled_challenges() -> (QuadFelt, QuadFelt) {
    let (output, _) = build_test!(&sampler_source(), &[])
        .execute_for_output()
        .expect("challenge sampler must execute");
    let aux_rand_elem_ptr = pvm_layout_const("AUX_RAND_ELEM_PTR");
    let beta = QuadFelt::new([
        read_memory_felt(&output, aux_rand_elem_ptr),
        read_memory_felt(&output, aux_rand_elem_ptr + 1),
    ]);
    let alpha = QuadFelt::new([
        read_memory_felt(&output, aux_rand_elem_ptr + 2),
        read_memory_felt(&output, aux_rand_elem_ptr + 3),
    ]);
    (alpha, beta)
}

fn encode_message(alpha: QuadFelt, beta: QuadFelt, scale: u32, payload: &[u32]) -> QuadFelt {
    let gamma = (0..18).fold(QuadFelt::ONE, |acc, _| acc * beta);
    let message = payload
        .iter()
        .rev()
        .fold(QuadFelt::ZERO, |acc, value| acc * beta + QuadFelt::from(Felt::from_u32(*value)));
    alpha + gamma * QuadFelt::from(Felt::from_u32(scale)) + message
}

/// Derives the verifier-side fixed consumes from the public semantic definitions, independently
/// of the MASM literals and folding procedures.
fn fixed_boundary_correction(alpha: QuadFelt, beta: QuadFelt) -> QuadFelt {
    let uint_messages = UintDomain::ALL.into_iter().map(|domain| {
        let ptr = domain.bound_ptr();
        let mut payload = vec![ptr, ptr];
        payload.extend_from_slice(&domain.minus_one());
        payload
    });
    let coefficient_messages = CurveId::ALL.into_iter().flat_map(|curve| {
        let bound_ptr = curve.base_domain().bound_ptr();
        [
            {
                let mut payload = vec![curve.a_ptr(), bound_ptr];
                payload.extend_from_slice(&curve.a_value());
                payload
            },
            {
                let mut payload = vec![curve.b_ptr(), bound_ptr];
                payload.extend_from_slice(&curve.b_value());
                payload
            },
        ]
    });
    let endomorphism_messages = CurveId::ALL.into_iter().flat_map(|curve| {
        let base_bound_ptr = curve.base_domain().bound_ptr();
        let scalar_bound_ptr = curve.scalar_domain().bound_ptr();
        curve.endomorphism().into_iter().flat_map(move |endomorphism| {
            [
                {
                    let mut payload = vec![endomorphism.beta_ptr, base_bound_ptr];
                    payload.extend_from_slice(&endomorphism.beta);
                    payload
                },
                {
                    let mut payload = vec![endomorphism.lambda_ptr, scalar_bound_ptr];
                    payload.extend_from_slice(&endomorphism.lambda);
                    payload
                },
            ]
        })
    });

    let uint_correction = uint_messages
        .chain(coefficient_messages)
        .chain(endomorphism_messages)
        .fold(QuadFelt::ZERO, |acc, payload| {
            acc + encode_message(alpha, beta, 11, &payload)
                .try_inverse()
                .expect("nonzero fixed UintVal denominator")
        });
    CurveId::ALL.into_iter().fold(uint_correction, |acc, curve| {
        let (beta_ptr, lambda_ptr) = curve
            .endomorphism()
            .map(|endomorphism| (endomorphism.beta_ptr, endomorphism.lambda_ptr))
            .unwrap_or((0, 0));
        let payload = [
            curve.group_ptr(),
            curve.a_ptr(),
            curve.b_ptr(),
            curve.base_domain().bound_ptr(),
            curve.scalar_domain().bound_ptr(),
            beta_ptr,
            lambda_ptr,
        ];
        acc + encode_message(alpha, beta, 15, &payload)
            .try_inverse()
            .expect("nonzero fixed EcGroup denominator")
    })
}

fn proof_order() -> [usize; 10] {
    let mut order = core::array::from_fn(|index| index);
    order.sort_by_key(|&index| (LOG_HEIGHTS[index], index));
    order
}

fn valid_sigmas(correction: QuadFelt) -> [Vec<QuadFelt>; 10] {
    let mut next = 1u32;
    let mut sigmas: [Vec<QuadFelt>; 10] = core::array::from_fn(|air_index| {
        (0..AUX_VALUE_WIDTHS[air_index])
            .map(|_| {
                let value = QuadFelt::new([Felt::from_u32(next), Felt::from_u32(next + 1)]);
                next += 2;
                value
            })
            .collect()
    });

    // Reserve a single-width AIR as the balancing term, then mirror MultiAir::eval_external:
    // the second EidosCompression and BytePairAnd8 values use the centered sigma-prime convention.
    sigmas[9][0] = QuadFelt::ZERO;
    let partial = sigmas.iter().enumerate().fold(QuadFelt::ZERO, |sum, (index, values)| {
        if matches!(index, 1 | 3) {
            let n = Felt::new_unchecked(1u64 << LOG_HEIGHTS[index]);
            sum + values[0] + values[1] * n
        } else {
            sum + values[0]
        }
    });
    sigmas[9][0] = -correction - partial;
    sigmas
}

fn proof_ordered_sigmas(sigmas: &[Vec<QuadFelt>; 10]) -> Vec<QuadFelt> {
    proof_order()
        .into_iter()
        .flat_map(|air_index| sigmas[air_index].iter().copied())
        .collect()
}

fn advice(sigmas: &[Vec<QuadFelt>; 10]) -> Vec<u64> {
    let ordered = proof_ordered_sigmas(sigmas);
    COMMITMENT
        .into_iter()
        .chain(ordered.iter().flat_map(|sigma| {
            sigma
                .as_basis_coefficients_slice()
                .iter()
                .map(|felt: &Felt| felt.as_canonical_u64())
        }))
        .collect()
}

#[test]
fn pvm_aux_hook_matches_independent_transcript_and_fixed_boundary_oracles() {
    let (alpha, beta) = sampled_challenges();
    let correction = fixed_boundary_correction(alpha, beta);
    let sigmas = valid_sigmas(correction);
    let advice = advice(&sigmas);

    let (hook_output, _) = build_test!(&hook_source(), &[], &advice)
        .execute_for_output()
        .expect("PVM aux hook must accept the balanced boundary");
    let (reference_output, _) = build_test!(&reference_source(), &[], &advice)
        .execute_for_output()
        .expect("reference transcript must execute");

    for addr in RANDOM_COIN_CV_PTR..RANDOM_COIN_CV_PTR + 4 {
        assert_eq!(
            read_memory_felt(&hook_output, addr),
            read_memory_felt(&reference_output, addr),
            "transcript state differs at address {addr}"
        );
    }
    for addr in [RANDOM_COIN_INPUT_LEN_PTR, RANDOM_COIN_OUTPUT_LEN_PTR, RANDOM_COIN_COUNTER_PTR] {
        assert_eq!(
            read_memory_felt(&hook_output, addr),
            read_memory_felt(&reference_output, addr),
            "transcript counter differs at address {addr}"
        );
    }

    let gamma = (0..18).fold(QuadFelt::ONE, |acc, _| acc * beta);
    let expected_gamma: &[Felt] = gamma.as_basis_coefficients_slice();
    let bus_gamma_ptr = pvm_layout_const("BUS_GAMMA_PTR");
    assert_eq!(read_memory_felt(&hook_output, bus_gamma_ptr), expected_gamma[0]);
    assert_eq!(read_memory_felt(&hook_output, bus_gamma_ptr + 1), expected_gamma[1]);
    assert_eq!(read_memory_felt(&hook_output, bus_gamma_ptr + 2), Felt::ZERO);
    assert_eq!(read_memory_felt(&hook_output, bus_gamma_ptr + 3), Felt::ZERO);

    let expected_correction: &[Felt] = correction.as_basis_coefficients_slice();
    let c_total_ptr = pvm_layout_const("C_TOTAL_PTR");
    assert_eq!(read_memory_felt(&hook_output, c_total_ptr), expected_correction[0]);
    assert_eq!(read_memory_felt(&hook_output, c_total_ptr + 1), expected_correction[1]);
    assert_eq!(read_memory_felt(&hook_output, c_total_ptr + 2), Felt::ZERO);
    assert_eq!(read_memory_felt(&hook_output, c_total_ptr + 3), Felt::ZERO);

    let aux_bus_boundary_ptr = pvm_layout_const("AUX_BUS_BOUNDARY_PTR");
    for (i, sigma) in proof_ordered_sigmas(&sigmas).iter().enumerate() {
        let coefficients: &[Felt] = sigma.as_basis_coefficients_slice();
        for (coord, expected) in coefficients.iter().enumerate() {
            assert_eq!(
                read_memory_felt(&hook_output, aux_bus_boundary_ptr + 2 * i as u32 + coord as u32,),
                *expected,
                "sigma {i} coordinate {coord} was not stored in proof order"
            );
        }
    }
    for (i, expected) in COMMITMENT.into_iter().enumerate() {
        assert_eq!(
            read_memory_felt(&hook_output, AUX_TRACE_COM_PTR + i as u32),
            Felt::new_unchecked(expected),
            "aux commitment coordinate {i} mismatch"
        );
    }
}

#[test]
fn pvm_aux_hook_rejects_an_unbalanced_sigma() {
    let (alpha, beta) = sampled_challenges();
    let mut sigmas = valid_sigmas(fixed_boundary_correction(alpha, beta));
    sigmas[4][0] += QuadFelt::ONE;
    let advice = advice(&sigmas);

    let test = build_test!(&hook_source(), &[], &advice);
    // The release package retains the assertion code but not the source message. The matching
    // balanced fixture above reaches this point successfully; changing only one sigma therefore
    // isolates the final fixed-boundary assertion.
    expect_assert_error_message!(test);
}
