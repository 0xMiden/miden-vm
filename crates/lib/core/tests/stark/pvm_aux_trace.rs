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
type LogHeights = [u8; 10];

// BytePairLut is fixed at 2^16. The other entries meet their AIRs' minimum heights while
// exercising distinct proof-order positions, including an equal-height tie.
const EQUAL_EIDOS_BYTE_PAIR_HEIGHTS: LogHeights = [8, 16, 7, 16, 5, 9, 10, 11, 12, 13];
const EIDOS_PRECEDES_ORDINARY_HEIGHTS: LogHeights = [8, 5, 7, 16, 6, 9, 10, 11, 12, 13];
const BYTE_PAIR_PRECEDES_EIDOS_HEIGHTS: LogHeights = [18, 17, 19, 16, 20, 21, 22, 23, 24, 25];
const PROOF_ORDER_CASES: [(&str, LogHeights); 3] = [
    ("equal Eidos and byte-pair heights", EQUAL_EIDOS_BYTE_PAIR_HEIGHTS),
    ("Eidos before ordinary AIRs", EIDOS_PRECEDES_ORDINARY_HEIGHTS),
    ("BytePairLut before Eidos", BYTE_PAIR_PRECEDES_EIDOS_HEIGHTS),
];
const AUX_VALUE_WIDTHS: [usize; 10] = [1; 10];

fn random_coin_setup_masm() -> String {
    let cv = INITIAL_CV;
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
        "#,
        cv0 = cv[0],
        cv1 = cv[1],
        cv2 = cv[2],
        cv3 = cv[3],
    )
}

fn direct_random_coin_setup_masm() -> String {
    format!(
        "{}\npush.{} exec.constants::set_aux_rand_elem_address",
        random_coin_setup_masm(),
        pvm_layout_const("AUX_RAND_ELEM_PTR")
    )
}

fn setup_masm(log_heights: &LogHeights) -> String {
    let mut heights = String::new();
    for (index, &height) in log_heights.iter().enumerate() {
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

    let mut value_ptrs = [0_u32; 10];
    let mut next_value_ptr = pvm_layout_const("AUX_BUS_BOUNDARY_PTR");
    for air_index in proof_order(log_heights) {
        value_ptrs[air_index] = next_value_ptr;
        next_value_ptr += u32::try_from(2 * AUX_VALUE_WIDTHS[air_index])
            .expect("test auxiliary-value width must fit in u32");
    }
    let value_ptrs_base = pvm_layout_const("AUX_VALUE_PTRS_PTR");
    let mut value_ptr_setup = String::new();
    for (air_index, value_ptr) in value_ptrs.into_iter().enumerate() {
        writeln!(
            value_ptr_setup,
            "push.{value_ptr} push.{} mem_store",
            value_ptrs_base + u32::try_from(air_index).expect("AIR index must fit in u32")
        )
        .expect("write auxiliary-value pointer setup");
    }

    format!(
        r#"
        {random_coin_setup}
        {heights}
        {value_ptr_setup}
        "#,
        random_coin_setup = direct_random_coin_setup_masm(),
    )
}

fn sampler_source(log_heights: &LogHeights) -> String {
    format!(
        r#"
        use miden::core::stark::constants
        use miden::core::stark::random_coin

        begin
            {}
            exec.random_coin::generate_aux_randomness
        end
        "#,
        setup_masm(log_heights)
    )
}

fn hook_source(log_heights: &LogHeights) -> String {
    format!(
        r#"
        use miden::core::stark::constants
        use miden::core::sys::pvm::aux_trace

        begin
            {}
            exec.aux_trace::observe_aux_trace
        end
        "#,
        setup_masm(log_heights)
    )
}

fn production_hook_source() -> String {
    format!(
        r#"
        use miden::core::stark::constants
        use miden::core::sys::pvm
        use miden::core::sys::pvm::aux_trace

        begin
            {}
            exec.pvm::load_air_context
            exec.aux_trace::observe_aux_trace
        end
        "#,
        random_coin_setup_masm()
    )
}

fn air_context_source() -> &'static str {
    "use miden::core::sys::pvm
     begin
         exec.pvm::load_air_context
     end"
}

/// Reference transcript path using the public buffered word API for the same six advice words.
fn reference_source(log_heights: &LogHeights) -> String {
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
        end
        "#,
        setup_masm(log_heights)
    )
}

fn sampled_challenges(log_heights: &LogHeights) -> (QuadFelt, QuadFelt) {
    let (output, _) = build_test!(&sampler_source(log_heights), &[])
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

fn proof_order(log_heights: &LogHeights) -> [usize; 10] {
    let mut order = core::array::from_fn(|index| index);
    order.sort_by_key(|&index| (log_heights[index], index));
    order
}

fn balanced_normalized_sums(correction: QuadFelt, log_heights: &LogHeights) -> [Vec<QuadFelt>; 10] {
    let mut next = 1u32;
    let mut normalized_sums: [Vec<QuadFelt>; 10] = core::array::from_fn(|air_index| {
        (0..AUX_VALUE_WIDTHS[air_index])
            .map(|_| {
                let value = QuadFelt::new([Felt::from_u32(next), Felt::from_u32(next + 1)]);
                next += 2;
                value
            })
            .collect()
    });

    // Reserve a single-width AIR as the balancing term, then apply the same trace-length weighting
    // as `MultiAir::eval_external`.
    normalized_sums[9][0] = QuadFelt::ZERO;
    let partial =
        normalized_sums.iter().enumerate().fold(QuadFelt::ZERO, |sum, (index, values)| {
            let n = Felt::new_unchecked(1u64 << log_heights[index]);
            sum + values.iter().copied().sum::<QuadFelt>() * n
        });
    let balancing_n_inv = Felt::new_unchecked(1u64 << log_heights[9])
        .try_inverse()
        .expect("nonzero trace length");
    normalized_sums[9][0] = (-correction - partial) * balancing_n_inv;
    normalized_sums
}

fn proof_ordered_normalized_sums(
    values: &[Vec<QuadFelt>; 10],
    log_heights: &LogHeights,
) -> Vec<QuadFelt> {
    proof_order(log_heights)
        .into_iter()
        .flat_map(|air_index| values[air_index].iter().copied())
        .collect()
}

fn advice(normalized_sums: &[Vec<QuadFelt>; 10], log_heights: &LogHeights) -> Vec<u64> {
    let ordered = proof_ordered_normalized_sums(normalized_sums, log_heights);
    COMMITMENT
        .into_iter()
        .chain(ordered.iter().flat_map(|value| {
            value
                .as_basis_coefficients_slice()
                .iter()
                .map(|felt: &Felt| felt.as_canonical_u64())
        }))
        .collect()
}

#[test]
fn pvm_aux_hook_matches_independent_transcript_and_fixed_boundary_oracles() {
    for (case, log_heights) in PROOF_ORDER_CASES {
        let (alpha, beta) = sampled_challenges(&log_heights);
        let correction = fixed_boundary_correction(alpha, beta);
        let normalized_sums = balanced_normalized_sums(correction, &log_heights);
        let advice = advice(&normalized_sums, &log_heights);

        let (hook_output, _) = build_test!(&hook_source(&log_heights), &[], &advice)
            .execute_for_output()
            .unwrap_or_else(|error| {
                panic!("{case}: PVM aux hook rejected balanced boundary: {error}")
            });
        let (reference_output, _) = build_test!(&reference_source(&log_heights), &[], &advice)
            .execute_for_output()
            .unwrap_or_else(|error| panic!("{case}: reference transcript failed: {error}"));

        for addr in RANDOM_COIN_CV_PTR..RANDOM_COIN_CV_PTR + 4 {
            assert_eq!(
                read_memory_felt(&hook_output, addr),
                read_memory_felt(&reference_output, addr),
                "{case}: transcript state differs at address {addr}"
            );
        }
        for addr in [RANDOM_COIN_INPUT_LEN_PTR, RANDOM_COIN_OUTPUT_LEN_PTR, RANDOM_COIN_COUNTER_PTR]
        {
            assert_eq!(
                read_memory_felt(&hook_output, addr),
                read_memory_felt(&reference_output, addr),
                "{case}: transcript counter differs at address {addr}"
            );
        }

        let gamma = (0..18).fold(QuadFelt::ONE, |acc, _| acc * beta);
        let expected_gamma: &[Felt] = gamma.as_basis_coefficients_slice();
        let bus_gamma_ptr = pvm_layout_const("BUS_GAMMA_PTR");
        assert_eq!(
            read_memory_felt(&hook_output, bus_gamma_ptr),
            expected_gamma[0],
            "{case}: bus gamma coordinate 0 mismatch"
        );
        assert_eq!(
            read_memory_felt(&hook_output, bus_gamma_ptr + 1),
            expected_gamma[1],
            "{case}: bus gamma coordinate 1 mismatch"
        );
        assert_eq!(read_memory_felt(&hook_output, bus_gamma_ptr + 2), Felt::ZERO);
        assert_eq!(read_memory_felt(&hook_output, bus_gamma_ptr + 3), Felt::ZERO);

        let expected_correction: &[Felt] = correction.as_basis_coefficients_slice();
        let c_total_ptr = pvm_layout_const("C_TOTAL_PTR");
        assert_eq!(
            read_memory_felt(&hook_output, c_total_ptr),
            expected_correction[0],
            "{case}: fixed correction coordinate 0 mismatch"
        );
        assert_eq!(
            read_memory_felt(&hook_output, c_total_ptr + 1),
            expected_correction[1],
            "{case}: fixed correction coordinate 1 mismatch"
        );
        assert_eq!(read_memory_felt(&hook_output, c_total_ptr + 2), Felt::ZERO);
        assert_eq!(read_memory_felt(&hook_output, c_total_ptr + 3), Felt::ZERO);

        let aux_bus_boundary_ptr = pvm_layout_const("AUX_BUS_BOUNDARY_PTR");
        for (i, value) in
            proof_ordered_normalized_sums(&normalized_sums, &log_heights).iter().enumerate()
        {
            let coefficients: &[Felt] = value.as_basis_coefficients_slice();
            for (coord, expected) in coefficients.iter().enumerate() {
                assert_eq!(
                    read_memory_felt(
                        &hook_output,
                        aux_bus_boundary_ptr + 2 * i as u32 + coord as u32,
                    ),
                    *expected,
                    "{case}: normalized LogUp value {i} coordinate {coord} was not stored in proof order"
                );
            }
        }
        for (i, expected) in COMMITMENT.into_iter().enumerate() {
            assert_eq!(
                read_memory_felt(&hook_output, AUX_TRACE_COM_PTR + i as u32),
                Felt::new_unchecked(expected),
                "{case}: aux commitment coordinate {i} mismatch"
            );
        }
    }
}

#[test]
fn pvm_aux_hook_uses_value_ptrs_materialized_by_air_context() {
    for (case, log_heights) in PROOF_ORDER_CASES {
        let (alpha, beta) = sampled_challenges(&log_heights);
        let normalized_sums =
            balanced_normalized_sums(fixed_boundary_correction(alpha, beta), &log_heights);
        let proof_advice = advice(&normalized_sums, &log_heights);
        let height_advice: Vec<u64> = log_heights.into_iter().map(u64::from).collect();

        let (context_output, _) = build_test!(air_context_source(), &[], &height_advice)
            .execute_for_output()
            .unwrap_or_else(|error| panic!("{case}: PVM context load failed: {error}"));
        let mut next_value_ptr = pvm_layout_const("AUX_BUS_BOUNDARY_PTR");
        let mut expected_value_ptrs = [0_u32; 10];
        for air_index in proof_order(&log_heights) {
            expected_value_ptrs[air_index] = next_value_ptr;
            next_value_ptr += u32::try_from(2 * AUX_VALUE_WIDTHS[air_index])
                .expect("test auxiliary-value width must fit in u32");
        }
        let value_ptrs_base = pvm_layout_const("AUX_VALUE_PTRS_PTR");
        for (air_index, expected) in expected_value_ptrs.into_iter().enumerate() {
            assert_eq!(
                read_memory_felt(&context_output, value_ptrs_base + air_index as u32),
                Felt::from_u32(expected),
                "{case}: AIR {air_index} auxiliary-value pointer is wrong"
            );
        }

        let combined_advice: Vec<u64> =
            height_advice.into_iter().chain(proof_advice.iter().copied()).collect();

        build_test!(&production_hook_source(), &[], &combined_advice)
            .execute()
            .unwrap_or_else(|error| {
                panic!(
                    "{case}: production PVM context + aux hook rejected balanced boundary: {error}"
                )
            });
    }
}

#[test]
fn pvm_aux_hook_rejects_an_unbalanced_normalized_sum() {
    let log_heights = EIDOS_PRECEDES_ORDINARY_HEIGHTS;
    let (alpha, beta) = sampled_challenges(&log_heights);
    let mut normalized_sums =
        balanced_normalized_sums(fixed_boundary_correction(alpha, beta), &log_heights);
    normalized_sums[4][0] += QuadFelt::ONE;
    let advice = advice(&normalized_sums, &log_heights);

    let test = build_test!(&hook_source(&log_heights), &[], &advice);
    // The release package retains the assertion code but not the source message. The matching
    // balanced fixture above reaches this point successfully; changing only one normalized sum
    // therefore isolates the final fixed-boundary assertion.
    expect_assert_error_message!(test);
}
