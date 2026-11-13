//! Native-reference checks for shared LogUp staging and the PVM boundary correction.

use std::fmt::Write as _;

use miden_air_definitions::precompiles::relations::MAX_MESSAGE_WIDTH;
use miden_core::{
    Felt, Word,
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt},
};
use miden_crypto::hash::eidos::EidosChallenger;
use miden_precompiles::{CurveId, UintDomain};
use p3_challenger::{CanObserve, FieldChallenger};

use super::pvm_layout_const;
use crate::helpers::{read_memory_felt, stark_constant};

const INITIAL_CV: [u64; 4] = [19, 20, 21, 22];
const COMMITMENT: [u64; 4] = [31, 32, 33, 34];
type LogHeights = [u8; 12];

// BytePairLut is fixed at 2^16. The other entries meet their AIRs' minimum heights while
// exercising distinct proof-order positions, including an equal-height tie.
const EQUAL_EIDOS_BYTE_PAIR_HEIGHTS: LogHeights = [8, 16, 7, 16, 5, 9, 10, 11, 12, 13, 14, 15];
const EIDOS_PRECEDES_ORDINARY_HEIGHTS: LogHeights = [8, 5, 7, 16, 6, 9, 10, 11, 12, 13, 14, 15];
const BYTE_PAIR_PRECEDES_EIDOS_HEIGHTS: LogHeights =
    [18, 17, 19, 16, 20, 21, 22, 23, 24, 25, 26, 27];
const PROOF_ORDER_CASES: [(&str, LogHeights); 3] = [
    ("equal Eidos and byte-pair heights", EQUAL_EIDOS_BYTE_PAIR_HEIGHTS),
    ("Eidos before ordinary AIRs", EIDOS_PRECEDES_ORDINARY_HEIGHTS),
    ("BytePairLut before Eidos", BYTE_PAIR_PRECEDES_EIDOS_HEIGHTS),
];
const SAMPLES_PTR: u32 = 1_000;
const NUM_SAMPLES: usize = 6;

fn random_coin_setup_masm() -> String {
    let cv = INITIAL_CV;
    format!(
        r#"
        push.{cv3}.{cv2}.{cv1}.{cv0}
        mem_storew_le.RANDOM_COIN_CV_PTR dropw
        padw mem_storew_le.RANDOM_COIN_OUTPUT_WORD_PTR dropw
        padw mem_storew_le.RANDOM_COIN_INPUT_BUF_PTR dropw
        padw push.RANDOM_COIN_INPUT_BUF_PTR add.4 mem_storew_le dropw
        push.0 mem_store.RANDOM_COIN_INPUT_LENGTH_PTR
        push.0 mem_store.RANDOM_COIN_OUTPUT_LENGTH_PTR
        push.0 mem_store.RANDOM_COIN_COUNTER_PTR
        "#,
        cv0 = cv[0],
        cv1 = cv[1],
        cv2 = cv[2],
        cv3 = cv[3],
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
        writeln!(heights, "push.{height} push.LOG_AIR_TRACE_LENGTHS_PTR{offset} mem_store")
            .expect("write height setup");
    }

    format!(
        r#"
        {random_coin_setup}
        {heights}
        "#,
        random_coin_setup = random_coin_setup_masm(),
    )
}

fn hook_source(log_heights: &LogHeights) -> String {
    format!(
        r#"
        use {{
            AUX_TRACE_COM_PTR, LOG_AIR_TRACE_LENGTHS_PTR,
            RANDOM_COIN_COUNTER_PTR, RANDOM_COIN_CV_PTR, RANDOM_COIN_INPUT_BUF_PTR,
            RANDOM_COIN_INPUT_LENGTH_PTR, RANDOM_COIN_OUTPUT_LENGTH_PTR, RANDOM_COIN_OUTPUT_WORD_PTR
        }} from miden::core::stark::constants
        use miden::core::stark::random_coin
        use miden::core::sys::pvm::aux_trace
        use miden::core::sys::pvm::ood_frames

        begin
            {}
            exec.ood_frames::stage_proof_order_maps
            exec.aux_trace::observe_aux_trace
            mem_load.RANDOM_COIN_INPUT_LENGTH_PTR push.4 assert_eq
            mem_load.RANDOM_COIN_OUTPUT_LENGTH_PTR assertz
            mem_load.RANDOM_COIN_COUNTER_PTR assertz
            {samples}
        end
        "#,
        setup_masm(log_heights),
        samples = (0..NUM_SAMPLES)
            .map(|i| format!("exec.random_coin::sample_felt mem_store.{}", SAMPLES_PTR + i as u32))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

fn sampled_challenges() -> (EidosChallenger, QuadFelt, QuadFelt) {
    let mut challenger = EidosChallenger::new(Word::new(INITIAL_CV.map(Felt::new_unchecked)));
    let alpha = challenger.sample_algebra_element();
    let beta = challenger.sample_algebra_element();
    (challenger, alpha, beta)
}

fn encode_message(alpha: QuadFelt, beta: QuadFelt, scale: u32, payload: &[u32]) -> QuadFelt {
    let gamma = (0..MAX_MESSAGE_WIDTH).fold(QuadFelt::ONE, |acc, _| acc * beta);
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

fn balanced_normalized_sums(correction: QuadFelt, log_heights: &[u8]) -> Vec<QuadFelt> {
    let n = log_heights.len();
    let mut sums: Vec<_> = (0..n)
        .map(|i| QuadFelt::new([Felt::from_usize(2 * i + 1), Felt::from_usize(2 * i + 2)]))
        .collect();
    // Reserve the last AIR as the balancing term in the trace-length-weighted identity.
    let weight = |i: usize| Felt::from_u64(1u64 << log_heights[i]);
    let partial: QuadFelt = (0..n - 1).map(|i| sums[i] * weight(i)).sum();
    sums[n - 1] = (-correction - partial) * weight(n - 1).inverse();
    sums
}

fn proof_ordered_normalized_sums(values: &[QuadFelt], log_heights: &[u8]) -> Vec<QuadFelt> {
    let mut order: Vec<_> = (0..log_heights.len()).collect();
    order.sort_by_key(|&i| (log_heights[i], i));
    order.into_iter().map(|i| values[i]).collect()
}

fn advice(normalized_sums: &[QuadFelt], log_heights: &[u8]) -> Vec<u64> {
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
        let (mut challenger, alpha, beta) = sampled_challenges();
        let correction = fixed_boundary_correction(alpha, beta);
        let normalized_sums = balanced_normalized_sums(correction, &log_heights);
        let advice = advice(&normalized_sums, &log_heights);

        let (hook_output, _) = build_test!(&hook_source(&log_heights), &[], &advice)
            .execute_for_output()
            .unwrap_or_else(|error| {
                panic!("{case}: PVM aux hook rejected balanced boundary: {error}")
            });
        challenger
            .observe_slice(&advice.iter().copied().map(Felt::new_unchecked).collect::<Vec<_>>());
        for i in 0..NUM_SAMPLES {
            let expected: Felt = challenger.sample_algebra_element();
            assert_eq!(
                read_memory_felt(&hook_output, SAMPLES_PTR + i as u32),
                expected,
                "{case}: sample {i}"
            );
        }
        for (i, expected) in challenger.cv().iter().enumerate() {
            assert_eq!(
                read_memory_felt(&hook_output, stark_constant("RANDOM_COIN_CV_PTR") + i as u32),
                *expected,
                "{case}: chaining value {i}"
            );
        }

        let gamma = (0..MAX_MESSAGE_WIDTH).fold(QuadFelt::ONE, |acc, _| acc * beta);
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

        // The hook absorbs the values in proof order and then scatters them, so the region the
        // constraint circuit reads must end up in the canonical numbering: `ChipletAir::all()`
        // order.
        let aux_bus_boundary_ptr = pvm_layout_const("AUX_BUS_BOUNDARY_PTR");
        assert_ne!(
            normalized_sums,
            proof_ordered_normalized_sums(&normalized_sums, &log_heights),
            "{case}: the fixture heights must induce a non-identity proof order"
        );
        for (i, value) in normalized_sums.iter().enumerate() {
            let coefficients: &[Felt] = value.as_basis_coefficients_slice();
            for (coord, expected) in coefficients.iter().enumerate() {
                assert_eq!(
                    read_memory_felt(
                        &hook_output,
                        aux_bus_boundary_ptr + 2 * i as u32 + coord as u32,
                    ),
                    *expected,
                    "{case}: canonical normalized LogUp value {i} coordinate {coord} is not at \
                     the address the circuit reads"
                );
            }
        }
        for (i, expected) in COMMITMENT.into_iter().enumerate() {
            assert_eq!(
                read_memory_felt(&hook_output, stark_constant("AUX_TRACE_COM_PTR") + i as u32),
                Felt::new_unchecked(expected),
                "{case}: aux commitment coordinate {i} mismatch"
            );
        }
    }
}

#[test]
fn pvm_fixed_boundary_preserves_caller_values_through_stack_overflow() {
    let alpha = QuadFelt::new([Felt::from_u32(11), Felt::from_u32(13)]);
    let beta = QuadFelt::new([Felt::from_u32(17), Felt::from_u32(19)]);
    let expected = fixed_boundary_correction(alpha, beta);
    let coordinates: &[Felt] = expected.as_basis_coefficients_slice();
    let mut source = String::from(
        "use miden::core::sys::pvm::fixed_boundary\n\
         use {AUX_RAND_ELEM_PTR} from miden::core::stark::constants\n\
         begin\n",
    );
    // Include the weighted sum's two slots and caller values that travel through overflow.
    for value in 1..=24 {
        writeln!(source, "push.{value}").unwrap();
    }
    source.push_str(
        "push.13.11.19.17 mem_storew_le.AUX_RAND_ELEM_PTR dropw\n\
         exec.fixed_boundary::compute_fixed_boundary_correction\n",
    );
    for coordinate in coordinates {
        writeln!(source, "push.{coordinate} assert_eq").unwrap();
    }
    for value in (1..=24).rev() {
        writeln!(source, "push.{value} assert_eq").unwrap();
    }
    source.push_str("end");
    let test = build_test!(&source);
    test.expect_stack(&[0; 16]);
    test.check_constraints();
}

#[test]
fn generated_extension_power_matches_rust_and_preserves_caller_values() {
    use miden_ace::compiler::render_masm_ext2_power;

    // Cover both relation widths, identity cases, and reuse of the retained base across bits.
    for exponent in [0, 1, 2, 3, 5, 16, 18, 31, 32, 0x8000_0000, 0xaaaa_aaaa, u32::MAX] {
        for base in [QuadFelt::ZERO, QuadFelt::new([Felt::from_u32(17), Felt::from_u32(19)])] {
            let power = render_masm_ext2_power(exponent);
            let mut source = format!(
                "use miden::core::stark::types\n\
                 proc power(base: types::QuadFelt) -> types::QuadFelt\n{power}\nend\nbegin\n"
            );
            for value in 1..=24 {
                writeln!(source, "push.{value}").unwrap();
            }
            let coordinates: &[Felt] = base.as_basis_coefficients_slice();
            writeln!(source, "push.{}.{}", coordinates[1], coordinates[0]).unwrap();
            source.push_str("exec.power\n");
            let expected = base.exp_u64(u64::from(exponent));
            let coordinates: &[Felt] = expected.as_basis_coefficients_slice();
            for coordinate in coordinates {
                writeln!(source, "push.{coordinate} assert_eq").unwrap();
            }
            for value in (1..=24).rev() {
                writeln!(source, "push.{value} assert_eq").unwrap();
            }
            source.push_str("end");
            let test = build_test!(&source);
            test.expect_stack(&[0; 16]);
            if exponent == u32::MAX && base != QuadFelt::ZERO {
                test.check_constraints();
            }
        }
    }
}

#[test]
fn pvm_aux_hook_rejects_an_unbalanced_normalized_sum() {
    let log_heights = EIDOS_PRECEDES_ORDINARY_HEIGHTS;
    let (_, alpha, beta) = sampled_challenges();
    for index in [4, 11] {
        // Cover an inner value and the last value: omitting the final word from the external
        // identity must fail even when the other eleven values balance.
        let mut normalized_sums =
            balanced_normalized_sums(fixed_boundary_correction(alpha, beta), &log_heights);
        normalized_sums[index] += QuadFelt::ONE;
        let advice = advice(&normalized_sums, &log_heights);

        let test = build_test!(&hook_source(&log_heights), &[], &advice);
        // The release package retains the assertion code but not the source message. The
        // matching balanced fixture above reaches this point successfully; changing only one
        // normalized sum therefore isolates the final fixed-boundary assertion.
        expect_assert_error_message!(test);
    }
}

/// Exercises every supported shape against Rust, including odd tails and a full final block.
#[test]
fn generated_logup_stage_matches_rust_for_every_air_count() {
    use miden_ace::{
        MAX_ORDER_AIRS,
        compiler::{MasmAuxTraceConfig, render_masm_aux_trace, render_proof_order_maps},
    };

    let mut config = MasmAuxTraceConfig {
        generated_by: "test",
        boundary_module: "miden::core::sys::pvm::layout",
        correction_module: "miden::core::sys::pvm::fixed_boundary",
        correction_procedure: "compute_fixed_boundary_correction",
        num_airs: 0,
    };
    for n in [0, 1, MAX_ORDER_AIRS + 1, usize::MAX] {
        config.num_airs = n;
        assert!(render_masm_aux_trace(&config).is_err(), "unsupported AIR count {n}");
    }
    for n in 2..=MAX_ORDER_AIRS {
        let (mut challenger, alpha, beta) = sampled_challenges();
        let correction = fixed_boundary_correction(alpha, beta);
        let heights = &EQUAL_EIDOS_BYTE_PAIR_HEIGHTS[..n];
        let sums = balanced_normalized_sums(correction, heights);
        let mut advice = advice(&sums, heights);
        challenger
            .observe_slice(&advice.iter().copied().map(Felt::new_unchecked).collect::<Vec<_>>());
        advice.extend([98765, 43210]);

        config.num_airs = n;
        let stage = render_masm_aux_trace(&config).unwrap().replace("pub proc ", "proc ");
        let maps = render_proof_order_maps(n).unwrap().replace("pub proc ", "proc ");
        let base = pvm_layout_const("AUX_BUS_BOUNDARY_PTR");
        let guards = [base - 1, base + 2 * n as u32];
        let mut source = format!(
            "{stage}\n\
             use {{PROOF_ORDER_IDS_PTR, RANDOM_COIN_CV_PTR, RANDOM_COIN_INPUT_BUF_PTR,\n\
             RANDOM_COIN_INPUT_LENGTH_PTR, RANDOM_COIN_OUTPUT_LENGTH_PTR,\n\
             RANDOM_COIN_OUTPUT_WORD_PTR, RANDOM_COIN_COUNTER_PTR}} from miden::core::stark::constants\n\
             {maps}\nbegin\n{}\nexec.stage_proof_order_maps\n",
            setup_masm(&EQUAL_EIDOS_BYTE_PAIR_HEIGHTS),
        );
        for address in guards {
            writeln!(source, "push.777 mem_store.{address}").unwrap();
        }
        for value in 1..=24 {
            writeln!(source, "push.{value}").unwrap();
        }
        source.push_str("exec.observe_aux_trace\n");
        let rejection_source = format!("{source}repeat.24 drop end end");
        writeln!(
            source,
            "mem_load.RANDOM_COIN_INPUT_LENGTH_PTR push.{} assert_eq\n\
             mem_load.RANDOM_COIN_OUTPUT_LENGTH_PTR assertz",
            (4 + 2 * n) % 8,
        )
        .unwrap();
        for address in guards {
            writeln!(source, "mem_load.{address} push.777 assert_eq").unwrap();
        }
        for (i, sum) in sums.iter().enumerate() {
            let coordinates: &[Felt] = sum.as_basis_coefficients_slice();
            for (coordinate, value) in coordinates.iter().enumerate() {
                writeln!(
                    source,
                    "mem_load.{} push.{value} assert_eq",
                    base + (2 * i + coordinate) as u32
                )
                .unwrap();
            }
        }
        // Check both the next proof field and samples spanning a challenger refill.
        source.push_str("adv_push push.98765 assert_eq adv_push push.43210 assert_eq\n");
        for _ in 0..6 {
            let expected: Felt = challenger.sample_algebra_element();
            writeln!(source, "exec.random_coin::sample_felt push.{expected} assert_eq").unwrap();
        }
        for value in (1..=24).rev() {
            writeln!(source, "push.{value} assert_eq").unwrap();
        }
        source.push_str("end");
        let test = build_test!(&source, &[], &advice);
        test.expect_stack(&[0; 16]);
        if [3, 6, MAX_ORDER_AIRS].contains(&n) {
            test.check_constraints();
        }
        // Corrupt each coordinate of the final pair, including the odd-count scalar tail.
        for coordinate in 0..2 {
            let mut corrupted = advice.clone();
            let index = 4 + 2 * n - 2 + coordinate;
            corrupted[index] =
                (Felt::new_unchecked(corrupted[index]) + Felt::ONE).as_canonical_u64();
            expect_assert_error_message!(build_test!(&rejection_source, &[], &corrupted));
        }
    }
}
