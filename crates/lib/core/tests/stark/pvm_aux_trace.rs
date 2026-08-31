//! Behavioral oracles for the PVM auxiliary-trace verifier hook.

use miden_core::{
    Felt,
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt},
};
use miden_precompiles::{CurveId, UintDomain};

use crate::helpers::read_memory_felt;

const AUX_TRACE_COM_PTR: u32 = 3_223_322_644;
const R1_PTR: u32 = 3_223_322_672;
const RANDOM_COIN_INPUT_LEN_PTR: u32 = 3_223_322_759;
const RANDOM_COIN_OUTPUT_LEN_PTR: u32 = 3_223_322_760;
const AUX_RAND_ELEM_PTR: u32 = 3_225_426_424;
const AUX_BUS_BOUNDARY_PTR: u32 = 3_225_429_504;
const BUS_GAMMA_PTR: u32 = 3_225_443_400;
const C_TOTAL_PTR: u32 = 3_225_443_404;

const INITIAL_SPONGE: [u64; 12] = [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22];
const COMMITMENT: [u64; 4] = [31, 32, 33, 34];

fn setup_masm() -> String {
    let s = INITIAL_SPONGE;
    format!(
        r#"
        push.{r1_3}.{r1_2}.{r1_1}.{r1_0}
        exec.constants::r1_ptr mem_storew_le dropw
        push.{r2_3}.{r2_2}.{r2_1}.{r2_0}
        exec.constants::r2_ptr mem_storew_le dropw
        push.{c_3}.{c_2}.{c_1}.{c_0}
        exec.constants::c_ptr mem_storew_le dropw
        push.0 exec.constants::random_coin_input_len_ptr mem_store
        push.8 exec.constants::random_coin_output_len_ptr mem_store
        "#,
        r1_0 = s[0],
        r1_1 = s[1],
        r1_2 = s[2],
        r1_3 = s[3],
        r2_0 = s[4],
        r2_1 = s[5],
        r2_2 = s[6],
        r2_3 = s[7],
        c_0 = s[8],
        c_1 = s[9],
        c_2 = s[10],
        c_3 = s[11],
    )
}

fn sampler_source() -> String {
    format!(
        r#"
        use miden::core::stark::constants
        use miden::core::stark::random_coin
        use miden::core::sys::pvm::layout

        begin
            {}
            exec.layout::aux_rand_elem_ptr
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

/// A deliberately straightforward transcript path: consume the same six advice words through
/// the public buffered word API, pairing them into three full rate blocks.
fn reference_source() -> String {
    format!(
        r#"
        use miden::core::stark::constants
        use miden::core::stark::random_coin
        use miden::core::sys::pvm::layout

        begin
            {}
            exec.layout::aux_rand_elem_ptr
            exec.random_coin::generate_aux_randomness

            padw adv_loadw
            exec.constants::aux_trace_com_ptr mem_storew_le
            exec.random_coin::observe_word
            padw adv_loadw
            exec.layout::aux_bus_boundary_ptr mem_storew_le
            exec.random_coin::observe_word_and_flush_buffer

            padw adv_loadw
            exec.layout::aux_bus_boundary_ptr add.4 mem_storew_le
            exec.random_coin::observe_word
            padw adv_loadw
            exec.layout::aux_bus_boundary_ptr add.8 mem_storew_le
            exec.random_coin::observe_word_and_flush_buffer

            padw adv_loadw
            exec.layout::aux_bus_boundary_ptr add.12 mem_storew_le
            exec.random_coin::observe_word
            padw adv_loadw
            exec.layout::aux_bus_boundary_ptr add.16 mem_storew_le
            exec.random_coin::observe_word_and_flush_buffer
        end
        "#,
        setup_masm()
    )
}

fn sampled_challenges() -> (QuadFelt, QuadFelt) {
    let (output, _) = build_test!(&sampler_source(), &[])
        .execute_for_output()
        .expect("challenge sampler must execute");
    let beta = QuadFelt::new([
        read_memory_felt(&output, AUX_RAND_ELEM_PTR),
        read_memory_felt(&output, AUX_RAND_ELEM_PTR + 1),
    ]);
    let alpha = QuadFelt::new([
        read_memory_felt(&output, AUX_RAND_ELEM_PTR + 2),
        read_memory_felt(&output, AUX_RAND_ELEM_PTR + 3),
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

fn valid_sigmas(correction: QuadFelt) -> [QuadFelt; 10] {
    let mut sigmas = core::array::from_fn(|i| {
        QuadFelt::new([Felt::from_u32(i as u32 + 1), Felt::from_u32(2 * i as u32 + 3)])
    });
    let partial = sigmas[..9].iter().copied().sum::<QuadFelt>();
    sigmas[9] = -correction - partial;
    sigmas
}

fn advice(sigmas: &[QuadFelt; 10]) -> Vec<u64> {
    COMMITMENT
        .into_iter()
        .chain(sigmas.iter().flat_map(|sigma| {
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

    for addr in R1_PTR..R1_PTR + 12 {
        assert_eq!(
            read_memory_felt(&hook_output, addr),
            read_memory_felt(&reference_output, addr),
            "transcript state differs at address {addr}"
        );
    }
    for addr in [RANDOM_COIN_INPUT_LEN_PTR, RANDOM_COIN_OUTPUT_LEN_PTR] {
        assert_eq!(
            read_memory_felt(&hook_output, addr),
            read_memory_felt(&reference_output, addr),
            "transcript counter differs at address {addr}"
        );
    }

    let gamma = (0..18).fold(QuadFelt::ONE, |acc, _| acc * beta);
    let expected_gamma: &[Felt] = gamma.as_basis_coefficients_slice();
    assert_eq!(read_memory_felt(&hook_output, BUS_GAMMA_PTR), expected_gamma[0]);
    assert_eq!(read_memory_felt(&hook_output, BUS_GAMMA_PTR + 1), expected_gamma[1]);
    assert_eq!(read_memory_felt(&hook_output, BUS_GAMMA_PTR + 2), Felt::ZERO);
    assert_eq!(read_memory_felt(&hook_output, BUS_GAMMA_PTR + 3), Felt::ZERO);

    let expected_correction: &[Felt] = correction.as_basis_coefficients_slice();
    assert_eq!(read_memory_felt(&hook_output, C_TOTAL_PTR), expected_correction[0]);
    assert_eq!(read_memory_felt(&hook_output, C_TOTAL_PTR + 1), expected_correction[1]);
    assert_eq!(read_memory_felt(&hook_output, C_TOTAL_PTR + 2), Felt::ZERO);
    assert_eq!(read_memory_felt(&hook_output, C_TOTAL_PTR + 3), Felt::ZERO);

    for (i, sigma) in sigmas.iter().enumerate() {
        let coefficients: &[Felt] = sigma.as_basis_coefficients_slice();
        for (coord, expected) in coefficients.iter().enumerate() {
            assert_eq!(
                read_memory_felt(&hook_output, AUX_BUS_BOUNDARY_PTR + 2 * i as u32 + coord as u32,),
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
    sigmas[4] += QuadFelt::ONE;
    let advice = advice(&sigmas);

    let test = build_test!(&hook_source(), &[], &advice);
    // The release package retains the assertion code but not the source message. The matching
    // balanced fixture above reaches this point successfully; changing only one sigma therefore
    // isolates the final fixed-boundary assertion.
    expect_assert_error_message!(test);
}
