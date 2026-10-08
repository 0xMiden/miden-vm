use std::vec;

use miden_air::Felt;
use miden_core::{
    ZERO,
    crypto::{dsa::falcon512_eidos::Nonce, hash::Eidos},
    events::EventName,
    field::PrimeField64,
    mast::error_code_from_msg,
    program::domain::{FALCON_PRODUCT_CHECK, FALCON_PRODUCT_CHECK_PAYLOAD_LEN},
};
use miden_core_lib::{
    CoreLibrary,
    dsa::falcon512_eidos::{self, product_check_digest},
};
use miden_crypto::hash::eidos::domains::{FALCON_HASH_TO_POINT, FALCON_PUBLIC_KEY};
use miden_processor::{
    ExecutionError, ProcessorState,
    advice::{AdviceMutation, AdviceStack},
    event::EventError,
    operation::OperationError,
};
#[cfg(feature = "arbitrary")]
use miden_utils_testing::proptest::{
    array::{uniform4, uniform8},
    collection,
    prelude::*,
};
use miden_utils_testing::{
    Test, Word,
    crypto::{
        MerkleStore,
        falcon512_eidos::{Polynomial, SecretKey},
    },
    expect_exec_error_matches,
};
use rand::{Rng, RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

/// Modulus used for Falcon512.
const M: u64 = 12289;
const M_HALF: i64 = ((M - 1) / 2) as i64;
const N: usize = 512;
const J: u64 = N as u64 * M * M;
const PRODUCT_BOUND: i64 = N as i64 * (M as i64 - 1) * M_HALF;
const SQUARE_NORM_BOUND: u64 = 34_034_726;

const PROBABILISTIC_PRODUCT_SOURCE: &str = "
    use miden::core::crypto::dsa::falcon512_eidos
    begin
        push.0
        exec.falcon512_eidos::load_h_s2_and_product
    end
";
const VERIFY_SOURCE: &str = "
    use miden::core::crypto::dsa::falcon512_eidos
    begin
        exec.falcon512_eidos::verify
    end
";
const VERIFY_FROM_MAP_SOURCE: &str = "
    use miden::core::crypto::dsa::falcon512_eidos
    begin
        exec.falcon512_eidos::move_sig_from_map_to_adv_stack
        exec.falcon512_eidos::verify
    end
";
const MOD_12289_SOURCE: &str = "
    use miden::core::crypto::dsa::falcon512_eidos
    begin
        exec.falcon512_eidos::mod_12289
    end
";

#[test]
fn falcon_advice_encodes_centered_product_and_shifted_signature() {
    let mut h = vec![0i16; N];
    h[0] = 1;
    let public_key = falcon512_eidos::PublicKey::from(Polynomial::from(&h));
    let mut s2 = vec![0i16; N];
    s2[0] = -(M_HALF as i16);
    s2[1] = -1;
    s2[N / 2] = 1;
    s2[N - 1] = M_HALF as i16;
    let nonce = Nonce::deterministic();
    let nonce_elements = nonce.to_elements();
    let signature =
        falcon512_eidos::Signature::new(nonce, public_key.clone(), Polynomial::from(&s2).into());

    // With h = 1, the unreduced product is s2 followed by 512 zero coefficients.
    let mut product = vec![Felt::ZERO; 2 * N];
    for (coefficient, &value) in product.iter_mut().zip(&s2) {
        *coefficient = field_from_signed(i64::from(value));
    }
    let shifted: Vec<_> = s2
        .iter()
        .map(|&value| Felt::from_u32((i64::from(value) + M_HALF) as u32))
        .collect();
    let digest = product_check_digest(public_key.to_commitment(), &shifted, &product);
    let advice = falcon512_eidos::encode_signature(&public_key, &signature);

    assert_eq!(advice.len(), 2 + 4 * N + nonce_elements.len());
    assert_eq!(advice[..2], [digest[1], digest[0]]);
    assert_eq!(advice[2], Felt::ONE);
    assert_eq!(advice[3..2 + N], [Felt::ZERO; N - 1]);
    assert_eq!(advice[2 + N..2 + 2 * N], shifted);
    assert_eq!(advice[2 + 2 * N..2 + 4 * N], product);
    assert_eq!(advice[2 + 4 * N..], nonce_elements);
}

#[test]
fn test_falcon512_norm_sq() {
    let source = "
        use miden::core::crypto::dsa::falcon512_eidos
        begin
            exec.falcon512_eidos::norm_sq
        end
    ";
    for value in [0, 1, M_HALF as u64, M_HALF as u64 + 1, M - 1] {
        let magnitude = value.min(M - value);
        build_test!(source, &[value]).expect_stack(&[magnitude * magnitude]);
    }
}

/// Exposes private arithmetic from the production module through test-only exports.
fn private_arithmetic_test(procedure: &str, inputs: &[u64]) -> Test {
    const MODULE: &str = concat!(
        include_str!("../../asm/crypto/dsa/falcon512_eidos.masm"),
        "\npub proc reduce_for_test(c: felt, shift: felt) -> Coefficient
            exec.reduce_shifted_sample
        end
        pub proc norm_word_for_test(pi_hi: word, pi_lo: word, c: word) -> SquaredNorm
            exec.s1_norm_sq_word
        end
        pub proc product_evaluation_for_test(
            tau_inv: [felt; 2],
            tau: [felt; 2],
            product_eval: [felt; 2],
            s2_shifted_eval: [felt; 2],
            h_eval: [felt; 2],
        )
            exec.assert_product_evaluation
        end\n"
    );
    let source = format!(
        "
        use test::falcon
        begin
            exec.falcon::{procedure}
        end
    "
    );
    build_test!(source, inputs).with_module("test::falcon", MODULE)
}

#[rstest]
#[case::valid([1, 0], true)]
#[case::wrong_first_component([2, 0], false)]
#[case::wrong_second_component([1, 1], false)]
fn falcon_product_evaluation_checks_each_component(
    #[case] product_eval: [u64; 2],
    #[case] valid: bool,
) {
    // At tau = 1, U(tau_inv) = N. Set A_h = A_s2 = 1, so A_pi must equal (1, 0).
    let tau = [1, 0];
    let s2_shifted_eval = [N as u64 * M_HALF as u64 + 1, 0];
    let mut inputs = [tau, tau, product_eval, s2_shifted_eval, [1, 0]].concat();
    inputs.extend([7, 11, 13, 17]);
    let test = private_arithmetic_test("product_evaluation_for_test", &inputs);
    if valid {
        test.expect_stack(&[7, 11, 13, 17]);
    } else {
        expect_exec_error_matches!(
            test,
            ExecutionError::OperationError {
                err: OperationError::FailedAssertion { err_code, err_msg }, ..
            } if err_code == ZERO && err_msg.is_none()
        );
    }
}

/// Full-field samples and shift endpoints must reduce as integers without wrapping modulo Q.
#[test]
fn test_falcon512_reduce_shifted_sample_boundaries() {
    let cases = [
        (0, 1),
        (0, 2 * J - 1),
        ((1 << 32) - 1, 1),
        (1 << 32, 2 * J - 1),
        ((1 << 63) - 1, J),
        (1 << 63, J),
        (Felt::ORDER_U64 - 1, 1),
        (Felt::ORDER_U64 - 1, 2 * J - 1),
        (Felt::ORDER_U64 - 1, J + M_HALF as u64 - 2 * PRODUCT_BOUND as u64),
        (Felt::ORDER_U64 - 1, J + M_HALF as u64 + 2 * PRODUCT_BOUND as u64),
    ];

    for (c, shift) in cases {
        let expected = ((u128::from(c) + u128::from(shift)) % u128::from(M)) as u64;
        private_arithmetic_test("reduce_for_test", &[c, shift, 7, 11, 13, 17])
            .expect_stack(&[expected, 7, 11, 13, 17]);
    }
}

fn field_from_signed(value: i64) -> Felt {
    let magnitude = Felt::new_unchecked(value.unsigned_abs());
    if value < 0 { -magnitude } else { magnitude }
}

#[cfg(feature = "arbitrary")]
proptest! {
    #[test]
    fn reduce_shifted_sample_proptest(
        c in 0..Felt::ORDER_U64,
        shift in 1..2 * J,
    ) {
        let expected = ((u128::from(c) + u128::from(shift)) % u128::from(M)) as u64;
        private_arithmetic_test("reduce_for_test", &[c, shift, 7, 11, 13, 17])
            .prop_expect_stack(&[expected, 7, 11, 13, 17])?;
    }

    #[test]
    fn s1_norm_sq_word_proptest(
        c in uniform4(prop_oneof![Just(0), Just(Felt::ORDER_U64 - 1), 0..Felt::ORDER_U64]),
        pi_lo in uniform4(prop_oneof![Just(-PRODUCT_BOUND), Just(PRODUCT_BOUND),
            -PRODUCT_BOUND..=PRODUCT_BOUND]),
        pi_hi in uniform4(prop_oneof![Just(-PRODUCT_BOUND), Just(PRODUCT_BOUND),
            -PRODUCT_BOUND..=PRODUCT_BOUND]),
        tail in uniform4(0..Felt::ORDER_U64),
    ) {
        let expected: u64 = (0..4).map(|i| {
            let value = c[i] as i128 + pi_hi[i] as i128 - pi_lo[i] as i128;
            centered_residue(value).unsigned_abs().pow(2)
        }).sum();
        let inputs: Vec<_> = pi_hi.into_iter().chain(pi_lo)
            .map(|value| field_from_signed(value).as_canonical_u64())
            .chain(c).chain(tail).collect();
        let expected: Vec<_> = [expected].into_iter().chain(tail).collect();
        private_arithmetic_test("norm_word_for_test", &inputs).prop_expect_stack(&expected)?;
    }

    /// A nonzero monomial error cannot vanish at a nonzero challenge, even after rehashing.
    #[test]
    fn falcon_product_identity_proptest(
        h in collection::vec(0u32..M as u32, N),
        s2 in collection::vec(0u32..M as u32, N),
        index in 0..2 * N,
        delta in 1..Felt::ORDER_U64,
    ) {
        let h: Vec<_> = h.into_iter().map(Felt::from_u32).collect();
        let s2: Vec<_> = s2.into_iter().map(Felt::from_u32).collect();
        let mut pi = mul_modulo_p_shifted(&h, &s2);
        product_test(&h, &s2, &pi).prop_expect_stack(&[])?;
        pi[index] += Felt::new_unchecked(delta);
        let result = product_test(&h, &s2, &pi).execute().map(|_| ());
        prop_assert!(matches!(&result,
            Err(ExecutionError::OperationError {
                err: OperationError::FailedAssertion { err_code, .. }, ..
            }) if *err_code == ZERO
        ), "expected product identity rejection, got {result:?}");
    }

    /// Unit monomials exercise negacyclic wraparound while allowing the exact norm to be chosen.
    #[test]
    fn falcon_verify_norm_proptest(
        s1 in prop_oneof![collection::vec(-20i64..=20, N),
            collection::vec(-450i64..=450, N), collection::vec(-M_HALF..=M_HALF, N)],
        degree in prop_oneof![Just(0), Just(N - 1), 0..N],
        negative in any::<bool>(),
        message in uniform4(0..Felt::ORDER_U64),
        nonce in uniform8(0..(1u64 << 40)),
    ) {
        let message = Word::new(message.map(Felt::new_unchecked));
        let nonce = nonce.map(Felt::new_unchecked);
        let test = norm_test(&s1, degree, if negative { -1 } else { 1 }, message, nonce);
        let norm = 1 + s1.iter().map(|c| c.unsigned_abs().pow(2)).sum::<u64>();
        if norm < SQUARE_NORM_BOUND {
            test.prop_expect_stack(&[])?;
        } else {
            let result = test.execute().map(|_| ());
            if u32::try_from(norm).is_ok() {
                prop_assert!(matches!(&result, Err(ExecutionError::OperationError {
                    err: OperationError::FailedAssertion { err_code, .. }, ..
                }) if *err_code == error_code_from_msg("comparison failed: norm bound")),
                    "expected norm bound rejection for {norm}, got {result:?}");
            } else {
                prop_assert!(matches!(&result, Err(ExecutionError::OperationError {
                    err: OperationError::NotU32Values { .. }, ..
                })), "expected u32 rejection for {norm}, got {result:?}");
            }
        }
    }
}

/// The complete product check must agree with the native transcript and its fixed digest.
#[test]
fn falcon_product_transcript_matches_host() {
    let h: Vec<_> = (0..N).map(|i| Felt::from_u32(i as u32)).collect();
    let s2: Vec<_> = (0..N).map(|i| Felt::from_u32((i + 3) as u32)).collect();
    let pi = mul_modulo_p_shifted(&h, &s2);
    let public_key = Eidos::hash_elements_in_domain(&h, FALCON_PUBLIC_KEY);
    let expected = product_check_digest(public_key, &s2, &pi);

    // Scalar Eidos reference for h[i] = i and shifted s2[i] = i + 3.
    assert_eq!(
        expected,
        Word::new(
            [
                4180249070640490373,
                5710444900508321502,
                8063547575669664642,
                958734707045704282,
            ]
            .map(Felt::new_unchecked)
        )
    );

    let mut payload = Vec::with_capacity(FALCON_PRODUCT_CHECK_PAYLOAD_LEN as usize);
    payload.extend_from_slice(public_key.as_elements());
    payload.extend([Felt::ZERO; 4]);
    payload.extend_from_slice(&s2);
    payload.extend_from_slice(&pi);
    assert_eq!(expected, Eidos::hash_elements_in_domain(&payload, FALCON_PRODUCT_CHECK));
    product_test(&h, &s2, &pi).expect_stack(&[]);
}

#[test]
fn test_falcon512_probabilistic_product() {
    let (h, s2, pi) = product_polynomials(0);
    product_test(&h, &s2, &pi).expect_stack(&[]);
}

/// Recompute the challenge after changing the product, so rejection depends on the identity check.
#[rstest]
#[case::constant(0)]
#[case::degree_1023(2 * N - 1)]
fn test_falcon512_probabilistic_product_failure(#[case] index: usize) {
    let (h, s2, mut pi) = product_polynomials(1);
    pi[index] += Felt::ONE;
    let test = product_test(&h, &s2, &pi);
    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError {
            err: OperationError::FailedAssertion { err_code, err_msg }, ..
        } if err_code == ZERO && err_msg.is_none()
    );
}

/// The claimed product must use s2'_i - M_HALF, even when the transcript commits to h * s2'.
#[test]
fn test_falcon512_probabilistic_product_rejects_unshifted_encoding() {
    let (h, s2, _) = product_polynomials(2);
    let mut pi = [0u64; 2 * N];
    for i in 0..N {
        for j in 0..N {
            pi[i + j] += h[i].as_canonical_u64() * s2[j].as_canonical_u64();
        }
    }
    let test = product_test(&h, &s2, &pi.map(Felt::new_unchecked));
    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError {
            err: OperationError::FailedAssertion { err_code, err_msg }, ..
        } if err_code == ZERO && err_msg.is_none()
    );
}

/// Range checks must reject malformed coefficients even when their commitments match the advice.
#[rstest]
#[case::public_key(true)]
#[case::signature(false)]
fn falcon_product_rejects_out_of_range_coefficient(#[case] in_h: bool) {
    let (h, s2, pi) = product_polynomials(1);
    // Check every adv_pipe lane in the first and last blocks, with matching commitments.
    for index in (0..8).chain(N - 8..N) {
        for value in [M, u32::MAX as u64, 1 << 32, Felt::ORDER_U64 - 1] {
            let (mut h, mut s2) = (h.clone(), s2.clone());
            if in_h {
                h[index] = Felt::new_unchecked(value);
            } else {
                s2[index] = Felt::new_unchecked(value);
            }
            let result = product_test(&h, &s2, &pi).execute().map(|_| ());
            let rejected = if u32::try_from(value).is_ok() {
                matches!(&result, Err(ExecutionError::OperationError {
                    err: OperationError::FailedAssertion { err_code, .. }, ..
                }) if *err_code == error_code_from_msg("comparison failed: modulus"))
            } else {
                matches!(
                    &result,
                    Err(ExecutionError::OperationError {
                        err: OperationError::NotU32Values { .. },
                        ..
                    })
                )
            };
            assert!(
                rejected,
                "range check for in_h={in_h}, index={index}, value={value}: {result:?}"
            );
        }
    }
}

/// An honest product holds at every point, so only the transcript check rejects a different tau.
#[test]
fn falcon_product_binds_each_challenge_limb() {
    let (h, s2, pi) = product_polynomials(7);
    let (public_key, advice) = product_advice(&h, &s2, &pi);
    for limb in 0..2 {
        let mut advice: Vec<_> = advice.iter().map(Felt::as_canonical_u64).collect();
        advice[limb] += 1;
        let inputs = stack_from_words(&[public_key]);
        let test = build_test!(PROBABILISTIC_PRODUCT_SOURCE, &inputs, &advice);
        expect_exec_error_matches!(
            test,
            ExecutionError::OperationError {
                err: OperationError::FailedAssertion { err_code, .. }, ..
            } if err_code == error_code_from_msg("comparison failed: tau")
        );
    }
}

#[test]
fn test_move_sig_to_adv_stack() {
    let (public_key, message, advice) = signature_fixture();
    verify_from_map_test(public_key, message, advice).expect_stack(&[]);
}

#[test]
fn falcon_execution() {
    let (public_key, message, advice) = signature_fixture();
    let preserved = [7, 11, 13, 17, 19, 23, 29, 31];
    let mut inputs = stack_from_words(&[public_key, message]);
    inputs.extend(preserved);
    verify_test(public_key, message, &advice)
        .with_stack_inputs(inputs)
        .expect_stack(&preserved);
}

#[test]
fn falcon_verify_binds_each_public_key_limb() {
    let (public_key, message, advice) = signature_fixture();
    for limb in 0..4 {
        let mut wrong_key = public_key;
        wrong_key[limb] += Felt::ONE;
        let test = verify_test(wrong_key, message, &advice);
        expect_exec_error_matches!(
            test,
            ExecutionError::OperationError {
                err: OperationError::FailedAssertion { err_code, .. }, ..
            } if err_code == error_code_from_msg("comparison failed: public key")
        );
    }
}

#[rstest]
#[case::small(100_000)]
#[case::high_limb(1 << 33)]
#[case::distinct_limbs(0x0123_4567_89ab_cdef)]
#[case::maximum(u64::MAX)]
fn test_mod_12289(#[case] dividend: u64) {
    let inputs = [dividend & 0xffff_ffff, dividend >> 32, 17, 31];
    build_test!(MOD_12289_SOURCE, &inputs).expect_stack(&[dividend % M, 17, 31]);
}

#[test]
fn test_mod_12289_after_u32split() {
    let source = "
        use miden::core::crypto::dsa::falcon512_eidos

        begin
            u32split
            exec.falcon512_eidos::mod_12289
        end
    ";

    let dividend = Felt::ORDER_U64 - 1;
    build_test!(source, &[dividend]).expect_stack(&[dividend % M]);
}

/// Supplies q and r without installing the core library's honest division handler.
fn forged_division_test(dividend: u64, quotient: u64, remainder: u64) -> Test {
    const FALCON_DIV: EventName =
        EventName::new("miden::core::crypto::dsa::falcon512_eidos::falcon_div");
    let inputs = [dividend & 0xffff_ffff, dividend >> 32];
    miden_utils_testing::build_test_by_mode!(false, MOD_12289_SOURCE, &inputs)
        .with_library(CoreLibrary::default().package())
        .with_event_handler(FALCON_DIV, move |_process: &ProcessorState| {
            let mut advice = AdviceStack::new();
            advice.append_elements([
                Felt::new_unchecked(quotient >> 32),
                Felt::new_unchecked(quotient & 0xffff_ffff),
                Felt::new_unchecked(remainder),
            ]);
            Ok::<_, EventError>(vec![AdviceMutation::extend_advice_stack(advice)])
        })
}

#[rstest]
#[case(100_000)]
#[case(2 << 32)]
#[case(12_290)]
#[case((1 << 32) + 1)]
#[case(0xffff_ffff_ffff_fffe)]
fn test_mod_12289_rejects_forged_remainder_zero(#[case] dividend: u64) {
    // M * q = dividend modulo 2^64, but not as an integer with remainder zero.
    const M_INV: u64 = 15010777177727684609;
    assert_ne!(dividend % M, 0);
    let test = forged_division_test(dividend, dividend.wrapping_mul(M_INV), 0);
    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError {
            err: OperationError::FailedAssertion { err_code, err_msg }, ..
        } if err_code == error_code_from_msg("comparison failed: quotient overflow")
            && err_msg.is_none()
    );
}

#[test]
fn test_mod_12289_rejects_forged_addition_overflow() {
    // M * q fits in u64, but M * q + r = 2^64, whose wrapped value is the supplied dividend.
    let quotient = u64::MAX / M;
    let remainder = 5_664;
    let dividend = M.wrapping_mul(quotient).wrapping_add(remainder);
    let test = forged_division_test(dividend, quotient, remainder);
    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError {
            err: OperationError::FailedAssertion { err_code, err_msg }, ..
        } if err_code == error_code_from_msg("comparison failed: addition overflow")
            && err_msg.is_none()
    );
}

#[test]
fn test_mod_12289_rejects_non_u32_remainder_advice() {
    let test = forged_division_test(100_000, 100_000 / M, Felt::ORDER_U64 - 1);
    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError {
            err: OperationError::NotU32Values { values }, ..
        } if values.iter().any(|value| value.as_canonical_u64() == Felt::ORDER_U64 - 1)
    );
}

#[test]
fn falcon_trace_constraints() {
    let (public_key, message, advice) = signature_fixture();
    verify_test(public_key, message, &advice).check_constraints();
}

#[test]
fn falcon_prove_verify() {
    let (public_key, message, advice) = signature_fixture();
    verify_test(public_key, message, &advice)
        .prove_and_verify(stack_from_words(&[public_key, message]), false);
}

/// Corrupts the boundaries of each advice region and sampled interior positions.
/// The honest stream must accept, and each corrupted stream must reject.
#[test]
fn falcon_verify_rejects_corrupted_signature_advice() {
    let (public_key, message, signature) = signature_fixture();
    // [tau (2), h (512), s2 (512), pi (1024), nonce (8)]
    assert_eq!(signature.len(), 2058);
    let run = |advice| verify_from_map_test(public_key, message, advice).execute();
    run(signature.clone()).expect("honest control must accept");

    // region boundaries: tau, first/last of h, s2, pi, and the nonce
    let mut targets = vec![0, 1, 2, 513, 514, 1025, 1026, 2049, 2050, 2057];
    let mut sample_rng = ChaCha20Rng::from_seed([3; 32]);
    for _ in 0..10 {
        targets.push(sample_rng.random_range(0..signature.len()));
    }

    for &idx in &targets {
        let deltas = [Felt::new_unchecked(1), Felt::new_unchecked(sample_rng.random_range(2..M))];
        for delta in deltas {
            let mut corrupted = signature.clone();
            corrupted[idx] += delta;
            assert!(
                run(corrupted).is_err(),
                "corrupted advice element {idx} (delta {delta}) was accepted",
            );
        }
    }
}

/// Checks the shifted coefficient decoding and accumulated norm against an integer sum.
#[test]
fn test_falcon512_compute_s2_norm_sq() {
    let source = "
    use miden::core::crypto::dsa::falcon512_eidos

    begin
        push.1000 padw padw padw
        repeat.64
            adv_pipe
        end
        dropw dropw dropw drop
        push.1000
        exec.falcon512_eidos::compute_s2_norm_sq
        # the operand stack is 16 elements deep on entry, and the norm adds one more, so
        # discard a padding element to leave a result the harness can read back
        swap drop
    end
    ";

    let mut rng = ChaCha20Rng::from_seed([17; 32]);
    let coefficients: Vec<u64> = (0..N).map(|_| rng.random_range(0..M)).collect();
    let expected: u64 = coefficients
        .iter()
        .map(|&c| {
            let centered = c as i64 - M_HALF;
            (centered * centered) as u64
        })
        .sum();

    let test = build_test!(source, &[], &coefficients);
    test.expect_stack(&[expected]);
}

/// Checks the verifier's fused hash-to-point and norm computation against native Eidos samples
/// and an integer norm calculation, including signed product coefficients at the convolution bound.
#[rstest]
#[case::zero_product(false)]
#[case::signed_product(true)]
fn falcon_hash_to_point_s1_norm_matches_eidos(#[case] signed_product: bool) {
    let source = "
    use miden::core::crypto::dsa::falcon512_eidos

    begin
        push.1000 padw padw padw
        repeat.128
            adv_pipe
        end
        dropw dropw dropw drop
        push.1000
        exec.falcon512_eidos::hash_to_point_s1_norm_sq
    end
    ";

    let message = Word::from([13, 21, 34, 55].map(Felt::from_u32));
    let nonce = Nonce::deterministic().to_elements();
    let c = hash_to_point_samples(&message, &nonce);
    let pi = if signed_product {
        let mut rng = ChaCha20Rng::from_seed([18; 32]);
        let mut pi: Vec<i64> =
            (0..2 * N).map(|_| rng.random_range(-PRODUCT_BOUND..=PRODUCT_BOUND)).collect();
        pi[0] = -PRODUCT_BOUND;
        pi[N] = PRODUCT_BOUND;
        pi[1] = PRODUCT_BOUND;
        pi[N + 1] = -PRODUCT_BOUND;
        pi
    } else {
        vec![0; 2 * N]
    };

    let expected: u64 = (0..N)
        .map(|i| {
            let value = c[i].as_canonical_u64() as i128 + pi[N + i] as i128 - pi[i] as i128;
            centered_residue(value).unsigned_abs().pow(2)
        })
        .sum();

    let advice: Vec<_> = pi
        .into_iter()
        .map(|value| field_from_signed(value).as_canonical_u64())
        .collect();

    let preserved = [7, 11, 13, 17];
    let mut op_stack = stack_from_words(&[message]);
    op_stack.extend(nonce.iter().map(Felt::as_canonical_u64));
    op_stack.extend(preserved);
    let test = build_test!(source, &op_stack, &advice);
    test.expect_stack(&[expected, preserved[0], preserved[1], preserved[2], preserved[3]]);
}

/// An adversary who could choose the evaluation point would be able to prove a false product:
/// adding a multiple of `(x - t)` to the product leaves its value at `t` unchanged while
/// changing the polynomial. The verifier must reject a supplied point that differs from its
/// Fiat-Shamir challenge.
#[test]
fn test_falcon512_probabilistic_product_rejects_chosen_evaluation_point() {
    let (h, s2, mut pi) = product_polynomials(11);
    let t = Felt::from_u32(7);
    let scale = Felt::from_u32(3);
    pi[0] -= scale * t;
    pi[1] += scale;

    let (public_key, mut advice) = product_advice(&h, &s2, &pi);
    advice[..2].copy_from_slice(&[Felt::ZERO, t]);
    let inputs = stack_from_words(&[public_key]);
    let advice: Vec<_> = advice.iter().map(Felt::as_canonical_u64).collect();
    let test = build_test!(PROBABILISTIC_PRODUCT_SOURCE, &inputs, &advice);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError {
            err: OperationError::FailedAssertion { err_code, err_msg }, ..
        }
        if err_code == error_code_from_msg("comparison failed: tau") && err_msg.is_none()
    );
}

/// The strict norm bound must apply at the first word, across word boundaries, and at the end.
#[rstest]
#[case::first_word(0, 1, 1)]
#[case::word_boundary(3, 4, -1)]
#[case::last_word(510, 511, 1)]
fn falcon_verify_norm_boundary(#[case] first: usize, #[case] second: usize, #[case] sign: i64) {
    // 150^2 + 5832^2 + ||1||^2 = SQUARE_NORM_BOUND - 1.
    norm_boundary_test(&[(first, sign * 150), (second, 5832)]).check_constraints();

    // 1026^2 + 5743^2 + ||1||^2 = SQUARE_NORM_BOUND.
    let test = norm_boundary_test(&[(first, sign * 1026), (second, 5743)]);
    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError {
            err: OperationError::FailedAssertion { err_code, err_msg }, ..
        } if err_code == error_code_from_msg("comparison failed: norm bound")
            && err_msg.is_none()
    );
}

/// A consistent product with a norm above 2^32 must fail the u32 guard before the norm comparison.
#[test]
fn falcon_verify_rejects_high_norm_witness() {
    let (h, s2, pi) = product_polynomials(42);
    let (public_key, mut advice) = product_advice(&h, &s2, &pi);
    advice.extend((0..8).map(Felt::from_u32));
    let test = verify_test(public_key, Word::default(), &advice);
    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError {
            err: OperationError::NotU32Values { .. },
            ..
        }
    );
}

// HELPERS
// ================================================================================================

fn signature_fixture() -> (Word, Word, Vec<Felt>) {
    let mut rng = ChaCha20Rng::from_seed([4; 32]);
    let secret_key = SecretKey::with_rng(&mut rng);
    let message = rng.random();
    let advice = falcon512_eidos::sign(&secret_key, message).expect("failed to sign message");
    (secret_key.public_key().to_commitment(), message, advice)
}

fn verify_test(public_key: Word, message: Word, advice: &[Felt]) -> Test {
    let inputs = stack_from_words(&[public_key, message]);
    let advice: Vec<_> = advice.iter().map(Felt::as_canonical_u64).collect();
    build_test!(VERIFY_SOURCE, &inputs, &advice)
}

fn verify_from_map_test(public_key: Word, message: Word, advice: Vec<Felt>) -> Test {
    let key = Eidos::hash_elements(Word::words_as_elements(&[public_key, message]));
    let inputs = stack_from_words(&[public_key, message]);
    build_debug_test!(VERIFY_FROM_MAP_SOURCE, &inputs, &[], MerkleStore::new(), [(key, advice)])
}

fn random_coefficients_with_rng<R: Rng>(rng: &mut R) -> Vec<Felt> {
    (0..N).map(|_| Felt::new_unchecked(rng.random_range(0..M))).collect()
}

fn product_polynomials(seed: u8) -> (Vec<Felt>, Vec<Felt>, [Felt; 2 * N]) {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let h = random_coefficients_with_rng(&mut rng);
    let s2 = random_coefficients_with_rng(&mut rng);
    let pi = mul_modulo_p_shifted(&h, &s2);
    (h, s2, pi)
}

/// Integer convolution of h with s2'_i - M_HALF, encoded as Miden field elements.
fn mul_modulo_p_shifted(h: &[Felt], s2_shifted: &[Felt]) -> [Felt; 2 * N] {
    let mut product = [0i64; 2 * N];
    for i in 0..N {
        for j in 0..N {
            product[i + j] +=
                h[i].as_canonical_u64() as i64 * (s2_shifted[j].as_canonical_u64() as i64 - M_HALF);
        }
    }
    product.map(field_from_signed)
}

/// Builds commitments from the supplied polynomials, including deliberately malformed values.
fn product_advice(h: &[Felt], s2: &[Felt], pi: &[Felt]) -> (Word, Vec<Felt>) {
    let public_key = Eidos::hash_elements_in_domain(h, FALCON_PUBLIC_KEY);
    let digest = product_check_digest(public_key, s2, pi);
    let advice = [digest[1], digest[0]]
        .into_iter()
        .chain(h.iter().chain(s2).chain(pi).copied())
        .collect();
    (public_key, advice)
}

fn product_test(h: &[Felt], s2: &[Felt], pi: &[Felt]) -> Test {
    let (public_key, advice) = product_advice(h, s2, pi);
    let inputs = stack_from_words(&[public_key]);
    let advice: Vec<_> = advice.iter().map(Felt::as_canonical_u64).collect();
    build_test!(PROBABILISTIC_PRODUCT_SOURCE, &inputs, &advice)
}

/// Builds inputs in stack order, with the first word on top.
fn stack_from_words(words: &[Word]) -> Vec<u64> {
    words.iter().flat_map(|word| word.iter().map(Felt::as_canonical_u64)).collect()
}

fn norm_boundary_test(target_s1: &[(usize, i64)]) -> Test {
    let mut s1 = [0i64; N];
    for &(index, coefficient) in target_s1 {
        assert!(index < N);
        assert!(coefficient.abs() <= M_HALF);
        s1[index] = coefficient;
    }

    let s1_norm: u64 = s1.iter().map(|coefficient| coefficient.unsigned_abs().pow(2)).sum();
    assert!(s1_norm < SQUARE_NORM_BOUND);
    let nonce = std::array::from_fn(|i| Felt::from_u32(i as u32));
    norm_test(&s1, 0, 1, Word::default(), nonce)
}

/// Chooses h so that c - h * s2 equals the supplied s1 in Z_M[x]/(x^512 + 1), with
/// s2 = sign * x^degree. The integer convolution is pi[i + degree] = sign * h[i].
fn norm_test(s1: &[i64], degree: usize, sign: i64, message: Word, nonce: [Felt; 8]) -> Test {
    assert_eq!(s1.len(), N);
    assert!(sign == -1 || sign == 1);
    let c = hash_to_point_samples(&message, &nonce);
    let h: Vec<_> = (0..N)
        .map(|i| {
            let k = (i + degree) % N;
            let value = c[k].as_canonical_u64() as i128 - s1[k] as i128;
            let wrap_sign = if i + degree >= N { -1 } else { 1 };
            Felt::new_unchecked((value * (sign * wrap_sign) as i128).rem_euclid(M as i128) as u64)
        })
        .collect();

    let mut s2_shifted = vec![Felt::new_unchecked(M_HALF as u64); N];
    s2_shifted[degree] = Felt::new_unchecked((M_HALF + sign) as u64);
    let mut pi = [Felt::ZERO; 2 * N];
    for (i, coefficient) in h.iter().enumerate() {
        pi[i + degree] = field_from_signed(sign * coefficient.as_canonical_u64() as i64);
    }

    let (public_key, mut advice) = product_advice(&h, &s2_shifted, &pi);
    advice.extend(nonce);
    verify_test(public_key, message, &advice)
}

fn centered_residue(value: i128) -> i64 {
    let residue = value.rem_euclid(M as i128) as i64;
    if residue > M_HALF { residue - M as i64 } else { residue }
}

/// Computes native Eidos samples for the fused norm reference and controlled verifier witnesses.
fn hash_to_point_samples(message: &Word, nonce: &[Felt; 8]) -> Vec<Felt> {
    let mut cv = Eidos::init_chaining_word(FALCON_HASH_TO_POINT, 0);
    cv = Eidos::compress(cv, *nonce);
    let mut block = [ZERO; 8];
    block[..4].copy_from_slice(message.as_elements());
    let seed = Eidos::compress(cv, block);

    let mut block = [ZERO; 8];
    let mut coefficients = Vec::with_capacity(N);
    for counter in 0..128 {
        block[0] = Felt::from_u32(counter);
        coefficients.extend_from_slice(Eidos::compress(seed, block).as_slice());
    }
    coefficients
}
