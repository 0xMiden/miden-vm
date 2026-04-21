use std::{sync::Arc, vec};

use miden_air::Felt;
use miden_assembly::Assembler;
use miden_core::{
    ZERO,
    events::EventName,
    field::PrimeField64,
    serde::{Deserializable, Serializable},
};
use miden_core_lib::{CoreLibrary, dsa::falcon512_poseidon2};
use miden_processor::{
    DefaultHost, ExecutionError, FastProcessor, ProcessorState, Program, StackInputs,
    advice::{AdviceInputs, AdviceMutation},
    crypto::random::RandomCoin,
    event::EventError,
    operation::OperationError,
};
use miden_utils_testing::{
    AdviceStackBuilder, Word,
    crypto::{
        MerkleStore, Poseidon2,
        falcon512_poseidon2::{Polynomial, SecretKey},
    },
    expect_exec_error_matches,
    proptest::proptest,
    rand::random_word,
};
use rand::{Rng, SeedableRng, rng};
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

/// Modulus used for Falcon512-Poseidon2.
const M: u64 = 12289;
const Q: u64 = (M - 1) / 2;
const N: usize = 512;
const J: u64 = (N * M as usize * M as usize) as u64;

const PROBABILISTIC_PRODUCT_SOURCE: &str = "
    use miden::core::crypto::dsa::falcon512_poseidon2

    begin
        #=> [PK, ...]
        push.0
        #=> [h_ptr, PK, ...]

        exec.falcon512_poseidon2::load_h_s2_and_product
        #=> [...]
    end
    ";

/// Event ID for pushing a Falcon signature to the advice stack.
/// This event is used for testing purposes only.
const EVENT_FALCON_SIG_TO_STACK: EventName = EventName::new("test::falcon::sig_to_stack");

/// Event handler which pushes values onto the advice stack which are required for verification
/// of a DSA in Miden VM.
///
/// Inputs:
///   Operand stack: [event_id, PK, MSG, ...]
///   Advice stack: \[ SIGNATURE \]
///
/// Outputs:
///   Advice stack: [...]
///
/// Where:
/// - PK is the digest of an expanded public.
/// - MSG is the digest of the message to be signed.
/// - SIGNATURE is the signature being verified.
///
/// The advice provider is expected to contain the private key associated to the public key PK.
pub fn push_falcon_signature(process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
    let pub_key = process.get_stack_word(1);
    let msg = process.get_stack_word(5);

    let pk_sk_felts = process
        .advice_provider()
        .get_mapped_values(&pub_key)
        .ok_or(FalconError::NoSecretKey { key: pub_key })?;

    // Convert felts back to bytes (each felt was a single byte stored as u64)
    let sk_bytes: Vec<u8> = pk_sk_felts.iter().map(|f| f.as_canonical_u64() as u8).collect();

    // Reconstruct SecretKey from bytes
    let sk = SecretKey::read_from_bytes(&sk_bytes)
        .map_err(|_| FalconError::MalformedSignatureKey { key_type: "Poseidon2 Falcon512" })?;

    let signature_result = falcon512_poseidon2::sign(&sk, msg)
        .ok_or(FalconError::MalformedSignatureKey { key_type: "Poseidon2 Falcon512" })?;

    Ok(vec![AdviceMutation::extend_stack(signature_result)])
}

// EVENT ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum FalconError {
    #[error("public key {} not present in the event handler", .key.to_hex())]
    NoSecretKey { key: Word },
    #[error("malformed signature key: {key_type}")]
    MalformedSignatureKey { key_type: &'static str },
}

#[test]
fn test_falcon512_norm_sq() {
    let source = "
    use miden::core::crypto::dsa::falcon512_poseidon2

    begin
        exec.falcon512_poseidon2::norm_sq
    end
    ";

    // normalize(e) = e^2 - phi * (2*M*e - M^2) where phi := (e > (M - 1)/2)
    let upper = rng().random_range(Q + 1..M);
    let test_upper = build_test!(source, &[upper]);
    test_upper.expect_stack(&[(M - upper) * (M - upper)]);

    let lower = rng().random_range(0..=Q);
    let test_lower = build_test!(source, &[lower]);
    test_lower.expect_stack(&[lower * lower])
}

#[test]
fn test_falcon512_diff_mod_m() {
    let source = "
    use miden::core::crypto::dsa::falcon512_poseidon2

    begin
        exec.falcon512_poseidon2::diff_mod_M
    end
    ";
    let v = Felt::ORDER_U64 - 1;
    let (v_lo, v_hi) = (v as u32, v >> 32);

    // test largest possible value given v
    let w = J - 1;
    let u = 0;
    let test1 = build_test!(source, &[u, w + J, v_hi, v_lo as u64]);

    // Calculating (v - (u + (- w % M) % M) % M) should be the same as (v + w + J - u) % M.
    let expanded_answer = (v as i128
        - ((u as i64 + -(w as i64).rem_euclid(M as i64)).rem_euclid(M as i64) as i128))
        .rem_euclid(M as i128);
    let simplified_answer = (v as i128 + w as i128 + J as i128 - u as i128).rem_euclid(M as i128);
    assert_eq!(expanded_answer, simplified_answer);

    test1.expect_stack(&[simplified_answer as u64]);

    // test smallest possible value given v
    let w = 0;
    let u = J - 1;
    let test2 = build_test!(source, &[u, w + J, v_hi, v_lo as u64]);

    // Calculating (v - (u + (- w % M) % M) % M) should be the same as (v + w + J - u) % M.
    let expanded_answer = (v as i128
        - ((u as i64 + -(w as i64).rem_euclid(M as i64)).rem_euclid(M as i64) as i128))
        .rem_euclid(M as i128);
    let simplified_answer = (v as i128 + w as i128 + J as i128 - u as i128).rem_euclid(M as i128);
    assert_eq!(expanded_answer, simplified_answer);

    test2.expect_stack(&[simplified_answer as u64]);
}

proptest! {
    #[test]
    fn diff_mod_m_proptest(v in 0..Felt::ORDER_U64, w in 0..J, u in 0..J) {

          let source = "
    use miden::core::crypto::dsa::falcon512_poseidon2

    begin
        exec.falcon512_poseidon2::diff_mod_M
    end
    ";

    let (v_lo, v_hi) = (v as u32, v >> 32);
    let test1 = build_test!(source, &[u, w + J, v_hi, v_lo as u64]);

    // Calculating (v - (u + (- w % M) % M) % M) should be the same as (v + w + J - u) % M.
    let expanded_answer = (v as i128
        - ((u as i64 + -(w as i64).rem_euclid(M as i64)).rem_euclid(M as i64) as i128))
    .rem_euclid(M as i128);
    let simplified_answer = (v as i128 + w as i128 + J as i128 - u as i128).rem_euclid(M as i128);
    assert_eq!(expanded_answer, simplified_answer);

    test1.prop_expect_stack(&[simplified_answer as u64])?;
    }

}

#[test]
fn test_falcon512_probabilistic_product_deterministic() {
    // Use a fixed seed to make the test deterministic
    use miden_crypto::rand::RandomCoin;
    let seed = Word::default();
    let mut rng = RandomCoin::new(seed);

    // Generate deterministic coefficients
    let mut h_coeffs = Vec::new();
    let mut s2_coeffs = Vec::new();
    for _i in 0..N {
        h_coeffs.push(Felt::new_unchecked(rng.random_range(0..M)));
        s2_coeffs.push(Felt::new_unchecked(rng.random_range(0..M)));
    }

    let h: Polynomial<Felt> = Polynomial::new(h_coeffs);
    let s2: Polynomial<Felt> = Polynomial::new(s2_coeffs);
    let (operand_stack, advice_stack): (Vec<u64>, Vec<u64>) =
        generate_data_probabilistic_product_test(h, s2, false);

    let test = build_test!(PROBABILISTIC_PRODUCT_SOURCE, &operand_stack, &advice_stack);
    let expected_stack = &[];
    test.expect_stack(expected_stack);
}

#[test]
fn test_falcon512_probabilistic_product() {
    // create two random polynomials and generate the input operand stack and advice stack to
    // the probabilistic product test procedure
    let mut rng = ChaCha20Rng::from_seed([0; 32]);
    let h: Polynomial<Felt> = Polynomial::new(random_coefficients_with_rng(&mut rng));
    let s2: Polynomial<Felt> = Polynomial::new(random_coefficients_with_rng(&mut rng));
    let (operand_stack, advice_stack): (Vec<u64>, Vec<u64>) =
        generate_data_probabilistic_product_test(h, s2, false);

    let test = build_test!(PROBABILISTIC_PRODUCT_SOURCE, &operand_stack, &advice_stack);
    let expected_stack = &[];
    test.expect_stack(expected_stack);
}

#[test]
fn test_falcon512_probabilistic_product_failure() {
    // create two random polynomials and generate the input operand stack and advice stack to
    // the probabilistic product test procedure
    let mut rng = rng();
    let h: Polynomial<Felt> = Polynomial::new(random_coefficients_with_rng(&mut rng));
    let s2: Polynomial<Felt> = Polynomial::new(random_coefficients_with_rng(&mut rng));
    let (operand_stack, advice_stack): (Vec<u64>, Vec<u64>) =
        generate_data_probabilistic_product_test(h, s2, true);

    let test = build_test!(PROBABILISTIC_PRODUCT_SOURCE, &operand_stack, &advice_stack);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError{ err: OperationError::FailedAssertion{err_code, err_msg}, .. }
        if err_code == ZERO && err_msg.is_none()
    );
}

/// Similar to `falcon_execution` test, but with the `move_sig_to_adv_stack` operation.
/// Specifically, we put the signature in the advice map ahead of time, call
/// `move_sig_to_adv_stack`, and then proceed to `verify` the signature.
#[test]
fn test_move_sig_to_adv_stack() {
    let seed = Word::default();
    let mut rng = RandomCoin::new(seed);
    let secret_key = SecretKey::with_rng(&mut rng);
    let message = random_word();

    let source = "
    use miden::core::crypto::dsa::falcon512_poseidon2

    begin
        exec.falcon512_poseidon2::move_sig_from_map_to_adv_stack
        exec.falcon512_poseidon2::verify
    end
    ";

    let public_key = secret_key.public_key().to_commitment();

    let advice_map: Vec<(Word, Vec<Felt>)> = {
        let sig_key = Poseidon2::merge(&[public_key, message]);
        let signature =
            falcon512_poseidon2::sign(&secret_key, message).expect("failed to sign message");

        vec![(sig_key, signature)]
    };

    let op_stack = stack_from_words(&[public_key, message]);

    let adv_stack = vec![];
    let store = MerkleStore::new();

    let test = build_debug_test!(source, &op_stack, &adv_stack, store, advice_map.into_iter())
        .with_event_handler(EVENT_FALCON_SIG_TO_STACK, push_falcon_signature);
    test.expect_stack(&[])
}

#[test]
fn falcon_execution() {
    let seed = Word::default();
    let mut rng = RandomCoin::new(seed);
    let sk = SecretKey::with_rng(&mut rng);
    let message = random_word();
    let (source, op_stack, adv_stack, store, advice_map) = generate_test(sk, message);

    let test = build_debug_test!(&source, &op_stack, &adv_stack, store, advice_map.into_iter())
        .with_event_handler(EVENT_FALCON_SIG_TO_STACK, push_falcon_signature);
    test.expect_stack(&[])
}

#[test]
fn test_mod_12289_simple() {
    // Simple test to debug mod_12289 with a known input
    let source = "
        use miden::core::crypto::dsa::falcon512_poseidon2

        begin
            exec.falcon512_poseidon2::mod_12289
        end
    ";

    let op_stack = vec![0u64, 100000u64];

    let test = build_test!(source, &op_stack, &[]);

    // Expected: 100000 % 12289 = 1688
    test.expect_stack(&[1688]);
}

#[test]
fn test_mod_12289_larger_value() {
    // Test with a larger value that requires the higher 32 bits
    let source = "
        use miden::core::crypto::dsa::falcon512_poseidon2

        begin
            exec.falcon512_poseidon2::mod_12289
        end
    ";

    // Test with a = 2^33 = 8589934592
    // a_hi = 2, a_lo = 0
    let op_stack = vec![2u64, 0u64];

    let test = build_test!(source, &op_stack, &[]);

    // Expected: 8589934592 % 12289 = 7507
    let expected = 8589934592u64 % 12289;
    test.expect_stack(&[expected]);
}

#[rstest]
#[case(0, 100_000)]
#[case(2, 0)]
#[case(0, 12_290)]
#[case(1, 1)]
#[case(0xffff_ffff, 0xffff_fffe)]
fn test_mod_12289_rejects_forged_remainder_zero(#[case] a_hi: u64, #[case] a_lo: u64) {
    const FALCON_DIV: EventName =
        EventName::new("miden::core::crypto::dsa::falcon512_poseidon2::falcon_div");

    // M^(-1) mod 2^64. For any a, q = a * M_INV (mod 2^64) satisfies M*q ≡ a (mod 2^64).
    const M_INV: u64 = 15010777177727684609;

    // Malicious event handler that always returns remainder = 0.
    fn malicious_falcon_div(process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        let a_hi = process.get_stack_item(1).as_canonical_u64();
        let a_lo = process.get_stack_item(2).as_canonical_u64();
        let a = (a_hi << 32) | a_lo;

        let q = a.wrapping_mul(M_INV);
        let q_hi = Felt::new_unchecked(q >> 32);
        let q_lo = Felt::new_unchecked(q & 0xffff_ffff);

        let remainder = AdviceMutation::extend_stack([ZERO]);
        let quotient = AdviceMutation::extend_stack([q_hi, q_lo]);
        Ok(vec![remainder, quotient])
    }

    let source = "
        use miden::core::crypto::dsa::falcon512_poseidon2
        begin
            exec.falcon512_poseidon2::mod_12289
        end
    ";

    let a = (a_hi << 32) | a_lo;
    let true_remainder = a % M;
    assert_ne!(true_remainder, 0, "test expects inputs with non-zero true remainder");

    let op_stack = vec![a_hi, a_lo];
    let adv_stack: Vec<u64> = vec![];

    // Use the upstream test builder directly so we do not auto-register the honest
    // falcon_div handler from CoreLibrary.
    let core_lib = CoreLibrary::default();
    let test = miden_utils_testing::build_test_by_mode!(false, source, &op_stack, &adv_stack)
        .with_library(core_lib.library().clone())
        .with_event_handler(FALCON_DIV, malicious_falcon_div);

    // Hardened mod_12289 must reject forged advice.
    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError {
            err: OperationError::FailedAssertion { err_msg, .. },
            ..
        } if err_msg.as_deref() == Some("comparison failed: quotient overflow")
    );
}

#[test]
fn test_mod_12289_rejects_forged_addition_overflow() {
    const FALCON_DIV: EventName =
        EventName::new("miden::core::crypto::dsa::falcon512_poseidon2::falcon_div");

    // Largest q such that M * q fits into 64 bits. This guarantees quotient-overflow checks pass.
    const FORGED_Q: u64 = u64::MAX / M;
    // 5664 > u64::MAX - M * FORGED_Q, so (M * FORGED_Q + FORGED_R) overflows u64.
    const FORGED_R: u64 = 5_664;

    // Malicious event handler that forges q/r to trigger the addition-overflow assertion.
    fn malicious_falcon_div(_process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        let q_hi = Felt::new_unchecked(FORGED_Q >> 32);
        let q_lo = Felt::new_unchecked(FORGED_Q & 0xffff_ffff);

        let remainder = AdviceMutation::extend_stack([Felt::new_unchecked(FORGED_R)]);
        let quotient = AdviceMutation::extend_stack([q_hi, q_lo]);
        Ok(vec![remainder, quotient])
    }

    let source = "
        use miden::core::crypto::dsa::falcon512_poseidon2
        begin
            exec.falcon512_poseidon2::mod_12289
        end
    ";

    // Choose input equal to wrapping sum, so without the assertz this forged advice would pass.
    let a = M.wrapping_mul(FORGED_Q).wrapping_add(FORGED_R);
    let op_stack = vec![a >> 32, a & 0xffff_ffff];
    let adv_stack: Vec<u64> = vec![];

    let core_lib = CoreLibrary::default();
    let test = miden_utils_testing::build_test_by_mode!(false, source, &op_stack, &adv_stack)
        .with_library(core_lib.library().clone())
        .with_event_handler(FALCON_DIV, malicious_falcon_div);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError {
            err: OperationError::FailedAssertion { err_msg, .. },
            ..
        } if err_msg.as_deref() == Some("comparison failed: addition overflow")
    );
}

#[test]
fn test_mod_12289_rejects_non_u32_remainder_advice() {
    const FALCON_DIV: EventName =
        EventName::new("miden::core::crypto::dsa::falcon512_poseidon2::falcon_div");

    fn malicious_falcon_div(process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        let a_hi = process.get_stack_item(1).as_canonical_u64();
        let a_lo = process.get_stack_item(2).as_canonical_u64();
        let dividend = (a_hi << 32) | a_lo;
        let quotient = dividend / M;

        let q_hi = Felt::new_unchecked(quotient >> 32);
        let q_lo = Felt::new_unchecked(quotient & 0xffff_ffff);
        let forged_remainder = Felt::new_unchecked(Felt::ORDER_U64 - 1);

        let remainder = AdviceMutation::extend_stack([forged_remainder]);
        let quotient = AdviceMutation::extend_stack([q_hi, q_lo]);
        Ok(vec![remainder, quotient])
    }

    let source = "
        use miden::core::crypto::dsa::falcon512_poseidon2
        begin
            exec.falcon512_poseidon2::mod_12289
        end
    ";

    let op_stack = vec![0, 100_000];
    let adv_stack: Vec<u64> = vec![];

    let core_lib = CoreLibrary::default();
    let mut test = miden_utils_testing::build_test_by_mode!(false, source, &op_stack, &adv_stack);
    test.libraries.push(core_lib.library().clone());
    test.add_event_handler(FALCON_DIV, malicious_falcon_div);

    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError {
            err: OperationError::NotU32Values { values },
            ..
        } if values.iter().any(|value| value.as_canonical_u64() == Felt::ORDER_U64 - 1)
    );
}

#[test]
fn falcon_prove_verify() {
    let sk = SecretKey::new();
    let message = random_word();
    let (source, op_stack, _, _, advice_map) = generate_test(sk, message);

    let program: Program = Assembler::default()
        .with_dynamic_library(CoreLibrary::default())
        .expect("failed to load core library")
        .assemble_program(source)
        .expect("failed to compile test source");

    let stack_inputs = StackInputs::try_from_ints(op_stack).expect("failed to create stack inputs");
    let advice_inputs = AdviceInputs::default().with_map(advice_map);
    let mut host = DefaultHost::default();
    host.load_library(&CoreLibrary::default()).expect("failed to load mast forest");
    host.register_handler(EVENT_FALCON_SIG_TO_STACK, Arc::new(push_falcon_signature))
        .unwrap();

    let trace_inputs =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, Default::default())
            .execute_trace_inputs_sync(&program, &mut host)
            .expect("failed to execute");
    let trace = miden_processor::trace::build_trace(trace_inputs).expect("failed to build trace");
    trace.check_constraints();
}

#[allow(clippy::type_complexity)]
fn generate_test(
    sk: SecretKey,
    message: Word,
) -> (String, Vec<u64>, Vec<u64>, MerkleStore, Vec<(Word, Vec<Felt>)>) {
    let source = format!(
        "
    use miden::core::crypto::dsa::falcon512_poseidon2

    begin
        emit.event(\"{EVENT_FALCON_SIG_TO_STACK}\")
        exec.falcon512_poseidon2::verify
    end
    "
    );

    let pk: Word = sk.public_key().to_commitment();
    let sk_bytes = sk.to_bytes();

    let to_adv_map = sk_bytes.iter().map(|a| Felt::new_unchecked(*a as u64)).collect::<Vec<Felt>>();

    let advice_map: Vec<(Word, Vec<Felt>)> = vec![(pk, to_adv_map)];

    let op_stack = stack_from_words(&[pk, message]);
    let adv_stack = vec![];
    let store = MerkleStore::new();

    (source, op_stack, adv_stack, store, advice_map)
}

// HELPER FUNCTIONS
// ================================================================================================

/// Creates random coefficients of a polynomial in the range (0..M) using the given RNG.
fn random_coefficients_with_rng<R: Rng>(rng: &mut R) -> Vec<Felt> {
    let mut res = Vec::new();
    for _i in 0..N {
        res.push(Felt::new_unchecked(rng.random_range(0..M)))
    }
    res
}

/// Multiplies two polynomials over Z_p\[x\] without reducing modulo p.
///
/// Given that the degrees of the input polynomials are less than 512 and their coefficients are
/// less than the modulus M = 12289, the resulting product polynomial is guaranteed to have
/// coefficients less than the Miden prime.
///
/// Note that this multiplication is not over Z_p\[x\]/(phi).
fn mul_modulo_p(a: Polynomial<Felt>, b: Polynomial<Felt>) -> [u64; 1024] {
    let mut c = [0; 2 * N];
    for i in 0..N {
        for j in 0..N {
            c[i + j] += a.coefficients[i].as_canonical_u64() * b.coefficients[j].as_canonical_u64();
        }
    }
    c
}

/// Returns the coefficients of a polynomial.
fn to_elements(poly: Polynomial<Felt>) -> Vec<Felt> {
    poly.coefficients.to_vec()
}

/// Generates the data needed to execute the probabilistic product test.
fn generate_data_probabilistic_product_test(
    h: Polynomial<Felt>,
    s2: Polynomial<Felt>,
    test_failure: bool,
) -> (Vec<u64>, Vec<u64>) {
    let mut rng = rng();
    let pi = mul_modulo_p(h.clone(), s2.clone());
    // lay the polynomials in order h then s2 then pi = h * s2
    let mut polynomials = if test_failure {
        to_elements(Polynomial::new(random_coefficients_with_rng(&mut rng)))
    } else {
        to_elements(h.clone())
    };

    polynomials.extend(to_elements(s2));
    polynomials.extend(pi.iter().map(|a| Felt::new_unchecked(*a)));

    // get the challenge point and push it to the advice stack
    // Push tau1 first, then tau0, so adv_push.2 produces _le format [tau0, tau1, ...] directly
    let digest_polynomials = Poseidon2::hash_elements(&polynomials[..]);
    let challenge = (digest_polynomials[0], digest_polynomials[1]);
    let mut builder = AdviceStackBuilder::new();
    builder.push_element(challenge.1);
    builder.push_element(challenge.0);
    builder.push_elements(polynomials.iter().copied());
    let advice_stack = builder.build_vec_u64();

    // compute hash of h and place it on the stack.
    let h_hash = Poseidon2::hash_elements(&to_elements(h));
    let operand_stack = stack_from_words(&[h_hash]);

    (operand_stack, advice_stack)
}

/// Builds operand-stack inputs from words. The first word ends up on top of the stack.
///
/// This matches `stack![]` semantics: `stack_from_words(&[A, B])` results in stack `[A, B, ...]`
/// with A at position 0 (top).
fn stack_from_words(words: &[Word]) -> Vec<u64> {
    words.iter().flat_map(|w| w.iter().map(Felt::as_canonical_u64)).collect()
}
