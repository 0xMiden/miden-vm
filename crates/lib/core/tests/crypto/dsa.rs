use std::sync::Arc;

use miden_assembly::{Assembler, Linkage};
use miden_core::{
    Felt,
    deferred::DeferredState,
    serde::{Deserializable, Serializable},
    utils::bytes_to_packed_u32_elements,
};
use miden_core_lib::{
    CoreLibrary, dsa::ecdsa_k256_keccak,
    handlers::ecdsa_k256_keccak::ECDSA_K256_KECCAK_RECOVER_EVENT_NAME,
};
use miden_crypto::{
    SequentialCommit, Word,
    dsa::ecdsa_k256_keccak::{PublicKey, Signature, SigningKey},
    hash::keccak::Keccak256,
    utils::hex_to_bytes,
};
use miden_precompiles::{K1Scalar, SECP256K1_LAMBDA, scalar_mul_mod_n};
use miden_precompiles_prover::{HashFunction, prove_deferred_state};
use miden_precompiles_verifier::verify_deferred;
use miden_processor::{
    DefaultHost, ExecutionError, ExecutionOptions, ExecutionOutput, FastProcessor, MemoryError,
    ProcessorState, StackInputs,
    advice::{AdviceInputs, AdviceMutation, AdviceStack},
    event::{EventError, EventHandler},
};
use miden_utils_testing::crypto::Poseidon2;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

use crate::{
    helpers::{masm_push_word, masm_store_felts},
    support::ecdsa::{
        EcdsaFixture as Fixture, fixture_from_signing_key, generator_public_key_fixture,
        valid_fixture,
    },
};

const MESSAGE_PTR: u32 = 128;
// Deliberately word-aligned but not double-word-aligned.
const SIGNATURE_PTR: u32 = 260;

#[test]
fn core_ecdsa_k256_keccak_recover_returns_public_key() {
    let fixture = valid_fixture();

    let output = run_recover(fixture.message, &fixture.signature)
        .expect("a valid recoverable signature must return its public key");

    assert_eq!(stack_elements::<16>(&output), public_key_elements(&fixture.public_key));
    assert_deferred_state_round_trips(&output);
    assert_deferred_proof_verifies(&output);
}

#[test]
fn core_ecdsa_k256_keccak_recover_loads_signature_before_local_write() {
    let fixture = valid_fixture();
    // Deliberately bypass the caller-owned-memory precondition to preserve the defensive
    // load-before-local-write ordering requested in review.
    // `recover` owns locals [2^31, 2^31 + 8), so the nested `recover_digest` frame begins here.
    // Its candidate-key `adv_pipe` overwrites this region after the signature has been loaded.
    let recover_digest_locals_ptr = (1_u32 << 31) + 8;

    let output = run_recover_with_native_signature(
        fixture.message,
        &native_recovery_signature(&fixture.signature),
        recover_digest_locals_ptr,
        None,
    )
    .expect("signature inputs must be bound before candidate-key locals overwrite their memory");

    assert_eq!(stack_elements::<16>(&output), public_key_elements(&fixture.public_key));
}

#[test]
fn core_ecdsa_k256_keccak_recover_bytes_respects_partial_final_word() {
    let message: Vec<u8> = (0..33).map(|value| value as u8).collect();
    let mut rng = ChaCha20Rng::from_seed([0x95; 32]);
    let signing_key = SigningKey::with_rng(&mut rng);
    let public_key = signing_key.public_key();
    let digest: [u8; 32] = Keccak256::hash(&message).into();
    let signature = signing_key.sign_prehash(digest);

    let output = run_recover_bytes(&message, &signature)
        .expect("message byte length must exclude zero padding in the final memory word");

    assert_eq!(stack_elements::<16>(&output), public_key_elements(&public_key));
}

#[test]
fn core_ecdsa_k256_keccak_recover_bytes_matches_usdcx_attestation_vector() {
    // xUSDC `att-2`, which signs the raw 240-byte DepositIntent payload with Keccak/secp256k1:
    // https://github.com/0xMiden/miden-usdcx/blob/c269baa63415327036c58bfac0f5679cb4907e6b/crates/xusdc-encoding/tests/vectors/xreserve-encoding-vectors.json
    let message = hex_to_bytes::<240>(concat!(
        "0x5a2e0acd00000001000000000000000000000000000000000000000000000000",
        "00000000000f424000000007000000000000000000000000000000008430fc24",
        "320cdd01726fbe7dcfa27200000000000000000000000000000000008110548c",
        "c41852010140bd1325ff0800b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3",
        "c4c5c6c7c8c9cacbcccdcecfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3",
        "d4d5d6d7d8d9dadbdcdddedf0000000000000000000000000000000000000000",
        "0000000000000000001e8480d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5",
        "e6e7e8e9eaebecedeeeff0f100000000",
    ))
    .unwrap();
    let sec1_signature = hex_to_bytes::<64>(concat!(
        "0x22ea73875e0676759fb166435c75c85288788004f67556afe9f9a4ae7f38a1a4",
        "1d680d3cb029694d99c61f1b3bbb05e5c8e07363493928907fe60c153de5507d",
    ))
    .unwrap();
    let signature = Signature::from_sec1_bytes_and_recovery_id(sec1_signature, 1).unwrap();
    let expected_public_key = PublicKey::read_from_bytes(
        &hex_to_bytes::<33>("0x03bcf58bdbe660d20db4a3233f7f7a78a7c0ede9ac159f96123954d5f147f5a0af")
            .unwrap(),
    )
    .unwrap();

    let output = run_recover_bytes(&message, &signature)
        .expect("the xUSDC attestation vector must recover its pinned signer");

    assert_eq!(stack_elements::<16>(&output), public_key_elements(&expected_public_key),);
}

#[test]
fn core_ecdsa_k256_keccak_recover_accepts_generator_and_high_s_signatures() {
    let generator = generator_public_key_fixture();
    let output = run_recover(generator.message, &generator.signature)
        .expect("the generator public key must be recoverable");
    assert_eq!(stack_elements::<16>(&output), public_key_elements(&generator.public_key));

    let fixture = valid_fixture();
    let low_s = be_bytes_to_le_limbs(fixture.signature.s());
    assert!(!is_high_s(low_s), "miden-crypto signer must produce low-s");
    let high_s_signature = signature_with_s(&fixture.signature, negate_scalar_mod_n(low_s));

    let output = run_recover(fixture.message, &high_s_signature)
        .expect("high-s with flipped parity must recover the same signer");
    assert_eq!(stack_elements::<16>(&output), public_key_elements(&fixture.public_key));
}

#[test]
fn core_ecdsa_k256_keccak_recover_wrong_message_returns_different_key() {
    let fixture = valid_fixture();
    let wrong_message = Word::new([
        Felt::new_unchecked(0x0001_0203_0405_0607),
        Felt::new_unchecked(0x0809_0a0b_0c0d_0e0f),
        Felt::new_unchecked(0x1011_1213_1415_1617),
        Felt::new_unchecked(0x1819_1a1b_1c1d_1e20),
    ]);

    let output = run_recover(wrong_message, &fixture.signature)
        .expect("a wrong message may still define a valid recovered key");

    assert_ne!(stack_elements::<16>(&output), public_key_elements(&fixture.public_key));
}

#[test]
fn core_ecdsa_k256_keccak_recover_traps_on_malformed_signature_memory() {
    let fixture = valid_fixture();
    let valid = native_recovery_signature(&fixture.signature);
    let non_u32 = Felt::new(u32::MAX as u64 + 1).expect("2^32 fits in the VM field");
    let modulus = limbs_to_felts(K1Scalar::MODULUS);

    let mut cases = Vec::new();
    for recovery_byte in [0, 1, 26, 29] {
        let mut signature = valid;
        signature[16] = Felt::from_u32(recovery_byte);
        cases.push(("invalid recovery byte", signature));
    }
    for (name, range, value) in [
        ("r is zero", 0..8, [Felt::ZERO; 8]),
        ("s is zero", 8..16, [Felt::ZERO; 8]),
        ("r equals n", 0..8, modulus),
        ("s equals n", 8..16, modulus),
    ] {
        let mut signature = valid;
        signature[range].copy_from_slice(&value);
        cases.push((name, signature));
    }
    let mut non_u32_signature = valid;
    non_u32_signature[0] = non_u32;
    cases.push(("r has a non-u32 limb", non_u32_signature));

    for (name, signature) in cases {
        run_recover_with_native_signature(fixture.message, &signature, SIGNATURE_PTR, None)
            .expect_err(name);
    }

    let error = run_recover_with_native_signature(
        fixture.message,
        &valid,
        SIGNATURE_PTR + 1,
        Some(recovery_public_key_handler(&fixture.public_key)),
    )
    .expect_err("the MASM scalar loader must reject an unaligned signature pointer");
    match error {
        ExecutionError::MemoryError {
            err: MemoryError::UnalignedWordAccess { addr, .. },
            ..
        } => assert_eq!(addr, SIGNATURE_PTR + 1),
        other => panic!("expected an unaligned word access, got {other:?}"),
    }
}

#[test]
fn core_ecdsa_k256_keccak_recover_rejects_forged_public_key_advice() {
    let fixture = valid_fixture();
    let mut rng = ChaCha20Rng::from_seed([0xfc; 32]);
    let wrong_public_key = SigningKey::with_rng(&mut rng).public_key();

    run_recover_with_native_signature(
        fixture.message,
        &native_recovery_signature(&fixture.signature),
        SIGNATURE_PTR,
        Some(recovery_public_key_handler(&wrong_public_key)),
    )
    .expect_err("an unrelated advice key must not satisfy the recovery constraints");
}

#[test]
fn core_ecdsa_k256_keccak_verify_accepts_valid_signature() {
    let fixture = valid_fixture();

    let output = run_verify(&fixture).expect("valid core ECDSA K256/Keccak signature must verify");
    assert_deferred_state_round_trips(&output);

    let wire = output.deferred_state.to_wire().expect("deferred state must encode to wire");
    assert_eq!(wire.to_bytes().len(), 2455);
}

/// Full round trip through the real precompile side prover: `verify` logs a plain 2-base MSM
/// claim (`R = u1*G + u2*Q`), and the side prover satisfies it with a GLV-decomposed addition
/// chain internally (`intro_endo`'s in-circuit `phi(G)`/`phi(Q)` certs, no untrusted advice) --
/// this proves those claims the deferred state above only checked structurally, then verifies the
/// resulting STARK proof against the same root the main VM committed.
#[test]
fn core_ecdsa_k256_keccak_verify_glv_claim_proves_and_verifies() {
    let fixture = valid_fixture();
    let output = run_verify(&fixture).expect("valid core ECDSA K256/Keccak signature must verify");

    assert_deferred_proof_verifies(&output);
}

#[test]
fn core_ecdsa_k256_keccak_verify_bytes_accepts_long_payload() {
    let payload: Vec<u8> = (0..240).map(|value| value as u8).collect();

    let output = run_verify_bytes(&payload, [0x91; 32])
        .expect("signature over a long memory-backed message must verify");
    assert_deferred_state_round_trips(&output);
}

#[test]
fn core_ecdsa_k256_keccak_verify_bytes_respects_partial_final_word() {
    let payload: Vec<u8> = (0..33).map(|value| value as u8).collect();

    run_verify_bytes(&payload, [0x92; 32])
        .expect("message byte length must exclude zero padding in the final memory word");
}

#[test]
fn core_ecdsa_k256_keccak_verify_accepts_generator_public_key() {
    let fixture = generator_public_key_fixture();

    let output = run_verify(&fixture).expect("generator public key must verify");
    assert_deferred_state_round_trips(&output);
}

/// A public key whose x-coordinate is `G_x`, `beta*G_x`, or `beta^2*G_x` puts it on the secp256k1
/// GLV endomorphism's orbit of the generator -- `Q` coincides with `G`, `phi(G)`, or `phi^2(G)` as
/// a point value. `verify` logs the same plain `u1*G + u2*Q` claim regardless; on the prover side,
/// `intro_endo`'s in-circuit value relation means a coincidence like this is ordinary point-store
/// dedup, not a forgery surface, so it needs no special-casing -- each such key must verify (and
/// prove) like any other.
///
/// Their discrete logs are `1`, `lambda`, `lambda^2` and the negations thereof, so no such key has
/// practical use. They are valid curve points all the same, and a verifier that traps on a valid
/// key decides it by accident rather than on the signature.
#[test]
fn core_ecdsa_k256_keccak_verify_accepts_glv_base_repeating_public_keys() {
    let one = core::array::from_fn(|i| u32::from(i == 0));
    let lambda_squared = scalar_mul_mod_n(SECP256K1_LAMBDA, SECP256K1_LAMBDA);

    for (name, secret_scalar) in [
        ("Q == G", one),
        ("Q == -G", negate_scalar_mod_n(one)),
        ("Q == phi(G)", SECP256K1_LAMBDA),
        ("Q == -phi(G)", negate_scalar_mod_n(SECP256K1_LAMBDA)),
        ("Q == phi^2(G)", lambda_squared),
        ("Q == -phi^2(G)", negate_scalar_mod_n(lambda_squared)),
    ] {
        let sk = SigningKey::read_from_bytes(&le_limbs_to_be_bytes(secret_scalar))
            .unwrap_or_else(|_| panic!("{name}: the secret scalar must be a valid key"));
        let fixture = fixture_from_signing_key(sk);

        let output = run_verify(&fixture)
            .unwrap_or_else(|e| panic!("{name} must verify through the 2-base fallback: {e}"));

        let proof = prove_deferred_state(&output.deferred_state, HashFunction::Blake3_256)
            .unwrap_or_else(|_| panic!("{name}: the fallback's deferred claims must be provable"));
        verify_deferred(&proof, output.deferred_state.root()).unwrap_or_else(|_| {
            panic!("{name}: the fallback's deferred proof must verify against the committed root")
        });
    }
}

#[test]
fn core_ecdsa_k256_keccak_verify_accepts_high_s_untrusted_witness() {
    let mut fixture = valid_fixture();
    let low_s = core::array::from_fn(|i| {
        fixture.advice[24 + i]
            .as_canonical_u64()
            .try_into()
            .expect("signature limbs are u32")
    });
    assert!(!is_high_s(low_s), "miden-crypto signer must produce low-s");

    let high_s = negate_scalar_mod_n(low_s);
    assert!(is_high_s(high_s), "n - low_s must be high-s");

    let high_s_signature = signature_with_s(&fixture.signature, high_s);
    assert!(
        !fixture.public_key.verify(fixture.message, &high_s_signature),
        "miden-crypto Rust verification must reject high-s",
    );

    fixture.advice = ecdsa_k256_keccak::encode_signature(&fixture.public_key, &high_s_signature);
    run_verify(&fixture)
        .expect("high-s remains an equivalent witness when signature advice is not committed");
}

#[test]
fn core_ecdsa_k256_keccak_verify_cycle_baseline() {
    let fixture = valid_fixture();

    let output = run_core_program_with_advice(&verify_cycle_source(&fixture), &fixture.advice)
        .expect("valid core ECDSA K256/Keccak signature must verify");
    let cycles = output.stack.get_element(0).expect("cycle count").as_canonical_u64();
    assert_eq!(cycles, 1325);
}

#[test]
fn core_ecdsa_k256_keccak_verify_traps_on_wrong_pk_comm() {
    let mut fixture = valid_fixture();
    tamper_felt(&mut fixture.public_key_commitment[0]);

    run_verify(&fixture).expect_err("wrong public key commitment must trap");
}

#[test]
fn core_ecdsa_k256_keccak_verify_traps_on_off_curve_public_key() {
    let mut fixture = valid_fixture();
    fixture.advice[8..16].copy_from_slice(&[Felt::from_u32(0); 8]);
    fixture.public_key_commitment = Poseidon2::hash_elements(&fixture.advice[..16]);

    run_verify(&fixture).expect_err("off-curve public key advice must trap");
}

#[test]
fn core_ecdsa_k256_keccak_verify_traps_on_non_u32_limb() {
    let non_u32 = Felt::new(u32::MAX as u64 + 1).expect("2^32 must fit in the VM field");

    let mut pubkey_fixture = valid_fixture();
    pubkey_fixture.advice[0] = non_u32;
    pubkey_fixture.public_key_commitment = Poseidon2::hash_elements(&pubkey_fixture.advice[..16]);
    run_verify(&pubkey_fixture).expect_err("non-u32 public-key limb must trap");

    let mut r_fixture = valid_fixture();
    r_fixture.advice[16] = non_u32;
    run_verify(&r_fixture).expect_err("non-u32 signature r limb must trap");

    let mut s_fixture = valid_fixture();
    s_fixture.advice[24] = non_u32;
    run_verify(&s_fixture).expect_err("non-u32 signature s limb must trap");
}

#[test]
fn core_ecdsa_k256_keccak_verify_traps_on_noncanonical_signature_scalar() {
    let mut r_fixture = valid_fixture();
    set_r(&mut r_fixture, K1Scalar::MODULUS);
    run_verify(&r_fixture).expect_err("noncanonical r scalar must trap");

    let mut s_fixture = valid_fixture();
    set_s(&mut s_fixture, K1Scalar::MODULUS);
    run_verify(&s_fixture).expect_err("noncanonical s scalar must trap");
}

#[test]
fn core_ecdsa_k256_keccak_verify_traps_on_zero_signature_scalar() {
    let mut r_fixture = valid_fixture();
    r_fixture.advice[16..24].copy_from_slice(&[Felt::from_u32(0); 8]);
    run_verify(&r_fixture).expect_err("zero r scalar must trap");

    let mut s_fixture = valid_fixture();
    s_fixture.advice[24..32].copy_from_slice(&[Felt::from_u32(0); 8]);
    run_verify(&s_fixture).expect_err("zero s scalar must trap");
}

#[test]
fn core_ecdsa_k256_keccak_verify_traps_on_tampered_signature() {
    let mut fixture = valid_fixture();
    tamper_felt(&mut fixture.advice[16]);

    run_verify(&fixture).expect_err("tampered signature must trap");
}

#[test]
fn core_ecdsa_k256_keccak_verify_traps_on_valid_but_wrong_public_key() {
    let mut fixture = valid_fixture();
    let mut rng = ChaCha20Rng::from_seed([0xa5; 32]);
    let wrong_public_key = SigningKey::with_rng(&mut rng).public_key();
    let wrong_public_key_elements = public_key_elements(&wrong_public_key);
    assert_ne!(
        &fixture.advice[..16],
        wrong_public_key_elements.as_slice(),
        "deterministic wrong key should differ",
    );

    fixture.advice[..16].copy_from_slice(&wrong_public_key_elements);
    fixture.public_key_commitment = ecdsa_k256_keccak::public_key_commitment(&wrong_public_key);

    run_verify(&fixture).expect_err("valid signature under wrong public key must trap");
}

fn run_verify_bytes(
    message: &[u8],
    signing_key_seed: [u8; 32],
) -> Result<ExecutionOutput, ExecutionError> {
    let mut rng = ChaCha20Rng::from_seed(signing_key_seed);
    let signing_key = SigningKey::with_rng(&mut rng);
    let public_key = signing_key.public_key();
    let digest: [u8; 32] = Keccak256::hash(message).into();
    let signature = signing_key.sign_prehash(digest);

    assert!(
        public_key.verify_prehash(digest, &signature),
        "Rust prehash signature must verify before passing it to MASM",
    );

    let stores = masm_store_felts(&bytes_to_packed_u32_elements(message), MESSAGE_PTR);
    let pk_comm = masm_push_word(&ecdsa_k256_keccak::public_key_commitment(&public_key));
    let advice = ecdsa_k256_keccak::encode_signature(&public_key, &signature);
    let source = format!(
        r#"
        begin
            {stores}
            push.{len_bytes}
            push.{MESSAGE_PTR}
            {pk_comm}
            exec.::miden::core::crypto::dsa::ecdsa_k256_keccak::verify_bytes
        end
        "#,
        len_bytes = message.len(),
    );

    run_core_program_with_advice(&source, &advice)
}
fn public_key_elements(public_key: &PublicKey) -> [Felt; 16] {
    public_key
        .to_elements()
        .try_into()
        .expect("public key must encode as QX[8] || QY[8]")
}

fn set_r(fixture: &mut Fixture, limbs: [u32; 8]) {
    fixture.advice[16..24].copy_from_slice(&limbs_to_felts(limbs));
}

fn set_s(fixture: &mut Fixture, limbs: [u32; 8]) {
    fixture.advice[24..32].copy_from_slice(&limbs_to_felts(limbs));
}

fn limbs_to_felts<const N: usize>(limbs: [u32; N]) -> [Felt; N] {
    limbs.map(Felt::from_u32)
}

fn is_high_s(value: [u32; 8]) -> bool {
    let negated = negate_scalar_mod_n(value);
    value.iter().rev().cmp(negated.iter().rev()).is_gt()
}

fn signature_with_s(signature: &Signature, s: [u32; 8]) -> Signature {
    let mut sec1 = signature.to_sec1_bytes();
    sec1[32..].copy_from_slice(&le_limbs_to_be_bytes(s));
    Signature::from_sec1_bytes_and_recovery_id(sec1, signature.v() ^ 1)
        .expect("canonical high-s scalar and recovery ID must encode")
}

fn le_limbs_to_be_bytes(limbs: [u32; 8]) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (i, limb) in limbs.iter().rev().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&limb.to_be_bytes());
    }
    bytes
}

fn be_bytes_to_le_limbs(bytes: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|i| {
        let offset = bytes.len() - (i + 1) * 4;
        u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("u32 limb"))
    })
}

fn negate_scalar_mod_n(value: [u32; 8]) -> [u32; 8] {
    let mut borrow = 0u64;
    let result = core::array::from_fn(|i| {
        let modulus_limb = K1Scalar::MODULUS[i] as u64;
        let subtrahend = value[i] as u64 + borrow;
        let (limb, next_borrow) = if modulus_limb >= subtrahend {
            (modulus_limb - subtrahend, 0)
        } else {
            ((1u64 << 32) + modulus_limb - subtrahend, 1)
        };
        borrow = next_borrow;
        limb as u32
    });
    assert_eq!(borrow, 0, "canonical scalar must be less than the modulus");
    result
}

fn run_verify(fixture: &Fixture) -> Result<ExecutionOutput, ExecutionError> {
    run_core_program_with_advice(&verify_source(fixture), &fixture.advice)
}

fn run_recover(message: Word, signature: &Signature) -> Result<ExecutionOutput, ExecutionError> {
    run_recover_with_native_signature(
        message,
        &native_recovery_signature(signature),
        SIGNATURE_PTR,
        None,
    )
}

fn run_recover_with_native_signature(
    message: Word,
    signature: &[Felt; 17],
    signature_ptr: u32,
    handler: Option<Arc<dyn EventHandler>>,
) -> Result<ExecutionOutput, ExecutionError> {
    let stores = masm_store_felts(signature, signature_ptr);
    let message = masm_push_word(&message);
    let source = format!(
        r#"
        begin
            {stores}
            push.{signature_ptr}
            {message}
            exec.::miden::core::crypto::dsa::ecdsa_k256_keccak::recover
            exec.::miden::core::sys::truncate_stack
        end
        "#,
    );

    run_core_program(&source, &[], handler)
}

fn run_recover_bytes(
    message: &[u8],
    signature: &Signature,
) -> Result<ExecutionOutput, ExecutionError> {
    let message_stores = masm_store_felts(&bytes_to_packed_u32_elements(message), MESSAGE_PTR);
    let signature_stores = masm_store_felts(&native_recovery_signature(signature), SIGNATURE_PTR);
    let source = format!(
        r#"
        begin
            {message_stores}
            {signature_stores}
            push.{SIGNATURE_PTR}
            push.{len_bytes}
            push.{MESSAGE_PTR}
            exec.::miden::core::crypto::dsa::ecdsa_k256_keccak::recover_bytes
            exec.::miden::core::sys::truncate_stack
        end
        "#,
        len_bytes = message.len(),
    );

    run_core_program_with_advice(&source, &[])
}

fn native_recovery_signature(signature: &Signature) -> [Felt; 17] {
    assert!(signature.v() <= 1, "EVM recovery only supports parity recovery IDs");
    let r = be_bytes_to_le_limbs(signature.r());
    let s = be_bytes_to_le_limbs(signature.s());

    core::array::from_fn(|index| match index {
        0..8 => Felt::from_u32(r[index]),
        8..16 => Felt::from_u32(s[index - 8]),
        16 => Felt::from_u32(u32::from(signature.v()) + 27),
        _ => unreachable!(),
    })
}

fn verify_source(fixture: &Fixture) -> String {
    let setup = verify_setup(fixture);

    format!(
        r#"
        begin
            {setup}
            exec.::miden::core::crypto::dsa::ecdsa_k256_keccak::verify
        end
        "#,
    )
}

fn verify_cycle_source(fixture: &Fixture) -> String {
    let setup = verify_setup(fixture);

    format!(
        r#"
        begin
            {setup}
            clk
            movdn.8
            exec.::miden::core::crypto::dsa::ecdsa_k256_keccak::verify
            clk
            swap sub
            swap drop
        end
        "#,
    )
}

fn verify_setup(fixture: &Fixture) -> String {
    let message = masm_push_word(&fixture.message);
    let pk_comm = masm_push_word(&fixture.public_key_commitment);

    format!(
        r#"
        {message}
        {pk_comm}
        "#,
    )
}

fn run_core_program_with_advice(
    source: &str,
    advice: &[Felt],
) -> Result<ExecutionOutput, ExecutionError> {
    run_core_program(source, advice, None)
}

fn run_core_program(
    source: &str,
    advice: &[Felt],
    recovery_handler: Option<Arc<dyn EventHandler>>,
) -> Result<ExecutionOutput, ExecutionError> {
    let core_lib = CoreLibrary::default();
    let program = Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("failed to link core library")
        .assemble_program("core_ecdsa_k256_keccak_test", source)
        .expect("failed to assemble core ECDSA test program")
        .unwrap_program();

    let mut host = DefaultHost::default()
        .with_library(&core_lib)
        .expect("failed to load CoreLibrary into the host");
    if let Some(handler) = recovery_handler {
        assert!(
            host.replace_handler(ECDSA_K256_KECCAK_RECOVER_EVENT_NAME, handler),
            "the default recovery handler must already be registered",
        );
    }

    let mut advice_stack = AdviceStack::new();
    advice_stack.append_elements(advice.iter().copied());
    let processor = FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default().with_stack(advice_stack),
        ExecutionOptions::default(),
    )
    .expect("processor construction");

    let output = processor.execute_sync(&program, &mut host);
    if let Ok(output) = &output {
        assert!(output.advice.stack().is_empty(), "core ECDSA wrapper must consume advice");
    }

    output
}

fn recovery_public_key_handler(public_key: &PublicKey) -> Arc<dyn EventHandler> {
    let elements = public_key_elements(public_key);
    Arc::new(move |_process: &ProcessorState| -> Result<Vec<AdviceMutation>, EventError> {
        let mut advice_stack = AdviceStack::new();
        advice_stack.append_for_adv_pipe(&elements);
        Ok(vec![AdviceMutation::extend_advice_stack(advice_stack)])
    })
}

fn assert_deferred_state_round_trips(output: &ExecutionOutput) {
    let registry = Arc::new(miden_precompiles::registry());
    let wire = output.deferred_state.to_wire().expect("deferred state must encode to wire");
    let rehydrated = DeferredState::from_wire(Arc::clone(&registry), &wire)
        .expect("deferred wire must rehydrate under miden-precompiles registry");
    assert_eq!(
        rehydrated.root(),
        output.deferred_state.root(),
        "wire round-trip must preserve the deferred root",
    );
}

fn assert_deferred_proof_verifies(output: &ExecutionOutput) {
    let proof = prove_deferred_state(&output.deferred_state, HashFunction::Blake3_256)
        .expect("the GLV-decomposed deferred claims must be provable");
    verify_deferred(&proof, output.deferred_state.root())
        .expect("the GLV-decomposed deferred proof must verify against the committed root");
}

fn stack_elements<const N: usize>(output: &ExecutionOutput) -> [Felt; N] {
    core::array::from_fn(|index| output.stack.get_element(index).expect("stack output element"))
}

fn tamper_felt(felt: &mut Felt) {
    let value = felt.as_canonical_u64();
    *felt = if value == 0 {
        Felt::from_u32(1)
    } else {
        Felt::new(value - 1).expect("decremented canonical field element must stay canonical")
    };
}
