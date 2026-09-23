use std::sync::Arc;

use miden_assembly::{Assembler, Linkage};
use miden_core::{
    Felt, Word, events::EventName, mast::error_code_from_msg, utils::bytes_to_packed_u32_elements,
};
use miden_core_lib::{
    CoreLibrary,
    dsa::ecdsa_p256_sha256,
    handlers::{
        ecdsa_p256_sha256::ECDSA_P256_SHA256_RECOVER_EVENT_NAME,
        precompiles::sha256::SHA256_DIGEST_EVENT_NAME,
    },
};
use miden_crypto::hash::{eidos::Eidos, sha2::Sha256};
use miden_precompiles::{
    CurveId, CurvePoint, Limbs, ONE_LIMBS, P256Base, P256Scalar, UintDomain, ZERO_LIMBS,
};
use miden_precompiles_prover::{HashFunction, prove_precompiles};
use miden_precompiles_verifier::verify_deferred;
use miden_processor::{
    DefaultHost, ExecutionError, ExecutionOptions, ExecutionOutput, FastProcessor, MemoryError,
    ProcessorState, StackInputs,
    advice::{AdviceInputs, AdviceMutation, AdviceStack},
    event::{EventError, EventHandler},
    operation::OperationError,
};
use p256::ecdsa::{
    RecoveryId, Signature, SigningKey, VerifyingKey, signature::hazmat::PrehashVerifier,
};

use crate::helpers::{assert_precompile_witness_round_trips, masm_push_word, masm_store_felts};

const MESSAGE_PTR: u32 = 128;
// Deliberately word-aligned but not double-word-aligned.
const SIGNATURE_PTR: u32 = 260;

const INVALID_COMMITMENT: &str = "invalid public key commitment";
const INVALID_RECOVERY_BYTE: &str = "invalid ECDSA recovery byte: expected 0 or 1";
const R_IS_ZERO: &str = "invalid ECDSA signature: r is zero";
const RECOVERY_X_MISMATCH: &str = "ECDSA recovery point x-coordinate does not equal r";

// VERIFY
// ================================================================================================

#[test]
fn p256_verify_accepts_valid_signature() {
    let fixture = valid_fixture();
    let public_key = public_key_elements(&fixture.verifying_key);
    let (r, s) = scalar_limbs(&fixture.signature);

    assert_eq!(&fixture.advice[..16], &public_key);
    assert_eq!(&fixture.advice[16..24], &limbs_to_felts(r));
    assert_eq!(&fixture.advice[24..], &limbs_to_felts(s));
    assert_eq!(fixture.public_key_commitment, Eidos::hash_elements(&public_key));
    assert_eq!(ecdsa_p256_sha256::sign(&fixture.signing_key, fixture.message), fixture.advice);

    let output = run_verify(&fixture).expect("valid P-256/SHA-256 signature must verify");
    assert_precompile_witness_round_trips(&output);
}

#[test]
fn p256_verify_bytes_accepts_lengths_0_1_55_56_64_200() {
    for len in [0usize, 1, 55, 56, 64, 200] {
        let message: Vec<u8> =
            (0..len).map(|i| (i as u8).wrapping_mul(29).wrapping_add(3)).collect();

        let output = run_verify_bytes(&message)
            .unwrap_or_else(|err| panic!("{len}-byte message must verify: {err}"));
        assert_precompile_witness_round_trips(&output);
    }
}

#[test]
fn p256_verify_accepts_high_s_untrusted_witness() {
    let mut fixture = valid_fixture();
    let (r, s) = scalar_limbs(&fixture.signature);
    let high_s = if is_high_s(s) { s } else { negate_scalar_mod_n(s) };
    assert!(is_high_s(high_s));

    let high_s_signature = signature_from_limbs(r, high_s);
    fixture
        .verifying_key
        .verify_prehash(&word_prehash(fixture.message), &high_s_signature)
        .expect("FIPS 186-5 P-256 verification accepts high-s");

    fixture.advice = ecdsa_p256_sha256::encode_signature(&fixture.verifying_key, &high_s_signature);
    run_verify(&fixture).expect("high-s is an equivalent uncommitted witness");
}

#[test]
fn p256_verify_traps_on_wrong_pk_comm() {
    let mut fixture = valid_fixture();
    tamper_felt(&mut fixture.public_key_commitment[0]);

    assert_failed_assertion(run_verify(&fixture), INVALID_COMMITMENT);
}

#[test]
fn p256_verify_traps_on_wrong_message() {
    let mut fixture = valid_fixture();
    fixture.message = wrong_message();

    run_verify(&fixture).expect_err("a signature over a different message must trap");
}

#[test]
fn p256_verify_traps_on_off_curve_public_key() {
    let mut y_zero = valid_fixture();
    y_zero.advice[8..16].copy_from_slice(&[Felt::ZERO; 8]);
    y_zero.public_key_commitment = Eidos::hash_elements(&y_zero.advice[..16]);
    let err = run_verify(&y_zero).expect_err("off-curve public key advice must trap");
    assert!(!is_failed_assertion(&err, INVALID_COMMITMENT), "{err:?}");

    let mut origin = valid_fixture();
    origin.advice[..16].copy_from_slice(&[Felt::ZERO; 16]);
    origin.public_key_commitment = Eidos::hash_elements(&origin.advice[..16]);
    let err = run_verify(&origin).expect_err("(0, 0) is not a valid P-256 public key");
    assert!(!is_failed_assertion(&err, INVALID_COMMITMENT), "{err:?}");
}

#[test]
fn p256_verify_traps_on_noncanonical_public_key_coordinate() {
    // x = p is the smallest noncanonical encoding. The commitment binds the tampered limbs, so
    // only the canonical coordinate loader can reject them.
    let mut fixture = valid_fixture();
    fixture.advice[..8].copy_from_slice(&limbs_to_felts(P256Base::MODULUS));
    fixture.public_key_commitment = Eidos::hash_elements(&fixture.advice[..16]);

    let err = run_verify(&fixture).expect_err("a noncanonical public-key coordinate must trap");
    assert!(!is_failed_assertion(&err, INVALID_COMMITMENT), "{err:?}");
}

#[test]
fn p256_verify_traps_on_zero_r() {
    let mut fixture = valid_fixture();
    set_r(&mut fixture, ZERO_LIMBS);

    assert_failed_assertion(run_verify(&fixture), R_IS_ZERO);
}

#[test]
fn p256_verify_traps_on_zero_s() {
    let mut fixture = valid_fixture();
    set_s(&mut fixture, ZERO_LIMBS);

    run_verify(&fixture).expect_err("s = 0 has no inverse and must trap");
}

#[test]
fn p256_verify_traps_on_r_at_least_n() {
    for r in [P256Scalar::MODULUS, [u32::MAX; 8]] {
        let mut fixture = valid_fixture();
        set_r(&mut fixture, r);

        run_verify(&fixture).expect_err("r >= n must trap");
    }
}

#[test]
fn p256_verify_traps_on_s_at_least_n() {
    for s in [P256Scalar::MODULUS, [u32::MAX; 8]] {
        let mut fixture = valid_fixture();
        set_s(&mut fixture, s);

        run_verify(&fixture).expect_err("s >= n must trap");
    }
}

#[test]
fn p256_verify_bytes_traps_on_nonzero_bytes_past_message_length() {
    let message = [0x11, 0x22, 0x33, 0x44, 0x55];
    let memory = bytes_to_packed_u32_elements(&message);
    assert_eq!(memory.len(), 2);
    run_verify_bytes_with_memory(&message, &memory, None)
        .expect("the zero-padded message must verify");
    run_verify_bytes_with_memory(&message, &memory, Some(sha256_digest_handler(&message)))
        .expect("the digest override must accept the zero-padded message");

    // Byte 5 is the second byte of the u32 limb that holds the final message byte.
    let mut same_limb = memory.clone();
    same_limb[1] = Felt::from_u32(0x0000_ff55);
    // The message occupies felts 0 and 1 of its single 8-felt chunk.
    let mut later_felt = memory;
    later_felt.resize(8, Felt::ZERO);
    later_felt[7] = Felt::from_u32(1);

    for (name, tampered) in [("byte 5 in the final limb", same_limb), ("felt 7", later_felt)] {
        run_verify_bytes_with_memory(&message, &tampered, None).expect_err(name);
        // A host that hashes only the first MSG_LEN bytes leaves rejection to the deferred
        // SHA-256 validation of the registered chunks.
        run_verify_bytes_with_memory(&message, &tampered, Some(sha256_digest_handler(&message)))
            .expect_err(name);
    }
}

#[test]
fn p256_verify_accepts_and_recover_rejects_x_reduced_point() {
    let curve = CurveId::P256;
    let message = fixed_message();
    let base = UintDomain::P256Base;
    let scalar = UintDomain::P256Scalar;

    // Find R with n < x(R) < p. P-256 has p ≡ 3 (mod 4), so sqrt(rhs) = rhs^((p + 1) / 4).
    let p_plus_one = UintDomain::U256.add(P256Base::MODULUS, ONE_LIMBS);
    let sqrt_exponent: Limbs = core::array::from_fn(|i| {
        (p_plus_one[i] >> 2) | p_plus_one.get(i + 1).map_or(0, |next| next << 30)
    });
    let mut x = P256Scalar::MODULUS;
    let (x, y) = loop {
        // r = x - n must be nonzero, so the scan starts at n + 1.
        x = UintDomain::U256.add(x, ONE_LIMBS);
        assert!(base.is_canonical(&x), "the scan must stay below p");
        let rhs = base.add(
            base.add(base.mul(base.mul(x, x), x), base.mul(curve.a_value(), x)),
            curve.b_value(),
        );
        let y = pow_mod(base, rhs, sqrt_exponent);
        if base.mul(y, y) == rhs {
            break (x, y);
        }
    };
    let point_r = curve.point_from_affine(x, y).expect("R is on P-256");

    let r = UintDomain::U256.sub(x, P256Scalar::MODULUS);
    assert!(scalar.is_canonical(&r) && r != ZERO_LIMBS);
    let s = limbs_from_u32(5);
    let z = reduce_mod_n(be_bytes_to_le_limbs(&word_prehash(message)));

    // Q = (s / r)·(R − (z / s)·G), so (z / s)·G + (r / s)·Q = R.
    let z_over_s = scalar.mul(z, scalar.inv(s).expect("s is nonzero"));
    let s_over_r = scalar.mul(s, scalar.inv(r).expect("r is nonzero"));
    let shifted = curve
        .sub(point_r, curve.mul_scalar(curve.generator(), z_over_s).expect("valid scalar"))
        .expect("valid points");
    let CurvePoint::Affine { x: qx, y: qy } =
        curve.mul_scalar(shifted, s_over_r).expect("valid scalar")
    else {
        panic!("the constructed public key must not be the identity");
    };
    let public_key: [Felt; 16] =
        core::array::from_fn(|i| Felt::from_u32(if i < 8 { qx[i] } else { qy[i - 8] }));

    // RustCrypto agrees: verification accepts x(R) mod n == r, and only the x-reduced recovery
    // IDs (2 and 3), which the MASM ABI does not admit, recover Q.
    let verifying_key = VerifyingKey::from_sec1_bytes(
        &[&[0x04][..], &le_limbs_to_be_bytes(qx), &le_limbs_to_be_bytes(qy)].concat(),
    )
    .expect("Q is a valid public key");
    let signature = signature_from_limbs(r, s);
    let prehash = word_prehash(message);
    verifying_key
        .verify_prehash(&prehash, &signature)
        .expect("FIPS 186-5 accepts the x-reduced verification point");
    let x_reduced_id = RecoveryId::new(y[0] & 1 == 1, true);
    let recovered = VerifyingKey::recover_from_prehash(&prehash, &signature, x_reduced_id)
        .expect("the x-reduced recovery ID recovers Q");
    assert_eq!(recovered.to_sec1_point(false), verifying_key.to_sec1_point(false));

    let mut advice = public_key.to_vec();
    advice.extend(limbs_to_felts(r));
    advice.extend(limbs_to_felts(s));
    run_verify_with(message, Eidos::hash_elements(&public_key), &advice)
        .expect("verify must accept x(R) mod n == r");

    let mut recovery_signature = [Felt::ZERO; 17];
    recovery_signature[..8].copy_from_slice(&limbs_to_felts(r));
    recovery_signature[8..16].copy_from_slice(&limbs_to_felts(s));
    recovery_signature[16] = Felt::from_u32(y[0] & 1);
    assert_failed_assertion(
        run_recover_with_native_signature(
            message,
            &recovery_signature,
            SIGNATURE_PTR,
            Some(recovery_public_key_handler(public_key)),
        ),
        RECOVERY_X_MISMATCH,
    );
}

#[test]
fn p256_verify_proves_and_verifies_deferred() {
    let fixture = valid_fixture();
    let output = run_verify(&fixture).expect("valid P-256/SHA-256 signature must verify");

    assert_deferred_proof_verifies(&output);
}

// RECOVER
// ================================================================================================

#[test]
fn p256_recover_returns_public_key() {
    let fixture = valid_fixture();

    let output = run_recover(&fixture).expect("a valid recoverable signature must return its key");

    assert_eq!(stack_elements::<16>(&output), public_key_elements(&fixture.verifying_key));
    assert_precompile_witness_round_trips(&output);
    assert_deferred_proof_verifies(&output);
}

#[test]
fn p256_recover_bytes_respects_partial_final_word() {
    let message: Vec<u8> = (0..33).map(|value| value as u8).collect();
    let signing_key = signing_key();
    let prehash: [u8; 32] = Sha256::hash(&message).into();
    let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&prehash);

    let output = run_recover_bytes(&message, &native_recovery_signature(&signature, recovery_id))
        .expect("message byte length must exclude zero padding in the final memory word");

    assert_eq!(stack_elements::<16>(&output), public_key_elements(signing_key.verifying_key()));
}

#[test]
fn p256_recover_accepts_high_s_with_flipped_parity() {
    let fixture = valid_fixture();
    let (r, s) = scalar_limbs(&fixture.signature);
    let negated = signature_from_limbs(r, negate_scalar_mod_n(s));
    let v = fixture.recovery_id.to_byte();
    let flipped = RecoveryId::from_byte(v ^ 1).expect("parity recovery IDs are valid");
    let expected = public_key_elements(&fixture.verifying_key);

    let output = run_recover_with_native_signature(
        fixture.message,
        &native_recovery_signature(&negated, flipped),
        SIGNATURE_PTR,
        None,
    )
    .expect("(r, n - s) with the flipped parity must recover the same signer");
    assert_eq!(stack_elements::<16>(&output), expected);

    let output = run_recover_with_native_signature(
        fixture.message,
        &native_recovery_signature(&negated, fixture.recovery_id),
        SIGNATURE_PTR,
        None,
    )
    .expect("(r, n - s) with the original parity defines another valid key");
    assert_ne!(stack_elements::<16>(&output), expected);
}

#[test]
fn p256_recover_wrong_message_returns_different_key() {
    let fixture = valid_fixture();

    let output = run_recover_with_native_signature(
        wrong_message(),
        &native_recovery_signature(&fixture.signature, fixture.recovery_id),
        SIGNATURE_PTR,
        None,
    )
    .expect("a wrong message may still define a valid recovered key");

    assert_ne!(stack_elements::<16>(&output), public_key_elements(&fixture.verifying_key));
}

#[test]
fn p256_recover_traps_on_malformed_signature_memory() {
    let fixture = valid_fixture();
    let valid = native_recovery_signature(&fixture.signature, fixture.recovery_id);
    let signer = public_key_elements(&fixture.verifying_key);
    let non_u32 = Felt::new(u32::MAX as u64 + 1).expect("2^32 fits in the VM field");
    let modulus = limbs_to_felts(P256Scalar::MODULUS);

    let mut cases = Vec::new();
    for recovery_byte in [2, 3, 27, 28] {
        let mut signature = valid;
        signature[16] = Felt::from_u32(recovery_byte);
        cases.push(("recovery byte outside {0, 1}", signature, Some(INVALID_RECOVERY_BYTE)));
    }
    for (name, range, value, masm_error) in [
        ("r is zero", 0..8, [Felt::ZERO; 8], Some(R_IS_ZERO)),
        ("s is zero", 8..16, [Felt::ZERO; 8], None),
        ("r equals n", 0..8, modulus, None),
        ("s equals n", 8..16, modulus, None),
    ] {
        let mut signature = valid;
        signature[range].copy_from_slice(&value);
        cases.push((name, signature, masm_error));
    }
    let mut non_u32_signature = valid;
    non_u32_signature[0] = non_u32;
    cases.push(("r has a non-u32 limb", non_u32_signature, None));

    for (name, signature, masm_error) in cases {
        run_recover_with_native_signature(fixture.message, &signature, SIGNATURE_PTR, None)
            .expect_err(name);

        // A host that returns the signer's key regardless leaves rejection to the MASM checks.
        let result = run_recover_with_native_signature(
            fixture.message,
            &signature,
            SIGNATURE_PTR,
            Some(recovery_public_key_handler(signer)),
        );
        match masm_error {
            Some(message) => assert_failed_assertion(result, message),
            None => {
                result.expect_err(name);
            },
        }
    }

    let error = run_recover_with_native_signature(
        fixture.message,
        &valid,
        SIGNATURE_PTR + 1,
        Some(recovery_public_key_handler(signer)),
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
fn p256_recover_rejects_forged_public_key_advice() {
    let fixture = valid_fixture();
    let other_key = SigningKey::from_slice(&[9u8; 32]).expect("[9; 32] is a valid secret scalar");

    assert_failed_assertion(
        run_recover_with_native_signature(
            fixture.message,
            &native_recovery_signature(&fixture.signature, fixture.recovery_id),
            SIGNATURE_PTR,
            Some(recovery_public_key_handler(public_key_elements(other_key.verifying_key()))),
        ),
        RECOVERY_X_MISMATCH,
    );
}

#[test]
fn p256_recover_loads_signature_before_local_write() {
    let fixture = valid_fixture();
    // Deliberately bypass the caller-owned-memory precondition to preserve the defensive
    // load-before-local-write ordering.
    // `recover` owns locals [2^31, 2^31 + 8), so the nested `recover_digest` frame begins here.
    // Its candidate-key `adv_pipe` overwrites this region after the signature has been loaded.
    let recover_digest_locals_ptr = (1_u32 << 31) + 8;

    let output = run_recover_with_native_signature(
        fixture.message,
        &native_recovery_signature(&fixture.signature, fixture.recovery_id),
        recover_digest_locals_ptr,
        None,
    )
    .expect("signature inputs must be bound before candidate-key locals overwrite their memory");

    assert_eq!(stack_elements::<16>(&output), public_key_elements(&fixture.verifying_key));
}

#[test]
fn p256_recovered_key_compresses_to_the_signer_key() {
    let fixture = valid_fixture();
    let output = run_recover(&fixture).expect("a valid recoverable signature must return its key");
    let key = stack_elements::<16>(&output).map(|felt| {
        u32::try_from(felt.as_canonical_u64()).expect("recovered coordinates are u32 limbs")
    });
    let qx: [u32; 8] = key[..8].try_into().unwrap();
    let qy_low = key[8];

    let mut compressed = vec![0x02 | (qy_low & 1) as u8];
    compressed.extend(le_limbs_to_be_bytes(qx));

    assert_eq!(compressed, fixture.verifying_key.to_sec1_point(true).as_bytes());
}

// FIXTURES
// ================================================================================================

struct Fixture {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    message: Word,
    signature: Signature,
    recovery_id: RecoveryId,
    public_key_commitment: Word,
    advice: Vec<Felt>,
}

fn signing_key() -> SigningKey {
    SigningKey::from_slice(&[7u8; 32]).expect("[7; 32] is a valid P-256 secret scalar")
}

fn valid_fixture() -> Fixture {
    let signing_key = signing_key();
    let verifying_key = *signing_key.verifying_key();
    let message = fixed_message();
    let prehash = word_prehash(message);
    let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&prehash);
    verifying_key
        .verify_prehash(&prehash, &signature)
        .expect("Rust fixture signature must verify before passing it to MASM");

    Fixture {
        public_key_commitment: ecdsa_p256_sha256::public_key_commitment(&verifying_key),
        advice: ecdsa_p256_sha256::encode_signature(&verifying_key, &signature),
        signing_key,
        verifying_key,
        message,
        signature,
        recovery_id,
    }
}

fn fixed_message() -> Word {
    Word::new([
        Felt::new_unchecked(0x0001_0203_0405_0607),
        Felt::new_unchecked(0x0809_0a0b_0c0d_0e0f),
        Felt::new_unchecked(0x1011_1213_1415_1617),
        Felt::new_unchecked(0x1819_1a1b_1c1d_1e1f),
    ])
}

fn wrong_message() -> Word {
    Word::new([
        Felt::new_unchecked(0x0001_0203_0405_0607),
        Felt::new_unchecked(0x0809_0a0b_0c0d_0e0f),
        Felt::new_unchecked(0x1011_1213_1415_1617),
        Felt::new_unchecked(0x1819_1a1b_1c1d_1e20),
    ])
}

/// SHA-256 of the message word's 32 little-endian bytes.
fn word_prehash(message: Word) -> [u8; 32] {
    Sha256::hash(&message.as_bytes()).into()
}

fn public_key_elements(verifying_key: &VerifyingKey) -> [Felt; 16] {
    let point = verifying_key.to_sec1_point(false);
    let x: [u8; 32] = point.x().expect("uncompressed").as_slice().try_into().unwrap();
    let y: [u8; 32] = point.y().expect("uncompressed").as_slice().try_into().unwrap();
    let (x, y) = (be_bytes_to_le_limbs(&x), be_bytes_to_le_limbs(&y));
    core::array::from_fn(|i| Felt::from_u32(if i < 8 { x[i] } else { y[i - 8] }))
}

fn scalar_limbs(signature: &Signature) -> ([u32; 8], [u32; 8]) {
    let (r, s) = signature.split_bytes();
    (be_bytes_to_le_limbs(&r.into()), be_bytes_to_le_limbs(&s.into()))
}

fn signature_from_limbs(r: [u32; 8], s: [u32; 8]) -> Signature {
    Signature::from_scalars(le_limbs_to_be_bytes(r), le_limbs_to_be_bytes(s))
        .expect("canonical nonzero scalars must encode")
}

fn native_recovery_signature(signature: &Signature, recovery_id: RecoveryId) -> [Felt; 17] {
    let v = recovery_id.to_byte();
    assert!(v <= 1, "P-256 recovery supports only the parity recovery IDs");
    let (r, s) = scalar_limbs(signature);

    core::array::from_fn(|index| match index {
        0..8 => Felt::from_u32(r[index]),
        8..16 => Felt::from_u32(s[index - 8]),
        16 => Felt::from_u32(u32::from(v)),
        _ => unreachable!(),
    })
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

fn limbs_from_u32(value: u32) -> Limbs {
    core::array::from_fn(|i| if i == 0 { value } else { 0 })
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
    UintDomain::P256Scalar.sub(ZERO_LIMBS, value)
}

fn is_high_s(value: [u32; 8]) -> bool {
    let negated = negate_scalar_mod_n(value);
    value.iter().rev().cmp(negated.iter().rev()).is_gt()
}

/// Reduces a 256-bit value modulo n; one subtraction suffices because n > 2^255.
fn reduce_mod_n(value: Limbs) -> Limbs {
    if UintDomain::P256Scalar.is_canonical(&value) {
        value
    } else {
        UintDomain::U256.sub(value, P256Scalar::MODULUS)
    }
}

fn pow_mod(domain: UintDomain, base: Limbs, exponent: Limbs) -> Limbs {
    let mut acc = ONE_LIMBS;
    for bit in (0..256).rev() {
        acc = domain.mul(acc, acc);
        if (exponent[bit / 32] >> (bit % 32)) & 1 == 1 {
            acc = domain.mul(acc, base);
        }
    }
    acc
}

fn tamper_felt(felt: &mut Felt) {
    let value = felt.as_canonical_u64();
    *felt = if value == 0 {
        Felt::from_u32(1)
    } else {
        Felt::new(value - 1).expect("decremented canonical field element must stay canonical")
    };
}

// RUNNERS
// ================================================================================================

fn run_verify(fixture: &Fixture) -> Result<ExecutionOutput, ExecutionError> {
    run_verify_with(fixture.message, fixture.public_key_commitment, &fixture.advice)
}

fn run_verify_with(
    message: Word,
    public_key_commitment: Word,
    advice: &[Felt],
) -> Result<ExecutionOutput, ExecutionError> {
    let source = format!(
        r#"
        begin
            {message}
            {pk_comm}
            exec.::miden::core::crypto::dsa::ecdsa_p256_sha256::verify
        end
        "#,
        message = masm_push_word(&message),
        pk_comm = masm_push_word(&public_key_commitment),
    );

    run_core_program(&source, advice, None)
}

fn run_verify_bytes(message: &[u8]) -> Result<ExecutionOutput, ExecutionError> {
    run_verify_bytes_with_memory(message, &bytes_to_packed_u32_elements(message), None)
}

/// Signs `message` and verifies it with `memory` stored at the message pointer.
fn run_verify_bytes_with_memory(
    message: &[u8],
    memory: &[Felt],
    handler: Option<HandlerOverride>,
) -> Result<ExecutionOutput, ExecutionError> {
    let signing_key = signing_key();
    let verifying_key = signing_key.verifying_key();
    let prehash: [u8; 32] = Sha256::hash(message).into();
    let (signature, _) = signing_key.sign_prehash_recoverable(&prehash);
    verifying_key
        .verify_prehash(&prehash, &signature)
        .expect("Rust prehash signature must verify before passing it to MASM");

    let source = format!(
        r#"
        begin
            {stores}
            push.{len_bytes}
            push.{MESSAGE_PTR}
            {pk_comm}
            exec.::miden::core::crypto::dsa::ecdsa_p256_sha256::verify_bytes
        end
        "#,
        stores = masm_store_felts(memory, MESSAGE_PTR),
        len_bytes = message.len(),
        pk_comm = masm_push_word(&ecdsa_p256_sha256::public_key_commitment(verifying_key)),
    );

    run_core_program(
        &source,
        &ecdsa_p256_sha256::encode_signature(verifying_key, &signature),
        handler,
    )
}

fn run_recover(fixture: &Fixture) -> Result<ExecutionOutput, ExecutionError> {
    run_recover_with_native_signature(
        fixture.message,
        &native_recovery_signature(&fixture.signature, fixture.recovery_id),
        SIGNATURE_PTR,
        None,
    )
}

fn run_recover_with_native_signature(
    message: Word,
    signature: &[Felt; 17],
    signature_ptr: u32,
    handler: Option<HandlerOverride>,
) -> Result<ExecutionOutput, ExecutionError> {
    let source = format!(
        r#"
        begin
            {stores}
            push.{signature_ptr}
            {message}
            exec.::miden::core::crypto::dsa::ecdsa_p256_sha256::recover
            exec.::miden::core::sys::truncate_stack
        end
        "#,
        stores = masm_store_felts(signature, signature_ptr),
        message = masm_push_word(&message),
    );

    run_core_program(&source, &[], handler)
}

fn run_recover_bytes(
    message: &[u8],
    signature: &[Felt; 17],
) -> Result<ExecutionOutput, ExecutionError> {
    let source = format!(
        r#"
        begin
            {message_stores}
            {signature_stores}
            push.{SIGNATURE_PTR}
            push.{len_bytes}
            push.{MESSAGE_PTR}
            exec.::miden::core::crypto::dsa::ecdsa_p256_sha256::recover_bytes
            exec.::miden::core::sys::truncate_stack
        end
        "#,
        message_stores = masm_store_felts(&bytes_to_packed_u32_elements(message), MESSAGE_PTR),
        signature_stores = masm_store_felts(signature, SIGNATURE_PTR),
        len_bytes = message.len(),
    );

    run_core_program(&source, &[], None)
}

/// A replacement for one default core-library event handler.
type HandlerOverride = (EventName, Arc<dyn EventHandler>);

fn run_core_program(
    source: &str,
    advice: &[Felt],
    handler: Option<HandlerOverride>,
) -> Result<ExecutionOutput, ExecutionError> {
    let core_lib = CoreLibrary::default();
    let program = Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("failed to link core library")
        .assemble_program("core_ecdsa_p256_sha256_test", source)
        .expect("failed to assemble core ECDSA P-256 test program")
        .unwrap_program();

    let mut host = DefaultHost::default()
        .with_library(&core_lib)
        .expect("failed to load CoreLibrary into the host");
    if let Some((event, handler)) = handler {
        let message = format!("the default {event} handler must already be registered");
        assert!(host.replace_handler(event, handler), "{message}");
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

fn recovery_public_key_handler(public_key: [Felt; 16]) -> HandlerOverride {
    (ECDSA_P256_SHA256_RECOVER_EVENT_NAME, advice_handler(public_key.to_vec()))
}

/// Supplies SHA-256(`message`) regardless of the memory the procedure hashes.
fn sha256_digest_handler(message: &[u8]) -> HandlerOverride {
    let digest: [u8; 32] = Sha256::hash(message).into();
    (SHA256_DIGEST_EVENT_NAME, advice_handler(bytes_to_packed_u32_elements(&digest)))
}

fn advice_handler(elements: Vec<Felt>) -> Arc<dyn EventHandler> {
    Arc::new(move |_process: &ProcessorState| -> Result<Vec<AdviceMutation>, EventError> {
        let mut advice_stack = AdviceStack::new();
        advice_stack.append_for_adv_pipe(&elements);
        Ok(vec![AdviceMutation::extend_advice_stack(advice_stack)])
    })
}

fn assert_deferred_proof_verifies(output: &ExecutionOutput) {
    let proof = prove_precompiles(
        vec![output.precompile_witness.clone().expect("execution has deferred work")],
        HashFunction::Eidos,
    )
    .expect("the deferred claims must be provable");
    verify_deferred(&proof.proof, output.precompile_root())
        .expect("the deferred proof must verify against the committed root");
}

fn stack_elements<const N: usize>(output: &ExecutionOutput) -> [Felt; N] {
    core::array::from_fn(|index| output.stack.get_element(index).expect("stack output element"))
}

fn is_failed_assertion(err: &ExecutionError, message: &str) -> bool {
    matches!(
        err,
        ExecutionError::OperationError {
            err: OperationError::FailedAssertion { err_code, .. },
            ..
        } if *err_code == error_code_from_msg(message)
    )
}

fn assert_failed_assertion(result: Result<ExecutionOutput, ExecutionError>, message: &str) {
    let err = result.expect_err(message);
    assert!(is_failed_assertion(&err, message), "expected `{message}`, got {err:?}");
}
