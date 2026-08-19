use std::sync::Arc;

use miden_assembly::{Assembler, Linkage};
use miden_core::{
    Felt, Word,
    deferred::{DeferredError, DeferredState, PrecompileError},
    serde::{Deserializable, Serializable},
    utils::{bytes_to_packed_u32_elements, packed_u32_elements_to_bytes},
};
use miden_core_lib::{
    CoreLibrary, dsa::ecdsa_k256_keccak, handlers::ecrecover::ECRECOVER_EVENT_NAME,
};
use miden_crypto::{
    SequentialCommit,
    dsa::ecdsa_k256_keccak::{PublicKey, Signature, SigningKey},
    hash::keccak::Keccak256,
    utils::hex_to_bytes,
};
use miden_precompiles::{K1Scalar, SECP256K1_LAMBDA, scalar_mul_mod_n};
use miden_precompiles_prover::{HashFunction, prove_deferred_state, verify_deferred};
use miden_processor::{
    DefaultHost, ExecutionError, ExecutionOptions, ExecutionOutput, FastProcessor, ProcessorState,
    StackInputs,
    advice::{AdviceInputs, AdviceMutation, AdviceStack},
    event::{EventError, EventHandler},
};
use miden_utils_testing::crypto::Poseidon2;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

use crate::helpers::masm_store_felts;

// Core invokes the separately packaged precompile wrappers through dynamic MAST calls.
const VERIFY_EXPECTED_CYCLES: u64 = 1_587;
const VERIFY_EXPECTED_WIRE_BYTES: usize = 2_455;
const MESSAGE_PTR: u32 = 128;
const ECRECOVER_INPUT_PTR: u32 = 256;

#[test]
fn core_ecdsa_k256_keccak_ecrecover_returns_ethereum_address() {
    // Vector from Ethereum's CallEcrecover0 consensus test:
    // https://github.com/ethereum/execution-spec-tests/blob/62035359cc4bd2d326844188f2003d29f6be1d97/tests/static/state_tests/stPreCompiledContracts2/CallEcrecover0Filler.json
    let input = hex_to_bytes(concat!(
        "0x18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c",
        "000000000000000000000000000000000000000000000000000000000000001c",
        "73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f",
        "eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549",
    ))
    .expect("Ethereum ECRECOVER input vector must be valid hex");
    let expected_address: [Felt; 8] = bytes_to_packed_u32_elements(
        &hex_to_bytes::<32>("0x000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b")
            .expect("Ethereum address vector must be valid hex"),
    )
    .try_into()
    .expect("an Ethereum address result has eight packed elements");

    let output = run_ecrecover(&input)
        .expect("valid Ethereum-shaped ECRECOVER input must recover an address");
    assert_eq!(stack_elements(&output), expected_address);
    assert_deferred_state_round_trips(&output);

    assert_deferred_proof_verifies(&output);
}

#[test]
fn core_ecdsa_k256_keccak_ecrecover_accepts_high_s() {
    let mut fixture = ecrecover_fixture([0x36; 32], [0xb8; 32]);
    let low_s = be_bytes_to_le_limbs(fixture.signature.s());
    assert!(!is_high_s(low_s), "miden-crypto signer must produce low-s");
    let high_s_signature = signature_with_s(&fixture.signature, negate_scalar_mod_n(low_s));
    fixture.input = ecrecover_input([0xb8; 32], &high_s_signature);

    let output = run_ecrecover(&fixture.input)
        .expect("high-s ECRECOVER input with flipped recovery parity must succeed");
    assert_eq!(stack_elements(&output), fixture.expected_address);
}

#[test]
fn core_ecdsa_k256_keccak_ecrecover_accepts_zero_prehash() {
    let fixture = ecrecover_fixture([0x37; 32], [0; 32]);

    let output =
        run_ecrecover(&fixture.input).expect("z mod n = 0 must use the single-base recovery path");
    assert_eq!(stack_elements(&output), fixture.expected_address);

    assert_deferred_proof_verifies(&output);
}

#[test]
fn core_ecdsa_k256_keccak_ecrecover_traps_on_invalid_v() {
    let fixture = ecrecover_fixture([0x38; 32], [0xc9; 32]);

    for v in [0, 1, 26, 29] {
        let mut input = fixture.input;
        input[63] = v;
        assert!(run_ecrecover(&input).is_err(), "v={v} must trap");
    }

    let mut nonzero_prefix = fixture.input;
    nonzero_prefix[32] = 1;
    run_ecrecover(&nonzero_prefix)
        .expect_err("a nonzero high byte in the 32-byte v word must trap");

    for recovery_id in 2..=3 {
        let signature = Signature::from_sec1_bytes_and_recovery_id(
            fixture.signature.to_sec1_bytes(),
            recovery_id,
        )
        .expect("recovery ID must be valid for a generic recoverable signature");
        assert!(ecdsa_k256_keccak::encode_ecrecover_input([0; 32], &signature).is_none());
    }
}

#[test]
fn core_ecdsa_k256_keccak_ecrecover_traps_on_unaligned_input() {
    let fixture = ecrecover_fixture([0x3b; 32], [0x9d; 32]);

    run_ecrecover_at(&fixture.input, ECRECOVER_INPUT_PTR + 1)
        .expect_err("an unaligned ECRECOVER input pointer must trap");
}

#[test]
fn core_ecdsa_k256_keccak_ecrecover_traps_on_invalid_scalars() {
    let fixture = ecrecover_fixture([0x39; 32], [0xda; 32]);

    let modulus = le_limbs_to_be_bytes(K1Scalar::MODULUS);
    for (name, offset, scalar, is_noncanonical) in [
        ("r = 0", 64, [0; 32], false),
        ("s = 0", 96, [0; 32], false),
        ("r = n", 64, modulus, true),
        ("s = n", 96, modulus, true),
    ] {
        let mut input = fixture.input;
        input[offset..offset + 32].copy_from_slice(&scalar);
        let error = run_ecrecover_with_handler(&input, Arc::new(push_wrong_ecrecover_public_key))
            .expect_err(&format!("{name} must trap"));
        if is_noncanonical {
            assert_invalid_deferred_payload(error);
        }
    }
}

#[test]
fn core_ecdsa_k256_keccak_ecrecover_rejects_forged_public_key_advice() {
    let fixture = ecrecover_fixture([0x3a; 32], [0xeb; 32]);

    run_ecrecover_with_handler(&fixture.input, Arc::new(push_wrong_ecrecover_public_key))
        .expect_err("a valid but unrelated public-key witness must not satisfy recovery");
}

#[test]
fn core_ecdsa_k256_keccak_verify_accepts_valid_signature() {
    let fixture = valid_fixture();

    let output = run_verify(&fixture).expect("valid core ECDSA K256/Keccak signature must verify");
    assert_deferred_state_round_trips(&output);

    let wire = output.deferred_state.to_wire().expect("deferred state must encode to wire");
    assert_eq!(wire.to_bytes().len(), VERIFY_EXPECTED_WIRE_BYTES);
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

    let proof = prove_deferred_state(&output.deferred_state, HashFunction::Blake3_256)
        .expect("the GLV-decomposed deferred claims must be provable");
    verify_deferred(&proof, output.deferred_state.root())
        .expect("the GLV-decomposed deferred proof must verify against the committed root");
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
    assert_eq!(cycles, VERIFY_EXPECTED_CYCLES);
}

#[test]
fn core_ecdsa_k256_keccak_verify_traps_on_wrong_pk_comm() {
    let mut fixture = valid_fixture();
    tamper_felt(&mut fixture.pk_comm[0]);

    run_verify(&fixture).expect_err("wrong public key commitment must trap");
}

#[test]
fn core_ecdsa_k256_keccak_verify_traps_on_off_curve_public_key() {
    let mut fixture = valid_fixture();
    fixture.advice[8..16].copy_from_slice(&[Felt::from_u32(0); 8]);
    fixture.pk_comm = Poseidon2::hash_elements(&fixture.advice[..16]);

    run_verify(&fixture).expect_err("off-curve public key advice must trap");
}

#[test]
fn core_ecdsa_k256_keccak_verify_traps_on_non_u32_limb() {
    let non_u32 = Felt::new(u32::MAX as u64 + 1).expect("2^32 must fit in the VM field");

    let mut pubkey_fixture = valid_fixture();
    pubkey_fixture.advice[0] = non_u32;
    pubkey_fixture.pk_comm = Poseidon2::hash_elements(&pubkey_fixture.advice[..16]);
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
    fixture.pk_comm = ecdsa_k256_keccak::public_key_commitment(&wrong_public_key);

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

struct Fixture {
    public_key: PublicKey,
    signature: Signature,
    pk_comm: Word,
    message: Word,
    advice: Vec<Felt>,
}

struct EcrecoverFixture {
    signature: Signature,
    input: [u8; 128],
    expected_address: [Felt; 8],
}

fn ecrecover_fixture(signing_key_seed: [u8; 32], prehash: [u8; 32]) -> EcrecoverFixture {
    let mut rng = ChaCha20Rng::from_seed(signing_key_seed);
    let signing_key = SigningKey::with_rng(&mut rng);
    let public_key = signing_key.public_key();
    let signature = signing_key.sign_prehash(prehash);
    assert!(
        public_key.verify_prehash(prehash, &signature),
        "Rust prehash signature must verify before passing it to MASM",
    );
    let input = ecrecover_input(prehash, &signature);

    EcrecoverFixture {
        input,
        expected_address: ethereum_address_felts(&public_key),
        signature,
    }
}

fn ecrecover_input(prehash: [u8; 32], signature: &Signature) -> [u8; 128] {
    let input = ecdsa_k256_keccak::encode_ecrecover_input(prehash, signature)
        .expect("test signatures must use an Ethereum recovery ID");
    packed_u32_elements_to_bytes(&input)
        .try_into()
        .expect("ECRECOVER input must contain 128 bytes")
}

fn ethereum_address_felts(public_key: &PublicKey) -> [Felt; 8] {
    let coordinates = public_key_elements(public_key);
    let mut uncompressed = [0u8; 64];
    for coordinate_index in 0..2 {
        for limb_index in 0..8 {
            let limb: u32 = coordinates[coordinate_index * 8 + limb_index]
                .as_canonical_u64()
                .try_into()
                .expect("public-key coordinate limbs are u32");
            let byte_offset = coordinate_index * 32 + (7 - limb_index) * 4;
            uncompressed[byte_offset..byte_offset + 4].copy_from_slice(&limb.to_be_bytes());
        }
    }

    let digest: [u8; 32] = Keccak256::hash(&uncompressed).into();
    let mut address = [0u8; 32];
    address[12..].copy_from_slice(&digest[12..]);
    bytes_to_packed_u32_elements(&address)
        .try_into()
        .expect("an Ethereum address result has eight packed elements")
}

fn valid_fixture() -> Fixture {
    fixture_from_signing_key(default_signing_key())
}

fn default_signing_key() -> SigningKey {
    let mut rng = ChaCha20Rng::from_seed([0xe5; 32]);
    SigningKey::with_rng(&mut rng)
}

fn generator_public_key_fixture() -> Fixture {
    let mut secret_key_bytes = [0u8; 32];
    secret_key_bytes[31] = 1;
    let sk = SigningKey::read_from_bytes(&secret_key_bytes).expect("scalar 1 is a valid key");

    fixture_from_signing_key(sk)
}

fn fixture_from_signing_key(sk: SigningKey) -> Fixture {
    let message = fixed_message();
    let public_key = sk.public_key();
    let signature = sk.sign(message);

    assert!(
        public_key.verify(message, &signature),
        "Rust fixture signature must verify before passing it to MASM",
    );

    let pk_comm = ecdsa_k256_keccak::public_key_commitment(&public_key);
    let advice = ecdsa_k256_keccak::encode_signature(&public_key, &signature);

    Fixture {
        public_key,
        signature,
        pk_comm,
        message,
        advice,
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

fn run_ecrecover(input: &[u8; 128]) -> Result<ExecutionOutput, ExecutionError> {
    run_ecrecover_at(input, ECRECOVER_INPUT_PTR)
}

fn run_ecrecover_at(input: &[u8; 128], input_ptr: u32) -> Result<ExecutionOutput, ExecutionError> {
    run_ecrecover_with_optional_handler(input, input_ptr, None)
}

fn run_ecrecover_with_handler(
    input: &[u8; 128],
    handler: Arc<dyn EventHandler>,
) -> Result<ExecutionOutput, ExecutionError> {
    run_ecrecover_with_optional_handler(input, ECRECOVER_INPUT_PTR, Some(handler))
}

fn run_ecrecover_with_optional_handler(
    input: &[u8; 128],
    input_ptr: u32,
    handler: Option<Arc<dyn EventHandler>>,
) -> Result<ExecutionOutput, ExecutionError> {
    let input_felts = bytes_to_packed_u32_elements(input);
    let stores = masm_store_felts(&input_felts, input_ptr);
    let source = format!(
        r#"
        begin
            {stores}
            push.{input_ptr}
            exec.::miden::core::crypto::dsa::ecdsa_k256_keccak::ecrecover
            exec.::miden::core::sys::truncate_stack
        end
        "#,
    );

    run_core_program(&source, &[], handler)
}

fn stack_elements<const N: usize>(output: &ExecutionOutput) -> [Felt; N] {
    core::array::from_fn(|index| output.stack.get_element(index).expect("stack output element"))
}

fn assert_deferred_proof_verifies(output: &ExecutionOutput) {
    let proof = prove_deferred_state(&output.deferred_state, HashFunction::Blake3_256)
        .expect("ECRECOVER deferred claims must be provable");
    verify_deferred(&proof, output.deferred_state.root())
        .expect("ECRECOVER deferred proof must verify against the committed root");
}

fn assert_invalid_deferred_payload(error: ExecutionError) {
    let ExecutionError::DeferredError { err, .. } = error else {
        panic!("expected deferred invalid-payload error, got {error:?}");
    };
    assert!(matches!(err.root(), PrecompileError::Other(DeferredError::InvalidPayload)));
}

#[allow(clippy::unnecessary_wraps)]
fn push_wrong_ecrecover_public_key(
    _process: &ProcessorState<'_>,
) -> Result<Vec<AdviceMutation>, EventError> {
    let mut rng = ChaCha20Rng::from_seed([0xfc; 32]);
    let wrong_public_key = SigningKey::with_rng(&mut rng).public_key();
    let mut advice_stack = AdviceStack::new();
    advice_stack.append_for_adv_pipe(&public_key_elements(&wrong_public_key));
    Ok(vec![AdviceMutation::extend_advice_stack(advice_stack)])
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
    let pk_comm = masm_push_word(&fixture.pk_comm);

    format!(
        r#"
        {message}
        {pk_comm}
        "#,
    )
}

fn masm_push_word(word: &Word) -> String {
    let felts = word
        .iter()
        .rev()
        .map(|felt| felt.as_canonical_u64().to_string())
        .collect::<Vec<_>>()
        .join(".");
    format!("push.{felts}")
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
    ecrecover_handler: Option<Arc<dyn EventHandler>>,
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
    if let Some(handler) = ecrecover_handler {
        assert!(
            host.replace_handler(ECRECOVER_EVENT_NAME, handler),
            "the default ECRECOVER handler must already be registered",
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

fn tamper_felt(felt: &mut Felt) {
    let value = felt.as_canonical_u64();
    *felt = if value == 0 {
        Felt::from_u32(1)
    } else {
        Felt::new(value - 1).expect("decremented canonical field element must stay canonical")
    };
}
