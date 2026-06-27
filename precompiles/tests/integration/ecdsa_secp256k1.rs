use miden_core::{Felt, serde::Serializable};
use miden_crypto::dsa::ecdsa_k256_keccak::{Signature, SigningKey};
use miden_precompiles::{CurveId, CurvePoint, CurvePrecompile, K1Base, K1Scalar, Limbs, UintSpec};
use miden_processor::{ExecutionError, ExecutionOutput};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

use crate::helpers::{
    assert_deferred_state_round_trips, masm_store_felts, read_stack_felts, run_precompile_program,
};

const PUBKEY_PTR: u32 = 128;
const DIGEST_PTR: u32 = PUBKEY_PTR + 16;
const SIG_PTR: u32 = DIGEST_PTR + 8;
const ASSERT_VERIFY_PREHASH_EXPECTED_CYCLES: u64 = 1_446;

#[test]
fn assert_verify_prehash_accepts_valid_signature() {
    let fixture = valid_prehash_fixture();

    let output = run_assert_verify_prehash(&fixture)
        .expect("valid secp256k1 ECDSA prehash signature must verify");
    assert_deferred_state_round_trips(&output);
}

#[test]
fn assert_verify_prehash_cycle_baseline() {
    let fixture = valid_prehash_fixture();

    let output = run_precompile_program(&assert_verify_prehash_cycle_source(&fixture))
        .expect("valid secp256k1 ECDSA prehash signature must verify");
    let cycles = read_stack_felts(&output, 1)[0].as_canonical_u64();
    assert_eq!(cycles, ASSERT_VERIFY_PREHASH_EXPECTED_CYCLES);
    assert_eq!(curve_op_count(&output, CurvePrecompile::MSM_OP_ID), 1);
    assert_eq!(curve_op_count(&output, CurvePrecompile::ADD_OP_ID), 0);
    assert_deferred_state_round_trips(&output);
}

#[test]
fn assert_verify_prehash_traps_on_off_curve_public_key() {
    let mut fixture = valid_prehash_fixture();
    fixture.pubkey[8..16].copy_from_slice(&[Felt::from_u32(0); 8]);

    expect_assert_verify_trap(&fixture);
}

#[test]
fn assert_verify_prehash_traps_on_non_u32_limb() {
    let mut digest_fixture = valid_prehash_fixture();
    digest_fixture.digest[0] = non_u32_felt();
    expect_assert_verify_trap(&digest_fixture);

    let mut r_fixture = valid_prehash_fixture();
    r_fixture.signature[0] = non_u32_felt();
    expect_assert_verify_trap(&r_fixture);

    let mut s_fixture = valid_prehash_fixture();
    s_fixture.signature[8] = non_u32_felt();
    expect_assert_verify_trap(&s_fixture);
}

#[test]
fn assert_verify_prehash_traps_on_noncanonical_signature_scalar() {
    let mut r_fixture = valid_prehash_fixture();
    r_fixture.set_r(K1Scalar::MODULUS);
    expect_assert_verify_trap(&r_fixture);

    let mut s_fixture = valid_prehash_fixture();
    s_fixture.set_s(K1Scalar::MODULUS);
    expect_assert_verify_trap(&s_fixture);
}

#[test]
fn assert_verify_prehash_traps_on_zero_signature_scalar() {
    let mut r_fixture = valid_prehash_fixture();
    r_fixture.set_r([0; 8]);
    expect_assert_verify_trap(&r_fixture);

    let mut s_fixture = valid_prehash_fixture();
    s_fixture.set_s([0; 8]);
    expect_assert_verify_trap(&s_fixture);
}

#[test]
fn assert_verify_prehash_traps_on_tampered_digest() {
    let mut fixture = valid_prehash_fixture();
    flip_low_bit(&mut fixture.digest[0]);

    expect_assert_verify_trap(&fixture);
}

#[test]
fn assert_verify_prehash_traps_on_tampered_signature() {
    let mut fixture = valid_prehash_fixture();
    flip_low_bit(&mut fixture.signature[0]);

    expect_assert_verify_trap(&fixture);
}

#[test]
fn assert_verify_prehash_traps_on_valid_but_wrong_public_key() {
    let mut fixture = valid_prehash_fixture();
    let generator = generator_pubkey_felts();
    assert_ne!(fixture.pubkey, generator, "deterministic test key should not be the generator");
    fixture.pubkey = generator;

    expect_assert_verify_trap(&fixture);
}

#[derive(Clone)]
struct EcdsaPrehashFixture {
    pubkey: [Felt; 16],
    digest: [Felt; 8],
    signature: [Felt; 16],
}

impl EcdsaPrehashFixture {
    fn set_r(&mut self, limbs: [u32; 8]) {
        self.signature[..8].copy_from_slice(&limbs_to_felts(limbs));
    }

    fn set_s(&mut self, limbs: [u32; 8]) {
        self.signature[8..].copy_from_slice(&limbs_to_felts(limbs));
    }
}

fn valid_prehash_fixture() -> EcdsaPrehashFixture {
    let mut rng = ChaCha20Rng::from_seed([0xe5; 32]);
    let sk = SigningKey::with_rng(&mut rng);
    let digest = [0x42u8; 32];
    let public_key = sk.public_key();
    let signature = sk.sign_prehash(digest);

    assert!(
        public_key.verify_prehash(digest, &signature),
        "Rust fixture signature must verify before passing it to MASM",
    );

    EcdsaPrehashFixture {
        pubkey: decompress_public_key(&public_key.to_bytes()),
        digest: limbs_to_felts(be_bytes_to_le_limbs(&digest)),
        signature: signature_felts(&signature),
    }
}

fn signature_felts(signature: &Signature) -> [Felt; 16] {
    let mut felts = [Felt::from_u32(0); 16];
    felts[..8].copy_from_slice(&limbs_to_felts(be_bytes_to_le_limbs(signature.r())));
    felts[8..].copy_from_slice(&limbs_to_felts(be_bytes_to_le_limbs(signature.s())));
    felts
}

fn decompress_public_key(compressed: &[u8]) -> [Felt; 16] {
    assert_eq!(compressed.len(), 33, "fixture public key must be compressed SEC1");
    let prefix = compressed[0];
    assert!(matches!(prefix, 0x02 | 0x03), "unexpected compressed SEC1 prefix");

    let x_bytes = compressed[1..].try_into().expect("x coordinate length");
    let x = be_bytes_to_le_limbs(x_bytes);
    assert!(K1Base::is_canonical(&x), "public key x is canonical");
    let rhs = K1Base::add(K1Base::mul(K1Base::mul(x, x), x), k1_base_from_u32(7));
    let mut y = sqrt_k1_base(rhs);
    let should_be_odd = prefix == 0x03;
    if (y[0] & 1 != 0) != should_be_odd {
        y = K1Base::sub([0; 8], y);
    }

    let mut felts = [Felt::from_u32(0); 16];
    felts[..8].copy_from_slice(&limbs_to_felts(x));
    felts[8..].copy_from_slice(&limbs_to_felts(y));
    felts
}

fn sqrt_k1_base(value: Limbs) -> Limbs {
    let root = pow_k1_base(value, secp256k1_p_plus_one_over_four());
    assert_eq!(K1Base::mul(root, root), value, "fixture public key y coordinate must exist");
    root
}

fn pow_k1_base(base: Limbs, exponent: Limbs) -> Limbs {
    let mut result = [1, 0, 0, 0, 0, 0, 0, 0];
    for limb in exponent.into_iter().rev() {
        for bit in (0..32).rev() {
            result = K1Base::mul(result, result);
            if (limb >> bit) & 1 == 1 {
                result = K1Base::mul(result, base);
            }
        }
    }
    result
}

fn secp256k1_p_plus_one_over_four() -> Limbs {
    let mut p_plus_one = K1Base::MODULUS;
    let mut carry = 1u64;
    for limb in &mut p_plus_one {
        let sum = *limb as u64 + carry;
        *limb = sum as u32;
        carry = sum >> 32;
        if carry == 0 {
            break;
        }
    }
    debug_assert_eq!(carry, 0);

    let mut shifted = [0u32; 8];
    let mut carry_bits = 0u32;
    for i in (0..8).rev() {
        shifted[i] = (p_plus_one[i] >> 2) | (carry_bits << 30);
        carry_bits = p_plus_one[i] & 0b11;
    }
    debug_assert_eq!(carry_bits, 0, "p + 1 must be divisible by four");
    shifted
}

fn k1_base_from_u32(value: u32) -> Limbs {
    let mut limbs = [0; 8];
    limbs[0] = value;
    assert!(K1Base::is_canonical(&limbs), "small base-field element is canonical");
    limbs
}

fn be_bytes_to_le_limbs(bytes: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|i| {
        let offset = bytes.len() - (i + 1) * 4;
        u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("u32 limb"))
    })
}

fn limbs_to_felts<const N: usize>(limbs: [u32; N]) -> [Felt; N] {
    limbs.map(Felt::from_u32)
}

fn non_u32_felt() -> Felt {
    Felt::new(u32::MAX as u64 + 1).expect("2^32 must fit in the VM field")
}

fn flip_low_bit(felt: &mut Felt) {
    let value: u32 = felt.as_canonical_u64().try_into().expect("fixture limb must fit in u32");
    *felt = Felt::from_u32(value ^ 1);
}

fn generator_pubkey_felts() -> [Felt; 16] {
    let CurvePoint::Affine { x, y } = CurveId::Secp256k1.generator() else {
        unreachable!("secp256k1 generator is affine");
    };

    let mut felts = [Felt::from_u32(0); 16];
    felts[..8].copy_from_slice(&limbs_to_felts(x));
    felts[8..].copy_from_slice(&limbs_to_felts(y));
    felts
}

fn run_assert_verify_prehash(
    fixture: &EcdsaPrehashFixture,
) -> Result<ExecutionOutput, ExecutionError> {
    run_precompile_program(&assert_verify_prehash_source(fixture))
}

fn expect_assert_verify_trap(fixture: &EcdsaPrehashFixture) -> ExecutionError {
    run_assert_verify_prehash(fixture).expect_err("invalid verifier fixture must trap")
}

fn curve_op_count(output: &ExecutionOutput, op_id: u64) -> usize {
    output
        .deferred_state
        .nodes()
        .values()
        .filter(|node| {
            let tag = node.tag();
            tag.id() == CurvePrecompile::id() && tag.args()[0].as_canonical_u64() == op_id
        })
        .count()
}

fn assert_verify_prehash_source(fixture: &EcdsaPrehashFixture) -> String {
    let setup = assert_verify_prehash_setup(fixture);

    format!(
        r#"
        begin
            {setup}
            exec.::miden::precompiles::crypto::dsa::ecdsa_secp256k1::assert_verify_prehash
        end
        "#,
    )
}

fn assert_verify_prehash_cycle_source(fixture: &EcdsaPrehashFixture) -> String {
    let setup = assert_verify_prehash_setup(fixture);

    format!(
        r#"
        begin
            {setup}
            clk
            movdn.3
            exec.::miden::precompiles::crypto::dsa::ecdsa_secp256k1::assert_verify_prehash
            clk
            swap sub
            swap drop
        end
        "#,
    )
}

fn assert_verify_prehash_setup(fixture: &EcdsaPrehashFixture) -> String {
    let pubkey_stores = masm_store_felts(&fixture.pubkey, PUBKEY_PTR);
    let digest_stores = masm_store_felts(&fixture.digest, DIGEST_PTR);
    let signature_stores = masm_store_felts(&fixture.signature, SIG_PTR);

    format!(
        r#"
        {pubkey_stores}
        {digest_stores}
        {signature_stores}

        push.{SIG_PTR}
        push.{DIGEST_PTR}
        push.{PUBKEY_PTR}
        "#,
    )
}
