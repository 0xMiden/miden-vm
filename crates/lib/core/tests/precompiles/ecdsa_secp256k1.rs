use miden_core::Felt;
use miden_crypto::{
    SequentialCommit,
    dsa::ecdsa_k256_keccak::{PublicKey, Signature, SigningKey},
};
use miden_precompiles::{CurvePrecompile, K1Scalar};
use miden_processor::ExecutionOutput;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

use super::helpers::{
    assert_deferred_state_round_trips, masm_store_felts, read_stack_felts, run_precompile_program,
};

const PUBKEY_PTR: u32 = 128;
const DIGEST_PTR: u32 = PUBKEY_PTR + 16;
const SIG_PTR: u32 = DIGEST_PTR + 8;
const ASSERT_VERIFY_PREHASH_EXPECTED_CYCLES: u64 = 1_085;

#[test]
fn assert_verify_prehash_accepts_valid_signature() {
    let fixture = valid_prehash_fixture();

    let output = run_precompile_program(&assert_verify_prehash_source(&fixture))
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
    let non_u32 = Felt::new(u32::MAX as u64 + 1).expect("2^32 must fit in the VM field");

    let mut digest_fixture = valid_prehash_fixture();
    digest_fixture.digest[0] = non_u32;
    expect_assert_verify_trap(&digest_fixture);

    let mut r_fixture = valid_prehash_fixture();
    r_fixture.signature[0] = non_u32;
    expect_assert_verify_trap(&r_fixture);

    let mut s_fixture = valid_prehash_fixture();
    s_fixture.signature[8] = non_u32;
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
    let mut rng = ChaCha20Rng::from_seed([0xa5; 32]);
    let wrong_pubkey = public_key_felts(&SigningKey::with_rng(&mut rng).public_key());
    assert_ne!(fixture.pubkey, wrong_pubkey, "deterministic wrong key should differ");
    fixture.pubkey = wrong_pubkey;

    expect_assert_verify_trap(&fixture);
}

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
        pubkey: public_key_felts(&public_key),
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

fn public_key_felts(public_key: &PublicKey) -> [Felt; 16] {
    public_key
        .to_elements()
        .try_into()
        .expect("public key must encode as QX[8] || QY[8]")
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

fn flip_low_bit(felt: &mut Felt) {
    let value: u32 = felt.as_canonical_u64().try_into().expect("fixture limb must fit in u32");
    *felt = Felt::from_u32(value ^ 1);
}

fn expect_assert_verify_trap(fixture: &EcdsaPrehashFixture) {
    run_precompile_program(&assert_verify_prehash_source(fixture))
        .expect_err("invalid verifier fixture must trap");
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
