use miden_core::{Felt, utils::bytes_to_packed_u32_elements};
use miden_precompiles::{CurvePrecompile, Ed25519Scalar, Limbs};
use miden_processor::{ExecutionError, ExecutionOutput};

use crate::helpers::{
    assert_deferred_state_round_trips, masm_store_felts, read_stack_felts, run_precompile_program,
};

const A_PTR: u32 = 128;
const SIG_PTR: u32 = A_PTR + 16;
const R_PTR: u32 = SIG_PTR;
const S_PTR: u32 = SIG_PTR + 16;
const MSG_PTR: u32 = SIG_PTR + 24;
const ASSERT_VERIFY_EXPECTED_CYCLES: u64 = 1_402;

const FIXED_MESSAGE: [u8; 32] = [
    0xa5, 0xa8, 0xab, 0xae, 0xb1, 0xb4, 0xb7, 0xba, 0xbd, 0xc0, 0xc3, 0xc6, 0xc9, 0xcc, 0xcf, 0xd2,
    0xd5, 0xd8, 0xdb, 0xde, 0xe1, 0xe4, 0xe7, 0xea, 0xed, 0xf0, 0xf3, 0xf6, 0xf9, 0xfc, 0xff, 0x02,
];

const A_X: Limbs = [
    0xf196_f769,
    0x550a_b2e3,
    0x09b5_0e41,
    0x50ea_cc04,
    0x5694_c542,
    0xf4c8_4d07,
    0x0c9f_8983,
    0x663f_be98,
];

const A_Y: Limbs = [
    0x1069_5688,
    0x745a_b4cd,
    0xecde_63a3,
    0xdd94_e244,
    0x49f1_f1b6,
    0xfac5_42d8,
    0x1314_f27f,
    0x3a14_10af,
];

const R_X: Limbs = [
    0x56df_a62a,
    0xec6b_da23,
    0xe6b5_bebc,
    0x6816_ffc0,
    0x6161_1c5d,
    0x8a9c_a483,
    0xa4d4_eb34,
    0x2a2e_0fde,
];

const R_Y: Limbs = [
    0x316e_f152,
    0xd9d3_8e73,
    0xa377_5e5e,
    0x9167_48e2,
    0xbb7e_d0cc,
    0x6c1f_c00f,
    0xec8f_617e,
    0x07da_3899,
];

const S: Limbs = [
    0xd431_1936,
    0xb547_6910,
    0x65dd_d83d,
    0xc6be_886c,
    0x3cf4_956a,
    0x085d_c6c7,
    0x9aeb_7fcd,
    0x0478_9830,
];

#[test]
fn assert_verify_accepts_fixed_message_signature() {
    let fixture = fixed_message_fixture();

    let output = run_assert_verify(&fixture).expect("fixed-message Ed25519 signature must verify");
    assert_deferred_state_round_trips(&output);
}

#[test]
fn assert_verify_cycle_baseline() {
    let fixture = fixed_message_fixture();

    let output = run_precompile_program(&assert_verify_cycle_source(&fixture))
        .expect("fixed-message Ed25519 signature must verify");
    let cycles = read_stack_felts(&output, 1)[0].as_canonical_u64();
    assert_eq!(cycles, ASSERT_VERIFY_EXPECTED_CYCLES);
    assert_eq!(curve_op_count(&output, CurvePrecompile::MSM_OP_ID), 1);
    assert_eq!(curve_op_count(&output, CurvePrecompile::ADD_OP_ID), 6);
    assert_deferred_state_round_trips(&output);
}

#[test]
fn assert_verify_traps_on_tampered_message() {
    let mut fixture = fixed_message_fixture();
    fixture.message[0] ^= 0x01;

    expect_assert_verify_trap(&fixture);
}

#[test]
fn assert_verify_traps_on_noncanonical_s() {
    let mut fixture = fixed_message_fixture();
    fixture.s = limbs_to_felts(Ed25519Scalar::MODULUS);

    expect_assert_verify_trap(&fixture);
}

#[test]
fn assert_verify_traps_on_low_order_a_or_r() {
    let mut low_order_a = fixed_message_fixture();
    low_order_a.a = identity_point_felts();
    expect_assert_verify_trap(&low_order_a);

    let mut low_order_r = fixed_message_fixture();
    low_order_r.r = identity_point_felts();
    expect_assert_verify_trap(&low_order_r);
}

#[derive(Clone)]
struct EddsaFixture {
    a: [Felt; 16],
    r: [Felt; 16],
    s: [Felt; 8],
    message: [u8; 32],
}

fn fixed_message_fixture() -> EddsaFixture {
    EddsaFixture {
        a: point_felts(A_X, A_Y),
        r: point_felts(R_X, R_Y),
        s: limbs_to_felts(S),
        message: FIXED_MESSAGE,
    }
}

fn point_felts(x: Limbs, y: Limbs) -> [Felt; 16] {
    let mut felts = [Felt::from_u32(0); 16];
    felts[..8].copy_from_slice(&limbs_to_felts(x));
    felts[8..].copy_from_slice(&limbs_to_felts(y));
    felts
}

fn identity_point_felts() -> [Felt; 16] {
    let mut felts = [Felt::from_u32(0); 16];
    felts[8] = Felt::from_u32(1);
    felts
}

fn limbs_to_felts<const N: usize>(limbs: [u32; N]) -> [Felt; N] {
    limbs.map(Felt::from_u32)
}

fn run_assert_verify(fixture: &EddsaFixture) -> Result<ExecutionOutput, ExecutionError> {
    run_precompile_program(&assert_verify_source(fixture))
}

fn expect_assert_verify_trap(fixture: &EddsaFixture) -> ExecutionError {
    run_assert_verify(fixture).expect_err("invalid Ed25519 verifier fixture must trap")
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

fn assert_verify_source(fixture: &EddsaFixture) -> String {
    let setup = assert_verify_setup(fixture);

    format!(
        r#"
        begin
            {setup}
            exec.::miden::precompiles::crypto::dsa::eddsa_ed25519::assert_verify
        end
        "#,
    )
}

fn assert_verify_cycle_source(fixture: &EddsaFixture) -> String {
    let setup = assert_verify_setup(fixture);

    format!(
        r#"
        begin
            {setup}
            clk
            movdn.3
            exec.::miden::precompiles::crypto::dsa::eddsa_ed25519::assert_verify
            clk
            swap sub
            swap drop
        end
        "#,
    )
}

fn assert_verify_setup(fixture: &EddsaFixture) -> String {
    let a_stores = masm_store_felts(&fixture.a, A_PTR);
    let r_stores = masm_store_felts(&fixture.r, R_PTR);
    let s_stores = masm_store_felts(&fixture.s, S_PTR);
    let message_felts = bytes_to_packed_u32_elements(&fixture.message);
    assert_eq!(message_felts.len(), 8, "fixed Ed25519 message is exactly two words");
    let message_stores = masm_store_felts(&message_felts, MSG_PTR);

    format!(
        r#"
        {a_stores}
        {r_stores}
        {s_stores}
        {message_stores}

        push.{MSG_PTR}
        push.{SIG_PTR}
        push.{A_PTR}
        "#,
    )
}
