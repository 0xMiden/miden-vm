//! Verifier-level negative tests for the generated SZ `u256_modmul_k1_base` MASM proc. Each test
//! installs a custom event handler that returns advice the verifier should reject, then asserts
//! the proc traps.
//!
//! The handler runs the honest witness computation via [`compute_modmul_witness`] (so the
//! tests aren't sensitive to the exact arithmetic), then either tampers one felt of the
//! advice payload before returning it, or synthesizes an alternate witness whose transcript
//! and alpha match the modified payload (for the `c >= p` case).
//!
//! Advice payload layout (114 felts) for the generated SZ verifier:
//!
//! | index range | meaning                                                          |
//! |-------------|------------------------------------------------------------------|
//! | 0           | `alpha[1]`                                                       |
//! | 1           | `alpha[0]`                                                       |
//! | 2..18       | `p` reversed: `p[15]` at 2, `p[0]` at 17                         |
//! | 18..50      | `offset` reversed: `offset[31]` at 18, `offset[0]` at 49         |
//! | 50..66      | `q` reversed: `q[15]` at 50, `q[0]` at 65                        |
//! | 66..82      | `c` reversed: `c[15]` at 66, `c[0]` at 81                        |
//! | 82..114     | `e_shifted` reversed: `e_shifted[31]` at 82, `e_shifted[0]` at 113 |

use alloc::vec::Vec;

use miden_core::Felt;
use miden_core_lib::{
    CoreLibrary,
    handlers::{
        secp256k1_constants::{SECP256K1_BASE_PRIME_U16, SECP256K1_BASE_PRIME_U32},
        u256_modmul::{compute_carry_poly, compute_modmul_witness, derive_alpha},
        u256_modmul_k1::{U256_MODMUL_K1_BASE_EVENT_NAME, handle_u256_modmul_k1_base},
    },
};
use miden_processor::{
    ProcessorState,
    advice::AdviceMutation,
    event::{EventError, EventHandler},
};
use miden_utils_testing::Test;

const MODMUL_SOURCE: &str = "
    use miden::core::math::u256_sz_modmul_k1_base
    use miden::core::sys

    begin
        push.0xdeadbeef.0x12345678.0xcafebabe.0x9abcdef0
        push.0x11111111.0x22222222.0x33333333.0x12345678
        push.0xfedcba98.0x87654321.0xa1b2c3d4.0xe5f60708
        push.0x99887766.0x55443322.0x11ffeedd.0xccbbaa99
        exec.u256_sz_modmul_k1_base::modmul_k1_base
        exec.sys::truncate_stack
    end
";

#[derive(Clone, Copy)]
enum Tamper {
    None,
    Set(u64),
    BumpModU16,
}

struct TamperHandler {
    index: usize,
    tamper: Tamper,
}

impl EventHandler for TamperHandler {
    fn on_event(&self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        let mut muts = handle_u256_modmul_k1_base(process)?;
        for m in &mut muts {
            if let AdviceMutation::ExtendStack { values } = m {
                match self.tamper {
                    Tamper::None => {},
                    Tamper::Set(v) => {
                        values[self.index] = Felt::new(v).expect("tamper value must fit in Felt");
                    },
                    Tamper::BumpModU16 => {
                        let orig = values[self.index].as_canonical_u64() as u32;
                        values[self.index] = Felt::from_u32(orig.wrapping_add(1) & 0xffff);
                    },
                }
            }
        }
        Ok(muts)
    }
}

fn install_handler<H: EventHandler + 'static>(handler: H) -> Test {
    let core_lib = CoreLibrary::default();
    let mut handlers = core_lib.handlers();
    handlers.retain(|(name, _)| name != &U256_MODMUL_K1_BASE_EVENT_NAME);

    miden_utils_testing::build_debug_test!(MODMUL_SOURCE, &[])
        .with_library(core_lib.package())
        .with_event_handlers(handlers)
        .with_event_handler(U256_MODMUL_K1_BASE_EVENT_NAME, handler)
}

fn build_tampered_test(index: usize, tamper: Tamper) -> Test {
    install_handler(TamperHandler { index, tamper })
}

#[test]
fn honest_advice_succeeds() {
    // Sanity check: the harness itself must not break the proc when no tampering occurs.
    let test = build_tampered_test(0, Tamper::None);
    test.execute().expect("honest advice must succeed");
}

#[test]
fn tampered_p_limb_traps_at_commitment_mismatch() {
    // Index 17 is p[0] (lowest-degree limb). The combined pin covers both p and the offset
    // vector, so any modulus felt change trips it.
    let test = build_tampered_test(17, Tamper::BumpModU16);
    test.execute()
        .expect_err("tampered fixed p limb must trap at commitment mismatch");
}

#[test]
fn tampered_offset_limb_traps_at_commitment_mismatch() {
    // Index 49 is offset[0]. Same combined pin as the modulus.
    let test = build_tampered_test(49, Tamper::Set(0));
    test.execute()
        .expect_err("tampered offset limb must trap at commitment mismatch");
}

#[test]
fn tampered_q_limb_traps_at_alpha_mismatch() {
    // Index 65 is q[0]. Bumping by 1 mod 2^16 keeps the felt u16-valid (so u32assertw passes)
    // but changes the witness, so the FS hash disagrees with the claimed alpha.
    let test = build_tampered_test(65, Tamper::BumpModU16);
    test.execute().expect_err("tampered q limb must trap at FS alpha mismatch");
}

#[test]
fn tampered_c_limb_traps_at_alpha_mismatch() {
    // Index 81 is c[0].
    let test = build_tampered_test(81, Tamper::BumpModU16);
    test.execute().expect_err("tampered c limb must trap at FS alpha mismatch");
}

#[test]
fn non_u32_witness_felt_traps() {
    // Index 81 is c[0]. Setting it to 2^32 (just past u32::MAX) trips `u32assertw` during the
    // c absorb.
    let test = build_tampered_test(81, Tamper::Set(1u64 << 32));
    test.execute().expect_err("non-u32 witness felt must trap at u32assertw");
}

#[test]
fn tampered_e_shifted_31_traps_at_top_felt_check() {
    // Index 82 is e_shifted[31]. The honest value is 2^31 (zero in shifted form); any other u32
    // trips the top-felt assert.
    let test = build_tampered_test(82, Tamper::Set(0));
    test.execute()
        .expect_err("tampered e_shifted[31] must trap at top-felt assertion");
}

#[test]
fn tampered_e_shifted_30_traps_at_top_felt_check() {
    // Index 83 is e_shifted[30].
    let test = build_tampered_test(83, Tamper::Set(0));
    test.execute()
        .expect_err("tampered e_shifted[30] must trap at top-felt assertion");
}

/// Synthetic-malicious-witness handler for the `c >= p` test. Computes the honest witness for
/// the inputs on the operand stack, then constructs an alternate transcript-matching witness with
/// `c' = c + p` and `q' = q - 1`. This shift preserves the polynomial identity
/// `a*b - q'*p - c' = a*b - (q-1)*p - (c+p) = a*b - q*p - c`, so the rebuilt witness passes
/// the FS check and the SZ identity check; only the final canonical reduction `c < p` should
/// fire.
///
/// The test must run with inputs where the natural `c` is small enough that `c + p < 2^256`
/// AND `q >= 1` (so `q - 1` doesn't underflow).
/// `synthetic_c_ge_p_traps_at_canonical_check` uses `a = 2, b = (p+1)/2`, giving `q = 1, c = 1`
/// and therefore `c + p = p + 1 < 2^256`.
struct CGePHandler;

// Local copies of `handlers::u256_modmul::{CARRY_SHIFT, NUM_CARRY_COEFFS}`. The originals are
// crate-private; any drift from production would trip either the fixed-prefix commitment check
// (offset coefficients) or the FS alpha check (e_shifted layout).
const CARRY_SHIFT: u32 = 1 << 31;
const NUM_CARRY_COEFFS: usize = 32;

impl EventHandler for CGePHandler {
    fn on_event(&self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        let w =
            compute_modmul_witness(process, &SECP256K1_BASE_PRIME_U16, &SECP256K1_BASE_PRIME_U32)?;

        // c' = c + p, q' = q - 1. Both done as u16-limb arithmetic.
        let (q_new, q_borrow) = sub_u16_one(&w.q_u16);
        assert!(
            q_borrow == 0,
            "test setup picked a, b such that q = 0; need q >= 1 so q - 1 doesn't underflow",
        );
        let (c_new, c_carry) = add_u16(&w.c_u16, &SECP256K1_BASE_PRIME_U16);
        assert!(
            c_carry == 0,
            "test setup picked a, b such that c + p overflows u256; choose different inputs",
        );

        // a, b are unchanged. Read once in u32 form for the FS transcript, then split locally
        // for the carry recurrence.
        let a_u32 = read_a_b_as_u32(process, 9);
        let b_u32 = read_a_b_as_u32(process, 1);
        let a_u16 = u32_to_u16_limbs(&a_u32);
        let b_u16 = u32_to_u16_limbs(&b_u32);
        let e_shifted_new =
            compute_carry_poly(&a_u16, &b_u16, &q_new, &c_new, &SECP256K1_BASE_PRIME_U16);

        let alpha_new =
            derive_alpha(&SECP256K1_BASE_PRIME_U16, &a_u32, &b_u32, &q_new, &c_new, &e_shifted_new);

        // Push the synthetic advice in the same shape as handle_modmul.
        let capacity = 2 + 16 + NUM_CARRY_COEFFS + 16 + 16 + NUM_CARRY_COEFFS;
        let mut advice: Vec<Felt> = Vec::with_capacity(capacity);
        advice.push(alpha_new[1]);
        advice.push(alpha_new[0]);
        advice.extend(SECP256K1_BASE_PRIME_U16.iter().rev().map(|&v| Felt::from_u32(v as u32)));
        advice.extend(core::iter::repeat_n(Felt::from_u32(CARRY_SHIFT), NUM_CARRY_COEFFS));
        advice.extend(q_new.iter().rev().map(|&v| Felt::from_u32(v as u32)));
        advice.extend(c_new.iter().rev().map(|&v| Felt::from_u32(v as u32)));
        advice.extend(e_shifted_new.iter().rev().map(|&v| Felt::from_u32(v)));
        Ok(vec![AdviceMutation::extend_stack(advice)])
    }
}

// Source for the synthetic c >= p test. a = 2, b = (p_k1 + 1) / 2 gives natural witness
// `q = 1, c = 1`, so the tampered `c' = 1 + p_k1 = p_k1 + 1` just fits in u256.
const C_GE_P_SOURCE: &str = "
    use miden::core::math::u256_sz_modmul_k1_base
    use miden::core::sys

    begin
        # a = 2: limbs [2, 0, 0, 0, 0, 0, 0, 0] with limb 0 on top.
        push.0.0.0.0
        push.0.0.0.2
        # b = (p_k1 + 1) / 2 = 2^255 - 2^31 - 488
        # Limbs (LE): [0x7FFFFE18, 0xFFFFFFFF * 6, 0x7FFFFFFF].
        push.0x7FFFFFFF.0xFFFFFFFF.0xFFFFFFFF.0xFFFFFFFF
        push.0xFFFFFFFF.0xFFFFFFFF.0xFFFFFFFF.0x7FFFFE18
        exec.u256_sz_modmul_k1_base::modmul_k1_base
        exec.sys::truncate_stack
    end
";

#[test]
fn synthetic_c_ge_p_traps_at_canonical_check() {
    let core_lib = CoreLibrary::default();
    let mut handlers = core_lib.handlers();
    handlers.retain(|(name, _)| name != &U256_MODMUL_K1_BASE_EVENT_NAME);

    let test = miden_utils_testing::build_debug_test!(C_GE_P_SOURCE, &[])
        .with_library(core_lib.package())
        .with_event_handlers(handlers)
        .with_event_handler(U256_MODMUL_K1_BASE_EVENT_NAME, CGePHandler);

    test.execute()
        .expect_err("synthetic c >= p witness must trap at c < p assertion");
}

/// Bumps one interior coefficient of `e_shifted` by 1 and re-derives alpha over the mutated
/// transcript. The mutation is invisible to the fixed-prefix pin (offset unchanged), the
/// u32assertw checks (value stays in u32), the top-felt asserts (index 0 is interior), and the
/// FS alpha check (alpha recomputed). The only check left that can fire is the SZ identity, so
/// this exercises the identity-check assertion path directly.
struct TamperedEShiftedIdentityHandler;

impl EventHandler for TamperedEShiftedIdentityHandler {
    fn on_event(&self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        let w =
            compute_modmul_witness(process, &SECP256K1_BASE_PRIME_U16, &SECP256K1_BASE_PRIME_U32)?;

        // Mutate e_shifted[0] by +1. The honest value is near 2^31, so checked_add(1) cannot
        // overflow u32; keep the checked form to document the assumption.
        let mut e_shifted_new = w.e_shifted;
        e_shifted_new[0] =
            e_shifted_new[0].checked_add(1).expect("e_shifted[0] + 1 must fit in u32");

        let a_u32 = read_a_b_as_u32(process, 9);
        let b_u32 = read_a_b_as_u32(process, 1);
        let alpha_new = derive_alpha(
            &SECP256K1_BASE_PRIME_U16,
            &a_u32,
            &b_u32,
            &w.q_u16,
            &w.c_u16,
            &e_shifted_new,
        );

        let capacity = 2 + 16 + NUM_CARRY_COEFFS + 16 + 16 + NUM_CARRY_COEFFS;
        let mut advice: Vec<Felt> = Vec::with_capacity(capacity);
        advice.push(alpha_new[1]);
        advice.push(alpha_new[0]);
        advice.extend(SECP256K1_BASE_PRIME_U16.iter().rev().map(|&v| Felt::from_u32(v as u32)));
        advice.extend(core::iter::repeat_n(Felt::from_u32(CARRY_SHIFT), NUM_CARRY_COEFFS));
        advice.extend(w.q_u16.iter().rev().map(|&v| Felt::from_u32(v as u32)));
        advice.extend(w.c_u16.iter().rev().map(|&v| Felt::from_u32(v as u32)));
        advice.extend(e_shifted_new.iter().rev().map(|&v| Felt::from_u32(v)));
        Ok(vec![AdviceMutation::extend_stack(advice)])
    }
}

#[test]
fn tampered_e_shifted_limb_traps_at_identity_check() {
    let core_lib = CoreLibrary::default();
    let mut handlers = core_lib.handlers();
    handlers.retain(|(name, _)| name != &U256_MODMUL_K1_BASE_EVENT_NAME);

    let test = miden_utils_testing::build_debug_test!(MODMUL_SOURCE, &[])
        .with_library(core_lib.package())
        .with_event_handlers(handlers)
        .with_event_handler(U256_MODMUL_K1_BASE_EVENT_NAME, TamperedEShiftedIdentityHandler);

    test.execute().expect_err(
        "e_shifted interior-limb tamper with re-derived alpha must trap at identity check",
    );
}

// HELPERS
// ================================================================================================

fn u32_to_u16_limbs(v: &[u32; 8]) -> [u16; 16] {
    let mut out = [0u16; 16];
    for i in 0..8 {
        out[2 * i] = v[i] as u16;
        out[2 * i + 1] = (v[i] >> 16) as u16;
    }
    out
}

fn read_a_b_as_u32(process: &ProcessorState, depth_start: usize) -> [u32; 8] {
    let mut out = [0u32; 8];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = process.get_stack_item(depth_start + i).as_canonical_u64() as u32;
    }
    out
}

fn sub_u16_one(x: &[u16; 16]) -> ([u16; 16], u32) {
    let mut out = [0u16; 16];
    let mut borrow: i32 = 1;
    for i in 0..16 {
        let v = x[i] as i32 - borrow;
        if v < 0 {
            out[i] = (v + 0x10000) as u16;
            borrow = 1;
        } else {
            out[i] = v as u16;
            borrow = 0;
        }
    }
    (out, borrow as u32)
}

fn add_u16(x: &[u16; 16], y: &[u16; 16]) -> ([u16; 16], u32) {
    let mut out = [0u16; 16];
    let mut carry: u32 = 0;
    for i in 0..16 {
        let s = x[i] as u32 + y[i] as u32 + carry;
        out[i] = s as u16;
        carry = s >> 16;
    }
    (out, carry)
}
