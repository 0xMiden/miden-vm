//! Verifier-level negative tests for the generated SZ `u256_modmul_k1_base` MASM proc. Each test
//! installs a custom event handler that returns advice the verifier should reject, then asserts
//! the proc traps.
//!
//! The handler runs the honest witness computation via [`compute_modmul_witness`] (so the
//! tests aren't sensitive to the exact arithmetic), then either tampers one felt of the
//! advice payload before returning it, or synthesizes a self-consistent malicious witness
//! (for the `c >= p` case) and re-derives alpha from it.
//!
//! Advice payload layout (114 felts) for the generated SZ verifier:
//!
//! | index range | meaning                                                |
//! |-------------|--------------------------------------------------------|
//! | 0           | `alpha[1]`                                             |
//! | 1           | `alpha[0]`                                             |
//! | 2..18       | `p` reversed: `p[15]` at 2, `p[0]` at 17               |
//! | 18..34      | `q` reversed: `q[15]` at 18, `q[0]` at 33              |
//! | 34..50      | `c` reversed: `c[15]` at 34, `c[0]` at 49              |
//! | 50..82      | `e_pos` reversed: `e_pos[31]` at 50, `e_pos[30]` at 51 |
//! | 82..114     | `e_neg` reversed: `e_neg[31]` at 82, `e_neg[30]` at 83 |

use alloc::vec::Vec;

use miden_core::Felt;
use miden_core_lib::{
    CoreLibrary,
    handlers::{
        secp256k1_constants::{SECP256K1_BASE_PRIME_U16, SECP256K1_BASE_PRIME_U32},
        u256_modmul::{compute_carry_polys, compute_modmul_witness, derive_alpha},
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
        .with_library(core_lib.library().clone())
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
    // Index 17 is p[0] (lowest-degree limb). The fixed modulus is advice-loaded for batching,
    // but it is checked against a hardcoded Poseidon commitment before the transcript continues.
    let test = build_tampered_test(17, Tamper::BumpModU16);
    test.execute()
        .expect_err("tampered fixed p limb must trap at commitment mismatch");
}

#[test]
fn tampered_q_limb_traps_at_alpha_mismatch() {
    // Index 33 is q[0] (lowest-degree limb). Bumping by 1 mod 2^16 keeps the felt u16-valid
    // (so u32assertw passes) but changes the witness, so the FS hash disagrees with the
    // claimed alpha.
    let test = build_tampered_test(33, Tamper::BumpModU16);
    test.execute().expect_err("tampered q limb must trap at FS alpha mismatch");
}

#[test]
fn tampered_c_limb_traps_at_alpha_mismatch() {
    // Index 49 is c[0] (lowest-degree limb).
    let test = build_tampered_test(49, Tamper::BumpModU16);
    test.execute().expect_err("tampered c limb must trap at FS alpha mismatch");
}

#[test]
fn non_u32_witness_felt_traps() {
    // Index 49 is c[0]. Setting it to 2^32 (just past u32::MAX) must trip the `u32assertw`
    // batch range-check that runs over every adv_pipe chunk before Horner evaluation.
    let test = build_tampered_test(49, Tamper::Set(1u64 << 32));
    test.execute().expect_err("non-u32 witness felt must trap at u32assertw");
}

#[test]
fn nonzero_e_pos_31_traps() {
    // Index 50 is e_pos[31] (first element after the p/q/c reversed blocks; e_pos starts here).
    let test = build_tampered_test(50, Tamper::Set(1));
    test.execute().expect_err("nonzero e_pos[31] must trap at top-carry assertion");
}

#[test]
fn nonzero_e_pos_30_traps() {
    // Index 51 is e_pos[30].
    let test = build_tampered_test(51, Tamper::Set(1));
    test.execute().expect_err("nonzero e_pos[30] must trap at top-carry assertion");
}

#[test]
fn nonzero_e_neg_31_traps() {
    // Index 82 is e_neg[31].
    let test = build_tampered_test(82, Tamper::Set(1));
    test.execute().expect_err("nonzero e_neg[31] must trap at top-carry assertion");
}

#[test]
fn nonzero_e_neg_30_traps() {
    // Index 83 is e_neg[30].
    let test = build_tampered_test(83, Tamper::Set(1));
    test.execute().expect_err("nonzero e_neg[30] must trap at top-carry assertion");
}

/// Synthetic-malicious-witness handler for the `c >= p` test. Computes the honest witness for
/// the inputs on the operand stack, then constructs a self-consistent alternate witness with
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
        let (e_pos_new, e_neg_new) =
            compute_carry_polys(&a_u16, &b_u16, &q_new, &c_new, &SECP256K1_BASE_PRIME_U16);

        let alpha_new = derive_alpha(
            &SECP256K1_BASE_PRIME_U16,
            &a_u32,
            &b_u32,
            &q_new,
            &c_new,
            &e_pos_new,
            &e_neg_new,
        );

        // Push the synthetic advice in the same shape as handle_modmul.
        let capacity = 2 + 16 + 16 + 16 + 32 + 32;
        let mut advice: Vec<Felt> = Vec::with_capacity(capacity);
        advice.push(alpha_new[1]);
        advice.push(alpha_new[0]);
        advice.extend(SECP256K1_BASE_PRIME_U16.iter().rev().map(|&v| Felt::from_u32(v as u32)));
        advice.extend(q_new.iter().rev().map(|&v| Felt::from_u32(v as u32)));
        advice.extend(c_new.iter().rev().map(|&v| Felt::from_u32(v as u32)));
        advice.extend(e_pos_new.iter().rev().map(|&v| Felt::from_u32(v)));
        advice.extend(e_neg_new.iter().rev().map(|&v| Felt::from_u32(v)));
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
        .with_library(core_lib.library().clone())
        .with_event_handlers(handlers)
        .with_event_handler(U256_MODMUL_K1_BASE_EVENT_NAME, CGePHandler);

    test.execute()
        .expect_err("synthetic c >= p witness must trap at c < p assertion");
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
    for i in 0..8 {
        out[i] = process.get_stack_item(depth_start + i).as_canonical_u64() as u32;
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
