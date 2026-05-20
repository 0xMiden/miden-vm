//! Cycle comparison for deterministic hint-and-check modmul alternatives over the secp256k1 base
//! field.
//!
//! This is intentionally test-only. The production backend is the generated SZ verifier emitted by
//! `miden-sz-codegen`; these alternatives are retained as regression benches so that future
//! optimization work has a concrete baseline instead of re-litigating the design from scratch.
//!
//! 1. host hints `(q, c)` such that `a * b = q * p + c`,
//! 2. VM checks `q * p + c == a * b` and `c < p`, either by computing both full 512-bit products or
//!    by using the k1 base-prime shape `p = 2^256 - 2^32 - 977`,
//! 3. VM returns `c`.
//!
//! Run the ignored `modmul_k1_base_hint_checker_comparison_cycles` test to print the current cycle
//! table and ratios.

use miden_core::Felt;
use miden_core_lib::handlers::secp256k1_constants::SECP256K1_BASE_PRIME_U32;
use miden_processor::{ContextId, ExecutionOutput};
use num::BigUint;

const B_LIMBS: [u32; 8] = [
    0xccbbaa99, 0x11ffeedd, 0x55443322, 0x99887766, 0xe5f60708, 0xa1b2c3d4, 0x87654321, 0xfedcba98,
];

const A_LIMBS: [u32; 8] = [
    0x12345678, 0x33333333, 0x22222222, 0x11111111, 0x9abcdef0, 0xcafebabe, 0x12345678, 0xdeadbeef,
];

const GENERIC_HINT_CHECKER_SOURCE: &str = r#"
    use miden::core::math::u256
    use miden::core::sys

    @locals(81)
    proc naive_modmul_k1_base
        # Advice stack: q[0..8] followed by c[0..8], all u32 LE limbs.
        adv_pushw u32assertw  loc_storew_le.0   dropw   # q[0..4]
        adv_pushw u32assertw  loc_storew_le.4   dropw   # q[4..8]
        adv_pushw u32assertw  loc_storew_le.8   dropw   # c[0..4]
        adv_pushw u32assertw  loc_storew_le.12  dropw   # c[4..8]

        # Store inputs: stack is [b0..b7, a0..a7, ...].
        loc_storew_le.16  dropw                         # b[0..4]
        loc_storew_le.20  dropw                         # b[4..8]
        loc_storew_le.24  dropw                         # a[0..4]
        loc_storew_le.28  dropw                         # a[4..8]

        # ab = a * b, stored in mem[32..48] as low half then high half.
        padw loc_loadw_le.28
        padw loc_loadw_le.24
        padw loc_loadw_le.20
        padw loc_loadw_le.16
        exec.u256::widening_mul
        loc_storew_le.32  dropw
        loc_storew_le.36  dropw
        loc_storew_le.40  dropw
        loc_storew_le.44  dropw

        # qp = q * p, stored in mem[48..64].
        padw loc_loadw_le.4
        padw loc_loadw_le.0
        push.0xffffffff.0xffffffff.0xffffffff.0xffffffff
        push.0xffffffff.0xffffffff.0xfffffffe.0xfffffc2f
        exec.u256::widening_mul
        loc_storew_le.48  dropw
        loc_storew_le.52  dropw
        loc_storew_le.56  dropw
        loc_storew_le.60  dropw

        # sum_lo = qp_lo + c; keep carry for high half.
        padw loc_loadw_le.52
        padw loc_loadw_le.48
        padw loc_loadw_le.12
        padw loc_loadw_le.8
        exec.u256::overflowing_add
        loc_store.80
        loc_storew_le.64  dropw
        loc_storew_le.68  dropw

        # sum_hi = qp_hi + carry; overflow past 512 bits is invalid.
        padw loc_loadw_le.60
        padw loc_loadw_le.56
        padw
        push.0.0.0
        loc_load.80
        exec.u256::overflowing_add
        assertz.err="naive modmul: q*p + c overflows 512 bits"
        loc_storew_le.72  dropw
        loc_storew_le.76  dropw

        # Check low 256 bits.
        padw loc_loadw_le.68
        padw loc_loadw_le.64
        padw loc_loadw_le.36
        padw loc_loadw_le.32
        exec.u256::eq
        assert.err="naive modmul: low half mismatch"

        # Check high 256 bits.
        padw loc_loadw_le.76
        padw loc_loadw_le.72
        padw loc_loadw_le.44
        padw loc_loadw_le.40
        exec.u256::eq
        assert.err="naive modmul: high half mismatch"

        # Check canonical result c < p.
        padw loc_loadw_le.12
        padw loc_loadw_le.8
        push.0xffffffff.0xffffffff.0xffffffff.0xffffffff
        push.0xffffffff.0xffffffff.0xfffffffe.0xfffffc2f
        exec.u256::lt
        assert.err="naive modmul: c >= p"

        # Return c.
        padw loc_loadw_le.12
        padw loc_loadw_le.8
    end

    begin
        clk
        push.0xdeadbeef.0x12345678.0xcafebabe.0x9abcdef0
        push.0x11111111.0x22222222.0x33333333.0x12345678
        push.0xfedcba98.0x87654321.0xa1b2c3d4.0xe5f60708
        push.0x99887766.0x55443322.0x11ffeedd.0xccbbaa99
        exec.naive_modmul_k1_base
        clk
        movup.9 sub
        push.5000 mem_store
        push.5010 mem_store
        push.5011 mem_store
        push.5012 mem_store
        push.5013 mem_store
        push.5014 mem_store
        push.5015 mem_store
        push.5016 mem_store
        push.5017 mem_store
        exec.sys::truncate_stack
    end
"#;

const PSEUDO_MERSENNE_HINT_CHECKER_SOURCE: &str = r#"
    use miden::core::math::u256
    use miden::core::sys

    @locals(81)
    proc naive_modmul_k1_base_pseudo_mersenne
        # Advice stack: q[0..8] followed by c[0..8], all u32 LE limbs.
        adv_pushw u32assertw  loc_storew_le.0   dropw   # q[0..4]
        adv_pushw u32assertw  loc_storew_le.4   dropw   # q[4..8]
        adv_pushw u32assertw  loc_storew_le.8   dropw   # c[0..4]
        adv_pushw u32assertw  loc_storew_le.12  dropw   # c[4..8]

        # Store inputs: stack is [b0..b7, a0..a7, ...].
        loc_storew_le.16  dropw                         # b[0..4]
        loc_storew_le.20  dropw                         # b[4..8]
        loc_storew_le.24  dropw                         # a[0..4]
        loc_storew_le.28  dropw                         # a[4..8]

        # ab = a * b, stored in mem[32..48] as low half then high half.
        padw loc_loadw_le.28
        padw loc_loadw_le.24
        padw loc_loadw_le.20
        padw loc_loadw_le.16
        exec.u256::widening_mul
        loc_storew_le.32  dropw
        loc_storew_le.36  dropw
        loc_storew_le.40  dropw
        loc_storew_le.44  dropw

        # p = 2^256 - d, d = 2^32 + 977.
        # Then q*p + c = q*2^256 + c - q*d. Compute t = q*d limb-by-limb and fuse the
        # low-half check:
        #   t_i = 977*q_i + q_{i-1} + carry_t for i in 0..7, q_-1 = 0
        #   assert (ab_lo + t_low) mod 2^256 == c
        # The final carry of the low-half addition is the borrow that would be produced by
        # `c - t_low`.
        push.0 loc_store.56
        push.0 loc_store.58

        loc_load.0 push.977 mul loc_load.56 add u32split
        swap loc_store.56
        loc_load.32 loc_load.58 u32overflowing_add3
        loc_store.58
        loc_load.8 eq assert.err="naive pm modmul: low limb 0 mismatch"

        loc_load.1 push.977 mul loc_load.0 add loc_load.56 add u32split
        swap loc_store.56
        loc_load.33 loc_load.58 u32overflowing_add3
        loc_store.58
        loc_load.9 eq assert.err="naive pm modmul: low limb 1 mismatch"

        loc_load.2 push.977 mul loc_load.1 add loc_load.56 add u32split
        swap loc_store.56
        loc_load.34 loc_load.58 u32overflowing_add3
        loc_store.58
        loc_load.10 eq assert.err="naive pm modmul: low limb 2 mismatch"

        loc_load.3 push.977 mul loc_load.2 add loc_load.56 add u32split
        swap loc_store.56
        loc_load.35 loc_load.58 u32overflowing_add3
        loc_store.58
        loc_load.11 eq assert.err="naive pm modmul: low limb 3 mismatch"

        loc_load.4 push.977 mul loc_load.3 add loc_load.56 add u32split
        swap loc_store.56
        loc_load.36 loc_load.58 u32overflowing_add3
        loc_store.58
        loc_load.12 eq assert.err="naive pm modmul: low limb 4 mismatch"

        loc_load.5 push.977 mul loc_load.4 add loc_load.56 add u32split
        swap loc_store.56
        loc_load.37 loc_load.58 u32overflowing_add3
        loc_store.58
        loc_load.13 eq assert.err="naive pm modmul: low limb 5 mismatch"

        loc_load.6 push.977 mul loc_load.5 add loc_load.56 add u32split
        swap loc_store.56
        loc_load.38 loc_load.58 u32overflowing_add3
        loc_store.58
        loc_load.14 eq assert.err="naive pm modmul: low limb 6 mismatch"

        loc_load.7 push.977 mul loc_load.6 add loc_load.56 add u32split
        swap loc_store.56
        loc_load.39 loc_load.58 u32overflowing_add3
        loc_store.58
        loc_load.15 eq assert.err="naive pm modmul: low limb 7 mismatch"

        loc_load.7 loc_load.56 add u32split
        loc_store.56 loc_store.57

        # High-half check:
        #   assert ab_hi + t_high + low_carry == q.
        loc_load.40 loc_load.56 loc_load.58 u32overflowing_add3
        loc_store.59
        loc_load.0 eq assert.err="naive pm modmul: high limb 0 mismatch"

        loc_load.41 loc_load.57 loc_load.59 u32overflowing_add3
        loc_store.59
        loc_load.1 eq assert.err="naive pm modmul: high limb 1 mismatch"

        loc_load.42 loc_load.59 u32overflowing_add
        loc_store.59
        loc_load.2 eq assert.err="naive pm modmul: high limb 2 mismatch"

        loc_load.43 loc_load.59 u32overflowing_add
        loc_store.59
        loc_load.3 eq assert.err="naive pm modmul: high limb 3 mismatch"

        loc_load.44 loc_load.59 u32overflowing_add
        loc_store.59
        loc_load.4 eq assert.err="naive pm modmul: high limb 4 mismatch"

        loc_load.45 loc_load.59 u32overflowing_add
        loc_store.59
        loc_load.5 eq assert.err="naive pm modmul: high limb 5 mismatch"

        loc_load.46 loc_load.59 u32overflowing_add
        loc_store.59
        loc_load.6 eq assert.err="naive pm modmul: high limb 6 mismatch"

        loc_load.47 loc_load.59 u32overflowing_add
        loc_store.59
        loc_load.7 eq assert.err="naive pm modmul: high limb 7 mismatch"
        loc_load.59 assertz.err="naive pm modmul: high half overflow"

        # Check canonical result c < p.
        padw loc_loadw_le.12
        padw loc_loadw_le.8
        push.0xffffffff.0xffffffff.0xffffffff.0xffffffff
        push.0xffffffff.0xffffffff.0xfffffffe.0xfffffc2f
        exec.u256::lt
        assert.err="naive pm modmul: c >= p"

        # Return c.
        padw loc_loadw_le.12
        padw loc_loadw_le.8
    end

    begin
        clk
        push.0xdeadbeef.0x12345678.0xcafebabe.0x9abcdef0
        push.0x11111111.0x22222222.0x33333333.0x12345678
        push.0xfedcba98.0x87654321.0xa1b2c3d4.0xe5f60708
        push.0x99887766.0x55443322.0x11ffeedd.0xccbbaa99
        exec.naive_modmul_k1_base_pseudo_mersenne
        clk
        movup.9 sub
        push.5000 mem_store
        push.5010 mem_store
        push.5011 mem_store
        push.5012 mem_store
        push.5013 mem_store
        push.5014 mem_store
        push.5015 mem_store
        push.5016 mem_store
        push.5017 mem_store
        exec.sys::truncate_stack
    end
"#;

const SZ_SOURCE: &str = r#"
    use miden::core::math::u256_sz_modmul_k1_base
    use miden::core::sys

    begin
        clk
        push.0xdeadbeef.0x12345678.0xcafebabe.0x9abcdef0
        push.0x11111111.0x22222222.0x33333333.0x12345678
        push.0xfedcba98.0x87654321.0xa1b2c3d4.0xe5f60708
        push.0x99887766.0x55443322.0x11ffeedd.0xccbbaa99
        exec.u256_sz_modmul_k1_base::modmul_k1_base
        clk
        movup.9 sub
        push.5000 mem_store
        dropw dropw
        exec.sys::truncate_stack
    end
"#;

const WIDENING_MUL_SOURCE: &str = r#"
    use miden::core::math::u256
    use miden::core::sys

    begin
        clk push.4999 mem_store
        push.0xdeadbeef.0x12345678.0xcafebabe.0x9abcdef0
        push.0x11111111.0x22222222.0x33333333.0x12345678
        push.0xfedcba98.0x87654321.0xa1b2c3d4.0xe5f60708
        push.0x99887766.0x55443322.0x11ffeedd.0xccbbaa99
        exec.u256::widening_mul
        clk push.5001 mem_store
        push.5001 mem_load
        push.4999 mem_load
        sub
        push.5000 mem_store
        dropw dropw dropw dropw
        exec.sys::truncate_stack
    end
"#;

fn biguint_from_le_u32(limbs: &[u32]) -> BigUint {
    BigUint::from_slice(limbs)
}

fn to_le_u32_8(value: &BigUint) -> [u32; 8] {
    let digits = value.to_u32_digits();
    let mut out = [0u32; 8];
    for (i, limb) in digits.into_iter().enumerate().take(8) {
        out[i] = limb;
    }
    out
}

fn advice_and_expected() -> (Vec<u64>, [u32; 8]) {
    let a = biguint_from_le_u32(&A_LIMBS);
    let b = biguint_from_le_u32(&B_LIMBS);
    let p = biguint_from_le_u32(&SECP256K1_BASE_PRIME_U32);
    let product = a * b;
    let q = &product / &p;
    let c = &product % &p;

    let q_limbs = to_le_u32_8(&q);
    let c_limbs = to_le_u32_8(&c);

    let mut advice = Vec::with_capacity(16);
    advice.extend(q_limbs.iter().map(|&v| v as u64));
    advice.extend(c_limbs.iter().map(|&v| v as u64));
    (advice, c_limbs)
}

fn read_memory(output: &ExecutionOutput, addr: u32) -> u64 {
    output
        .memory
        .read_element(ContextId::root(), Felt::from_u32(addr))
        .unwrap()
        .as_canonical_u64()
}

fn assert_result_matches(output: &ExecutionOutput, expected: &[u32; 8]) {
    for (i, expected_limb) in expected.iter().enumerate() {
        let actual = read_memory(output, 5010 + i as u32);
        assert_eq!(actual, *expected_limb as u64, "result limb {i} mismatch");
    }
}

fn cycle_count_with_advice(source: &str, advice: &[u64], expect_msg: &str) -> u64 {
    let test = build_debug_test!(source, &[], advice);
    let (output, _) = test.execute_for_output().expect(expect_msg);
    read_memory(&output, 5000)
}

fn cycle_count_without_advice(source: &str, expect_msg: &str) -> u64 {
    let test = build_debug_test!(source, &[]);
    let (output, _) = test.execute_for_output().expect(expect_msg);
    read_memory(&output, 5000)
}

#[test]
fn naive_modmul_k1_base_honest_succeeds() {
    let (advice, expected) = advice_and_expected();
    let test = build_debug_test!(GENERIC_HINT_CHECKER_SOURCE, &[], &advice);
    let (output, _) = test.execute_for_output().expect("naive modmul should accept honest hint");
    assert_result_matches(&output, &expected);
}

#[test]
fn naive_modmul_k1_base_rejects_tampered_q() {
    let (mut advice, _) = advice_and_expected();
    advice[0] = advice[0].wrapping_add(1);
    let test = build_debug_test!(GENERIC_HINT_CHECKER_SOURCE, &[], &advice);
    test.execute().expect_err("tampered q must fail deterministic product check");
}

#[test]
fn naive_modmul_k1_base_rejects_tampered_c() {
    let (mut advice, _) = advice_and_expected();
    advice[8] = advice[8].wrapping_add(1);
    let test = build_debug_test!(GENERIC_HINT_CHECKER_SOURCE, &[], &advice);
    test.execute().expect_err("tampered c must fail deterministic product check");
}

#[test]
fn naive_modmul_k1_base_pseudo_mersenne_honest_succeeds() {
    let (advice, expected) = advice_and_expected();
    let test = build_debug_test!(PSEUDO_MERSENNE_HINT_CHECKER_SOURCE, &[], &advice);
    let (output, _) = test
        .execute_for_output()
        .expect("pseudo-Mersenne checker should accept honest hint");
    assert_result_matches(&output, &expected);
}

#[test]
fn naive_modmul_k1_base_pseudo_mersenne_rejects_tampered_q() {
    let (mut advice, _) = advice_and_expected();
    advice[0] = advice[0].wrapping_add(1);
    let test = build_debug_test!(PSEUDO_MERSENNE_HINT_CHECKER_SOURCE, &[], &advice);
    test.execute().expect_err("tampered q must fail pseudo-Mersenne product check");
}

#[test]
fn naive_modmul_k1_base_pseudo_mersenne_rejects_tampered_c() {
    let (mut advice, _) = advice_and_expected();
    advice[8] = advice[8].wrapping_add(1);
    let test = build_debug_test!(PSEUDO_MERSENNE_HINT_CHECKER_SOURCE, &[], &advice);
    test.execute().expect_err("tampered c must fail pseudo-Mersenne product check");
}

#[test]
#[ignore = "benchmark; run with --ignored to print cycle count"]
fn modmul_k1_base_hint_checker_comparison_cycles() {
    let (advice, _) = advice_and_expected();

    let generic =
        cycle_count_with_advice(GENERIC_HINT_CHECKER_SOURCE, &advice, "generic checker should run");
    let pseudo_mersenne = cycle_count_with_advice(
        PSEUDO_MERSENNE_HINT_CHECKER_SOURCE,
        &advice,
        "pseudo-Mersenne checker should run",
    );
    let widening_mul = cycle_count_without_advice(WIDENING_MUL_SOURCE, "widening_mul should run");
    let sz = cycle_count_without_advice(SZ_SOURCE, "SZ modmul should run");

    eprintln!("modmul_k1_base comparison, same operands:");
    eprintln!("  generic deterministic hint checker      : {generic:>5} cycles");
    eprintln!("  pseudo-Mersenne deterministic checker  : {pseudo_mersenne:>5} cycles");
    eprintln!("  u256::widening_mul lower bound         : {widening_mul:>5} cycles");
    eprintln!("  generated SZ checker                   : {sz:>5} cycles");
    eprintln!("  generic / SZ                           : {:.2}x", generic as f64 / sz as f64);
    eprintln!(
        "  pseudo-Mersenne / SZ                   : {:.2}x",
        pseudo_mersenne as f64 / sz as f64
    );

    assert!(
        generic > pseudo_mersenne,
        "k1 base-prime specialization should beat generic check"
    );
    assert!(
        pseudo_mersenne > sz,
        "SZ should remain faster than the best deterministic checker"
    );
    assert!(widening_mul > sz, "one full product is already more expensive than SZ modmul");
}
