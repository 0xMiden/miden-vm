//! Tests for `k1_scalar` field arithmetic over the secp256k1 group order
//! `n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`.
//! Covers `add`, `sub`, `neg`, `mul`, and `inv`.

use miden_utils_testing::proptest::prelude::*;
use num::bigint::BigUint;

use super::u256_mod::{
    U256, assert_stack_words, biguint_to_u256, boundary_biased_u32, secp256k1_scalar_order,
};

#[test]
fn k1_scalar_add_edge_cases() {
    let zero = U256::ZERO;
    let one = U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]);
    let two = U256::from_le_u32_limbs([2, 0, 0, 0, 0, 0, 0, 0]);
    let n_minus_one = secp256k1_scalar_order().wrapping_sub(one);
    // 2^255 + a small offset: doubling exceeds 2^256 and exercises the carry path.
    let big = U256::from_le_u32_limbs([0, 0, 0, 0, 0, 0, 0, 0x8000_0000]);

    assert_k1_scalar_add(zero, zero);
    assert_k1_scalar_add(zero, one);
    assert_k1_scalar_add(n_minus_one, one); // wraps once: result = 0
    assert_k1_scalar_add(n_minus_one, two); // result = 1
    assert_k1_scalar_add(n_minus_one, n_minus_one); // 2(n-1) mod n = n-2
    assert_k1_scalar_add(big, big); // 2 * 2^255 = 2^256: carry path
}

#[test]
fn k1_scalar_sub_edge_cases() {
    let zero = U256::ZERO;
    let one = U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]);
    let two = U256::from_le_u32_limbs([2, 0, 0, 0, 0, 0, 0, 0]);
    let n_minus_one = secp256k1_scalar_order().wrapping_sub(one);

    assert_k1_scalar_sub(zero, zero);
    assert_k1_scalar_sub(zero, one); // wraps: result = n-1
    assert_k1_scalar_sub(one, zero); // result = -1 mod n = n-1
    assert_k1_scalar_sub(n_minus_one, n_minus_one); // 0
    assert_k1_scalar_sub(two, one); // -1 mod n = n-1
}

#[test]
fn k1_scalar_neg_edge_cases() {
    let zero = U256::ZERO;
    let one = U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]);
    let n_minus_one = secp256k1_scalar_order().wrapping_sub(one);

    assert_k1_scalar_neg(zero);
    assert_k1_scalar_neg(one);
    assert_k1_scalar_neg(n_minus_one);
}

#[test]
fn k1_scalar_mul_smoke() {
    let a = U256::from_le_u32_limbs([7, 0, 0, 0, 0, 0, 0, 0]);
    let b = U256::from_le_u32_limbs([11, 0, 0, 0, 0, 0, 0, 0]);
    assert_k1_scalar_mul(a, b);
}

#[test]
fn k1_scalar_inv_edge_cases() {
    let one = U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]);
    let n_minus_one = secp256k1_scalar_order().wrapping_sub(one);
    let arbitrary = U256::from_le_u32_limbs([
        0xdeadbeef, 0x12345678, 0xcafebabe, 0x9abcdef0, 0x11111111, 0x22222222, 0x33333333,
        0x12345678,
    ]);
    assert_k1_scalar_inv(one); // inv(1) = 1
    assert_k1_scalar_inv(n_minus_one); // inv(n-1) = n-1 (since (n-1)^2 = 1 mod n)
    assert_k1_scalar_inv(arbitrary);
}

proptest! {
    #[test]
    fn k1_scalar_add_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let n = secp256k1_scalar_order();
        if a < n && b < n {
            assert_k1_scalar_add(a, b);
        }
    }

    #[test]
    fn k1_scalar_sub_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let n = secp256k1_scalar_order();
        if a < n && b < n {
            assert_k1_scalar_sub(a, b);
        }
    }

    #[test]
    fn k1_scalar_neg_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let a = U256::from_le_u32_limbs(a);
        let n = secp256k1_scalar_order();
        if a < n {
            assert_k1_scalar_neg(a);
        }
    }

    #[test]
    fn k1_scalar_mul_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let n = secp256k1_scalar_order();
        if a < n && b < n {
            assert_k1_scalar_mul(a, b);
        }
    }

    #[test]
    fn k1_scalar_inv_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let a = U256::from_le_u32_limbs(a);
        let n = secp256k1_scalar_order();
        if a > U256::ZERO && a < n {
            assert_k1_scalar_inv(a);
        }
    }
}

fn assert_k1_scalar_add(a: U256, b: U256) {
    let n = secp256k1_scalar_order();
    assert!(a < n && b < n, "k1_scalar inputs must be < n");
    let bn_n = BigUint::from_slice(&n.to_le_u32_limbs());
    let bn_c = (BigUint::from_slice(&a.to_le_u32_limbs())
        + BigUint::from_slice(&b.to_le_u32_limbs()))
        % &bn_n;
    run_k1_scalar_op("add", a, b, biguint_to_u256(&bn_c));
}

fn assert_k1_scalar_sub(a: U256, b: U256) {
    let n = secp256k1_scalar_order();
    assert!(a < n && b < n, "k1_scalar inputs must be < n");
    let bn_n = BigUint::from_slice(&n.to_le_u32_limbs());
    let bn_a = BigUint::from_slice(&a.to_le_u32_limbs());
    let bn_b = BigUint::from_slice(&b.to_le_u32_limbs());
    let bn_c = ((&bn_a + &bn_n) - &bn_b) % &bn_n;
    run_k1_scalar_op("sub", a, b, biguint_to_u256(&bn_c));
}

fn assert_k1_scalar_mul(a: U256, b: U256) {
    let n = secp256k1_scalar_order();
    assert!(a < n && b < n, "k1_scalar inputs must be < n");
    let bn_n = BigUint::from_slice(&n.to_le_u32_limbs());
    let bn_c = (BigUint::from_slice(&a.to_le_u32_limbs())
        * BigUint::from_slice(&b.to_le_u32_limbs()))
        % &bn_n;
    run_k1_scalar_op("mul", a, b, biguint_to_u256(&bn_c));
}

fn assert_k1_scalar_neg(a: U256) {
    let n = secp256k1_scalar_order();
    assert!(a < n, "k1_scalar input must be < n");
    let bn_n = BigUint::from_slice(&n.to_le_u32_limbs());
    let bn_a = BigUint::from_slice(&a.to_le_u32_limbs());
    let bn_c = (&bn_n - &bn_a) % &bn_n;
    let c = biguint_to_u256(&bn_c);
    let c_limbs = c.to_le_limbs();
    let source = format!(
        "
        use miden::core::math::k1_scalar
        begin
            exec.k1_scalar::neg
            {assert_c}
        end",
        assert_c = assert_stack_words(&c_limbs),
    );
    build_test!(&source, &a.to_le_limbs()).execute().unwrap();
}

fn assert_k1_scalar_inv(a: U256) {
    let n = secp256k1_scalar_order();
    assert!(a > U256::ZERO && a < n, "k1_scalar::inv input must be in (0, n)");
    let bn_n = BigUint::from_slice(&n.to_le_u32_limbs());
    let bn_a = BigUint::from_slice(&a.to_le_u32_limbs());
    let bn_n_minus_2 = &bn_n - BigUint::from(2u32);
    let bn_c = bn_a.modpow(&bn_n_minus_2, &bn_n);
    let c = biguint_to_u256(&bn_c);
    let c_limbs = c.to_le_limbs();
    let source = format!(
        "
        use miden::core::math::k1_scalar
        begin
            exec.k1_scalar::inv
            {assert_c}
        end",
        assert_c = assert_stack_words(&c_limbs),
    );
    build_test!(&source, &a.to_le_limbs()).execute().unwrap();
}

// VERIFY_GLV_SPLIT
// ================================================================================================
// Drive the production handler+verifier round-trip for the GLV decomposition. The handler
// produces (mag_a, sign_a, mag_b, sign_b) honestly; the MASM verifier asserts the relation
// `k_a + k_b·λ ≡ k mod n` plus the magnitude/sign-bit bounds. Test passes iff the proc
// completes without trapping.

#[test]
fn verify_glv_split_zero() {
    run_verify_glv_split(U256::ZERO);
}

#[test]
fn verify_glv_split_one() {
    run_verify_glv_split(U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]));
}

#[test]
fn verify_glv_split_n_minus_one() {
    let n = secp256k1_scalar_order();
    let one = U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]);
    run_verify_glv_split(n.wrapping_sub(one));
}

#[test]
fn verify_glv_split_arbitrary_large() {
    let n = secp256k1_scalar_order();
    let bn_n = BigUint::from_slice(&n.to_le_u32_limbs());
    let k_unreduced = BigUint::from_bytes_be(&[
        0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78, 0xca, 0xfe, 0xba, 0xbe, 0x9a, 0xbc, 0xde,
        0xf0, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77,
        0x88, 0x88,
    ]);
    let k = biguint_to_u256(&(k_unreduced % bn_n));
    run_verify_glv_split(k);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn verify_glv_split_proptest(
        k_limbs in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let n = secp256k1_scalar_order();
        let k = U256::from_le_u32_limbs(k_limbs);
        if k < n {
            run_verify_glv_split(k);
        }
    }
}

/// Drives the production verify_glv_split proc with the supplied scalar `k` and asserts it
/// completes without trapping. The verifier's internal assertions cover the witness; if any
/// of them fail, the proc traps and the test fails.
fn run_verify_glv_split(k: U256) {
    let n = secp256k1_scalar_order();
    assert!(k < n, "verify_glv_split test inputs must be in [0, n)");

    let source = "
        use miden::core::math::k1_scalar

        @locals(40)
        proc test_wrapper
            # Stack at entry: [k0..k7, ...]. Save k to mem[0..8].
            loc_storew_le.0  dropw
            loc_storew_le.4  dropw

            # verify_glv_split: [out_addr, k_addr, ...] -> [...]. Push deeper first.
            # out_addr must be word-aligned (mem_storew_le inside the proc requires it).
            locaddr.0  locaddr.16
            exec.k1_scalar::verify_glv_split
        end

        begin
            exec.test_wrapper
        end
    ";

    build_test!(source, &k.to_le_limbs()).execute().unwrap();
}

/// Drives a 2-input k1_scalar op (add/sub/mul) and asserts the stack-top word matches `expected`.
fn run_k1_scalar_op(op_name: &str, a: U256, b: U256, expected: U256) {
    let c_limbs = expected.to_le_limbs();
    let source = format!(
        "
        use miden::core::math::k1_scalar
        begin
            exec.k1_scalar::{op_name}
            {assert_c}
        end",
        assert_c = assert_stack_words(&c_limbs),
    );
    let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
    build_test!(&source, &operands).execute().unwrap();
}
