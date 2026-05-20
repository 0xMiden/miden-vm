//! Tests for `f_k1` field arithmetic over the secp256k1 base prime
//! `p = 2^256 - 2^32 - 977`. Covers `add`, `sub`, `neg`, `mul`, and `inv`.

use miden_utils_testing::proptest::prelude::*;
use num::bigint::BigUint;

use super::u256_mod::{
    U256, assert_stack_words, biguint_to_u256, boundary_biased_u32, secp256k1_base_prime,
};

#[test]
fn f_k1_add_edge_cases() {
    let zero = U256::ZERO;
    let one = U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]);
    let two = U256::from_le_u32_limbs([2, 0, 0, 0, 0, 0, 0, 0]);
    let p_minus_one = secp256k1_base_prime().wrapping_sub(one);
    // A value just under 2^255: exercises the carry=0 path with a sum that wraps p but not 2^256.
    let big = U256::from_le_u32_limbs([0, 0, 0, 0, 0, 0, 0, 0x7fff_ffff]);

    assert_f_k1_add(zero, zero);
    assert_f_k1_add(zero, one);
    assert_f_k1_add(p_minus_one, one); // wraps once: result = 0
    assert_f_k1_add(p_minus_one, two); // result = 1
    assert_f_k1_add(p_minus_one, p_minus_one); // 2(p-1) mod p = p-2
    assert_f_k1_add(big, big); // ~2^256 sum: exercises carry path
}

#[test]
fn f_k1_sub_edge_cases() {
    let zero = U256::ZERO;
    let one = U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]);
    let two = U256::from_le_u32_limbs([2, 0, 0, 0, 0, 0, 0, 0]);
    let p_minus_one = secp256k1_base_prime().wrapping_sub(one);

    assert_f_k1_sub(zero, zero);
    assert_f_k1_sub(zero, one); // wraps: result = p-1
    assert_f_k1_sub(one, zero); // result = -1 mod p = p-1
    assert_f_k1_sub(p_minus_one, p_minus_one); // 0
    assert_f_k1_sub(two, one); // -1 mod p = p-1
}

#[test]
fn f_k1_neg_edge_cases() {
    let zero = U256::ZERO;
    let one = U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]);
    let p_minus_one = secp256k1_base_prime().wrapping_sub(one);

    assert_f_k1_neg(zero);
    assert_f_k1_neg(one);
    assert_f_k1_neg(p_minus_one);
}

#[test]
fn f_k1_mul_smoke() {
    let a = U256::from_le_u32_limbs([7, 0, 0, 0, 0, 0, 0, 0]);
    let b = U256::from_le_u32_limbs([11, 0, 0, 0, 0, 0, 0, 0]);
    assert_f_k1_mul(a, b);
}

#[test]
fn f_k1_inv_edge_cases() {
    let one = U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]);
    let p_minus_one = secp256k1_base_prime().wrapping_sub(one);
    let arbitrary = U256::from_le_u32_limbs([
        0xdeadbeef, 0x12345678, 0xcafebabe, 0x9abcdef0, 0x11111111, 0x22222222, 0x33333333,
        0x12345678,
    ]);
    assert_f_k1_inv(one); // inv(1) = 1
    assert_f_k1_inv(p_minus_one); // inv(p-1) = p-1 (since (p-1)^2 = 1 mod p)
    assert_f_k1_inv(arbitrary);
}

proptest! {
    #[test]
    fn f_k1_add_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let p = secp256k1_base_prime();
        if a < p && b < p {
            assert_f_k1_add(a, b);
        }
    }

    #[test]
    fn f_k1_sub_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let p = secp256k1_base_prime();
        if a < p && b < p {
            assert_f_k1_sub(a, b);
        }
    }

    #[test]
    fn f_k1_neg_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let a = U256::from_le_u32_limbs(a);
        let p = secp256k1_base_prime();
        if a < p {
            assert_f_k1_neg(a);
        }
    }

    #[test]
    fn f_k1_mul_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let p = secp256k1_base_prime();
        if a < p && b < p {
            assert_f_k1_mul(a, b);
        }
    }

    #[test]
    fn f_k1_inv_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let a = U256::from_le_u32_limbs(a);
        let p = secp256k1_base_prime();
        if a > U256::ZERO && a < p {
            assert_f_k1_inv(a);
        }
    }
}

fn assert_f_k1_add(a: U256, b: U256) {
    let p = secp256k1_base_prime();
    assert!(a < p && b < p, "f_k1 inputs must be < p");
    let bn_p = BigUint::from_slice(&p.to_le_u32_limbs());
    let bn_c = (BigUint::from_slice(&a.to_le_u32_limbs())
        + BigUint::from_slice(&b.to_le_u32_limbs()))
        % &bn_p;
    run_f_k1_op("add", a, b, biguint_to_u256(&bn_c));
}

fn assert_f_k1_sub(a: U256, b: U256) {
    let p = secp256k1_base_prime();
    assert!(a < p && b < p, "f_k1 inputs must be < p");
    let bn_p = BigUint::from_slice(&p.to_le_u32_limbs());
    let bn_a = BigUint::from_slice(&a.to_le_u32_limbs());
    let bn_b = BigUint::from_slice(&b.to_le_u32_limbs());
    let bn_c = ((&bn_a + &bn_p) - &bn_b) % &bn_p;
    run_f_k1_op("sub", a, b, biguint_to_u256(&bn_c));
}

fn assert_f_k1_mul(a: U256, b: U256) {
    let p = secp256k1_base_prime();
    assert!(a < p && b < p, "f_k1 inputs must be < p");
    let bn_p = BigUint::from_slice(&p.to_le_u32_limbs());
    let bn_c = (BigUint::from_slice(&a.to_le_u32_limbs())
        * BigUint::from_slice(&b.to_le_u32_limbs()))
        % &bn_p;
    run_f_k1_op("mul", a, b, biguint_to_u256(&bn_c));
}

fn assert_f_k1_neg(a: U256) {
    let p = secp256k1_base_prime();
    assert!(a < p, "f_k1 input must be < p");
    let bn_p = BigUint::from_slice(&p.to_le_u32_limbs());
    let bn_a = BigUint::from_slice(&a.to_le_u32_limbs());
    let bn_c = (&bn_p - &bn_a) % &bn_p;
    let c = biguint_to_u256(&bn_c);
    let c_limbs = c.to_le_limbs();
    let source = format!(
        "
        use miden::core::math::f_k1
        begin
            exec.f_k1::neg
            {assert_c}
        end",
        assert_c = assert_stack_words(&c_limbs),
    );
    build_test!(&source, &a.to_le_limbs()).execute().unwrap();
}

fn assert_f_k1_inv(a: U256) {
    let p = secp256k1_base_prime();
    assert!(a > U256::ZERO && a < p, "f_k1::inv input must be in (0, p)");
    let bn_p = BigUint::from_slice(&p.to_le_u32_limbs());
    let bn_a = BigUint::from_slice(&a.to_le_u32_limbs());
    let bn_p_minus_2 = &bn_p - BigUint::from(2u32);
    let bn_c = bn_a.modpow(&bn_p_minus_2, &bn_p);
    let c = biguint_to_u256(&bn_c);
    let c_limbs = c.to_le_limbs();
    let source = format!(
        "
        use miden::core::math::f_k1
        begin
            exec.f_k1::inv
            {assert_c}
        end",
        assert_c = assert_stack_words(&c_limbs),
    );
    build_test!(&source, &a.to_le_limbs()).execute().unwrap();
}

/// Drives a 2-input f_k1 op (add/sub/mul) and asserts the stack-top word matches `expected`.
fn run_f_k1_op(op_name: &str, a: U256, b: U256, expected: U256) {
    let c_limbs = expected.to_le_limbs();
    let source = format!(
        "
        use miden::core::math::f_k1
        begin
            exec.f_k1::{op_name}
            {assert_c}
        end",
        assert_c = assert_stack_words(&c_limbs),
    );
    let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
    build_test!(&source, &operands).execute().unwrap();
}
