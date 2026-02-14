use miden_utils_testing::{proptest::prelude::*, rand::rand_vector};
use num_bigint::BigUint;

// MULTIPLICATION
// ================================================================================================

#[test]
fn mul_unsafe() {
    let a = rand_u256();
    let b = rand_u256();

    let source = "
        use miden::core::math::u256
        begin
            exec.u256::wrapping_mul
            swapdw dropw dropw
        end";

    // Stack layout: [b_lo..b_hi, a_lo..a_hi] with b's low limb on top (LE format)
    let operands = [u256_to_le_limbs(&b), u256_to_le_limbs(&a)].concat();

    // Result in LE format (low limb on top)
    let result = u256_to_le_limbs(&((a * b) & max_u256()));

    build_test!(source, &operands).expect_stack(&result);
}

// SUBTRACTION
// ================================================================================================

#[test]
fn overflowing_sub_edge_cases() {
    let source = "
        use miden::core::math::u256
        begin
            exec.u256::overflowing_sub
        end";

    let cases = [
        // a = 0, b = 1 -> underflow, result = 2^256 - 1
        (
            u256_from_limbs([0, 0, 0, 0, 0, 0, 0, 0]),
            u256_from_limbs([1, 0, 0, 0, 0, 0, 0, 0]),
        ),
        // a = 1<<32, b = 1 -> borrow across one limb
        (
            u256_from_limbs([0, 1, 0, 0, 0, 0, 0, 0]),
            u256_from_limbs([1, 0, 0, 0, 0, 0, 0, 0]),
        ),
        // a = 1<<224, b = 1 -> borrow across all limbs
        (
            u256_from_limbs([0, 0, 0, 0, 0, 0, 0, 1]),
            u256_from_limbs([1, 0, 0, 0, 0, 0, 0, 0]),
        ),
    ];

    for (a, b) in cases {
        let (underflow, result) = expected_sub(&a, &b);
        let operands = [u256_to_le_limbs(&b), u256_to_le_limbs(&a)].concat();
        let mut expected = vec![underflow];
        expected.extend(result);
        build_test!(source, &operands).expect_stack(&expected);
    }
}

#[test]
fn wrapping_sub_underflow() {
    let source = "
        use miden::core::math::u256
        begin
            exec.u256::wrapping_sub
        end";

    let a = u256_from_limbs([0, 0, 0, 0, 0, 0, 0, 0]);
    let b = u256_from_limbs([1, 0, 0, 0, 0, 0, 0, 0]);
    let (_, result) = expected_sub(&a, &b);
    let operands = [u256_to_le_limbs(&b), u256_to_le_limbs(&a)].concat();

    build_test!(source, &operands).expect_stack(&result);
}

proptest! {
    #[test]
    fn overflowing_sub_proptest(a in prop::array::uniform8(any::<u32>()), b in prop::array::uniform8(any::<u32>())) {
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::overflowing_sub
            end";

        let a = u256_from_limbs(a);
        let b = u256_from_limbs(b);
        let (underflow, result) = expected_sub(&a, &b);
        let operands = [u256_to_le_limbs(&b), u256_to_le_limbs(&a)].concat();
        let mut expected = vec![underflow];
        expected.extend(result);
        build_test!(source, &operands).expect_stack(&expected);
    }

    #[test]
    fn wrapping_sub_proptest(a in prop::array::uniform8(any::<u32>()), b in prop::array::uniform8(any::<u32>())) {
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::wrapping_sub
            end";

        let a = u256_from_limbs(a);
        let b = u256_from_limbs(b);
        let (_, result) = expected_sub(&a, &b);
        let operands = [u256_to_le_limbs(&b), u256_to_le_limbs(&a)].concat();
        build_test!(source, &operands).expect_stack(&result);
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn rand_u256() -> BigUint {
    let limbs = rand_vector::<u64>(8).iter().map(|&v| v as u32).collect::<Vec<_>>();
    BigUint::new(limbs)
}

fn u256_from_limbs(limbs: [u32; 8]) -> BigUint {
    BigUint::new(limbs.to_vec())
}

fn u256_to_le_limbs(n: &BigUint) -> Vec<u64> {
    let mut limbs: Vec<u64> = n.to_u32_digits().iter().map(|&v| v as u64).collect();
    limbs.resize(8, 0);
    limbs
}

fn expected_sub(a: &BigUint, b: &BigUint) -> (u64, Vec<u64>) {
    let underflow = if a < b { 1 } else { 0 };
    let modulus = max_u256() + 1u32;
    let diff = if a >= b { a - b } else { a + &modulus - b };
    let result = diff & max_u256();
    (underflow, u256_to_le_limbs(&result))
}

fn max_u256() -> BigUint {
    (BigUint::from(1u32) << 256) - 1u32
}
