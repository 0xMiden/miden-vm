use miden_utils_testing::rand::rand_vector;
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

    // Stack layout: [b_hi..b_lo, a_hi..a_lo] with b's high limb on top (BE format)
    let operands = [u256_to_be_limbs(&b), u256_to_be_limbs(&a)].concat();

    // Result in BE format (high limb on top)
    let result = u256_to_be_limbs(&((a * b) & max_u256()));

    build_test!(source, &operands).expect_stack(&result);
}

// HELPER FUNCTIONS
// ================================================================================================

fn rand_u256() -> BigUint {
    let limbs = rand_vector::<u64>(8).iter().map(|&v| v as u32).collect::<Vec<_>>();
    BigUint::new(limbs)
}

fn u256_to_be_limbs(n: &BigUint) -> Vec<u64> {
    let mut limbs: Vec<u64> = n.to_u32_digits().iter().map(|&v| v as u64).collect();
    limbs.resize(8, 0);
    limbs.reverse();
    limbs
}

fn max_u256() -> BigUint {
    (BigUint::from(1u32) << 256) - 1u32
}
