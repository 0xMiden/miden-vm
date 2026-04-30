use core::ops::{BitAnd, BitOr, BitXor};

use miden_utils_testing::proptest::prelude::*;

// MULTIPLICATION
// ================================================================================================

#[test]
fn wrapping_mul_regression_vectors() {
    for (a, b) in regression_pairs() {
        assert_wrapping_mul(a, b);
    }
}

#[test]
fn wrapping_mul_consumed_result_restores_min_stack_depth() {
    let source = "
        use miden::core::math::u256
        begin
            exec.u256::wrapping_mul
            dropw dropw
            sdepth push.16 assert_eq
        end";

    let a = U256::from_le_u32_limbs([11, 22, 33, 44, 55, 66, 77, 88]);
    let b = U256::from_le_u32_limbs([101, 202, 303, 404, 505, 606, 707, 808]);
    let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();

    build_test!(source, &operands).execute().unwrap();
}

#[test]
fn wrapping_mul_preserves_caller_stack() {
    let a = [11, 22, 33, 44, 55, 66, 77, 88];
    let b = [101, 202, 303, 404, 505, 606, 707, 808];
    let sentinels = [
        9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010, 9011, 9012, 9013, 9014, 9015,
        9016,
    ];

    let source = format!(
        "
        use miden::core::math::u256
        begin
            push.{sentinels}
            push.{a}
            push.{b}
            exec.u256::wrapping_mul
            dropw dropw
            {assert_sentinels}
        end",
        sentinels = push_masm_values(&sentinels),
        a = push_masm_values(&a),
        b = push_masm_values(&b),
        assert_sentinels = assert_stack_words(&sentinels),
    );

    build_test!(&source).execute().unwrap();
}

#[test]
fn arithmetic_regression_vectors() {
    for (a, b) in regression_pairs() {
        assert_binary_u256_op("wrapping_add", a, b, &a.wrapping_add(b).to_le_limbs());

        let (overflow, sum) = a.overflowing_add(b);
        let mut expected = vec![overflow];
        expected.extend(sum.to_le_limbs());
        assert_binary_u256_op("overflowing_add", a, b, &expected);

        let (sum, overflow) = a.widening_add(b);
        let mut expected = sum.to_le_limbs();
        expected.push(overflow);
        assert_binary_u256_op("widening_add", a, b, &expected);

        assert_binary_u256_op("wrapping_sub", a, b, &a.wrapping_sub(b).to_le_limbs());

        let (underflow, diff) = a.overflowing_sub(b);
        let mut expected = vec![underflow];
        expected.extend(diff.to_le_limbs());
        assert_binary_u256_op("overflowing_sub", a, b, &expected);
    }
}

#[test]
fn bitwise_and_comparison_regression_vectors() {
    for (a, b) in regression_pairs() {
        assert_binary_u256_op("and", a, b, &(a & b).to_le_limbs());
        assert_binary_u256_op("or", a, b, &(a | b).to_le_limbs());
        assert_binary_u256_op("xor", a, b, &(a ^ b).to_le_limbs());
        assert_binary_u256_op("eq", a, b, &[a.eq_u64(b)]);
    }

    for value in regression_values() {
        assert_unary_u256_op("eqz", value, &[value.eqz()]);
    }
}

// ADDITION
// ================================================================================================

#[test]
fn overflowing_add_edge_cases() {
    // Carry-propagation cases that the regression-vector pairs do not cover, exercising single-
    // limb carries, cross-word carries, and the 2^256 wrap point.
    let source = "
        use miden::core::math::u256
        begin
            exec.u256::overflowing_add
        end";

    let max = U256::from_le_u32_limbs([u32::MAX; 8]);
    let one = U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]);
    let one_in_limb1 = U256::from_le_u32_limbs([0, 1, 0, 0, 0, 0, 0, 0]);
    let high_limb_max = U256::from_le_u32_limbs([u32::MAX, 0, 0, 0, 0, 0, 0, 0]);
    let lo_word_max = U256::from_le_u32_limbs([u32::MAX, u32::MAX, u32::MAX, u32::MAX, 0, 0, 0, 0]);

    let cases = [
        // a + b with no overflow
        (U256::ZERO, U256::ZERO),
        (U256::ZERO, one),
        // single-limb carry into limb 1
        (high_limb_max, one),
        // carry propagating through several limbs
        (U256::from_le_u32_limbs([u32::MAX, u32::MAX, u32::MAX, 0, 0, 0, 0, 0]), one),
        // carry crossing the lo/hi 128-bit boundary
        (lo_word_max, one),
        // carry propagates through the bottom 7 limbs and is absorbed by the top limb (no
        // overflow)
        (
            U256::from_le_u32_limbs([
                u32::MAX,
                u32::MAX,
                u32::MAX,
                u32::MAX,
                u32::MAX,
                u32::MAX,
                u32::MAX,
                0,
            ]),
            one,
        ),
        // overflow at the top: max + 1 = 0 with overflow=1
        (max, one),
        // overflow at the top via limb 1 increment
        (max, one_in_limb1),
        // saturated max + max = max-1 with overflow=1
        (max, max),
        // commutativity sanity: pseudo-random pair both orderings
        pseudo_random_pair(),
    ];

    for (a, b) in cases {
        let (overflow, sum) = a.overflowing_add(b);
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        let mut expected = vec![overflow];
        expected.extend(sum.to_le_limbs());
        build_test!(source, &operands).expect_stack(&expected);
    }
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
            U256::from_le_u32_limbs([0, 0, 0, 0, 0, 0, 0, 0]),
            U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]),
        ),
        // a = 1<<32, b = 1 -> borrow across one limb
        (
            U256::from_le_u32_limbs([0, 1, 0, 0, 0, 0, 0, 0]),
            U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]),
        ),
        // a = 1<<224, b = 1 -> borrow across all limbs
        (
            U256::from_le_u32_limbs([0, 0, 0, 0, 0, 0, 0, 1]),
            U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]),
        ),
    ];

    for (a, b) in cases {
        let (underflow, result) = expected_sub(&a, &b);
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
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

    let a = U256::from_le_u32_limbs([0, 0, 0, 0, 0, 0, 0, 0]);
    let b = U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]);
    let (_, result) = expected_sub(&a, &b);
    let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();

    build_test!(source, &operands).expect_stack(&result);
}

// EQUALITY
// ================================================================================================

#[test]
fn eq_edge_cases() {
    // Cases beyond the regression-pair coverage: equality at zero/max, and inequality isolated to
    // a single limb at each position (lo word and hi word, plus the 32-bit boundary).
    let source = "
        use miden::core::math::u256
        begin
            exec.u256::eq
        end";

    let max = U256::from_le_u32_limbs([u32::MAX; 8]);

    // (a, b, expected_eq)
    let cases: [(U256, U256, u64); 11] = [
        (U256::ZERO, U256::ZERO, 1),
        (max, max, 1),
        (U256::from_bit(0), U256::from_bit(0), 1),
        (U256::from_bit(255), U256::from_bit(255), 1),
        // differ in exactly one limb, varying the position to exercise both eqw comparisons
        (U256::ZERO, U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]), 0),
        (U256::ZERO, U256::from_le_u32_limbs([0, 1, 0, 0, 0, 0, 0, 0]), 0),
        (U256::ZERO, U256::from_le_u32_limbs([0, 0, 0, 1, 0, 0, 0, 0]), 0),
        (U256::ZERO, U256::from_le_u32_limbs([0, 0, 0, 0, 1, 0, 0, 0]), 0),
        (U256::ZERO, U256::from_le_u32_limbs([0, 0, 0, 0, 0, 0, 0, 1]), 0),
        // full match in lo word, mismatch in hi word
        (
            U256::from_le_u32_limbs([1, 2, 3, 4, 5, 6, 7, 8]),
            U256::from_le_u32_limbs([1, 2, 3, 4, 5, 6, 7, 9]),
            0,
        ),
        // full match in hi word, mismatch in lo word
        (
            U256::from_le_u32_limbs([1, 2, 3, 4, 5, 6, 7, 8]),
            U256::from_le_u32_limbs([1, 2, 3, 5, 5, 6, 7, 8]),
            0,
        ),
    ];

    for (a, b, expected_eq) in cases {
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        build_test!(source, &operands).expect_stack(&[expected_eq]);
    }
}

proptest! {
    #[test]
    fn wrapping_mul_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        // assert_wrapping_mul embeds an assert_eqw against the expected product inside the
        // MASM program; a mismatch surfaces as a MASM execution failure.
        assert_wrapping_mul(U256::from_le_u32_limbs(a), U256::from_le_u32_limbs(b));
    }

    #[test]
    fn overflowing_add_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::overflowing_add
            end";

        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let (overflow, sum) = a.overflowing_add(b);
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        let mut expected = vec![overflow];
        expected.extend(sum.to_le_limbs());
        build_test!(source, &operands).prop_expect_stack(&expected)?;
    }

    #[test]
    fn wrapping_add_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::wrapping_add
            end";

        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let result = a.wrapping_add(b);
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        build_test!(source, &operands).prop_expect_stack(&result.to_le_limbs())?;
    }

    #[test]
    fn widening_add_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::widening_add
            end";

        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let (sum, overflow) = a.widening_add(b);
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        let mut expected = sum.to_le_limbs();
        expected.push(overflow);
        build_test!(source, &operands).prop_expect_stack(&expected)?;
    }

    #[test]
    fn overflowing_sub_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::overflowing_sub
            end";

        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let (underflow, result) = expected_sub(&a, &b);
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        let mut expected = vec![underflow];
        expected.extend(result);
        build_test!(source, &operands).prop_expect_stack(&expected)?;
    }

    #[test]
    fn wrapping_sub_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::wrapping_sub
            end";

        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let (_, result) = expected_sub(&a, &b);
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        build_test!(source, &operands).prop_expect_stack(&result)?;
    }

    #[test]
    fn eq_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::eq
            end";

        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        build_test!(source, &operands).prop_expect_stack(&[a.eq_u64(b)])?;
    }

    #[test]
    fn eq_proptest_self(a in prop::array::uniform8(boundary_biased_u32())) {
        // Self-equality must always hold.
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::eq
            end";

        let a = U256::from_le_u32_limbs(a);
        let operands = [a.to_le_limbs(), a.to_le_limbs()].concat();
        build_test!(source, &operands).prop_expect_stack(&[1])?;
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct U256 {
    lo: u128,
    hi: u128,
}

impl U256 {
    const ZERO: Self = Self { lo: 0, hi: 0 };
    const MASK32: u128 = (1u128 << 32) - 1;

    const fn new(lo: u128, hi: u128) -> Self {
        Self { lo, hi }
    }

    fn from_bit(bit: u32) -> Self {
        match bit {
            0..=127 => Self::new(1u128 << bit, 0),
            128..=255 => Self::new(0, 1u128 << (bit - 128)),
            _ => panic!("bit index out of range"),
        }
    }

    fn from_le_u32_limbs(limbs: [u32; 8]) -> Self {
        let lo = limbs[..4]
            .iter()
            .enumerate()
            .fold(0u128, |acc, (i, &limb)| acc | ((limb as u128) << (i * 32)));
        let hi = limbs[4..]
            .iter()
            .enumerate()
            .fold(0u128, |acc, (i, &limb)| acc | ((limb as u128) << (i * 32)));
        Self::new(lo, hi)
    }

    fn to_le_u32_limbs(self) -> [u32; 8] {
        [
            (self.lo & Self::MASK32) as u32,
            ((self.lo >> 32) & Self::MASK32) as u32,
            ((self.lo >> 64) & Self::MASK32) as u32,
            ((self.lo >> 96) & Self::MASK32) as u32,
            (self.hi & Self::MASK32) as u32,
            ((self.hi >> 32) & Self::MASK32) as u32,
            ((self.hi >> 64) & Self::MASK32) as u32,
            ((self.hi >> 96) & Self::MASK32) as u32,
        ]
    }

    fn to_le_limbs(self) -> Vec<u64> {
        self.to_le_u32_limbs().into_iter().map(u64::from).collect()
    }

    fn overflowing_add(self, rhs: Self) -> (u64, Self) {
        let (lo, carry_lo) = self.lo.overflowing_add(rhs.lo);
        let (hi_partial, carry_hi0) = self.hi.overflowing_add(rhs.hi);
        let (hi, carry_hi1) = hi_partial.overflowing_add(carry_lo as u128);
        (u64::from(carry_hi0 || carry_hi1), Self::new(lo, hi))
    }

    fn wrapping_add(self, rhs: Self) -> Self {
        self.overflowing_add(rhs).1
    }

    fn widening_add(self, rhs: Self) -> (Self, u64) {
        let (overflow, sum) = self.overflowing_add(rhs);
        (sum, overflow)
    }

    fn overflowing_sub(self, rhs: Self) -> (u64, Self) {
        let (lo, borrow_lo) = self.lo.overflowing_sub(rhs.lo);
        let (hi_partial, borrow_hi0) = self.hi.overflowing_sub(rhs.hi);
        let (hi, borrow_hi1) = hi_partial.overflowing_sub(borrow_lo as u128);
        (u64::from(borrow_hi0 || borrow_hi1), Self::new(lo, hi))
    }

    fn wrapping_sub(self, rhs: Self) -> Self {
        self.overflowing_sub(rhs).1
    }

    fn wrapping_mul(self, rhs: Self) -> Self {
        let lhs = self.to_le_u32_limbs().map(|limb| limb as u128);
        let rhs = rhs.to_le_u32_limbs().map(|limb| limb as u128);
        let mut result = [0u128; 8];

        for (i, &lhs_limb) in lhs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &rhs_limb) in rhs.iter().enumerate().take(8 - i) {
                let idx = i + j;
                let accum = result[idx] + lhs_limb * rhs_limb + carry;
                result[idx] = accum & Self::MASK32;
                carry = accum >> 32;
            }
        }

        Self::from_le_u32_limbs(result.map(|limb| limb as u32))
    }

    fn eq_u64(self, rhs: Self) -> u64 {
        u64::from(self == rhs)
    }

    fn eqz(self) -> u64 {
        u64::from(self == Self::ZERO)
    }
}

impl BitAnd for U256 {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self::new(self.lo & rhs.lo, self.hi & rhs.hi)
    }
}

impl BitOr for U256 {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self::new(self.lo | rhs.lo, self.hi | rhs.hi)
    }
}

impl BitXor for U256 {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self::new(self.lo ^ rhs.lo, self.hi ^ rhs.hi)
    }
}

fn regression_values() -> Vec<U256> {
    vec![
        U256::ZERO,
        U256::new(u64::MAX as u128, 0),
        U256::new(0, u64::MAX as u128),
        U256::new(u64::MAX as u128, u64::MAX as u128),
        U256::from_bit(0),
        U256::from_bit(31),
        U256::from_bit(32),
        U256::from_bit(63),
        U256::from_bit(64),
        U256::from_bit(127),
        U256::from_bit(128),
        U256::from_bit(191),
        U256::from_bit(255),
        pseudo_random_pair().0,
        pseudo_random_pair().1,
    ]
}

fn regression_pairs() -> Vec<(U256, U256)> {
    let (rand_a, rand_b) = pseudo_random_pair();
    vec![
        (U256::ZERO, U256::ZERO),
        (U256::new(u64::MAX as u128, 0), U256::ZERO),
        (U256::ZERO, U256::new(u64::MAX as u128, 0)),
        (U256::new(u64::MAX as u128, u64::MAX as u128), U256::new(u64::MAX as u128, 0)),
        (U256::from_bit(0), U256::from_bit(255)),
        (U256::from_bit(64), U256::from_bit(128)),
        (U256::from_bit(127), U256::from_bit(127)),
        (rand_a, rand_b),
    ]
}

/// Strategy that mixes 32-bit boundary values with uniformly random ones. Each variant has equal
/// probability of being sampled; the boundary cases stress carry/borrow handling and the sign-bit
/// position within a limb.
fn boundary_biased_u32() -> impl Strategy<Value = u32> {
    prop_oneof![
        Just(0u32),
        Just(1u32),
        Just(u32::MAX),
        Just(u32::MAX - 1),
        Just(0x7fffffff),
        Just(0x80000000),
        any::<u32>(),
    ]
}

fn pseudo_random_pair() -> (U256, U256) {
    (
        U256::new(
            0x1234_5678_9abc_def0_1357_9bdf_2468_ace0,
            0x0fed_cba9_8765_4321_0246_8ace_1357_9bdf,
        ),
        U256::new(
            0xdead_beef_cafe_f00d_3141_5926_5358_9793,
            0xa5a5_5a5a_0123_4567_f0e1_d2c3_b4a5_9687,
        ),
    )
}

fn assert_binary_u256_op(op: &str, a: U256, b: U256, expected: &[u64]) {
    let source = format!(
        "
        use miden::core::math::u256
        begin
            exec.u256::{op}
        end"
    );

    let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
    build_test!(&source, &operands).expect_stack(expected);
}

fn assert_wrapping_mul(a: U256, b: U256) {
    let expected = a.wrapping_mul(b).to_le_limbs();
    let source = format!(
        "
        use miden::core::math::u256
        begin
            exec.u256::wrapping_mul
            {assert_expected}
        end",
        assert_expected = assert_stack_words(&expected),
    );

    let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
    build_test!(&source, &operands).execute().unwrap();
}

fn push_masm_values(values: &[u64]) -> String {
    values.iter().rev().map(u64::to_string).collect::<Vec<_>>().join(".")
}

fn assert_stack_words(values: &[u64]) -> String {
    values
        .chunks(4)
        .map(|word| format!("push.{} assert_eqw", push_masm_values(word)))
        .collect::<Vec<_>>()
        .join("\n            ")
}

fn assert_unary_u256_op(op: &str, value: U256, expected: &[u64]) {
    let source = format!(
        "
        use miden::core::math::u256
        begin
            exec.u256::{op}
        end"
    );

    build_test!(&source, &value.to_le_limbs()).expect_stack(expected);
}

fn expected_sub(a: &U256, b: &U256) -> (u64, Vec<u64>) {
    let (underflow, result) = a.overflowing_sub(*b);
    (underflow, result.to_le_limbs())
}
