use core::ops::{BitAnd, BitOr, BitXor, Not};

#[cfg(feature = "arbitrary")]
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
fn wrapping_mul_edge_cases() {
    let zero = U256::ZERO;
    let one = U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]);
    let max = U256::from_le_u32_limbs([u32::MAX; 8]);
    let lo_max = U256::from_le_u32_limbs([u32::MAX, u32::MAX, u32::MAX, u32::MAX, 0, 0, 0, 0]);
    let hi_max = U256::from_le_u32_limbs([0, 0, 0, 0, u32::MAX, u32::MAX, u32::MAX, u32::MAX]);
    let single_lo = U256::from_le_u32_limbs([u32::MAX, 0, 0, 0, 0, 0, 0, 0]);
    let mixed = U256::from_le_u32_limbs([
        0xdead_beef,
        0xcafe_f00d,
        0x1234_5678,
        0x0fed_cba9,
        0x8000_0000,
        0x7fff_ffff,
        0xaaaa_5555,
        0x5555_aaaa,
    ]);

    // identity
    assert_wrapping_mul(mixed, one);
    assert_wrapping_mul(one, mixed);

    // squaring (diagonal limb products)
    assert_wrapping_mul(zero, zero);
    assert_wrapping_mul(one, one);
    assert_wrapping_mul(max, max);
    assert_wrapping_mul(mixed, mixed);
    assert_wrapping_mul(lo_max, lo_max);
    assert_wrapping_mul(hi_max, hi_max);

    // halves crossed
    assert_wrapping_mul(lo_max, hi_max);

    // single-limb operand stresses the row-0 special path under maximal carries
    assert_wrapping_mul(single_lo, max);
    assert_wrapping_mul(max, single_lo);
}

#[test]
fn divmod_edge_cases() {
    let one = U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]);
    let two = U256::from_le_u32_limbs([2, 0, 0, 0, 0, 0, 0, 0]);
    let max = U256::from_le_u32_limbs([u32::MAX; 8]);
    let lo_max = U256::from_le_u32_limbs([u32::MAX, u32::MAX, u32::MAX, u32::MAX, 0, 0, 0, 0]);
    let mid = U256::from_bit(128);

    // trivial divisors and self-division
    assert_divmod(one, one);
    assert_divmod(max, one);
    assert_divmod(max, max);
    assert_divmod(max, two);
    assert_divmod(U256::ZERO, max);

    // a < b: q = 0, r = a (boundary between q = 0 and q >= 1)
    assert_divmod(
        lo_max,
        U256::from_le_u32_limbs([u32::MAX, u32::MAX, u32::MAX, u32::MAX, 1, 0, 0, 0]),
    );

    // operands straddling the lo/hi 128-bit boundary
    assert_divmod(mid, lo_max);
    assert_divmod(max, mid);

    for (a, b) in regression_pairs() {
        if b != U256::ZERO {
            assert_divmod(a, b);
        }
    }

    // Boundary remainders: probe r = 0, r = 1, r = b - 1 around several non-trivial b values.
    let bs = [
        U256::from_le_u32_limbs([3, 0, 0, 0, 0, 0, 0, 0]),
        U256::from_le_u32_limbs([0xdead_beef, 0, 0, 0, 0, 0, 0, 0]),
        U256::from_le_u32_limbs([1, 1, 1, 1, 1, 1, 1, 1]),
        lo_max,
        U256::from_le_u32_limbs([1, 0, 0, 0, 1, 0, 0, 0]),
    ];
    for b in bs {
        // (b - 1, b): largest a with q = 0, r = a.
        assert_divmod(b.wrapping_sub(one), b);
        // (b, b): smallest a with q = 1, r = 0.
        assert_divmod(b, b);
        // (b + 1, b): q = 1, r = 1.
        assert_divmod(b.wrapping_add(one), b);
        // (2*b - 1, b): q = 1, r = b - 1 (max remainder for q = 1).
        assert_divmod(b.wrapping_mul(two).wrapping_sub(one), b);
        // (2*b, b): q = 2, r = 0.
        assert_divmod(b.wrapping_mul(two), b);
    }

    // Power-of-two divisors: r is the bottom k bits of a; quotient is a >> k.
    let a_dense = U256::from_le_u32_limbs([0xdead_beef; 8]);
    for k in [0, 1, 31, 32, 33, 63, 64, 65, 127, 128, 129, 191, 192, 254, 255] {
        assert_divmod(a_dense, U256::from_bit(k));
        assert_divmod(max, U256::from_bit(k));
    }
}

#[test]
fn divmod_panics_on_zero_divisor() {
    let source = "
        use miden::core::math::u256
        begin
            exec.u256::divmod
        end";
    let a = U256::from_le_u32_limbs([1, 2, 3, 4, 5, 6, 7, 8]);
    let operands = [U256::ZERO.to_le_limbs(), a.to_le_limbs()].concat();
    assert!(build_test!(source, &operands).execute().is_err());
}

#[test]
fn divmod_panics_on_non_u32_limb() {
    let source = "
        use miden::core::math::u256
        begin
            exec.u256::divmod
        end";
    // b has a limb that exceeds u32::MAX; the host handler should reject the inputs.
    let non_u32: u64 = (1u64 << 32) + 1;
    let mut operands = vec![1u64, non_u32, 0, 0, 0, 0, 0, 0];
    operands.extend([42u64, 0, 0, 0, 0, 0, 0, 0]);
    assert!(build_test!(source, &operands).execute().is_err());
}

#[test]
fn widening_mul_edge_cases() {
    let zero = U256::ZERO;
    let one = U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]);
    let max = U256::from_le_u32_limbs([u32::MAX; 8]);
    let lo_max = U256::from_le_u32_limbs([u32::MAX, u32::MAX, u32::MAX, u32::MAX, 0, 0, 0, 0]);
    let hi_max = U256::from_le_u32_limbs([0, 0, 0, 0, u32::MAX, u32::MAX, u32::MAX, u32::MAX]);

    assert_widening_mul(zero, zero);
    assert_widening_mul(one, max);
    assert_widening_mul(lo_max, lo_max);
    assert_widening_mul(max, max);
    assert_widening_mul(hi_max, hi_max);
    assert_widening_mul(lo_max, hi_max);
    assert_widening_mul(U256::from_bit(255), U256::from_le_u32_limbs([2, 0, 0, 0, 0, 0, 0, 0]));

    for (a, b) in regression_pairs() {
        assert_widening_mul(a, b);
    }
}

#[test]
fn overflowing_mul_edge_cases() {
    let zero = U256::ZERO;
    let one = U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]);
    let max = U256::from_le_u32_limbs([u32::MAX; 8]);
    let lo_max = U256::from_le_u32_limbs([u32::MAX, u32::MAX, u32::MAX, u32::MAX, 0, 0, 0, 0]);
    let hi_max = U256::from_le_u32_limbs([0, 0, 0, 0, u32::MAX, u32::MAX, u32::MAX, u32::MAX]);

    // overflow = 0
    assert_overflowing_mul(zero, zero);
    assert_overflowing_mul(zero, max);
    assert_overflowing_mul(one, max);
    assert_overflowing_mul(lo_max, one);
    // largest no-overflow product: (2^128 - 1)^2 = 2^256 - 2^129 + 1
    assert_overflowing_mul(lo_max, lo_max);

    // overflow = 1
    assert_overflowing_mul(max, max);
    assert_overflowing_mul(hi_max, hi_max);
    assert_overflowing_mul(lo_max, hi_max);
    // smallest overflow product: bit 255 * 2 = bit 256, lo == 0
    assert_overflowing_mul(U256::from_bit(255), U256::from_le_u32_limbs([2, 0, 0, 0, 0, 0, 0, 0]));

    for (a, b) in regression_pairs() {
        assert_overflowing_mul(a, b);
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

#[test]
fn neq_edge_cases() {
    // Mirrors eq_edge_cases with the expected flag flipped, so both procs cover the same surface.
    let source = "
        use miden::core::math::u256
        begin
            exec.u256::neq
        end";

    let max = U256::from_le_u32_limbs([u32::MAX; 8]);

    // (a, b, expected_neq)
    let cases: [(U256, U256, u64); 11] = [
        (U256::ZERO, U256::ZERO, 0),
        (max, max, 0),
        (U256::from_bit(0), U256::from_bit(0), 0),
        (U256::from_bit(255), U256::from_bit(255), 0),
        (U256::ZERO, U256::from_le_u32_limbs([1, 0, 0, 0, 0, 0, 0, 0]), 1),
        (U256::ZERO, U256::from_le_u32_limbs([0, 1, 0, 0, 0, 0, 0, 0]), 1),
        (U256::ZERO, U256::from_le_u32_limbs([0, 0, 0, 1, 0, 0, 0, 0]), 1),
        (U256::ZERO, U256::from_le_u32_limbs([0, 0, 0, 0, 1, 0, 0, 0]), 1),
        (U256::ZERO, U256::from_le_u32_limbs([0, 0, 0, 0, 0, 0, 0, 1]), 1),
        (
            U256::from_le_u32_limbs([1, 2, 3, 4, 5, 6, 7, 8]),
            U256::from_le_u32_limbs([1, 2, 3, 4, 5, 6, 7, 9]),
            1,
        ),
        (
            U256::from_le_u32_limbs([1, 2, 3, 4, 5, 6, 7, 8]),
            U256::from_le_u32_limbs([1, 2, 3, 5, 5, 6, 7, 8]),
            1,
        ),
    ];

    for (a, b, expected_neq) in cases {
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        build_test!(source, &operands).expect_stack(&[expected_neq]);
    }
}

#[test]
fn not_regression_vectors() {
    let source = "
        use miden::core::math::u256
        begin
            exec.u256::not
        end";

    for value in regression_values() {
        let inverted = (!value).to_le_limbs();
        let operands = value.to_le_limbs();
        build_test!(source, &operands).expect_stack(&inverted);
    }
}

// COMPARISONS
// ================================================================================================

#[test]
fn comparison_edge_cases() {
    // Probe ordering at the extremes (zero/max), at the lo/hi 128-bit half-boundary, and with
    // values that differ at each limb position so the per-limb borrow chain has to propagate
    // across every boundary.
    let zero = U256::ZERO;
    let max = U256::from_le_u32_limbs([u32::MAX; 8]);
    let lo_max = U256::from_le_u32_limbs([u32::MAX, u32::MAX, u32::MAX, u32::MAX, 0, 0, 0, 0]);
    let just_above_lo = U256::from_le_u32_limbs([0, 0, 0, 0, 1, 0, 0, 0]);

    let mut cases: Vec<(U256, U256)> = vec![
        (zero, zero),
        (zero, max),
        (max, zero),
        (max, max),
        (lo_max, just_above_lo),
        (just_above_lo, lo_max),
        (lo_max, lo_max),
    ];
    // For each limb position i, generate (a, b) pairs that differ only at limb i.
    for i in 0..8 {
        let mut a_limbs = [1u32; 8];
        let mut b_limbs = [1u32; 8];
        b_limbs[i] = 2;
        cases.push((U256::from_le_u32_limbs(a_limbs), U256::from_le_u32_limbs(b_limbs)));
        // And the symmetric pair with the difference also requiring a borrow from below.
        a_limbs[i] = 2;
        b_limbs[i] = 1;
        cases.push((U256::from_le_u32_limbs(a_limbs), U256::from_le_u32_limbs(b_limbs)));
    }

    for &(a, b) in &cases {
        assert_binary_u256_op("lt", a, b, &[u64::from(a < b)]);
        assert_binary_u256_op("gt", a, b, &[u64::from(a > b)]);
        assert_binary_u256_op("lte", a, b, &[u64::from(a <= b)]);
        assert_binary_u256_op("gte", a, b, &[u64::from(a >= b)]);
        assert_binary_u256_op("min", a, b, &a.min(b).to_le_limbs());
        assert_binary_u256_op("max", a, b, &a.max(b).to_le_limbs());
    }
}

// BIT COUNTING
// ================================================================================================

#[test]
fn bit_count_edge_cases() {
    // Zero, all-ones, and a single-bit value at every limb boundary. The 8-deep nested-if
    // dispatch in clz/ctz/clo/cto branches on which limb is the first non-zero (or non-MAX)
    // one, so a single-bit value at each 32k boundary forces a different branch.
    let mut cases: Vec<U256> = vec![
        U256::ZERO,
        U256::from_le_u32_limbs([u32::MAX; 8]),
        U256::from_le_u32_limbs([u32::MAX, u32::MAX, u32::MAX, u32::MAX, 0, 0, 0, 0]),
        U256::from_le_u32_limbs([0, 0, 0, 0, u32::MAX, u32::MAX, u32::MAX, u32::MAX]),
        U256::from_le_u32_limbs([0xdead_beef, 0, 0, 0, 0, 0, 0, 0]),
        U256::from_le_u32_limbs([0, 0, 0, 0, 0, 0, 0, 0xdead_beef]),
    ];
    for bit in [0, 31, 32, 63, 64, 95, 96, 127, 128, 159, 160, 191, 192, 223, 224, 255] {
        cases.push(U256::from_bit(bit));
    }

    for &value in &cases {
        assert_unary_u256_op("clz", value, &[value.clz()]);
        assert_unary_u256_op("ctz", value, &[value.ctz()]);
        assert_unary_u256_op("clo", value, &[value.clo()]);
        assert_unary_u256_op("cto", value, &[value.cto()]);
    }
}

// SHIFTS / ROTATIONS
// ================================================================================================

#[test]
fn shift_edge_cases() {
    // Shift amounts target each k = n / 32 dispatch arm and the m = 0 / m > 0 split inside shr.
    let amounts: &[u32] = &[
        0, 1, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128, 129, 159, 160, 161, 191, 192, 193, 223,
        224, 225, 254, 255,
    ];
    let mut values: Vec<U256> = vec![
        U256::ZERO,
        U256::from_le_u32_limbs([u32::MAX; 8]),
        // single-limb-full: each limb = u32::MAX, others zero.
        U256::from_le_u32_limbs([u32::MAX, 0, 0, 0, 0, 0, 0, 0]),
        U256::from_le_u32_limbs([0, u32::MAX, 0, 0, 0, 0, 0, 0]),
        U256::from_le_u32_limbs([0, 0, 0, 0, u32::MAX, 0, 0, 0]),
        U256::from_le_u32_limbs([0, 0, 0, 0, 0, 0, 0, u32::MAX]),
        // half-fills stress lo/hi crossover.
        U256::new(u128::MAX, 0),
        U256::new(0, u128::MAX),
        // alternating bits within and across limbs.
        U256::from_le_u32_limbs([0xaaaa_aaaa; 8]),
        U256::from_le_u32_limbs([0x5555_5555; 8]),
        pseudo_random_pair().0,
        pseudo_random_pair().1,
    ];
    // Single-bit values at every limb boundary catch off-by-one bit-position errors.
    for bit in [0, 31, 32, 63, 64, 95, 96, 127, 128, 159, 160, 191, 192, 223, 224, 255] {
        values.push(U256::from_bit(bit));
    }

    for &n in amounts {
        for &a in &values {
            assert_shift_op("shl", n, a, &a.shl(n).to_le_limbs());
            assert_shift_op("shr", n, a, &a.shr(n).to_le_limbs());
            assert_shift_op("rotl", n, a, &a.rotl(n).to_le_limbs());
            assert_shift_op("rotr", n, a, &a.rotr(n).to_le_limbs());
        }
    }
}

#[test]
fn shift_panics_when_amount_out_of_range() {
    for &n in &[256u64, u64::from(u32::MAX)] {
        for op in ["shl", "shr", "rotl", "rotr"] {
            let source = format!(
                "
                use miden::core::math::u256
                begin
                    exec.u256::{op}
                end"
            );
            let mut operands = vec![n];
            operands.extend(U256::from_bit(0).to_le_limbs());
            assert!(
                build_test!(&source, &operands).execute().is_err(),
                "{op} with n={n} should panic"
            );
        }
    }
}

#[test]
fn shift_panics_on_non_u32_amount() {
    for &n in &[1u64 << 32, (1u64 << 32) + 1, 1u64 << 40, (1u64 << 63) + 7] {
        for op in ["shl", "shr", "rotl", "rotr"] {
            let source = format!(
                "
                use miden::core::math::u256
                begin
                    exec.u256::{op}
                end"
            );
            let mut operands = vec![n];
            operands.extend(U256::from_bit(0).to_le_limbs());
            assert!(
                build_test!(&source, &operands).execute().is_err(),
                "{op} with non-u32 n={n} should panic"
            );
        }
    }
}

#[cfg(feature = "arbitrary")]
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
    fn widening_mul_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        assert_widening_mul(U256::from_le_u32_limbs(a), U256::from_le_u32_limbs(b));
    }

    #[test]
    fn overflowing_mul_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        assert_overflowing_mul(U256::from_le_u32_limbs(a), U256::from_le_u32_limbs(b));
    }

    #[test]
    fn divmod_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        if b != U256::ZERO {
            assert_divmod(a, b);
        }
    }

    // Synthesizes a from (q, b, r) so the test guarantees valid divmod inputs. q and b are
    // bounded to u128 each so q*b always fits in u256; r < b is enforced. The resulting a
    // can span the full u256 range (since q*b can reach (2^128-1)^2 ~ 2^256). Covers small-q
    // and small-b cases that the random `divmod_proptest` almost never hits.
    #[test]
    fn divmod_synthesized_proptest(
        q_lo in prop::array::uniform4(boundary_biased_u32()),
        b_lo in prop::array::uniform4(boundary_biased_u32()),
        r_lo in prop::array::uniform4(boundary_biased_u32()),
    ) {
        let q = U256::from_le_u32_limbs([q_lo[0], q_lo[1], q_lo[2], q_lo[3], 0, 0, 0, 0]);
        let b = U256::from_le_u32_limbs([b_lo[0], b_lo[1], b_lo[2], b_lo[3], 0, 0, 0, 0]);
        let r = U256::from_le_u32_limbs([r_lo[0], r_lo[1], r_lo[2], r_lo[3], 0, 0, 0, 0]);
        if b != U256::ZERO && r < b {
            // q, b < 2^128 implies q*b < 2^256 (fits); r < b < 2^128 implies q*b + r < 2^256.
            let (_, qb) = q.overflowing_mul(b);
            let (_, sum) = qb.overflowing_add(r);
            assert_divmod(sum, b);
        }
    }

    // Power-of-two divisors: stress the bit-by-bit loop with single-bit b values, where r is the
    // bottom k bits of a and q = a >> k.
    #[test]
    fn divmod_power_of_two_divisor_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        k in 0u32..256,
    ) {
        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_bit(k);
        assert_divmod(a, b);
    }

    // Small divisors produce huge quotients (up to ~2^256), exercising the carry chain across
    // every limb of q*b in the masm verification.
    #[test]
    fn divmod_small_divisor_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in 1u32..1024,
    ) {
        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs([b, 0, 0, 0, 0, 0, 0, 0]);
        assert_divmod(a, b);
    }

    #[test]
    fn div_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        if b != U256::ZERO {
            assert_div(a, b);
        }
    }

    #[test]
    fn mod_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        if b != U256::ZERO {
            assert_mod(a, b);
        }
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

    #[test]
    fn neq_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::neq
            end";

        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        build_test!(source, &operands).prop_expect_stack(&[u64::from(a != b)])?;
    }

    #[test]
    fn neq_proptest_self(a in prop::array::uniform8(boundary_biased_u32())) {
        // Self-inequality must always be 0; covers the OR-fold collapsing 8 zero comparisons.
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::neq
            end";

        let a = U256::from_le_u32_limbs(a);
        let operands = [a.to_le_limbs(), a.to_le_limbs()].concat();
        build_test!(source, &operands).prop_expect_stack(&[0])?;
    }

    #[test]
    fn not_proptest(a in prop::array::uniform8(boundary_biased_u32())) {
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::not
            end";

        let a = U256::from_le_u32_limbs(a);
        let expected = (!a).to_le_limbs();
        build_test!(source, &a.to_le_limbs()).prop_expect_stack(&expected)?;
    }

    #[test]
    fn lt_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::lt
            end";

        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        build_test!(source, &operands).prop_expect_stack(&[u64::from(a < b)])?;
    }

    #[test]
    fn gt_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::gt
            end";

        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        build_test!(source, &operands).prop_expect_stack(&[u64::from(a > b)])?;
    }

    #[test]
    fn lte_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::lte
            end";

        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        build_test!(source, &operands).prop_expect_stack(&[u64::from(a <= b)])?;
    }

    #[test]
    fn gte_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::gte
            end";

        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        build_test!(source, &operands).prop_expect_stack(&[u64::from(a >= b)])?;
    }

    #[test]
    fn min_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::min
            end";

        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        build_test!(source, &operands).prop_expect_stack(&a.min(b).to_le_limbs())?;
    }

    #[test]
    fn max_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::max
            end";

        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        build_test!(source, &operands).prop_expect_stack(&a.max(b).to_le_limbs())?;
    }

    #[test]
    fn clz_proptest(a in prop::array::uniform8(boundary_biased_u32())) {
        let a = U256::from_le_u32_limbs(a);
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::clz
            end";
        build_test!(source, &a.to_le_limbs()).prop_expect_stack(&[a.clz()])?;
    }

    #[test]
    fn ctz_proptest(a in prop::array::uniform8(boundary_biased_u32())) {
        let a = U256::from_le_u32_limbs(a);
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::ctz
            end";
        build_test!(source, &a.to_le_limbs()).prop_expect_stack(&[a.ctz()])?;
    }

    #[test]
    fn clo_proptest(a in prop::array::uniform8(boundary_biased_u32())) {
        let a = U256::from_le_u32_limbs(a);
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::clo
            end";
        build_test!(source, &a.to_le_limbs()).prop_expect_stack(&[a.clo()])?;
    }

    #[test]
    fn cto_proptest(a in prop::array::uniform8(boundary_biased_u32())) {
        let a = U256::from_le_u32_limbs(a);
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::cto
            end";
        build_test!(source, &a.to_le_limbs()).prop_expect_stack(&[a.cto()])?;
    }

    #[test]
    fn shl_proptest(a in prop::array::uniform8(boundary_biased_u32()), n in 0u32..256) {
        let a = U256::from_le_u32_limbs(a);
        let expected = a.shl(n).to_le_limbs();
        let source = format!(
            "
            use miden::core::math::u256
            begin
                exec.u256::shl
                {assert_expected}
            end",
            assert_expected = assert_stack_words(&expected),
        );
        let mut operands = vec![u64::from(n)];
        operands.extend(a.to_le_limbs());
        build_test!(&source, &operands).execute().map_err(|e| {
            TestCaseError::fail(format!("shl(n={n}, a={a:?}) failed: {e:?}"))
        })?;
    }

    #[test]
    fn shr_proptest(a in prop::array::uniform8(boundary_biased_u32()), n in 0u32..256) {
        let a = U256::from_le_u32_limbs(a);
        let expected = a.shr(n).to_le_limbs();
        let source = format!(
            "
            use miden::core::math::u256
            begin
                exec.u256::shr
                {assert_expected}
            end",
            assert_expected = assert_stack_words(&expected),
        );
        let mut operands = vec![u64::from(n)];
        operands.extend(a.to_le_limbs());
        build_test!(&source, &operands).execute().map_err(|e| {
            TestCaseError::fail(format!("shr(n={n}, a={a:?}) failed: {e:?}"))
        })?;
    }

    #[test]
    fn rotl_proptest(a in prop::array::uniform8(boundary_biased_u32()), n in 0u32..256) {
        let a = U256::from_le_u32_limbs(a);
        let expected = a.rotl(n).to_le_limbs();
        let source = format!(
            "
            use miden::core::math::u256
            begin
                exec.u256::rotl
                {assert_expected}
            end",
            assert_expected = assert_stack_words(&expected),
        );
        let mut operands = vec![u64::from(n)];
        operands.extend(a.to_le_limbs());
        build_test!(&source, &operands).execute().map_err(|e| {
            TestCaseError::fail(format!("rotl(n={n}, a={a:?}) failed: {e:?}"))
        })?;
    }

    #[test]
    fn rotr_proptest(a in prop::array::uniform8(boundary_biased_u32()), n in 0u32..256) {
        let a = U256::from_le_u32_limbs(a);
        let expected = a.rotr(n).to_le_limbs();
        let source = format!(
            "
            use miden::core::math::u256
            begin
                exec.u256::rotr
                {assert_expected}
            end",
            assert_expected = assert_stack_words(&expected),
        );
        let mut operands = vec![u64::from(n)];
        operands.extend(a.to_le_limbs());
        build_test!(&source, &operands).execute().map_err(|e| {
            TestCaseError::fail(format!("rotr(n={n}, a={a:?}) failed: {e:?}"))
        })?;
    }

    #[test]
    fn and_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::and
            end";
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        build_test!(source, &operands).prop_expect_stack(&(a & b).to_le_limbs())?;
    }

    #[test]
    fn or_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::or
            end";
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        build_test!(source, &operands).prop_expect_stack(&(a | b).to_le_limbs())?;
    }

    #[test]
    fn xor_proptest(
        a in prop::array::uniform8(boundary_biased_u32()),
        b in prop::array::uniform8(boundary_biased_u32()),
    ) {
        let a = U256::from_le_u32_limbs(a);
        let b = U256::from_le_u32_limbs(b);
        let source = "
            use miden::core::math::u256
            begin
                exec.u256::xor
            end";
        let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
        build_test!(source, &operands).prop_expect_stack(&(a ^ b).to_le_limbs())?;
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

    fn divmod(self, rhs: Self) -> (Self, Self) {
        // Bit-by-bit long division: q = a / b, r = a % b.
        assert!(rhs != Self::ZERO, "u256 divmod: divide by zero");
        let mut q = Self::ZERO;
        let mut r = Self::ZERO;
        for bit in (0..256).rev() {
            r = r.shl(1);
            r.lo |= u128::from(self.bit(bit));
            if r >= rhs {
                r = r.wrapping_sub(rhs);
                q = q | Self::from_bit(bit);
            }
        }
        (q, r)
    }

    fn bit(self, index: u32) -> u32 {
        if index < 128 {
            ((self.lo >> index) & 1) as u32
        } else {
            ((self.hi >> (index - 128)) & 1) as u32
        }
    }

    fn widening_mul(self, rhs: Self) -> (Self, Self) {
        let lhs = self.to_le_u32_limbs().map(|limb| limb as u128);
        let rhs = rhs.to_le_u32_limbs().map(|limb| limb as u128);
        let mut full = [0u128; 16];

        for (i, &lhs_limb) in lhs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &rhs_limb) in rhs.iter().enumerate() {
                let idx = i + j;
                let accum = full[idx] + lhs_limb * rhs_limb + carry;
                full[idx] = accum & Self::MASK32;
                carry = accum >> 32;
            }
            full[i + 8] = carry;
        }

        let lo: [u32; 8] = core::array::from_fn(|i| full[i] as u32);
        let hi: [u32; 8] = core::array::from_fn(|i| full[i + 8] as u32);
        (Self::from_le_u32_limbs(lo), Self::from_le_u32_limbs(hi))
    }

    fn overflowing_mul(self, rhs: Self) -> (u64, Self) {
        let (lo, hi) = self.widening_mul(rhs);
        (u64::from(hi != Self::ZERO), lo)
    }

    fn eq_u64(self, rhs: Self) -> u64 {
        u64::from(self == rhs)
    }

    fn eqz(self) -> u64 {
        u64::from(self == Self::ZERO)
    }

    fn clz(self) -> u64 {
        if self.hi != 0 {
            self.hi.leading_zeros() as u64
        } else {
            128 + self.lo.leading_zeros() as u64
        }
    }

    fn ctz(self) -> u64 {
        if self.lo != 0 {
            self.lo.trailing_zeros() as u64
        } else {
            128 + self.hi.trailing_zeros() as u64
        }
    }

    fn clo(self) -> u64 {
        (!self).clz()
    }

    fn cto(self) -> u64 {
        (!self).ctz()
    }

    fn shl(self, n: u32) -> Self {
        assert!(n < 256, "shift amount must be in [0, 256)");
        if n == 0 {
            return self;
        }
        if n < 128 {
            let lo = self.lo << n;
            let hi = (self.hi << n) | (self.lo >> (128 - n));
            Self::new(lo, hi)
        } else if n == 128 {
            Self::new(0, self.lo)
        } else {
            Self::new(0, self.lo << (n - 128))
        }
    }

    fn shr(self, n: u32) -> Self {
        assert!(n < 256, "shift amount must be in [0, 256)");
        if n == 0 {
            return self;
        }
        if n < 128 {
            let hi = self.hi >> n;
            let lo = (self.lo >> n) | (self.hi << (128 - n));
            Self::new(lo, hi)
        } else if n == 128 {
            Self::new(self.hi, 0)
        } else {
            Self::new(self.hi >> (n - 128), 0)
        }
    }

    fn rotl(self, n: u32) -> Self {
        assert!(n < 256, "rotation amount must be in [0, 256)");
        if n == 0 { self } else { self.shl(n) | self.shr(256 - n) }
    }

    fn rotr(self, n: u32) -> Self {
        assert!(n < 256, "rotation amount must be in [0, 256)");
        if n == 0 { self } else { self.shr(n) | self.shl(256 - n) }
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

impl Not for U256 {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self::new(!self.lo, !self.hi)
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.hi.cmp(&other.hi).then(self.lo.cmp(&other.lo))
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
#[cfg(feature = "arbitrary")]
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

fn assert_divmod(a: U256, b: U256) {
    let (q, r) = a.divmod(b);
    let q_limbs = q.to_le_limbs();
    let r_limbs = r.to_le_limbs();
    let source = format!(
        "
        use miden::core::math::u256
        begin
            exec.u256::divmod
            {assert_r}
            {assert_q}
        end",
        assert_r = assert_stack_words(&r_limbs),
        assert_q = assert_stack_words(&q_limbs),
    );
    let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
    build_test!(&source, &operands).execute().unwrap();
}

#[cfg(feature = "arbitrary")]
fn assert_div(a: U256, b: U256) {
    let (q, _) = a.divmod(b);
    let q_limbs = q.to_le_limbs();
    let source = format!(
        "
        use miden::core::math::u256
        begin
            exec.u256::div
            {assert_q}
        end",
        assert_q = assert_stack_words(&q_limbs),
    );
    let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
    build_test!(&source, &operands).execute().unwrap();
}

#[cfg(feature = "arbitrary")]
fn assert_mod(a: U256, b: U256) {
    let (_, r) = a.divmod(b);
    let r_limbs = r.to_le_limbs();
    let source = format!(
        "
        use miden::core::math::u256
        begin
            exec.u256::mod
            {assert_r}
        end",
        assert_r = assert_stack_words(&r_limbs),
    );
    let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
    build_test!(&source, &operands).execute().unwrap();
}

fn assert_widening_mul(a: U256, b: U256) {
    let (lo, hi) = a.widening_mul(b);
    let lo_limbs = lo.to_le_limbs();
    let hi_limbs = hi.to_le_limbs();
    // widening_mul outputs [c0..c15] with the lo half on top, so assert lo first.
    let source = format!(
        "
        use miden::core::math::u256
        begin
            exec.u256::widening_mul
            {assert_lo}
            {assert_hi}
        end",
        assert_lo = assert_stack_words(&lo_limbs),
        assert_hi = assert_stack_words(&hi_limbs),
    );
    let operands = [b.to_le_limbs(), a.to_le_limbs()].concat();
    build_test!(&source, &operands).execute().unwrap();
}

fn assert_overflowing_mul(a: U256, b: U256) {
    let (overflow, c) = a.overflowing_mul(b);
    let lo = c.to_le_limbs();
    let source = format!(
        "
        use miden::core::math::u256
        begin
            exec.u256::overflowing_mul
            push.{overflow} assert_eq
            {assert_expected}
        end",
        assert_expected = assert_stack_words(&lo),
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

fn assert_shift_op(op: &str, n: u32, value: U256, expected: &[u64]) {
    let source = format!(
        "
        use miden::core::math::u256
        begin
            exec.u256::{op}
            {assert_expected}
        end",
        assert_expected = assert_stack_words(expected),
    );
    let mut operands = vec![u64::from(n)];
    operands.extend(value.to_le_limbs());
    build_test!(&source, &operands).execute().unwrap();
}

fn expected_sub(a: &U256, b: &U256) -> (u64, Vec<u64>) {
    let (underflow, result) = a.overflowing_sub(*b);
    (underflow, result.to_le_limbs())
}
