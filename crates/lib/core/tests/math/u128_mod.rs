use miden_core::Felt;
use miden_utils_testing::proptest::prelude::*;

// =================================================================================================
// EDGE CASE TESTS
// =================================================================================================

/// Helper to run a u128 operation and check the result
fn test_u128_op(op: &str, a: u128, b: u128, expected: &[u64]) {
    let (a3, a2, a1, a0) = split_u128(a);
    let (b3, b2, b1, b0) = split_u128(b);

    let source = format!(
        "
        use miden::core::math::u128
        begin
            exec.u128::{op}
        end
        "
    );

    build_test!(&source, &[b0, b1, b2, b3, a0, a1, a2, a3]).expect_stack(expected);
}

/// Helper to run a u128 operation and verify stack preservation
fn test_u128_op_stack_preservation(op: &str, a: u128, b: u128, expected_len: usize) {
    let (a3, a2, a1, a0) = split_u128(a);
    let (b3, b2, b1, b0) = split_u128(b);
    let sentinel: u64 = 0xdeadbeef;

    let source = format!(
        "
        use miden::core::math::u128
        begin
            exec.u128::{op}
        end
        "
    );

    // Add sentinel value after the operands
    let test = build_test!(&source, &[b0, b1, b2, b3, a0, a1, a2, a3, sentinel]);

    // Verify sentinel is preserved at the expected position
    let output = test.execute().unwrap();
    let stack_value = output.stack_outputs().get_element(expected_len).unwrap();
    assert_eq!(
        stack_value,
        Felt::new(sentinel),
        "Stack preservation failed for {op}: sentinel at position {expected_len} was corrupted"
    );
}

#[test]
fn edge_case_add_zeros() {
    // 0 + 0 = 0, no overflow
    let (c3, c2, c1, c0) = split_u128(0);
    test_u128_op("overflowing_add", 0, 0, &[0, c0, c1, c2, c3]);
    test_u128_op("widening_add", 0, 0, &[c0, c1, c2, c3, 0]);
    test_u128_op("wrapping_add", 0, 0, &[c0, c1, c2, c3]);
}

#[test]
fn edge_case_add_max_values() {
    // MAX + MAX = overflow
    let a = u128::MAX;
    let b = u128::MAX;
    let (c, ov) = a.overflowing_add(b);
    let (c3, c2, c1, c0) = split_u128(c);
    test_u128_op("overflowing_add", a, b, &[ov as u64, c0, c1, c2, c3]);
    // wrapping_add returns the same c value, reuse the split
    test_u128_op("wrapping_add", a, b, &[c0, c1, c2, c3]);
}

#[test]
fn edge_case_add_max_plus_one() {
    // MAX + 1 = 0 with overflow
    let a = u128::MAX;
    let b = 1u128;
    let (c, ov) = a.overflowing_add(b);
    assert!(ov);
    assert_eq!(c, 0);
    let (c3, c2, c1, c0) = split_u128(c);
    test_u128_op("overflowing_add", a, b, &[1, c0, c1, c2, c3]);
}

#[test]
fn edge_case_add_carry_propagation() {
    // Test carry propagating through all limbs: 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF + 1
    // This is u128::MAX + 1, already covered, but let's test intermediate carries too
    // 0x00000000_FFFFFFFF_FFFFFFFF_FFFFFFFF + 1 = 0x00000001_00000000_00000000_00000000
    let a = (1u128 << 96) - 1; // lower 96 bits all 1s
    let b = 1u128;
    let (c, ov) = a.overflowing_add(b);
    assert!(!ov);
    assert_eq!(c, 1u128 << 96);
    let (c3, c2, c1, c0) = split_u128(c);
    test_u128_op("overflowing_add", a, b, &[0, c0, c1, c2, c3]);
}

#[test]
fn edge_case_sub_zeros() {
    // 0 - 0 = 0, no underflow
    let (c3, c2, c1, c0) = split_u128(0);
    test_u128_op("overflowing_sub", 0, 0, &[0, c0, c1, c2, c3]);
    test_u128_op("wrapping_sub", 0, 0, &[c0, c1, c2, c3]);
}

#[test]
fn edge_case_sub_underflow() {
    // 0 - 1 = MAX with underflow
    let a = 0u128;
    let b = 1u128;
    let (c, un) = a.overflowing_sub(b);
    assert!(un);
    assert_eq!(c, u128::MAX);
    let (c3, c2, c1, c0) = split_u128(c);
    test_u128_op("overflowing_sub", a, b, &[1, c0, c1, c2, c3]);
}

#[test]
fn edge_case_sub_borrow_propagation() {
    // Test borrow propagating: 0x00000001_00000000_00000000_00000000 - 1
    // = 0x00000000_FFFFFFFF_FFFFFFFF_FFFFFFFF
    let a = 1u128 << 96;
    let b = 1u128;
    let (c, un) = a.overflowing_sub(b);
    assert!(!un);
    assert_eq!(c, (1u128 << 96) - 1);
    let (c3, c2, c1, c0) = split_u128(c);
    test_u128_op("overflowing_sub", a, b, &[0, c0, c1, c2, c3]);
}

#[test]
fn edge_case_mul_zeros() {
    // 0 * anything = 0
    let (c3, c2, c1, c0) = split_u128(0);
    test_u128_op("overflowing_mul", 0, 0, &[0, c0, c1, c2, c3]);
    test_u128_op("overflowing_mul", 0, u128::MAX, &[0, c0, c1, c2, c3]);
    test_u128_op("overflowing_mul", u128::MAX, 0, &[0, c0, c1, c2, c3]);
    test_u128_op("wrapping_mul", 0, 12345, &[c0, c1, c2, c3]);
}

#[test]
fn edge_case_mul_one() {
    // 1 * x = x
    let x = 0x12345678_9abcdef0_12345678_9abcdef0u128;
    let (c3, c2, c1, c0) = split_u128(x);
    test_u128_op("overflowing_mul", 1, x, &[0, c0, c1, c2, c3]);
    test_u128_op("overflowing_mul", x, 1, &[0, c0, c1, c2, c3]);
    test_u128_op("widening_mul", 1, x, &[c0, c1, c2, c3, 0]);
    test_u128_op("wrapping_mul", 1, x, &[c0, c1, c2, c3]);
}

#[test]
fn edge_case_mul_max_times_two() {
    // MAX * 2 = overflow, result is MAX - 1 (since MAX*2 mod 2^128 = -2 mod 2^128 = MAX-1)
    let a = u128::MAX;
    let b = 2u128;
    let (c, ov) = a.overflowing_mul(b);
    assert!(ov);
    let (c3, c2, c1, c0) = split_u128(c);
    test_u128_op("overflowing_mul", a, b, &[1, c0, c1, c2, c3]);
}

#[test]
fn edge_case_mul_powers_of_two() {
    // 2^64 * 2^63 = 2^127, no overflow
    let a = 1u128 << 64;
    let b = 1u128 << 63;
    let (c, ov) = a.overflowing_mul(b);
    assert!(!ov);
    assert_eq!(c, 1u128 << 127);
    let (c3, c2, c1, c0) = split_u128(c);
    test_u128_op("overflowing_mul", a, b, &[0, c0, c1, c2, c3]);

    // 2^64 * 2^64 = 2^128 overflows
    let a = 1u128 << 64;
    let b = 1u128 << 64;
    let (c, ov) = a.overflowing_mul(b);
    assert!(ov);
    assert_eq!(c, 0); // 2^128 mod 2^128 = 0
    let (c3, c2, c1, c0) = split_u128(c);
    test_u128_op("overflowing_mul", a, b, &[1, c0, c1, c2, c3]);
}

#[test]
fn edge_case_mul_single_limb() {
    // Test multiplication where only one limb is non-zero
    // low limb only: 0xFFFFFFFF * 0xFFFFFFFF
    let a = 0xffffffffu128;
    let b = 0xffffffffu128;
    let c = a.wrapping_mul(b);
    let (c3, c2, c1, c0) = split_u128(c);
    test_u128_op("wrapping_mul", a, b, &[c0, c1, c2, c3]);
}

#[test]
fn edge_case_stack_preservation() {
    // Verify that operations don't corrupt stack values beyond their outputs
    // overflowing ops output 5 values, wrapping ops output 4 values
    test_u128_op_stack_preservation("overflowing_add", 12345, 67890, 5);
    test_u128_op_stack_preservation("widening_add", 12345, 67890, 5);
    test_u128_op_stack_preservation("wrapping_add", 12345, 67890, 4);
    test_u128_op_stack_preservation("overflowing_sub", 67890, 12345, 5);
    test_u128_op_stack_preservation("wrapping_sub", 67890, 12345, 4);
    test_u128_op_stack_preservation("overflowing_mul", 12345, 67890, 5);
    test_u128_op_stack_preservation("widening_mul", 12345, 67890, 5);
    test_u128_op_stack_preservation("wrapping_mul", 12345, 67890, 4);
}

// =================================================================================================
// PROPERTY-BASED TESTS
// =================================================================================================

proptest! {
    #[test]
    fn overflowing_add(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let (c, ov) = a.overflowing_add(b);
        let (c3, c2, c1, c0) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::overflowing_add
            end
        ";

        // LE convention: low limb at position 0 (top of stack)
        // StackInputs::try_from_ints puts first array element at position 0
        // Stack: [b0, b1, b2, b3, a0, a1, a2, a3, ...]
        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[ov as u64, c0, c1, c2, c3]);
    }

    #[test]
    fn widening_add(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let (c, ov) = a.overflowing_add(b);
        let (c3, c2, c1, c0) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::widening_add
            end
        ";

        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[c0, c1, c2, c3, ov as u64]);
    }

    #[test]
    fn wrapping_add(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let (c3, c2, c1, c0) = split_u128(a.wrapping_add(b));

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::wrapping_add
            end
        ";

        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[c0, c1, c2, c3]);
    }

    #[test]
    fn overflowing_sub(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let (c, un) = a.overflowing_sub(b);
        let (c3, c2, c1, c0) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::overflowing_sub
            end
        ";

        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[un as u64, c0, c1, c2, c3]);
    }

    #[test]
    fn wrapping_sub(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let (c3, c2, c1, c0) = split_u128(a.wrapping_sub(b));

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::wrapping_sub
            end
        ";

        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[c0, c1, c2, c3]);
    }

    #[test]
    fn overflowing_mul(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let (c, ov) = a.overflowing_mul(b);
        let (c3, c2, c1, c0) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::overflowing_mul
            end
        ";

        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[ov as u64, c0, c1, c2, c3]);
    }

    #[test]
    fn widening_mul(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let (c, ov) = a.overflowing_mul(b);
        let (c3, c2, c1, c0) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::widening_mul
            end
        ";

        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[c0, c1, c2, c3, ov as u64]);
    }

    #[test]
    fn wrapping_mul(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let (c3, c2, c1, c0) = split_u128(a.wrapping_mul(b));

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::wrapping_mul
            end
        ";

        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[c0, c1, c2, c3]);
    }
}

fn split_u128(value: u128) -> (u64, u64, u64, u64) {
    (
        (value >> 96) as u64,
        (value >> 64) as u32 as u64,
        (value >> 32) as u32 as u64,
        value as u32 as u64,
    )
}

// =================================================================================================
// COMPARISON TESTS
// =================================================================================================

proptest! {
    #[test]
    fn test_eq(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let expected = if a == b { 1u64 } else { 0u64 };

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::eq
            end
        ";

        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[expected]);
    }

    #[test]
    fn test_neq(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let expected = if a != b { 1u64 } else { 0u64 };

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::neq
            end
        ";

        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[expected]);
    }

    #[test]
    fn test_lt(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let expected = if a < b { 1u64 } else { 0u64 };

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::lt
            end
        ";

        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[expected]);
    }

    #[test]
    fn test_lte(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let expected = if a <= b { 1u64 } else { 0u64 };

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::lte
            end
        ";

        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[expected]);
    }

    #[test]
    fn test_gt(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let expected = if a > b { 1u64 } else { 0u64 };

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::gt
            end
        ";

        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[expected]);
    }

    #[test]
    fn test_gte(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let expected = if a >= b { 1u64 } else { 0u64 };

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::gte
            end
        ";

        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[expected]);
    }

    #[test]
    fn test_eqz(a in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let expected = if a == 0 { 1u64 } else { 0u64 };

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::eqz
            end
        ";

        build_test!(source, &[a0, a1, a2, a3])
            .expect_stack(&[expected]);
    }
}

// =================================================================================================
// BITWISE TESTS
// =================================================================================================

proptest! {
    #[test]
    fn test_and(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let c = a & b;
        let (c3, c2, c1, c0) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::and
            end
        ";

        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[c0, c1, c2, c3]);
    }

    #[test]
    fn test_or(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let c = a | b;
        let (c3, c2, c1, c0) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::or
            end
        ";

        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[c0, c1, c2, c3]);
    }

    #[test]
    fn test_xor(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let c = a ^ b;
        let (c3, c2, c1, c0) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::xor
            end
        ";

        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[c0, c1, c2, c3]);
    }

    #[test]
    fn test_not(a in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let c = !a;
        let (c3, c2, c1, c0) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::not
            end
        ";

        build_test!(source, &[a0, a1, a2, a3])
            .expect_stack(&[c0, c1, c2, c3]);
    }
}

// =================================================================================================
// SHIFT TESTS
// =================================================================================================

proptest! {
    #[test]
    fn test_shl(a in any::<u128>(), n in 0u32..128u32) {
        let (a3, a2, a1, a0) = split_u128(a);
        let c = a << n;
        let (c3, c2, c1, c0) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::shl
            end
        ";

        build_test!(source, &[n as u64, a0, a1, a2, a3])
            .expect_stack(&[c0, c1, c2, c3]);
    }

    #[test]
    fn test_shr(a in any::<u128>(), n in 0u32..128u32) {
        let (a3, a2, a1, a0) = split_u128(a);
        let c = a >> n;
        let (c3, c2, c1, c0) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::shr
            end
        ";

        build_test!(source, &[n as u64, a0, a1, a2, a3])
            .expect_stack(&[c0, c1, c2, c3]);
    }

    #[test]
    fn test_rotl(a in any::<u128>(), n in 0u32..128u32) {
        let (a3, a2, a1, a0) = split_u128(a);
        let c = a.rotate_left(n);
        let (c3, c2, c1, c0) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::rotl
            end
        ";

        build_test!(source, &[n as u64, a0, a1, a2, a3])
            .expect_stack(&[c0, c1, c2, c3]);
    }

    #[test]
    fn test_rotr(a in any::<u128>(), n in 0u32..128u32) {
        let (a3, a2, a1, a0) = split_u128(a);
        let c = a.rotate_right(n);
        let (c3, c2, c1, c0) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::rotr
            end
        ";

        build_test!(source, &[n as u64, a0, a1, a2, a3])
            .expect_stack(&[c0, c1, c2, c3]);
    }
}

// =================================================================================================
// MIN/MAX TESTS
// =================================================================================================

proptest! {
    #[test]
    fn test_min(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let c = a.min(b);
        let (c3, c2, c1, c0) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::min
            end
        ";

        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[c0, c1, c2, c3]);
    }

    #[test]
    fn test_max(a in any::<u128>(), b in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let (b3, b2, b1, b0) = split_u128(b);
        let c = a.max(b);
        let (c3, c2, c1, c0) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::max
            end
        ";

        build_test!(source, &[b0, b1, b2, b3, a0, a1, a2, a3])
            .expect_stack(&[c0, c1, c2, c3]);
    }
}

// =================================================================================================
// BIT-COUNTING TESTS
// =================================================================================================

proptest! {
    #[test]
    fn test_clz(a in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let expected = a.leading_zeros() as u64;

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::clz
            end
        ";

        build_test!(source, &[a0, a1, a2, a3])
            .expect_stack(&[expected]);
    }

    #[test]
    fn test_ctz(a in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let expected = a.trailing_zeros() as u64;

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::ctz
            end
        ";

        build_test!(source, &[a0, a1, a2, a3])
            .expect_stack(&[expected]);
    }

    #[test]
    fn test_clo(a in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let expected = a.leading_ones() as u64;

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::clo
            end
        ";

        build_test!(source, &[a0, a1, a2, a3])
            .expect_stack(&[expected]);
    }

    #[test]
    fn test_cto(a in any::<u128>()) {
        let (a3, a2, a1, a0) = split_u128(a);
        let expected = a.trailing_ones() as u64;

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::cto
            end
        ";

        build_test!(source, &[a0, a1, a2, a3])
            .expect_stack(&[expected]);
    }
}

// =================================================================================================
// SHIFT STACK PADDING TESTS
// =================================================================================================

/// Test that shr does not leak sentinel values from below the stack frame into results.
/// This verifies that shr_k1/k2/k3 helpers explicitly push zeros instead of relying on
/// implicit stack padding.
#[test]
fn shr_stack_padding_k1() {
    let a: u128 = 0x00000000_00000000_00000000_FFFFFFFFu128;
    let (a3, a2, a1, a0) = split_u128(a);
    let sentinel1: u64 = 0xDEADBEEF;
    let sentinel2: u64 = 0xCAFEBABE;

    let source = "
        use miden::core::math::u128
        begin
            exec.u128::shr
        end
    ";

    // Shift right by 32 (k=1, m=0): c0=a1, c1=a2, c2=a3, c3=0
    let c = a >> 32;
    let (c3, c2, c1, c0) = split_u128(c);

    let test = build_test!(source, &[sentinel1, sentinel2, 32u64, a0, a1, a2, a3]);
    let result = test.execute().unwrap();

    // Verify the result is correct and sentinels do not appear in the output
    let stack = result.stack_outputs();
    assert_eq!(stack.get_element(0).unwrap(), Felt::new(c0), "c0 mismatch");
    assert_eq!(stack.get_element(1).unwrap(), Felt::new(c1), "c1 mismatch");
    assert_eq!(stack.get_element(2).unwrap(), Felt::new(c2), "c2 mismatch");
    assert_eq!(stack.get_element(3).unwrap(), Felt::new(0), "c3 should be 0, not a sentinel");
}

#[test]
fn shr_stack_padding_k2() {
    let a: u128 = 0x00000000_00000000_FFFFFFFF_FFFFFFFFu128;
    let (a3, a2, a1, a0) = split_u128(a);
    let sentinel1: u64 = 0xDEADBEEF;
    let sentinel2: u64 = 0xCAFEBABE;

    let source = "
        use miden::core::math::u128
        begin
            exec.u128::shr
        end
    ";

    // Shift right by 64 (k=2, m=0): c0=a2, c1=a3, c2=0, c3=0
    let c = a >> 64;
    let (c3, c2, c1, c0) = split_u128(c);

    let test = build_test!(source, &[sentinel1, sentinel2, 64u64, a0, a1, a2, a3]);
    let result = test.execute().unwrap();

    let stack = result.stack_outputs();
    assert_eq!(stack.get_element(0).unwrap(), Felt::new(c0), "c0 mismatch");
    assert_eq!(stack.get_element(1).unwrap(), Felt::new(c1), "c1 mismatch");
    assert_eq!(stack.get_element(2).unwrap(), Felt::new(0), "c2 should be 0, not a sentinel");
    assert_eq!(stack.get_element(3).unwrap(), Felt::new(0), "c3 should be 0, not a sentinel");
}

#[test]
fn shr_stack_padding_k3() {
    let a: u128 = 0xFFFFFFFF_00000000_00000000_00000000u128;
    let (a3, a2, a1, a0) = split_u128(a);
    let sentinel1: u64 = 0xDEADBEEF;
    let sentinel2: u64 = 0xCAFEBABE;

    let source = "
        use miden::core::math::u128
        begin
            exec.u128::shr
        end
    ";

    // Shift right by 96 (k=3, m=0): c0=a3, c1=0, c2=0, c3=0
    let c = a >> 96;
    let (c3, c2, c1, c0) = split_u128(c);

    let test = build_test!(source, &[sentinel1, sentinel2, 96u64, a0, a1, a2, a3]);
    let result = test.execute().unwrap();

    let stack = result.stack_outputs();
    assert_eq!(stack.get_element(0).unwrap(), Felt::new(c0), "c0 mismatch");
    assert_eq!(stack.get_element(1).unwrap(), Felt::new(0), "c1 should be 0, not a sentinel");
    assert_eq!(stack.get_element(2).unwrap(), Felt::new(0), "c2 should be 0, not a sentinel");
    assert_eq!(stack.get_element(3).unwrap(), Felt::new(0), "c3 should be 0, not a sentinel");
}

/// Test shr with non-zero m values and sentinels to verify cross-limb bit transfer
/// doesn't leak stack values.
#[test]
fn shr_stack_padding_nonzero_m() {
    let a: u128 = 0x00000001_00000001u128; // bits at positions 0 and 32
    let (a3, a2, a1, a0) = split_u128(a);
    let sentinel: u64 = 0xDEADBEEF;

    let source = "
        use miden::core::math::u128
        begin
            exec.u128::shr
        end
    ";

    // shr by 33 (k=1, m=1): crosses limb boundary
    let c = a >> 33;
    let (c3, c2, c1, c0) = split_u128(c);

    let test = build_test!(source, &[sentinel, 33u64, a0, a1, a2, a3]);
    let result = test.execute().unwrap();

    let stack = result.stack_outputs();
    assert_eq!(stack.get_element(0).unwrap(), Felt::new(c0), "c0 mismatch");
    assert_eq!(stack.get_element(1).unwrap(), Felt::new(c1), "c1 mismatch");
    assert_eq!(stack.get_element(2).unwrap(), Felt::new(c2), "c2 mismatch");
    assert_eq!(stack.get_element(3).unwrap(), Felt::new(0), "c3 should be 0, not a sentinel");
}

/// Test shr with boundary shift values.
#[test]
fn shr_boundary_values() {
    let a: u128 = 0x12345678_9ABCDEF0_12345678_9ABCDEF0u128;
    let (a3, a2, a1, a0) = split_u128(a);

    let source = "
        use miden::core::math::u128
        begin
            exec.u128::shr
        end
    ";

    let boundaries = [0, 1, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127];
    for n in boundaries {
        let c = a >> n;
        let (c3, c2, c1, c0) = split_u128(c);

        build_test!(source, &[n as u64, a0, a1, a2, a3])
            .expect_stack(&[c0, c1, c2, c3]);
    }
}

/// Test shl with boundary shift values.
#[test]
fn shl_boundary_values() {
    let a: u128 = 0x12345678_9ABCDEF0_12345678_9ABCDEF0u128;
    let (a3, a2, a1, a0) = split_u128(a);

    let source = "
        use miden::core::math::u128
        begin
            exec.u128::shl
        end
    ";

    let boundaries = [0, 1, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127];
    for n in boundaries {
        let c = a << n;
        let (c3, c2, c1, c0) = split_u128(c);

        build_test!(source, &[n as u64, a0, a1, a2, a3])
            .expect_stack(&[c0, c1, c2, c3]);
    }
}

/// Test rotl with n=0 is identity.
#[test]
fn rotl_n_zero_is_identity() {
    let a: u128 = 0x12345678_9ABCDEF0_12345678_9ABCDEF0u128;
    let (a3, a2, a1, a0) = split_u128(a);

    let source = "
        use miden::core::math::u128
        begin
            exec.u128::rotl
        end
    ";

    build_test!(source, &[0u64, a0, a1, a2, a3])
        .expect_stack(&[a0, a1, a2, a3]);
}

/// Test rotr with n=0 is identity.
#[test]
fn rotr_n_zero_is_identity() {
    let a: u128 = 0x12345678_9ABCDEF0_12345678_9ABCDEF0u128;
    let (a3, a2, a1, a0) = split_u128(a);

    let source = "
        use miden::core::math::u128
        begin
            exec.u128::rotr
        end
    ";

    build_test!(source, &[0u64, a0, a1, a2, a3])
        .expect_stack(&[a0, a1, a2, a3]);
}

/// Test that shr with n >= 128 produces an assertion error.
#[test]
fn shr_out_of_range_errors() {
    let a: u128 = 0x12345678_9ABCDEF0_12345678_9ABCDEF0u128;
    let (a3, a2, a1, a0) = split_u128(a);

    let source = "
        use miden::core::math::u128
        begin
            exec.u128::shr
        end
    ";

    let test = build_test!(source, &[128u64, a0, a1, a2, a3]);
    expect_assert_error_message!(test);

    let test = build_test!(source, &[200u64, a0, a1, a2, a3]);
    expect_assert_error_message!(test);
}

/// Test that shl with n >= 128 produces an assertion error.
#[test]
fn shl_out_of_range_errors() {
    let a: u128 = 0x12345678_9ABCDEF0_12345678_9ABCDEF0u128;
    let (a3, a2, a1, a0) = split_u128(a);

    let source = "
        use miden::core::math::u128
        begin
            exec.u128::shl
        end
    ";

    let test = build_test!(source, &[128u64, a0, a1, a2, a3]);
    expect_assert_error_message!(test);

    let test = build_test!(source, &[200u64, a0, a1, a2, a3]);
    expect_assert_error_message!(test);
}
