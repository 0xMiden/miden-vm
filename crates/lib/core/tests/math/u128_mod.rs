use miden_core::Felt;
use miden_utils_testing::proptest::prelude::*;

// =================================================================================================
// EDGE CASE TESTS
// =================================================================================================

/// Helper to run a u128 operation and check the result
fn test_u128_op(op: &str, a: u128, b: u128, expected: &[u64]) {
    let (a_hh, a_mh, a_ml, a_ll) = split_u128(a);
    let (b_hh, b_mh, b_ml, b_ll) = split_u128(b);

    let source = format!(
        "
        use miden::core::math::u128
        begin
            exec.u128::{op}
        end
        "
    );

    build_test!(&source, &[b_ll, b_ml, b_mh, b_hh, a_ll, a_ml, a_mh, a_hh]).expect_stack(expected);
}

/// Helper to run a u128 operation and verify stack preservation
fn test_u128_op_stack_preservation(op: &str, a: u128, b: u128, expected_len: usize) {
    let (a_hh, a_mh, a_ml, a_ll) = split_u128(a);
    let (b_hh, b_mh, b_ml, b_ll) = split_u128(b);
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
    let test = build_test!(&source, &[b_ll, b_ml, b_mh, b_hh, a_ll, a_ml, a_mh, a_hh, sentinel]);

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
    let (c_hh, c_mh, c_ml, c_ll) = split_u128(0);
    test_u128_op("overflowing_add", 0, 0, &[0, c_ll, c_ml, c_mh, c_hh]);
    test_u128_op("wrapping_add", 0, 0, &[c_ll, c_ml, c_mh, c_hh]);
}

#[test]
fn edge_case_add_max_values() {
    // MAX + MAX = overflow
    let a = u128::MAX;
    let b = u128::MAX;
    let (c, ov) = a.overflowing_add(b);
    let (c_hh, c_mh, c_ml, c_ll) = split_u128(c);
    test_u128_op("overflowing_add", a, b, &[ov as u64, c_ll, c_ml, c_mh, c_hh]);
    // wrapping_add returns the same c value, reuse the split
    test_u128_op("wrapping_add", a, b, &[c_ll, c_ml, c_mh, c_hh]);
}

#[test]
fn edge_case_add_max_plus_one() {
    // MAX + 1 = 0 with overflow
    let a = u128::MAX;
    let b = 1u128;
    let (c, ov) = a.overflowing_add(b);
    assert!(ov);
    assert_eq!(c, 0);
    let (c_hh, c_mh, c_ml, c_ll) = split_u128(c);
    test_u128_op("overflowing_add", a, b, &[1, c_ll, c_ml, c_mh, c_hh]);
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
    let (c_hh, c_mh, c_ml, c_ll) = split_u128(c);
    test_u128_op("overflowing_add", a, b, &[0, c_ll, c_ml, c_mh, c_hh]);
}

#[test]
fn edge_case_sub_zeros() {
    // 0 - 0 = 0, no underflow
    let (c_hh, c_mh, c_ml, c_ll) = split_u128(0);
    test_u128_op("overflowing_sub", 0, 0, &[0, c_ll, c_ml, c_mh, c_hh]);
    test_u128_op("wrapping_sub", 0, 0, &[c_ll, c_ml, c_mh, c_hh]);
}

#[test]
fn edge_case_sub_underflow() {
    // 0 - 1 = MAX with underflow
    let a = 0u128;
    let b = 1u128;
    let (c, un) = a.overflowing_sub(b);
    assert!(un);
    assert_eq!(c, u128::MAX);
    let (c_hh, c_mh, c_ml, c_ll) = split_u128(c);
    test_u128_op("overflowing_sub", a, b, &[1, c_ll, c_ml, c_mh, c_hh]);
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
    let (c_hh, c_mh, c_ml, c_ll) = split_u128(c);
    test_u128_op("overflowing_sub", a, b, &[0, c_ll, c_ml, c_mh, c_hh]);
}

#[test]
fn edge_case_mul_zeros() {
    // 0 * anything = 0
    let (c_hh, c_mh, c_ml, c_ll) = split_u128(0);
    test_u128_op("overflowing_mul", 0, 0, &[0, c_ll, c_ml, c_mh, c_hh]);
    test_u128_op("overflowing_mul", 0, u128::MAX, &[0, c_ll, c_ml, c_mh, c_hh]);
    test_u128_op("overflowing_mul", u128::MAX, 0, &[0, c_ll, c_ml, c_mh, c_hh]);
    test_u128_op("wrapping_mul", 0, 12345, &[c_ll, c_ml, c_mh, c_hh]);
}

#[test]
fn edge_case_mul_one() {
    // 1 * x = x
    let x = 0x12345678_9abcdef0_12345678_9abcdef0u128;
    let (c_hh, c_mh, c_ml, c_ll) = split_u128(x);
    test_u128_op("overflowing_mul", 1, x, &[0, c_ll, c_ml, c_mh, c_hh]);
    test_u128_op("overflowing_mul", x, 1, &[0, c_ll, c_ml, c_mh, c_hh]);
    test_u128_op("wrapping_mul", 1, x, &[c_ll, c_ml, c_mh, c_hh]);
}

#[test]
fn edge_case_mul_max_times_two() {
    // MAX * 2 = overflow, result is MAX - 1 (since MAX*2 mod 2^128 = -2 mod 2^128 = MAX-1)
    let a = u128::MAX;
    let b = 2u128;
    let (c, ov) = a.overflowing_mul(b);
    assert!(ov);
    let (c_hh, c_mh, c_ml, c_ll) = split_u128(c);
    test_u128_op("overflowing_mul", a, b, &[1, c_ll, c_ml, c_mh, c_hh]);
}

#[test]
fn edge_case_mul_powers_of_two() {
    // 2^64 * 2^63 = 2^127, no overflow
    let a = 1u128 << 64;
    let b = 1u128 << 63;
    let (c, ov) = a.overflowing_mul(b);
    assert!(!ov);
    assert_eq!(c, 1u128 << 127);
    let (c_hh, c_mh, c_ml, c_ll) = split_u128(c);
    test_u128_op("overflowing_mul", a, b, &[0, c_ll, c_ml, c_mh, c_hh]);

    // 2^64 * 2^64 = 2^128 overflows
    let a = 1u128 << 64;
    let b = 1u128 << 64;
    let (c, ov) = a.overflowing_mul(b);
    assert!(ov);
    assert_eq!(c, 0); // 2^128 mod 2^128 = 0
    let (c_hh, c_mh, c_ml, c_ll) = split_u128(c);
    test_u128_op("overflowing_mul", a, b, &[1, c_ll, c_ml, c_mh, c_hh]);
}

#[test]
fn edge_case_mul_single_limb() {
    // Test multiplication where only one limb is non-zero
    // low limb only: 0xFFFFFFFF * 0xFFFFFFFF
    let a = 0xffffffffu128;
    let b = 0xffffffffu128;
    let c = a.wrapping_mul(b);
    let (c_hh, c_mh, c_ml, c_ll) = split_u128(c);
    test_u128_op("wrapping_mul", a, b, &[c_ll, c_ml, c_mh, c_hh]);
}

#[test]
fn edge_case_stack_preservation() {
    // Verify that operations don't corrupt stack values beyond their outputs
    // overflowing ops output 5 values, wrapping ops output 4 values
    test_u128_op_stack_preservation("overflowing_add", 12345, 67890, 5);
    test_u128_op_stack_preservation("wrapping_add", 12345, 67890, 4);
    test_u128_op_stack_preservation("overflowing_sub", 67890, 12345, 5);
    test_u128_op_stack_preservation("wrapping_sub", 67890, 12345, 4);
    test_u128_op_stack_preservation("overflowing_mul", 12345, 67890, 5);
    test_u128_op_stack_preservation("wrapping_mul", 12345, 67890, 4);
}

// =================================================================================================
// PROPERTY-BASED TESTS
// =================================================================================================

proptest! {
    #[test]
    fn overflowing_add(a in any::<u128>(), b in any::<u128>()) {
        let (a_hh, a_mh, a_ml, a_ll) = split_u128(a);
        let (b_hh, b_mh, b_ml, b_ll) = split_u128(b);
        let (c, ov) = a.overflowing_add(b);
        let (c_hh, c_mh, c_ml, c_ll) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::overflowing_add
            end
        ";

        // LE convention: low limb at position 0 (top of stack)
        // StackInputs::try_from_ints puts first array element at position 0
        // Stack: [b_ll, b_ml, b_mh, b_hh, a_ll, a_ml, a_mh, a_hh, ...]
        build_test!(source, &[b_ll, b_ml, b_mh, b_hh, a_ll, a_ml, a_mh, a_hh])
            .expect_stack(&[ov as u64, c_ll, c_ml, c_mh, c_hh]);
    }

    #[test]
    fn wrapping_add(a in any::<u128>(), b in any::<u128>()) {
        let (a_hh, a_mh, a_ml, a_ll) = split_u128(a);
        let (b_hh, b_mh, b_ml, b_ll) = split_u128(b);
        let (c_hh, c_mh, c_ml, c_ll) = split_u128(a.wrapping_add(b));

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::wrapping_add
            end
        ";

        build_test!(source, &[b_ll, b_ml, b_mh, b_hh, a_ll, a_ml, a_mh, a_hh])
            .expect_stack(&[c_ll, c_ml, c_mh, c_hh]);
    }

    #[test]
    fn overflowing_sub(a in any::<u128>(), b in any::<u128>()) {
        let (a_hh, a_mh, a_ml, a_ll) = split_u128(a);
        let (b_hh, b_mh, b_ml, b_ll) = split_u128(b);
        let (c, un) = a.overflowing_sub(b);
        let (c_hh, c_mh, c_ml, c_ll) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::overflowing_sub
            end
        ";

        build_test!(source, &[b_ll, b_ml, b_mh, b_hh, a_ll, a_ml, a_mh, a_hh])
            .expect_stack(&[un as u64, c_ll, c_ml, c_mh, c_hh]);
    }

    #[test]
    fn wrapping_sub(a in any::<u128>(), b in any::<u128>()) {
        let (a_hh, a_mh, a_ml, a_ll) = split_u128(a);
        let (b_hh, b_mh, b_ml, b_ll) = split_u128(b);
        let (c_hh, c_mh, c_ml, c_ll) = split_u128(a.wrapping_sub(b));

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::wrapping_sub
            end
        ";

        build_test!(source, &[b_ll, b_ml, b_mh, b_hh, a_ll, a_ml, a_mh, a_hh])
            .expect_stack(&[c_ll, c_ml, c_mh, c_hh]);
    }

    #[test]
    fn overflowing_mul(a in any::<u128>(), b in any::<u128>()) {
        let (a_hh, a_mh, a_ml, a_ll) = split_u128(a);
        let (b_hh, b_mh, b_ml, b_ll) = split_u128(b);
        let (c, ov) = a.overflowing_mul(b);
        let (c_hh, c_mh, c_ml, c_ll) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::overflowing_mul
            end
        ";

        build_test!(source, &[b_ll, b_ml, b_mh, b_hh, a_ll, a_ml, a_mh, a_hh])
            .expect_stack(&[ov as u64, c_ll, c_ml, c_mh, c_hh]);
    }

    #[test]
    fn wrapping_mul(a in any::<u128>(), b in any::<u128>()) {
        let (a_hh, a_mh, a_ml, a_ll) = split_u128(a);
        let (b_hh, b_mh, b_ml, b_ll) = split_u128(b);
        let (c_hh, c_mh, c_ml, c_ll) = split_u128(a.wrapping_mul(b));

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::wrapping_mul
            end
        ";

        build_test!(source, &[b_ll, b_ml, b_mh, b_hh, a_ll, a_ml, a_mh, a_hh])
            .expect_stack(&[c_ll, c_ml, c_mh, c_hh]);
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
