use miden_utils_testing::proptest::prelude::*;

use super::build_op_test;

// PUSHING VALUES ONTO THE STACK (PUSH)
// ================================================================================================

#[test]
fn push_one() {
    let asm_op_base = "push";

    // --- test zero ------------------------------------------------------------------------------
    let asm_op = format!("{}.{}", asm_op_base, "0");
    let test = build_op_test!(&asm_op);
    test.expect_stack(&[0]);

    // --- single decimal input -------------------------------------------------------------------
    let asm_op = format!("{}.{}", asm_op_base, "5");
    let test = build_op_test!(&asm_op);
    test.expect_stack(&[5]);

    // --- single hexadecimal input ---------------------------------------------------------------
    let asm_op = format!("{}.{}", asm_op_base, "0xAF");
    let test = build_op_test!(&asm_op);
    test.expect_stack(&[175]);
}

#[test]
fn push_many() {
    let base_op = "push";

    // --- multiple values as individual push instructions ----------------------------------------
    let asm_op = format!("{base_op}.17 {base_op}.0x13 {base_op}.23");
    let test = build_op_test!(asm_op);
    test.expect_stack(&[23, 19, 17]);

    // --- push 16 decimal values as individual push instructions --------------------------------
    let asm_op = (16..32).map(|i| format!("{base_op}.{i}")).collect::<Vec<_>>().join(" ");
    let mut expected = Vec::with_capacity(16);
    for i in (16..32).rev() {
        expected.push(i);
    }

    let test = build_op_test!(asm_op);
    test.expect_stack(&expected);

    // --- push hexadecimal values as individual push instructions --------------------------------
    let asm_op = format!("{base_op}.0x0A {base_op}.0x64 {base_op}.0x03E8 {base_op}.0x2710 {base_op}.0x0186A0");
    let mut expected = Vec::with_capacity(5);
    for i in (1..=5).rev() {
        expected.push(10_u64.pow(i));
    }

    let test = build_op_test!(asm_op);
    test.expect_stack(&expected);

    // --- push a mixture of decimal and hexadecimal values --------------------------------------
    let asm_op = format!("{base_op}.2 {base_op}.4 {base_op}.8 {base_op}.0x10 {base_op}.0x20 {base_op}.0x40 {base_op}.128 {base_op}.0x0100");
    let mut expected = Vec::with_capacity(8);
    for i in (1_u32..=8).rev() {
        expected.push(2_u64.pow(i));
    }

    let test = build_op_test!(asm_op);
    test.expect_stack(&expected);
}

#[test]
fn push_without_separator() {
    // --- push the maximum allowed number of hexadecimal values without separators (4) -----------
    let asm_op = "push.0x\
    0000000000000000\
    0100000000000000\
    0200000000000000\
    0300000000000000";
    // First word goes to position 0 (top)
    let expected = vec![0, 1, 2, 3];

    let test = build_op_test!(asm_op);
    test.expect_stack(&expected);
}

#[test]
fn push_odd_hex_length_original_issue() {
    // Test for issue 1302: now fixed with padding
    let asm_op = "push.0x100";

    let test = build_op_test!(asm_op);
    test.expect_stack(&[256]); // 0x100 = 256 (now works with padding)
}

proptest! {
    #[test]
    fn proptest_push_all_hex_lengths(
        // Generate random hex strings of all lengths between 1 and 16
        length in 1usize..=16,
        hex_bytes in prop::collection::vec(prop::num::u8::ANY, 1..=16)
    ) {
        // Convert to hex string, taking only the lower 4 bits of each byte
        let hex_str: String = hex_bytes.iter()
            .take(length)
            .map(|&b| format!("{:x}", b & 0xF))
            .collect();

        // Calculate expected value by padding with leading zero for odd lengths
        let padded_hex = if hex_str.len() % 2 == 1 {
            format!("0{}", hex_str)
        } else {
            hex_str.clone()
        };

        // Parse as 64-bit integer (this should always succeed for valid hex)
        let expected = u64::from_str_radix(&padded_hex, 16).unwrap();

        // Build assembly operation
        let asm_op = format!("push.0x{}", hex_str);

        // Test that it parses and executes correctly
        let test = build_op_test!(&asm_op);
        test.expect_stack(&[expected]);
    }
}
