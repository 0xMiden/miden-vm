use miden_assembly::testing::regex;
use miden_processor::{ExecutionError, RowIndex};
use miden_utils_testing::{
    Felt, FieldElement, ONE, StarkField, WORD_SIZE, ZERO, assert_assembler_diagnostic,
    assert_diagnostic_lines, build_op_test, expect_exec_error_matches, prop_randw,
    proptest::prelude::*, rand::rand_value,
};

// FIELD OPS ARITHMETIC - MANUAL TESTS
// ================================================================================================

#[test]
fn add() {
    let asm_op = "add";

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2]);
    test.expect_stack(&[3]);

    let test = build_op_test!(asm_op, &[5, 8]);
    test.expect_stack(&[13]);

    // --- test overflow --------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[Felt::MODULUS - 1, 9]);
    test.expect_stack(&[8]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let c = rand_value::<u64>();
    let test = build_op_test!(asm_op, &[c, 5, 2]);
    test.expect_stack(&[7, c]);
}

#[test]
fn add_b() {
    let build_asm_op = |param: u64| format!("add.{param}");

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(build_asm_op(2), &[1]);
    test.expect_stack(&[3]);

    let test = build_op_test!(build_asm_op(0), &[28]);
    test.expect_stack(&[28]);

    let test = build_op_test!(build_asm_op(1), &[32]);
    test.expect_stack(&[33]);

    let test = build_op_test!(build_asm_op(8), &[5]);
    test.expect_stack(&[13]);

    // --- test overflow --------------------------------------------------------------------------
    let test = build_op_test!(build_asm_op(9), &[Felt::MODULUS - 1]);
    test.expect_stack(&[8]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let c = rand_value::<u64>();
    let test = build_op_test!(build_asm_op(2), &[c, 5]);
    test.expect_stack(&[7, c]);
}

#[test]
fn sub() {
    let asm_op = "sub";

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[3, 2]);
    test.expect_stack(&[1]);

    let test = build_op_test!(asm_op, &[10, 7]);
    test.expect_stack(&[3]);

    // --- test underflow -------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[0, 1]);
    test.expect_stack(&[Felt::MODULUS - 1]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let c = rand_value::<u64>();
    let test = build_op_test!(asm_op, &[c, 2, 2]);
    test.expect_stack(&[0, c]);
}

#[test]
fn sub_b() {
    let build_asm_op = |param: u64| format!("sub.{param}");

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(build_asm_op(2), &[3]);
    test.expect_stack(&[1]);

    let test = build_op_test!(build_asm_op(7), &[10]);
    test.expect_stack(&[3]);

    // --- test underflow -------------------------------------------------------------------------
    let test = build_op_test!(build_asm_op(1), &[0]);
    test.expect_stack(&[Felt::MODULUS - 1]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let c = rand_value::<u64>();
    let test = build_op_test!(build_asm_op(2), &[c, 2]);
    test.expect_stack(&[0, c]);
}

#[test]
fn mul() {
    let asm_op = "mul";

    // --- simple cases ---------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 0]);
    test.expect_stack(&[0]);

    let test = build_op_test!(asm_op, &[1, 5]);
    test.expect_stack(&[5]);

    // --- test overflow --------------------------------------------------------------------------
    let high_number = Felt::MODULUS - 1;
    let test = build_op_test!(asm_op, &[high_number, 2]);
    let expected = high_number as u128 * 2_u128 % Felt::MODULUS as u128;
    test.expect_stack(&[expected as u64]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let c = rand_value::<u64>();
    let test = build_op_test!(asm_op, &[c, 2, 2]);
    test.expect_stack(&[4, c]);
}

#[test]
fn mul_b() {
    let build_asm_op = |param: u64| format!("mul.{param}");

    // --- simple cases ---------------------------------------------------------------------------
    let test = build_op_test!(build_asm_op(0), &[1]);
    test.expect_stack(&[0]);

    let test = build_op_test!(build_asm_op(1), &[5]);
    test.expect_stack(&[5]);

    let test = build_op_test!(build_asm_op(2), &[5]);
    test.expect_stack(&[10]);

    // --- test overflow --------------------------------------------------------------------------
    let high_number = Felt::MODULUS - 1;
    let test = build_op_test!(build_asm_op(2), &[high_number]);
    let expected = high_number as u128 * 2_u128 % Felt::MODULUS as u128;
    test.expect_stack(&[expected as u64]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let c = rand_value::<u64>();
    let test = build_op_test!(build_asm_op(2), &[c, 2]);
    test.expect_stack(&[4, c]);
}

#[test]
fn div() {
    let asm_op = "div";

    // --- simple cases ---------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[0, 1]);
    test.expect_stack(&[0]);

    let test = build_op_test!(asm_op, &[2, 1]);
    test.expect_stack(&[2]);

    // --- test remainder -------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[5, 2]);
    let expected = (Felt::new(2).inv().as_int() as u128 * 5_u128) % Felt::MODULUS as u128;
    test.expect_stack(&[expected as u64]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let c = rand_value::<u64>();
    let test = build_op_test!(asm_op, &[c, 10, 5]);
    test.expect_stack(&[2, c]);
}

#[test]
fn div_b() {
    let build_asm_op = |param: u64| format!("div.{param}");

    // --- simple cases ---------------------------------------------------------------------------
    let test = build_op_test!(build_asm_op(1), &[0]);
    test.expect_stack(&[0]);

    let test = build_op_test!(build_asm_op(1), &[77]);
    test.expect_stack(&[77]);

    let test = build_op_test!(build_asm_op(0), &[14]);

    assert_assembler_diagnostic!(
        test,
        "invalid constant expression: division by zero",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "11 |",
        "12 | begin div.0 exec.truncate_stack end",
        "   :       ^^^^^",
        "   `----"
    );

    let test = build_op_test!(build_asm_op(2), &[4]);
    test.expect_stack(&[2]);

    // --- test remainder -------------------------------------------------------------------------
    let test = build_op_test!(build_asm_op(2), &[5]);
    let expected = (Felt::new(2).inv().as_int() as u128 * 5_u128) % Felt::MODULUS as u128;
    test.expect_stack(&[expected as u64]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let c = rand_value::<u64>();
    let test = build_op_test!(build_asm_op(5), &[c, 10]);
    test.expect_stack(&[2, c]);
}

#[test]
fn div_fail() {
    let asm_op = "div";

    // --- test divide by zero --------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 0]);
    expect_exec_error_matches!(
        test,
        ExecutionError::DivideByZero{ clk:value, label: _, source_file: _ } if value == RowIndex::from(2)
    );
}

#[test]
fn neg() {
    let asm_op = "neg";

    // --- simple cases ---------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1]);
    test.expect_stack(&[Felt::MODULUS - 1]);

    let test = build_op_test!(asm_op, &[64]);
    test.expect_stack(&[Felt::MODULUS - 64]);

    let test = build_op_test!(asm_op, &[0]);
    test.expect_stack(&[0]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let c = rand_value::<u64>();
    let test = build_op_test!(asm_op, &[c, 5]);
    test.expect_stack(&[Felt::MODULUS - 5, c]);
}

#[test]
fn neg_fail() {
    let asm_op = "neg.1";

    // --- test illegal argument -------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1]);

    assert_assembler_diagnostic!(
        test,
        "invalid syntax",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "11 |",
        "12 | begin neg.1 exec.truncate_stack end",
        "   :          |",
        "   :          `-- found a . here",
        "   `----",
        r#" help: expected primitive opcode (e.g. "add"), or "end", or control flow opcode (e.g. "if.true")"#
    );
}

#[test]
fn inv() {
    let asm_op = "inv";

    // --- simple cases ---------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1]);
    test.expect_stack(&[ONE.inv().as_int()]);

    let test = build_op_test!(asm_op, &[64]);
    test.expect_stack(&[Felt::new(64).inv().as_int()]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let c = rand_value::<u64>();
    let test = build_op_test!(asm_op, &[c, 5]);
    test.expect_stack(&[Felt::new(5).inv().as_int(), c]);
}

#[test]
fn inv_fail() {
    let asm_op = "inv";

    // --- test no inv on 0 -----------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[0]);
    expect_exec_error_matches!(test, ExecutionError::DivideByZero{clk: row_idx, label: _, source_file: _ } if row_idx == RowIndex::from(2));

    let asm_op = "inv.1";

    // --- test illegal argument -----------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1]);

    assert_assembler_diagnostic!(
        test,
        "invalid syntax",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "11 |",
        "12 | begin inv.1 exec.truncate_stack end",
        "   :          |",
        "   :          `-- found a . here",
        "   `----",
        r#" help: expected primitive opcode (e.g. "add"), or "end", or control flow opcode (e.g. "if.true")"#
    );
}

#[test]
fn pow2() {
    let asm_op = "pow2";

    build_op_test!(asm_op, &[0]).expect_stack(&[1]);
    build_op_test!(asm_op, &[31]).expect_stack(&[1 << 31]);
    build_op_test!(asm_op, &[63]).expect_stack(&[1 << 63]);
}

#[test]
fn pow2_fail() {
    let asm_op = "pow2";

    // --- random u32 values > 63 ------------------------------------------------------

    let mut value = rand_value::<u32>() as u64;
    value += (u32::MAX as u64) + 1;

    let test = build_op_test!(asm_op, &[value]);

    expect_exec_error_matches!(
        test,
        ExecutionError::FailedAssertion{clk, err_code, err_msg, label: _, source_file: _ }
        if clk == RowIndex::from(17) && err_code == ZERO && err_msg.is_none()
    );
}

#[test]
fn exp_bits_length() {
    let build_asm_op = |param: u64| format!("exp.u{param}");

    //---------------------- exp with parameter containing bits length ----------------------------

    let base = 9;
    let pow = 1021;
    let expected = Felt::new(base).exp(pow);

    let test = build_op_test!(build_asm_op(10), &[base, pow]);
    test.expect_stack(&[expected.as_int()]);
}

#[test]
fn exp_bits_length_fail() {
    let build_asm_op = |param: u64| format!("exp.u{param}");

    //---------------------- exp containing more bits than specified in the parameter ------------

    let base = 9;
    let pow = 1021; // pow is a 10 bit number

    let test = build_op_test!(build_asm_op(9), &[base, pow]);

    expect_exec_error_matches!(
        test,
        ExecutionError::FailedAssertion{clk, err_code, err_msg, label: _, source_file: _ }
        if clk == RowIndex::from(19) && err_code == ZERO && err_msg.is_none()
    );

    //---------------------- exp containing more than 64 bits -------------------------------------

    let base = 9;
    let pow = 1021; // pow is a 10 bit number

    let test = build_op_test!(build_asm_op(65), &[base, pow]);

    assert_assembler_diagnostic!(
        test,
        "invalid literal: expected value to be a valid bit size, e.g. 0..63",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "11 |",
        "12 | begin exp.u65 exec.truncate_stack end",
        "   :            ^^",
        "   `----",
        r#" help: expected primitive opcode (e.g. "add"), or "end", or control flow opcode (e.g. "if.true")"#
    );
}

#[test]
fn exp_small_pow() {
    let build_asm_op = |param: u64| format!("exp.{param}");

    let base = rand_value::<u64>();
    let pow = 7;
    let expected = Felt::new(base).exp(pow);

    let test = build_op_test!(build_asm_op(pow), &[base]);
    test.expect_stack(&[expected.as_int()]);
}

#[test]
fn ilog2() {
    let asm_op = "ilog2";
    build_op_test!(asm_op, &[1]).expect_stack(&[0]);
    build_op_test!(asm_op, &[8]).expect_stack(&[3]);
    build_op_test!(asm_op, &[15]).expect_stack(&[3]);
    build_op_test!(asm_op, &[Felt::MODULUS - 1]).expect_stack(&[63]);
}

#[test]
fn ilog2_fail() {
    let asm_op = "ilog2";

    let test = build_op_test!(asm_op, &[0]);
    expect_exec_error_matches!(
        test,
        ExecutionError::LogArgumentZero{ clk: row_idx, label: _, source_file: _ } if row_idx == RowIndex::from(3)
    );
}

// FIELD OPS BOOLEAN - MANUAL TESTS
// ================================================================================================

#[test]
fn not() {
    let asm_op = "not";

    let test = build_op_test!(asm_op, &[1]);
    test.expect_stack(&[0]);

    let test = build_op_test!(asm_op, &[0]);
    test.expect_stack(&[1]);
}

#[test]
fn not_fail() {
    let asm_op = "not";

    // --- test value > 1 --------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[2]);

    expect_exec_error_matches!(
        test,
        ExecutionError::NotBinaryValueOp{value, label: _, source_file: _ } if value == Felt::new(2_u64)
    );
}

#[test]
fn and() {
    let asm_op = "and";

    let test = build_op_test!(asm_op, &[1, 1]);
    test.expect_stack(&[1]);

    let test = build_op_test!(asm_op, &[0, 1]);
    test.expect_stack(&[0]);

    let test = build_op_test!(asm_op, &[1, 0]);
    test.expect_stack(&[0]);

    let test = build_op_test!(asm_op, &[0, 0]);
    test.expect_stack(&[0]);
}

#[test]
fn and_fail() {
    let asm_op = "and";

    // --- test value > 1 --------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[2, 3]);
    expect_exec_error_matches!(
        test,
        ExecutionError::NotBinaryValueOp{value, label: _, source_file: _ } if value == Felt::new(3_u64)
    );

    let test = build_op_test!(asm_op, &[2, 0]);
    expect_exec_error_matches!(
        test,
        ExecutionError::NotBinaryValueOp{value, label: _, source_file: _ } if value == Felt::new(2_u64)
    );

    let test = build_op_test!(asm_op, &[0, 2]);
    expect_exec_error_matches!(
        test,
        ExecutionError::NotBinaryValueOp{value, label: _, source_file: _ } if value == Felt::new(2_u64)
    );
}

#[test]
fn or() {
    let asm_op = "or";

    let test = build_op_test!(asm_op, &[1, 1]);
    test.expect_stack(&[1]);

    let test = build_op_test!(asm_op, &[0, 1]);
    test.expect_stack(&[1]);

    let test = build_op_test!(asm_op, &[1, 0]);
    test.expect_stack(&[1]);

    let test = build_op_test!(asm_op, &[0, 0]);
    test.expect_stack(&[0]);
}

#[test]
fn or_fail() {
    let asm_op = "or";

    // --- test value > 1 --------------------------------------------------------------------
    let expected_value = Felt::new(3);
    let test = build_op_test!(asm_op, &[2, 3]);
    expect_exec_error_matches!(
        test,
        ExecutionError::NotBinaryValueOp{value, label: _, source_file: _ } if value == expected_value
    );

    let expected_value = Felt::new(2);
    let test = build_op_test!(asm_op, &[2, 0]);
    expect_exec_error_matches!(
        test,
        ExecutionError::NotBinaryValueOp{value, label: _, source_file: _ } if value == expected_value
    );

    let test = build_op_test!(asm_op, &[0, 2]);
    expect_exec_error_matches!(
        test,
        ExecutionError::NotBinaryValueOp{value, label: _, source_file: _ } if value == expected_value
    );
}

#[test]
fn xor() {
    let asm_op = "xor";

    let test = build_op_test!(asm_op, &[1, 1]);
    test.expect_stack(&[0]);

    let test = build_op_test!(asm_op, &[0, 1]);
    test.expect_stack(&[1]);

    let test = build_op_test!(asm_op, &[1, 0]);
    test.expect_stack(&[1]);

    let test = build_op_test!(asm_op, &[0, 0]);
    test.expect_stack(&[0]);
}

#[test]
fn xor_fail() {
    let asm_op = "xor";

    let expected_value = Felt::new(2);
    // --- test value > 1 --------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[2, 3]);
    expect_exec_error_matches!(
        test,
        ExecutionError::NotBinaryValueOp{value, label: _, source_file: _ } if value == expected_value
    );

    let test = build_op_test!(asm_op, &[2, 0]);
    expect_exec_error_matches!(
        test,
        ExecutionError::NotBinaryValueOp{value, label: _, source_file: _ } if value == expected_value
    );

    let test = build_op_test!(asm_op, &[0, 2]);
    expect_exec_error_matches!(
        test,
        ExecutionError::NotBinaryValueOp{value, label: _, source_file: _ } if value == expected_value
    );
}

// FIELD OPS COMPARISON - MANUAL TESTS
// ================================================================================================

#[test]
fn eq() {
    let asm_op = "eq";

    // --- test when two elements are equal ------------------------------------------------------
    let test = build_op_test!(asm_op, &[100, 100]);
    test.expect_stack(&[1]);

    // --- test when two elements are unequal ----------------------------------------------------
    let test = build_op_test!(asm_op, &[25, 100]);
    test.expect_stack(&[0]);
}

#[test]
fn eq_b() {
    let build_asm_op = |param: u64| format!("eq.{param}");

    // --- test when two elements are equal ------------------------------------------------------
    let test = build_op_test!(build_asm_op(100), &[100]);
    test.expect_stack(&[1]);

    // --- test when two elements are unequal ----------------------------------------------------
    let test = build_op_test!(build_asm_op(25), &[100]);
    test.expect_stack(&[0]);
}

#[test]
fn eqw() {
    let asm_op = "eqw";

    // --- test when top two words are equal ------------------------------------------------------
    let values = vec![5, 4, 3, 2, 5, 4, 3, 2];
    let mut expected = values.clone();
    // push the result
    expected.push(1);
    // put it in stack order
    expected.reverse();
    let test = build_op_test!(asm_op, &values);
    test.expect_stack(&expected);

    // --- test when top two words are not equal --------------------------------------------------
    let values = vec![8, 7, 6, 5, 4, 3, 2, 1];
    let mut expected = values.clone();
    // push the result
    expected.push(0);
    // put it in stack order
    expected.reverse();
    let test = build_op_test!(asm_op, &values);
    test.expect_stack(&expected);
}

#[test]
fn lt() {
    // Results in 1 if a < b for a starting stack of [b, a, ...] and 0 otherwise
    test_felt_comparison_op("lt", 1, 0, 0);
}

#[test]
fn lte() {
    // Results in 1 if a <= b for a starting stack of [b, a, ...] and 0 otherwise
    test_felt_comparison_op("lte", 1, 1, 0);
}

#[test]
fn gt() {
    // Results in 1 if a > b for a starting stack of [b, a, ...] and 0 otherwise
    test_felt_comparison_op("gt", 0, 0, 1);
}

#[test]
fn gte() {
    // Results in 1 if a >= b for a starting stack of [b, a, ...] and 0 otherwise
    test_felt_comparison_op("gte", 0, 1, 1);
}

// FIELD OPS ARITHMETIC - RANDOMIZED TESTS
// ================================================================================================

proptest! {
    #[test]
    fn add_proptest(a in any::<u64>(), b in any::<u64>()) {
        let asm_op = "add";

        // allow a possible overflow then mod by the Felt Modulus
        let expected = (a as u128 + b as u128) % Felt::MODULUS as u128;

        // b provided via the stack
        let test = build_op_test!(asm_op, &[a, b]);
        test.prop_expect_stack(&[expected as u64])?;

        // b provided as a parameter
        let asm_op = format!("{asm_op}.{b}");
        let test = build_op_test!(&asm_op, &[a]);
        test.prop_expect_stack(&[expected as u64])?;
    }

    #[test]
    fn sub_proptest(val1 in any::<u64>(), val2 in any::<u64>()) {
        let asm_op = "sub";

        // assign the larger value to a and the smaller value to b
        let (a, b) = if val1 >= val2 {
            (val1, val2)
        } else {
            (val2, val1)
        };

        let expected = a - b;

        // b provided via the stack
        let test = build_op_test!(asm_op, &[a, b]);
        test.prop_expect_stack(&[expected])?;

        // underflow by a provided via the stack
        let test = build_op_test!(asm_op, &[b, a]);
        test.prop_expect_stack(&[Felt::MODULUS - expected])?;

        // b provided as a parameter
        let asm_op_b = format!("{asm_op}.{b}");
        let test = build_op_test!(&asm_op_b, &[a]);
        test.prop_expect_stack(&[expected])?;

        // underflow by a provided as a parameter
        let asm_op_b = format!("{asm_op}.{a}");
        let test = build_op_test!(asm_op_b, &[b]);
        test.prop_expect_stack(&[Felt::MODULUS - expected])?;
    }

    #[test]
    fn mul_proptest(a in any::<u64>(), b in any::<u64>()) {
        let asm_op = "mul";

        // allow a possible overflow then mod by the Felt Modulus
        let expected = (a as u128 * b as u128) % Felt::MODULUS as u128;

        // b provided via the stack
        let test = build_op_test!(asm_op, &[a, b]);
        test.prop_expect_stack(&[expected as u64])?;

        // b provided as a parameter
        let asm_op = format!("{asm_op}.{b}");
        let test = build_op_test!(&asm_op, &[a]);
        test.prop_expect_stack(&[expected as u64])?;
    }

    #[test]
    fn div_proptest(a in any::<u64>(), b in 1..u64::MAX) {
        let asm_op = "div";

        // allow a possible overflow then mod by the Felt Modulus
        let expected = (Felt::new(b).inv().as_int() as u128 * a as u128) % Felt::MODULUS as u128;

        // b provided via the stack
        let test = build_op_test!(asm_op, &[a, b]);
        test.prop_expect_stack(&[expected as u64])?;

        // b provided as a parameter
        let asm_op = format!("{asm_op}.{b}");
        let test = build_op_test!(&asm_op, &[a]);
        test.prop_expect_stack(&[expected as u64])?;
    }

    #[test]
    fn neg_proptest(a in any::<u64>()) {
        let asm_op = "neg";

        let expected = if a > 0 {
            Felt::MODULUS - a
        } else {
            0
        };

        let test = build_op_test!(asm_op, &[a]);
        test.prop_expect_stack(&[expected])?;
    }

    #[test]
    fn inv_proptest(a in 1..u64::MAX) {
        let asm_op = "inv";

        let expected = Felt::new(a).inv().as_int();

        let test = build_op_test!(asm_op, &[a]);
        test.prop_expect_stack(&[expected])?;
    }

    #[test]
    fn pow2_proptest(b in 0_u32..64) {
        let asm_op = "pow2";
        let expected = 2_u64.wrapping_pow(b);

        let test = build_op_test!(asm_op, &[b as u64]);
        test.prop_expect_stack(&[expected])?;
    }

    #[test]
    fn exp_proptest(a in any::<u64>(), b in any::<u64>()) {
        // --- exp with no parameter --------------------------------------------------------------
        let asm_op = "exp";
        let base = a;
        let pow = b;
        let expected = Felt::new(base).exp(pow);

        let test = build_op_test!(asm_op, &[base, pow]);
        test.prop_expect_stack(&[expected.as_int()])?;

        // --- exp with parameter containing pow --------------------------------------------------
        let build_asm_op = |param: u64| format!("exp.{param}");
        let base = a;
        let pow = b;
        let expected = Felt::new(base).exp(pow);

        let test = build_op_test!(build_asm_op(pow), &[base]);
        test.prop_expect_stack(&[expected.as_int()])?;
    }

    #[test]
    fn ilog2_proptest(a in 1..Felt::MODULUS) {
        let asm_op = "ilog2";
        let expected = a.ilog2();

        let test = build_op_test!(asm_op, &[a]);
        test.prop_expect_stack(&[expected as u64])?;
    }
}

// FIELD OPS COMPARISON - RANDOMIZED TESTS
// ================================================================================================

proptest! {
    #[test]
    fn eq_proptest(a in any::<u64>(), b in any::<u64>()) {
        let asm_op = "eq";
        // compare the random a & b values modulo the field modulus to get the expected result
        let expected_result = if a % Felt::MODULUS == b % Felt::MODULUS { 1 } else { 0 };

        let test = build_op_test!(asm_op, &[a,b]);
        test.prop_expect_stack(&[expected_result])?;
    }

    #[test]
    fn eqw_proptest(w1 in prop_randw(), w2 in prop_randw()) {
        // test the eqw assembly operation with randomized inputs
        let asm_op = "eqw";

        // 2 words (8 values) for comparison and 1 for the result
        let mut values = vec![0; 2 * WORD_SIZE + 1];

        // check the inputs for equality in the field
        let mut inputs_equal = true;
        for (i, (a, b)) in w1.iter().zip(w2.iter()).enumerate() {
            // if any of the values are unequal in the field, then the words will be unequal
            if *a % Felt::MODULUS != *b % Felt::MODULUS {
                inputs_equal = false;
            }
            // add the values to the vector
            values[i] = *a;
            values[i + WORD_SIZE] = *b;
        }

        let test = build_op_test!(asm_op, &values);

        // add the expected result to get the expected state
        let expected_result = if inputs_equal { 1 } else { 0 };
        values.push(expected_result);
        values.reverse();

        test.prop_expect_stack(&values)?;
    }

    #[test]
    fn lt_proptest(a in any::<u64>(), b in any::<u64>()) {
        // test the less-than assembly operation with randomized inputs
        let asm_op = "lt";
        // compare the random a & b values modulo the field modulus to get the expected result
        let expected_result = if a % Felt::MODULUS < b % Felt::MODULUS { 1 } else { 0 };

        let test = build_op_test!(asm_op, &[a,b]);
        test.prop_expect_stack(&[expected_result])?;
    }

    #[test]
    fn lte_proptest(a in any::<u64>(), b in any::<u64>()) {
        // test the less-than-or-equal assembly operation with randomized inputs
        let asm_op = "lte";
        // compare the random a & b values modulo the field modulus to get the expected result
        let expected_result = if a % Felt::MODULUS <= b % Felt::MODULUS { 1 } else { 0 };

        let test = build_op_test!(asm_op, &[a,b]);
        test.prop_expect_stack(&[expected_result])?;
    }

    #[test]
    fn gt_proptest(a in any::<u64>(), b in any::<u64>()) {
        // test the greater-than assembly operation with randomized inputs
        let asm_op = "gt";
        // compare the random a & b values modulo the field modulus to get the expected result
        let expected_result = if a % Felt::MODULUS > b % Felt::MODULUS { 1 } else { 0 };

        let test = build_op_test!(asm_op, &[a,b]);
        test.prop_expect_stack(&[expected_result])?;
    }

    #[test]
    fn gte_proptest(a in any::<u64>(), b in any::<u64>()) {
        // test the greater-than-or-equal assembly operation with randomized inputs
        let asm_op = "gte";
        // compare the random a & b values modulo the field modulus to get the expected result
        let expected_result = if a % Felt::MODULUS >= b % Felt::MODULUS { 1 } else { 0 };

        let test = build_op_test!(asm_op, &[a,b]);
        test.prop_expect_stack(&[expected_result])?;
    }
}

// HELPER FUNCTIONS FOR MANUAL TESTS
// ================================================================================================

/// This helper function runs an assembly field comparison operation (lt, lte, gt, gte) against a
/// variety of field element pairs.
//
/// The assembly ops which compare multiple field elements work by splitting both elements and
/// performing a comparison of the upper and lower 32-bit values for each element.
/// Since we're working with a 64-bit field modulus, we need to ensure that valid field elements
/// represented by > 32 bits are still compared properly, with high-bit values prioritized over low
/// when they disagree.
//
/// In order for an encoded 64-bit value to be a valid field element while having bits set in
/// both the high and low 32 bits, the upper 32 bits must not be all 1s. Therefore, for testing
/// it's sufficient to use elements with one high bit and one low bit set.
fn test_felt_comparison_op(asm_op: &str, expect_if_lt: u64, expect_if_eq: u64, expect_if_gt: u64) {
    // create an operation with an immediate value
    let build_asm_op = |param: u64| format!("{asm_op}.{param}");

    // create vars with a variety of high and low bit relationships for testing
    let low_bit = 1;
    let high_bit = 1 << 48;

    // a smaller field element with both a high and a low bit set
    let smaller = high_bit + low_bit;
    // element with high bits equal to "smaller" and low bits bigger
    let hi_eq_lo_gt = smaller + low_bit;
    // element with high bits bigger than "smaller" and low bits smaller
    let hi_gt_lo_lt = high_bit << 1;
    // element with high bits bigger than "smaller" and low bits equal
    let hi_gt_lo_eq = hi_gt_lo_lt + low_bit;

    // --- a < b ----------------------------------------------------------------------------------
    // a is smaller in the low bits (equal in high bits)
    let test = build_op_test!(asm_op, &[smaller, hi_eq_lo_gt]);
    test.expect_stack(&[expect_if_lt]);
    // run the same test using instruction with an immediate value
    let test = build_op_test!(build_asm_op(hi_eq_lo_gt), &[smaller]);
    test.expect_stack(&[expect_if_lt]);

    // a is smaller in the high bits and equal in the low bits
    let test = build_op_test!(asm_op, &[smaller, hi_gt_lo_eq]);
    test.expect_stack(&[expect_if_lt]);
    // run the same test using instruction with an immediate value
    let test = build_op_test!(build_asm_op(hi_gt_lo_eq), &[smaller]);
    test.expect_stack(&[expect_if_lt]);

    // a is smaller in the high bits but bigger in the low bits
    let test = build_op_test!(asm_op, &[smaller, hi_gt_lo_lt]);
    test.expect_stack(&[expect_if_lt]);
    // run the same test using instruction with an immediate value
    let test = build_op_test!(build_asm_op(hi_gt_lo_lt), &[smaller]);
    test.expect_stack(&[expect_if_lt]);

    // --- a = b ----------------------------------------------------------------------------------
    // high and low bits are both set
    let test = build_op_test!(asm_op, &[hi_gt_lo_eq, hi_gt_lo_eq]);
    test.expect_stack(&[expect_if_eq]);
    // run the same test using instruction with an immediate value
    let test = build_op_test!(build_asm_op(hi_gt_lo_eq), &[hi_gt_lo_eq]);
    test.expect_stack(&[expect_if_eq]);

    // --- a > b ----------------------------------------------------------------------------------
    // a is bigger in the low bits (equal in high bits)
    let test = build_op_test!(asm_op, &[hi_eq_lo_gt, smaller]);
    test.expect_stack(&[expect_if_gt]);
    // run the same test using instruction with an immediate value
    let test = build_op_test!(build_asm_op(smaller), &[hi_eq_lo_gt]);
    test.expect_stack(&[expect_if_gt]);

    // a is bigger in the high bits and equal in the low bits
    let test = build_op_test!(asm_op, &[hi_gt_lo_eq, smaller]);
    test.expect_stack(&[expect_if_gt]);
    // run the same test using instruction with an immediate value
    let test = build_op_test!(build_asm_op(smaller), &[hi_gt_lo_eq]);
    test.expect_stack(&[expect_if_gt]);

    // a is bigger in the high bits but smaller in the low bits
    let test = build_op_test!(asm_op, &[hi_gt_lo_lt, smaller]);
    test.expect_stack(&[expect_if_gt]);
    // run the same test using instruction with an immediate value
    let test = build_op_test!(build_asm_op(smaller), &[hi_gt_lo_lt]);
    test.expect_stack(&[expect_if_gt]);
}
