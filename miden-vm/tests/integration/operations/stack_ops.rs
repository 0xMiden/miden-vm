use miden_assembly::testing::regex;
use miden_utils_testing::{
    MIN_STACK_DEPTH, WORD_SIZE, assert_assembler_diagnostic, assert_diagnostic_lines,
    build_op_test, proptest::prelude::*,
};

// STACK OPERATIONS TESTS
// ================================================================================================

#[test]
fn drop() {
    let asm_op = "drop";

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    test.expect_stack(&[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0]);
}

#[test]
fn dropw() {
    let asm_op = "dropw";

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    test.expect_stack(&[5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0]);
}

#[test]
fn padw() {
    let asm_op = "padw";

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    test.expect_stack(&[0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
}

#[test]
fn dup() {
    let asm_op = "dup";

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    test.expect_stack(&[1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
}

#[test]
fn dupn() {
    let asm_op = "dup.1";

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    test.expect_stack(&[2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
}

#[test]
fn dupn_fail() {
    let asm_op = "dup.16";

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    assert_assembler_diagnostic!(
        test,
        "invalid immediate: value must be in the range 0..16 (exclusive)",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "12 |",
        "13 | begin dup.16 exec.truncate_stack end",
        "   :           ^^",
        "  `----"
    );
}

#[test]
fn dupw() {
    let asm_op = "dupw";

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    test.expect_stack(&[1, 2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
}

#[test]
fn dupwn() {
    let asm_op = "dupw.1";

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    test.expect_stack(&[5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
}

#[test]
fn dupwn_fail() {
    let asm_op = "dupw.4";

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    assert_assembler_diagnostic!(
        test,
        "invalid immediate: value must be in the range 0..4 (exclusive)",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "12 |",
        "13 | begin dupw.4 exec.truncate_stack end",
        "   :            ^",
        "  `----"
    );
}

#[test]
fn swap() {
    let asm_op = "swap";

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    test.expect_stack(&[2, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
}

#[test]
fn swapn() {
    let asm_op = "swap.2";

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    test.expect_stack(&[3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
}

#[test]
fn swapn_fail() {
    let asm_op = "swap.16";

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    assert_assembler_diagnostic!(
        test,
        "invalid immediate: value must be in the range 1..16 (exclusive)",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "12 |",
        "13 | begin swap.16 exec.truncate_stack end",
        "   :            ^^",
        "  `----"
    );
}

#[test]
fn swapw() {
    let asm_op = "swapw";

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    test.expect_stack(&[5, 6, 7, 8, 1, 2, 3, 4, 9, 10, 11, 12, 13, 14, 15, 16]);
}

#[test]
fn swapwn() {
    let asm_op = "swapw.2";

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    test.expect_stack(&[9, 10, 11, 12, 5, 6, 7, 8, 1, 2, 3, 4, 13, 14, 15, 16]);
}

#[test]
fn swapwn_fail() {
    let asm_op = "swapw.4";

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    assert_assembler_diagnostic!(
        test,
        "invalid immediate: value must be in the range 1..4 (exclusive)",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "12 |",
        "13 | begin swapw.4 exec.truncate_stack end",
        "   :             ^",
        "   `----"
    );
}

#[test]
fn swapdw() {
    let asm_op = "swapdw";

    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    test.expect_stack(&[9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn movup() {
    let asm_op = "movup.2";
    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    test.expect_stack(&[3, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
}

#[test]
fn movup_fail() {
    let asm_op = "movup.0";
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    assert_assembler_diagnostic!(
        test,
        "invalid immediate: value must be in the range 2..16 (exclusive)",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "12 |",
        "13 | begin movup.0 exec.truncate_stack end",
        "   :             ^",
        "  `----"
    );

    let asm_op = "movup.1";
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    assert_assembler_diagnostic!(
        test,
        "invalid immediate: value must be in the range 2..16 (exclusive)",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "12 |",
        "13 | begin movup.1 exec.truncate_stack end",
        "   :             ^",
        "  `----"
    );

    let asm_op = "movup.16";
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    assert_assembler_diagnostic!(
        test,
        "invalid immediate: value must be in the range 2..16 (exclusive)",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "12 |",
        "13 | begin movup.16 exec.truncate_stack end",
        "   :             ^^",
        "  `----"
    );
}

#[test]
fn movupw() {
    let asm_op = "movupw.2";
    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    test.expect_stack(&[9, 10, 11, 12, 1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 15, 16]);
}

#[test]
fn movupw_fail() {
    let asm_op = "movupw.0";
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    assert_assembler_diagnostic!(
        test,
        "invalid immediate: value must be in the range 2..4 (exclusive)",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "12 |",
        "13 | begin movupw.0 exec.truncate_stack end",
        "   :              ^",
        "  `----"
    );

    let asm_op = "movupw.1";
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    assert_assembler_diagnostic!(
        test,
        "invalid immediate: value must be in the range 2..4 (exclusive)",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "12 |",
        "13 | begin movupw.1 exec.truncate_stack end",
        "   :              ^",
        "  `----"
    );

    let asm_op = "movupw.4";
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    assert_assembler_diagnostic!(
        test,
        "invalid immediate: value must be in the range 2..4 (exclusive)",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "12 |",
        "13 | begin movupw.4 exec.truncate_stack end",
        "   :              ^",
        "  `----"
    );
}

#[test]
fn movdn() {
    let asm_op = "movdn.2";
    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    test.expect_stack(&[2, 3, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
}

#[test]
fn movdn_fail() {
    let asm_op = "movdn.0";
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    assert_assembler_diagnostic!(
        test,
        "invalid immediate: value must be in the range 2..16 (exclusive)",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "12 |",
        "13 | begin movdn.0 exec.truncate_stack end",
        "   :             ^",
        "  `----"
    );

    let asm_op = "movdn.1";
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    assert_assembler_diagnostic!(
        test,
        "invalid immediate: value must be in the range 2..16 (exclusive)",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "12 |",
        "13 | begin movdn.1 exec.truncate_stack end",
        "   :             ^",
        "  `----"
    );

    let asm_op = "movdn.16";
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    assert_assembler_diagnostic!(
        test,
        "invalid immediate: value must be in the range 2..16 (exclusive)",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "12 |",
        "13 | begin movdn.16 exec.truncate_stack end",
        "   :             ^^",
        "  `----"
    );
}

#[test]
fn movdnw() {
    let asm_op = "movdnw.2";
    // --- simple case ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    test.expect_stack(&[5, 6, 7, 8, 9, 10, 11, 12, 1, 2, 3, 4, 13, 14, 15, 16]);
}

#[test]
fn movdnw_fail() {
    let asm_op = "movdnw.0";
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    assert_assembler_diagnostic!(
        test,
        "invalid immediate: value must be in the range 2..4 (exclusive)",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "12 |",
        "13 | begin movdnw.0 exec.truncate_stack end",
        "   :              ^",
        "  `----"
    );

    let asm_op = "movdnw.1";
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    assert_assembler_diagnostic!(
        test,
        "invalid immediate: value must be in the range 2..4 (exclusive)",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "12 |",
        "13 | begin movdnw.1 exec.truncate_stack end",
        "   :              ^",
        "  `----"
    );

    let asm_op = "movdnw.4";
    let test = build_op_test!(asm_op, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    assert_assembler_diagnostic!(
        test,
        "invalid immediate: value must be in the range 2..4 (exclusive)",
        regex!(r#",-\[test[\d]+:[\d]+:[\d]+\]"#),
        "12 |",
        "13 | begin movdnw.4 exec.truncate_stack end",
        "   :              ^",
        "  `----"
    );
}

#[test]
fn cswap() {
    let asm_op = "cswap";
    // --- simple cases ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    test.expect_stack(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0]);

    let test = build_op_test!(asm_op, &[1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    test.expect_stack(&[2, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0]);
}

#[test]
fn cswapw() {
    let asm_op = "cswapw";
    // --- simple cases ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    test.expect_stack(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0]);

    let test = build_op_test!(asm_op, &[1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    test.expect_stack(&[5, 6, 7, 8, 1, 2, 3, 4, 9, 10, 11, 12, 13, 14, 15, 0]);
}

#[test]
fn cdrop() {
    let asm_op = "cdrop";
    // --- simple cases ----------------------------------------------------------------------------
    let test = build_op_test!(asm_op, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    test.expect_stack(&[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 0]);

    let test = build_op_test!(asm_op, &[1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    test.expect_stack(&[1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 0]);
}

#[test]
fn cdropw() {
    let asm_op = "cdropw";
    // --- simple cases ----------------------------------------------------------------------------

    let test = build_op_test!(asm_op, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    test.expect_stack(&[5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0]);

    let test = build_op_test!(asm_op, &[1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    test.expect_stack(&[1, 2, 3, 4, 9, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0]);
}

proptest! {

    #[test]
    fn drop_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH)) {
        let asm_op = "drop";
        let mut expected_values = test_values.clone();
        expected_values.remove(0);
        expected_values.push(0);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn dropw_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH)) {
        let asm_op = "dropw";
        let mut expected_values = test_values.clone();
        expected_values.drain(0..WORD_SIZE);
        expected_values.append(&mut vec![0; WORD_SIZE]);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn padw_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH)) {
        let asm_op = "padw";
        let mut expected_values = vec![0; WORD_SIZE];
        expected_values.extend_from_slice(&test_values[..MIN_STACK_DEPTH - WORD_SIZE]);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn dup_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH)) {
        let asm_op = "dup";
        let mut expected_values = vec![test_values[0]];
        expected_values.extend_from_slice(&test_values[..MIN_STACK_DEPTH - 1]);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn dupn_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH), n in 0_usize..MIN_STACK_DEPTH) {
        let asm_op = format!("dup.{n}");
        let mut expected_values = vec![test_values[n]];
        expected_values.extend_from_slice(&test_values[..MIN_STACK_DEPTH - 1]);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn dupw_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH)) {
        let asm_op = "dupw";
        let mut expected_values = test_values[..WORD_SIZE].to_vec();
        expected_values.extend_from_slice(&test_values[..MIN_STACK_DEPTH - WORD_SIZE]);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn dupwn_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH), n in 0_usize..WORD_SIZE) {
        let asm_op = format!("dupw.{n}");
        let start = n * WORD_SIZE;
        let end = start + WORD_SIZE;
        let mut expected_values = test_values[start..end].to_vec();
        expected_values.extend_from_slice(&test_values[..MIN_STACK_DEPTH - WORD_SIZE]);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn swap_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH)) {
        let asm_op = "swap";
        let mut expected_values = test_values.clone();
        expected_values.swap(0, 1);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn swapn_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH), n in 1_usize..MIN_STACK_DEPTH) {
        let asm_op = format!("swap.{n}");
        let mut expected_values = test_values.clone();
        expected_values.swap(0, n);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn swapw_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH)) {
        let asm_op = "swapw";
        let mut expected_values = test_values[WORD_SIZE..(WORD_SIZE * 2)].to_vec();
        expected_values.extend_from_slice(&test_values[..WORD_SIZE]);
        expected_values.extend_from_slice(&test_values[(WORD_SIZE * 2)..]);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn swapwn_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH), n in 1_usize..WORD_SIZE) {
        let asm_op = format!("swapw.{n}");
        let start = n * WORD_SIZE;
        let end = start + WORD_SIZE;
        let mut expected_values = test_values[start..end].to_vec();
        expected_values.extend_from_slice(&test_values[WORD_SIZE..start]);
        expected_values.extend_from_slice(&test_values[..WORD_SIZE]);
        expected_values.extend_from_slice(&test_values[end..]);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn swapdw_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH)) {
        let asm_op = "swapdw";
        let mut expected_values = test_values[(WORD_SIZE * 2)..].to_vec();
        expected_values.extend_from_slice(&test_values[..(WORD_SIZE * 2)]);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn movup_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH), movup_idx in 2_usize..MIN_STACK_DEPTH) {
        let asm_op = format!("movup.{movup_idx}");
        let mut expected_values = vec![test_values[movup_idx]];
        expected_values.extend_from_slice(&test_values[..movup_idx]);
        expected_values.extend_from_slice(&test_values[movup_idx + 1..]);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn movupw_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH), movupw_idx in 2_usize..WORD_SIZE) {
        let asm_op = format!("movupw.{movupw_idx}");
        let start = movupw_idx * WORD_SIZE;
        let end = start + WORD_SIZE;
        let mut expected_values = test_values[start..end].to_vec();
        expected_values.extend_from_slice(&test_values[..start]);
        expected_values.extend_from_slice(&test_values[end..]);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn movdn_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH), movdn_idx in 2_usize..MIN_STACK_DEPTH) {
        let asm_op = format!("movdn.{movdn_idx}");
        let mut expected_values = test_values[1..=movdn_idx].to_vec();
        expected_values.insert(0, test_values[0]);
        expected_values.rotate_left(1);
        expected_values = test_values[1..=movdn_idx].to_vec();
        expected_values.push(test_values[0]);
        expected_values.extend_from_slice(&test_values[movdn_idx + 1..]);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn movdnw_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH), movdnw_idx in 2_usize..WORD_SIZE) {
        let asm_op = format!("movdnw.{movdnw_idx}");
        let end = (movdnw_idx + 1) * WORD_SIZE;
        let mut expected_values = test_values[WORD_SIZE..end].to_vec();
        expected_values.extend_from_slice(&test_values[..WORD_SIZE]);
        expected_values.extend_from_slice(&test_values[end..]);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn cswap_proptest(mut test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH - 1), c in 0_u64..2) {
        let asm_op = "cswap";
        test_values.insert(0, c);
        let mut expected_values = test_values[1..].to_vec();
        if c == 1 {
            expected_values.swap(0, 1);
        }
        expected_values.push(0);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn cswapw_proptest(mut test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH - 1), c in 0_u64..2) {
        let asm_op = "cswapw";
        test_values.insert(0, c);
        let mut expected_values = if c == 1 {
            let mut v = test_values[1 + WORD_SIZE..1 + WORD_SIZE * 2].to_vec();
            v.extend_from_slice(&test_values[1..1 + WORD_SIZE]);
            v.extend_from_slice(&test_values[1 + WORD_SIZE * 2..]);
            v
        } else {
            test_values[1..].to_vec()
        };
        expected_values.push(0);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn cdrop_proptest(mut test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH - 1), c in 0_u64..2) {
        let asm_op = "cdrop";
        test_values.insert(0, c);
        let mut expected_values = if c == 1 {
            let mut v = vec![test_values[1]];
            v.extend_from_slice(&test_values[3..]);
            v
        } else {
            test_values[2..].to_vec()
        };
        expected_values.push(0);
        expected_values.push(0);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn cdropw_proptest(mut test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH - 1), c in 0_u64..2) {
        let asm_op = "cdropw";
        test_values.insert(0, c);
        let mut expected_values = if c == 1 {
            let mut v = test_values[1..1 + WORD_SIZE].to_vec();
            v.extend_from_slice(&test_values[1 + WORD_SIZE * 2..]);
            v
        } else {
            test_values[1 + WORD_SIZE..].to_vec()
        };
        expected_values.append(&mut vec![0; WORD_SIZE]);
        expected_values.push(0);
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn reversew_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH)) {
        let asm_op = "reversew";
        let mut expected_values = test_values.clone();
        expected_values[0..WORD_SIZE].reverse();
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

    #[test]
    fn reversedw_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH)) {
        let asm_op = "reversedw";
        let mut expected_values = test_values.clone();
        expected_values[0..WORD_SIZE * 2].reverse();
        build_op_test!(asm_op, &test_values).prop_expect_stack(&expected_values)?;
    }

}
