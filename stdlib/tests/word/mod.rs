use core::cmp::Ordering;

use miden_core::LexicographicWord;
use miden_utils_testing::{prepend_word_to_vec as prepend_word, rand};
use num::Integer;
use rstest::rstest;

#[rstest]
#[case::gt("gt", &[Ordering::Greater])]
#[case::gte("gte", &[Ordering::Greater, Ordering::Equal])]
#[case::eq("eq", &[Ordering::Equal])]
#[case::lt("lt", &[Ordering::Less])]
#[case::lte("lte", &[Ordering::Less, Ordering::Equal])]
fn test_word_comparison(#[case] proc_name: &str, #[case] valid_ords: &[Ordering]) {
    let source = &format!(
        "
        use.std::word

        begin
            exec.word::{proc_name}
        end
    "
    );

    let mut seed = 0xfacade;

    for i in 0..1000 {
        let lhs = rand::seeded_word(&mut seed);
        let rhs = if i.is_even() { rand::seeded_word(&mut seed) } else { lhs };

        let expected_cmp = LexicographicWord::cmp(&lhs.into(), &rhs.into());

        let mut operand_stack: Vec<u64> = Default::default();
        prepend_word(&mut operand_stack, rhs);
        prepend_word(&mut operand_stack, lhs);
        // => [RHS, LHS]

        let expected = u64::from(valid_ords.contains(&expected_cmp));

        build_test!(source, &operand_stack).expect_stack(&[expected]);
    }
}

#[test]
fn test_reverse() {
    const SOURCE: &str = "
        use.std::word

        begin
            exec.word::reverse
        end
    ";

    let mut seed = 0xfacade;
    for _ in 0..1000 {
        let mut operand_stack: Vec<u64> = Default::default();
        prepend_word(&mut operand_stack, rand::seeded_word(&mut seed));

        // This looks extremely weird, but `build_test!()` and `expect_stack()` take opposite
        // stack orders, so this is actually correct.
        build_test!(SOURCE, &operand_stack).expect_stack(&operand_stack);
    }
}

#[test]
fn test_eqz() {
    const SOURCE: &str = "
        use.std::word

        begin
            exec.word::eqz
        end
    ";

    build_test!(SOURCE, &[0, 0, 0, 0]).expect_stack(&[1]);
    build_test!(SOURCE, &[0, 1, 2, 3]).expect_stack(&[0]);
}

#[test]
fn test_preserving_eqz() {
    const SOURCE: &str = "
        use.std::word
        use.std::sys

        begin
            exec.word::testz
            exec.sys::truncate_stack
        end
    ";

    build_test!(SOURCE, &[0, 0, 0, 0]).expect_stack(&[1, 0, 0, 0, 0]);
    build_test!(SOURCE, &[0, 1, 2, 3]).expect_stack(&[0, 3, 2, 1, 0]);
}

#[test]
fn test_preserving_eq() {
    const SOURCE: &str = "
        use.std::word
        use.std::sys

        begin
            exec.word::test_eq
            exec.sys::truncate_stack
        end
    ";

    let mut seed = 0xfacade;
    for i in 0..1000 {
        let lhs = rand::seeded_word(&mut seed);
        let rhs = if i.is_even() { rand::seeded_word(&mut seed) } else { lhs };
        let is_equal = lhs == rhs;

        let mut operand_stack: Vec<u64> = Default::default();
        prepend_word(&mut operand_stack, rhs);
        prepend_word(&mut operand_stack, lhs);

        let mut expected: Vec<u64> = operand_stack.clone();
        expected.push(is_equal.into());
        expected.reverse();

        build_test!(SOURCE, &operand_stack).expect_stack(&expected);
    }
}

#[test]
fn store_word_u32s_le_stores_limbs() {
    const PTR: u32 = 256;
    const W0: u64 = 0x1234567890abcdef;
    const W1: u64 = 0x0000000200000001;
    const W2: u64 = 0xffffffff00000000;
    const W3: u64 = 0x00000000ffffffff;

    fn limbs(value: u64) -> (u64, u64) {
        (value & 0xffff_ffff, value >> 32)
    }

    let (w0_lo, w0_hi) = limbs(W0);
    let (w1_lo, w1_hi) = limbs(W1);
    let (w2_lo, w2_hi) = limbs(W2);
    let (w3_lo, w3_hi) = limbs(W3);

    let source = format!(
        "
        use.std::word

        begin
            push.{ptr}
            push.{w0}
            push.{w1}
            push.{w2}
            push.{w3}
            exec.word::store_word_u32s_le
        end
    ",
        ptr = PTR,
        w0 = W0,
        w1 = W1,
        w2 = W2,
        w3 = W3,
    );

    let expected_mem = [w0_lo, w0_hi, w1_lo, w1_hi, w2_lo, w2_hi, w3_lo, w3_hi];

    build_test!(&source).expect_stack_and_memory(&[], PTR, &expected_mem);
}
