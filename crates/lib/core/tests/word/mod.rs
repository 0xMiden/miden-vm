use core::cmp::Ordering;

use miden_core::{Felt, LexicographicWord, Word, field::PrimeField64};
use miden_utils_testing::rand;
use num::Integer;
use rstest::rstest;

#[rstest]
#[case::gt("gt_le", &[Ordering::Greater])]
#[case::gte("gte_le", &[Ordering::Greater, Ordering::Equal])]
#[case::eq("eq", &[Ordering::Equal])]
#[case::lt("lt_le", &[Ordering::Less])]
#[case::lte("lte_le", &[Ordering::Less, Ordering::Equal])]
fn test_word_comparison(#[case] proc_name: &str, #[case] valid_ords: &[Ordering]) {
    let source = &format!(
        "
        use miden::core::word

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
        prepend_word_le(&mut operand_stack, rhs);
        prepend_word_le(&mut operand_stack, lhs);
        // => [RHS, LHS] in LE format (word[0] on top)

        let expected = u64::from(valid_ords.contains(&expected_cmp));

        build_test!(source, &operand_stack).expect_stack(&[expected]);
    }
}

#[test]
fn test_reverse() {
    const SOURCE: &str = "
        use miden::core::word

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
        use miden::core::word

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
        use miden::core::word
        use miden::core::sys

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
        use miden::core::word
        use miden::core::sys

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
        use miden::core::word

        begin
            push.{ptr}
            push.{w3}
            push.{w2}
            push.{w1}
            push.{w0}
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

/// Add a Word to the bottom of the operand stack Vec.
/// After `StackInputs::try_from_ints` reversal, `word[3]` will be on top of the stack.
fn prepend_word(target: &mut Vec<u64>, word: Word) {
    let _iterator = target.splice(0..0, word.iter().map(Felt::as_canonical_u64));
}

/// Add a Word to the bottom of the operand stack Vec in LE order.
/// After `StackInputs::try_from_ints` reversal, `word[0]` will be on top of the stack.
fn prepend_word_le(target: &mut Vec<u64>, word: Word) {
    let _iterator = target.splice(0..0, word.iter().rev().map(Felt::as_canonical_u64));
}
