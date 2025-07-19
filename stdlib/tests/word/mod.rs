use core::cmp::Ordering;

use miden_core::{Felt, LexicographicWord, Word};
use miden_utils_testing::rand;

/// Note that adding a word to the *beginning* of a Vec adds it to the *bottom* of the stack.
fn prepend_word(stack: &mut Vec<u64>, word: Word) {
    // Actual insertion happens when this iterator is dropped.
    let _iterator = stack.splice(0..0, word.iter().map(Felt::as_int));
}

fn execute_comparison_test(proc_name: &str, valid_ords: &[Ordering]) {
    let source = &format!(
        "
        use.std::word

        begin
            exec.word::{proc_name}
        end
    "
    );

    let mut seed = 0xfacade;

    for _ in 0..1000 {
        let lhs = rand::seeded_word(&mut seed);
        let rhs = rand::seeded_word(&mut seed);

        let expected_cmp = LexicographicWord::cmp(&lhs.into(), &rhs.into());

        let mut operand_stack: Vec<u64> = Default::default();
        prepend_word(&mut operand_stack, lhs);
        prepend_word(&mut operand_stack, rhs);
        // => [LHS, RHS]

        let expected = u64::from(valid_ords.contains(&expected_cmp));

        build_test!(source, &operand_stack).expect_stack(&[expected]);
    }
}

#[test]
fn test_gt() {
    execute_comparison_test("gt", &[Ordering::Greater]);
}

#[test]
fn test_gte() {
    execute_comparison_test("gte", &[Ordering::Greater, Ordering::Equal]);
}

#[test]
fn test_eq() {
    execute_comparison_test("eq", &[Ordering::Equal]);
}

#[test]
fn test_lt() {
    execute_comparison_test("lt", &[Ordering::Less]);
}

#[test]
fn test_lte() {
    execute_comparison_test("lte", &[Ordering::Less, Ordering::Equal]);
}

