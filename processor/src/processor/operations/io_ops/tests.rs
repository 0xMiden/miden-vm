use alloc::vec::Vec;

use miden_core::{Felt, Word, ZERO, field::PrimeField64, stack::MIN_STACK_DEPTH};

use super::{
    super::stack_ops::{op_pad, op_push},
    op_advpop, op_advpopw, op_mload, op_mloadw, op_mstore, op_mstorew, op_mstream, op_pipe,
};
use crate::{
    AdviceInputs, ContextId,
    fast::{FastProcessor, NoopTracer, step::NeverStopper},
    processor::{Processor, StackInterface},
};

// ADVICE INPUT TESTS
// --------------------------------------------------------------------------------------------

#[test]
fn test_op_advpop() {
    // popping from the advice stack should push the value onto the operand stack
    let advice_stack: Vec<u64> = vec![3];
    let advice_inputs = AdviceInputs::default().with_stack_values(advice_stack).unwrap();
    let mut processor = FastProcessor::new_with_advice_inputs(&[], advice_inputs);
    let mut tracer = NoopTracer;

    op_push(&mut processor, Felt::new(1), &mut tracer).unwrap();
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);
    op_advpop(&mut processor, &(), &mut tracer).unwrap();
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);

    let expected = build_expected(&[3, 1]);
    assert_eq!(expected, processor.stack_top());

    // popping again should result in an error because advice stack is empty
    assert!(op_advpop(&mut processor, &(), &mut tracer).is_err());
}

#[test]
fn test_op_advpopw() {
    // popping a word from the advice stack should overwrite top 4 elements of the operand stack
    // Advice stack: with_stack_values([3, 4, 5, 6]) puts 3 at front (top when popping).
    // pop_stack_word() pops: 3, 4, 5, 6 -> Word([3, 4, 5, 6])
    // word[0]=3 goes to stack position 0 (top), so result is [3, 4, 5, 6, 1].
    let advice_stack: Vec<u64> = vec![3, 4, 5, 6];
    let advice_inputs = AdviceInputs::default().with_stack_values(advice_stack).unwrap();
    let mut processor = FastProcessor::new_with_advice_inputs(&[], advice_inputs);
    let mut tracer = NoopTracer;

    op_push(&mut processor, Felt::new(1), &mut tracer).unwrap();
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);
    for _ in 0..4 {
        op_pad(&mut processor, &mut tracer).unwrap();
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);
    }
    op_advpopw(&mut processor, &(), &mut tracer).unwrap();
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);

    // word[0]=3 at top, word[3]=6 at position 3
    let expected = build_expected(&[3, 4, 5, 6, 1]);
    assert_eq!(expected, processor.stack_top());
}

// MEMORY OPERATION TESTS
// --------------------------------------------------------------------------------------------

#[test]
fn test_op_mloadw() {
    let mut processor = FastProcessor::new(&[]);
    let mut tracer = NoopTracer;

    assert_eq!(0, processor.memory.num_accessed_words());

    // store a word at address 4
    let word: Word = [Felt::new(1), Felt::new(3), Felt::new(5), Felt::new(7)].into();
    store_word(&mut processor, 4, word, &mut tracer);

    // push four zeros onto the stack (padding)
    for _ in 0..4 {
        op_pad(&mut processor, &mut tracer).unwrap();
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);
    }

    // push the address onto the stack and load the word
    op_push(&mut processor, Felt::new(4), &mut tracer).unwrap();
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);
    op_mloadw(&mut processor, &(), &mut tracer).unwrap();
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);

    // word[0] at top. Store puts Word([1,3,5,7]) in memory,
    // load puts [1,3,5,7,...] on stack. First 4 positions are loaded word,
    // next 4 are the word left on stack after store.
    let expected = build_expected(&[1, 3, 5, 7, 1, 3, 5, 7]);
    assert_eq!(expected, processor.stack_top());

    // check memory state
    assert_eq!(1, processor.memory.num_accessed_words());
    let clk = processor.clk;
    let stored_word =
        processor.memory.read_word(ContextId::root(), Felt::new(4), clk, &()).unwrap();
    assert_eq!(word, stored_word);

    // --- calling MLOADW with address greater than u32::MAX leads to an error ----------------
    op_push(&mut processor, Felt::new(u64::MAX / 2), &mut tracer).unwrap();
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);
    assert!(op_mloadw(&mut processor, &(), &mut tracer).is_err());

    // --- calling MLOADW with a stack of minimum depth is ok ----------------
    let mut processor = FastProcessor::new(&[]);
    assert!(op_mloadw(&mut processor, &(), &mut tracer).is_ok());
}

#[test]
fn test_op_mload() {
    let mut processor = FastProcessor::new(&[]);
    let mut tracer = NoopTracer;

    assert_eq!(0, processor.memory.num_accessed_words());

    // store a word at address 4
    let word: Word = [Felt::new(1), Felt::new(3), Felt::new(5), Felt::new(7)].into();
    store_word(&mut processor, 4, word, &mut tracer);

    // push the address onto the stack and load the element
    op_push(&mut processor, Felt::new(4), &mut tracer).unwrap();
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);
    op_mload(&mut processor, &(), &mut tracer).unwrap();
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);

    // Element at addr 4 is word[0] = 1.
    // After store, stack is [1, 3, 5, 7, ...]. After push addr: [4, 1, 3, 5, 7, ...]
    // After mload: [1, 1, 3, 5, 7, ...] (addr replaced by loaded element)
    let expected = build_expected(&[1, 1, 3, 5, 7]);
    assert_eq!(expected, processor.stack_top());

    // check memory state
    assert_eq!(1, processor.memory.num_accessed_words());
    let clk = processor.clk;
    let stored_word =
        processor.memory.read_word(ContextId::root(), Felt::new(4), clk, &()).unwrap();
    assert_eq!(word, stored_word);

    // --- calling MLOAD with address greater than u32::MAX leads to an error -----------------
    op_push(&mut processor, Felt::new(u64::MAX / 2), &mut tracer).unwrap();
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);
    assert!(op_mload(&mut processor, &(), &mut tracer).is_err());

    // --- calling MLOAD with a stack of minimum depth is ok ----------------
    let mut processor = FastProcessor::new(&[]);
    assert!(op_mload(&mut processor, &(), &mut tracer).is_ok());
}

#[test]
fn test_op_mstream() {
    let mut processor = FastProcessor::new(&[]);
    let mut tracer = NoopTracer;

    // save two words into memory addresses 4 and 8
    let word1: Word = [Felt::new(30), Felt::new(29), Felt::new(28), Felt::new(27)].into();
    let word2: Word = [Felt::new(26), Felt::new(25), Felt::new(24), Felt::new(23)].into();
    store_word(&mut processor, 4, word1, &mut tracer);
    store_word(&mut processor, 8, word2, &mut tracer);

    // check memory state
    assert_eq!(2, processor.memory.num_accessed_words());
    let clk = processor.clk;
    let stored_word1 =
        processor.memory.read_word(ContextId::root(), Felt::new(4), clk, &()).unwrap();
    assert_eq!(word1, stored_word1);
    let stored_word2 =
        processor.memory.read_word(ContextId::root(), Felt::new(8), clk, &()).unwrap();
    assert_eq!(word2, stored_word2);

    // clear the stack (drop the 8 elements we pushed while storing)
    for _ in 0..8 {
        Processor::stack(&mut processor).decrement_size(&mut tracer);
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);
    }

    // arrange the stack such that:
    // - 101 is at position 13 (to make sure it is not overwritten)
    // - 4 (the address) is at position 12
    // - values 1 - 12 are at positions 0 - 11
    op_push(&mut processor, Felt::new(101), &mut tracer).unwrap();
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);
    op_push(&mut processor, Felt::new(4), &mut tracer).unwrap();
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);
    for i in 1..13 {
        op_push(&mut processor, Felt::new(i), &mut tracer).unwrap();
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);
    }

    // execute the MSTREAM operation
    op_mstream(&mut processor, &(), &mut tracer).unwrap();
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);

    // Word at addr 4 (word1) goes to positions 0-3, word at addr 8 (word2) to 4-7.
    // word[0] at lowest position.
    let expected = build_expected(&[
        word1[0].as_canonical_u64(),
        word1[1].as_canonical_u64(),
        word1[2].as_canonical_u64(),
        word1[3].as_canonical_u64(),
        word2[0].as_canonical_u64(),
        word2[1].as_canonical_u64(),
        word2[2].as_canonical_u64(),
        word2[3].as_canonical_u64(),
        4,
        3,
        2,
        1,
        4 + 8, // initial address + 2 words
        101,   // rest of stack
    ]);
    assert_eq!(expected, processor.stack_top());
}

#[test]
fn test_op_mstorew() {
    let mut processor = FastProcessor::new(&[]);
    let mut tracer = NoopTracer;

    assert_eq!(0, processor.memory.num_accessed_words());

    // push the first word onto the stack and save it at address 0
    let word1: Word = [Felt::new(1), Felt::new(3), Felt::new(5), Felt::new(7)].into();
    store_word(&mut processor, 0, word1, &mut tracer);

    // After store, word remains on stack with word[0] at top: [1, 3, 5, 7]
    let expected = build_expected(&[1, 3, 5, 7]);
    assert_eq!(expected, processor.stack_top());

    // check memory state
    assert_eq!(1, processor.memory.num_accessed_words());
    let clk = processor.clk;
    let stored_word =
        processor.memory.read_word(ContextId::root(), Felt::new(0), clk, &()).unwrap();
    assert_eq!(word1, stored_word);

    // push the second word onto the stack and save it at address 4
    let word2: Word = [Felt::new(2), Felt::new(4), Felt::new(6), Felt::new(8)].into();
    store_word(&mut processor, 4, word2, &mut tracer);

    // word2 on top of word1: [2, 4, 6, 8, 1, 3, 5, 7]
    let expected = build_expected(&[2, 4, 6, 8, 1, 3, 5, 7]);
    assert_eq!(expected, processor.stack_top());

    // check memory state
    assert_eq!(2, processor.memory.num_accessed_words());
    let clk = processor.clk;
    let stored_word1 =
        processor.memory.read_word(ContextId::root(), Felt::new(0), clk, &()).unwrap();
    assert_eq!(word1, stored_word1);
    let stored_word2 =
        processor.memory.read_word(ContextId::root(), Felt::new(4), clk, &()).unwrap();
    assert_eq!(word2, stored_word2);

    // --- calling MSTOREW with address greater than u32::MAX leads to an error ----------------
    op_push(&mut processor, Felt::new(u64::MAX / 2), &mut tracer).unwrap();
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);
    assert!(op_mstorew(&mut processor, &(), &mut tracer).is_err());

    // --- calling MSTOREW with a stack of minimum depth is ok ----------------
    let mut processor = FastProcessor::new(&[]);
    assert!(op_mstorew(&mut processor, &(), &mut tracer).is_ok());
}

#[test]
fn test_op_mstore() {
    let mut processor = FastProcessor::new(&[]);
    let mut tracer = NoopTracer;

    assert_eq!(0, processor.memory.num_accessed_words());

    // push new element onto the stack and save it as first element of the word on
    // uninitialized memory at address 0
    let element = Felt::new(10);
    store_element(&mut processor, 0, element, &mut tracer);

    // check stack state
    let expected = build_expected(&[10]);
    assert_eq!(expected, processor.stack_top());

    // check memory state - the word should be [10, 0, 0, 0]
    let expected_word: Word = [element, ZERO, ZERO, ZERO].into();
    assert_eq!(1, processor.memory.num_accessed_words());
    let clk = processor.clk;
    let stored_word =
        processor.memory.read_word(ContextId::root(), Felt::new(0), clk, &()).unwrap();
    assert_eq!(expected_word, stored_word);

    // push a word onto the stack and save it at address 4
    let word2: Word = [Felt::new(1), Felt::new(3), Felt::new(5), Felt::new(7)].into();
    store_word(&mut processor, 4, word2, &mut tracer);

    // push new element onto the stack and save it as first element of the word at address 4
    let element2 = Felt::new(12);
    store_element(&mut processor, 4, element2, &mut tracer);

    // After store_word, stack is [1, 3, 5, 7, 10]
    // After store_element: [12, 1, 3, 5, 7, 10]
    let expected = build_expected(&[12, 1, 3, 5, 7, 10]);
    assert_eq!(expected, processor.stack_top());

    // check memory state to make sure the other 3 elements were not affected
    let expected_word2: Word = [element2, Felt::new(3), Felt::new(5), Felt::new(7)].into();
    assert_eq!(2, processor.memory.num_accessed_words());
    let clk = processor.clk;
    let stored_word2 =
        processor.memory.read_word(ContextId::root(), Felt::new(4), clk, &()).unwrap();
    assert_eq!(expected_word2, stored_word2);

    // --- calling MSTORE with address greater than u32::MAX leads to an error ----------------
    op_push(&mut processor, Felt::new(u64::MAX / 2), &mut tracer).unwrap();
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);
    assert!(op_mstore(&mut processor, &(), &mut tracer).is_err());

    // --- calling MSTORE with a stack of minimum depth is ok ----------------
    let mut processor = FastProcessor::new(&[]);
    assert!(op_mstore(&mut processor, &(), &mut tracer).is_ok());
}

#[test]
fn test_op_pipe() {
    // push words onto the advice stack
    // with_stack_values([30, 29, ..., 23]) puts 30 at front (first to pop).
    // pop_stack_dword pops: 30, 29, 28, 27 -> words[0], then 26, 25, 24, 23 -> words[1]
    let advice_stack: Vec<u64> = vec![30, 29, 28, 27, 26, 25, 24, 23];
    let advice_inputs = AdviceInputs::default().with_stack_values(advice_stack).unwrap();
    let mut processor = FastProcessor::new_with_advice_inputs(&[], advice_inputs);
    let mut tracer = NoopTracer;

    // arrange the stack such that:
    // - 101 is at position 13 (to make sure it is not overwritten)
    // - 4 (the address) is at position 12
    // - values 1 - 12 are at positions 0 - 11
    op_push(&mut processor, Felt::new(101), &mut tracer).unwrap();
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);
    op_push(&mut processor, Felt::new(4), &mut tracer).unwrap();
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);
    for i in 1..13 {
        op_push(&mut processor, Felt::new(i), &mut tracer).unwrap();
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);
    }

    // execute the PIPE operation
    op_pipe(&mut processor, &(), &mut tracer).unwrap();
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);

    // check memory state contains the words from the advice stack
    // pop_stack_dword returns [Word([30,29,28,27]), Word([26,25,24,23])]
    // words[0] stored at addr 4, words[1] at addr 8
    assert_eq!(2, processor.memory.num_accessed_words());
    let clk = processor.clk;
    let stored_word1 =
        processor.memory.read_word(ContextId::root(), Felt::new(4), clk, &()).unwrap();
    let stored_word2 =
        processor.memory.read_word(ContextId::root(), Felt::new(8), clk, &()).unwrap();

    let word1 = stored_word1;
    let word2 = stored_word2;

    // words[0] goes to positions 0-3, words[1] to 4-7
    // word[0] at lowest position.
    let expected = build_expected(&[
        word1[0].as_canonical_u64(),
        word1[1].as_canonical_u64(),
        word1[2].as_canonical_u64(),
        word1[3].as_canonical_u64(),
        word2[0].as_canonical_u64(),
        word2[1].as_canonical_u64(),
        word2[2].as_canonical_u64(),
        word2[3].as_canonical_u64(),
        4,
        3,
        2,
        1,
        4 + 8, // initial address + 2 words
        101,   // rest of stack
    ]);
    assert_eq!(expected, processor.stack_top());
}

// CLOCK CYCLE CONFLICT TESTS
// --------------------------------------------------------------------------------------------

/// Ensures that reading and writing in the same clock cycle results in an error.
#[test]
#[ignore = "Re-enable when addressing issue 2276"]
fn test_read_and_write_in_same_clock_cycle() {
    let mut processor = FastProcessor::new(&[]);
    let mut tracer = NoopTracer;

    assert_eq!(0, processor.memory.num_accessed_words());

    // emulate reading and writing in the same clock cycle (no increment_clk between operations)
    op_mload(&mut processor, &(), &mut tracer).unwrap();
    assert!(op_mstore(&mut processor, &(), &mut tracer).is_err());
}

/// Ensures that writing twice in the same clock cycle results in an error.
#[test]
#[ignore = "Re-enable when addressing issue 2276"]
fn test_write_twice_in_same_clock_cycle() {
    let mut processor = FastProcessor::new(&[]);
    let mut tracer = NoopTracer;

    assert_eq!(0, processor.memory.num_accessed_words());

    // emulate writing twice in the same clock cycle (no increment_clk between operations)
    op_mstore(&mut processor, &(), &mut tracer).unwrap();
    assert!(op_mstore(&mut processor, &(), &mut tracer).is_err());
}

/// Ensures that reading twice in the same clock cycle does NOT result in an error.
#[test]
fn test_read_twice_in_same_clock_cycle() {
    let mut processor = FastProcessor::new(&[]);
    let mut tracer = NoopTracer;

    assert_eq!(0, processor.memory.num_accessed_words());

    // emulate reading twice in the same clock cycle (no increment_clk between operations)
    op_mload(&mut processor, &(), &mut tracer).unwrap();
    op_mload(&mut processor, &(), &mut tracer).unwrap();
}

// HELPER METHODS
// --------------------------------------------------------------------------------------------

fn store_word(processor: &mut FastProcessor, addr: u64, word: Word, tracer: &mut NoopTracer) {
    // Push word elements in reverse order so word[0] ends up at position 1.
    // After pushing, word[0] should be at stack position 1 (after addr at position 0).
    // So push word[3], then word[2], word[1], word[0], then addr.
    for &value in word.iter().rev() {
        op_push(processor, value, tracer).unwrap();
        let _ = processor.increment_clk(tracer, &NeverStopper);
    }
    // Push address
    op_push(processor, Felt::new(addr), tracer).unwrap();
    let _ = processor.increment_clk(tracer, &NeverStopper);
    // Store the word (LE: stack pos 1-4 -> word[0-3])
    op_mstorew(processor, &(), tracer).unwrap();
    let _ = processor.increment_clk(tracer, &NeverStopper);
}

fn store_element(processor: &mut FastProcessor, addr: u64, value: Felt, tracer: &mut NoopTracer) {
    // Push value
    op_push(processor, value, tracer).unwrap();
    let _ = processor.increment_clk(tracer, &NeverStopper);
    // Push address
    op_push(processor, Felt::new(addr), tracer).unwrap();
    let _ = processor.increment_clk(tracer, &NeverStopper);
    // Store the element
    op_mstore(processor, &(), tracer).unwrap();
    let _ = processor.increment_clk(tracer, &NeverStopper);
}

/// Builds an expected stack state from the given values.
///
/// The values are provided in "stack order" (top of stack first), and the result is a Vec<Felt>
/// that can be compared with `processor.stack_top()`, where the top of the stack is at the
/// **last** index.
fn build_expected(values: &[u64]) -> Vec<Felt> {
    let mut expected = vec![ZERO; MIN_STACK_DEPTH];
    for (i, &value) in values.iter().enumerate() {
        // In the result, top of stack is at index 15, second at 14, etc.
        expected[15 - i] = Felt::new(value);
    }
    expected
}
