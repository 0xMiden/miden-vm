use alloc::string::String;

use rstest::fixture;

use super::*;

/// Test a number of combinations of stack inputs and operations to ensure that the fast processor
/// produces the same results as `Process`.
///
/// This creates a test for each element of the cross product of the given stack inputs and
/// operations.
#[rstest]
fn test_basic_block(
    testname: String,
    // Stack inputs start from 1 so that moved elements are distinguishable from padding zeros
    #[values(
        vec![],
        vec![Felt::from_u32(1)],
        vec![Felt::from_u32(1), Felt::from_u32(2)],
        vec![Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3)],
        vec![Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4)],
        vec![Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4), Felt::from_u32(5)],
        vec![Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4), Felt::from_u32(5), Felt::from_u32(6)],
        vec![Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4), Felt::from_u32(5), Felt::from_u32(6), Felt::from_u32(7)],
        vec![Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4), Felt::from_u32(5), Felt::from_u32(6), Felt::from_u32(7), Felt::from_u32(8)],
        vec![Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4), Felt::from_u32(5), Felt::from_u32(6), Felt::from_u32(7), Felt::from_u32(8), Felt::from_u32(9)],
        vec![Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4), Felt::from_u32(5), Felt::from_u32(6), Felt::from_u32(7), Felt::from_u32(8), Felt::from_u32(9), Felt::from_u32(10)],
        vec![Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4), Felt::from_u32(5), Felt::from_u32(6), Felt::from_u32(7), Felt::from_u32(8), Felt::from_u32(9), Felt::from_u32(10), Felt::from_u32(11)],
        vec![Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4), Felt::from_u32(5), Felt::from_u32(6), Felt::from_u32(7), Felt::from_u32(8), Felt::from_u32(9), Felt::from_u32(10), Felt::from_u32(11), Felt::from_u32(12)],
        vec![Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4), Felt::from_u32(5), Felt::from_u32(6), Felt::from_u32(7), Felt::from_u32(8), Felt::from_u32(9), Felt::from_u32(10), Felt::from_u32(11), Felt::from_u32(12), Felt::from_u32(13)],
        vec![Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4), Felt::from_u32(5), Felt::from_u32(6), Felt::from_u32(7), Felt::from_u32(8), Felt::from_u32(9), Felt::from_u32(10), Felt::from_u32(11), Felt::from_u32(12), Felt::from_u32(13), Felt::from_u32(14)],
        vec![Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4), Felt::from_u32(5), Felt::from_u32(6), Felt::from_u32(7), Felt::from_u32(8), Felt::from_u32(9), Felt::from_u32(10), Felt::from_u32(11), Felt::from_u32(12), Felt::from_u32(13), Felt::from_u32(14), Felt::from_u32(15)],
        vec![Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4), Felt::from_u32(5), Felt::from_u32(6), Felt::from_u32(7), Felt::from_u32(8), Felt::from_u32(9), Felt::from_u32(10), Felt::from_u32(11), Felt::from_u32(12), Felt::from_u32(13), Felt::from_u32(14), Felt::from_u32(15), Felt::from_u32(16)],
    )]
    stack_inputs: Vec<Felt>,
    #[values(
        // clk
        vec![Operation::Noop, Operation::Noop, Operation::Clk, Operation::MovUp8, Operation::Drop],
        vec![Operation::Add],
        vec![Operation::Swap],
        // We want SDepth to output "17", and then drop 2 elements from somewhere else in the stack.
        vec![Operation::Dup0, Operation::SDepth, Operation::MovUp8, Operation::Drop,Operation::MovUp8, Operation::Drop],
        vec![Operation::Neg],
        vec![Operation::Mul],
        vec![Operation::Inv],
        vec![Operation::Incr],
        vec![Operation::And],
        vec![Operation::Or],
        vec![Operation::Not],
        vec![Operation::Eq],
        vec![Operation::Eqz],
        vec![Operation::Expacc],
        vec![Operation::Ext2Mul],
        vec![Operation::U32split, Operation::MovUp8, Operation::Drop],
        vec![Operation::U32add],
        vec![Operation::U32add3],
        vec![Operation::U32mul],
        vec![Operation::U32sub],
        vec![Operation::U32div],
        vec![Operation::U32and],
        vec![Operation::U32xor],
        vec![Operation::U32madd],
        vec![Operation::U32assert2(Felt::from_u32(5))],
        vec![Operation::Pad, Operation::MovUp8, Operation::Drop],
        // for the dups, we drop an element that was not duplicated, and hence we are still testing
        // that the `dup` works as expected
        vec![Operation::Dup0, Operation::MovUp8, Operation::Drop],
        vec![Operation::Dup1, Operation::MovUp8, Operation::Drop],
        vec![Operation::Dup2, Operation::MovUp8, Operation::Drop],
        vec![Operation::Dup3, Operation::MovUp8, Operation::Drop],
        vec![Operation::Dup4, Operation::MovUp8, Operation::Drop],
        vec![Operation::Dup5, Operation::MovUp8, Operation::Drop],
        vec![Operation::Dup6, Operation::MovUp8, Operation::Drop],
        vec![Operation::Dup7, Operation::MovUp8, Operation::Drop],
        vec![Operation::Dup9, Operation::MovUp8, Operation::Drop],
        vec![Operation::Dup11, Operation::MovUp8, Operation::Drop],
        vec![Operation::Dup13, Operation::MovUp8, Operation::Drop],
        vec![Operation::Dup15, Operation::MovUp8, Operation::Drop],

        vec![Operation::SwapW],
        vec![Operation::SwapW2],
        vec![Operation::SwapW3],
        vec![Operation::SwapDW],
        vec![Operation::MovUp2],
        vec![Operation::MovUp3],
        vec![Operation::MovUp4],
        vec![Operation::MovUp5],
        vec![Operation::MovUp6],
        vec![Operation::MovUp7],
        vec![Operation::MovUp8],
        vec![Operation::MovDn2],
        vec![Operation::MovDn3],
        vec![Operation::MovDn4],
        vec![Operation::MovDn5],
        vec![Operation::MovDn6],
        vec![Operation::MovDn7],
        vec![Operation::MovDn8],
        vec![Operation::CSwap],
        vec![Operation::CSwapW],
        vec![Operation::Push(Felt::from_u32(42)), Operation::MovUp8, Operation::Drop],
        // the memory operations here are more to ensure e.g. that unaligned word accesses are
        // reported correctly.
        vec![Operation::MLoadW],
        vec![Operation::MStoreW],
        vec![Operation::MLoad],
        vec![Operation::MStore],
        vec![Operation::MStream],
        // crypto ops
        vec![Operation::HPerm],
        // Note: we have more specific tests for these below
        vec![Operation::FriE2F4],
        vec![Operation::HornerBase],
        vec![Operation::HornerExt],
        vec![Operation::EvalCircuit],
    )]
    operations: Vec<Operation>,
) {
    let program = simple_program_with_ops(operations);

    let mut host = DefaultHost::default();
    let fast_processor = FastProcessor::new(StackInputs::new(&stack_inputs).unwrap());
    let fast_stack_outputs =
        fast_processor.execute_sync(&program, &mut host).map(|output| output.stack);

    // Make sure that we're not getting an output stack overflow error, as it indicates that
    // the sequence of operations makes the stack end with a non-16 depth, and doesn't tell
    // us if the stack outputs are actually the same.
    if let Some(err) = fast_stack_outputs.as_ref().err()
        && matches!(err, ExecutionError::OutputStackOverflow(_))
    {
        panic!("we don't want to be testing this output stack overflow error");
    }

    insta::assert_debug_snapshot!(testname, fast_stack_outputs);
}

// Workaround to make insta and rstest work together.
// See: https://github.com/la10736/rstest/issues/183#issuecomment-1564088329
//
// `rstest` names each generated test thread after the full `Debug` output of every
// `#[values(..)]` argument (e.g. `..._stack_inputs_13_vec![Felt::from_u32(1), ...]_operations_45_vec![...]`).
// For `test_basic_block` below, that produces snapshot file names over 250 characters long,
// which exceeds Windows' default 260-character path limit once combined with a repo checkout
// path — `git clone` on Windows fails with "Filename too long" before any tests can even run.
//
// `rstest` already numbers each `#[values(..)]` entry (the `_NN_` after each parameter name),
// and that pair of indices alone uniquely identifies a test case, so we extract just the
// indices instead of embedding the full Debug-formatted values. `insta` prepends its own
// `<crate>__<module path>__` prefix to whatever explicit name we return here, so returning
// just `case_NN_NN` yields a final snapshot filename of
// `miden_processor__fast__tests__all_ops__case_NN_NN.snap` — still under 55 characters, well
// within Windows' limit. (We must not include that prefix in the string ourselves: insta
// already adds it, so doing so would double it up and no longer match the `.snap` files
// actually checked into the repo.)
#[fixture]
fn testname() -> String {
    let full_name = std::thread::current().name().unwrap().replace("::", "__");

    let stack_inputs_idx = extract_index_after(&full_name, "stack_inputs_");
    let operations_idx = extract_index_after(&full_name, "operations_");

    match (stack_inputs_idx, operations_idx) {
        (Some(a), Some(b)) => alloc::format!("case_{a}_{b}"),
        // Fall back to the full (verbose) name for any test that doesn't match the
        // expected `..._NN_vec..._NN_vec...` shape from the two `#[values(..)]`
        // parameters, so this fixture stays safe to reuse elsewhere.
        _ => full_name,
    }
}

/// Reads the run of ASCII digits immediately following the first occurrence of `marker` in
/// `s`, e.g. `extract_index_after("..._stack_inputs_13_vec...", "stack_inputs_") == Some("13")`.
fn extract_index_after<'a>(s: &'a str, marker: &str) -> Option<&'a str> {
    let after = &s[s.find(marker)? + marker.len()..];
    let digit_len = after.chars().take_while(|c| c.is_ascii_digit()).count();
    if digit_len == 0 { None } else { Some(&after[..digit_len]) }
}
