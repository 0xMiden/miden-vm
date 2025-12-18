use super::*;

/// Test a number of combinations of stack inputs and operations to ensure that the fast processor
/// produces the same results as `Process`.
///
/// This creates a test for each element of the cross product of the given stack inputs and
/// operations.
#[rstest]
fn test_basic_block(
    #[values(
        vec![],
        vec![0_u32.into()],
        vec![0_u32.into(), 1_u32.into()],
        vec![0_u32.into(), 1_u32.into(), 2_u32.into()],
        vec![0_u32.into(), 1_u32.into(), 2_u32.into(), 3_u32.into()],
        vec![0_u32.into(), 1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into()],
        vec![0_u32.into(), 1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into(), 5_u32.into()],
        vec![0_u32.into(), 1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into(), 5_u32.into(), 6_u32.into()],
        vec![0_u32.into(), 1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into(), 5_u32.into(), 6_u32.into(), 7_u32.into()],
        vec![0_u32.into(), 1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into(), 5_u32.into(), 6_u32.into(), 7_u32.into(), 8_u32.into()],
        vec![0_u32.into(), 1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into(), 5_u32.into(), 6_u32.into(), 7_u32.into(), 8_u32.into(), 9_u32.into()],
        vec![0_u32.into(), 1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into(), 5_u32.into(), 6_u32.into(), 7_u32.into(), 8_u32.into(), 9_u32.into(), 10_u32.into()],
        vec![0_u32.into(), 1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into(), 5_u32.into(), 6_u32.into(), 7_u32.into(), 8_u32.into(), 9_u32.into(), 10_u32.into(), 11_u32.into()],
        vec![0_u32.into(), 1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into(), 5_u32.into(), 6_u32.into(), 7_u32.into(), 8_u32.into(), 9_u32.into(), 10_u32.into(), 11_u32.into(), 12_u32.into()],
        vec![0_u32.into(), 1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into(), 5_u32.into(), 6_u32.into(), 7_u32.into(), 8_u32.into(), 9_u32.into(), 10_u32.into(), 11_u32.into(), 12_u32.into(), 13_u32.into()],
        vec![0_u32.into(), 1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into(), 5_u32.into(), 6_u32.into(), 7_u32.into(), 8_u32.into(), 9_u32.into(), 10_u32.into(), 11_u32.into(), 12_u32.into(), 13_u32.into(), 14_u32.into()],
        vec![0_u32.into(), 1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into(), 5_u32.into(), 6_u32.into(), 7_u32.into(), 8_u32.into(), 9_u32.into(), 10_u32.into(), 11_u32.into(), 12_u32.into(), 13_u32.into(), 14_u32.into(), 15_u32.into()],
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
        vec![Operation::U32assert2(Felt::from(5u32))],
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
        vec![Operation::Push(42_u32.into()), Operation::MovUp8, Operation::Drop],
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
    let fast_processor = FastProcessor::new(&stack_inputs);
    let fast_stack_outputs =
        fast_processor.execute_sync(&program, &mut host).map(|output| output.stack);

    let mut host = DefaultHost::default();
    let mut slow_processor = Process::new(
        Kernel::default(),
        StackInputs::new(stack_inputs).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    );
    let slow_stack_outputs = slow_processor.execute(&program, &mut host);

    match (&fast_stack_outputs, &slow_stack_outputs) {
        (Ok(fast_stack_outputs), Ok(slow_stack_outputs)) => {
            assert_eq!(fast_stack_outputs, slow_stack_outputs);
        },
        (Err(fast_error), Err(slow_error)) => {
            assert_eq!(fast_error.to_string(), slow_error.to_string());

            // Make sure that we're not getting an output stack overflow error, as it indicates that
            // the sequence of operations makes the stack end with a non-16 depth, and doesn't tell
            // us if the stack outputs are actually the same.
            if matches!(fast_error, ExecutionError::OutputStackOverflow(_)) {
                panic!("we don't want to be testing this output stack overflow error");
            }
        },
        _ => panic!(
            "Fast processor: {:?}. Slow processor: {:?}",
            fast_stack_outputs, slow_stack_outputs
        ),
    }
}
