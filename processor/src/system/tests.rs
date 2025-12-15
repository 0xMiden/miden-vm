use miden_core::mast::MastForest;

use crate::{AdviceInputs, DefaultHost, ExecutionOptions, Kernel, Operation, Process, StackInputs};

// Check that process returns an error if a maximum number of cycles is exceeded.
#[test]
fn cycles_num_exceeded() {
    let stack = StackInputs::default();
    let mut host = DefaultHost::default();
    let program = &MastForest::default();

    let max_cycles = 2048;
    let mut process = Process::new(
        Kernel::default(),
        stack,
        AdviceInputs::default(),
        ExecutionOptions::new(Some(max_cycles), max_cycles, false, false).unwrap(),
    );
    for _ in 0..max_cycles {
        process.execute_op(Operation::Noop, program, &mut host).unwrap();
    }
    assert!(process.execute_op(Operation::Noop, program, &mut host).is_err());
}
