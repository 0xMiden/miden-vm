use alloc::sync::Arc;

use miden_core::{
    Felt,
    mast::arbitrary::{MastForestParams, forest_kernel_strategy},
    program::{Program, StackInputs},
};
use proptest::prelude::*;

use crate::{DefaultHost, FastProcessor};

proptest! {
    /// Every procedure root of an executable forest runs to completion on any operand stack.
    #[test]
    fn executable_forests_run_on_any_stack(
        (forest, kernel) in forest_kernel_strategy(MastForestParams {
            blocks: 1..=4,
            max_joins: 2,
            max_splits: 2,
            max_loops: 2,
            max_calls: 2,
            max_syscalls: 2,
            max_externals: 2,
            ..Default::default()
        }),
        stack in prop::collection::vec(any::<u32>().prop_map(Felt::from_u32), 0..=16),
    ) {
        let forest = Arc::new(forest);
        let mut host = DefaultHost::default().with_library(&forest).unwrap();
        for &root in forest.procedure_roots() {
            let program = Program::with_kernel(forest.clone(), root, kernel.clone());
            let processor = FastProcessor::new(StackInputs::new(&stack).unwrap());
            let outcome = processor.execute_sync(&program, &mut host);
            prop_assert!(outcome.is_ok(), "root {root} failed: {}", outcome.unwrap_err());
        }
    }
}
