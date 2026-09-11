use alloc::{
    string::{String, ToString},
    sync::Arc,
};

use miden_core::{
    Felt,
    mast::{
        MastForest,
        arbitrary::{MastForestParams, forest_kernel_strategy},
    },
    program::{KernelDescriptor, Program, StackInputs},
};
use proptest::prelude::*;

use crate::{DefaultHost, FastProcessor};

fn params() -> MastForestParams {
    MastForestParams {
        blocks: 1..=4,
        max_joins: 2,
        max_splits: 2,
        max_loops: 2,
        max_calls: 2,
        max_syscalls: 2,
        max_externals: 2,
        ..Default::default()
    }
}

/// Runs every procedure root of `forest` as a program with `kernel` on `stack`.
fn run_every_root(
    forest: MastForest,
    kernel: KernelDescriptor,
    stack: &[Felt],
) -> Result<(), String> {
    let forest = Arc::new(forest);
    let mut host = DefaultHost::default().with_library(&forest).map_err(|err| err.to_string())?;
    for &root in forest.procedure_roots() {
        let program = Program::with_kernel(forest.clone(), root, kernel.clone());
        let inputs = StackInputs::new(stack).map_err(|err| err.to_string())?;
        FastProcessor::new(inputs)
            .execute_sync(&program, &mut host)
            .map_err(|err| format!("root {root} failed: {err}"))?;
    }
    Ok(())
}

proptest! {
    /// Every procedure root of an executable forest runs to completion on any operand stack.
    #[test]
    fn executable_forests_run_on_any_stack(
        (forest, kernel) in forest_kernel_strategy(params()),
        stack in prop::collection::vec(any::<u32>().prop_map(Felt::from_u32), 0..=16),
    ) {
        prop_assert_eq!(run_every_root(forest, kernel, &stack), Ok(()));
    }

    /// Forests from the plain `Arbitrary` impl run under the empty kernel of `Program::new`.
    #[test]
    fn plain_executable_forests_run_without_a_kernel(
        forest in any_with::<MastForest>(params()),
        stack in prop::collection::vec(any::<u32>().prop_map(Felt::from_u32), 0..=16),
    ) {
        prop_assert_eq!(run_every_root(forest, KernelDescriptor::default(), &stack), Ok(()));
    }
}
