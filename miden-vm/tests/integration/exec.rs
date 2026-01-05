use alloc::sync::Arc;

use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core::{ONE, Program, assert_matches};
use miden_processor::{AdviceError, AdviceInputs, ExecutionOptions, MastForest};
use miden_prover::{StackInputs, Word};
use miden_vm::DefaultHost;

#[test]
fn advice_map_loaded_before_execution() {
    let source = "\
    begin
        push.1.1.1.1
        adv.push_mapval
        dropw
    end";

    // compile and execute program
    let program_without_advice_map: Program =
        Assembler::default().assemble_program(source).unwrap();

    // Test `miden_processor::execute_sync` fails if no advice map provided with the program
    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));
    match miden_processor::execute_sync(
        &program_without_advice_map,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default(),
    ) {
        Ok(_) => panic!("Expected error"),
        Err(e) => {
            assert_matches!(
                e,
                miden_prover::ExecutionError::AdviceError {
                    err: AdviceError::MapKeyNotFound { .. },
                    ..
                }
            );
        },
    }

    // Test `miden_processor::execute_sync` works if advice map provided with the program
    let mast_forest: MastForest = (**program_without_advice_map.mast_forest()).clone();

    let key = Word::new([ONE, ONE, ONE, ONE]);
    let value = vec![ONE, ONE];

    let mut mast_forest = mast_forest.clone();
    mast_forest.advice_map_mut().insert(key, value);
    let program_with_advice_map =
        Program::new(mast_forest.into(), program_without_advice_map.entrypoint());

    let mut host = DefaultHost::default();
    miden_processor::execute_sync(
        &program_with_advice_map,
        StackInputs::default(),
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default(),
    )
    .unwrap();
}
