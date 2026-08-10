use alloc::sync::Arc;
use core::assert_matches;

use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core::{ONE, Word, advice::AdviceMap, program::Program};
use miden_processor::{
    ExecutionOptions, FastProcessor, StackInputs,
    advice::{AdviceError, AdviceInputs},
    mast::MastForest,
};
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
    let program_without_advice_map: Program = Assembler::default()
        .assemble_program("program", source)
        .unwrap()
        .unwrap_program();

    // Test `FastProcessor::execute_sync` fails if no advice map provided with the program
    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));
    match FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .expect("failed to construct FastProcessor")
    .execute_sync(&program_without_advice_map, &mut host)
    {
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

    // Test `FastProcessor::execute_sync` works if advice map provided with the program
    let mast_forest: MastForest = (**program_without_advice_map.mast_forest()).clone();

    let key = Word::new([ONE, ONE, ONE, ONE]);
    let value = vec![ONE, ONE];

    let mast_forest = mast_forest.with_advice_map(AdviceMap::from_iter([(key, value)]));
    let program_with_advice_map =
        Program::new(mast_forest.into(), program_without_advice_map.entrypoint());

    let mut host = DefaultHost::default();
    FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .expect("failed to construct FastProcessor")
    .execute_sync(&program_with_advice_map, &mut host)
    .unwrap();
}
