use alloc::sync::Arc;
use core::assert_matches;

use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core::{ONE, Word, advice::AdviceMap, program::Program};
use miden_processor::{advice::AdviceError, mast::MastForest};
use miden_vm::{DefaultHost, ExecutionRequest};

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

    // Ordinary execution fails if the program has no required advice map.
    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));
    match ExecutionRequest::new(&program_without_advice_map).execute().run_sync(&mut host) {
        Ok(_) => panic!("Expected error"),
        Err(e) => {
            assert_matches!(
                e,
                miden_processor::ExecutionError::AdviceError {
                    err: AdviceError::MapKeyNotFound { .. },
                    ..
                }
            );
        },
    }

    // Ordinary execution succeeds when the program provides its required advice map.
    let mast_forest: MastForest = (**program_without_advice_map.mast_forest()).clone();

    let key = Word::new([ONE, ONE, ONE, ONE]);
    let value = vec![ONE, ONE];

    let mast_forest = mast_forest.with_advice_map(AdviceMap::from_iter([(key, value)]));
    let program_with_advice_map =
        Program::new(mast_forest.into(), program_without_advice_map.entrypoint());

    let mut host = DefaultHost::default();
    ExecutionRequest::new(&program_with_advice_map)
        .execute()
        .run_sync(&mut host)
        .unwrap();
}

#[cfg(feature = "internal")]
#[test]
fn canonical_deferred_ecdsa4_keccak100_example_executes() {
    use std::path::PathBuf;

    use miden_assembly::Linkage;
    use miden_core::{Felt, Word, crypto::hash::Eidos};
    use miden_core_lib::CoreLibrary;
    use miden_vm::{StackInputs, internal::InputFile};

    let program_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("masm-examples/precompiles/deferred_ecdsa4_keccak100")
        .join("deferred_ecdsa4_keccak100.masm");
    let source = std::fs::read_to_string(&program_path).expect("example source must be readable");
    let inputs = InputFile::read(&None, &program_path).expect("example inputs must be readable");
    let advice_values = inputs
        .advice_stack
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|value| {
            let value = value.parse::<u64>().expect("advice-stack value must be a u64");
            Felt::new(value).expect("advice-stack value must be canonical")
        })
        .collect::<Vec<_>>();
    let (fixtures, remainder) = advice_values.as_chunks::<40>();
    assert!(remainder.is_empty(), "ECDSA fixtures must contain 40 Felts each");
    let (stored_commitments, derived_commitments): (Vec<_>, Vec<_>) = fixtures
        .iter()
        .map(|fixture| {
            let stored = Word::new(fixture[4..8].try_into().expect("commitment is one word"));
            let derived = Eidos::hash_elements(&fixture[8..24]);
            (stored, derived)
        })
        .unzip();
    assert_eq!(
        stored_commitments, derived_commitments,
        "ECDSA fixture commitments must match their public-key limbs"
    );
    let stack_values = inputs
        .operand_stack
        .iter()
        .map(|value| {
            let value = value.parse::<u64>().expect("operand-stack value must be a u64");
            Felt::new(value).expect("operand-stack value must be canonical")
        })
        .collect::<Vec<_>>();
    let stack_inputs = StackInputs::new(&stack_values).expect("example stack inputs must fit");
    let advice_inputs = inputs.parse_advice_inputs().expect("example advice must be valid");

    let core_lib = CoreLibrary::default();
    let program = Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("core library must link")
        .assemble_program("deferred_ecdsa4_keccak100", source)
        .expect("example must assemble")
        .unwrap_program();
    let mut host = DefaultHost::default()
        .with_library(&core_lib)
        .expect("core library must load into the host");

    ExecutionRequest::new(&program)
        .with_stack_inputs(stack_inputs)
        .with_advice(advice_inputs)
        .execute()
        .run_sync(&mut host)
        .expect("canonical deferred ECDSA/Keccak example must execute");
}
