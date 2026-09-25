use miden_core::{
    field::PrimeField64,
    mast::{BasicBlockNodeBuilder, MastForest},
};
use miden_processor::{
    AceError, DefaultHost, ExecutionError, ExecutionOptions, FastProcessor, Felt, Program,
    StackInputs, advice::AdviceInputs, operation::Operation,
};

#[test]
fn eval_circuit_overflow_panic_check() {
    let ptr = Felt::new_unchecked(0);
    let n_read = Felt::new_unchecked(Felt::ORDER_U64 - 3); // = 2^64 - 2^32 - 2
    let n_eval = Felt::new_unchecked((1u64 << 32) + 4); // = 2^32 + 4

    let stack_inputs = StackInputs::new(&[ptr, n_read, n_eval]).unwrap();

    let program = eval_circuit_program();

    let mut host = DefaultHost::default();
    let processor = FastProcessor::new_with_options(
        stack_inputs,
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .expect("processor advice inputs should fit advice map limits");

    assert!(matches!(
        processor.execute_sync(&program, &mut host),
        Err(ExecutionError::AceChipError {
            label: _,
            source_file: _,
            error: AceError(_),
        })
    ));
}

#[test]
fn eval_circuit_rejects_oversized_counts_before_memory_reads() {
    let program = eval_circuit_program();

    // Each case exceeds the default ACE limit by READ or EVAL rows, with no circuit data in memory.
    let limit = ExecutionOptions::DEFAULT_MAX_ACE_ROWS;
    for (num_vars, num_eval) in [(2 * limit, 4), (2, limit)] {
        let inputs = StackInputs::new(&[
            Felt::new_unchecked(0),
            Felt::from_u32(num_vars),
            Felt::from_u32(num_eval),
        ])
        .unwrap();
        let processor = FastProcessor::new_with_options(
            inputs,
            AdviceInputs::default(),
            ExecutionOptions::default(),
        )
        .unwrap();
        let err = processor.execute_sync(&program, &mut DefaultHost::default()).unwrap_err();
        assert!(matches!(
            err,
            ExecutionError::AceChipError { error: AceError(message), .. }
                if message.contains(&format!("exceeds max_ace_rows limit of {limit}"))
        ));
    }
}

fn eval_circuit_program() -> Program {
    let mut forest = MastForest::new();
    let root = BasicBlockNodeBuilder::new(vec![Operation::EvalCircuit])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(root);
    Program::new(forest.into(), root)
}
