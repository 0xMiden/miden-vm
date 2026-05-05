use miden_core::{
    field::PrimeField64,
    mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor},
};
use miden_processor::{
    AceError, DefaultHost, ExecutionError, FastProcessor, Felt, Program, StackInputs,
    advice::AdviceInputs, operation::Operation,
};

#[test]
fn eval_circuit_overflow_panic_check() {
    let ptr = Felt::new_unchecked(0);
    let n_read = Felt::new_unchecked(Felt::ORDER_U64 - 3); // = 2^64 - 2^32 - 2
    let n_eval = Felt::new_unchecked((1u64 << 32) + 4); // = 2^32 + 4

    let stack_inputs = StackInputs::new(&[ptr, n_read, n_eval]).unwrap();

    let program = {
        let mut forest = MastForest::new();
        let root = BasicBlockNodeBuilder::new(vec![Operation::EvalCircuit], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(root);
        Program::new(forest.into(), root)
    };

    let mut host = DefaultHost::default();
    let processor = FastProcessor::new_with_options(
        stack_inputs,
        AdviceInputs::default(),
        miden_processor::ExecutionOptions::default(),
    )
    .expect("processor advice inputs should fit advice map limits");

    // Namely, this checks that execution doesn't panic due to an overflow.
    assert!(matches!(
        processor.execute_sync(&program, &mut host),
        Err(ExecutionError::AceChipError {
            label: _,
            source_file: _,
            error: AceError(_),
        })
    ));
}
