use miden_assembly::Assembler;
use miden_core::{
    field::PrimeField64,
    mast::{BasicBlockNodeBuilder, MastForest},
};
use miden_processor::{
    AceError, DefaultHost, ExecutionError, FastProcessor, Felt, Program, StackInputs,
    advice::AdviceInputs,
    operation::Operation,
    trace::chiplets::{MAX_EVAL_CIRCUIT_INVOCATIONS, MAX_EVAL_CIRCUIT_WIRES},
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

#[test]
fn eval_circuit_rejects_excessive_wires_before_memory_access() {
    let program = eval_circuit_program();
    let limit = MAX_EVAL_CIRCUIT_WIRES;
    // READ-heavy and EVAL-heavy circuits, both two wires above the limit.
    for (num_read, num_eval) in [(limit - 2, 4), (2, limit)] {
        // An unaligned pointer would produce a memory error if execution reached the READ loop.
        let stack_inputs =
            StackInputs::new(&[Felt::new_unchecked(1), Felt::from(num_read), Felt::from(num_eval)])
                .unwrap();
        let error = FastProcessor::new(stack_inputs)
            .execute_sync(&program, &mut DefaultHost::default())
            .unwrap_err();
        let ExecutionError::AceChipError { error: AceError(message), .. } = error else {
            panic!("expected an ACE resource-limit error, got {error}");
        };
        assert_eq!(message, format!("num of wires cannot exceed {limit} but was {}", limit + 2));
    }
}

#[test]
fn eval_circuit_witness_invocation_limit_across_calls() {
    let limit = MAX_EVAL_CIRCUIT_INVOCATIONS;
    // Two zero inputs and four gates, each subtracting the first input (wire 5) from itself.
    let gate = 5 + (5_u64 << 30);
    for invocations in [limit, limit + 1] {
        let source = format!(
            r#"
            proc evaluate
                push.{gate}.{gate}.{gate}.{gate}.4 mem_storew_be dropw
                push.4.2.0 eval_circuit drop drop drop
            end
            begin
                repeat.{invocations} call.evaluate end
            end
            "#
        );
        let program = Assembler::default()
            .assemble_program("program", source)
            .unwrap()
            .unwrap_program();
        // Each call enters a fresh context, but all evaluations belong to the same witness.
        let result = FastProcessor::new(StackInputs::default())
            .execute_for_proving_sync(&program, &mut DefaultHost::default());
        if invocations == limit {
            result.unwrap();
        } else {
            let ExecutionError::AceChipError { error: AceError(message), .. } = result.unwrap_err()
            else {
                panic!("expected an ACE invocation-limit error");
            };
            assert_eq!(
                message,
                format!("number of recorded eval_circuit invocations cannot exceed {limit}")
            );
        }
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
