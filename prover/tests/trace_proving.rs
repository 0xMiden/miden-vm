use miden_assembly::Assembler;
use miden_processor::{DefaultHost, ExecutionError, Processor};
use miden_prover::{Prover, ProverError, ProvingInput};

#[test]
fn materialized_trace_proving_rechecks_the_provers_memory_budget() {
    let program = Assembler::default()
        .assemble_program("trace_budget", "begin push.1 drop end")
        .unwrap()
        .unwrap_program();
    let prover = Prover::new().with_max_prover_memory_bytes(0);
    let capture = Processor::new(&program)
        .build_trace(prover.trace_budget())
        .run_sync(&mut DefaultHost::default());
    assert_eq!(prover.trace_budget().limit_bytes(), 0);
    // A zero budget can reject the trace at the row-allocation guard before the peak check.
    assert!(matches!(
        capture,
        Err(ExecutionError::TraceLenExceeded(0)
            | ExecutionError::ProverMemoryExceeded { budget_bytes: 0, .. })
    ));

    let witness = Processor::new(&program)
        .record_witness()
        .run_sync(&mut DefaultHost::default())
        .unwrap()
        .witness;
    assert!(matches!(
        prover.prove(witness),
        Err(ProverError::TraceGeneration(
            ExecutionError::TraceLenExceeded(0)
                | ExecutionError::ProverMemoryExceeded { budget_bytes: 0, .. }
        ))
    ));

    // Materialize under a larger budget to check that proving re-applies its own limit.
    let recording_prover = Prover::new();
    for complete in [false, true] {
        let execution_trace = Processor::new(&program)
            .build_trace(recording_prover.trace_budget())
            .run_sync(&mut DefaultHost::default())
            .expect("trace capture should fit the normal budget")
            .trace;
        let input = ProvingInput::from(execution_trace);
        let result = if complete {
            prover.prove_full(input)
        } else {
            prover.prove(input)
        };
        assert!(
            matches!(
                result,
                Err(ProverError::VmProofGeneration(ExecutionError::ProverMemoryExceeded {
                    estimated_bytes,
                    budget_bytes: 0,
                })) if estimated_bytes > 0
            ),
            "materialized trace proving must enforce its own budget (complete={complete})"
        );
    }
}
