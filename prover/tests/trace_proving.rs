use miden_assembly::Assembler;
use miden_processor::{DefaultHost, ExecutionError, FastProcessor, StackInputs};
use miden_prover::{CompleteProof, Prover, ProverError};

#[test]
fn materialized_trace_proving_rechecks_the_provers_memory_budget() {
    let program = Assembler::default()
        .assemble_program("trace_budget", "begin push.1 drop end")
        .unwrap()
        .unwrap_program();
    let prover = Prover::new().with_max_prover_memory_bytes(0);
    let record_witness = || {
        FastProcessor::new(StackInputs::default())
            .execute_for_proving_sync(&program, &mut DefaultHost::default())
            .unwrap()
    };
    let capture = record_witness().build_trace(prover.trace_budget());
    assert_eq!(prover.trace_budget().limit_bytes(), 0);
    // A zero budget can reject the trace at the row-allocation guard before the peak check.
    assert!(matches!(
        capture,
        Err(ExecutionError::TraceLenExceeded(0)
            | ExecutionError::ProverMemoryExceeded { budget_bytes: 0, .. })
    ));

    // Materialize under a larger budget to check that proving re-applies its own limit.
    let recording_prover = Prover::new();
    for complete in [false, true] {
        let execution_trace = record_witness()
            .build_trace(recording_prover.trace_budget())
            .expect("trace capture should fit the normal budget");
        let result = if complete {
            prover.prove_full_trace(execution_trace).map(CompleteProof::into_inner)
        } else {
            prover.prove_trace(execution_trace)
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
