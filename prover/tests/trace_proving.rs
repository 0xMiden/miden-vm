use miden_assembly::Assembler;
use miden_processor::{DefaultHost, ExecutionError, ExecutionOptions, Processor};
use miden_prover::{Prover, ProverError};

#[test]
fn witness_proving_enforces_the_provers_memory_budget() {
    let program = Assembler::default()
        .assemble_program("trace_budget", "begin push.1 drop end")
        .unwrap()
        .unwrap_program();
    let record = || {
        Processor::new(&program)
            .with_options(ExecutionOptions::default().with_core_trace_fragment_size(8).unwrap())
            .record_witness()
            .run_sync(&mut DefaultHost::default())
            .unwrap()
            .witness
    };
    let budget = miden_vm_stark::memory::default_budget();
    let (vm, _) = record().into_parts();
    let exact_peak = {
        let trace = vm.build_trace(&budget).unwrap();
        budget.prover_peak_bytes(trace.trace_len_summary().padded_heights()).unwrap()
    };

    // Both entrypoints must enforce the padded shape even when the raw buffers fit.
    let limit = exact_peak - 1;
    let prover = Prover::new().with_max_prover_memory_bytes(limit);
    for complete in [false, true] {
        let witness = record();
        let result = if complete {
            prover.prove_full(witness)
        } else {
            prover.prove(witness)
        };
        assert!(matches!(
            result,
            Err(ProverError::TraceGeneration(
                ExecutionError::ProverMemoryExceeded { estimated_bytes, budget_bytes }
            )) if estimated_bytes == exact_peak && budget_bytes == limit
        ));
    }
}
