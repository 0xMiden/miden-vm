use miden_assembly::Assembler;
use miden_core::serde::Serializable;
use miden_precompiles_stark::prover::SessionInputError;
use miden_processor::{DefaultHost, ExecutionError, ExecutionOptions, ExecutionWitness, Processor};
use miden_prover::{PrecompileProvingError, Prover, ProverError};

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
            prover.prove_full(witness).map(Into::into)
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

#[test]
fn full_proving_rejects_mismatched_imported_precompile_graph() {
    let record = |source: &str| {
        let program = Assembler::default().assemble_program("deferred", source).unwrap();
        Processor::new(&program.unwrap_program())
            .record_witness()
            .run_sync(&mut DefaultHost::default())
            .unwrap()
            .witness
    };
    let original = record("begin log_deferred end");
    let original_bytes = original.to_bytes();
    let (vm, graph) = original.into_parts();
    let (other_vm, other_graph) = record("begin log_deferred log_deferred end").into_parts();
    let expected_root = vm.precompile_root();
    let other_root = other_vm.precompile_root();
    assert_ne!(expected_root, other_root);

    // Replace only the trailing precompile witness in the original execution's wire envelope.
    let graph_bytes = graph.unwrap().to_bytes();
    let mut bytes = original_bytes.strip_suffix(graph_bytes.as_slice()).unwrap().to_vec();
    other_graph.unwrap().write_into(&mut bytes);
    let imported = ExecutionWitness::read_from_bytes(&bytes).expect("both parts are well formed");
    let error = Prover::new().prove_full(imported).expect_err("the graph has a different root");
    assert!(
        matches!(
            error,
            ProverError::PrecompileProofGeneration(PrecompileProvingError::Input(
                SessionInputError::RootMismatch { witness: 0, expected, actual }
            )) if expected == expected_root && actual == other_root
        ),
        "{error:?}"
    );
}
