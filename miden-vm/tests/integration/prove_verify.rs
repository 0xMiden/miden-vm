//! Integration tests for the prove/verify flow with different hash functions.

use alloc::sync::Arc;

use miden_assembly::{Assembler, DefaultSourceManager};
use miden_processor::ExecutionOptions;
use miden_prover::{AdviceInputs, ProvingOptions, StackInputs, prove_sync};
use miden_verifier::verify;
use miden_vm::{DefaultHost, HashFunction};

fn assert_prove_verify(
    source: &str,
    hash_fn: HashFunction,
    hash_name: &str,
    print_stack_outputs: bool,
) {
    let program = Assembler::default().assemble_program(source).unwrap();
    let stack_inputs = StackInputs::try_from_ints([0, 1]).unwrap();
    let advice_inputs = AdviceInputs::default();
    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));
    let options = ProvingOptions::with_96_bit_security(hash_fn);

    println!("Proving with {hash_name}...");
    let (stack_outputs, proof) = prove_sync(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
        options,
    )
    .expect("Proving failed");

    println!("Proof generated successfully!");
    if print_stack_outputs {
        println!("Stack outputs: {:?}", stack_outputs);
    }

    println!("Verifying proof...");
    let security_level =
        verify(program.into(), stack_inputs, stack_outputs, proof).expect("Verification failed");

    println!("Verification successful! Security level: {}", security_level);
}

#[test]
fn test_blake3_256_prove_verify() {
    // Compute many Fibonacci iterations to generate a trace >= 2048 rows
    let source = "
        begin
            repeat.1000
                swap dup.1 add
            end
        end
    ";

    assert_prove_verify(source, HashFunction::Blake3_256, "Blake3_256", false);
}

#[test]
fn test_keccak_prove_verify() {
    // Compute 150th Fibonacci number to generate a longer trace
    let source = "
        begin
            repeat.149
                swap dup.1 add
            end
        end
    ";

    assert_prove_verify(source, HashFunction::Keccak, "Keccak", true);
}

#[test]
fn test_rpo_prove_verify() {
    // Compute 150th Fibonacci number to generate a longer trace
    let source = "
        begin
            repeat.149
                swap dup.1 add
            end
        end
    ";

    assert_prove_verify(source, HashFunction::Rpo256, "RPO", true);
}

#[test]
fn test_poseidon2_prove_verify() {
    // Compute 150th Fibonacci number to generate a longer trace
    let source = "
        begin
            repeat.149
                swap dup.1 add
            end
        end
    ";

    assert_prove_verify(source, HashFunction::Poseidon2, "Poseidon2", true);
}

/// Test end-to-end proving and verification with RPX
#[test]
fn test_rpx_prove_verify() {
    // Compute 150th Fibonacci number to generate a longer trace
    let source = "
        begin
            repeat.149
                swap dup.1 add
            end
        end
    ";

    assert_prove_verify(source, HashFunction::Rpx256, "RPX", true);
}

// ================================================================================================
// FAST PROCESSOR + PARALLEL TRACE GENERATION TESTS
// ================================================================================================

mod fast_parallel {
    use alloc::{sync::Arc, vec::Vec};

    use miden_assembly::{Assembler, DefaultSourceManager};
    use miden_core::{
        Felt, Word,
        events::{EventId, EventName},
        precompile::{
            PrecompileCommitment, PrecompileError, PrecompileRequest, PrecompileTranscript,
            PrecompileVerifier, PrecompileVerifierRegistry,
        },
        proof::{ExecutionProof, HashFunction},
    };
    use miden_core_lib::CoreLibrary;
    use miden_processor::{
        DefaultHost, ExecutionOptions, FastProcessor, ProcessorState, StackInputs,
        advice::{AdviceInputs, AdviceMutation},
        event::{EventError, EventHandler},
        trace::build_trace,
    };
    use miden_prover::{
        ProvingOptions, TraceProvingInputs, config, prove_from_trace_sync, prove_stark,
    };
    use miden_verifier::{verify, verify_with_precompiles};
    use miden_vm::{Program, TraceBuildInputs};

    /// Default fragment size for parallel trace generation
    const FRAGMENT_SIZE: usize = 1024;

    fn parallel_execution_options() -> ExecutionOptions {
        ExecutionOptions::default()
            .with_core_trace_fragment_size(FRAGMENT_SIZE)
            .unwrap()
    }

    fn execute_parallel_trace_inputs(
        program: &Program,
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        host: &mut DefaultHost,
    ) -> TraceBuildInputs {
        FastProcessor::new_with_options(stack_inputs, advice_inputs, parallel_execution_options())
            .execute_trace_inputs_sync(program, host)
            .expect("Fast processor execution failed")
    }

    fn default_source_manager_host() -> DefaultHost {
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()))
    }

    /// Test that proves and verifies using the fast processor + parallel trace generation path.
    /// This verifies the complete code path works end-to-end.
    ///
    /// Note: We only test one hash function here since
    /// `test_trace_equivalence_slow_vs_fast_parallel` verifies trace equivalence, and the slow
    /// processor tests already cover all hash functions.
    #[test]
    fn test_fast_parallel_prove_verify() {
        // Use a program with enough iterations to generate a meaningful trace
        let source = "
            begin
                repeat.500
                    swap dup.1 add
                end
            end
        ";

        let program = Assembler::default().assemble_program(source).unwrap();
        let stack_inputs = StackInputs::try_from_ints([0, 1]).unwrap();
        let advice_inputs = AdviceInputs::default();
        let mut host = default_source_manager_host();
        let trace_inputs =
            execute_parallel_trace_inputs(&program, stack_inputs, advice_inputs.clone(), &mut host);

        let fast_stack_outputs = *trace_inputs.stack_outputs();

        // Build trace using parallel trace generation
        let trace = build_trace(trace_inputs).unwrap();

        // Convert trace to row-major format for proving
        let trace_matrix = trace.to_row_major_matrix();

        // Build public inputs
        let (public_values, kernel_felts) = trace.public_inputs().to_air_inputs();
        let var_len_public_inputs: &[&[Felt]] = &[&kernel_felts];

        let aux_builder = trace.aux_trace_builders();

        // Generate proof using Blake3_256
        let blake3_config = config::blake3_256_config(config::pcs_params());
        let proof_bytes = prove_stark(
            &blake3_config,
            &trace_matrix,
            &public_values,
            var_len_public_inputs,
            &aux_builder,
        )
        .expect("Proving failed");

        let precompile_requests = trace.precompile_requests().to_vec();

        let proof = ExecutionProof::new(proof_bytes, HashFunction::Blake3_256, precompile_requests);

        // Verify the proof
        verify(program.into(), stack_inputs, fast_stack_outputs, proof)
            .expect("Verification failed");
    }

    #[test]
    fn test_prove_from_trace_sync() {
        let source = "
            begin
                repeat.128
                    swap dup.1 add
                end
            end
        ";

        let program = Assembler::default().assemble_program(source).unwrap();
        let stack_inputs = StackInputs::try_from_ints([0, 1]).unwrap();
        let advice_inputs = AdviceInputs::default();
        let mut host = default_source_manager_host();
        let trace_inputs =
            execute_parallel_trace_inputs(&program, stack_inputs, advice_inputs, &mut host);

        let (stack_outputs, proof) = prove_from_trace_sync(TraceProvingInputs::new(
            trace_inputs,
            ProvingOptions::with_96_bit_security(HashFunction::Blake3_256),
        ))
        .expect("prove_from_trace_sync failed");

        verify(program.into(), stack_inputs, stack_outputs, proof).expect("Verification failed");
    }

    #[test]
    fn test_prove_from_trace_sync_preserves_precompile_requests() {
        const NUM_ITERATIONS: usize = 256;
        let fixtures = logged_precompile_fixtures(NUM_ITERATIONS);

        let request_snippets = fixtures
            .iter()
            .map(LoggedPrecompileFixture::source_snippet)
            .collect::<Vec<_>>()
            .join("\n");

        let source = format!(
            "
                use miden::core::sys

                begin
                    {request_snippets}
                end
            "
        );

        let program = Assembler::default()
            .with_dynamic_library(CoreLibrary::default())
            .expect("failed to load core library")
            .assemble_program(source)
            .expect("failed to assemble log_precompile fixture");
        let stack_inputs = StackInputs::default();
        let advice_inputs = AdviceInputs::default();
        let mut host = DefaultHost::default();
        let core_lib = CoreLibrary::default();
        host.load_library(&core_lib).expect("failed to load core library into host");
        for fixture in &fixtures {
            host.register_handler(
                fixture.event_name.clone(),
                Arc::new(DummyLogPrecompileHandler::new(fixture)),
            )
            .expect("failed to register dummy handler");
        }

        let trace_inputs =
            execute_parallel_trace_inputs(&program, stack_inputs, advice_inputs, &mut host);
        assert!(
            trace_inputs.trace_generation_context().core_trace_contexts.len() > 1,
            "expected precompile fixture to span multiple core-trace fragments"
        );

        let (stack_outputs, proof) = prove_from_trace_sync(TraceProvingInputs::new(
            trace_inputs,
            ProvingOptions::with_96_bit_security(HashFunction::Blake3_256),
        ))
        .expect("prove_from_trace_sync failed");

        let expected_requests =
            fixtures.iter().map(LoggedPrecompileFixture::request).collect::<Vec<_>>();

        assert_eq!(proof.precompile_requests(), expected_requests.as_slice());

        let verifier_registry =
            fixtures.iter().fold(PrecompileVerifierRegistry::new(), |registry, fixture| {
                registry.with_verifier(
                    &fixture.event_name,
                    Arc::new(DummyLogPrecompileVerifier::new(fixture)),
                )
            });
        let transcript = verifier_registry
            .requests_transcript(proof.precompile_requests())
            .expect("failed to recompute deferred commitment");
        let mut expected_transcript = PrecompileTranscript::new();
        for fixture in &fixtures {
            expected_transcript.record(fixture.commitment);
        }
        assert_eq!(transcript.finalize(), expected_transcript.finalize());

        let (_, transcript_digest) = verify_with_precompiles(
            program.into(),
            stack_inputs,
            stack_outputs,
            proof,
            &verifier_registry,
        )
        .expect("proof verification with precompiles failed");
        assert_eq!(expected_transcript.finalize(), transcript_digest);
    }

    fn logged_precompile_fixtures(num_iterations: usize) -> Vec<LoggedPrecompileFixture> {
        (0..num_iterations)
            .flat_map(|iteration| {
                (0..3)
                    .map(move |slot| LoggedPrecompileFixture::for_iteration(iteration as u8, slot))
            })
            .collect()
    }

    #[derive(Clone)]
    struct LoggedPrecompileFixture {
        event_name: EventName,
        calldata: Vec<u8>,
        commitment: PrecompileCommitment,
    }

    impl LoggedPrecompileFixture {
        fn new(event_name: EventName, calldata: [u8; 4], tag: Word, comm_calldata: Word) -> Self {
            Self {
                event_name,
                calldata: calldata.into(),
                commitment: PrecompileCommitment::new(tag, comm_calldata),
            }
        }

        fn for_iteration(iteration: u8, slot: u8) -> Self {
            let event_name =
                EventName::from_string(format!("test::sys::log_precompile_{iteration}_{slot}"));
            let iteration = u64::from(iteration);
            let slot = u64::from(slot);
            let event_id = EventId::from_name(event_name.as_str());

            Self::new(
                event_name,
                [
                    iteration as u8,
                    slot as u8,
                    (iteration + slot) as u8,
                    ((iteration * 3) + slot + 1) as u8,
                ],
                Word::from([
                    event_id.as_felt(),
                    Felt::new(iteration + 1),
                    Felt::new(slot + 1),
                    Felt::new((iteration * 3) + slot + 7),
                ]),
                Word::from([
                    Felt::new((iteration * 5) + slot + 11),
                    Felt::new((iteration * 7) + slot + 13),
                    Felt::new((iteration * 11) + slot + 17),
                    Felt::new((iteration * 13) + slot + 19),
                ]),
            )
        }

        fn event_id(&self) -> EventId {
            self.commitment.event_id()
        }

        fn request(&self) -> PrecompileRequest {
            PrecompileRequest::new(self.event_id(), self.calldata.clone())
        }

        fn source_snippet(&self) -> String {
            format!(
                "emit.event(\"{event_name}\")\n\
                 push.{tag} push.{comm}\n\
                 exec.sys::log_precompile_request",
                event_name = self.event_name,
                tag = self.commitment.tag(),
                comm = self.commitment.comm_calldata(),
            )
        }
    }

    #[derive(Clone)]
    struct DummyLogPrecompileHandler {
        event_id: EventId,
        calldata: Vec<u8>,
    }

    impl DummyLogPrecompileHandler {
        fn new(fixture: &LoggedPrecompileFixture) -> Self {
            Self {
                event_id: fixture.event_id(),
                calldata: fixture.calldata.clone(),
            }
        }
    }

    impl EventHandler for DummyLogPrecompileHandler {
        fn on_event(&self, _process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
            Ok(vec![AdviceMutation::extend_precompile_requests([PrecompileRequest::new(
                self.event_id,
                self.calldata.clone(),
            )])])
        }
    }

    #[derive(Clone)]
    struct DummyLogPrecompileVerifier {
        commitment: PrecompileCommitment,
    }

    impl DummyLogPrecompileVerifier {
        fn new(fixture: &LoggedPrecompileFixture) -> Self {
            Self { commitment: fixture.commitment }
        }
    }

    impl PrecompileVerifier for DummyLogPrecompileVerifier {
        fn verify(&self, _calldata: &[u8]) -> Result<PrecompileCommitment, PrecompileError> {
            Ok(self.commitment)
        }
    }
}
