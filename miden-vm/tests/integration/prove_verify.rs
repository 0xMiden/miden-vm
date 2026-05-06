//! Integration tests for the prove/verify flow with different hash functions.

use alloc::sync::Arc;

use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core::{precompile::PrecompileTranscriptState, proof::ExecutionProof};
use miden_core_lib::CoreLibrary;
use miden_processor::ExecutionOptions;
use miden_prover::{
    AdviceInputs, ProgramInfo, ProvingOptions, PublicInputs, StackInputs, StackOutputs, prove_sync,
};
use miden_verifier::verify;
use miden_vm::{DefaultHost, HashFunction};

fn assert_prove_verify(
    source: &str,
    hash_fn: HashFunction,
    hash_name: &str,
    print_stack_outputs: bool,
    verify_recursively: bool,
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
        println!("Stack outputs: {stack_outputs:?}");
    }

    if verify_recursively {
        assert_recursive_verify(
            program.to_info(),
            stack_inputs,
            stack_outputs,
            PrecompileTranscriptState::default(),
            &proof,
        );
    }

    println!("Verifying proof...");
    let security_level =
        verify(program.into(), stack_inputs, stack_outputs, proof).expect("Verification failed");

    println!("Verification successful! Security level: {security_level}");
}

fn assert_recursive_verify(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    pc_transcript_state: PrecompileTranscriptState,
    proof: &ExecutionProof,
) {
    assert_eq!(proof.hash_fn(), HashFunction::Poseidon2);

    let pub_inputs =
        PublicInputs::new(program_info, stack_inputs, stack_outputs, pc_transcript_state);
    let verifier_inputs =
        recursive_verifier::generate_advice_inputs(proof.stark_proof(), pub_inputs);

    let source = "
        use miden::core::sys::vm
        begin
            exec.vm::verify_proof
        end
    ";

    let mut test = crate::build_test!(
        source,
        &verifier_inputs.initial_stack,
        &verifier_inputs.advice_stack,
        verifier_inputs.store,
        verifier_inputs.advice_map
    );
    test.libraries.push(CoreLibrary::default().library().clone());
    test.execute().expect("recursive verifier execution failed");
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

    assert_prove_verify(source, HashFunction::Blake3_256, "Blake3_256", false, false);
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

    assert_prove_verify(source, HashFunction::Keccak, "Keccak", true, false);
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

    assert_prove_verify(source, HashFunction::Rpo256, "RPO", true, false);
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

    assert_prove_verify(source, HashFunction::Poseidon2, "Poseidon2", true, true);
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

    assert_prove_verify(source, HashFunction::Rpx256, "RPX", true, false);
}

mod recursive_verifier {
    use alloc::vec::Vec;

    use miden_core::{
        Felt, WORD_SIZE, Word,
        field::{BasedVectorSpace, QuadFelt},
    };
    use miden_crypto::stark::{
        StarkConfig,
        challenger::CanObserve,
        fri::PcsTranscript,
        lmcs::{Lmcs, proof::BatchProofView},
        proof::StarkTranscript,
    };
    use miden_lifted_stark::AirInstance;
    use miden_prover::{ProcessorAir, PublicInputs, config};
    use miden_utils_testing::crypto::{MerklePath, MerkleStore, PartialMerkleTree};

    type Challenge = QuadFelt;
    type P2Config = config::Poseidon2Config;
    type P2Lmcs = <P2Config as StarkConfig<Felt, Challenge>>::Lmcs;

    pub struct VerifierInputs {
        pub initial_stack: Vec<u64>,
        pub advice_stack: Vec<u64>,
        pub store: MerkleStore,
        pub advice_map: Vec<(Word, Vec<Felt>)>,
    }

    pub fn generate_advice_inputs(proof_bytes: &[u8], pub_inputs: PublicInputs) -> VerifierInputs {
        let params = config::pcs_params();
        let config = config::poseidon2_config(params);
        let transcript_data =
            bincode::deserialize(proof_bytes).expect("failed to deserialize proof bytes");

        let (public_values, kernel_felts) = pub_inputs.to_air_inputs();
        let mut challenger = config.challenger();
        config::observe_protocol_params(&mut challenger);
        challenger.observe_slice(&public_values);
        let var_len_public_inputs: &[&[Felt]] = &[&kernel_felts];
        config::observe_var_len_public_inputs(&mut challenger, var_len_public_inputs, &[WORD_SIZE]);

        let air = ProcessorAir;
        let instance = AirInstance {
            public_values: &public_values,
            var_len_public_inputs,
        };

        let (stark, _digest) =
            StarkTranscript::from_proof(&config, &[(&air, instance)], &transcript_data, challenger)
                .expect("failed to replay verifier transcript");
        let log_trace_height = stark.instance_shapes.log_trace_heights()[0] as usize;

        let kernel_digests: Vec<Word> = kernel_felts
            .chunks_exact(4)
            .map(|chunk| Word::new([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();

        build_advice(&config, &stark, log_trace_height, pub_inputs, &kernel_digests)
    }

    fn build_advice(
        config: &P2Config,
        stark: &StarkTranscript<Challenge, P2Lmcs>,
        log_trace_height: usize,
        pub_inputs: PublicInputs,
        kernel_digests: &[Word],
    ) -> VerifierInputs {
        let pcs = &stark.pcs_transcript;
        let mut advice_stack = Vec::new();

        let params = config::pcs_params();
        advice_stack.push(params.num_queries() as u64);
        advice_stack.push(params.query_pow_bits() as u64);
        advice_stack.push(config::DEEP_POW_BITS as u64);
        advice_stack.push(config::FOLDING_POW_BITS as u64);

        advice_stack.extend_from_slice(&build_fixed_len_inputs(&pub_inputs));
        advice_stack.push(kernel_digests.len() as u64);
        advice_stack.extend_from_slice(&build_kernel_digest_advice(kernel_digests));

        let alpha = stark.randomness[0];
        let beta = stark.randomness[1];
        let beta_coeffs: &[Felt] = beta.as_basis_coefficients_slice();
        let alpha_coeffs: &[Felt] = alpha.as_basis_coefficients_slice();
        advice_stack.extend_from_slice(&[
            beta_coeffs[0].as_canonical_u64(),
            beta_coeffs[1].as_canonical_u64(),
            alpha_coeffs[0].as_canonical_u64(),
            alpha_coeffs[1].as_canonical_u64(),
        ]);

        advice_stack.extend_from_slice(&commitment_to_u64s(stark.main_commit));
        advice_stack.extend_from_slice(&commitment_to_u64s(stark.aux_commit));

        if let Some(aux_values) = stark.all_aux_values.first() {
            advice_stack.extend_from_slice(&challenges_to_u64s(aux_values));
        }

        advice_stack.extend_from_slice(&commitment_to_u64s(stark.quotient_commit));

        let deep_alpha = pcs.deep_transcript.challenge_columns;
        let deep_coeffs: &[Felt] = deep_alpha.as_basis_coefficients_slice();
        advice_stack.extend_from_slice(&[
            deep_coeffs[1].as_canonical_u64(),
            deep_coeffs[0].as_canonical_u64(),
        ]);

        append_ood_evaluations(&mut advice_stack, pcs);
        advice_stack.push(pcs.deep_transcript.pow_witness.as_canonical_u64());

        for round in &pcs.fri_transcript.rounds {
            advice_stack.extend_from_slice(&commitment_to_u64s(round.commitment));
            advice_stack.push(round.pow_witness.as_canonical_u64());
        }

        let final_poly = &pcs.fri_transcript.final_poly;
        let remainder_base: Vec<Felt> = QuadFelt::flatten_to_base(final_poly.to_vec());
        advice_stack.extend(remainder_base.iter().map(Felt::as_canonical_u64));
        advice_stack.push(pcs.query_pow_witness.as_canonical_u64());

        let (store, advice_map) = build_merkle_data(config, stark);
        VerifierInputs {
            initial_stack: vec![log_trace_height as u64],
            advice_stack,
            store,
            advice_map,
        }
    }

    fn append_ood_evaluations<L>(advice_stack: &mut Vec<u64>, pcs: &PcsTranscript<Challenge, L>)
    where
        L: Lmcs<F = Felt>,
    {
        let evals = &pcs.deep_transcript.evals;
        let mut local_values = Vec::new();
        let mut next_values = Vec::new();

        for group in evals {
            for matrix in group {
                let width = matrix.width;
                let values = matrix.values.as_slice();
                local_values.extend_from_slice(&values[..width]);
                if values.len() > width {
                    next_values.extend_from_slice(&values[width..2 * width]);
                }
            }
        }

        advice_stack.extend_from_slice(&challenges_to_u64s(&local_values));
        advice_stack.extend_from_slice(&challenges_to_u64s(&next_values));
    }

    fn build_merkle_data(
        config: &P2Config,
        stark: &StarkTranscript<Challenge, P2Lmcs>,
    ) -> (MerkleStore, Vec<(Word, Vec<Felt>)>) {
        let pcs = &stark.pcs_transcript;
        let lmcs = config.lmcs();

        let mut partial_trees = Vec::new();
        let mut advice_map = Vec::new();

        for batch_proof in &pcs.deep_witnesses {
            let (trees, entries) = batch_proof_to_merkle(lmcs, batch_proof);
            partial_trees.extend(trees);
            advice_map.extend(entries);
        }

        for batch_proof in pcs.fri_witnesses.iter() {
            let (trees, entries) = batch_proof_to_merkle(lmcs, batch_proof);
            partial_trees.extend(trees);
            advice_map.extend(entries);
        }

        let mut store = MerkleStore::new();
        for tree in &partial_trees {
            store.extend(tree.inner_nodes());
        }

        (store, advice_map)
    }

    fn batch_proof_to_merkle<L>(
        lmcs: &L,
        batch_proof: &L::BatchProof,
    ) -> (Vec<PartialMerkleTree>, Vec<(Word, Vec<Felt>)>)
    where
        L: Lmcs<F = Felt>,
        L::Commitment: Copy + Into<[Felt; 4]> + PartialEq,
        L::BatchProof: BatchProofView<Felt, L::Commitment>,
    {
        let mut paths = Vec::new();
        let mut advice_entries = Vec::new();

        for index in batch_proof.indices() {
            let rows = batch_proof.opening(index).expect("missing opening for query index");
            let siblings = batch_proof.path(index).expect("missing Merkle path for query index");
            let leaf_data = rows.as_slice().to_vec();
            let leaf_hash = lmcs.hash(rows.iter_rows());
            let leaf_word = Word::new(leaf_hash.into());
            let merkle_path = MerklePath::new(
                siblings.into_iter().map(|commitment| Word::new(commitment.into())).collect(),
            );

            paths.push((index as u64, leaf_word, merkle_path));
            advice_entries.push((leaf_word, leaf_data));
        }

        let tree =
            PartialMerkleTree::with_paths(paths).expect("failed to build partial Merkle tree");
        (vec![tree], advice_entries)
    }

    fn build_kernel_digest_advice(kernel_digests: &[Word]) -> Vec<u64> {
        let mut result = Vec::with_capacity(kernel_digests.len() * 8);
        for digest in kernel_digests {
            let mut padded: Vec<u64> =
                digest.as_elements().iter().map(Felt::as_canonical_u64).collect();
            padded.resize(8, 0);
            padded.reverse();
            result.extend_from_slice(&padded);
        }
        result
    }

    fn build_fixed_len_inputs(pub_inputs: &PublicInputs) -> Vec<u64> {
        let mut felts = Vec::<Felt>::new();
        felts.extend_from_slice(pub_inputs.program_info().program_hash().as_elements());
        felts.extend_from_slice(pub_inputs.stack_inputs().as_ref());
        felts.extend_from_slice(pub_inputs.stack_outputs().as_ref());
        felts.extend_from_slice(pub_inputs.pc_transcript_state().as_ref());

        let mut fixed_len: Vec<u64> = felts.iter().map(Felt::as_canonical_u64).collect();
        fixed_len.resize(fixed_len.len().next_multiple_of(8), 0);
        fixed_len
    }

    fn commitment_to_u64s<C: Copy + Into<[Felt; 4]>>(commitment: C) -> Vec<u64> {
        let felts: [Felt; 4] = commitment.into();
        felts.iter().map(Felt::as_canonical_u64).collect()
    }

    fn challenges_to_u64s(challenges: &[Challenge]) -> Vec<u64> {
        let base: Vec<Felt> = QuadFelt::flatten_to_base(challenges.to_vec());
        base.iter().map(Felt::as_canonical_u64).collect()
    }
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
        DefaultHost, ExecutionOptions, FastProcessor, ProcessorState, StackInputs, StackOutputs,
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
            execute_parallel_trace_inputs(&program, stack_inputs, advice_inputs, &mut host);

        let fast_stack_outputs = *trace_inputs.stack_outputs();

        // Build trace using parallel trace generation
        let trace = build_trace(trace_inputs).unwrap();

        // Convert trace to row-major format for proving
        let trace_matrix = trace.to_row_major_matrix();

        // Build public inputs
        let (public_values, kernel_felts) = trace.public_inputs().to_air_inputs();
        let var_len_public_inputs: &[&[Felt]] = &[&kernel_felts];

        // Generate proof using Blake3_256
        let blake3_config = config::blake3_256_config(config::pcs_params());
        let proof_bytes =
            prove_stark(&blake3_config, &trace_matrix, &public_values, var_len_public_inputs)
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
        let LoggedPrecompileProofFixture {
            program,
            stack_inputs,
            stack_outputs,
            proof,
            verifier_registry,
            expected_transcript,
        } = prove_logged_precompile_fixture(HashFunction::Blake3_256);

        let (_, pc_transcript_state) = verify_with_precompiles(
            program.into(),
            stack_inputs,
            stack_outputs,
            proof,
            &verifier_registry,
        )
        .expect("proof verification with precompiles failed");
        assert_eq!(expected_transcript.state(), pc_transcript_state);
    }

    #[test]
    fn test_poseidon2_recursive_verify_with_precompile_requests() {
        let LoggedPrecompileProofFixture {
            program,
            stack_inputs,
            stack_outputs,
            proof,
            verifier_registry,
            expected_transcript,
        } = prove_logged_precompile_fixture(HashFunction::Poseidon2);

        super::assert_recursive_verify(
            program.to_info(),
            stack_inputs,
            stack_outputs,
            expected_transcript.state(),
            &proof,
        );

        verify_with_precompiles(
            program.into(),
            stack_inputs,
            stack_outputs,
            proof,
            &verifier_registry,
        )
        .expect("proof verification with precompiles failed");
    }

    fn prove_logged_precompile_fixture(hash_fn: HashFunction) -> LoggedPrecompileProofFixture {
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
            ProvingOptions::with_96_bit_security(hash_fn),
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
        assert_eq!(transcript.state(), expected_transcript.state());

        LoggedPrecompileProofFixture {
            program,
            stack_inputs,
            stack_outputs,
            proof,
            verifier_registry,
            expected_transcript,
        }
    }

    struct LoggedPrecompileProofFixture {
        program: Program,
        stack_inputs: StackInputs,
        stack_outputs: StackOutputs,
        proof: ExecutionProof,
        verifier_registry: PrecompileVerifierRegistry,
        expected_transcript: PrecompileTranscript,
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
        fn new(
            event_name: EventName,
            calldata: [u8; 4],
            tag: Word,
            comm_0: Word,
            comm_1: Word,
        ) -> Self {
            Self {
                event_name,
                calldata: calldata.into(),
                commitment: PrecompileCommitment::new(tag, comm_0, comm_1),
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
                    Felt::new_unchecked(iteration + 1),
                    Felt::new_unchecked(slot + 1),
                    Felt::new_unchecked((iteration * 3) + slot + 7),
                ]),
                Word::from([
                    Felt::new_unchecked((iteration * 5) + slot + 11),
                    Felt::new_unchecked((iteration * 7) + slot + 13),
                    Felt::new_unchecked((iteration * 11) + slot + 17),
                    Felt::new_unchecked((iteration * 13) + slot + 19),
                ]),
                Word::from([
                    Felt::new_unchecked((iteration * 17) + slot + 23),
                    Felt::new_unchecked((iteration * 19) + slot + 29),
                    Felt::new_unchecked((iteration * 23) + slot + 31),
                    Felt::new_unchecked((iteration * 29) + slot + 37),
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
            let stmnt = self.commitment.statement();
            format!(
                "emit.event(\"{event_name}\")\n\
                 push.{stmnt}\n\
                 exec.sys::log_precompile_request",
                event_name = self.event_name,
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
