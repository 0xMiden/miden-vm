use std::sync::Arc;

use miden_assembly::Assembler;
use miden_core::{
    Felt, WORD_SIZE, Word,
    events::{EventId, EventName},
    precompile::{
        PrecompileCommitment, PrecompileError, PrecompileRequest, PrecompileTranscript,
        PrecompileVerifier, PrecompileVerifierRegistry,
    },
    program::ProgramInfo,
    proof::HashFunction,
};
use miden_core_lib::CoreLibrary;
use miden_processor::{
    DefaultHost, ExecutionOptions, ProcessorState, Program, StackInputs,
    advice::{AdviceInputs, AdviceMutation},
    event::{EventError, EventHandler},
};
use miden_prover::ProvingOptions;
use miden_utils_testing::{MIN_STACK_DEPTH, proptest::prelude::*, rand::rand_vector};

#[test]
fn truncate_stack() {
    let source = "use miden::core::sys begin repeat.12 push.0 end exec.sys::truncate_stack end";
    // Input [1, 2, ..., 16] -> stack with 1 at top
    // After 12 push.0 and truncate: [0, 0, ..., 0, 1, 2, 3, 4]
    build_test!(source, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        .expect_stack(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4]);
}

#[test]
fn reduce_kernel_digests_upper_bound() {
    // init_seed contract:
    //   Stack: [log(trace_length), rd0, rd1, rd2, rd3, ...]
    //   Memory: num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits
    //
    // process_public_inputs advice stack (consumed in order):
    //   1. load_public_inputs: 40 fixed-length PI felts (5 iterations of 8)
    //   2. reduce_variable_length_public_inputs:
    //        - 1 felt (num_kernel_proc_digests)
    //        - num_kernel_proc_digests * 8 felts (digests via adv_pipe)
    //        - 4 felts (aux randomness via adv_loadw)
    //   3. reduce_kernel_digests asserts num_kernel_proc_digests < 1024
    let source = "
        use miden::core::stark::random_coin
        use miden::core::stark::constants
        use miden::core::sys::vm::public_inputs
        begin
            push.27 exec.constants::set_number_queries
            push.0  exec.constants::set_query_pow_bits
            push.0  exec.constants::set_deep_pow_bits
            push.16 exec.constants::set_folding_pow_bits
            push.0.0.0.0 push.10
            exec.random_coin::init_seed
            exec.public_inputs::process_public_inputs
        end
    ";

    let num_kernel_proc_digests = 1024_usize;
    let num_elements_kernel_proc_digests = num_kernel_proc_digests * WORD_SIZE.next_multiple_of(8);
    let fixed_length_public_inputs = vec![0_u64; 40];
    let kernel_procedures_digests = vec![0_u64; num_elements_kernel_proc_digests];
    let auxiliary_rand_values = [0_u64; 4];

    // Advice layout (consumed top-to-bottom):
    //   40 fixed-len PI, 1 num_kernel_proc_digests, 8192 digest felts, 4 aux rand
    let mut advice_stack = Vec::new();
    advice_stack.extend_from_slice(&fixed_length_public_inputs);
    advice_stack.push(num_kernel_proc_digests as u64);
    advice_stack.extend_from_slice(&kernel_procedures_digests);
    advice_stack.extend_from_slice(&auxiliary_rand_values);

    let test = build_test!(source, &[], &advice_stack);
    expect_assert_error_message!(test);
}

proptest! {
    #[test]
    fn truncate_stack_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH), n in 1_usize..100) {
        let push_values = rand_vector::<u64>(n);
        let mut source_vec = vec!["use miden::core::sys".to_string(), "begin".to_string()];
        for value in push_values.iter() {
            source_vec.push(format!("push.{value}"));
        }
        source_vec.push("exec.sys::truncate_stack".to_string());
        source_vec.push("end".to_string());
        let source = source_vec.join(" ");
        let mut expected_values: Vec<u64> = push_values.iter().rev().copied().collect();
        expected_values.extend(test_values.iter());
        expected_values.truncate(MIN_STACK_DEPTH);
        build_test!(&source, &test_values).prop_expect_stack(&expected_values)?;
    }
}

#[test]
fn log_precompile_request_procedure() {
    // This test ensures that `exec.sys::log_precompile_request` correctly invokes the
    // `log_precompile` instruction, records the deferred request, and yields the expected
    // precompile sponge update. We run both direct execution (debug test) and a full
    // prove/verify cycle to exercise the deferred-request commitment path end-to-end.
    const EVENT_NAME: EventName = EventName::new("test::sys::log_precompile");
    let event_id = EventId::from_name(EVENT_NAME);
    let calldata = vec![1u8, 2, 3, 4];

    let tag = Word::from([
        event_id.as_felt(),
        Felt::new_unchecked(1),
        Felt::new_unchecked(0),
        Felt::new_unchecked(7),
    ]);
    let comm_0 = Word::from([
        Felt::new_unchecked(43),
        Felt::new_unchecked(62),
        Felt::new_unchecked(24),
        Felt::new_unchecked(1),
    ]);
    let comm_1 = Word::from([
        Felt::new_unchecked(11),
        Felt::new_unchecked(13),
        Felt::new_unchecked(17),
        Felt::new_unchecked(19),
    ]);
    let commitment = PrecompileCommitment::new(tag, comm_0, comm_1);
    let stmnt = commitment.statement();

    let source = format!(
        "
            use miden::core::sys

            begin
                emit.event(\"{EVENT_NAME}\")

                push.{stmnt}
                exec.sys::log_precompile_request
            end
        ",
    );

    let handler = DummyLogPrecompileHandler { event_id, calldata: calldata.clone() };

    let test = build_debug_test!(&source, &[]).with_event_handler(EVENT_NAME, handler.clone());

    let trace = test.execute().expect("failed to execute log_precompile test");

    let requests = trace.precompile_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].event_id(), event_id);
    assert_eq!(requests[0].calldata(), calldata.as_slice());

    let verifier_registry = PrecompileVerifierRegistry::new()
        .with_verifier(&EVENT_NAME, Arc::new(DummyLogPrecompileVerifier { commitment }));
    let transcript = verifier_registry
        .requests_transcript(requests)
        .expect("failed to recompute deferred commitment");

    let mut expected_transcript = PrecompileTranscript::new();
    expected_transcript.record(commitment);
    assert_eq!(expected_transcript, transcript);

    // Prove/verify the same program to ensure deferred requests are handled in the STARK proof.
    let program: Program = Assembler::default()
        .with_dynamic_library(CoreLibrary::default())
        .expect("failed to load core library")
        .assemble_program(source)
        .expect("failed to assemble log_precompile fixture");

    let stack_inputs = StackInputs::default();
    let advice_inputs = AdviceInputs::default();
    let mut host = DefaultHost::default();
    let core_lib = CoreLibrary::default();
    host.load_library(&core_lib).expect("failed to load core library into host");
    host.register_handler(EVENT_NAME, Arc::new(handler))
        .expect("failed to register dummy handler");

    let options = ProvingOptions::with_96_bit_security(HashFunction::Blake3_256);
    let (stack_outputs, proof) = miden_utils_testing::prove_sync(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
        options,
    )
    .expect("failed to generate proof for log_precompile helper");

    // Proof should include the single deferred request that we expect.
    assert_eq!(proof.precompile_requests().len(), 1);

    let verifier_registry = PrecompileVerifierRegistry::new()
        .with_verifier(&EVENT_NAME, Arc::new(DummyLogPrecompileVerifier { commitment }));
    let verifier_transcript = verifier_registry
        .requests_transcript(proof.precompile_requests())
        .expect("failed to recompute deferred commitment (proof)");
    assert_eq!(
        verifier_transcript.state(),
        transcript.state(),
        "deferred commitment mismatch in proof"
    );

    let mut expected_proof_transcript = PrecompileTranscript::new();
    expected_proof_transcript.record(commitment);
    assert_eq!(
        expected_proof_transcript.state(),
        transcript.state(),
        "deferred commitment mismatch in proof"
    );

    let program_info = ProgramInfo::from(program);
    let (_, pc_transcript_state) = miden_verifier::verify_with_precompiles(
        program_info,
        stack_inputs,
        stack_outputs,
        proof,
        &verifier_registry,
    )
    .expect("proof verification with precompiles failed");
    assert_eq!(transcript.state(), pc_transcript_state);
}

#[derive(Clone)]
struct DummyLogPrecompileHandler {
    event_id: EventId,
    calldata: Vec<u8>,
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

impl PrecompileVerifier for DummyLogPrecompileVerifier {
    fn verify(&self, _calldata: &[u8]) -> Result<PrecompileCommitment, PrecompileError> {
        Ok(self.commitment)
    }
}
