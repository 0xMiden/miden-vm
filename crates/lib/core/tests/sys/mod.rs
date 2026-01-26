use std::sync::Arc;

use miden_assembly::Assembler;
use miden_core::{
    EventId, EventName, Felt, HashFunction, ProgramInfo, Word,
    precompile::{
        PrecompileCommitment, PrecompileError, PrecompileRequest, PrecompileTranscript,
        PrecompileVerifier, PrecompileVerifierRegistry,
    },
};
use miden_core_lib::CoreLibrary;
use miden_processor::{
    AdviceInputs, AdviceMutation, DefaultHost, EventError, EventHandler, ProcessorState, Program,
    StackInputs,
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

    let tag = Word::from([event_id.as_felt(), Felt::new(1), Felt::new(0), Felt::new(7)]);
    let comm = Word::from([Felt::new(43), Felt::new(62), Felt::new(24), Felt::new(1)]);
    let commitment = PrecompileCommitment::new(tag, comm);

    let source = format!(
        "
            use miden::core::sys

            begin
                emit.event(\"{EVENT_NAME}\")

                push.{tag} push.{comm}
                exec.sys::log_precompile_request
            end
        ",
    );

    let handler = DummyLogPrecompileHandler { event_id, calldata: calldata.clone() };

    let mut test = build_debug_test!(&source, &[]);
    test.add_event_handler(EVENT_NAME, handler.clone());

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
    host.register_handler(EVENT_NAME, Arc::new(handler.clone()))
        .expect("failed to register dummy handler");

    let options = ProvingOptions::with_96_bit_security(HashFunction::Blake3_256);
    let (stack_outputs, proof) =
        miden_utils_testing::prove_sync(&program, stack_inputs, advice_inputs, &mut host, options)
            .expect("failed to generate proof for log_precompile helper");

    // Proof should include the single deferred request that we expect.
    assert_eq!(proof.precompile_requests().len(), 1);

    let verifier_registry = PrecompileVerifierRegistry::new()
        .with_verifier(&EVENT_NAME, Arc::new(DummyLogPrecompileVerifier { commitment }));
    let verifier_transcript = verifier_registry
        .requests_transcript(proof.precompile_requests())
        .expect("failed to recompute deferred commitment (proof)");
    assert_eq!(
        verifier_transcript.finalize(),
        transcript.finalize(),
        "deferred commitment mismatch in proof"
    );

    let mut expected_proof_transcript = PrecompileTranscript::new();
    expected_proof_transcript.record(commitment);
    assert_eq!(
        expected_proof_transcript.finalize(),
        transcript.finalize(),
        "deferred commitment mismatch in proof"
    );

    let program_info = ProgramInfo::from(program);
    let (_, transcript_digest) = miden_verifier::verify_with_precompiles(
        program_info,
        stack_inputs,
        stack_outputs,
        proof,
        &verifier_registry,
    )
    .expect("proof verification with precompiles failed");
    assert_eq!(transcript.finalize(), transcript_digest);
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
