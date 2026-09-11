//! Checks for skipped TRUE roots, repeated roots, and proofs of the wrong batch.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use miden_assembly::Assembler;
use miden_core::{
    Felt, Word,
    deferred::PrecompileWitness,
    program::{ExecutionClaim, proof_request_key},
    proof::{ExecutionProof, HashFunction, PrecompileProof, PrecompileStatus},
};
use miden_core_lib::{CoreLibrary, PVM_PROOF_REQUEST_EVENT_NAME};
use miden_precompiles_verifier::masm_verifier::PvmRecursiveVerifierInputs;
use miden_processor::{
    DefaultHost, ExecutionError, ExecutionOptions, FastProcessor, ProcessorState, Program,
    StackInputs,
    advice::{AdviceInputs, AdviceMutation},
    operation::OperationError,
};
use miden_prover::Prover;

use super::{PvmSettlementHost, assemble_batch, batch_inputs, prove_ecdsa_execution};
use crate::support::ecdsa::{generator_public_key_fixture, valid_fixture};

#[tokio::test(flavor = "current_thread")]
async fn batch_root_and_response_checks() {
    let core_lib = CoreLibrary::default();
    let program = assemble_batch(&core_lib);
    let (first, first_claim, first_state) =
        prove_ecdsa_execution(&core_lib, valid_fixture(), StackInputs::default());
    let (second, second_claim, second_state) =
        prove_ecdsa_execution(&core_lib, generator_public_key_fixture(), StackInputs::default());
    // A different public input gives a different claim with the same ECDSA work.
    let (repeated, repeated_claim, repeated_state) =
        prove_ecdsa_execution(&core_lib, valid_fixture(), StackInputs::new(&[Felt::ONE]).unwrap());
    let (plain, plain_claim) = prove_without_precompiles();
    assert_ne!(first_claim.commitment(), repeated_claim.commitment());
    assert_eq!(first_state.root(), repeated_state.root());
    assert_ne!(first_state.root(), second_state.root());
    assert!(matches!(plain.precompile(), PrecompileStatus::Empty));

    // [A, TRUE, B, A] must keep both occurrences of A and skip only TRUE.
    let executions = [
        (&first, &first_claim),
        (&plain, &plain_claim),
        (&second, &second_claim),
        (&repeated, &repeated_claim),
    ];
    let (stack_inputs, advice_inputs) = batch_inputs(&core_lib, &executions);

    let first_witness = PrecompileWitness::new(first_state).unwrap();
    let merged = PrecompileWitness::merge(vec![
        first_witness.clone(),
        PrecompileWitness::new(second_state).unwrap(),
        PrecompileWitness::new(repeated_state).unwrap(),
    ])
    .unwrap();
    let expected_roots = merged.roots().to_vec();
    let expected_root = merged.state().root();
    let mut host = PvmSettlementHost::new(&core_lib, merged);

    let witness = FastProcessor::new_with_options(
        stack_inputs,
        advice_inputs.clone(),
        ExecutionOptions::default(),
    )
    .unwrap()
    .execute_for_proving(&program, &mut host)
    .await
    .expect("batch settlement failed");
    let precompile_proof = host.precompile_proof.take().unwrap();
    assert_eq!(precompile_proof.roots, expected_roots);
    assert_eq!(precompile_proof.aggregate_root(), Some(expected_root));
    assert!(!witness.has_precompiles());

    // A valid PVM proof for [A, B, A] must fail for [B, A, A].
    let reordered = [
        (&second, &second_claim),
        (&plain, &plain_claim),
        (&first, &first_claim),
        (&repeated, &repeated_claim),
    ];
    let (reordered_stack, reordered_advice) = batch_inputs(&core_lib, &reordered);
    assert_rejects_pvm_response(
        &core_lib,
        &program,
        reordered_stack,
        reordered_advice,
        &precompile_proof,
    );

    // A proof of A alone leaves part of the batch's work unproved.
    let missing_witnesses = Prover::new()
        .with_hash_fn(HashFunction::Poseidon2)
        .prove_precompile(&first_witness)
        .unwrap();
    assert_rejects_pvm_response(
        &core_lib,
        &program,
        stack_inputs,
        advice_inputs.clone(),
        &missing_witnesses,
    );

    // Supply the claim list under a wrong public hash. This must reach and fail the hash check.
    let mut elements = *stack_inputs;
    elements[1] += Felt::ONE;
    let wrong_batch_input = StackInputs::new(&elements).unwrap();
    let commitments: Vec<_> = executions.iter().map(|(_, claim)| claim.commitment()).collect();
    let wrong_commitment = Word::new(elements[1..5].try_into().unwrap());
    let wrong_advice = advice_inputs
        .with_map([(wrong_commitment, Word::words_as_elements(&commitments).to_vec())]);
    let mut host = DefaultHost::default().with_library(&core_lib).unwrap();
    let error = FastProcessor::new_with_options(
        wrong_batch_input,
        wrong_advice,
        ExecutionOptions::default(),
    )
    .unwrap()
    .execute_sync(&program, &mut host)
    .expect_err("accepted a claim list with the wrong public hash");
    assert_failed_assertion(error);

    // Three valid claims must fail the even-count requirement.
    let (stack_inputs, advice_inputs) = batch_inputs(&core_lib, &[(&plain, &plain_claim); 3]);
    let error =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .unwrap()
            .execute_sync(&program, &mut host)
            .expect_err("accepted an odd number of claims");
    assert_failed_assertion(error);

    // With only TRUE roots, the batch needs no PVM proof. This host has no request handler.
    let (stack_inputs, advice_inputs) = batch_inputs(&core_lib, &[(&plain, &plain_claim); 2]);
    let witness =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .unwrap()
            .execute_for_proving_sync(&program, &mut host)
            .expect("a batch with no deferred work requested a PVM proof");
    assert!(!witness.has_precompiles());
}

fn prove_without_precompiles() -> (ExecutionProof, ExecutionClaim) {
    let program = Assembler::default()
        .assemble_program("no_precompiles", "begin push.7 drop end")
        .unwrap()
        .unwrap_program();
    let witness = FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .unwrap()
    .execute_for_proving_sync(&program, &mut DefaultHost::default())
    .unwrap();
    let claim = witness.claim();
    let proof = Prover::new().with_hash_fn(HashFunction::Poseidon2).prove(witness).unwrap();
    (proof, claim)
}

fn assert_rejects_pvm_response(
    core_lib: &CoreLibrary,
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    proof: &PrecompileProof,
) {
    let verifier_root = core_lib.pvm_recursive_verifier_root();
    let response = PvmRecursiveVerifierInputs::for_request(verifier_root, proof).unwrap();
    let response_root = response.claim_commitment();
    let requests = Arc::new(AtomicUsize::new(0));
    let handler_requests = Arc::clone(&requests);
    let mut host = DefaultHost::default().with_library(core_lib).unwrap();
    host.register_handler(
        PVM_PROOF_REQUEST_EVENT_NAME,
        Arc::new(move |process: &ProcessorState<'_>| {
            handler_requests.fetch_add(1, Ordering::Relaxed);
            assert_eq!(process.get_stack_word(1), verifier_root);
            let requested_root = process.get_stack_word(5);
            assert_ne!(requested_root, response_root);
            // Put a valid proof of a different root under the requested key. The MASM verifier
            // must reject it even though the host returned a proof in the expected place.
            let (_, mut map, store) = response.advice().clone().into_parts();
            let stream = map.remove(&proof_request_key(verifier_root, response_root)).unwrap();
            map.insert(proof_request_key(verifier_root, requested_root), stream);
            Ok(vec![
                AdviceMutation::extend_map(map),
                AdviceMutation::extend_merkle_store(store.inner_nodes()),
            ])
        }),
    )
    .unwrap();
    let error =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .unwrap()
            .execute_sync(program, &mut host)
            .expect_err("accepted a PVM proof of different deferred work");
    assert_eq!(requests.load(Ordering::Relaxed), 1, "MASM did not receive the PVM response");
    assert_failed_assertion(error);
}

#[track_caller]
fn assert_failed_assertion(error: ExecutionError) {
    assert!(
        matches!(
            error,
            ExecutionError::OperationError {
                err: OperationError::FailedAssertion { .. },
                ..
            }
        ),
        "{error}",
    );
}
