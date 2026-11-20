//! Checks for skipped TRUE roots, repeated roots, and proofs of the wrong batch.

use miden_assembly::Assembler;
use miden_core::{
    Felt, Word,
    deferred::fold_deferred_root,
    program::{ExecutionClaim, proof_request_key},
    proof::{ExecutionProof, HashFunction, PrecompileProof, PrecompileStatus},
};
use miden_core_lib::CoreLibrary;
use miden_processor::{
    DefaultHost, ExecutionError, ExecutionOptions, FastProcessor, Program, StackInputs,
    advice::AdviceInputs, operation::OperationError,
};
use miden_prover::Prover;

use super::{assemble_batch, batch_inputs, prove_ecdsa_execution, pvm_proof_advice};
use crate::support::ecdsa::{generator_public_key_fixture, valid_fixture};

#[test]
fn batch_root_and_response_checks() {
    let core_lib = CoreLibrary::default();
    let program = assemble_batch(&core_lib);
    let (first, first_claim, first_witness) =
        prove_ecdsa_execution(&core_lib, valid_fixture(), StackInputs::default());
    let (second, second_claim, second_witness) =
        prove_ecdsa_execution(&core_lib, generator_public_key_fixture(), StackInputs::default());
    // A different public input gives a different claim with the same ECDSA work.
    let (repeated, repeated_claim, repeated_witness) =
        prove_ecdsa_execution(&core_lib, valid_fixture(), StackInputs::new(&[Felt::ONE]).unwrap());
    let (plain, plain_claim) = prove_without_precompiles();
    assert_ne!(first_claim.commitment(), repeated_claim.commitment());
    let first_root = first.vm().precompile_root;
    let second_root = second.vm().precompile_root;
    let repeated_root = repeated.vm().precompile_root;
    assert_eq!(first_root, repeated_root);
    assert_ne!(first_root, second_root);
    assert!(matches!(plain.precompile(), PrecompileStatus::Empty));

    // [A, TRUE, B, A] must keep both occurrences of A and skip only TRUE.
    let executions = [
        (&first, &first_claim),
        (&plain, &plain_claim),
        (&second, &second_claim),
        (&repeated, &repeated_claim),
    ];
    let (stack_inputs, advice_inputs) = batch_inputs(&core_lib, &executions);

    let expected_roots = vec![first_root, second_root, repeated_root];
    let expected_root = expected_roots.iter().copied().reduce(fold_deferred_root).unwrap();
    let precompile_proof = Prover::new()
        .with_hash_fn(HashFunction::Eidos)
        .prove_precompiles(vec![first_witness.clone(), second_witness, repeated_witness])
        .unwrap();
    assert_eq!(precompile_proof.roots, expected_roots);
    assert_eq!(precompile_proof.aggregate_root(), Some(expected_root));
    let pvm_advice =
        pvm_proof_advice(core_lib.pvm_recursive_verifier_root(), &precompile_proof).unwrap();
    let mut prepared_advice = advice_inputs.clone();
    prepared_advice.extend(pvm_advice);
    let mut host = DefaultHost::default().with_library(&core_lib).unwrap();

    let witness =
        FastProcessor::new_with_options(stack_inputs, prepared_advice, ExecutionOptions::default())
            .unwrap()
            .execute_for_proving_sync(&program, &mut host)
            .expect("batch settlement failed");
    assert!(!witness.has_precompiles());

    // A valid PVM proof for [A, B, A] must fail for [B, A, A].
    let reordered = [
        (&second, &second_claim),
        (&plain, &plain_claim),
        (&first, &first_claim),
        (&repeated, &repeated_claim),
    ];
    let (reordered_stack, reordered_advice) = batch_inputs(&core_lib, &reordered);
    let reordered_root =
        fold_deferred_root(fold_deferred_root(second_root, first_root), repeated_root);
    assert_rejects_pvm_response(
        &core_lib,
        &program,
        reordered_stack,
        reordered_advice,
        reordered_root,
        &precompile_proof,
    );

    // A proof of A alone leaves part of the batch's work unproved.
    let missing_witnesses = Prover::new()
        .with_hash_fn(HashFunction::Eidos)
        .prove_precompiles(vec![first_witness])
        .unwrap();
    assert_rejects_pvm_response(
        &core_lib,
        &program,
        stack_inputs,
        advice_inputs.clone(),
        expected_root,
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

    // With only TRUE roots, the batch needs no PVM proof package in advice.
    let (stack_inputs, advice_inputs) = batch_inputs(&core_lib, &[(&plain, &plain_claim); 2]);
    let witness =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .unwrap()
            .execute_for_proving_sync(&program, &mut host)
            .expect("a batch with no deferred work tried to fetch a PVM proof");
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
    let proof = Prover::new().with_hash_fn(HashFunction::Eidos).prove(witness).unwrap();
    (proof, claim)
}

fn assert_rejects_pvm_response(
    core_lib: &CoreLibrary,
    program: &Program,
    stack_inputs: StackInputs,
    mut advice_inputs: AdviceInputs,
    expected_root: Word,
    proof: &PrecompileProof,
) {
    let verifier_root = core_lib.pvm_recursive_verifier_root();
    let response_root = proof.aggregate_root().unwrap();
    let advice = pvm_proof_advice(verifier_root, proof).unwrap();
    assert_ne!(expected_root, response_root);
    // Put a valid proof of a different root under the expected key, so rejection must come
    // from verification rather than a missing advice-map entry.
    let (stack, mut map, store) = advice.into_parts();
    let stream = map.remove(&proof_request_key(verifier_root, response_root)).unwrap();
    map.insert(proof_request_key(verifier_root, expected_root), stream);
    advice_inputs.extend(AdviceInputs::new(stack, map, store));
    let mut host = DefaultHost::default().with_library(core_lib).unwrap();
    let error =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .unwrap()
            .execute_sync(program, &mut host)
            .expect_err("accepted a PVM proof of different deferred work");
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
