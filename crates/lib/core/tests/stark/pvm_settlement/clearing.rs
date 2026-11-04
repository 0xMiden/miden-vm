//! Settlement must prove the live accumulator and enforce its policy before clearing it.

use std::sync::{Arc, OnceLock};

use miden_core::{
    Word,
    deferred::TRUE_DIGEST,
    mast::error_code_from_msg,
    program::proof_request_key,
    proof::{HashFunction, PrecompileProof, PrecompileStatus},
};
use miden_core_lib::{CoreLibrary, PVM_PROOF_REQUEST_EVENT_NAME};
use miden_processor::{
    DefaultHost, ExecutionError, ExecutionOptions, FastProcessor, ProcessorState, StackInputs,
    advice::AdviceMutation, operation::OperationError,
};
use miden_prover::Prover;
use miden_verifier::Verifier;

use super::{PvmSettlementHost, SettlementWitnesses, pvm_proof_advice, signature_execution_inputs};
use crate::support::ecdsa::{generator_public_key_fixture, valid_fixture};

const MIN_SECURITY_BITS: u32 = 96;
const INSUFFICIENT_SECURITY: &str = "PVM proof security is below the clearing policy";

#[tokio::test(flavor = "current_thread")]
async fn live_accumulator_is_proved_before_clearing() {
    let core_lib = CoreLibrary::default();
    let mut host = PvmSettlementHost::new(&core_lib, SettlementWitnesses::Exported);
    let (program, advice) = signature_execution_inputs(
        &core_lib,
        valid_fixture(),
        None,
        &clearing_epilogue(MIN_SECURITY_BITS),
    );
    let witness = FastProcessor::new_with_options(
        StackInputs::default(),
        advice,
        ExecutionOptions::default(),
    )
    .unwrap()
    .execute_for_proving(&program, &mut host)
    .await
    .expect("recursive verification and clearing must succeed");
    let root = host.requested_root.expect("settlement must request the live root");
    assert_ne!(root, TRUE_DIGEST);
    let pvm_proof = host
        .precompile_proof
        .take()
        .expect("the exported witness must produce a PVM proof");
    assert_eq!(pvm_proof.roots, [root]);
    assert!(!witness.has_precompiles(), "clearing must remove the settled obligation");

    // Prove the execution containing both the original workload and recursive settlement.
    let claim = witness.claim();
    let proof = Prover::new().with_hash_fn(HashFunction::Eidos).prove(witness).unwrap();
    assert!(matches!(proof.precompile(), PrecompileStatus::Empty));
    assert_eq!(proof.vm().precompile_root, TRUE_DIGEST);
    assert!(Verifier::new().verify(&claim, &proof).unwrap().is_complete());

    // Reuse this valid proof: change the workload for the root failure, and raise the policy
    // above its authenticated security level for the security failure.
    let security_level = Verifier::new()
        .verify_precompile(&pvm_proof, root)
        .unwrap()
        .conjectured_security_level();
    enum Rejection {
        DifferentRoot,
        InsufficientSecurity,
    }
    for case in [Rejection::DifferentRoot, Rejection::InsufficientSecurity] {
        let (fixture, minimum) = match case {
            Rejection::DifferentRoot => (generator_public_key_fixture(), MIN_SECURITY_BITS),
            Rejection::InsufficientSecurity => (valid_fixture(), security_level + 1),
        };
        let (program, advice) =
            signature_execution_inputs(&core_lib, fixture, None, &clearing_epilogue(minimum));
        let (mut host, requested_root) = rejection_host(&core_lib, &pvm_proof);
        let mut processor = FastProcessor::new_with_options(
            StackInputs::default(),
            advice,
            ExecutionOptions::default(),
        )
        .unwrap();
        let error = processor
            .execute_mut_sync(&program, &mut host)
            .expect_err("an invalid settlement must fail before clearing");
        let requested_root = *requested_root.get().expect("the verifier must receive a proof");
        assert_ne!(requested_root, TRUE_DIGEST);
        assert_eq!(
            processor.deferred_state().root(),
            requested_root,
            "failed settlement must retain the live obligation",
        );
        let ExecutionError::OperationError {
            err: OperationError::FailedAssertion { err_code, .. },
            ..
        } = &error
        else {
            panic!("expected a verifier or security assertion, got {error}");
        };
        match case {
            Rejection::DifferentRoot => {
                assert_ne!(requested_root, root);
                assert_ne!(*err_code, error_code_from_msg(INSUFFICIENT_SECURITY));
            },
            Rejection::InsufficientSecurity => {
                assert_eq!(requested_root, root);
                assert_eq!(*err_code, error_code_from_msg(INSUFFICIENT_SECURITY));
            },
        }
    }
}

fn clearing_epilogue(minimum_security: u32) -> String {
    format!(
        "
        adv.push_deferred_root padw adv_loadw
        # => [ROOT, ...]; export the live execution's witness before requesting its proof.
        adv.export_deferred_witness
        exec.::miden::core::sys::pvm::request_proof
        dupw exec.::miden::core::sys::pvm::verify_proof
        # => [security_descriptor(12), ROOT, ...]
        exec.::miden::core::stark::security::compute_conjectured_security_level
        u32lt.{minimum_security} assertz.err=\"{INSUFFICIENT_SECURITY}\"
        # => [ROOT, ...]; the preserved root is exactly the one just verified.
        clear_deferred dropw
        "
    )
}

/// Supplies a known valid proof under the requested key, even when its root does not match.
/// This deliberately bypasses the honest host's root check so rejection must happen in MASM.
fn rejection_host(
    core_lib: &CoreLibrary,
    proof: &PrecompileProof,
) -> (DefaultHost, Arc<OnceLock<Word>>) {
    let verifier_root = core_lib.pvm_recursive_verifier_root();
    let proof_root = proof.aggregate_root().unwrap();
    let advice = pvm_proof_advice(verifier_root, proof).unwrap();
    let requested_root = Arc::new(OnceLock::new());
    let observed_root = Arc::clone(&requested_root);
    let mut host = DefaultHost::default().with_library(core_lib).unwrap();
    host.register_handler(
        PVM_PROOF_REQUEST_EVENT_NAME,
        Arc::new(move |process: &ProcessorState<'_>| {
            // Event stack: [event_id, VERIFIER_ROOT, ROOT, ...].
            assert_eq!(process.get_stack_word(1), verifier_root);
            let root = process.get_stack_word(5);
            observed_root.set(root).expect("each execution requests one settlement proof");
            let (_, mut map, store) = advice.clone().into_parts();
            let stream = map.remove(&proof_request_key(verifier_root, proof_root)).unwrap();
            map.insert(proof_request_key(verifier_root, root), stream);
            Ok(vec![
                AdviceMutation::extend_map(map),
                AdviceMutation::extend_merkle_store(store.inner_nodes()),
            ])
        }),
    )
    .unwrap();
    (host, requested_root)
}
