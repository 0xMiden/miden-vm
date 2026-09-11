//! Settle a batch of Miden VM (MVM) executions with one precompile VM (PVM) proof.
//!
//! The two ECDSA programs stand in for transactions; they do not use the protocol kernel.
//! Each leaves a deferred root identifying the precompile work still to be proved. `verify_batch`
//! in `batch.masm` accepts an even runtime claim count bounded by `MAX_CLAIMS`. `PvmSettlementHost`
//! in the parent module uses the executions' deferred witness data to generate a PVM proof when
//! MASM requests it.

use miden_assembly::{Assembler, Linkage};
use miden_core::{
    Felt, Word,
    crypto::hash::Poseidon2,
    deferred::{PrecompileWitness, TRUE_DIGEST},
    program::ExecutionClaim,
    proof::{ExecutionProof, HashFunction, PrecompileStatus},
};
use miden_core_lib::CoreLibrary;
use miden_processor::{
    ExecutionOptions, FastProcessor, Program, StackInputs, advice::AdviceInputs,
};
use miden_prover::Prover;
use miden_verifier::{Verifier, recursive::RecursiveVerifierInputs};

use super::{PvmSettlementHost, prove_ecdsa_execution};
use crate::support::ecdsa::{generator_public_key_fixture, valid_fixture};

mod checks;

#[tokio::test(flavor = "current_thread")]
async fn batch_settles_deferred_obligations_with_one_pvm_proof() {
    let core_lib = CoreLibrary::default();
    let program = assemble_batch(&core_lib);

    // Each returned state contains the precompile inputs needed by the host.
    let (first_proof, first_claim, first_state) =
        prove_ecdsa_execution(&core_lib, valid_fixture(), StackInputs::default());
    let (second_proof, second_claim, second_state) =
        prove_ecdsa_execution(&core_lib, generator_public_key_fixture(), StackInputs::default());
    let roots = [first_state.root(), second_state.root()];
    assert_ne!(roots[0], roots[1]);

    // Public inputs identify the ordered claims; advice supplies the proofs.
    let (stack_inputs, advice_inputs) =
        batch_inputs(&core_lib, &[(&first_proof, &first_claim), (&second_proof, &second_claim)]);

    // Combine the data for D1 and D2. Merging does not create a proof: the host waits for
    // the MASM request before proving D = digest(AND(D1, D2)).
    let merged = PrecompileWitness::merge(vec![
        PrecompileWitness::new(first_state).unwrap(),
        PrecompileWitness::new(second_state).unwrap(),
    ])
    .expect("failed to merge the precompile witnesses");
    let expected_root = merged.state().root();
    let mut host = PvmSettlementHost::new(&core_lib, merged);

    // Execution awaits the PVM proof, then MASM verifies it against the combined root.
    let witness =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .unwrap()
            .execute_for_proving(&program, &mut host)
            .await
            .expect("batch settlement failed");
    let precompile_proof = host.precompile_proof.take().expect("the host did not produce a proof");
    assert_eq!(precompile_proof.roots, roots);
    assert_eq!(precompile_proof.aggregate_root(), Some(expected_root));
    assert!(!witness.has_precompiles(), "the batch left precompile work unsettled");

    // Prove the batcher itself. Its proof settles both executions, so the recipient needs no
    // separate precompile proof.
    let batch_claim = witness.claim();
    let batch_proof = Prover::new()
        .with_hash_fn(HashFunction::Poseidon2)
        .prove(witness)
        .expect("failed to prove the batcher");
    assert!(matches!(batch_proof.precompile(), PrecompileStatus::Empty));
    assert_eq!(batch_proof.vm().precompile_root, TRUE_DIGEST);
    let outcome = Verifier::new()
        .verify(&batch_claim, &batch_proof)
        .expect("batch proof verification failed");
    assert!(outcome.is_complete());
    assert!(outcome.vm_security_parameters().conjectured_security_level() >= 96);
}

fn assemble_batch(core_lib: &CoreLibrary) -> Program {
    let mut assembler =
        Assembler::default().with_package(core_lib.package(), Linkage::Dynamic).unwrap();
    assembler
        .compile_and_statically_link(include_str!("batch.masm"))
        .expect("failed to link the batch verifier");

    let source = r#"
        use batch

        # Allocate 4 * MAX_CLAIMS elements; the bound is defined in batch.masm.
        @locals(16)
        proc run_batch_example(num_claims: u32, claims_commitment: word)
            locaddr.0
            exec.batch::verify_batch
        end

        begin
            exec.run_batch_example
        end
    "#;
    assembler
        .assemble_program("batch_precompile_settlement", source)
        .expect("failed to assemble the batcher")
        .unwrap_program()
}

/// Put the claims and proofs where the MASM batcher can read them.
///
/// Only the claim count and the hash of the ordered claim list are public inputs. The list and
/// proof data go in the advice map, the VM's untrusted input store. MASM checks the list against
/// the public hash, then verifies each proof. Request keys select proofs by verifier and claim.
fn batch_inputs(
    core_lib: &CoreLibrary,
    executions: &[(&ExecutionProof, &ExecutionClaim)],
) -> (StackInputs, AdviceInputs) {
    let commitments: Vec<_> = executions.iter().map(|(_, claim)| claim.commitment()).collect();
    let claim_elements = Word::words_as_elements(&commitments);
    let batch_commitment = Poseidon2::hash_elements(claim_elements);
    let mut inputs = vec![Felt::from_u32(executions.len().try_into().unwrap())];
    inputs.extend_from_slice(batch_commitment.as_elements());
    let stack_inputs = StackInputs::new(&inputs).unwrap();
    let mut advice =
        AdviceInputs::default().with_map([(batch_commitment, claim_elements.to_vec())]);
    for (proof, claim) in executions {
        let package = RecursiveVerifierInputs::for_request(
            core_lib.vm_recursive_verifier_root(),
            proof,
            claim,
        )
        .expect("failed to prepare an MVM proof for MASM");
        advice.extend(package.into_parts().0);
    }
    assert!(advice.stack().is_empty(), "proof data must be fetched through the advice map");
    (stack_inputs, advice)
}
