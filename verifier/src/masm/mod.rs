//! Executes the recursive STARK verifiers and interprets their authenticated outputs.

use alloc::boxed::Box;

use miden_air::{precompiles::policy::precompile_pcs_params, vm::config::pcs_params};
use miden_core::proof::{CURRENT_PVM_VERIFIER_ROOT, CURRENT_VM_VERIFIER_ROOT};
use miden_precompiles_stark::recursive::{
    PvmRecursiveVerifierInputs, PvmRecursiveVerifierInputsError,
};
use miden_processor::ExecutionError;
use miden_stark::{
    pcs::PcsParams, recursive::advice::security_parameter_words, security::COMMITMENT_ALIGNMENT,
};
use miden_vm_stark::recursive::{RecursiveVerifierInputs, RecursiveVerifierInputsError};

use super::{
    ExecutionClaim, ExecutionProof, HashFunction, PrecompileProof, ProofSecurityParameters,
    StackOutputs,
};

mod runner;

pub(super) fn verify_vm(
    claim: &ExecutionClaim,
    proof: &ExecutionProof,
) -> Result<ProofSecurityParameters, MasmVerificationError> {
    let package = RecursiveVerifierInputs::for_request(CURRENT_VM_VERIFIER_ROOT, proof, claim)?;
    let (advice, claim_commitment) = package.into_parts();
    let output = runner::run(runner::Relation::Vm, claim_commitment, advice)
        .map_err(|error| MasmVerificationError::VmExecution(Box::new(error)))?;

    // The MVM returns [security_descriptor(12), D(4)]. Bind the envelope's obligation to D
    // before the shared verifier uses it to evaluate a witness or verify an aggregate proof.
    if output.get_word(12) != Some(proof.vm().precompile_root) {
        return Err(MasmVerificationError::DeferredRootMismatch);
    }
    let params = pcs_params();
    Ok(miden_vm_stark::security::proof_security_parameters(
        &params,
        log_max_height(&output, &params)?,
        claim.kernel().proc_hashes().len() as u32,
        COMMITMENT_ALIGNMENT,
        HashFunction::Eidos,
    ))
}

pub(super) fn verify_precompile(
    proof: &PrecompileProof,
) -> Result<ProofSecurityParameters, MasmVerificationError> {
    // The caller checked expected-root membership. The package commits to the ordered aggregate
    // of those same roots, including any additional executions covered by this proof.
    let package = PvmRecursiveVerifierInputs::for_request(CURRENT_PVM_VERIFIER_ROOT, proof)?;
    let (advice, aggregate_root) = package.into_parts();
    let output = runner::run(runner::Relation::Pvm, aggregate_root, advice)
        .map_err(|error| MasmVerificationError::PrecompileExecution(Box::new(error)))?;

    let params = precompile_pcs_params();
    Ok(miden_precompiles_stark::setup::security::proof_security_parameters(
        &params,
        log_max_height(&output, &params)?,
        COMMITMENT_ALIGNMENT,
        HashFunction::Eidos,
    ))
}

/// Both procedures return the maximum AIR log height followed by the four transcript-bound PCS
/// parameters at stack offsets 7..12. The relation and the authenticated claim determine the
/// remaining security geometry, including the quotient chunk count omitted from the descriptor.
fn log_max_height(output: &StackOutputs, params: &PcsParams) -> Result<u32, MasmVerificationError> {
    if output[8..12] != security_parameter_words(params) {
        return Err(MasmVerificationError::InvalidSecurityDescriptor);
    }
    u32::try_from(output[7].as_canonical_u64())
        .map_err(|_| MasmVerificationError::InvalidSecurityDescriptor)
}

/// Failures in preparing or executing a recursive MASM verifier.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MasmVerificationError {
    #[error("could not prepare VM verifier advice: {0}")]
    VmAdvice(#[from] RecursiveVerifierInputsError),
    #[error("could not prepare precompile verifier advice: {0}")]
    PrecompileAdvice(#[from] PvmRecursiveVerifierInputsError),
    #[error("VM verifier execution failed: {0}")]
    VmExecution(#[source] Box<ExecutionError>),
    #[error("precompile verifier execution failed: {0}")]
    PrecompileExecution(#[source] Box<ExecutionError>),
    #[error("VM verifier returned a different deferred root from the execution proof")]
    DeferredRootMismatch,
    #[error("recursive verifier returned an invalid security descriptor")]
    InvalidSecurityDescriptor,
}
