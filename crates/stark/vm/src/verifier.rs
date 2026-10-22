//! Native verification of a VM STARK against an explicit execution claim.
use alloc::vec;

use miden_air::vm::{MidenMultiAir, config};
use miden_air_definitions::vm::PublicInputs;
use miden_core::{
    Felt,
    field::QuadFelt,
    program::ExecutionClaim,
    proof::{HashFunction, MAX_STARK_PROOF_BYTES, VmProof},
};
use miden_serde_utils::deserialize_schema_exact;
use miden_stark::{
    PreprocessedValidationError, StarkConfig, VerifierInstance,
    air::Statement,
    config::{blake3_256_config, keccak_config, observe_protocol_params},
    lmcs::Lmcs,
    proof::StarkProofData,
    security::ProofSecurityParameters,
    verifier::VerifierError,
};
use serde::de::DeserializeOwned;
use serde_wincode::{SerdeCompat, wincode};

use crate::{security, setup::config::eidos_config};

type PreprocessedCommitment<SC> = <<SC as StarkConfig<Felt, QuadFelt>>::Lmcs as Lmcs>::Commitment;

/// Rejects oversized VM STARK payloads before any cryptographic work.
pub fn preflight(proof: &VmProof) -> Result<(), VerificationError> {
    let size = proof.proof.bytes().len();
    if size > MAX_STARK_PROOF_BYTES {
        return Err(VerificationError::ProofTooLarge { size, max: MAX_STARK_PROOF_BYTES });
    }
    Ok(())
}

/// Verifies the VM STARK and derives authenticated security parameters.
pub fn verify(
    claim: &ExecutionClaim,
    proof: &VmProof,
) -> Result<ProofSecurityParameters, VerificationError> {
    let pub_inputs = PublicInputs::new(
        claim.to_program_info(),
        *claim.stack_inputs(),
        *claim.stack_outputs(),
        proof.precompile_root,
    );
    let (public_values, aux_inputs) = pub_inputs.to_air_inputs();

    let stark = &proof.proof;
    let proof_bytes = stark.bytes();
    let pcs_params = config::pcs_params();
    let num_kernel_procedures = claim.kernel().proc_hashes().len() as u32;
    match stark.hash_fn() {
        HashFunction::Blake3_256 => {
            let config = blake3_256_config(pcs_params, config::RELATION_DIGEST);
            verify_stark_proof(
                &config,
                &public_values,
                &aux_inputs,
                proof_bytes,
                config::BLAKE3_PREPROCESSED_COMMITMENT.into(),
            )
        },
        HashFunction::Eidos => {
            let config = eidos_config(pcs_params, config::RELATION_DIGEST);
            verify_stark_proof(
                &config,
                &public_values,
                &aux_inputs,
                proof_bytes,
                config::EIDOS_PREPROCESSED_COMMITMENT.into(),
            )
        },
        HashFunction::Keccak => {
            let config = keccak_config(pcs_params, config::RELATION_DIGEST);
            verify_stark_proof(
                &config,
                &public_values,
                &aux_inputs,
                proof_bytes,
                config::KECCAK_PREPROCESSED_COMMITMENT.into(),
            )
        },
    }
    .map(|(log_max_height, alignment)| {
        security::proof_security_parameters(
            &pcs_params,
            log_max_height,
            num_kernel_procedures,
            alignment,
            stark.hash_fn(),
        )
    })
}

/// Verifies a multi-AIR STARK proof for the Miden VM statement, returning the proof's largest
/// AIR log height and the LMCS's column alignment for grading.
///
/// Pre-seeds the challenger with protocol parameters, AIR public values, and statement
/// `aux_inputs` (program hash, final deferred root, and kernel-procedure digests). Then
/// delegates to the lifted multi-AIR verifier.
fn verify_stark_proof<SC>(
    config: &SC,
    public_values: &[Felt],
    aux_inputs: &[Felt],
    proof_bytes: &[u8],
    preprocessed_commitment: PreprocessedCommitment<SC>,
) -> Result<(u32, usize), VerificationError>
where
    SC: StarkConfig<Felt, QuadFelt>,
    PreprocessedCommitment<SC>: DeserializeOwned,
{
    if proof_bytes.len() > MAX_STARK_PROOF_BYTES {
        return Err(VerificationError::ProofTooLarge {
            size: proof_bytes.len(),
            max: MAX_STARK_PROOF_BYTES,
        });
    }

    let proof_encoding_config = wincode::config::Configuration::default()
        .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
    let proof = deserialize_schema_exact::<SerdeCompat<StarkProofData<Felt, QuadFelt, SC>>, _>(
        proof_bytes,
        proof_encoding_config,
    )?;

    let mut challenger = config.challenger();
    observe_protocol_params(config.pcs(), &mut challenger);

    // `air_inputs` are the public values read by the AIRs (stack i/o); `aux_inputs` are the
    // statement inputs read during observation/boundary correction. The lifted verifier absorbs
    // both into Fiat-Shamir internally, and derives the multi-AIR ordering deterministically
    // from the proof's per-AIR trace heights.
    let statement = Statement::<Felt, QuadFelt, _>::new(
        MidenMultiAir::new(),
        vec![(0, public_values.to_vec())],
        aux_inputs.to_vec(),
    )
    .map_err(|error| VerificationError::Verifier(VerifierError::from(error)))?;

    VerifierInstance::new(config, &statement, Some(preprocessed_commitment))?
        .verify(&proof, challenger)?;

    let log_max_height = u32::from(proof.log_trace_heights().iter().copied().max().unwrap_or(0));
    Ok((log_max_height, config.lmcs().alignment()))
}

/// Errors that can occur during low-level STARK proof verification.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("failed to deserialize proof: {0}")]
    Deserialization(#[from] wincode::error::ReadError),
    #[error("STARK proof is too large: {size} bytes exceeds the {max} byte limit")]
    ProofTooLarge { size: usize, max: usize },
    #[error(transparent)]
    Verifier(#[from] VerifierError),
    #[error(transparent)]
    Preprocessed(#[from] PreprocessedValidationError),
}
