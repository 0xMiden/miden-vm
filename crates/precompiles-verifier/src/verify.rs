use alloc::vec::Vec;

use miden_core::{
    Felt,
    deferred::DeferredRoot,
    field::QuadFelt,
    proof::{HashFunction, MAX_STARK_PROOF_BYTES, StarkProof},
};
use miden_lifted_air::Statement;
use miden_lifted_stark::{
    Preprocessed, PreprocessedValidationError, StarkConfig, VerifierError, VerifierInstance,
    lmcs::Lmcs as LmcsTrait, proof::StarkProofData,
};
use miden_precompiles_air::{
    ChipletMultiAir, preprocessed,
    security::{self, ProofSecurityParameters},
    stark_config::{
        PRECOMPILE_RELATION_DIGEST, blake3_256_config, keccak_config, observe_protocol_params,
        poseidon2_config, precompile_pcs_params, rpo_config, rpx_config,
    },
    transcript::poseidon2::P2Digest,
};
use miden_serde_utils::deserialize_schema_exact;
use serde::de::DeserializeOwned;
use serde_wincode::SerdeCompat;

/// Verifies a precompile STARK against an explicit deferred root and returns its authenticated
/// security parameters.
///
/// The returned parameters include the largest chiplet trace height and the DEEP term count
/// implied by the commitment scheme's column alignment. The PCS parameters and commitment
/// collision resistance come from the configuration used to verify the proof.
pub fn verify_deferred(
    proof: &StarkProof,
    public_root: DeferredRoot,
) -> Result<ProofSecurityParameters, VerifyError> {
    let (log_max_height, alignment) = verify_stark(proof, P2Digest::from(public_root))?;

    Ok(security::proof_security_parameters(
        &precompile_pcs_params(),
        log_max_height,
        alignment,
        proof.hash_fn().collision_resistance(),
    ))
}

fn verify_stark(proof: &StarkProof, public_root: P2Digest) -> Result<(u32, usize), VerifyError> {
    if proof.bytes().len() > MAX_STARK_PROOF_BYTES {
        return Err(VerifyError::ProofTooLarge {
            size: proof.bytes().len(),
            max: MAX_STARK_PROOF_BYTES,
        });
    }

    let params = precompile_pcs_params();
    match proof.hash_fn() {
        HashFunction::Blake3_256 => {
            let config = blake3_256_config(params, PRECOMPILE_RELATION_DIGEST);
            let preprocessed = preprocessed::blake3();
            verify_stark_with_config(&config, &preprocessed, proof.bytes(), public_root)
        },
        HashFunction::Rpo256 => {
            let config = rpo_config(params, PRECOMPILE_RELATION_DIGEST);
            let preprocessed = preprocessed::rpo();
            verify_stark_with_config(&config, &preprocessed, proof.bytes(), public_root)
        },
        HashFunction::Rpx256 => {
            let config = rpx_config(params, PRECOMPILE_RELATION_DIGEST);
            let preprocessed = preprocessed::rpx();
            verify_stark_with_config(&config, &preprocessed, proof.bytes(), public_root)
        },
        HashFunction::Poseidon2 => {
            let config = poseidon2_config(params, PRECOMPILE_RELATION_DIGEST);
            let preprocessed = preprocessed::poseidon2();
            verify_stark_with_config(&config, &preprocessed, proof.bytes(), public_root)
        },
        HashFunction::Keccak => {
            let config = keccak_config(params, PRECOMPILE_RELATION_DIGEST);
            let preprocessed = preprocessed::keccak();
            verify_stark_with_config(&config, &preprocessed, proof.bytes(), public_root)
        },
    }
}

fn verify_stark_with_config<SC>(
    config: &SC,
    preprocessed: &Preprocessed<Felt, SC::Lmcs>,
    proof_bytes: &[u8],
    public_root: P2Digest,
) -> Result<(u32, usize), VerifyError>
where
    SC: StarkConfig<Felt, QuadFelt>,
    <SC::Lmcs as LmcsTrait>::Commitment: DeserializeOwned,
{
    let proof_encoding_config = wincode::config::Configuration::default()
        .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
    let proof = deserialize_schema_exact::<SerdeCompat<StarkProofData<Felt, QuadFelt, SC>>, _>(
        proof_bytes,
        proof_encoding_config,
    )?;

    let statement =
        Statement::new(ChipletMultiAir::new(), public_root.as_array().to_vec(), Vec::new())
            .expect("chiplet statement inputs are valid");

    let mut challenger = config.challenger();
    observe_protocol_params(config.pcs(), &mut challenger);

    VerifierInstance::new(config, &statement, Some(preprocessed.commitment()))?
        .verify(&proof, challenger)?;

    let log_max_height = u32::from(proof.log_trace_heights().iter().copied().max().unwrap_or(0));
    Ok((log_max_height, config.lmcs().alignment()))
}

/// Why precompile STARK verification rejected a proof.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The serialized STARK proof bytes could not be decoded for the selected hash function.
    #[error("failed to deserialize STARK proof: {0}")]
    Deserialization(#[from] wincode::error::ReadError),
    /// The serialized STARK proof exceeds the verifier's byte size limit.
    #[error("STARK proof is too large: {size} bytes exceeds the {max} byte limit")]
    ProofTooLarge { size: usize, max: usize },
    /// The preprocessed commitment did not match the declared AIR columns and configuration.
    #[error(transparent)]
    Preprocessed(#[from] PreprocessedValidationError),
    /// The verifier rejected the proof.
    #[error(transparent)]
    Verifier(#[from] VerifierError),
}
