use alloc::{vec, vec::Vec};

use miden_air::precompiles::{
    ChipletMultiAir, PvmAirVariant,
    proof::decode_proof,
    protocol::{pins_for, relation_digest},
    security::{self, ProofSecurityParameters},
    stark_config::{
        blake3_256_config, eidos_config, keccak_config, observe_protocol_params,
        precompile_pcs_params,
    },
    transcript::eidos::EidosDigest,
};
use miden_core::{
    Felt,
    deferred::DeferredRoot,
    field::QuadFelt,
    proof::{HashFunction, MAX_STARK_PROOF_BYTES, StarkProof},
};
use miden_lifted_air::Statement;
use miden_lifted_stark::{
    PreprocessedValidationError, StarkConfig, VerifierError, VerifierInstance,
    lmcs::Lmcs as LmcsTrait, proof::StarkProofData,
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
    let (log_max_height, alignment, variant) = verify_stark(proof, EidosDigest::from(public_root))?;

    Ok(security::proof_security_parameters_for(
        &precompile_pcs_params(),
        log_max_height,
        alignment,
        proof.hash_fn(),
        variant,
    ))
}

fn verify_stark(
    proof: &StarkProof,
    public_root: EidosDigest,
) -> Result<(u32, usize, PvmAirVariant), VerifyError> {
    if proof.bytes().len() > MAX_STARK_PROOF_BYTES {
        return Err(VerifyError::ProofTooLarge {
            size: proof.bytes().len(),
            max: MAX_STARK_PROOF_BYTES,
        });
    }

    let (variant, proof_bytes) =
        decode_proof(proof.bytes()).map_err(VerifyError::InvalidVariantHeader)?;
    let digest = relation_digest(variant);
    let pins = pins_for(variant);
    let params = precompile_pcs_params();
    match proof.hash_fn() {
        HashFunction::Blake3_256 => {
            let config = blake3_256_config(params, digest);
            verify_stark_with_config(
                &config,
                pins.blake3_preprocessed_commitment.into(),
                proof_bytes,
                public_root,
                variant,
            )
        },
        HashFunction::Keccak => {
            let config = keccak_config(params, digest);
            verify_stark_with_config(
                &config,
                pins.keccak_preprocessed_commitment.into(),
                proof_bytes,
                public_root,
                variant,
            )
        },
        HashFunction::Eidos => {
            let config = eidos_config(params, digest);
            verify_stark_with_config(
                &config,
                pins.preprocessed_commitment.into(),
                proof_bytes,
                public_root,
                variant,
            )
        },
    }
}

fn verify_stark_with_config<SC>(
    config: &SC,
    preprocessed_commitment: <SC::Lmcs as LmcsTrait>::Commitment,
    proof_bytes: &[u8],
    public_root: EidosDigest,
    variant: PvmAirVariant,
) -> Result<(u32, usize, PvmAirVariant), VerifyError>
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

    let statement = Statement::new(
        ChipletMultiAir::with_variant(variant),
        vec![(
            ChipletMultiAir::with_variant(variant).transcript_eval_index(),
            public_root.as_array().to_vec(),
        )],
        Vec::new(),
    )
    .expect("chiplet statement inputs are valid");

    let mut challenger = config.challenger();
    observe_protocol_params(config.pcs(), &mut challenger);

    VerifierInstance::new(config, &statement, Some(preprocessed_commitment))?
        .verify(&proof, challenger)?;

    let log_max_height = u32::from(proof.log_trace_heights().iter().copied().max().unwrap_or(0));
    Ok((log_max_height, config.lmcs().alignment(), variant))
}

/// Why precompile STARK verification rejected a proof.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The PVM payload names an unsupported variant or encoding version.
    #[error("invalid PVM variant header: {0}")]
    InvalidVariantHeader(&'static str),
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
