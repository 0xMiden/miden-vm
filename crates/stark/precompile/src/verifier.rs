//! Native verification against an explicit precompile root.

use alloc::{vec, vec::Vec};

use miden_air::precompile::{ChipletAir, ChipletMultiAir, transcript::eidos::EidosDigest};
use miden_core::{
    Felt,
    deferred::DeferredRoot,
    field::QuadFelt,
    proof::{HashFunction, MAX_STARK_PROOF_BYTES, StarkProof},
};
use miden_serde_utils::deserialize_schema_exact;
use miden_stark::{
    Preprocessed, PreprocessedValidationError, StarkConfig, VerifierError, VerifierInstance,
    air::Statement, lmcs::Lmcs as LmcsTrait, proof::StarkProofData,
};
use serde::de::DeserializeOwned;
use serde_wincode::SerdeCompat;

use crate::setup::{
    config::{
        PRECOMPILE_RELATION_DIGEST, blake3_256_config, eidos_config, keccak_config,
        observe_protocol_params, precompile_pcs_params,
    },
    preprocessed,
    security::{self, ProofSecurityParameters},
};

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
    let (log_max_height, alignment) = verify_stark(proof, EidosDigest::from(public_root))?;

    Ok(security::proof_security_parameters(
        &precompile_pcs_params(),
        log_max_height,
        alignment,
        proof.hash_fn(),
    ))
}

fn verify_stark(proof: &StarkProof, public_root: EidosDigest) -> Result<(u32, usize), VerifyError> {
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
        HashFunction::Keccak => {
            let config = keccak_config(params, PRECOMPILE_RELATION_DIGEST);
            let preprocessed = preprocessed::keccak();
            verify_stark_with_config(&config, &preprocessed, proof.bytes(), public_root)
        },
        HashFunction::Eidos => {
            let config = eidos_config(params, PRECOMPILE_RELATION_DIGEST);
            let preprocessed = preprocessed::eidos();
            verify_stark_with_config(&config, &preprocessed, proof.bytes(), public_root)
        },
    }
}

fn verify_stark_with_config<SC>(
    config: &SC,
    preprocessed: &Preprocessed<Felt, SC::Lmcs>,
    proof_bytes: &[u8],
    public_root: EidosDigest,
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

    let statement = Statement::new(
        ChipletMultiAir::new(),
        vec![(ChipletAir::TRANSCRIPT_EVAL_INDEX, public_root.as_array().to_vec())],
        Vec::new(),
    )
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

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use miden_core::{Felt, Word, deferred::TRUE_DIGEST, proof::MAX_STARK_PROOF_BYTES};

    use super::*;

    fn fixture_root(text: &str) -> Word {
        let root: [Felt; 4] = text
            .split_ascii_whitespace()
            .map(|value| Felt::new_unchecked(value.parse().expect("root element must be a u64")))
            .collect::<Vec<_>>()
            .try_into()
            .expect("fixture root must contain four elements");
        Word::new(root)
    }

    #[test]
    fn rejects_pinned_old_eidos_proof() {
        let root = fixture_root(include_str!("../tests/fixtures/pvm_eidos_v0_31.root"));
        let proof = StarkProof::new(
            include_bytes!("../tests/fixtures/pvm_eidos_v0_31.bin").to_vec(),
            HashFunction::Eidos,
        );

        assert!(verify_deferred(&proof, root).is_err());
        assert!(verify_deferred(&proof, TRUE_DIGEST).is_err());
    }

    #[test]
    fn rejects_pinned_v0_35_eidos_proof() {
        let root = fixture_root(include_str!("../tests/fixtures/pvm_eidos_v0_35.root"));
        let proof = StarkProof::new(
            include_bytes!("../tests/fixtures/pvm_eidos_v0_35.bin").to_vec(),
            HashFunction::Eidos,
        );

        assert!(matches!(verify_deferred(&proof, root), Err(VerifyError::Verifier(_))));
    }

    #[test]
    fn verifies_pinned_current_eidos_proof() {
        let root = fixture_root(include_str!("../tests/fixtures/pvm_eidos_v1_0.root"));
        let proof = StarkProof::new(
            include_bytes!("../tests/fixtures/pvm_eidos_v1_0.bin").to_vec(),
            HashFunction::Eidos,
        );

        verify_deferred(&proof, root).expect("current Eidos proof must verify");
        assert!(verify_deferred(&proof, TRUE_DIGEST).is_err());
    }

    #[test]
    fn verify_deferred_enforces_fixed_stark_proof_size_ceiling() {
        let proof = StarkProof::new(vec![0; MAX_STARK_PROOF_BYTES + 1], HashFunction::Blake3_256);

        assert!(matches!(
            verify_deferred(&proof, TRUE_DIGEST),
            Err(VerifyError::ProofTooLarge { size: _, max: MAX_STARK_PROOF_BYTES })
        ));
    }
}
