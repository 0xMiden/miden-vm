//! Proving for the precompile multi-AIR relation.

use alloc::{vec, vec::Vec};

use miden_core::{
    Felt,
    field::QuadFelt,
    proof::{HashFunction, StarkProof},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{ProverStatement, Statement};
use miden_lifted_stark::{
    Preprocessed, PreprocessedValidationError, ProverInstance, StarkConfig, VerifierError,
    VerifierInstance, check_constraints,
    lmcs::Lmcs as LmcsTrait,
    proof::{StarkOutput, StarkProofData},
};
use miden_precompiles_air::{
    ChipletMultiAir, preprocessed,
    stark_config::{
        PRECOMPILE_RELATION_DIGEST, blake3_256_config, keccak_config, observe_protocol_params,
        poseidon2_config, precompile_pcs_params, rpo_config, rpx_config, test_challenger,
    },
};
use miden_serde_utils::deserialize_schema_exact;
use serde::{Serialize, de::DeserializeOwned};
use serde_wincode::SerdeCompat;

use super::SessionTraces;
use crate::{MAX_STARK_PROOF_BYTES, ProveError, transcript::poseidon2::P2Digest};

impl SessionTraces {
    fn prover_statement(&self) -> ProverStatement<Felt, QuadFelt, ChipletMultiAir> {
        let statement = Statement::new(ChipletMultiAir::new(), self.air_inputs(), Vec::new())
            .expect("chiplet statement inputs are valid");
        let mains: Vec<RowMajorMatrix<Felt>> = self.mains().into_iter().cloned().collect();
        ProverStatement::new(statement, mains).expect("chiplet trace shapes are valid")
    }

    /// Checks each AIR and the cross chiplet assertion with the fast test configuration.
    pub fn check(&self) {
        check_constraints(&self.prover_statement(), test_challenger());
    }

    /// Proves the whole chiplet stack with the requested hash function.
    #[tracing::instrument("prove_stark", skip_all)]
    pub(crate) fn prove_stark(self, hash_fn: HashFunction) -> Result<StarkProof, ProveError> {
        let params = precompile_pcs_params();
        match hash_fn {
            HashFunction::Blake3_256 => {
                let config = blake3_256_config(params, PRECOMPILE_RELATION_DIGEST);
                let preprocessed = preprocessed::blake3(&config);
                self.prove_stark_with_config(&config, &preprocessed, hash_fn)
            },
            HashFunction::Rpo256 => {
                let config = rpo_config(params, PRECOMPILE_RELATION_DIGEST);
                let preprocessed = preprocessed::rpo(&config);
                self.prove_stark_with_config(&config, &preprocessed, hash_fn)
            },
            HashFunction::Rpx256 => {
                let config = rpx_config(params, PRECOMPILE_RELATION_DIGEST);
                let preprocessed = preprocessed::rpx(&config);
                self.prove_stark_with_config(&config, &preprocessed, hash_fn)
            },
            HashFunction::Poseidon2 => {
                let config = poseidon2_config(params, PRECOMPILE_RELATION_DIGEST);
                let preprocessed = preprocessed::poseidon2(&config);
                self.prove_stark_with_config(&config, &preprocessed, hash_fn)
            },
            HashFunction::Keccak => {
                let config = keccak_config(params, PRECOMPILE_RELATION_DIGEST);
                let preprocessed = preprocessed::keccak(&config);
                self.prove_stark_with_config(&config, &preprocessed, hash_fn)
            },
        }
    }

    fn prove_stark_with_config<SC>(
        self,
        config: &SC,
        preprocessed: &Preprocessed<Felt, SC::Lmcs>,
        hash_fn: HashFunction,
    ) -> Result<StarkProof, ProveError>
    where
        SC: StarkConfig<Felt, QuadFelt>,
        <SC::Lmcs as LmcsTrait>::Commitment: Serialize,
    {
        let statement = Statement::new(ChipletMultiAir::new(), self.air_inputs(), Vec::new())
            .expect("chiplet statement inputs are valid");
        let prover_statement = ProverStatement::new(statement, self.into_mains())
            .expect("chiplet trace shapes are valid");

        let mut challenger = config.challenger();
        observe_protocol_params(config.pcs(), &mut challenger);

        let output: StarkOutput<Felt, QuadFelt, SC> =
            ProverInstance::new(config, &prover_statement, Some(preprocessed))?
                .prove(challenger)?;

        let proof_encoding_config = wincode::config::Configuration::default();
        let proof_bytes = <SerdeCompat<StarkProofData<Felt, QuadFelt, SC>> as wincode::config::Serialize<
            _,
        >>::serialize(&output.proof, proof_encoding_config)?;
        Ok(StarkProof::new(proof_bytes, hash_fn))
    }
}

/// Verify a core serialized STARK proof envelope against a public root.
///
/// Returns the proof's largest chiplet log trace height and its LMCS's column alignment iff the
/// verifier accepts, including the `Σ σ = 0` cross-chiplet identity via `eval_external`. Both feed
/// the security estimate: the lookup and out-of-domain rounds degrade with the height, and the
/// DEEP round's term count depends on the alignment.
pub(crate) fn verify_stark(
    proof: &StarkProof,
    public_root: P2Digest,
) -> Result<(u32, usize), VerifyError> {
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
            let preprocessed = preprocessed::blake3(&config);
            verify_stark_with_config(&config, &preprocessed, proof.bytes(), public_root)
        },
        HashFunction::Rpo256 => {
            let config = rpo_config(params, PRECOMPILE_RELATION_DIGEST);
            let preprocessed = preprocessed::rpo(&config);
            verify_stark_with_config(&config, &preprocessed, proof.bytes(), public_root)
        },
        HashFunction::Rpx256 => {
            let config = rpx_config(params, PRECOMPILE_RELATION_DIGEST);
            let preprocessed = preprocessed::rpx(&config);
            verify_stark_with_config(&config, &preprocessed, proof.bytes(), public_root)
        },
        HashFunction::Poseidon2 => {
            let config = poseidon2_config(params, PRECOMPILE_RELATION_DIGEST);
            let preprocessed = preprocessed::poseidon2(&config);
            verify_stark_with_config(&config, &preprocessed, proof.bytes(), public_root)
        },
        HashFunction::Keccak => {
            let config = keccak_config(params, PRECOMPILE_RELATION_DIGEST);
            let preprocessed = preprocessed::keccak(&config);
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
    /// The chiplet stack declares preprocessed columns, but no preprocessed bundle was produced.
    #[error("chiplet stack declares preprocessed columns, but no preprocessed bundle was built")]
    MissingPreprocessed,
    /// The serialized STARK proof bytes could not be decoded.
    #[error("failed to deserialize STARK proof: {0}")]
    Deserialization(#[from] wincode::error::ReadError),
    /// The serialized STARK proof exceeds the verifier's byte limit.
    #[error("STARK proof is too large: {size} bytes exceeds the {max} byte limit")]
    ProofTooLarge { size: usize, max: usize },
    /// The preprocessed commitment did not match the AIR columns and configuration.
    #[error(transparent)]
    Preprocessed(#[from] PreprocessedValidationError),
    /// The verifier rejected the proof.
    #[error(transparent)]
    Verifier(#[from] VerifierError),
}
