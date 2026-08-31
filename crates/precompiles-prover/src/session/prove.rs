//! Proving for the precompile multi-AIR relation.

use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::QuadFelt,
    proof::{HashFunction, StarkProof},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{ProverStatement, Statement};
use miden_lifted_stark::{
    Preprocessed, ProverInstance, StarkConfig, check_constraints,
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
use serde::Serialize;
use serde_wincode::SerdeCompat;

use super::SessionTraces;
use crate::ProveError;

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
                let preprocessed = preprocessed::blake3();
                self.prove_stark_with_config(&config, &preprocessed, hash_fn)
            },
            HashFunction::Rpo256 => {
                let config = rpo_config(params, PRECOMPILE_RELATION_DIGEST);
                let preprocessed = preprocessed::rpo();
                self.prove_stark_with_config(&config, &preprocessed, hash_fn)
            },
            HashFunction::Rpx256 => {
                let config = rpx_config(params, PRECOMPILE_RELATION_DIGEST);
                let preprocessed = preprocessed::rpx();
                self.prove_stark_with_config(&config, &preprocessed, hash_fn)
            },
            HashFunction::Poseidon2 => {
                let config = poseidon2_config(params, PRECOMPILE_RELATION_DIGEST);
                let preprocessed = preprocessed::poseidon2();
                self.prove_stark_with_config(&config, &preprocessed, hash_fn)
            },
            HashFunction::Keccak => {
                let config = keccak_config(params, PRECOMPILE_RELATION_DIGEST);
                let preprocessed = preprocessed::keccak();
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
