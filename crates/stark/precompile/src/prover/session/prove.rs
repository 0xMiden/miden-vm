//! Proving for the precompile multi-AIR relation.

use alloc::{vec, vec::Vec};

use miden_air::precompile::{ChipletAir, ChipletMultiAir};
#[cfg(test)]
use miden_core::utils::RowMajorMatrix;
use miden_core::{
    Felt,
    field::QuadFelt,
    proof::{HashFunction, StarkProof},
};
#[cfg(test)]
use miden_stark::check_constraints;
use miden_stark::{
    Preprocessed, ProverInstance, StarkConfig,
    air::{ProverStatement, Statement},
    lmcs::Lmcs as LmcsTrait,
    proof::{StarkOutput, StarkProofData},
};
use serde::Serialize;
use serde_wincode::SerdeCompat;

use super::SessionTraces;
#[cfg(test)]
use crate::setup::config::test_challenger;
use crate::{
    prover::ProveError,
    setup::{
        config::{
            PRECOMPILE_RELATION_DIGEST, blake3_256_config, eidos_config, keccak_config,
            observe_protocol_params, precompile_pcs_params,
        },
        preprocessed,
    },
};

impl SessionTraces {
    #[cfg(test)]
    fn prover_statement(&self) -> ProverStatement<Felt, QuadFelt, ChipletMultiAir> {
        let statement = Statement::new(
            ChipletMultiAir::new(),
            vec![(ChipletAir::TRANSCRIPT_EVAL_INDEX, self.air_inputs())],
            Vec::new(),
        )
        .expect("chiplet statement inputs are valid");
        let mains: Vec<RowMajorMatrix<Felt>> = self.mains().into_iter().cloned().collect();
        ProverStatement::new(statement, mains).expect("chiplet trace shapes are valid")
    }

    /// Checks each AIR and the cross-chiplet assertion with the lightweight test configuration.
    #[cfg(test)]
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
            HashFunction::Keccak => {
                let config = keccak_config(params, PRECOMPILE_RELATION_DIGEST);
                let preprocessed = preprocessed::keccak();
                self.prove_stark_with_config(&config, &preprocessed, hash_fn)
            },
            HashFunction::Eidos => {
                let config = eidos_config(params, PRECOMPILE_RELATION_DIGEST);
                let preprocessed = preprocessed::eidos();
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
        let statement = Statement::new(
            ChipletMultiAir::new(),
            vec![(ChipletAir::TRANSCRIPT_EVAL_INDEX, self.air_inputs())],
            Vec::new(),
        )
        .expect("chiplet statement inputs are valid");
        let prover_statement = ProverStatement::new(statement, self.into_mains())
            .expect("chiplet trace shapes are valid");

        let mut challenger = config.challenger();
        observe_protocol_params(config.pcs(), &mut challenger);

        let (output, _statement): (StarkOutput<Felt, QuadFelt, SC>, _) =
            ProverInstance::new(config, prover_statement, Some(preprocessed))?.prove(challenger)?;

        let proof_encoding_config = wincode::config::Configuration::default();
        let proof_bytes = <SerdeCompat<StarkProofData<Felt, QuadFelt, SC>> as wincode::config::Serialize<
            _,
        >>::serialize(&output.proof, proof_encoding_config)?;
        Ok(StarkProof::new(proof_bytes, hash_fn))
    }
}
