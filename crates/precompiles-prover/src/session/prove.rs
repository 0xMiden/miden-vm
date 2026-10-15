//! Proving for the precompile multi-AIR relation.

use alloc::{vec, vec::Vec};

#[cfg(test)]
use miden_air::precompiles::stark_config::test_challenger;
use miden_air::precompiles::{
    ChipletMultiAir, preprocessed,
    proof::encode_proof,
    protocol::relation_digest,
    stark_config::{
        blake3_256_config, eidos_config, keccak_config, observe_protocol_params,
        precompile_pcs_params,
    },
};
use miden_core::{
    Felt,
    field::QuadFelt,
    proof::{HashFunction, StarkProof},
};
use miden_lifted_air::{ProverStatement, Statement};
#[cfg(test)]
use miden_lifted_stark::check_constraints;
use miden_lifted_stark::{
    Preprocessed, ProverInstance, StarkConfig,
    lmcs::Lmcs as LmcsTrait,
    proof::{StarkOutput, StarkProofData},
};
use serde::Serialize;
use serde_wincode::SerdeCompat;

use super::SessionTraces;
use crate::ProveError;

impl SessionTraces {
    #[cfg(test)]
    fn prover_statement(&self) -> ProverStatement<Felt, QuadFelt, ChipletMultiAir> {
        let air = ChipletMultiAir::with_variant(self.variant);
        let inputs = vec![(air.transcript_eval_index(), self.air_inputs())];
        let statement =
            Statement::new(air, inputs, Vec::new()).expect("chiplet statement inputs are valid");
        let mains = self.main_traces.clone();
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
        let variant = self.variant;
        let relation_digest = relation_digest(variant);
        match hash_fn {
            HashFunction::Blake3_256 => {
                let config = blake3_256_config(params, relation_digest);
                let preprocessed = preprocessed::blake3_for(variant);
                self.prove_stark_with_config(&config, &preprocessed, hash_fn)
            },
            HashFunction::Keccak => {
                let config = keccak_config(params, relation_digest);
                let preprocessed = preprocessed::keccak_for(variant);
                self.prove_stark_with_config(&config, &preprocessed, hash_fn)
            },
            HashFunction::Eidos => {
                let config = eidos_config(params, relation_digest);
                let preprocessed = preprocessed::eidos_for(variant);
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
        let variant = self.variant;
        let air = ChipletMultiAir::with_variant(variant);
        let inputs = vec![(air.transcript_eval_index(), self.air_inputs())];
        let statement =
            Statement::new(air, inputs, Vec::new()).expect("chiplet statement inputs are valid");
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
        Ok(StarkProof::new(encode_proof(variant, proof_bytes), hash_fn))
    }
}
