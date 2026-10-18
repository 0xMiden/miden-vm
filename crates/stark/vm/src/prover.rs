//! VM relation proving. Outstanding precompile obligations are authenticated, not discharged.
use miden_air::config;
use miden_core::proof::{HashFunction, VmProof};
use miden_processor::{
    ExecutionError, VmWitness,
    trace::{self, VmTrace, build_trace_with_budget},
};

use crate::engine::prove_stark;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Prover {
    hash_fn: HashFunction,
    max_prover_memory_bytes: u64,
}
impl Prover {
    pub const DEFAULT_MAX_PROVER_MEMORY_BYTES: u64 = trace::DEFAULT_MAX_PROVER_MEMORY_BYTES;
    pub const fn new() -> Self {
        Self {
            hash_fn: HashFunction::Eidos,
            max_prover_memory_bytes: Self::DEFAULT_MAX_PROVER_MEMORY_BYTES,
        }
    }
    #[must_use]
    pub const fn with_hash_fn(mut self, hash_fn: HashFunction) -> Self {
        self.hash_fn = hash_fn;
        self
    }
    #[must_use]
    pub const fn with_max_prover_memory_bytes(mut self, bytes: u64) -> Self {
        self.max_prover_memory_bytes = bytes;
        self
    }
    pub const fn max_prover_memory_bytes(&self) -> u64 {
        self.max_prover_memory_bytes
    }
    pub fn prove_vm_witness(&self, witness: VmWitness) -> Result<VmProof, ProverError> {
        let trace = {
            let _span = tracing::info_span!("build_miden_vm_trace").entered();
            build_trace_with_budget(witness, self.max_prover_memory_bytes)
                .map_err(ProverError::TraceGeneration)?
        };
        self.prove_vm_trace(trace)
    }
    /// Proves a trace already built through the processor's streaming/replay path.
    #[tracing::instrument(name = "miden_vm", skip_all)]
    pub fn prove_vm_trace(&self, trace: VmTrace) -> Result<VmProof, ProverError> {
        let trace_len_summary = trace.trace_len_summary();
        let params = config::pcs_params();
        tracing::event!(
            tracing::Level::INFO,
            "Generated execution traces: core={}, chiplets={}, eidos_compression={}, and8={}, padded={}, \
             estimated_prover_memory_bytes={:?}",
            trace_len_summary.core_rows(),
            trace_len_summary.chiplets_rows(),
            trace_len_summary.eidos_compression_rows(),
            trace_len_summary.byte_pair_lookup_rows(),
            trace_len_summary.padded_trace_len(),
            trace_len_summary.prover_memory_bytes(&params)
        );

        let precompile_root = trace.precompile_root();
        let (public_values, aux_inputs) = trace.public_inputs().to_air_inputs();
        let (core_matrix, chiplets_matrix, eidos_compression_matrix, and8_matrix) =
            trace.into_air_matrices();

        let proof_bytes = match self.hash_fn {
            HashFunction::Blake3_256 => {
                let config = config::blake3_256_config(params, config::RELATION_DIGEST);
                prove_stark(
                    &config,
                    core_matrix,
                    chiplets_matrix,
                    eidos_compression_matrix,
                    and8_matrix,
                    &public_values,
                    &aux_inputs,
                )
            },
            HashFunction::Keccak => {
                let config = config::keccak_config(params, config::RELATION_DIGEST);
                prove_stark(
                    &config,
                    core_matrix,
                    chiplets_matrix,
                    eidos_compression_matrix,
                    and8_matrix,
                    &public_values,
                    &aux_inputs,
                )
            },
            HashFunction::Eidos => {
                let config = config::eidos_config(params, config::RELATION_DIGEST);
                prove_stark(
                    &config,
                    core_matrix,
                    chiplets_matrix,
                    eidos_compression_matrix,
                    and8_matrix,
                    &public_values,
                    &aux_inputs,
                )
            },
            HashFunction::Rpo256 => {
                let config = config::rpo_config(params, config::RELATION_DIGEST);
                prove_stark(
                    &config,
                    core_matrix,
                    chiplets_matrix,
                    eidos_compression_matrix,
                    and8_matrix,
                    &public_values,
                    &aux_inputs,
                )
            },
            HashFunction::Poseidon2 => {
                let config = config::poseidon2_config(params, config::RELATION_DIGEST);
                prove_stark(
                    &config,
                    core_matrix,
                    chiplets_matrix,
                    eidos_compression_matrix,
                    and8_matrix,
                    &public_values,
                    &aux_inputs,
                )
            },
            HashFunction::Rpx256 => {
                let config = config::rpx_config(params, config::RELATION_DIGEST);
                prove_stark(
                    &config,
                    core_matrix,
                    chiplets_matrix,
                    eidos_compression_matrix,
                    and8_matrix,
                    &public_values,
                    &aux_inputs,
                )
            },
        }
        .map_err(ProverError::VmProofGeneration)?;

        let proof = miden_core::proof::StarkProof::new(proof_bytes, self.hash_fn);
        Ok(VmProof { proof, precompile_root })
    }
}
impl Default for Prover {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("failed to materialize VM execution trace: {0}")]
    TraceGeneration(#[source] ExecutionError),
    #[error("failed to prove VM execution trace: {0}")]
    VmProofGeneration(#[source] ExecutionError),
}
