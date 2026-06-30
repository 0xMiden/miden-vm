#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{string::ToString, vec, vec::Vec};

use ::serde::Serialize;
use miden_air::{MidenMultiAir, ProverStatement, Statement};
use miden_core::{
    Felt,
    field::QuadFelt,
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable,
        DeserializationError as SerdeDeserializationError, Serializable, SliceReader,
    },
    utils::RowMajorMatrix,
};
use miden_crypto::stark::{
    ProverInstance, StarkConfig,
    lmcs::Lmcs,
    proof::{StarkOutput, StarkProofData},
};
use serde_wincode::{SerdeCompat, wincode};
use tracing::instrument;

mod prover;

#[cfg(all(test, feature = "std"))]
mod overflow_pointer_soundness_repro;

// EXPORTS
// ================================================================================================
pub use miden_air::{DeserializationError, MidenAir, PublicInputs, config};
pub use miden_core::proof::{ExecutionProof, HashFunction, PrecompileProof, StarkProof, VmProof};
pub use miden_processor::{
    ExecutionClaim, ExecutionError, ExecutionOptions, ExecutionOutput, ExecutionWitness,
    FutureMaybeSend, Host, InputError, PrecompileWitness, ProgramInfo, StackInputs, StackOutputs,
    SyncHost, VmWitness, Word, advice::AdviceInputs, crypto, field, serde, utils,
};
pub use prover::{Prover, ProverError, prove_sync};

// TRACE PROVING INPUTS
// ================================================================================================

const TRACE_PROVING_INPUTS_ALLOCATION_BUDGET_MULTIPLIER: usize = 4;

/// Inputs required to prove from pre-executed trace data.
///
/// Its binary form is a VM-owned trusted remote proving input containing trace replay data and
/// proof-generation options. Deserialization checks malformed structure and bounded allocation, but
/// sparse MAST node and digest maps are accepted as replay data and are not checked against a
/// source [`miden_core::mast::MastForest`] commitment.
///
/// See <https://github.com/0xMiden/miden-vm/issues/3303> for the planned untrusted reader.
#[derive(Debug)]
pub struct TraceProvingInputs {
    witness: ExecutionWitness,
    hash_fn: HashFunction,
}

impl TraceProvingInputs {
    /// Creates a new bundle of a post-execution witness and proof-generation options.
    pub fn new(witness: ExecutionWitness, hash_fn: HashFunction) -> Self {
        Self { witness, hash_fn }
    }

    /// Consumes this bundle and returns its witness and proof-generation options.
    pub fn into_parts(self) -> (ExecutionWitness, HashFunction) {
        (self.witness, self.hash_fn)
    }

    /// Deserializes trusted remote proving inputs using the supplied byte budget.
    ///
    /// The budget bounds parsing. It does not validate sparse MAST replay data from untrusted
    /// senders.
    /// This function reads one standalone payload and rejects trailing bytes. Readers for a larger
    /// wrapper object should call [`TraceProvingInputs::read_from`] and let the wrapper own the
    /// trailing-byte check.
    ///
    /// The public budget is a byte budget. Length-prefixed replay collections also need a bounded
    /// allocation budget, so the reader derives a small preallocation allowance from the actual
    /// payload length and caps it by the caller's byte budget.
    /// See <https://github.com/0xMiden/miden-vm/issues/3303>.
    pub fn read_from_bytes_with_budget(
        bytes: &[u8],
        budget: usize,
    ) -> Result<Self, SerdeDeserializationError> {
        if budget < bytes.len() {
            return Err(SerdeDeserializationError::InvalidValue(
                "TraceProvingInputs byte budget is smaller than payload length".into(),
            ));
        }
        let allocation_budget = budget
            .min(bytes.len().saturating_mul(TRACE_PROVING_INPUTS_ALLOCATION_BUDGET_MULTIPLIER));
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), allocation_budget);
        let inputs = Self::read_from(&mut reader)?;
        if reader.has_more_bytes() {
            return Err(SerdeDeserializationError::InvalidValue(
                "TraceProvingInputs payload has trailing bytes".into(),
            ));
        }
        Ok(inputs)
    }
}

impl Serializable for TraceProvingInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.witness.write_into(target);
        self.hash_fn.write_into(target);
    }
}

impl Deserializable for TraceProvingInputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, SerdeDeserializationError> {
        Ok(Self {
            witness: ExecutionWitness::read_from(source)?,
            hash_fn: HashFunction::read_from(source)?,
        })
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, SerdeDeserializationError> {
        TraceProvingInputs::read_from_bytes_with_budget(
            bytes,
            bytes.len().saturating_mul(TRACE_PROVING_INPUTS_ALLOCATION_BUDGET_MULTIPLIER),
        )
    }

    fn read_from_bytes_with_budget(
        bytes: &[u8],
        budget: usize,
    ) -> Result<Self, SerdeDeserializationError> {
        TraceProvingInputs::read_from_bytes_with_budget(bytes, budget)
    }
}

/// Builds a proof from pre-executed trace data synchronously, producing final deferred proof
/// material.
#[instrument("prove_from_trace_sync", skip_all)]
pub fn prove_from_trace_sync(
    inputs: TraceProvingInputs,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    let (witness, hash_fn) = inputs.into_parts();
    let stack_outputs = *witness.claim().stack_outputs();
    let prover = Prover::new().with_hash_fn(hash_fn);
    let proof = prover.prove_full(witness).map_err(ProverError::into_execution_error)?;
    Ok((stack_outputs, proof))
}

/// Builds a proof from pre-executed trace data synchronously, preserving wire-backed deferred
/// proof material.
///
/// Use this when precompile claims should be proved later by a delegated or batching prover.
/// [`prove_from_trace_sync`] produces final deferred proof material instead.
#[instrument("prove_partial_from_trace_sync", skip_all)]
pub fn prove_partial_from_trace_sync(
    inputs: TraceProvingInputs,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    let (witness, hash_fn) = inputs.into_parts();
    let stack_outputs = *witness.claim().stack_outputs();
    let prover = Prover::new().with_hash_fn(hash_fn);
    let proof = prover.prove(witness).map_err(ProverError::into_execution_error)?;
    Ok((stack_outputs, proof))
}

// STARK PROOF GENERATION
// ================================================================================================

/// Generates a multi-AIR STARK proof for the Miden trace set and public values.
///
/// Pre-seeds the challenger with the protocol parameters, the AIR public values, and the
/// statement `aux_inputs` (program hash, final deferred root, and the concatenated kernel-procedure
/// digests). Then delegates to the lifted multi-AIR prover.
#[instrument("prove_stark", skip_all)]
fn prove_stark<SC>(
    config: &SC,
    core_trace: RowMajorMatrix<Felt>,
    chiplets_trace: RowMajorMatrix<Felt>,
    poseidon2_trace: RowMajorMatrix<Felt>,
    public_values: &[Felt],
    aux_inputs: &[Felt],
) -> Result<Vec<u8>, ExecutionError>
where
    SC: StarkConfig<Felt, QuadFelt>,
    <SC::Lmcs as Lmcs>::Commitment: Serialize,
{
    let mut challenger = config.challenger();
    config::observe_protocol_params(config.pcs(), &mut challenger);

    // `air_inputs` are the public values read by the AIRs (stack i/o); `aux_inputs` are the
    // statement inputs read during observation/boundary correction.
    let statement =
        Statement::new(MidenMultiAir::new(), public_values.to_vec(), aux_inputs.to_vec())
            .map_err(|e| ExecutionError::ProvingError(e.to_string()))?;
    let prover_statement =
        ProverStatement::new(statement, vec![core_trace, chiplets_trace, poseidon2_trace])
            .map_err(|e| ExecutionError::ProvingError(e.to_string()))?;

    let output: StarkOutput<Felt, QuadFelt, SC> =
        ProverInstance::new(config, &prover_statement, None)
            .map_err(|e| ExecutionError::ProvingError(e.to_string()))?
            .prove(challenger)
            .map_err(|e| ExecutionError::ProvingError(e.to_string()))?;

    let proof_encoding_config = wincode::config::Configuration::default();
    let proof_bytes =
        <SerdeCompat<StarkProofData<Felt, QuadFelt, SC>> as wincode::config::Serialize<_>>::serialize(
            &output.proof,
            proof_encoding_config,
        )
        .map_err(|e| ExecutionError::ProvingError(e.to_string()))?;
    Ok(proof_bytes)
}
