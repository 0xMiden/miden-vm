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
use miden_processor::{
    FastProcessor, Program,
    trace::{ExecutionTrace, build_trace},
};
use serde_wincode::SerdeCompat;
use tracing::instrument;

mod proving_options;

// EXPORTS
// ================================================================================================
pub use miden_air::{DeserializationError, MidenAir, PublicInputs, config};
pub use miden_core::proof::{DeferredProof, ExecutionProof, HashFunction, StarkProof};
pub use miden_processor::{
    ExecutionError, ExecutionOptions, ExecutionOutput, FutureMaybeSend, Host, InputError,
    ProgramInfo, StackInputs, StackOutputs, SyncHost, TraceBuildInputs, TraceGenerationContext,
    Word, advice::AdviceInputs, crypto, field, serde, utils,
};
pub use proving_options::ProvingOptions;

const TRACE_PROVING_INPUTS_ALLOCATION_BUDGET_MULTIPLIER: usize = 4;

/// Inputs required to prove from pre-executed trace data.
///
/// Its binary form is a VM-owned trusted remote proving input containing trace replay data and
/// proof-generation options. Deserialization checks malformed structure and bounded allocation, but
/// sparse MAST hashes are accepted as replay data.
///
/// See <https://github.com/0xMiden/miden-vm/issues/3303> for the planned untrusted reader.
#[derive(Debug)]
pub struct TraceProvingInputs {
    trace_inputs: TraceBuildInputs,
    options: ProvingOptions,
}

impl TraceProvingInputs {
    /// Creates a new bundle of post-execution trace inputs and proof-generation options.
    pub fn new(trace_inputs: TraceBuildInputs, options: ProvingOptions) -> Self {
        Self { trace_inputs, options }
    }

    /// Consumes this bundle and returns its trace inputs and proof-generation options.
    pub fn into_parts(self) -> (TraceBuildInputs, ProvingOptions) {
        (self.trace_inputs, self.options)
    }

    /// Deserializes trusted remote proving inputs using the supplied byte budget.
    ///
    /// The budget bounds parsing. It does not validate sparse MAST hashes from untrusted senders.
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
        self.trace_inputs.write_into(target);
        self.options.write_into(target);
    }
}

impl Deserializable for TraceProvingInputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, SerdeDeserializationError> {
        Ok(Self {
            trace_inputs: TraceBuildInputs::read_from(source)?,
            options: ProvingOptions::read_from(source)?,
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

// PROVER
// ================================================================================================

/// Executes and proves the specified `program` and returns the result together with a final
/// STARK-based proof of the program's execution.
///
/// - `stack_inputs` specifies the initial state of the stack for the VM.
/// - `advice_inputs` provides the initial nondeterministic inputs for the VM.
/// - `host` specifies the host environment which contain non-deterministic (secret) inputs for the
///   prover.
/// - `execution_options` defines VM execution parameters such as cycle limits and fragmentation.
/// - `proving_options` defines parameters for STARK proof generation.
///
/// # Errors
/// Returns an error if program execution or STARK proof generation fails for any reason.
#[instrument("prove_program", skip_all)]
pub async fn prove(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl Host,
    execution_options: ExecutionOptions,
    proving_options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    // execute the program to create an execution trace using FastProcessor
    let processor = FastProcessor::new_with_options(stack_inputs, advice_inputs, execution_options)
        .map_err(ExecutionError::advice_error_no_context)?;

    let trace_inputs = {
        let _span = tracing::info_span!("execute_miden_vm").entered();
        processor.execute_trace_inputs(program, host).await?
    };
    prove_from_trace_sync(TraceProvingInputs::new(trace_inputs, proving_options))
}

/// Executes and proves the specified `program`, preserving wire-backed deferred proof material.
///
/// Use this when precompile claims should be proved later by a delegated or batching prover. The
/// default [`prove`] API produces final deferred proof material instead.
#[instrument("prove_program_partial", skip_all)]
pub async fn prove_partial(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl Host,
    execution_options: ExecutionOptions,
    proving_options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    let processor = FastProcessor::new_with_options(stack_inputs, advice_inputs, execution_options)
        .map_err(ExecutionError::advice_error_no_context)?;

    let trace_inputs = {
        let _span = tracing::info_span!("execute_miden_vm").entered();
        processor.execute_trace_inputs(program, host).await?
    };
    prove_partial_from_trace_sync(TraceProvingInputs::new(trace_inputs, proving_options))
}

/// Synchronous wrapper for [`prove()`].
#[instrument("prove_program_sync", skip_all)]
pub fn prove_sync(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl SyncHost,
    execution_options: ExecutionOptions,
    proving_options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    let processor = FastProcessor::new_with_options(stack_inputs, advice_inputs, execution_options)
        .map_err(ExecutionError::advice_error_no_context)?;

    let trace_inputs = {
        let _span = tracing::info_span!("execute_miden_vm").entered();
        processor.execute_trace_inputs_sync(program, host)?
    };
    prove_from_trace_sync(TraceProvingInputs::new(trace_inputs, proving_options))
}

/// Synchronous wrapper for [`prove_partial()`].
#[instrument("prove_program_partial_sync", skip_all)]
pub fn prove_partial_sync(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl SyncHost,
    execution_options: ExecutionOptions,
    proving_options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    let processor = FastProcessor::new_with_options(stack_inputs, advice_inputs, execution_options)
        .map_err(ExecutionError::advice_error_no_context)?;

    let trace_inputs = {
        let _span = tracing::info_span!("execute_miden_vm").entered();
        processor.execute_trace_inputs_sync(program, host)?
    };
    prove_partial_from_trace_sync(TraceProvingInputs::new(trace_inputs, proving_options))
}

/// Builds an execution trace from pre-executed trace inputs and proves it synchronously.
///
/// This is useful when program execution has already happened elsewhere and only trace building
/// plus proof generation remain. The execution settings are already reflected in the supplied
/// `TraceBuildInputs`, so only proof-generation options remain in this API.
#[instrument("prove_trace_sync", skip_all)]
pub fn prove_from_trace_sync(
    inputs: TraceProvingInputs,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    let (trace_inputs, options) = inputs.into_parts();
    let trace = {
        let _span = tracing::info_span!("build_miden_vm_trace").entered();
        build_trace(trace_inputs)?
    };
    prove_final_execution_trace(trace, options)
}

/// Builds an execution trace from pre-executed trace inputs and proves it synchronously, preserving
/// wire-backed deferred proof material.
///
/// This is the explicit partial-proof counterpart to [`prove_from_trace_sync`].
#[instrument("prove_partial_trace_sync", skip_all)]
pub fn prove_partial_from_trace_sync(
    inputs: TraceProvingInputs,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    let (trace_inputs, options) = inputs.into_parts();
    let trace = {
        let _span = tracing::info_span!("build_miden_vm_trace").entered();
        build_trace(trace_inputs)?
    };
    prove_partial_execution_trace(trace, options)
}

fn prove_final_execution_trace(
    trace: ExecutionTrace,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    let hash_fn = options.hash_fn();
    let deferred_proof = {
        let _span = tracing::info_span!("precompile_vm").entered();
        miden_precompiles_prover::prove_deferred_state(trace.deferred_state(), hash_fn)
            .map_err(|err| ExecutionError::ProvingError(err.to_string()))?
    };

    prove_miden_vm_execution_trace(trace, options, deferred_proof)
}

fn prove_partial_execution_trace(
    trace: ExecutionTrace,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    let deferred_proof = {
        let _precompile_vm_span = tracing::info_span!("precompile_vm").entered();
        let _serialize_witness_span = tracing::info_span!("serialize_witness").entered();
        let wire = trace
            .deferred_state()
            .to_wire()
            .map_err(|err| ExecutionError::ProvingError(err.to_string()))?;
        DeferredProof::Wire(wire)
    };

    prove_miden_vm_execution_trace(trace, options, deferred_proof)
}

#[instrument("miden_vm", skip_all)]
fn prove_miden_vm_execution_trace(
    trace: ExecutionTrace,
    options: ProvingOptions,
    deferred_proof: DeferredProof,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    let trace_len_summary = trace.trace_len_summary();
    tracing::event!(
        tracing::Level::INFO,
        "Generated execution traces: core={}, range={}, chiplets={}, poseidon2={}, padded={}",
        trace_len_summary.core_trace_len(),
        trace_len_summary.range_trace_len(),
        trace_len_summary.chiplets_trace_len().trace_len(),
        trace_len_summary.poseidon2_permutation_trace_len(),
        trace_len_summary.padded_trace_len()
    );

    let stack_outputs = *trace.stack_outputs();
    let hash_fn = options.hash_fn();

    // Extract public inputs before consuming the trace for the per-AIR matrices.
    let (public_values, aux_inputs) = trace.public_inputs().to_air_inputs();

    let (core_matrix, chiplets_matrix, poseidon2_matrix) = trace.into_air_matrices();

    let params = config::pcs_params();
    let proof_bytes = match hash_fn {
        HashFunction::Blake3_256 => {
            let config = config::blake3_256_config(params, config::RELATION_DIGEST);
            prove_stark(
                &config,
                core_matrix,
                chiplets_matrix,
                poseidon2_matrix,
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
                poseidon2_matrix,
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
                poseidon2_matrix,
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
                poseidon2_matrix,
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
                poseidon2_matrix,
                &public_values,
                &aux_inputs,
            )
        },
    }?;

    let proof = ExecutionProof::from_parts(proof_bytes, hash_fn, deferred_proof);

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
pub fn prove_stark<SC>(
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
    config::observe_protocol_params(&mut challenger);

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
