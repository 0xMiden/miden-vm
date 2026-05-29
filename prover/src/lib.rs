#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{string::ToString, vec, vec::Vec};

use ::serde::Serialize;
use miden_core::{Felt, WORD_SIZE, field::QuadFelt, utils::RowMajorMatrix};
use miden_crypto::stark::{
    StarkConfig,
    air::VarLenPublicInputs,
    challenger::CanObserve,
    lmcs::Lmcs,
    proof::{StarkOutput, StarkProof},
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
pub use miden_core::proof::{ExecutionProof, HashFunction};
pub use miden_processor::{
    ExecutionError, ExecutionOptions, ExecutionOutput, FutureMaybeSend, Host, InputError,
    ProgramInfo, StackInputs, StackOutputs, SyncHost, TraceBuildInputs, TraceGenerationContext,
    Word, advice::AdviceInputs, crypto, field, serde, utils,
};
pub use proving_options::ProvingOptions;

/// Inputs required to prove from pre-executed trace data.
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
}

// PROVER
// ================================================================================================

/// Executes and proves the specified `program` and returns the result together with a STARK-based
/// proof of the program's execution.
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

    let trace_inputs = processor.execute_trace_inputs(program, host).await?;
    prove_from_trace_sync(TraceProvingInputs::new(trace_inputs, proving_options))
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

    let trace_inputs = processor.execute_trace_inputs_sync(program, host)?;
    prove_from_trace_sync(TraceProvingInputs::new(trace_inputs, proving_options))
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
    let trace = build_trace(trace_inputs)?;
    prove_execution_trace(trace, options)
}

fn prove_execution_trace(
    trace: ExecutionTrace,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    tracing::event!(
        tracing::Level::INFO,
        "Generated execution trace of {} columns and {} steps (padded from {})",
        miden_air::trace::TRACE_WIDTH,
        trace.trace_len_summary().padded_trace_len(),
        trace.trace_len_summary().trace_len()
    );

    let stack_outputs = *trace.stack_outputs();
    let deferred_wire = trace
        .deferred_state()
        .to_wire(trace.precompiles())
        .map_err(|err| ExecutionError::ProvingError(err.to_string()))?;
    let hash_fn = options.hash_fn();

    // Extract public inputs before consuming the trace for the per-AIR matrices.
    let (public_values, kernel_felts) = trace.public_inputs().to_air_inputs();

    let (core_matrix, chiplets_matrix) = {
        let _span = tracing::info_span!("to_core_chiplets_matrices").entered();
        trace.into_core_chiplets_matrices()
    };

    let params = config::pcs_params();
    let proof_bytes = match hash_fn {
        HashFunction::Blake3_256 => {
            let config = config::blake3_256_config(params);
            prove_stark(&config, &core_matrix, &chiplets_matrix, &public_values, &kernel_felts)
        },
        HashFunction::Keccak => {
            let config = config::keccak_config(params);
            prove_stark(&config, &core_matrix, &chiplets_matrix, &public_values, &kernel_felts)
        },
        HashFunction::Rpo256 => {
            let config = config::rpo_config(params);
            prove_stark(&config, &core_matrix, &chiplets_matrix, &public_values, &kernel_felts)
        },
        HashFunction::Poseidon2 => {
            let config = config::poseidon2_config(params);
            prove_stark(&config, &core_matrix, &chiplets_matrix, &public_values, &kernel_felts)
        },
        HashFunction::Rpx256 => {
            let config = config::rpx_config(params);
            prove_stark(&config, &core_matrix, &chiplets_matrix, &public_values, &kernel_felts)
        },
    }?;

    let proof = ExecutionProof::new(proof_bytes, hash_fn, deferred_wire);

    Ok((stack_outputs, proof))
}
// STARK PROOF GENERATION
// ================================================================================================

/// Generates a multi-AIR STARK proof for the (Core, Chiplets) trace pair and public values.
///
/// Pre-seeds the challenger with the protocol parameters, public values, and the
/// concatenated kernel-procedure digests (the only variable-length public input today,
/// owned by the Chiplets AIR). Then delegates to the lifted multi-AIR prover.
pub fn prove_stark<SC>(
    config: &SC,
    core_trace: &RowMajorMatrix<Felt>,
    chiplets_trace: &RowMajorMatrix<Felt>,
    public_values: &[Felt],
    kernel_felts: &[Felt],
) -> Result<Vec<u8>, ExecutionError>
where
    SC: StarkConfig<Felt, QuadFelt>,
    <SC::Lmcs as Lmcs>::Commitment: Serialize,
{
    let mut challenger = config.challenger();
    config::observe_protocol_params(&mut challenger);
    challenger.observe_slice(public_values);
    let chiplets_var_len: VarLenPublicInputs<'_, Felt> = &[kernel_felts];
    config::observe_var_len_public_inputs(&mut challenger, chiplets_var_len, &[WORD_SIZE]);

    // Bind air_order into Fiat-Shamir before `prove_multi` (it absorbs heights but not
    // the air_order permutation, so the caller must).
    let trace_heights = vec![
        core_trace.values.len() / core_trace.width,
        chiplets_trace.values.len() / chiplets_trace.width,
    ];
    let shapes = miden_air::InstanceShapes::from_trace_heights(trace_heights)
        .map_err(|e| ExecutionError::ProvingError(e.to_string()))?;
    config::observe_air_order(&mut challenger, shapes.air_order());

    let core_witness = miden_air::AirWitness::new(core_trace, public_values, &[]);
    let chiplets_witness =
        miden_air::AirWitness::new(chiplets_trace, public_values, chiplets_var_len);

    let core_air = MidenAir::CORE;
    let chiplets_air = MidenAir::CHIPLETS;
    let instances = [
        (&core_air, core_witness, &core_air),
        (&chiplets_air, chiplets_witness, &chiplets_air),
    ];

    let output: StarkOutput<Felt, QuadFelt, SC> =
        miden_crypto::stark::prover::prove_multi(config, &instances, challenger)
            .map_err(|e| ExecutionError::ProvingError(e.to_string()))?;
    let proof_encoding_config = wincode::config::Configuration::default();
    let proof_bytes = <SerdeCompat<StarkProof<Felt, QuadFelt, SC>> as wincode::config::Serialize<
        _,
    >>::serialize(&output.proof, proof_encoding_config)
    .map_err(|e| ExecutionError::ProvingError(e.to_string()))?;
    Ok(proof_bytes)
}
