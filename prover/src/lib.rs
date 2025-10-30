#![no_std]

#[cfg_attr(all(feature = "metal", target_arch = "aarch64", target_os = "macos"), macro_use)]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use core::marker::PhantomData;

use miden_air::{AuxRandElements, PartitionOptions, ProcessorAir, PublicInputs};
#[cfg(all(feature = "metal", target_arch = "aarch64", target_os = "macos"))]
use miden_gpu::HashFn;
use miden_processor::{
    ExecutionTrace, Program,
    crypto::{
        Blake3_192, Blake3_256, ElementHasher, Poseidon2, RandomCoin, Rpo256, RpoRandomCoin,
        Rpx256, RpxRandomCoin, WinterRandomCoin,
    },
    math::{Felt, FieldElement},
};
use tracing::instrument;
use winter_maybe_async::{maybe_async, maybe_await};
use winter_prover::{
    CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde,
    ProofOptions as WinterProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable,
    matrix::ColMatrix,
};
#[cfg(feature = "std")]
use {std::time::Instant, winter_prover::Trace};
mod gpu;

// EXPORTS
// ================================================================================================

pub use miden_air::{
    DeserializationError, ExecutionProof, FieldExtension, HashFunction, ProvingOptions,
};
pub use miden_processor::{
    AdviceInputs, AsyncHost, BaseHost, ExecutionError, InputError, PrecompileRequest, StackInputs,
    StackOutputs, SyncHost, Word, crypto, math, utils,
};
pub use winter_prover::{Proof, crypto::MerkleTree as MerkleTreeVC};

// PROVER
// ================================================================================================

/// Executes and proves the specified `program` and returns the result together with a STARK-based
/// proof of the program's execution.
///
/// - `stack_inputs` specifies the initial state of the stack for the VM.
/// - `host` specifies the host environment which contain non-deterministic (secret) inputs for the
///   prover
/// - `options` defines parameters for STARK proof generation.
///
/// # Errors
/// Returns an error if program execution or STARK proof generation fails for any reason.
#[instrument("prove_program", skip_all)]
#[maybe_async]
pub fn prove(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl SyncHost,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    // execute the program to create an execution trace
    #[cfg(feature = "std")]
    let now = Instant::now();
    let mut trace = miden_processor::execute(
        program,
        stack_inputs.clone(),
        advice_inputs,
        host,
        *options.execution_options(),
    )?;
    #[cfg(feature = "std")]
    tracing::event!(
        tracing::Level::INFO,
        "Generated execution trace of {} columns and {} steps ({}% padded) in {} ms",
        trace.info().main_trace_width(),
        trace.trace_len_summary().padded_trace_len(),
        trace.trace_len_summary().padding_percentage(),
        now.elapsed().as_millis()
    );

    let stack_outputs = trace.stack_outputs().clone();
    let hash_fn = options.hash_fn();

    // extract precompile requests from the trace to include in the proof
    let pc_requests = trace.take_precompile_requests();

    // generate STARK proof
    let proof = match hash_fn {
        HashFunction::Blake3_192 => {
            let prover = ExecutionProver::<Blake3_192, WinterRandomCoin<_>>::new(
                options,
                stack_inputs,
                stack_outputs.clone(),
            );
            maybe_await!(prover.prove(trace))
        },
        HashFunction::Blake3_256 => {
            let prover = ExecutionProver::<Blake3_256, WinterRandomCoin<_>>::new(
                options,
                stack_inputs,
                stack_outputs.clone(),
            );
            maybe_await!(prover.prove(trace))
        },
        HashFunction::Rpo256 => {
            let prover = ExecutionProver::<Rpo256, RpoRandomCoin>::new(
                options,
                stack_inputs,
                stack_outputs.clone(),
            );
            #[cfg(all(feature = "metal", target_arch = "aarch64", target_os = "macos"))]
            let prover = gpu::metal::MetalExecutionProver::new(prover, HashFn::Rpo256);
            maybe_await!(prover.prove(trace))
        },
        HashFunction::Rpx256 => {
            let prover = ExecutionProver::<Rpx256, RpxRandomCoin>::new(
                options,
                stack_inputs,
                stack_outputs.clone(),
            );
            #[cfg(all(feature = "metal", target_arch = "aarch64", target_os = "macos"))]
            let prover = gpu::metal::MetalExecutionProver::new(prover, HashFn::Rpx256);
            maybe_await!(prover.prove(trace))
        },
        HashFunction::Poseidon2 => {
            let prover = ExecutionProver::<Poseidon2, WinterRandomCoin<_>>::new(
                options,
                stack_inputs,
                stack_outputs.clone(),
            );
            maybe_await!(prover.prove(trace))
        },
    }
    .map_err(ExecutionError::ProverError)?;

    let proof = ExecutionProof::new(proof, hash_fn, pc_requests);

    Ok((stack_outputs, proof))
}

// PROVER
// ================================================================================================

struct ExecutionProver<H, R>
where
    H: ElementHasher<BaseField = Felt>,
    R: RandomCoin<BaseField = Felt, Hasher = H>,
{
    random_coin: PhantomData<R>,
    options: WinterProofOptions,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
}

impl<H, R> ExecutionProver<H, R>
where
    H: ElementHasher<BaseField = Felt>,
    R: RandomCoin<BaseField = Felt, Hasher = H>,
{
    pub fn new(
        options: ProvingOptions,
        stack_inputs: StackInputs,
        stack_outputs: StackOutputs,
    ) -> Self {
        Self {
            random_coin: PhantomData,
            options: options.into(),
            stack_inputs,
            stack_outputs,
        }
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Validates the stack inputs against the provided execution trace and returns true if valid.
    fn are_inputs_valid(&self, trace: &ExecutionTrace) -> bool {
        self.stack_inputs
            .iter()
            .zip(trace.init_stack_state().iter())
            .all(|(l, r)| l == r)
    }

    /// Validates the stack outputs against the provided execution trace and returns true if valid.
    fn are_outputs_valid(&self, trace: &ExecutionTrace) -> bool {
        self.stack_outputs
            .iter()
            .zip(trace.last_stack_state().iter())
            .all(|(l, r)| l == r)
    }
}

impl<H, R> Prover for ExecutionProver<H, R>
where
    H: ElementHasher<BaseField = Felt> + Sync,
    R: RandomCoin<BaseField = Felt, Hasher = H> + Send,
{
    type BaseField = Felt;
    type Air = ProcessorAir;
    type Trace = ExecutionTrace;
    type HashFn = H;
    type VC = MerkleTreeVC<Self::HashFn>;
    type RandomCoin = R;
    type TraceLde<E: FieldElement<BaseField = Felt>> = DefaultTraceLde<E, H, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> =
        DefaultConstraintEvaluator<'a, ProcessorAir, E>;
    type ConstraintCommitment<E: FieldElement<BaseField = Felt>> =
        DefaultConstraintCommitment<E, H, Self::VC>;

    fn options(&self) -> &WinterProofOptions {
        &self.options
    }

    fn get_pub_inputs(&self, trace: &ExecutionTrace) -> PublicInputs {
        // ensure inputs and outputs are consistent with the execution trace.
        debug_assert!(
            self.are_inputs_valid(trace),
            "provided inputs do not match the execution trace"
        );
        debug_assert!(
            self.are_outputs_valid(trace),
            "provided outputs do not match the execution trace"
        );

        let program_info = trace.program_info().clone();
        let final_pc_transcript = trace.final_precompile_transcript();
        PublicInputs::new(
            program_info,
            self.stack_inputs.clone(),
            self.stack_outputs.clone(),
            final_pc_transcript.state(),
        )
    }

    #[maybe_async]
    fn new_trace_lde<E: FieldElement<BaseField = Felt>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Felt>,
        domain: &StarkDomain<Felt>,
        partition_options: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_options)
    }

    #[maybe_async]
    fn new_evaluator<'a, E: FieldElement<BaseField = Felt>>(
        &self,
        air: &'a ProcessorAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    #[instrument(skip_all)]
    #[maybe_async]
    fn build_aux_trace<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace: &Self::Trace,
        aux_rand_elements: &AuxRandElements<E>,
    ) -> ColMatrix<E> {
        trace.build_aux_trace(aux_rand_elements.rand_elements()).unwrap()
    }

    #[maybe_async]
    fn build_constraint_commitment<E: FieldElement<BaseField = Felt>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }
}
