#![no_std]

#[cfg_attr(all(feature = "metal", target_arch = "aarch64", target_os = "macos"), macro_use)]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use core::marker::PhantomData;
use std::println;
#[cfg(feature = "std")]
use std::time::Instant;

use miden_air::{ProcessorAir, PublicInputs};
#[cfg(all(feature = "metal", target_arch = "aarch64", target_os = "macos"))]
use miden_gpu::HashFn;
use miden_processor::{ExecutionTrace, Program};
use p3_uni_stark::StarkGenericConfig;
use tracing::instrument;

mod gpu;

mod prove;
use prove::{prove_blake, prove_keccak, types::Proof as P3Proof, utils::to_row_major};

// EXPORTS
// ================================================================================================

pub use miden_air::{
    DeserializationError, ExecutionProof, FieldExtension, HashFunction, ProvingOptions,
};
pub use miden_processor::{
    AdviceInputs, AsyncHost, BaseHost, ExecutionError, InputError, PrecompileRequest, StackInputs,
    StackOutputs, SyncHost, Word, crypto, math, utils,
};

// PROVER
// ================================================================================================

pub struct ExecutionProver<SC> {
    config: SC,
    public_inputs: PublicInputs,
    _sc: PhantomData<SC>,
}

impl<SC> ExecutionProver<SC>
where
    SC: StarkGenericConfig,
{
    pub fn new(config: SC, public_inputs: PublicInputs) -> Self {
        Self { config, public_inputs, _sc: PhantomData }
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Validates the stack inputs against the provided execution trace and returns true if valid.
    pub fn are_inputs_valid(&self, trace: &ExecutionTrace) -> bool {
        self.public_inputs
            .stack_inputs()
            .iter()
            .zip(trace.init_stack_state().iter())
            .all(|(l, r)| l == r)
    }

    /// Validates the stack outputs against the provided execution trace and returns true if valid.
    pub fn are_outputs_valid(&self, trace: &ExecutionTrace) -> bool {
        self.public_inputs
            .stack_outputs()
            .iter()
            .zip(trace.last_stack_state().iter())
            .all(|(l, r)| l == r)
    }

    pub fn prove(&self, trace: ExecutionTrace) -> P3Proof<SC> where {
        let _processor_air = ProcessorAir {};

        //let mut public_inputs = self.public_inputs.stack_inputs().to_vec();
        //public_inputs.extend_from_slice(&self.public_inputs.stack_outputs().to_vec() );
        //public_inputs.extend_from_slice(&self.public_inputs.program_info().to_elements() );

        //let public_inputs = vec![];
        let _trace_row_major = to_row_major(&trace);
        //prove_uni_stark(&self.config, &processor_air, trace_row_major, &public_inputs)
        todo!()
    }
}

#[instrument("program proving", skip_all)]
pub fn prove(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl SyncHost,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError>
where
{
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
        trace.trace_len_summary().main_trace_len(),
        trace.trace_len_summary().padded_trace_len(),
        trace.trace_len_summary().padding_percentage(),
        now.elapsed().as_millis()
    );

    let stack_outputs = trace.stack_outputs().clone();
    let hash_fn = options.hash_fn();
    let _program_info = trace.program_info();

    // extract precompile requests from the trace to include in the proof
    let pc_requests = trace.take_precompile_requests();

    // generate STARK proof
    let proof = match hash_fn {
        HashFunction::Rpo256 => {
            todo!()
            // println!("rpo proving");
            // let proof = prove_rpo(trace);
            // proof
        },
        HashFunction::Blake3_256 | HashFunction::Blake3_192 => {
            println!("blake proving");
            prove_blake(trace)
        },
        HashFunction::Keccak => {
            println!("kecak proving");
            prove_keccak(trace)
        },
        HashFunction::Rpx256 => {
            unimplemented!()
        },
        HashFunction::Poseidon2 => {
            todo!()
            // let prover = ExecutionProver::<Poseidon2, WinterRandomCoin<_>>::new(
            //     options,
            //     stack_inputs,
            //     stack_outputs.clone(),
            // );
            // maybe_await!(prover.prove(trace))
        },
    };

    let proof = ExecutionProof::new(proof, hash_fn, pc_requests);

    Ok((stack_outputs, proof))
}

// HELPERS
// ================================================================================================

// HELPERS and TYPES are consolidated into prove/ submodules

// NOTE: The following Winter prover implementations are commented out as they don't match
// the new struct definition with a single generic parameter SC.
// These were part of the old Winter prover API and need to be removed or refactored.

/*
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
*/
