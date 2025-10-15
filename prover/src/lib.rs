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
use tracing::{info_span, instrument};

mod gpu;

mod prove;

// EXPORTS
// ================================================================================================

pub use miden_air::{
    DeserializationError, ExecutionProof, FieldExtension, HashFunction, ProvingOptions,
};
pub use miden_processor::{
    AdviceInputs, AsyncHost, BaseHost, ExecutionError, InputError, StackInputs, StackOutputs,
    SyncHost, Word, crypto, math, utils,
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

    pub fn prove(&self, trace: ExecutionTrace) -> Proof<SC> where {
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
    let trace = info_span!("construct_execution_trace").in_scope(|| {
        miden_processor::execute(
            program,
            stack_inputs,
            advice_inputs,
            host,
            *options.execution_options(),
        )
    })?;
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

    // generate STARK proof
    let proof = match hash_fn {
        HashFunction::Rpo256 => {
            todo!()
            // println!("rpo proving");
            // let proof = prove_rpo(trace);

            // ExecutionProof::new(proof, hash_fn)
        },
        HashFunction::Blake3_256 | HashFunction::Blake3_192 => {
            println!("blake proving");
            let proof = prove_blake(trace);

            ExecutionProof::new(proof, hash_fn)
        },
        HashFunction::Keccak => {
            println!("kecak proving");
            let proof = prove_keccak(trace);

            ExecutionProof::new(proof, hash_fn)
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
    // let proof = ExecutionProof::new(proof, hash_fn);

    Ok((stack_outputs, proof))
}

// HELPERS
// ================================================================================================

// HELPERS and TYPES are consolidated into prove/ submodules

pub use crate::prove::types::{Commitments, OpenedValues, Proof};
use crate::prove::{prove_blake, prove_keccak, utils::to_row_major};
