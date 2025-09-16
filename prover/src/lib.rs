#![no_std]

#[cfg_attr(all(feature = "metal", target_arch = "aarch64", target_os = "macos"), macro_use)]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use core::marker::PhantomData;
use std::{println, vec, vec::Vec};
use tracing::instrument;

use air::{ProcessorAir, PublicInputs, trace::TRACE_WIDTH};
#[cfg(all(feature = "metal", target_arch = "aarch64", target_os = "macos"))]
use miden_gpu::HashFn;

use p3_field::extension::BinomialExtensionField;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::StarkGenericConfig;
use processor::{ExecutionTrace, Program, ZERO, math::Felt};

#[cfg(feature = "std")]
use std::time::Instant;
mod gpu;

mod prove;

// EXPORTS
// ================================================================================================

pub use air::{DeserializationError, ExecutionProof, FieldExtension, HashFunction, ProvingOptions};
pub use processor::{
    AdviceInputs, Digest, ExecutionError, Host, InputError, MemAdviceProvider, StackInputs,
    StackOutputs, Word, crypto, math, utils,
};

// PROVER
// ================================================================================================

struct ExecutionProver<SC> {
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
    fn are_inputs_valid(&self, trace: &ExecutionTrace) -> bool {
        self.public_inputs
            .stack_inputs()
            .iter()
            .zip(trace.init_stack_state().iter())
            .all(|(l, r)| l == r)
    }

    /// Validates the stack outputs against the provided execution trace and returns true if valid.
    fn are_outputs_valid(&self, trace: &ExecutionTrace) -> bool {
        self.public_inputs
            .stack_outputs()
            .iter()
            .zip(trace.last_stack_state().iter())
            .all(|(l, r)| l == r)
    }

    fn prove(&self, trace: ExecutionTrace) -> Proof<SC> where {
        let processor_air = ProcessorAir {};

        //let mut public_inputs = self.public_inputs.stack_inputs().to_vec();
        //public_inputs.extend_from_slice(&self.public_inputs.stack_outputs().to_vec() );
        //public_inputs.extend_from_slice(&self.public_inputs.program_info().to_elements() );

        //let public_inputs = vec![];
        let trace_row_major = to_row_major(&trace);
        //prove_uni_stark(&self.config, &processor_air, trace_row_major, &public_inputs)
        todo!()
    }
}

#[instrument("program proving", skip_all)]
pub fn prove(
    program: &Program,
    stack_inputs: StackInputs,
    host: &mut impl Host,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError>
where
{
    // execute the program to create an execution trace
    #[cfg(feature = "std")]
    let now = Instant::now();
    let trace =
        processor::execute(program, stack_inputs.clone(), host, *options.execution_options())?;
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
    let program_info = trace.program_info();
    let public_inputs = PublicInputs::new(program_info.clone(), stack_inputs, stack_outputs);

    type Val = Felt;
    type Challenge = BinomialExtensionField<Val, 2>;

    // generate STARK proof
    let proof = match hash_fn {
        HashFunction::Rpo256 => {
            println!("rpo proving");
            let proof = prove_rpo(trace);

            ExecutionProof::new(proof, hash_fn)
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
    };
    Ok((stack_outputs, proof))
}

// HELPERS
// ================================================================================================

#[instrument("naive transposition", skip_all)]
fn to_row_major(trace: &ExecutionTrace) -> RowMajorMatrix<Felt> {
    let mut result: RowMajorMatrix<Felt> =
        RowMajorMatrix::new(vec![ZERO; TRACE_WIDTH * trace.get_trace_len()], TRACE_WIDTH);
    result.rows_mut().enumerate().for_each(|(row_idx, row)| {
        for col_idx in 0..TRACE_WIDTH {
            row[col_idx] = trace.main_trace.get(col_idx, row_idx)
        }
    });

    result
}

// Prover-related proof data types (Proof, Commitments, OpenedValues) will live here

use p3_commit::Pcs;
use serde::{Deserialize, Serialize};

use crate::prove::{prove_blake, prove_keccak, prove_rpo};

type Com<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Commitment;

type PcsProof<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Proof;

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Proof<SC: StarkGenericConfig> {
    pub(crate) commitments: Commitments<Com<SC>>,
    pub(crate) opened_values: OpenedValues<SC::Challenge>,
    pub(crate) opening_proof: PcsProof<SC>,
    pub(crate) degree_bits: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Commitments<Com> {
    pub(crate) trace: Com,
    pub(crate) aux_trace: Com,
    pub(crate) quotient_chunks: Com,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenedValues<Challenge> {
    pub(crate) trace_local: Vec<Challenge>,
    pub(crate) trace_next: Vec<Challenge>,
    pub(crate) aux_trace_local: Vec<Challenge>,
    pub(crate) aux_trace_next: Vec<Challenge>,
    pub(crate) quotient_chunks: Vec<Vec<Challenge>>,
}
