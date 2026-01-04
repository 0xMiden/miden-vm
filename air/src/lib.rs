#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::vec::Vec;
use core::borrow::Borrow;

use miden_core::{
    ProgramInfo, StackInputs, StackOutputs, field::ExtensionField,
    precompile::PrecompileTranscriptState,
};

pub mod config;
mod constraints;

mod errors;
pub use errors::ExecutionOptionsError;

mod options;
pub use options::{DEFAULT_CORE_TRACE_FRAGMENT_SIZE, ExecutionOptions, ProvingOptions};

mod proof;
pub use proof::{ExecutionProof, HashFunction};

pub mod trace;
use trace::{AUX_TRACE_WIDTH, AuxTraceBuilder, MainTraceRow, TRACE_WIDTH};

// RE-EXPORTS
// ================================================================================================
mod export {
    pub use miden_core::{
        Felt,
        utils::{
            ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, ToElements,
        },
    };
    pub use miden_crypto::stark::air::{Air, AirBuilder, BaseAir, MidenAir, MidenAirBuilder};
}

pub use export::*;

// PUBLIC INPUTS
// ================================================================================================

#[derive(Debug, Clone)]
pub struct PublicInputs {
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    pc_transcript_state: PrecompileTranscriptState,
}

impl PublicInputs {
    /// Creates a new instance of `PublicInputs` from program information, stack inputs and outputs,
    /// and the precompile transcript state (capacity of an internal sponge).
    pub fn new(
        program_info: ProgramInfo,
        stack_inputs: StackInputs,
        stack_outputs: StackOutputs,
        pc_transcript_state: PrecompileTranscriptState,
    ) -> Self {
        Self {
            program_info,
            stack_inputs,
            stack_outputs,
            pc_transcript_state,
        }
    }

    pub fn stack_inputs(&self) -> StackInputs {
        self.stack_inputs.clone()
    }

    pub fn stack_outputs(&self) -> StackOutputs {
        self.stack_outputs.clone()
    }

    pub fn program_info(&self) -> ProgramInfo {
        self.program_info.clone()
    }

    /// Returns the precompile transcript state.
    pub fn pc_transcript_state(&self) -> PrecompileTranscriptState {
        self.pc_transcript_state
    }

    /// Converts public inputs into a vector of field elements (Felt) in the canonical order:
    /// - program info elements
    /// - stack inputs
    /// - stack outputs
    /// - precompile transcript state
    pub fn to_elements(&self) -> Vec<Felt> {
        let mut result = self.program_info.to_elements();
        result.extend_from_slice(self.stack_inputs.as_ref());
        result.extend_from_slice(self.stack_outputs.as_ref());
        result.extend_from_slice(self.pc_transcript_state.as_ref());
        result
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.program_info.write_into(target);
        self.stack_inputs.write_into(target);
        self.stack_outputs.write_into(target);
        self.pc_transcript_state.write_into(target);
    }
}

impl Deserializable for PublicInputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let program_info = ProgramInfo::read_from(source)?;
        let stack_inputs = StackInputs::read_from(source)?;
        let stack_outputs = StackOutputs::read_from(source)?;
        let pc_transcript_state = PrecompileTranscriptState::read_from(source)?;

        Ok(PublicInputs {
            program_info,
            stack_inputs,
            stack_outputs,
            pc_transcript_state,
        })
    }
}

// PROCESSOR AIR
// ================================================================================================

/// Miden VM Processor AIR implementation.
///
/// This struct defines the constraints for the Miden VM processor.
/// Generic over aux trace builder to support different extension fields.
pub struct ProcessorAir<B = ()> {
    /// Auxiliary trace builder for generating auxiliary columns.
    aux_builder: Option<B>,
}

impl Default for ProcessorAir<()> {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessorAir<()> {
    /// Creates a new ProcessorAir without auxiliary trace support.
    pub fn new() -> Self {
        Self { aux_builder: None }
    }
}

impl<B> ProcessorAir<B> {
    /// Creates a new ProcessorAir with auxiliary trace support.
    pub fn with_aux_builder(builder: B) -> Self {
        Self { aux_builder: Some(builder) }
    }
}

impl<EF, B> MidenAir<Felt, EF> for ProcessorAir<B>
where
    EF: ExtensionField<Felt>,
    B: AuxTraceBuilder<EF>,
{
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn aux_width(&self) -> usize {
        // Return the number of extension field columns
        // The prover will interpret the returned base field data as EF columns
        AUX_TRACE_WIDTH
    }

    fn num_randomness(&self) -> usize {
        trace::AUX_TRACE_RAND_ELEMENTS
    }

    fn build_aux_trace(
        &self,
        main: &p3_matrix::dense::RowMajorMatrix<Felt>,
        challenges: &[EF],
    ) -> Option<p3_matrix::dense::RowMajorMatrix<Felt>> {
        let _span = tracing::info_span!("build_aux_trace").entered();

        let builders = self.aux_builder.as_ref()?;

        Some(builders.build_aux_columns(main, challenges))
    }

    fn eval<AB: MidenAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        use p3_matrix::Matrix;

        use crate::constraints;

        let main = builder.main();

        // Access the two rows: current (local) and next
        let local = main.row_slice(0).expect("Matrix should have at least 1 row");
        let next = main.row_slice(1).expect("Matrix should have at least 2 rows");

        // Use structured column access via MainTraceCols
        let local: &MainTraceRow<AB::Var> = (*local).borrow();
        let next: &MainTraceRow<AB::Var> = (*next).borrow();

        // SYSTEM CONSTRAINTS
        constraints::enforce_clock_constraint(builder, local, next);

        // RANGE CHECKER CONSTRAINTS
        constraints::range::enforce_range_boundary_constraints(builder, local);
        constraints::range::enforce_range_transition_constraint(builder, local, next);
        constraints::range::enforce_range_bus_constraint(builder, local);
    }
}
