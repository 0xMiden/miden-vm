#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::vec::Vec;

use miden_core::{
    ProgramInfo, StackInputs, StackOutputs, field::ExtensionField,
    precompile::PrecompileTranscriptState,
};

pub mod config;
mod constraints;

pub mod unedited_constraints;
pub use unedited_constraints::*;
use p3_miden_air::BusType;

pub mod trace;
use trace::{AuxTraceBuilder, MainTraceRow, TRACE_WIDTH};

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

pub const NUM_PERIODIC_VALUES: usize = 29;
pub const PERIOD: usize = 8;

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
        self.stack_inputs
    }

    pub fn stack_outputs(&self) -> StackOutputs {
        self.stack_outputs
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
pub struct ProcessorAir<A, EF, B = ()>
where
    A: MidenAir<Felt, EF>,
    EF: ExtensionField<Felt>,
    B: AuxTraceBuilder<EF>
{
    inner: A,
    /// Auxiliary trace builder for generating auxiliary columns.
    aux_builder: Option<B>,
    phantom: core::marker::PhantomData<EF>,
}

impl<A, EF> ProcessorAir<A, EF, ()>
where
    A: MidenAir<Felt, EF>,
    EF: ExtensionField<Felt>
{
    /// Creates a new ProcessorAir without auxiliary trace support.
    pub fn new(a: A) -> Self {
        Self { 
            inner: a,
            aux_builder: None,
            phantom: core::marker::PhantomData
        }
    }
}

impl<A, EF, B> ProcessorAir<A, EF, B>
where
    A: MidenAir<Felt, EF>,
    EF: ExtensionField<Felt>,
    B: AuxTraceBuilder<EF>,
{
    /// Creates a new ProcessorAir with auxiliary trace support.
    pub fn with_aux_builder(a: A, builder: B) -> Self {
        Self { 
            inner: a,
            aux_builder: Some(builder),
            phantom: core::marker::PhantomData
        }
    }
}

use p3_matrix::dense::RowMajorMatrix;

impl<A, EF, B> MidenAir<Felt, EF> for ProcessorAir<A, EF, B>
where
    A: MidenAir<Felt, EF>,
    EF: ExtensionField<Felt>,
    B: AuxTraceBuilder<EF>,
{
    fn width(&self) -> usize {
        self.inner.width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        self.inner.preprocessed_trace()
    }

    fn num_public_values(&self) -> usize {
        self.inner.num_public_values()
    }

    fn periodic_table(&self) -> Vec<Vec<Felt>> {
        self.inner.periodic_table()
    }

    fn num_randomness(&self) -> usize {
        self.inner.num_randomness()
    }

    fn aux_width(&self) -> usize {
        self.inner.aux_width()
    }

    fn bus_types(&self) -> &[BusType] {
        self.inner.bus_types()
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
        // First, apply the inner AIR's constraints
        self.inner.eval(builder);
    }
}
