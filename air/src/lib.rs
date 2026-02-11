#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::vec::Vec;

use miden_core::{
    field::ExtensionField,
    precompile::PrecompileTranscriptState,
    program::{ProgramInfo, StackInputs, StackOutputs},
};
use miden_crypto::stark::matrix::RowMajorMatrix;

pub mod config;

#[cfg(feature = "human_readable")]
mod constraints;
#[cfg(all(
    feature = "human_readable",
    feature = "bus_active",
    any(
        feature = "system_constraints",
        feature = "chiplets_constraints",
        feature = "range_constraints",
        feature = "stack_constraints",
        feature = "decoder_constraints"
    )
))]
use constraints::enforce_bus_constraints;
#[cfg(all(
    feature = "human_readable",
    any(
        feature = "system_constraints",
        feature = "chiplets_constraints",
        feature = "range_constraints",
        feature = "stack_constraints",
        feature = "decoder_constraints"
    )
))]
use constraints::enforce_main_constraints;
use p3_miden_air::BusType;

#[cfg(feature = "human_readable")]
use crate::trace::AUX_TRACE_RAND_ELEMENTS;

mod unedited_constraints;
pub use unedited_constraints::miden_vm_plonky3::MidenVM;

pub mod trace;
#[cfg(feature = "human_readable")]
use constraints::chiplets::periodic_columns::NUM_PERIODIC_VALUES;
#[cfg(feature = "human_readable")]
use trace::{AUX_TRACE_WIDTH, MainTraceRow};

use crate::trace::{AuxTraceBuilder, TRACE_WIDTH};

// RE-EXPORTS
// ================================================================================================
mod export {
    pub use miden_core::{
        Felt,
        serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
        utils::ToElements,
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
pub struct ProcessorAir<EF, B = ()>
where
    EF: ExtensionField<Felt>,
    B: AuxTraceBuilder<EF>,
{
    #[cfg(not(feature = "human_readable"))]
    /// Inner MidenVM AIR instance, obtained from Plonky3 codegen of the Miden VM air-script
    /// constraints.
    inner: MidenVM,
    /// Auxiliary trace builder for generating auxiliary columns.
    aux_builder: Option<B>,
    phantom: core::marker::PhantomData<EF>,
}

impl<EF> ProcessorAir<EF, ()>
where
    EF: ExtensionField<Felt>,
{
    /// Creates a new ProcessorAir without auxiliary trace support.
    pub fn new() -> Self {
        Self {
            #[cfg(not(feature = "human_readable"))]
            inner: MidenVM {},
            aux_builder: None,
            phantom: core::marker::PhantomData,
        }
    }
}

impl<EF> Default for ProcessorAir<EF, ()>
where
    EF: ExtensionField<Felt>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<EF, B> ProcessorAir<EF, B>
where
    EF: ExtensionField<Felt>,
    B: AuxTraceBuilder<EF>,
{
    /// Creates a new ProcessorAir with auxiliary trace support.
    pub fn with_aux_builder(builder: B) -> Self {
        Self {
            #[cfg(not(feature = "human_readable"))]
            inner: MidenVM {},
            aux_builder: Some(builder),
            phantom: core::marker::PhantomData,
        }
    }
}

/// MidenAir implementation for ProcessorAir that delegates the constraints evaluation to the
/// generated MidenVM AIR if the human_readable feature is not enabled.
#[cfg(not(feature = "human_readable"))]
impl<EF, B> MidenAir<Felt, EF> for ProcessorAir<EF, B>
where
    EF: ExtensionField<Felt>,
    B: AuxTraceBuilder<EF>,
{
    fn width(&self) -> usize {
        <MidenVM as p3_miden_air::MidenAir<Felt, EF>>::width(&self.inner)
    }

    fn num_public_values(&self) -> usize {
        <MidenVM as p3_miden_air::MidenAir<Felt, EF>>::num_public_values(&self.inner)
    }

    #[cfg(any(
        feature = "system_constraints",
        feature = "chiplets_constraints",
        feature = "range_constraints",
        feature = "stack_constraints",
        feature = "decoder_constraints"
    ))]
    fn periodic_table(&self) -> Vec<Vec<Felt>> {
        <MidenVM as p3_miden_air::MidenAir<Felt, EF>>::periodic_table(&self.inner)
    }

    fn num_randomness(&self) -> usize {
        <MidenVM as p3_miden_air::MidenAir<Felt, EF>>::num_randomness(&self.inner)
    }

    fn aux_width(&self) -> usize {
        <MidenVM as p3_miden_air::MidenAir<Felt, EF>>::aux_width(&self.inner)
    }

    fn bus_types(&self) -> &[BusType] {
        <MidenVM as p3_miden_air::MidenAir<Felt, EF>>::bus_types(&self.inner)
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        challenges: &[EF],
    ) -> Option<RowMajorMatrix<Felt>> {
        let _span = tracing::info_span!("build_aux_trace").entered();

        let builders = self.aux_builder.as_ref()?;

        Some(builders.build_aux_columns(main, challenges))
    }

    #[cfg(not(any(
        feature = "system_constraints",
        feature = "chiplets_constraints",
        feature = "range_constraints",
        feature = "stack_constraints",
        feature = "decoder_constraints"
    )))]
    fn eval<AB: MidenAirBuilder<F = Felt>>(&self, _builder: &mut AB) {}

    #[cfg(any(
        feature = "system_constraints",
        feature = "chiplets_constraints",
        feature = "range_constraints",
        feature = "stack_constraints",
        feature = "decoder_constraints"
    ))]
    fn eval<AB: MidenAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        <MidenVM as p3_miden_air::MidenAir<miden_core::Felt, EF>>::eval::<AB>(&self.inner, builder);
    }
}

#[cfg(all(
    feature = "human_readable",
    not(any(
        feature = "system_constraints",
        feature = "chiplets_constraints",
        feature = "range_constraints",
        feature = "stack_constraints",
        feature = "decoder_constraints"
    ))
))]
compile_error!(
    "Please enable at least one of the constraints features when using human_readable feature"
);

/// MidenAir implementation for ProcessorAir that uses the constraints entry points defined in the
/// constraints module when the human_readable feature is enabled.
#[cfg(feature = "human_readable")]
impl<EF, B> MidenAir<Felt, EF> for ProcessorAir<EF, B>
where
    EF: ExtensionField<Felt>,
    B: AuxTraceBuilder<EF>,
{
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        0
    }

    #[cfg(any(
        feature = "system_constraints",
        feature = "chiplets_constraints",
        feature = "range_constraints",
        feature = "stack_constraints",
        feature = "decoder_constraints"
    ))]
    fn periodic_table(&self) -> Vec<Vec<Felt>> {
        let mut periodic_table = crate::constraints::chiplets::bitwise::bitwise_periodic_columns();
        periodic_table
            .extend_from_slice(&crate::constraints::chiplets::hasher::hasher_periodic_columns());
        periodic_table
    }

    fn num_randomness(&self) -> usize {
        AUX_TRACE_RAND_ELEMENTS
    }

    fn aux_width(&self) -> usize {
        AUX_TRACE_WIDTH
    }

    fn bus_types(&self) -> &[BusType] {
        &[]
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        challenges: &[EF],
    ) -> Option<RowMajorMatrix<Felt>> {
        let _span = tracing::info_span!("build_aux_trace").entered();

        let builders = self.aux_builder.as_ref()?;

        Some(builders.build_aux_columns(main, challenges))
    }

    #[cfg(not(any(
        feature = "system_constraints",
        feature = "chiplets_constraints",
        feature = "range_constraints",
        feature = "stack_constraints",
        feature = "decoder_constraints"
    )))]
    fn eval<AB: MidenAirBuilder<F = Felt>>(&self, _builder: &mut AB) {}

    #[cfg(any(
        feature = "system_constraints",
        feature = "chiplets_constraints",
        feature = "range_constraints",
        feature = "stack_constraints",
        feature = "decoder_constraints"
    ))]
    fn eval<AB: MidenAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        enforce_main_constraints(builder);
        #[cfg(feature = "bus_active")]
        enforce_bus_constraints(builder);
    }
}
