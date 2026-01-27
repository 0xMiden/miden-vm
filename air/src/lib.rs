#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::vec::Vec;

use miden_core::{
    ProgramInfo, StackInputs, StackOutputs, crypto::hash::Rpo256, 
    field::ExtensionField, precompile::PrecompileTranscriptState,
};
use p3_field::PrimeCharacteristicRing;
use p3_miden_air::BusType;
use p3_matrix::dense::RowMajorMatrix;

pub mod config;

#[cfg(feature = "constraint_eval")]
mod constraints;

mod unedited_constraints;
pub use unedited_constraints::miden_vm_plonky3::MidenVM;

pub mod trace;
use crate::trace::{AuxTraceBuilder, AUX_TRACE_WIDTH, TRACE_WIDTH, CYCLE_ROW_0, INV_CYCLE_ROW_7, CYCLE_ROW_6, CYCLE_ROW_7};

#[cfg(feature = "constraint_eval")]
use core::borrow::Borrow;
#[cfg(feature = "constraint_eval")]
use trace::MainTraceRow;

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
pub struct ProcessorAir<EF, B = ()>
where
    EF: ExtensionField<Felt>,
    B: AuxTraceBuilder<EF>,
{
    /// Inner MidenVM AIR instance, obtained from Plonky3 codegen of the Miden VM air-script constraints.
    inner: Option<MidenVM>,
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
            inner: Some(MidenVM {}),
            aux_builder: None,
            phantom: core::marker::PhantomData,
        }
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
            inner: Some(MidenVM {}),
            aux_builder: Some(builder),
            phantom: core::marker::PhantomData,
        }
    }
}

impl<EF, B> MidenAir<Felt, EF> for ProcessorAir<EF, B>
where
    EF: ExtensionField<Felt>,
    B: AuxTraceBuilder<EF>,
{
    fn width(&self) -> usize {
        self.inner.as_ref().map(<MidenVM as p3_miden_air::MidenAir<Felt, EF>>::width).unwrap_or(TRACE_WIDTH)
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        self.inner.as_ref().map(<MidenVM as p3_miden_air::MidenAir<Felt, EF>>::preprocessed_trace).unwrap_or(None)
    }

    fn num_public_values(&self) -> usize {
        self.inner.as_ref().map(<MidenVM as p3_miden_air::MidenAir<Felt, EF>>::num_public_values).unwrap_or(0) // todo
    }

    fn periodic_table(&self) -> Vec<Vec<Felt>> {
        self.inner.as_ref().map(<MidenVM as p3_miden_air::MidenAir<Felt, EF>>::periodic_table).unwrap_or_else(|| {
            let mut periodic_table = Vec::new();
            periodic_table.push(CYCLE_ROW_0.to_vec());
            periodic_table.push(INV_CYCLE_ROW_7.to_vec());
            periodic_table.push(CYCLE_ROW_0.to_vec());
            periodic_table.push(CYCLE_ROW_6.to_vec());
            periodic_table.push(CYCLE_ROW_7.to_vec());
            let ark1 = Rpo256::ARK1.iter().map(|&v| {
                let mut v = v.to_vec();
                v.push(Felt::ZERO);
                v
            }).collect::<Vec<_>>();
            let ark2 = Rpo256::ARK2.iter().map(|&v| {
                let mut v = v.to_vec();
                v.push(Felt::ZERO);
                v
            }).collect::<Vec<_>>();
            periodic_table.extend_from_slice(&ark1);
            periodic_table.extend_from_slice(&ark2);
            periodic_table
        }

        )
    }

    fn num_randomness(&self) -> usize {
        self.inner
            .as_ref()
            .map(<MidenVM as p3_miden_air::MidenAir<Felt, EF>>::num_randomness)
            .unwrap_or(trace::AUX_TRACE_RAND_ELEMENTS)
    }

    fn aux_width(&self) -> usize {
        self.inner.as_ref().map(<MidenVM as p3_miden_air::MidenAir<Felt, EF>>::aux_width).unwrap_or(AUX_TRACE_WIDTH)
    }

    fn bus_types(&self) -> &[BusType] {
        self.inner.as_ref().map(<MidenVM as p3_miden_air::MidenAir<Felt, EF>>::bus_types).unwrap_or(&[]) // todo
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

    #[cfg(not(feature = "constraint_eval"))]
    fn eval<AB: MidenAirBuilder<F = Felt>>(&self, _builder: &mut AB) {}

    #[cfg(feature = "constraint_eval")]
    fn eval<AB: MidenAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        if let Some(inner) = &self.inner {
            <MidenVM as p3_miden_air::MidenAir<miden_core::Felt, EF>>::eval::<AB>(inner, builder);
        } else {
            use p3_matrix::Matrix;

            use crate::constraints;

            let main = builder.main();

            // Access the two rows: current (local) and next
            let local = main.row_slice(0).expect("Matrix should have at least 1 row");
            let next = main.row_slice(1).expect("Matrix should have at least 2 rows");

            // Use structured column access via MainTraceCols
            let local: &MainTraceRow<AB::Var> = (*local).borrow();
            let next: &MainTraceRow<AB::Var> = (*next).borrow();

            let periodic_values: [_; NUM_PERIODIC_VALUES] =
                builder.periodic_evals().try_into().expect("Wrong number of periodic values");

            // SYSTEM CONSTRAINTS
            constraints::enforce_clock_constraint(builder, local, next);

            // STACK CONSTRAINTS
            //constraints::stack::enforce_stack_boundary_constraints(builder, local);
            //constraints::stack::enforce_stack_transition_constraint(builder, local, next);
            //constraints::stack::enforce_stack_bus_constraint(builder, local);

            // RANGE CHECKER CONSTRAINTS
            constraints::range::enforce_range_boundary_constraints(builder, local);
            constraints::range::enforce_range_transition_constraint(builder, local, next);
            constraints::range::enforce_range_bus_constraint(builder, local);

            // CHIPLETS CONSTRAINTS
            constraints::chiplets::enforce_chiplets_transition_constraint(
                builder,
                local,
                next,
                &periodic_values,
            );
            constraints::chiplets::enforce_chiplets_bus_constraint(builder, local);
        }
    }
}
