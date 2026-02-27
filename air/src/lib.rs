#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::vec::Vec;
use core::borrow::Borrow;

use miden_core::{
    WORD_SIZE, Word,
    field::ExtensionField,
    precompile::PrecompileTranscriptState,
    program::{MIN_STACK_DEPTH, ProgramInfo, StackInputs, StackOutputs},
};
use p3_matrix::Matrix;
use p3_miden_lifted_air::{ReducedAuxValues, ReductionError, VarLenPublicInputs};

pub mod config;
mod constraints;

pub mod trace;
use trace::{AUX_TRACE_WIDTH, MainTraceRow, TRACE_WIDTH};

// RE-EXPORTS
// ================================================================================================
mod export {
    pub use miden_core::{
        Felt,
        serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
        utils::ToElements,
    };
    pub use p3_air::{AirBuilder, BaseAir, BaseAirWithPublicValues};
    pub use p3_miden_lifted_air::{
        AirWithPeriodicColumns, AuxBuilder, LiftedAir, LiftedAirBuilder,
    };
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

    /// Returns the fixed-length public values and the variable-length kernel procedure digests.
    ///
    /// The fixed-length public values layout is:
    ///   [0..4]   program hash
    ///   [4..20]  stack inputs
    ///   [20..36] stack outputs
    ///   [36..40] precompile transcript state
    ///
    /// The kernel procedure digests are returned separately as `Word`s, to be passed
    /// as `var_len_public_inputs` to the verifier.
    pub fn to_air_inputs(&self) -> (Vec<Felt>, Vec<Word>) {
        let mut public_values = Vec::with_capacity(NUM_PUBLIC_VALUES);
        public_values.extend_from_slice(self.program_info.program_hash().as_elements());
        public_values.extend_from_slice(self.stack_inputs.as_ref());
        public_values.extend_from_slice(self.stack_outputs.as_ref());
        public_values.extend_from_slice(self.pc_transcript_state.as_ref());

        let kernel_digests: Vec<Word> = self
            .program_info
            .kernel_procedures()
            .iter()
            .map(|d| [d[0], d[1], d[2], d[3]].into())
            .collect();

        (public_values, kernel_digests)
    }

    /// Converts public inputs into a vector of field elements (Felt) in the canonical order:
    /// - program info elements (including kernel procedure hashes)
    /// - stack inputs
    /// - stack outputs
    /// - precompile transcript state
    #[deprecated = "use `to_air_inputs()` which separates fixed and variable-length data"]
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

/// Number of fixed-length public values for the Miden VM AIR.
///
/// Layout (40 Felts total):
///   [0..4]   program hash
///   [4..20]  stack inputs
///   [20..36] stack outputs
///   [36..40] precompile transcript state
pub const NUM_PUBLIC_VALUES: usize = WORD_SIZE + MIN_STACK_DEPTH + MIN_STACK_DEPTH + WORD_SIZE;

// Public values layout offsets.
const PV_PROGRAM_HASH: usize = 0;
const PV_TRANSCRIPT_STATE: usize = NUM_PUBLIC_VALUES - WORD_SIZE;

/// Miden VM Processor AIR implementation.
///
/// Auxiliary trace building is handled separately via [`AuxBuilder`].
/// Public-input-dependent checks are performed in [`LiftedAir::reduced_aux_values`]
/// by parsing the `public_values` slice directly.
pub struct ProcessorAir;

// --- Upstream trait impls for ProcessorAir ---

impl BaseAir<Felt> for ProcessorAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }
}

impl BaseAirWithPublicValues<Felt> for ProcessorAir {
    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl AirWithPeriodicColumns<Felt> for ProcessorAir {
    fn periodic_columns(&self) -> &[Vec<Felt>] {
        // ProcessorAir has no periodic columns; return a static empty slice.
        const EMPTY: &[Vec<Felt>] = &[];
        EMPTY
    }
}

// --- LiftedAir impl ---

impl<EF: ExtensionField<Felt>> LiftedAir<Felt, EF> for ProcessorAir {
    fn num_randomness(&self) -> usize {
        trace::AUX_TRACE_RAND_ELEMENTS
    }

    fn aux_width(&self) -> usize {
        AUX_TRACE_WIDTH
    }

    fn num_aux_values(&self) -> usize {
        AUX_TRACE_WIDTH
    }

    fn reduced_aux_values(
        &self,
        aux_values: &[EF],
        challenges: &[EF],
        public_values: &[Felt],
        var_len_public_inputs: VarLenPublicInputs<'_, Felt>,
    ) -> Result<ReducedAuxValues<EF>, ReductionError>
    where
        EF: ExtensionField<Felt>,
    {
        // Extract final aux column values.
        let p1 = aux_values[trace::DECODER_AUX_TRACE_OFFSET];
        let p2 = aux_values[trace::DECODER_AUX_TRACE_OFFSET + 1];
        let p3 = aux_values[trace::DECODER_AUX_TRACE_OFFSET + 2];
        let s_aux = aux_values[trace::STACK_AUX_TRACE_OFFSET];
        let b_range = aux_values[trace::RANGE_CHECK_AUX_TRACE_OFFSET];
        let b_hash_kernel = aux_values[trace::HASH_KERNEL_VTABLE_AUX_TRACE_OFFSET];
        let b_chiplets = aux_values[trace::CHIPLETS_BUS_AUX_TRACE_OFFSET];
        let v_wiring = aux_values[trace::ACE_CHIPLET_WIRING_BUS_OFFSET];

        // Parse fixed-length public values (see `NUM_PUBLIC_VALUES` for layout).
        debug_assert_eq!(public_values.len(), NUM_PUBLIC_VALUES);
        let program_hash: Word = public_values[PV_PROGRAM_HASH..PV_PROGRAM_HASH + WORD_SIZE]
            .try_into()
            .expect("program hash is 4 felts");
        let pc_transcript_state: PrecompileTranscriptState = public_values
            [PV_TRANSCRIPT_STATE..PV_TRANSCRIPT_STATE + WORD_SIZE]
            .try_into()
            .expect("transcript state is 4 felts");

        // Compute expected bus messages from public inputs and challenges.
        //
        // Running products accumulate response/request (responses in numerator).
        // Without init seeding, columns that previously started at identity now end at
        // non-trivial values encoding public-input bindings:
        //
        // - p2 ends at 1/program_hash_msg (block hash table missing program hash init)
        // - b_hash_kernel ends at final_transcript_msg/default_transcript_msg (virtual table
        //   missing transcript state init terms)
        // - b_chiplets ends at kernel_reduced (bus missing kernel ROM init requests)
        //
        // The product is constructed so that it equals 1 for valid executions.
        let ph_msg = program_hash_message(challenges, &program_hash);

        let default_transcript_msg = trace::log_precompile::transcript_message(
            challenges,
            PrecompileTranscriptState::default(),
        );
        let final_transcript_msg =
            trace::log_precompile::transcript_message(challenges, pc_transcript_state);

        let kernel_reduced = kernel_reduced_from_var_len(challenges, var_len_public_inputs);

        // Combine: for valid execution, prod = 1.
        //   p1 = 1, p3 = 1, s_aux = 1  (balanced buses)
        //   p2 * ph_msg = 1             (program hash binding)
        //   b_hash_kernel * default_transcript_msg / final_transcript_msg = 1
        //   b_chiplets / kernel_reduced = 1
        let expected_denom = final_transcript_msg * kernel_reduced;
        let expected_denom_inv = expected_denom.try_inverse().unwrap_or(EF::ONE);

        let prod = p1
            * p2
            * p3
            * s_aux
            * b_hash_kernel
            * b_chiplets
            * ph_msg
            * default_transcript_msg
            * expected_denom_inv;

        // LogUp: all columns should end at 0.
        let sum = b_range + v_wiring;

        Ok(ReducedAuxValues { prod, sum })
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        use crate::constraints;

        let main = builder.main();

        // Access the two rows: current (local) and next
        let local = main.row_slice(0).expect("Matrix should have at least 1 row");
        let next = main.row_slice(1).expect("Matrix should have at least 2 rows");

        // Use structured column access via MainTraceCols
        let local: &MainTraceRow<AB::Var> = (*local).borrow();
        let next: &MainTraceRow<AB::Var> = (*next).borrow();

        // Main trace constraints.
        constraints::enforce_main(builder, local, next);

        // Auxiliary (bus) constraints.
        constraints::enforce_bus(builder, local, next);
    }
}

// AUX FINALS HELPERS
// ================================================================================================

/// Builds the program-hash bus message for the initial block-hash table row.
///
/// Matches semantics of `BlockHashTableRow::collapse` for the initial program hash row:
/// parent_id=0, is_first_child=0, is_loop_body=0.
fn program_hash_message<EF: ExtensionField<Felt>>(alphas: &[EF], program_hash: &Word) -> EF {
    alphas[0]
        + alphas[2] * program_hash[0]
        + alphas[3] * program_hash[1]
        + alphas[4] * program_hash[2]
        + alphas[5] * program_hash[3]
}

/// Builds the kernel procedure init message for the kernel ROM bus.
fn kernel_proc_message<EF: ExtensionField<Felt>>(alphas: &[EF], digest: &Word) -> EF {
    alphas[0]
        + alphas[1] * trace::chiplets::kernel_rom::KERNEL_PROC_INIT_LABEL
        + alphas[2] * digest[0]
        + alphas[3] * digest[1]
        + alphas[4] * digest[2]
        + alphas[5] * digest[3]
}

/// Reduces kernel procedure digests from var-len public inputs into a multiset product.
///
/// Each entry in `var_len_public_inputs` is one kernel procedure digest (4 Felts).
fn kernel_reduced_from_var_len<EF: ExtensionField<Felt>>(
    alphas: &[EF],
    var_len_public_inputs: VarLenPublicInputs<'_, Felt>,
) -> EF {
    let mut acc = EF::ONE;
    for digest in var_len_public_inputs.iter() {
        debug_assert_eq!(digest.len(), WORD_SIZE);
        let word: Word = [digest[0], digest[1], digest[2], digest[3]].into();
        acc *= kernel_proc_message(alphas, &word);
    }

    acc
}
