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
use miden_crypto::stark::air::{
    ReducedAuxValues, ReductionError, VarLenPublicInputs, WindowAccess,
};

pub mod ace;
pub mod config;
mod constraints;
pub mod lookup;
pub mod trace;

/// Miden VM-specific LogUp lookup argument: bus identifiers and bus message types.
///
/// The `LookupAir` and `AuxBuilder` trait impls live directly on [`crate::ProcessorAir`].
/// The generic LogUp framework this builds on lives in [`crate::lookup`] and is free of
/// Miden-specific types so it can be extracted into its own crate.
pub mod logup {
    pub use crate::constraints::lookup::{
        BusId, MIDEN_MAX_MESSAGE_WIDTH, messages::*, miden_air::NUM_LOGUP_COMMITTED_FINALS,
    };
}

use constraints::{
    columns::MainCols,
    lookup::{
        chiplet_air::{ChipletLookupAir, ChipletLookupBuilder},
        main_air::{MainLookupAir, MainLookupBuilder},
        miden_air::{MIDEN_COLUMN_SHAPE, emit_miden_boundary},
    },
};
use logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH, NUM_LOGUP_COMMITTED_FINALS};
use lookup::{
    BoundaryBuilder, Challenges, ConstraintLookupBuilder, LookupAir, LookupMessage,
    build_logup_aux_trace,
};
use miden_core::utils::RowMajorMatrix;
use trace::TRACE_WIDTH;

// RE-EXPORTS
// ================================================================================================
mod export {
    pub use miden_core::{
        Felt,
        serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
        utils::ToElements,
    };
    pub use miden_crypto::stark::{
        air::{
            AirBuilder, AuxBuilder, BaseAir, ExtensionBuilder, LiftedAir, LiftedAirBuilder,
            PermutationAirBuilder,
        },
        debug,
    };
    pub use miden_lifted_stark::AirWitness;
}

pub use export::*;

// MIDEN AIR BUILDER
// ================================================================================================

/// Convenience super-trait that pins `LiftedAirBuilder` to our field.
///
/// All constraint functions in this crate should be generic over `AB: MidenAirBuilder`
/// instead of spelling out the full `LiftedAirBuilder<F = Felt>` bound.
pub trait MidenAirBuilder: LiftedAirBuilder<F = Felt> {}
impl<T: LiftedAirBuilder<F = Felt>> MidenAirBuilder for T {}

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

    /// Returns the fixed-length public values and the variable-length kernel procedure digests
    /// as a flat slice of `Felt`s.
    ///
    /// The fixed-length public values layout is:
    ///   [0..4]   program hash
    ///   [4..20]  stack inputs
    ///   [20..36] stack outputs
    ///   [36..40] precompile transcript state
    ///
    /// The kernel procedure digests are returned as a single flat `Vec<Felt>` (concatenated
    /// words), to be passed as a single variable-length public input slice to the verifier.
    pub fn to_air_inputs(&self) -> (Vec<Felt>, Vec<Felt>) {
        let mut public_values = Vec::with_capacity(NUM_PUBLIC_VALUES);
        public_values.extend_from_slice(self.program_info.program_hash().as_elements());
        public_values.extend_from_slice(self.stack_inputs.as_ref());
        public_values.extend_from_slice(self.stack_outputs.as_ref());
        public_values.extend_from_slice(self.pc_transcript_state.as_ref());

        let kernel_felts: Vec<Felt> =
            Word::words_as_elements(self.program_info.kernel_procedures()).to_vec();

        (public_values, kernel_felts)
    }

    /// Converts public inputs into a vector of field elements (Felt) in the canonical order:
    /// - program info elements (including kernel procedure hashes)
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

/// Number of fixed-length public values for the Miden VM AIR.
///
/// Layout (40 Felts total):
///   [0..4]   program hash
///   [4..20]  stack inputs
///   [20..36] stack outputs
///   [36..40] precompile transcript state
pub const NUM_PUBLIC_VALUES: usize = WORD_SIZE + MIN_STACK_DEPTH + MIN_STACK_DEPTH + WORD_SIZE;

/// LogUp aux trace width: 4 main-trace columns + 3 chiplet-trace columns.
pub const LOGUP_AUX_TRACE_WIDTH: usize = 7;

// Public values layout offsets.
const PV_PROGRAM_HASH: usize = 0;
const PV_TRANSCRIPT_STATE: usize = NUM_PUBLIC_VALUES - WORD_SIZE;

/// Miden VM Processor AIR implementation.
///
/// Auxiliary trace building is handled separately via [`AuxBuilder`].
///
/// Public-input-dependent boundary checks are performed in [`LiftedAir::reduced_aux_values`].
/// Aux columns are NOT initialized with boundary terms -- they start at identity. The verifier
/// independently computes expected boundary messages from variable length public values and checks
/// them against the final column values.
#[derive(Copy, Clone, Debug, Default)]
pub struct ProcessorAir;

// --- Upstream trait impls for ProcessorAir ---

impl BaseAir<Felt> for ProcessorAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

// --- LiftedAir impl ---

impl<EF: ExtensionField<Felt>> LiftedAir<Felt, EF> for ProcessorAir {
    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        constraints::chiplets::columns::PeriodicCols::periodic_columns()
    }

    fn num_randomness(&self) -> usize {
        trace::AUX_TRACE_RAND_CHALLENGES
    }

    fn aux_width(&self) -> usize {
        // 4 main-trace + 3 chiplet-trace = 7 LogUp columns. Matches
        // `ProcessorAir::num_columns()` (LookupAir impl) and the per-row shape returned by
        // `ProcessorAir::build_aux_trace` (AuxBuilder impl).
        LOGUP_AUX_TRACE_WIDTH
    }

    fn num_aux_values(&self) -> usize {
        NUM_LOGUP_COMMITTED_FINALS
    }

    /// Returns the number of variable-length public input slices.
    ///
    /// The Miden VM AIR uses a single variable-length slice that contains all kernel
    /// procedure digests as concatenated field elements (each digest is `WORD_SIZE`
    /// elements). The verifier framework uses this count to validate that the correct
    /// number of slices is provided.
    fn num_var_len_public_inputs(&self) -> usize {
        1
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
        // LogUp boundary identity. The verifier checks `is_identity()` — i.e.
        // `prod == ONE && sum == ZERO` — on the accumulated `ReducedAuxValues`
        // across every AIR. There are no multiplicative bus checks under LogUp, so
        // `prod = ONE`. The boundary equation lives in `sum`:
        //
        //   sum = Σ aux_finals[col]  +  total_correction
        //
        // `total_correction` cancels the unmatched-fraction contributions from the
        // three open buses (block hash, log precompile, kernel ROM init). Rather
        // than spelling those out here, we drive the shared
        // `emit_miden_boundary` emitter — the same source `LookupAir::eval_boundary`
        // uses for the debug walker — through a reducer that accumulates
        // `Σ multiplicity · encode(msg)⁻¹` into an `EF`.
        if public_values.len() != NUM_PUBLIC_VALUES {
            return Err(format!(
                "expected {} public values, got {}",
                NUM_PUBLIC_VALUES,
                public_values.len()
            )
            .into());
        }
        if var_len_public_inputs.len() != 1 {
            return Err(format!(
                "expected 1 var-len public input slice, got {}",
                var_len_public_inputs.len()
            )
            .into());
        }
        if !var_len_public_inputs[0].len().is_multiple_of(WORD_SIZE) {
            return Err(format!(
                "kernel digest felts length {} is not a multiple of {}",
                var_len_public_inputs[0].len(),
                WORD_SIZE
            )
            .into());
        }

        let challenges = Challenges::<EF>::new(
            challenges[0],
            challenges[1],
            MIDEN_MAX_MESSAGE_WIDTH,
            BusId::COUNT,
        );

        let mut reducer = ReduceBoundaryBuilder {
            challenges: &challenges,
            public_values,
            var_len_public_inputs,
            sum: EF::ZERO,
        };
        emit_miden_boundary(&mut reducer);
        let total_correction = reducer.finalize();

        // TODO(#3032): aux_values[1..] are the placeholder slots from
        // NUM_LOGUP_COMMITTED_FINALS (see `constraints::lookup::miden_air`); enforce the
        // zero invariant until trace splitting lands.
        for unused_aux in aux_values.iter().skip(1) {
            if !unused_aux.is_zero() {
                return Err("padding aux value is non-zero".into());
            }
        }
        let aux_sum: EF = aux_values.iter().copied().sum();

        Ok(ReducedAuxValues {
            prod: EF::ONE,
            sum: aux_sum + total_correction,
        })
    }

    fn eval<AB: MidenAirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();

        // Access the two rows: current (local) and next
        let local = main.current_slice();
        let next = main.next_slice();

        // Use structured column access via MainTraceCols
        let local: &MainCols<AB::Var> = (*local).borrow();
        let next: &MainCols<AB::Var> = (*next).borrow();

        // Build chiplet selectors and op flags once, shared by main and bus constraints.
        let selectors =
            constraints::chiplets::selectors::build_chiplet_selectors(builder, local, next);
        let op_flags =
            constraints::op_flags::OpFlags::new(&local.decoder, &local.stack, &next.decoder);

        // Main trace constraints.
        constraints::enforce_main(builder, local, next, &selectors, &op_flags);

        {
            let mut lb = ConstraintLookupBuilder::new(builder, self);
            <Self as LookupAir<_>>::eval(self, &mut lb);
        }

        // Public inputs boundary constraints.
        constraints::public_inputs::enforce_main(builder, local);
    }

    fn log_quotient_degree(&self) -> usize
    where
        Self: Sized,
    {
        // override to avoid recomputing through the SymbolicAir
        3
    }
}

// --- LookupAir impl (7-column aggregator over main + chiplet sub-AIRs) ---

impl<LB> LookupAir<LB> for ProcessorAir
where
    LB: MainLookupBuilder + ChipletLookupBuilder,
{
    fn num_columns(&self) -> usize {
        MIDEN_COLUMN_SHAPE.len()
    }

    fn column_shape(&self) -> &[usize] {
        &MIDEN_COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        // Width of the `beta_powers` table precomputed by `Challenges::new`, also equal
        // to the exponent of `gamma = beta^MIDEN_MAX_MESSAGE_WIDTH` used in the per-bus
        // prefix. Must match the MASM recursive verifier's Poseidon2 absorption loop.
        // `HasherMsg::State` is the widest live payload at 15 slots (label@β⁰, addr@β¹,
        // node_index@β², state[0..12]@β³..β¹⁴); the 16th slot is unused slack kept for
        // MASM transcript alignment.
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        BusId::COUNT
    }

    fn eval(&self, builder: &mut LB) {
        MainLookupAir.eval(builder);
        ChipletLookupAir.eval(builder);
    }

    fn eval_boundary<B>(&self, boundary: &mut B)
    where
        B: BoundaryBuilder<F = LB::F, EF = LB::EF>,
    {
        emit_miden_boundary(boundary);
    }
}

// --- AuxBuilder impl (stateless LogUp aux-trace construction) ---

impl<EF> AuxBuilder<Felt, EF> for ProcessorAir
where
    EF: ExtensionField<Felt>,
{
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        let (aux_trace, mut committed) = build_logup_aux_trace(self, main, challenges);
        // TODO(#3032): pad the placeholder slot — see `NUM_LOGUP_COMMITTED_FINALS`. Remove
        // the pad once trace splitting lands.
        debug_assert_eq!(
            committed.len(),
            1,
            "build_logup_aux_trace should return exactly one real committed final"
        );
        committed.push(EF::ZERO);
        (aux_trace, committed)
    }
}

// REDUCED-AUX BOUNDARY BUILDER
// ================================================================================================

/// `BoundaryBuilder` impl that reduces each emitted interaction to its LogUp
/// denominator contribution `multiplicity · encode(msg)⁻¹` and sums them into a
/// running `EF` accumulator.
///
/// Lets `reduced_aux_values` reuse the structured boundary emissions from
/// [`emit_miden_boundary`] — the same source consumed by the debug walker —
/// instead of open-coding the three corrections a second time.
///
/// Denominators are `α + Σ βⁱ · field_i` with random `α, β`; on any legitimate proof they
/// are non-zero with overwhelming probability, and the outer quotient check already rejects
/// the degenerate case, so `insert` panics rather than threading an error through the
/// reducer.
struct ReduceBoundaryBuilder<'a, EF: ExtensionField<Felt>> {
    challenges: &'a Challenges<EF>,
    public_values: &'a [Felt],
    var_len_public_inputs: VarLenPublicInputs<'a, Felt>,
    sum: EF,
}

impl<'a, EF: ExtensionField<Felt>> ReduceBoundaryBuilder<'a, EF> {
    fn finalize(self) -> EF {
        self.sum
    }
}

impl<'a, EF: ExtensionField<Felt>> BoundaryBuilder for ReduceBoundaryBuilder<'a, EF> {
    type F = Felt;
    type EF = EF;

    fn public_values(&self) -> &[Felt] {
        self.public_values
    }

    fn var_len_public_inputs(&self) -> &[&[Felt]] {
        self.var_len_public_inputs
    }

    fn insert<M>(&mut self, _name: &'static str, multiplicity: Felt, msg: M)
    where
        M: LookupMessage<Felt, EF>,
    {
        let inv = msg
            .encode(self.challenges)
            .try_inverse()
            .expect("LogUp denominator must be non-zero under random challenges");
        self.sum += inv * multiplicity;
    }
}
