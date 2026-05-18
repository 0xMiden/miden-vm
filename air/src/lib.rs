#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::vec::Vec;
use core::borrow::Borrow;

#[cfg(feature = "arbitrary")]
use miden_core::program::Kernel;
use miden_core::{
    WORD_SIZE, Word,
    field::ExtensionField,
    precompile::PrecompileTranscriptState,
    program::{MIN_STACK_DEPTH, ProgramInfo, StackInputs, StackOutputs},
};
use miden_crypto::stark::air::{
    ReducedAuxValues, ReductionError, VarLenPublicInputs, WindowAccess,
};
#[cfg(feature = "arbitrary")]
use proptest::prelude::*;

pub mod ace;
pub mod config;
mod constraints;
pub mod lookup;
pub mod trace;

/// Miden VM-specific LogUp lookup argument: bus identifiers and bus message types.
///
/// [`crate::MidenAir`] is the single `LiftedAir`/`AuxBuilder`/`LookupAir` for the multi-AIR
/// instance; it dispatches per-trace work to [`crate::CoreAir`] / [`crate::ChipletsAir`].
/// The generic LogUp framework this builds on lives in [`crate::lookup`] and is free of
/// Miden-specific types so it can be extracted into its own crate.
pub mod logup {
    pub use crate::constraints::lookup::{
        BusId, MIDEN_MAX_MESSAGE_WIDTH, messages::*, miden_air::NUM_LOGUP_COMMITTED_FINALS,
    };
}

use constraints::{
    columns::{ChipletCols, CoreCols},
    lookup::{
        chiplet_air::ChipletLookupBuilder,
        main_air::{MainLookupAir, MainLookupBuilder},
    },
};
use logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH};
use lookup::{
    BoundaryBuilder, Challenges, ConstraintLookupBuilder, LookupAir, LookupMessage,
    build_logup_aux_trace,
};
use miden_core::utils::RowMajorMatrix;

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
    pub use miden_lifted_stark::{AirInstance, AirWitness, InstanceShapes};
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
pub struct PublicInputs {
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    pc_transcript_state: PrecompileTranscriptState,
}

impl PublicInputs {
    /// Creates a new instance of `PublicInputs` from program information, stack inputs and outputs,
    /// and the precompile transcript state (rolling digest of all recorded commitments).
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

#[cfg(feature = "arbitrary")]
impl Arbitrary for PublicInputs {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        fn felt_strategy() -> impl Strategy<Value = Felt> {
            any::<u32>().prop_map(Felt::from)
        }

        fn word_strategy() -> impl Strategy<Value = Word> {
            any::<[u32; WORD_SIZE]>().prop_map(|values| Word::new(values.map(Felt::from)))
        }

        let program_info = word_strategy()
            .prop_map(|program_hash| ProgramInfo::new(program_hash, Kernel::default()));
        let stack_inputs = proptest::collection::vec(felt_strategy(), 0..=MIN_STACK_DEPTH)
            .prop_map(|values| StackInputs::new(&values).expect("generated stack inputs fit"));
        let stack_outputs = proptest::collection::vec(felt_strategy(), 0..=MIN_STACK_DEPTH)
            .prop_map(|values| StackOutputs::new(&values).expect("generated stack outputs fit"));

        (program_info, stack_inputs, stack_outputs, word_strategy())
            .prop_map(|(program_info, stack_inputs, stack_outputs, pc_transcript_state)| {
                Self::new(program_info, stack_inputs, stack_outputs, pc_transcript_state)
            })
            .boxed()
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

// CORE AIR
// ================================================================================================

/// Core-trace AIR.
///
/// Owns the system, decoder, stack, and range-check segments. Paired with [`ChipletsAir`]
/// for the two-AIR proving path.
#[derive(Copy, Clone, Debug, Default)]
pub struct CoreAir;

impl CoreAir {
    fn width(&self) -> usize {
        constraints::columns::NUM_CORE_COLS
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        // Core has no periodic columns; all periodic columns serve the chiplets.
        Vec::new()
    }

    fn aux_width(&self) -> usize {
        constraints::lookup::main_air::MAIN_COLUMN_SHAPE.len()
    }

    fn num_var_len_public_inputs(&self) -> usize {
        // Kernel digests (the only VLPI today) belong to ChipletsAir's reduced_aux_values.
        0
    }

    fn reduced_aux_values<EF: ExtensionField<Felt>>(
        &self,
        aux_values: &[EF],
        challenges: &[EF],
        public_values: &[Felt],
        var_len_public_inputs: VarLenPublicInputs<'_, Felt>,
    ) -> Result<ReducedAuxValues<EF>, ReductionError> {
        if public_values.len() != NUM_PUBLIC_VALUES {
            return Err(format!(
                "expected {} public values, got {}",
                NUM_PUBLIC_VALUES,
                public_values.len()
            )
            .into());
        }
        if !var_len_public_inputs.is_empty() {
            return Err(format!(
                "CoreAir expects 0 var-len public input slices, got {}",
                var_len_public_inputs.len()
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
            error: None,
        };
        constraints::lookup::miden_air::emit_core_boundary(&mut reducer);
        let total_correction = reducer.finalize()?;

        let aux_sum: EF = aux_values.iter().copied().sum();
        Ok(ReducedAuxValues {
            prod: EF::ONE,
            sum: aux_sum + total_correction,
        })
    }

    fn eval<AB: MidenAirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &CoreCols<AB::Var> = (*main.current_slice()).borrow();
        let next: &CoreCols<AB::Var> = (*main.next_slice()).borrow();

        let op_flags =
            constraints::op_flags::OpFlags::new(&local.decoder, &local.stack, &next.decoder);

        constraints::enforce_core(builder, local, next, &op_flags);
        constraints::public_inputs::enforce_main(builder, local);

        let mut lb = ConstraintLookupBuilder::new(builder, &MidenAir::CORE);
        self.lookup_eval(&mut lb);
    }

    fn log_quotient_degree(&self) -> usize {
        // Core dominates the combined quotient degree; override to avoid recomputing
        // through SymbolicAir.
        3
    }

    fn lookup_num_columns(&self) -> usize {
        constraints::lookup::main_air::MAIN_COLUMN_SHAPE.len()
    }

    fn lookup_column_shape(&self) -> &'static [usize] {
        &constraints::lookup::main_air::MAIN_COLUMN_SHAPE
    }

    fn lookup_max_message_width(&self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn lookup_num_bus_ids(&self) -> usize {
        BusId::COUNT
    }

    fn lookup_eval<LB: MainLookupBuilder>(&self, builder: &mut LB) {
        MainLookupAir.eval(builder);
    }

    fn lookup_eval_boundary<B: BoundaryBuilder>(&self, boundary: &mut B) {
        constraints::lookup::miden_air::emit_core_boundary(boundary);
    }
}

// CHIPLETS AIR
// ================================================================================================

/// Chiplets-trace AIR for the multi-AIR proving path.
///
/// Owns the chiplet section and its LogUp accumulator columns. Counterpart to [`CoreAir`].
#[derive(Copy, Clone, Debug, Default)]
pub struct ChipletsAir;

/// Per-trace AIR logic. Like [`CoreAir`], `ChipletsAir` is not an AIR trait impl itself —
/// [`MidenAir`] dispatches to these inherent (struct) methods for per-trace concerns.
impl ChipletsAir {
    fn width(&self) -> usize {
        constraints::columns::NUM_CHIPLETS_COLS
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        // All periodic columns (hasher round constants, bitwise operation table) belong to
        // the chiplets trace.
        constraints::chiplets::columns::PeriodicCols::periodic_columns()
    }

    fn aux_width(&self) -> usize {
        constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE.len()
    }

    fn num_var_len_public_inputs(&self) -> usize {
        // Kernel digests boundary-cancel against the kernel-rom bus, which lives on
        // `CHIPLET_COLUMN_SHAPE[0]` — owned by ChipletsAir.
        1
    }

    fn reduced_aux_values<EF: ExtensionField<Felt>>(
        &self,
        aux_values: &[EF],
        challenges: &[EF],
        public_values: &[Felt],
        var_len_public_inputs: VarLenPublicInputs<'_, Felt>,
    ) -> Result<ReducedAuxValues<EF>, ReductionError> {
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
                "ChipletsAir expects 1 var-len public input slice, got {}",
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
            error: None,
        };
        constraints::lookup::miden_air::emit_chiplets_boundary(&mut reducer);
        let total_correction = reducer.finalize()?;

        let aux_sum: EF = aux_values.iter().copied().sum();
        Ok(ReducedAuxValues {
            prod: EF::ONE,
            sum: aux_sum + total_correction,
        })
    }

    fn eval<AB: MidenAirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &ChipletCols<AB::Var> = (*main.current_slice()).borrow();
        let next: &ChipletCols<AB::Var> = (*main.next_slice()).borrow();

        let selectors =
            constraints::chiplets::selectors::build_chiplet_selectors(builder, local, next);

        constraints::enforce_chiplets(builder, local, next, &selectors);

        let mut lb = ConstraintLookupBuilder::new(builder, &MidenAir::CHIPLETS);
        self.lookup_eval(&mut lb);
    }

    fn log_quotient_degree(&self) -> usize {
        // The chiplet hasher dominates this AIR's quotient degree at deg 9 / log_blowup 3;
        // override to avoid recomputing through SymbolicAir.
        3
    }

    fn lookup_num_columns(&self) -> usize {
        constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE.len()
    }

    fn lookup_column_shape(&self) -> &'static [usize] {
        &constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE
    }

    fn lookup_max_message_width(&self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn lookup_num_bus_ids(&self) -> usize {
        BusId::COUNT
    }

    fn lookup_eval<LB: ChipletLookupBuilder>(&self, builder: &mut LB) {
        let main = builder.main();
        let local: &ChipletCols<_> = main.current_slice().borrow();
        let next: &ChipletCols<_> = main.next_slice().borrow();

        constraints::lookup::chiplet_air::emit_chiplet_lookup_columns(builder, local, next);
    }

    fn lookup_eval_boundary<B: BoundaryBuilder>(&self, boundary: &mut B) {
        constraints::lookup::miden_air::emit_chiplets_boundary(boundary);
    }
}

// MIDEN AIR (multi-AIR enum wrapper)
// ================================================================================================

/// Homogeneous wrapper that lets [`CoreAir`] and [`ChipletsAir`] share a single trait-object
/// type for `prove_multi`/`verify_multi`. Upstream's `prove_multi<F, EF, A, B, SC>` takes
/// `&[(&A, AirWitness, &B)]` — both `A` (the AIR) and `B` (the aux builder) must be the same
/// type across all instances, so we dispatch through this enum.
#[derive(Copy, Clone, Debug)]
pub enum MidenAir {
    Core(CoreAir),
    Chiplets(ChipletsAir),
}

impl MidenAir {
    pub const CORE: Self = Self::Core(CoreAir);
    pub const CHIPLETS: Self = Self::Chiplets(ChipletsAir);
}

impl BaseAir<Felt> for MidenAir {
    fn width(&self) -> usize {
        match self {
            Self::Core(a) => a.width(),
            Self::Chiplets(a) => a.width(),
        }
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl<EF: ExtensionField<Felt>> LiftedAir<Felt, EF> for MidenAir {
    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        match self {
            Self::Core(a) => a.periodic_columns(),
            Self::Chiplets(a) => a.periodic_columns(),
        }
    }

    fn num_randomness(&self) -> usize {
        // Instance-level: every AIR shares the same LogUp challenge set.
        trace::AUX_TRACE_RAND_CHALLENGES
    }

    fn aux_width(&self) -> usize {
        match self {
            Self::Core(a) => a.aux_width(),
            Self::Chiplets(a) => a.aux_width(),
        }
    }

    fn num_aux_values(&self) -> usize {
        // One real committed LogUp final per AIR instance.
        1
    }

    fn num_var_len_public_inputs(&self) -> usize {
        // Conceptually instance-level, but the count is still per-trace today (Core 0,
        // Chiplets 1): the only VLPI — the kernel-digest group — boundary-cancels against
        // a Chiplets column. Collapses to a single instance-level value once the
        // `Instance`/`PublicInputs` trait lands.
        match self {
            Self::Core(a) => a.num_var_len_public_inputs(),
            Self::Chiplets(a) => a.num_var_len_public_inputs(),
        }
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
        match self {
            Self::Core(a) => {
                a.reduced_aux_values(aux_values, challenges, public_values, var_len_public_inputs)
            },
            Self::Chiplets(a) => {
                a.reduced_aux_values(aux_values, challenges, public_values, var_len_public_inputs)
            },
        }
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        match self {
            Self::Core(a) => a.eval(builder),
            Self::Chiplets(a) => a.eval(builder),
        }
    }

    fn log_quotient_degree(&self) -> usize
    where
        Self: Sized,
    {
        match self {
            Self::Core(a) => a.log_quotient_degree(),
            Self::Chiplets(a) => a.log_quotient_degree(),
        }
    }
}

impl<LB> LookupAir<LB> for MidenAir
where
    LB: MainLookupBuilder + ChipletLookupBuilder,
{
    fn num_columns(&self) -> usize {
        match self {
            Self::Core(a) => a.lookup_num_columns(),
            Self::Chiplets(a) => a.lookup_num_columns(),
        }
    }

    fn column_shape(&self) -> &[usize] {
        match self {
            Self::Core(a) => a.lookup_column_shape(),
            Self::Chiplets(a) => a.lookup_column_shape(),
        }
    }

    fn max_message_width(&self) -> usize {
        match self {
            Self::Core(a) => a.lookup_max_message_width(),
            Self::Chiplets(a) => a.lookup_max_message_width(),
        }
    }

    fn num_bus_ids(&self) -> usize {
        match self {
            Self::Core(a) => a.lookup_num_bus_ids(),
            Self::Chiplets(a) => a.lookup_num_bus_ids(),
        }
    }

    fn eval(&self, builder: &mut LB) {
        match self {
            Self::Core(a) => a.lookup_eval(builder),
            Self::Chiplets(a) => a.lookup_eval(builder),
        }
    }

    fn eval_boundary<B>(&self, boundary: &mut B)
    where
        B: BoundaryBuilder<F = LB::F, EF = LB::EF>,
    {
        match self {
            Self::Core(a) => a.lookup_eval_boundary(boundary),
            Self::Chiplets(a) => a.lookup_eval_boundary(boundary),
        }
    }
}

impl<EF> AuxBuilder<Felt, EF> for MidenAir
where
    EF: ExtensionField<Felt>,
{
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        let (aux_trace, committed) = build_logup_aux_trace(self, main, challenges);
        debug_assert_eq!(
            committed.len(),
            1,
            "build_logup_aux_trace returns one committed final per AIR (col 0's terminal sum)"
        );
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
/// are non-zero with overwhelming probability. A malformed/adversarial proof can still
/// drive a denominator to zero, so the reducer captures the first failure and surfaces it
/// to `reduced_aux_values`, which bubbles a [`ReductionError`] to the verifier rather than
/// panicking.
struct ReduceBoundaryBuilder<'a, EF: ExtensionField<Felt>> {
    challenges: &'a Challenges<EF>,
    public_values: &'a [Felt],
    var_len_public_inputs: VarLenPublicInputs<'a, Felt>,
    sum: EF,
    error: Option<ReductionError>,
}

impl<'a, EF: ExtensionField<Felt>> ReduceBoundaryBuilder<'a, EF> {
    fn finalize(self) -> Result<EF, ReductionError> {
        match self.error {
            Some(err) => Err(err),
            None => Ok(self.sum),
        }
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
        if self.error.is_some() {
            return;
        }
        match msg.encode(self.challenges).try_inverse() {
            Some(inv) => self.sum += inv * multiplicity,
            None => {
                self.error = Some("LogUp boundary denominator was zero".into());
            },
        }
    }
}
