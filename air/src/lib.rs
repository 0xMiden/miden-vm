#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::vec::Vec;
use core::borrow::Borrow;

use miden_core::{
    WORD_SIZE, Word,
    deferred::DeferredRoot,
    field::ExtensionField,
    program::{Kernel, MIN_STACK_DEPTH, ProgramInfo, StackInputs, StackOutputs},
};
use miden_crypto::stark::air::{ReductionError, WindowAccess};
#[cfg(feature = "arbitrary")]
use proptest::prelude::*;

pub mod ace;
pub mod config;
mod constraints;
pub mod lookup;
pub mod trace;

/// Miden VM-specific LogUp lookup argument: bus identifiers and bus message types.
///
/// [`crate::MidenAir`] is the single `LiftedAir`/`LookupAir` for the multi-AIR
/// instance; it dispatches per-trace work to [`crate::CoreAir`] / [`crate::ChipletsAir`].
/// [`crate::MidenMultiAir`] is the `MultiAir` carrying the cross-AIR reduction.
/// The generic LogUp framework this builds on lives in [`crate::lookup`] and is free of
/// Miden-specific types so it can be extracted into its own crate.
pub mod logup {
    pub use crate::constraints::lookup::{
        BusId, MIDEN_MAX_MESSAGE_WIDTH, messages::*, miden_air::NUM_LOGUP_COMMITTED_FINALS,
    };
}

use constraints::lookup::{
    chiplet_air::ChipletLookupBuilder,
    main_air::{MainLookupAir, MainLookupBuilder},
};
pub use constraints::{
    chiplets::columns::{
        AceCols, AceEvalCols, AceReadCols, BitwiseCols, ControllerCols, KernelRomCols, MemoryCols,
        PermutationCols,
    },
    columns::{ChipletCols, CoreCols},
    decoder::columns::DecoderCols,
    ext_field::QuadFeltExpr,
    range::columns::RangeCols,
    stack::columns::StackCols,
    system::columns::SystemCols,
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
        StarkConfig,
        air::{
            AirBuilder, BaseAir, ConstraintDegrees, ExtensionBuilder, LiftedAir, LiftedAirBuilder,
            MultiAir, PermutationAirBuilder, ProverStatement, Statement,
        },
        debug,
    };
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
    deferred_root: DeferredRoot,
}

impl PublicInputs {
    /// Creates a new instance of `PublicInputs` from program information, stack inputs and outputs,
    /// and the deferred root.
    pub fn new(
        program_info: ProgramInfo,
        stack_inputs: StackInputs,
        stack_outputs: StackOutputs,
        deferred_root: DeferredRoot,
    ) -> Self {
        Self {
            program_info,
            stack_inputs,
            stack_outputs,
            deferred_root,
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

    /// Returns the deferred root.
    pub fn deferred_root(&self) -> DeferredRoot {
        self.deferred_root
    }

    /// Returns the fixed-length public values and the variable-length kernel procedure digests
    /// as a flat slice of `Felt`s.
    ///
    /// The fixed-length public values layout is:
    ///   [0..4]   program hash
    ///   [4..20]  stack inputs
    ///   [20..36] stack outputs
    ///   [36..40] deferred root
    ///
    /// The kernel procedure digests are returned as a single flat `Vec<Felt>` (concatenated
    /// words), to be passed as a single variable-length public input slice to the verifier.
    pub fn to_air_inputs(&self) -> (Vec<Felt>, Vec<Felt>) {
        let mut public_values = Vec::with_capacity(NUM_PUBLIC_VALUES);
        public_values.extend_from_slice(self.program_info.program_hash().as_elements());
        public_values.extend_from_slice(self.stack_inputs.as_ref());
        public_values.extend_from_slice(self.stack_outputs.as_ref());
        public_values.extend_from_slice(self.deferred_root.as_ref());

        let kernel_felts: Vec<Felt> =
            Word::words_as_elements(self.program_info.kernel_procedures()).to_vec();

        (public_values, kernel_felts)
    }

    /// Converts public inputs into a vector of field elements (Felt) in the canonical order:
    /// - program info elements (including kernel procedure hashes)
    /// - stack inputs
    /// - stack outputs
    /// - deferred root
    pub fn to_elements(&self) -> Vec<Felt> {
        let mut result = self.program_info.to_elements();
        result.extend_from_slice(self.stack_inputs.as_ref());
        result.extend_from_slice(self.stack_outputs.as_ref());
        result.extend_from_slice(self.deferred_root.as_ref());
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
            .prop_map(|(program_info, stack_inputs, stack_outputs, deferred_root)| {
                Self::new(program_info, stack_inputs, stack_outputs, deferred_root)
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
        self.deferred_root.write_into(target);
    }
}

impl Deserializable for PublicInputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let program_info = ProgramInfo::read_from(source)?;
        let stack_inputs = StackInputs::read_from(source)?;
        let stack_outputs = StackOutputs::read_from(source)?;
        let deferred_root = DeferredRoot::read_from(source)?;

        Ok(PublicInputs {
            program_info,
            stack_inputs,
            stack_outputs,
            deferred_root,
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
///   [36..40] deferred root
pub const NUM_PUBLIC_VALUES: usize = WORD_SIZE + MIN_STACK_DEPTH + MIN_STACK_DEPTH + WORD_SIZE;

/// LogUp aux trace width: 4 main-trace columns + 3 chiplet-trace columns.
pub const LOGUP_AUX_TRACE_WIDTH: usize = 7;

// Public values layout offsets.
const PV_PROGRAM_HASH: usize = 0;
const PV_DEFERRED_ROOT: usize = NUM_PUBLIC_VALUES - WORD_SIZE;

// CORE AIR
// ================================================================================================

/// Core-trace AIR.
///
/// Owns the system, decoder, stack, and range-check segments. Paired with [`ChipletsAir`]
/// for the two-AIR proving path.
#[derive(Copy, Clone, Debug, Default)]
pub struct CoreAir;

impl CoreAir {
    fn width(self) -> usize {
        constraints::columns::NUM_CORE_COLS
    }

    fn periodic_columns(self) -> Vec<Vec<Felt>> {
        // Core has no periodic columns; all periodic columns serve the chiplets.
        Vec::new()
    }

    fn aux_width(self) -> usize {
        constraints::lookup::main_air::MAIN_COLUMN_SHAPE.len()
    }

    /// LogUp boundary correction for the core trace: the running sum of every
    /// boundary interaction reduced to its denominator contribution.
    fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        challenges: &Challenges<EF>,
        public_values: &[Felt],
        var_len_public_inputs: &[&[Felt]],
    ) -> Result<EF, ReductionError> {
        if !var_len_public_inputs.is_empty() {
            return Err(format!(
                "CoreAir expects 0 var-len public input slices, got {}",
                var_len_public_inputs.len()
            )
            .into());
        }

        let mut reducer = ReduceBoundaryBuilder {
            challenges,
            public_values,
            var_len_public_inputs,
            sum: EF::ZERO,
            error: None,
        };
        constraints::lookup::miden_air::emit_core_boundary(&mut reducer);
        reducer.finalize()
    }

    fn eval<AB: MidenAirBuilder>(self, builder: &mut AB) {
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

    fn lookup_num_columns(self) -> usize {
        constraints::lookup::main_air::MAIN_COLUMN_SHAPE.len()
    }

    fn lookup_column_shape(self) -> &'static [usize] {
        &constraints::lookup::main_air::MAIN_COLUMN_SHAPE
    }

    fn lookup_max_message_width(self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn lookup_num_bus_ids(self) -> usize {
        BusId::COUNT
    }

    fn lookup_eval<LB: MainLookupBuilder>(self, builder: &mut LB) {
        MainLookupAir.eval(builder);
    }

    fn lookup_eval_boundary<B: BoundaryBuilder>(self, boundary: &mut B) {
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
    fn width(self) -> usize {
        constraints::columns::NUM_CHIPLETS_COLS
    }

    fn periodic_columns(self) -> Vec<Vec<Felt>> {
        // All periodic columns (hasher round constants, bitwise operation table) belong to
        // the chiplets trace.
        constraints::chiplets::columns::PeriodicCols::periodic_columns()
    }

    fn aux_width(self) -> usize {
        constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE.len()
    }

    /// LogUp boundary correction for the chiplets trace. The kernel digests are
    /// the single var-len public input group; they boundary-cancel against the
    /// kernel-rom bus, which lives on `CHIPLET_COLUMN_SHAPE[0]`. Consumed by
    /// [`MidenMultiAir::eval_external`].
    fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        challenges: &Challenges<EF>,
        public_values: &[Felt],
        var_len_public_inputs: &[&[Felt]],
    ) -> Result<EF, ReductionError> {
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

        let mut reducer = ReduceBoundaryBuilder {
            challenges,
            public_values,
            var_len_public_inputs,
            sum: EF::ZERO,
            error: None,
        };
        constraints::lookup::miden_air::emit_chiplets_boundary(&mut reducer);
        reducer.finalize()
    }

    fn eval<AB: MidenAirBuilder>(self, builder: &mut AB) {
        let main = builder.main();
        let local: &ChipletCols<AB::Var> = (*main.current_slice()).borrow();
        let next: &ChipletCols<AB::Var> = (*main.next_slice()).borrow();

        let selectors =
            constraints::chiplets::selectors::build_chiplet_selectors(builder, local, next);

        constraints::enforce_chiplets(builder, local, next, &selectors);

        let mut lb = ConstraintLookupBuilder::new(builder, &MidenAir::CHIPLETS);
        self.lookup_eval(&mut lb);
    }

    fn lookup_num_columns(self) -> usize {
        constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE.len()
    }

    fn lookup_column_shape(self) -> &'static [usize] {
        &constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE
    }

    fn lookup_max_message_width(self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn lookup_num_bus_ids(self) -> usize {
        BusId::COUNT
    }

    fn lookup_eval<LB: ChipletLookupBuilder>(self, builder: &mut LB) {
        let main = builder.main();
        let local: &ChipletCols<_> = main.current_slice().borrow();
        let next: &ChipletCols<_> = main.next_slice().borrow();

        constraints::lookup::chiplet_air::emit_chiplet_lookup_columns(builder, local, next);
    }

    fn lookup_eval_boundary<B: BoundaryBuilder>(self, boundary: &mut B) {
        constraints::lookup::miden_air::emit_chiplets_boundary(boundary);
    }
}

// MIDEN AIR (multi-AIR enum wrapper)
// ================================================================================================

/// Homogeneous wrapper that lets [`CoreAir`] and [`ChipletsAir`] share a single AIR type.
/// [`MultiAir::Air`](miden_crypto::stark::air::MultiAir) is a single associated type, so every
/// instance in the multi-AIR proof must be the same type; this enum dispatches per-trace work
/// to the inner [`CoreAir`] / [`ChipletsAir`].
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

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        match self {
            Self::Core(a) => a.periodic_columns(),
            Self::Chiplets(a) => a.periodic_columns(),
        }
    }
}

impl<EF: ExtensionField<Felt>> LiftedAir<Felt, EF> for MidenAir {
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

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
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

    fn constraint_degree(&self) -> ConstraintDegrees {
        // All AIRs peak at degree 9 over base-field and extension-field constraints.
        ConstraintDegrees { base: 9, ext: 9 }
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        match self {
            Self::Core(a) => a.eval(builder),
            Self::Chiplets(a) => a.eval(builder),
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

// MIDEN MULTI-AIR
// ================================================================================================

/// The cross-AIR statement for the `(Core, Chiplets)` proof: owns the AIR
/// collection in instance order and carries the LogUp reduction over the
/// committed aux finals.
///
/// Instance order is `[Core, Chiplets]`; every per-AIR slice follows that
/// ordering.
#[derive(Copy, Clone, Debug)]
pub struct MidenMultiAir {
    airs: [MidenAir; 2],
}

impl MidenMultiAir {
    /// Instance-order AIR collection: `[Core, Chiplets]`.
    pub const fn new() -> Self {
        Self {
            airs: [MidenAir::CORE, MidenAir::CHIPLETS],
        }
    }
}

impl Default for MidenMultiAir {
    fn default() -> Self {
        Self::new()
    }
}

impl<EF: ExtensionField<Felt>> MultiAir<Felt, EF> for MidenMultiAir {
    type Air = MidenAir;

    fn airs(&self) -> &[MidenAir] {
        &self.airs
    }

    fn num_air_inputs(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn max_aux_inputs(&self) -> usize {
        // The only var-len public input is the kernel-digest group: one `Word` per
        // kernel procedure, capped at `Kernel::MAX_NUM_PROCEDURES`.
        Kernel::MAX_NUM_PROCEDURES * WORD_SIZE
    }

    /// Cross-AIR LogUp closure: the sum of every committed aux final plus the
    /// per-trace boundary corrections must vanish. `aux_inputs` carries the
    /// kernel digests (the Chiplets var-len public input group).
    fn eval_external(
        &self,
        challenges: &[EF],
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        aux_values: &[&[EF]],
        _log_trace_heights: &[u8],
    ) -> Result<Vec<EF>, ReductionError> {
        let challenges = Challenges::<EF>::new(
            challenges[0],
            challenges[1],
            MIDEN_MAX_MESSAGE_WIDTH,
            BusId::COUNT,
        );

        let core_correction = CoreAir.boundary_correction(&challenges, air_inputs, &[])?;
        let chiplets_correction =
            ChipletsAir.boundary_correction(&challenges, air_inputs, &[aux_inputs])?;

        let aux_sum: EF = aux_values.iter().flat_map(|vals| vals.iter().copied()).sum();
        Ok(vec![aux_sum + core_correction + chiplets_correction])
    }
}

// REDUCED-AUX BOUNDARY BUILDER
// ================================================================================================

/// `BoundaryBuilder` impl that reduces each emitted interaction to its LogUp
/// denominator contribution `multiplicity · encode(msg)⁻¹` and sums them into a
/// running `EF` accumulator.
///
/// Lets the boundary correction reuse the structured boundary emissions from
/// [`emit_miden_boundary`] — the same source consumed by the debug walker —
/// instead of open-coding the three corrections a second time.
///
/// Denominators are `α + Σ βⁱ · field_i` with random `α, β`; on any legitimate proof they
/// are non-zero with overwhelming probability. A malformed/adversarial proof can still
/// drive a denominator to zero, so the reducer captures the first failure and surfaces it
/// as a [`ReductionError`] to the verifier rather than panicking.
struct ReduceBoundaryBuilder<'a, EF: ExtensionField<Felt>> {
    challenges: &'a Challenges<EF>,
    public_values: &'a [Felt],
    var_len_public_inputs: &'a [&'a [Felt]],
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::field::QuadFelt;

    use super::*;

    /// Guards the static `constraint_degree` override: if an AIR change moves the symbolic
    /// degree away from the declared value, the override must be updated.
    #[test]
    fn constraint_degree_override_matches_symbolic() {
        for air in [MidenAir::CORE, MidenAir::CHIPLETS] {
            let symbolic = ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air);
            let declared = <MidenAir as LiftedAir<Felt, QuadFelt>>::constraint_degree(&air);
            assert_eq!(declared, symbolic, "static constraint_degree override is stale");
        }
    }
}
