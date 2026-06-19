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
    program::{Kernel, MIN_STACK_DEPTH, ProgramInfo, StackInputs, StackOutputs},
};
use miden_crypto::stark::{
    air::{ReductionError, WindowAccess},
    challenger::CanObserve,
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

    /// Returns the canonical commitment to the kernel of the verified statement: the value the
    /// recursive verifier observes into the transcript in place of the raw kernel-procedure
    /// digest list. See [`Kernel::commitment`](miden_core::program::Kernel::commitment).
    pub fn kernel_commitment(&self) -> Word {
        self.program_info.kernel_commitment()
    }

    /// Returns the AIR public values (`air_inputs`) and the statement `aux_inputs` as flat
    /// slices of `Felt`s.
    ///
    /// `air_inputs` (the values read by the AIR constraints) layout:
    ///   [0..16]  stack inputs
    ///   [16..32] stack outputs
    ///
    /// `aux_inputs` (statement inputs not read by the AIRs, consumed only by `observe` and
    /// `eval_external`) layout:
    ///   [0..4]   program hash
    ///   [4..8]   precompile transcript state
    ///   [8..]    kernel procedure digests (concatenated words, variable length)
    pub fn to_air_inputs(&self) -> (Vec<Felt>, Vec<Felt>) {
        let mut air_inputs = Vec::with_capacity(NUM_PUBLIC_VALUES);
        air_inputs.extend_from_slice(self.stack_inputs.as_ref());
        air_inputs.extend_from_slice(self.stack_outputs.as_ref());

        let kernel_felts = Word::words_as_elements(self.program_info.kernel_procedures());
        let mut aux_inputs = Vec::with_capacity(AUX_KERNEL_DIGESTS + kernel_felts.len());
        aux_inputs.extend_from_slice(self.program_info.program_hash().as_elements());
        aux_inputs.extend_from_slice(self.pc_transcript_state.as_ref());
        aux_inputs.extend_from_slice(kernel_felts);

        (air_inputs, aux_inputs)
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

/// Number of public values read by the Miden VM AIRs — the `air_inputs` shared by every AIR.
///
/// Layout (32 Felts total):
///   [0..16]  stack inputs
///   [16..32] stack outputs
///
/// The program hash and precompile transcript state are not read by any AIR constraint, so they
/// are carried as `aux_inputs` (see [`AUX_PROGRAM_HASH`] / [`AUX_TRANSCRIPT_STATE`]) and consumed
/// only by [`MidenMultiAir::observe`] and [`MidenMultiAir::eval_external`].
pub const NUM_PUBLIC_VALUES: usize = MIN_STACK_DEPTH + MIN_STACK_DEPTH;

/// LogUp aux trace width: 4 main-trace columns + 3 chiplet-trace columns.
pub const LOGUP_AUX_TRACE_WIDTH: usize = 7;

// `aux_inputs` layout offsets — statement inputs that the AIRs do not read. The fixed program
// hash and transcript state occupy the first two words; the variable-length kernel-procedure
// digests follow.
const AUX_PROGRAM_HASH: usize = 0;
const AUX_TRANSCRIPT_STATE: usize = WORD_SIZE;
const AUX_KERNEL_DIGESTS: usize = 2 * WORD_SIZE;

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
    /// boundary interaction reduced to its denominator contribution. The single var-len slice
    /// carries `[program_hash (4) | transcript_state (4)]`, the statement inputs the core
    /// boundary cancels against the block-hash and log-precompile buses.
    fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        challenges: &Challenges<EF>,
        public_values: &[Felt],
        var_len_public_inputs: &[&[Felt]],
    ) -> Result<EF, ReductionError> {
        if var_len_public_inputs.len() != 1 {
            return Err(format!(
                "CoreAir expects 1 var-len public input slice, got {}",
                var_len_public_inputs.len()
            )
            .into());
        }
        if var_len_public_inputs[0].len() != 2 * WORD_SIZE {
            return Err(format!(
                "CoreAir expects {} boundary felts (program hash + transcript state), got {}",
                2 * WORD_SIZE,
                var_len_public_inputs[0].len()
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
        // aux_inputs = program hash (1 word) + transcript state (1 word) + the var-len
        // kernel-digest group: one `Word` per kernel procedure, capped at
        // `Kernel::MAX_NUM_PROCEDURES`.
        AUX_KERNEL_DIGESTS + Kernel::MAX_NUM_PROCEDURES * WORD_SIZE
    }

    /// Absorb statement-owned public inputs into the Fiat-Shamir challenger.
    ///
    /// Replaces the default length-prefixed stream with a rate-aligned schedule (six 8-felt
    /// blocks, 48 felts total) that the recursive verifier mirrors:
    ///
    /// ```text
    /// [ kernel_H (4) | program_hash (4) ]
    /// [ transcript_state (4) | 0,0,0,0 ]      trailing pad keeps the schedule rate-aligned
    /// [ stack_inputs (16) ]                   two blocks
    /// [ stack_outputs (16) ]                  two blocks
    /// ```
    ///
    /// The kernel digests enter the transcript only through `kernel_H`
    /// (see [`hash_kernel_digests`]), committing to the kernel with a fixed-size value instead
    /// of the unbounded digest list.
    fn observe<C: CanObserve<Felt>>(
        &self,
        challenger: &mut C,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        _log_trace_heights: &[u8],
    ) {
        assert_eq!(air_inputs.len(), NUM_PUBLIC_VALUES, "unexpected public-value count");
        assert!(
            aux_inputs.len() >= AUX_KERNEL_DIGESTS,
            "aux inputs shorter than the fixed program-hash + transcript-state prefix"
        );

        let kernel_h = hash_kernel_digests(&aux_inputs[AUX_KERNEL_DIGESTS..]);
        let program_hash = &aux_inputs[AUX_PROGRAM_HASH..AUX_PROGRAM_HASH + WORD_SIZE];
        let transcript_state = &aux_inputs[AUX_TRANSCRIPT_STATE..AUX_TRANSCRIPT_STATE + WORD_SIZE];
        let stack_io = air_inputs;

        // Block 1: kernel_H | program_hash. Block 2: transcript_state | zero pad.
        for &v in kernel_h.iter().chain(program_hash) {
            challenger.observe(v);
        }
        for &v in transcript_state {
            challenger.observe(v);
        }
        for _ in 0..WORD_SIZE {
            challenger.observe(Felt::ZERO);
        }
        for &v in stack_io {
            challenger.observe(v);
        }
    }

    /// Cross-AIR LogUp closure: the sum of every committed aux final plus the
    /// per-trace boundary corrections must vanish. `aux_inputs` carries the program hash and
    /// transcript state (consumed by the core boundary) followed by the kernel digests
    /// (consumed by the chiplets boundary).
    fn eval_external(
        &self,
        challenges: &[EF],
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        aux_values: &[&[EF]],
        _log_trace_heights: &[u8],
    ) -> Result<Vec<EF>, ReductionError> {
        if aux_inputs.len() < AUX_KERNEL_DIGESTS {
            return Err(format!(
                "aux_inputs length {} is shorter than the fixed prefix {AUX_KERNEL_DIGESTS}",
                aux_inputs.len()
            )
            .into());
        }
        let challenges = Challenges::<EF>::new(
            challenges[0],
            challenges[1],
            MIDEN_MAX_MESSAGE_WIDTH,
            BusId::COUNT,
        );

        let core_correction = CoreAir.boundary_correction(
            &challenges,
            air_inputs,
            &[&aux_inputs[..AUX_KERNEL_DIGESTS]],
        )?;
        let chiplets_correction = ChipletsAir.boundary_correction(
            &challenges,
            air_inputs,
            &[&aux_inputs[AUX_KERNEL_DIGESTS..]],
        )?;

        let aux_sum: EF = aux_values.iter().flat_map(|vals| vals.iter().copied()).sum();
        Ok(vec![aux_sum + core_correction + chiplets_correction])
    }
}

// KERNEL DIGEST SUMMARY HASH
// ================================================================================================

/// Computes `kernel_H`, the fixed-size commitment to the kernel-procedure digests.
///
/// This is the canonical [`Kernel::commitment`] value expressed over the flattened digest
/// felts: the linear hash (`hash_elements`) of `kernel_felts`. The empty digest list yields
/// `hash_elements(&[])`.
///
/// `kernel_H` is absorbed into the Fiat-Shamir transcript in place of the unbounded kernel
/// digest list, committing to the kernel with a fixed-size value.
pub fn hash_kernel_digests(kernel_felts: &[Felt]) -> [Felt; WORD_SIZE] {
    assert!(
        kernel_felts.len().is_multiple_of(WORD_SIZE),
        "kernel digest felts must be whole words"
    );

    miden_core::chiplets::hasher::hash_elements(kernel_felts).into()
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
