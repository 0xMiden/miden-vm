#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{string::String, vec::Vec};
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
/// [`crate::MidenAir`] is the single `LiftedAir`/`LookupAir` type for the multi-AIR
/// statement; it dispatches per-trace work to Core, Chiplets, and Poseidon2 permutation AIRs.
/// [`crate::MidenMultiAir`] is the `MultiAir` carrying the cross-AIR reduction.
/// The generic LogUp framework lives in [`crate::lookup`].
pub mod logup {
    pub use crate::constraints::lookup::{
        BusId, MIDEN_MAX_MESSAGE_WIDTH, messages::*, miden_air::NUM_LOGUP_COMMITTED_FINALS,
    };
}

use constraints::lookup::{
    chiplet_air::ChipletLookupBuilder,
    main_air::{MainLookupAir, MainLookupBuilder},
    poseidon2_permutation_air::Poseidon2PermutationLookupBuilder,
};
pub use constraints::{
    chiplets::columns::{
        AceCols, AceEvalCols, AceReadCols, BitwiseCols, ControllerCols, KernelRomCols, MemoryCols,
    },
    columns::{ChipletCols, CoreCols},
    decoder::columns::DecoderCols,
    ext_field::QuadFeltExpr,
    poseidon2_permutation::columns::{
        CYCLE_INPUT_ROW, CYCLE_OUTPUT_ROW, INITIAL_EXTERNAL_ROUND_END,
        INITIAL_EXTERNAL_ROUND_START, INTERNAL_PLUS_EXTERNAL_ROW, LAST_INTERNAL_ROUND_ARK_IDX,
        NUM_PACKED_INTERNAL_ROUND_ROWS, NUM_SBOX_WITNESSES, NUM_TRAILING_EXTERNAL_ROUND_ROWS,
        PACKED_INTERNAL_ROUND_START, Poseidon2PermutationCols, Poseidon2PermutationPeriodicCols,
    },
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

/// Convenience super-trait that pins `LiftedAirBuilder` to the Miden base field.
///
/// Constraint functions use `AB: MidenAirBuilder` instead of the longer
/// `LiftedAirBuilder<F = Felt>` bound.
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

    /// Returns the canonical commitment to the kernel of the verified statement.
    ///
    /// This fixed-size word replaces the raw kernel-procedure digest list in Fiat-Shamir
    /// observation. See [`Kernel::commitment`](miden_core::program::Kernel::commitment).
    pub fn kernel_commitment(&self) -> Word {
        self.program_info.kernel_commitment()
    }

    /// Returns the AIR public values (`air_inputs`) and statement inputs (`aux_inputs`).
    ///
    /// `air_inputs` (the values read by the AIR constraints) layout:
    ///   [0..16]  stack inputs
    ///   [16..32] stack outputs
    ///
    /// `aux_inputs` (statement inputs not read by the AIRs, consumed only by `observe` and
    /// `eval_external`) layout:
    ///   [0..4]   program hash
    ///   [4..8]   precompile transcript state
    ///   [8..]    kernel procedure digests (one word per kernel procedure)
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

/// Number of public values read by the Miden VM AIRs: the `air_inputs` shared by every AIR.
///
/// Layout (32 Felts total):
///   [0..16]  stack inputs
///   [16..32] stack outputs
///
/// The program hash and precompile transcript state are not read by any AIR constraint, so they
/// are carried as `aux_inputs` and consumed only by [`MidenMultiAir::observe`] and
/// [`MidenMultiAir::eval_external`].
pub const NUM_PUBLIC_VALUES: usize = MIN_STACK_DEPTH + MIN_STACK_DEPTH;

/// LogUp aux trace width: 4 core columns + 3 chiplet columns + 1 Poseidon2 column.
pub const LOGUP_AUX_TRACE_WIDTH: usize = 8;

// `aux_inputs` layout offsets: statement inputs that the AIRs do not read. The fixed program
// hash and transcript state occupy the first two words; the kernel-procedure digest list follows.
const AUX_PROGRAM_HASH: usize = 0;
const AUX_TRANSCRIPT_STATE: usize = WORD_SIZE;
const AUX_KERNEL_DIGESTS: usize = 2 * WORD_SIZE;

// CORE AIR
// ================================================================================================

/// Core trace AIR.
///
/// Enforces the system, decoder, stack, and range-check constraints.
#[derive(Copy, Clone, Debug, Default)]
pub struct CoreAir;

impl CoreAir {
    fn width(self) -> usize {
        constraints::columns::NUM_CORE_COLS
    }

    fn periodic_columns(self) -> Vec<Vec<Felt>> {
        Vec::new()
    }

    fn aux_width(self) -> usize {
        constraints::lookup::main_air::MAIN_COLUMN_SHAPE.len()
    }

    /// LogUp boundary correction for the core trace.
    ///
    /// The boundary input slice is `[program_hash (4) | transcript_state (4)]`; these statement
    /// values close the block-hash and log-precompile buses.
    fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        challenges: &Challenges<EF>,
        public_values: &[Felt],
        boundary_inputs: &[&[Felt]],
    ) -> Result<EF, ReductionError> {
        if boundary_inputs.len() != 1 {
            return Err(format!(
                "CoreAir expects 1 boundary input slice, got {}",
                boundary_inputs.len()
            )
            .into());
        }
        if boundary_inputs[0].len() != 2 * WORD_SIZE {
            return Err(format!(
                "CoreAir expects {} boundary felts (program hash + transcript state), got {}",
                2 * WORD_SIZE,
                boundary_inputs[0].len()
            )
            .into());
        }

        let mut reducer = ReduceBoundaryBuilder {
            challenges,
            public_values,
            var_len_public_inputs: boundary_inputs,
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

        let mut lb = ConstraintLookupBuilder::new(builder, &MidenAir::Core);
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

/// Chiplets trace AIR.
///
/// Enforces the chiplet selector hierarchy, chiplet transition constraints, and
/// chiplet-side LogUp buses.
#[derive(Copy, Clone, Debug, Default)]
pub struct ChipletsAir;

impl ChipletsAir {
    fn width(self) -> usize {
        constraints::columns::NUM_CHIPLETS_COLS
    }

    fn periodic_columns(self) -> Vec<Vec<Felt>> {
        constraints::chiplets::columns::PeriodicCols::periodic_columns()
    }

    fn aux_width(self) -> usize {
        constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE.len()
    }

    /// LogUp boundary correction for the chiplets trace.
    ///
    /// The boundary input slice contains the kernel-procedure digests; these statement values
    /// close the kernel-ROM bus.
    fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        challenges: &Challenges<EF>,
        public_values: &[Felt],
        boundary_inputs: &[&[Felt]],
    ) -> Result<EF, ReductionError> {
        if boundary_inputs.len() != 1 {
            return Err(format!(
                "ChipletsAir expects 1 boundary input slice, got {}",
                boundary_inputs.len()
            )
            .into());
        }
        if !boundary_inputs[0].len().is_multiple_of(WORD_SIZE) {
            return Err(format!(
                "kernel digest felts length {} is not a multiple of {}",
                boundary_inputs[0].len(),
                WORD_SIZE
            )
            .into());
        }

        let mut reducer = ReduceBoundaryBuilder {
            challenges,
            public_values,
            var_len_public_inputs: boundary_inputs,
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

        let mut lb = ConstraintLookupBuilder::new(builder, &MidenAir::Chiplets);
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

// POSEIDON2 PERMUTATION AIR
// ================================================================================================

/// Poseidon2 permutation trace AIR.
///
/// Enforces 16-row permutation cycles and the permutation-side LogUp bus.
#[derive(Copy, Clone, Debug, Default)]
pub struct Poseidon2PermutationAir;

impl Poseidon2PermutationAir {
    fn width(self) -> usize {
        constraints::poseidon2_permutation::columns::NUM_POSEIDON2_PERMUTATION_COLS
    }

    fn periodic_columns(self) -> Vec<Vec<Felt>> {
        Poseidon2PermutationPeriodicCols::periodic_columns()
    }

    fn aux_width(self) -> usize {
        constraints::lookup::poseidon2_permutation_air::POSEIDON2_PERMUTATION_COLUMN_SHAPE.len()
    }

    fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        _challenges: &Challenges<EF>,
        _public_values: &[Felt],
        boundary_inputs: &[&[Felt]],
    ) -> Result<EF, ReductionError> {
        if !boundary_inputs.is_empty() {
            return Err(format!(
                "Poseidon2PermutationAir expects 0 boundary input slices, got {}",
                boundary_inputs.len()
            )
            .into());
        }
        Ok(EF::ZERO)
    }

    fn eval<AB: MidenAirBuilder>(self, builder: &mut AB) {
        constraints::enforce_poseidon2_permutation(builder);

        let mut lb = ConstraintLookupBuilder::new(builder, &MidenAir::Poseidon2Permutation);
        self.lookup_eval(&mut lb);
    }

    fn lookup_num_columns(self) -> usize {
        constraints::lookup::poseidon2_permutation_air::POSEIDON2_PERMUTATION_COLUMN_SHAPE.len()
    }

    fn lookup_column_shape(self) -> &'static [usize] {
        &constraints::lookup::poseidon2_permutation_air::POSEIDON2_PERMUTATION_COLUMN_SHAPE
    }

    fn lookup_max_message_width(self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn lookup_num_bus_ids(self) -> usize {
        BusId::COUNT
    }

    fn lookup_eval<LB: Poseidon2PermutationLookupBuilder>(self, builder: &mut LB) {
        let main = builder.main();
        let local: &Poseidon2PermutationCols<_> = main.current_slice().borrow();

        constraints::lookup::poseidon2_permutation_air::emit_poseidon2_permutation_lookup_columns(
            builder, local,
        );
    }

    fn lookup_eval_boundary<B: BoundaryBuilder>(self, _boundary: &mut B) {}
}

// MIDEN AIR
// ================================================================================================

/// AIR instance identifier for the Miden multi-AIR statement.
///
/// [`MultiAir::Air`](miden_crypto::stark::air::MultiAir) is a single associated type, so every
/// instance in the multi-AIR proof must have the same type. This enum identifies which concrete
/// AIR logic to dispatch to.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MidenAir {
    Core,
    Chiplets,
    Poseidon2Permutation,
}

impl MidenAir {
    pub const fn instance_index(self) -> usize {
        match self {
            Self::Core => 0,
            Self::Chiplets => 1,
            Self::Poseidon2Permutation => 2,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Core => "Core",
            Self::Chiplets => "Chiplets",
            Self::Poseidon2Permutation => "Poseidon2Permutation",
        }
    }

    pub const fn file_token(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Chiplets => "chiplets",
            Self::Poseidon2Permutation => "poseidon2_permutation",
        }
    }

    fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        challenges: &Challenges<EF>,
        public_values: &[Felt],
        aux_inputs: &[Felt],
    ) -> Result<EF, ReductionError> {
        if aux_inputs.len() < AUX_KERNEL_DIGESTS {
            return Err(format!(
                "aux_inputs length {} is shorter than the fixed prefix {AUX_KERNEL_DIGESTS}",
                aux_inputs.len()
            )
            .into());
        }

        match self {
            Self::Core => CoreAir.boundary_correction(
                challenges,
                public_values,
                &[&aux_inputs[..AUX_KERNEL_DIGESTS]],
            ),
            Self::Chiplets => ChipletsAir.boundary_correction(
                challenges,
                public_values,
                &[&aux_inputs[AUX_KERNEL_DIGESTS..]],
            ),
            Self::Poseidon2Permutation => {
                Poseidon2PermutationAir.boundary_correction(challenges, public_values, &[])
            },
        }
    }
}

/// Supported AIRs in instance order.
///
/// This order is used for per-AIR inputs and breaks proof-order ties when trace heights are equal.
pub const AIRS: [MidenAir; 3] =
    [MidenAir::Core, MidenAir::Chiplets, MidenAir::Poseidon2Permutation];

pub const MIDEN_AIR_COUNT: usize = AIRS.len();

/// Number of possible proof-order permutations.
pub const PROOF_ORDER_COUNT: usize = factorial(MIDEN_AIR_COUNT);
const _: () = assert!(PROOF_ORDER_COUNT <= u32::MAX as usize, "proof-order tags must fit in u32");

/// Smallest Merkle tree depth covering every proof-order tag.
pub const PROOF_ORDER_REGISTRY_DEPTH: usize = ceil_log2(PROOF_ORDER_COUNT);

const fn factorial(n: usize) -> usize {
    let mut result = 1;
    let mut factor = 2;
    while factor <= n {
        result *= factor;
        factor += 1;
    }
    result
}

const fn ceil_log2(value: usize) -> usize {
    assert!(value > 0, "ceil_log2 is undefined for zero");

    let mut value = value - 1;
    let mut result = 0;
    while value > 0 {
        value >>= 1;
        result += 1;
    }
    result
}

/// Proof-order AIR permutation.
///
/// Proof order is sorted by `(log_trace_height, instance_index)`. The tag is the Lehmer rank of
/// that permutation relative to [`AIRS`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofOrder {
    airs: [MidenAir; MIDEN_AIR_COUNT],
    tag: u32,
}

impl ProofOrder {
    pub fn new(airs: [MidenAir; MIDEN_AIR_COUNT]) -> Self {
        assert_is_air_permutation(&airs);
        let tag = lehmer_rank(&airs);
        Self { airs, tag }
    }

    pub fn from_airs(airs: &[MidenAir]) -> Self {
        let Ok(airs) = airs.try_into() else {
            panic!("proof order must include every AIR exactly once");
        };
        Self::new(airs)
    }

    pub fn instance_order() -> Self {
        Self::new(AIRS)
    }

    pub fn variants() -> Vec<Self> {
        (0..PROOF_ORDER_COUNT).map(Self::from_rank).collect()
    }

    pub fn from_tag(tag: u32) -> Option<Self> {
        let rank = tag as usize;
        (rank < PROOF_ORDER_COUNT).then(|| Self::from_rank(rank))
    }

    pub fn from_instance_log_heights(log_heights: &[u8]) -> Self {
        assert_eq!(log_heights.len(), AIRS.len(), "one log height is required per AIR");

        let mut ordered: Vec<(MidenAir, u8)> =
            AIRS.iter().copied().zip(log_heights.iter().copied()).collect();
        ordered.sort_by_key(|(air, height)| (*height, air.instance_index()));

        let mut airs = [AIRS[0]; MIDEN_AIR_COUNT];
        for (dst, (air, _)) in airs.iter_mut().zip(ordered) {
            *dst = air;
        }
        Self::new(airs)
    }

    pub fn airs(&self) -> &[MidenAir] {
        &self.airs
    }

    pub fn tag(&self) -> u32 {
        self.tag
    }

    pub fn file_stem(&self) -> String {
        let mut stem = String::from("constraints_eval_");
        for (i, air) in self.airs.iter().copied().enumerate() {
            if i > 0 {
                stem.push_str("_then_");
            }
            stem.push_str(air.file_token());
        }
        stem
    }

    fn from_rank(rank: usize) -> Self {
        debug_assert!(rank < PROOF_ORDER_COUNT);
        debug_assert!(rank <= u32::MAX as usize);

        let tag = rank as u32;
        let mut rank = rank;
        let mut remaining = AIRS.to_vec();
        let mut airs = [AIRS[0]; MIDEN_AIR_COUNT];

        for (i, slot) in airs.iter_mut().enumerate() {
            let factor = factorial(MIDEN_AIR_COUNT - 1 - i);
            let index = rank / factor;
            rank %= factor;
            *slot = remaining.remove(index);
        }

        Self { airs, tag }
    }
}

fn assert_is_air_permutation(airs: &[MidenAir; MIDEN_AIR_COUNT]) {
    let mut seen = [false; MIDEN_AIR_COUNT];
    for air in airs {
        let index = air.instance_index();
        assert!(!seen[index], "proof order contains duplicate AIR: {air:?}");
        seen[index] = true;
    }
}

fn lehmer_rank(airs: &[MidenAir; MIDEN_AIR_COUNT]) -> u32 {
    let mut rank = 0;
    for i in 0..airs.len() {
        let smaller_after = airs[i + 1..]
            .iter()
            .filter(|air| air.instance_index() < airs[i].instance_index())
            .count();
        rank += smaller_after as u32 * factorial(airs.len() - 1 - i) as u32;
    }
    rank
}

impl BaseAir<Felt> for MidenAir {
    fn width(&self) -> usize {
        match self {
            Self::Core => CoreAir.width(),
            Self::Chiplets => ChipletsAir.width(),
            Self::Poseidon2Permutation => Poseidon2PermutationAir.width(),
        }
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        match self {
            Self::Core => CoreAir.periodic_columns(),
            Self::Chiplets => ChipletsAir.periodic_columns(),
            Self::Poseidon2Permutation => Poseidon2PermutationAir.periodic_columns(),
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
            Self::Core => CoreAir.aux_width(),
            Self::Chiplets => ChipletsAir.aux_width(),
            Self::Poseidon2Permutation => Poseidon2PermutationAir.aux_width(),
        }
    }

    fn num_aux_values(&self) -> usize {
        // One committed LogUp final per AIR instance.
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
            "build_logup_aux_trace returns one committed final per AIR"
        );
        (aux_trace, committed)
    }

    fn constraint_degree(&self) -> ConstraintDegrees {
        match self {
            Self::Core | Self::Chiplets => ConstraintDegrees { base: 9, ext: 9 },
            Self::Poseidon2Permutation => ConstraintDegrees { base: 8, ext: 3 },
        }
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        match self {
            Self::Core => CoreAir.eval(builder),
            Self::Chiplets => ChipletsAir.eval(builder),
            Self::Poseidon2Permutation => Poseidon2PermutationAir.eval(builder),
        }
    }
}

impl<LB> LookupAir<LB> for MidenAir
where
    LB: MainLookupBuilder + ChipletLookupBuilder + Poseidon2PermutationLookupBuilder,
{
    fn num_columns(&self) -> usize {
        match self {
            Self::Core => CoreAir.lookup_num_columns(),
            Self::Chiplets => ChipletsAir.lookup_num_columns(),
            Self::Poseidon2Permutation => Poseidon2PermutationAir.lookup_num_columns(),
        }
    }

    fn column_shape(&self) -> &[usize] {
        match self {
            Self::Core => CoreAir.lookup_column_shape(),
            Self::Chiplets => ChipletsAir.lookup_column_shape(),
            Self::Poseidon2Permutation => Poseidon2PermutationAir.lookup_column_shape(),
        }
    }

    fn max_message_width(&self) -> usize {
        match self {
            Self::Core => CoreAir.lookup_max_message_width(),
            Self::Chiplets => ChipletsAir.lookup_max_message_width(),
            Self::Poseidon2Permutation => Poseidon2PermutationAir.lookup_max_message_width(),
        }
    }

    fn num_bus_ids(&self) -> usize {
        match self {
            Self::Core => CoreAir.lookup_num_bus_ids(),
            Self::Chiplets => ChipletsAir.lookup_num_bus_ids(),
            Self::Poseidon2Permutation => Poseidon2PermutationAir.lookup_num_bus_ids(),
        }
    }

    fn eval(&self, builder: &mut LB) {
        match self {
            Self::Core => CoreAir.lookup_eval(builder),
            Self::Chiplets => ChipletsAir.lookup_eval(builder),
            Self::Poseidon2Permutation => Poseidon2PermutationAir.lookup_eval(builder),
        }
    }

    fn eval_boundary<B>(&self, boundary: &mut B)
    where
        B: BoundaryBuilder<F = LB::F, EF = LB::EF>,
    {
        match self {
            Self::Core => CoreAir.lookup_eval_boundary(boundary),
            Self::Chiplets => ChipletsAir.lookup_eval_boundary(boundary),
            Self::Poseidon2Permutation => Poseidon2PermutationAir.lookup_eval_boundary(boundary),
        }
    }
}

// MIDEN MULTI-AIR
// ================================================================================================

/// The cross-AIR statement for the Miden VM proof.
///
/// AIR instances come from [`AIRS`], and the external reduction sums the committed LogUp finals
/// with the open-bus boundary corrections.
///
/// Instance order is `[Core, Chiplets, Poseidon2Permutation]`; every per-AIR slice follows that
/// ordering.
#[derive(Copy, Clone, Debug)]
pub struct MidenMultiAir;

impl MidenMultiAir {
    /// Construct the Miden multi-AIR statement marker.
    pub const fn new() -> Self {
        Self
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
        &AIRS
    }

    fn num_air_inputs(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn max_aux_inputs(&self) -> usize {
        // aux_inputs = program hash (1 word) + transcript state (1 word) + one `Word` per kernel
        // procedure digest, capped at `Kernel::MAX_NUM_PROCEDURES`.
        AUX_KERNEL_DIGESTS + Kernel::MAX_NUM_PROCEDURES * WORD_SIZE
    }

    /// Absorb statement-owned public inputs into the Fiat-Shamir challenger.
    ///
    /// Uses a rate-aligned schedule: six 8-felt blocks, 48 felts total.
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

        // `observe` cannot return an error; malformed aux inputs are rejected by `eval_external`.
        let mut aux_prefix = [Felt::ZERO; AUX_KERNEL_DIGESTS];
        let prefix_len = aux_inputs.len().min(AUX_KERNEL_DIGESTS);
        aux_prefix[..prefix_len].copy_from_slice(&aux_inputs[..prefix_len]);

        let kernel_felts = aux_inputs.get(AUX_KERNEL_DIGESTS..).unwrap_or(&[]);
        let kernel_h = hash_kernel_input_felts(kernel_felts);
        let program_hash = &aux_prefix[AUX_PROGRAM_HASH..AUX_PROGRAM_HASH + WORD_SIZE];
        let transcript_state = &aux_prefix[AUX_TRANSCRIPT_STATE..AUX_TRANSCRIPT_STATE + WORD_SIZE];
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
        log_trace_heights: &[u8],
    ) -> Result<Vec<EF>, ReductionError> {
        if aux_values.len() != AIRS.len() {
            return Err(format!(
                "expected aux values for {} AIRs, got {}",
                AIRS.len(),
                aux_values.len()
            )
            .into());
        }
        if log_trace_heights.len() != AIRS.len() {
            return Err(format!(
                "expected log heights for {} AIRs, got {}",
                AIRS.len(),
                log_trace_heights.len()
            )
            .into());
        }
        if challenges.len() != trace::AUX_TRACE_RAND_CHALLENGES {
            return Err(format!(
                "expected {} aux trace challenges, got {}",
                trace::AUX_TRACE_RAND_CHALLENGES,
                challenges.len()
            )
            .into());
        }
        if air_inputs.len() != NUM_PUBLIC_VALUES {
            return Err(format!(
                "expected {NUM_PUBLIC_VALUES} public values, got {}",
                air_inputs.len()
            )
            .into());
        }
        if aux_inputs.len() < AUX_KERNEL_DIGESTS {
            return Err(format!(
                "aux_inputs length {} is shorter than the fixed prefix {AUX_KERNEL_DIGESTS}",
                aux_inputs.len()
            )
            .into());
        }
        let max_aux_inputs = <MidenMultiAir as MultiAir<Felt, EF>>::max_aux_inputs(self);
        if aux_inputs.len() > max_aux_inputs {
            return Err(format!(
                "aux_inputs length {} exceeds maximum {max_aux_inputs}",
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

        let mut aux_sum = EF::ZERO;
        let mut boundary_correction = EF::ZERO;
        for (air, values) in AIRS.iter().copied().zip(aux_values.iter()) {
            boundary_correction += air.boundary_correction(&challenges, air_inputs, aux_inputs)?;
            let expected = <MidenAir as LiftedAir<Felt, EF>>::num_aux_values(&air);
            if values.len() != expected {
                return Err(format!(
                    "{} expects {expected} aux boundary values, got {}",
                    air.name(),
                    values.len()
                )
                .into());
            }
            aux_sum += values.iter().copied().sum::<EF>();
        }

        Ok(vec![aux_sum + boundary_correction])
    }
}

// KERNEL DIGEST SUMMARY HASH
// ================================================================================================

/// Computes `kernel_H`, the fixed-size commitment to the kernel-procedure digests.
///
/// This is the canonical [`Kernel::commitment`] value expressed over the flattened digest
/// felts: `hash_elements(kernel_felts)`. The empty digest list yields `hash_elements(&[])`.
///
/// `kernel_H` is absorbed into the Fiat-Shamir transcript in place of the unbounded kernel
/// digest list, committing to the kernel with a fixed-size value.
pub fn hash_kernel_digests(kernel_felts: &[Felt]) -> [Felt; WORD_SIZE] {
    assert!(
        kernel_felts.len().is_multiple_of(WORD_SIZE),
        "kernel digest felts must be whole words"
    );
    assert!(
        kernel_felts.len() <= Kernel::MAX_NUM_PROCEDURES * WORD_SIZE,
        "kernel digest felts exceed Kernel::MAX_NUM_PROCEDURES"
    );

    hash_kernel_input_felts(kernel_felts)
}

fn hash_kernel_input_felts(kernel_felts: &[Felt]) -> [Felt; WORD_SIZE] {
    miden_core::chiplets::hasher::hash_elements(kernel_felts).into()
}

// REDUCED-AUX BOUNDARY BUILDER
// ================================================================================================

/// `BoundaryBuilder` impl that reduces each emitted interaction to its LogUp denominator
/// contribution `multiplicity / encode(msg)` and sums them into a running `EF` accumulator.
///
/// Boundary correction is computed from the structured boundary messages emitted by each AIR.
///
/// Denominators are `alpha + sum_i beta^i * field_i` with random `alpha, beta`; on any
/// legitimate proof they are non-zero with overwhelming probability. A malformed proof can still
/// drive a denominator to zero, so the reducer captures the first failure and surfaces it as a
/// [`ReductionError`] to the verifier rather than panicking.
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
    use alloc::string::ToString;

    use miden_core::field::QuadFelt;

    use super::*;

    /// Guards the static `constraint_degree` override: if an AIR change moves the symbolic
    /// degree away from the declared value, the override must be updated.
    #[test]
    fn constraint_degree_override_matches_symbolic() {
        for air in AIRS {
            let symbolic = ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air);
            let declared = <MidenAir as LiftedAir<Felt, QuadFelt>>::constraint_degree(&air);
            assert_eq!(declared, symbolic, "static constraint_degree override is stale");
        }
    }

    #[test]
    fn air_registry_order_matches_instance_indices() {
        for (index, air) in AIRS.iter().copied().enumerate() {
            assert_eq!(air.instance_index(), index);
        }
    }

    #[test]
    fn proof_order_constants_derive_from_air_count() {
        assert_eq!(PROOF_ORDER_COUNT, ProofOrder::variants().len());
        assert_eq!(PROOF_ORDER_REGISTRY_DEPTH, ceil_log2(PROOF_ORDER_COUNT));
    }

    #[test]
    fn proof_order_count_is_factorial() {
        assert_eq!(factorial(0), 1);
        assert_eq!(factorial(1), 1);
        assert_eq!(factorial(2), 2);
        assert_eq!(factorial(3), 6);
        assert_eq!(factorial(4), 24);
    }

    #[test]
    fn registry_depth_is_ceil_log2() {
        assert_eq!(ceil_log2(1), 0);
        assert_eq!(ceil_log2(2), 1);
        assert_eq!(ceil_log2(3), 2);
        assert_eq!(ceil_log2(6), 3);
        assert_eq!(ceil_log2(24), 5);
    }

    #[test]
    fn proof_order_tags_use_lehmer_rank() {
        let variants = ProofOrder::variants();

        assert_eq!(variants.len(), PROOF_ORDER_COUNT);
        assert_eq!(variants[0], ProofOrder::instance_order());
        for (tag, order) in variants.into_iter().enumerate() {
            assert_eq!(order.tag(), tag as u32);
            assert_eq!(ProofOrder::from_tag(tag as u32), Some(order));
        }
        assert_eq!(ProofOrder::from_tag(PROOF_ORDER_COUNT as u32), None);
    }

    #[test]
    fn proof_order_sorts_by_height_then_instance_index() {
        assert_eq!(
            ProofOrder::from_instance_log_heights(&[8, 9, 10]),
            ProofOrder::from_airs(&[
                MidenAir::Core,
                MidenAir::Chiplets,
                MidenAir::Poseidon2Permutation,
            ])
        );
        assert_eq!(
            ProofOrder::from_instance_log_heights(&[9, 8, 10]),
            ProofOrder::from_airs(&[
                MidenAir::Chiplets,
                MidenAir::Core,
                MidenAir::Poseidon2Permutation,
            ])
        );
        assert_eq!(
            ProofOrder::from_instance_log_heights(&[8, 8, 8]),
            ProofOrder::from_airs(&[
                MidenAir::Core,
                MidenAir::Chiplets,
                MidenAir::Poseidon2Permutation,
            ])
        );
    }

    #[test]
    fn eval_external_rejects_partial_kernel_digest() {
        let challenges =
            [QuadFelt::from(Felt::new_unchecked(3)), QuadFelt::from(Felt::new_unchecked(5))];
        let air_inputs = vec![Felt::ZERO; NUM_PUBLIC_VALUES];
        let mut aux_inputs = vec![Felt::ZERO; AUX_KERNEL_DIGESTS];
        aux_inputs.push(Felt::ONE);
        let zero = QuadFelt::from(Felt::ZERO);
        let core_aux = [zero];
        let chiplets_aux = [zero];
        let poseidon2_aux = [zero];
        let aux_values = [core_aux.as_slice(), chiplets_aux.as_slice(), poseidon2_aux.as_slice()];

        let err = MidenMultiAir::new()
            .eval_external(&challenges, &air_inputs, &aux_inputs, &aux_values, &[8, 8, 8])
            .unwrap_err();

        assert!(err.to_string().contains("kernel digest felts length 1 is not a multiple of 4"));
    }

    #[test]
    fn eval_external_rejects_too_many_kernel_digests() {
        let challenges =
            [QuadFelt::from(Felt::new_unchecked(3)), QuadFelt::from(Felt::new_unchecked(5))];
        let air_inputs = vec![Felt::ZERO; NUM_PUBLIC_VALUES];
        let max_aux_inputs = AUX_KERNEL_DIGESTS + Kernel::MAX_NUM_PROCEDURES * WORD_SIZE;
        let actual_aux_inputs = max_aux_inputs + WORD_SIZE;
        let aux_inputs = vec![Felt::ZERO; actual_aux_inputs];
        let zero = QuadFelt::from(Felt::ZERO);
        let core_aux = [zero];
        let chiplets_aux = [zero];
        let poseidon2_aux = [zero];
        let aux_values = [core_aux.as_slice(), chiplets_aux.as_slice(), poseidon2_aux.as_slice()];

        let err = MidenMultiAir::new()
            .eval_external(&challenges, &air_inputs, &aux_inputs, &aux_values, &[8, 8, 8])
            .unwrap_err();

        assert!(err.to_string().contains(&format!(
            "aux_inputs length {actual_aux_inputs} exceeds maximum {max_aux_inputs}"
        )));
    }

    #[test]
    #[should_panic(expected = "kernel digest felts exceed Kernel::MAX_NUM_PROCEDURES")]
    fn hash_kernel_digests_rejects_too_many_digest_felts() {
        let kernel_felts = vec![Felt::ZERO; (Kernel::MAX_NUM_PROCEDURES + 1) * WORD_SIZE];

        let _ = hash_kernel_digests(&kernel_felts);
    }

    #[test]
    fn observe_handles_short_aux_inputs() {
        #[derive(Default)]
        struct FeltSink {
            observed: Vec<Felt>,
        }

        impl CanObserve<Felt> for FeltSink {
            fn observe(&mut self, value: Felt) {
                self.observed.push(value);
            }
        }

        let mut challenger = FeltSink::default();
        let air_inputs = vec![Felt::ZERO; NUM_PUBLIC_VALUES];
        let multi_air = MidenMultiAir::new();

        <MidenMultiAir as MultiAir<Felt, QuadFelt>>::observe(
            &multi_air,
            &mut challenger,
            &air_inputs,
            &[],
            &[8, 8, 8],
        );

        assert_eq!(challenger.observed.len(), 48);
    }
}
