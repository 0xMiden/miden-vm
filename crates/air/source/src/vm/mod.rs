//! Authored constraints and trace schema for the Miden VM.
//!
//! [`MidenAir`] evaluates the handwritten definitions directly. Artifact generation and drift
//! checks consume this module without depending on the production generated evaluators.

use alloc::{borrow::Cow, vec::Vec};
use core::borrow::Borrow;

#[cfg(feature = "arbitrary")]
use miden_core::program::KernelDescriptor;
use miden_core::{
    WORD_SIZE, Word,
    deferred::DeferredRoot,
    field::ExtensionField,
    program::{MIN_STACK_DEPTH, ProgramInfo, StackInputs, StackOutputs},
};
use miden_stark::{
    air::{ReductionError, WindowAccess},
    lookup,
};
#[cfg(feature = "arbitrary")]
use proptest::prelude::*;

#[cfg(feature = "codegen")]
pub mod codegen;
mod constraints;
#[cfg(test)]
mod lookup_tests;
mod proof_order;
pub mod trace;

/// Miden VM-specific LogUp lookup argument: bus identifiers and bus message types.
///
/// [`crate::vm::MidenAir`] is the single `LiftedAir`/`LookupAir` type for the multi-AIR
/// statement; it dispatches per-trace work to Core, Chiplets, Eidos compression, and
/// byte-pair lookup AIRs.
/// The generic LogUp framework lives in [`miden_stark::lookup`].
pub mod logup {
    pub use crate::vm::constraints::lookup::{
        BusId, MIDEN_MAX_MESSAGE_WIDTH, messages::*, miden_air::NUM_LOGUP_COMMITTED_FINALS,
    };
}

pub use constraints::{
    and8_lookup,
    and8_lookup::columns::{And8LookupCols, And8LookupPreprocessedCols},
    chiplets::columns::{
        AceCols, AceEvalCols, AceReadCols, AeadStreamCols, AeadStreamHighFirstCols,
        AeadStreamHighSecondCols, AeadStreamLowSecondCols, AeadStreamReadCols, BitwiseCols,
        ControllerCols, KernelRomCols, MemoryCols,
    },
    columns::{ChipletCols, CoreCols},
    decoder::columns::DecoderCols,
    eidos_compression,
    eidos_compression::{EidosCompressionCols, NUM_COLS as NUM_EIDOS_COMPRESSION_COLS},
    ext_field::QuadFeltExpr,
    stack::columns::StackCols,
    system::columns::SystemCols,
};
use constraints::{
    eidos_compression::{
        constraints::{
            enforce_footer_rows, enforce_fused_rows, enforce_inactive_footer_input_aux,
            enforce_inactive_footer_output_aux,
        },
        lookup::{
            EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE, EidosCompressionLookupBuilder,
            emit_lookup_columns,
        },
        periodic::get_periodic_column_values,
        selectors::EidosCompressionSelectors,
    },
    lookup::{
        and8_lookup_air::And8LookupBuilder,
        chiplet_air::ChipletLookupBuilder,
        main_air::{MainLookupAir, MainLookupBuilder},
    },
};
use logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH};
use lookup::{
    BoundaryBuilder, Challenges, ConstraintLookupBuilder, LookupAir, LookupMessage,
    build_logup_aux_trace_with_preprocessed,
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
    pub use miden_stark::air::{
        AirBuilder, BaseAir, ConstraintCounts, ConstraintDegrees, ExtensionBuilder, LiftedAir,
        LiftedAirBuilder, PermutationAirBuilder,
    };
}

pub use export::*;
pub use proof_order::{AIRS, MIDEN_AIR_COUNT, PROOF_ORDER_COUNT, ProofOrder};

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
    miden_test_serialization_macros::serialization_test
)]
pub struct PublicInputs {
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    deferred_root: DeferredRoot,
}

impl PublicInputs {
    /// Creates a new instance of `PublicInputs` from program information, stack inputs and outputs,
    /// and the final deferred root.
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

    /// Returns the final deferred root.
    pub fn deferred_root(&self) -> DeferredRoot {
        self.deferred_root
    }

    /// Returns the canonical commitment to the kernel of the verified statement: the value the
    /// recursive verifier observes into the transcript in place of the raw kernel-procedure
    /// digest list. See
    /// [`KernelDescriptor::commitment`](miden_core::program::KernelDescriptor::commitment).
    pub fn kernel_commitment(&self) -> Word {
        self.program_info.kernel_commitment()
    }

    /// Returns the AIR public values (`air_inputs`) and statement inputs (`aux_inputs`).
    ///
    /// `air_inputs` (read by Core; all other AIRs have empty slices) layout:
    ///   [0..16]  stack inputs
    ///   [16..32] stack outputs
    ///
    /// `aux_inputs` (statement inputs not read by the AIRs, consumed only by `observe` and
    /// `eval_external`) layout:
    ///   [0..4]   program hash
    ///   [4..8]   final deferred root
    ///   [8..]    kernel procedure digests (concatenated words, variable length)
    pub fn to_air_inputs(&self) -> (Vec<Felt>, Vec<Felt>) {
        let mut air_inputs = Vec::with_capacity(NUM_PUBLIC_VALUES);
        air_inputs.extend_from_slice(self.stack_inputs.as_ref());
        air_inputs.extend_from_slice(self.stack_outputs.as_ref());

        let kernel_felts = Word::words_as_elements(self.program_info.kernel_procedures());
        let mut aux_inputs = Vec::with_capacity(AUX_KERNEL_DIGESTS + kernel_felts.len());
        aux_inputs.extend_from_slice(self.program_info.program_hash().as_elements());
        aux_inputs.extend_from_slice(self.deferred_root.as_ref());
        aux_inputs.extend_from_slice(kernel_felts);

        (air_inputs, aux_inputs)
    }

    /// Converts public inputs into a vector of field elements (Felt) in the canonical order:
    /// - program info elements (including kernel procedure hashes)
    /// - stack inputs
    /// - stack outputs
    /// - final deferred root
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
            .prop_map(|program_hash| ProgramInfo::new(program_hash, KernelDescriptor::default()));
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

/// Number of public values read by Core; the other Miden VM AIRs have no public values.
///
/// Layout (32 Felts total):
///   [0..16]  stack inputs
///   [16..32] stack outputs
///
/// The program hash and final deferred root are not read by any AIR constraint, so they
/// are carried as `aux_inputs` for transcript observation and the external LogUp reduction.
pub const NUM_PUBLIC_VALUES: usize = MIN_STACK_DEPTH + MIN_STACK_DEPTH;

/// Combined LogUp width used by constraint test harnesses: 4 core columns, 4 chiplet
/// columns, and the byte-pair table column. Standalone Eidos compression tests size their aux
/// matrix from the AIR directly.
pub const LOGUP_AUX_TRACE_WIDTH: usize = 9;

// `aux_inputs` layout offsets — statement inputs that the AIRs do not read. The fixed program
// hash and final deferred root occupy the first two words; the variable-length kernel-procedure
// digests follow.
/// Offset of the program hash in statement auxiliary inputs.
pub const AUX_PROGRAM_HASH: usize = 0;
/// Offset of the final deferred root in statement auxiliary inputs.
pub const AUX_DEFERRED_ROOT: usize = WORD_SIZE;
/// Offset of the variable-length kernel-procedure digest list in statement auxiliary inputs.
pub const AUX_KERNEL_DIGESTS: usize = 2 * WORD_SIZE;

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

    /// LogUp boundary correction for the core trace: the running sum of every
    /// boundary interaction reduced to its denominator contribution. The single var-len slice
    /// carries `[program_hash (4) | deferred_root (4)]`, the statement inputs the core
    /// boundary cancels against the block-hash and log-deferred buses.
    fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        challenges: &Challenges<EF>,
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
                "CoreAir expects {} boundary felts (program hash + deferred root), got {}",
                2 * WORD_SIZE,
                boundary_inputs[0].len()
            )
            .into());
        }

        let mut reducer = ReduceBoundaryBuilder {
            challenges,
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
        lb.finish();
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
        lb.finish();
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

// EIDOS COMPRESSION AIR
// ================================================================================================

/// Standalone Eidos compression AIR.
#[derive(Copy, Clone, Debug, Default)]
pub struct EidosCompressionAir;

impl EidosCompressionAir {
    fn width(self) -> usize {
        NUM_EIDOS_COMPRESSION_COLS
    }

    fn periodic_columns(self) -> Vec<Vec<Felt>> {
        get_periodic_column_values()
    }

    fn aux_width(self) -> usize {
        EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE.len()
    }

    fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        _challenges: &Challenges<EF>,
        boundary_inputs: &[&[Felt]],
    ) -> Result<EF, ReductionError> {
        if !boundary_inputs.is_empty() {
            return Err(format!(
                "EidosCompressionAir expects 0 boundary input slices, got {}",
                boundary_inputs.len()
            )
            .into());
        }
        Ok(EF::ZERO)
    }

    fn eval<AB: MidenAirBuilder>(self, builder: &mut AB) {
        {
            let main = builder.main();
            let local = main.current_slice();
            let next = main.next_slice();
            let periodic_values: Vec<AB::Expr> =
                builder.periodic_values().iter().map(|value| (*value).into()).collect();
            let selectors = EidosCompressionSelectors::new(&periodic_values, 0);

            enforce_fused_rows(builder, local, next, &selectors);
            enforce_footer_rows(builder, local, next, &selectors);
            enforce_inactive_footer_input_aux(builder, &selectors);
            enforce_inactive_footer_output_aux(builder, local, &selectors);
        }
        let mut lb = ConstraintLookupBuilder::new(builder, &MidenAir::EidosCompression);
        self.lookup_eval(&mut lb);
        lb.finish();
    }

    fn lookup_column_shape(self) -> &'static [usize] {
        &EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE
    }

    fn lookup_max_message_width(self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn lookup_num_bus_ids(self) -> usize {
        BusId::COUNT
    }

    fn lookup_eval<LB: EidosCompressionLookupBuilder>(self, builder: &mut LB) {
        let main = builder.main();
        let local: &EidosCompressionCols<_> = main.current_slice().borrow();
        let next: &EidosCompressionCols<_> = main.next_slice().borrow();
        let periodic_values: Vec<LB::Expr> =
            builder.periodic_values().iter().map(|value| (*value).into()).collect();
        let selectors = EidosCompressionSelectors::new(&periodic_values, 0);

        emit_lookup_columns(builder, local, next, &selectors);
    }

    fn lookup_eval_boundary<B: BoundaryBuilder>(self, _boundary: &mut B) {}
}

// BYTE-PAIR LOOKUP AIR
// ================================================================================================

/// Standalone byte-AND and range lookup-table AIR.
#[derive(Copy, Clone, Debug, Default)]
pub struct And8LookupAir;

impl And8LookupAir {
    fn width(self) -> usize {
        and8_lookup::columns::NUM_AND8_LOOKUP_COLS
    }

    fn preprocessed_trace(self) -> RowMajorMatrix<Felt> {
        and8_lookup::preprocessed_trace()
    }

    fn preprocessed_width(self) -> usize {
        and8_lookup::columns::NUM_AND8_LOOKUP_PREPROCESSED_COLS
    }

    fn aux_width(self) -> usize {
        constraints::lookup::and8_lookup_air::AND8_LOOKUP_COLUMN_SHAPE.len()
    }

    fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        _challenges: &Challenges<EF>,
        boundary_inputs: &[&[Felt]],
    ) -> Result<EF, ReductionError> {
        if !boundary_inputs.is_empty() {
            return Err(format!(
                "And8LookupAir expects 0 boundary input slices, got {}",
                boundary_inputs.len()
            )
            .into());
        }
        Ok(EF::ZERO)
    }

    fn eval<AB: MidenAirBuilder>(self, builder: &mut AB) {
        let mut lb = ConstraintLookupBuilder::new(builder, &MidenAir::And8Lookup);
        self.lookup_eval(&mut lb);
        lb.finish();
    }

    fn lookup_column_shape(self) -> &'static [usize] {
        &constraints::lookup::and8_lookup_air::AND8_LOOKUP_COLUMN_SHAPE
    }

    fn lookup_max_message_width(self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn lookup_num_bus_ids(self) -> usize {
        BusId::COUNT
    }

    fn lookup_eval<LB: And8LookupBuilder>(self, builder: &mut LB) {
        let main = builder.main();
        let local: &And8LookupCols<_> = main.current_slice().borrow();
        constraints::lookup::and8_lookup_air::emit_and8_lookup_columns(builder, local);
    }

    fn lookup_eval_boundary<B: BoundaryBuilder>(self, _boundary: &mut B) {}
}

// MIDEN AIR
// ================================================================================================

/// AIR instance identifier for the Miden multi-AIR statement.
///
/// [`MultiAir::Air`](miden_stark::air::MultiAir) is a single associated type, so every
/// instance in the multi-AIR proof must have the same type. This enum identifies which concrete
/// AIR logic to dispatch to.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MidenAir {
    Core,
    Chiplets,
    EidosCompression,
    And8Lookup,
}

impl MidenAir {
    pub const CORE: Self = Self::Core;
    pub const CHIPLETS: Self = Self::Chiplets;
    pub const EIDOS_COMPRESSION: Self = Self::EidosCompression;
    pub const AND8_LOOKUP: Self = Self::And8Lookup;

    pub const fn instance_index(self) -> usize {
        match self {
            Self::Core => 0,
            Self::Chiplets => 1,
            Self::EidosCompression => 2,
            Self::And8Lookup => 3,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Core => "Core",
            Self::Chiplets => "Chiplets",
            Self::EidosCompression => "EidosCompression",
            Self::And8Lookup => "And8Lookup",
        }
    }

    /// Lookup fractions emitted per row, one entry per auxiliary lookup column.
    ///
    /// Available without naming a lookup builder, so callers that only need the shape — such as
    /// the security estimator — do not have to pick an unrelated builder type to read it.
    pub fn column_shape(self) -> &'static [usize] {
        match self {
            Self::Core => CoreAir.lookup_column_shape(),
            Self::Chiplets => ChipletsAir.lookup_column_shape(),
            Self::EidosCompression => EidosCompressionAir.lookup_column_shape(),
            Self::And8Lookup => And8LookupAir.lookup_column_shape(),
        }
    }

    pub const fn file_token(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Chiplets => "chiplets",
            Self::EidosCompression => "eidos_compression",
            Self::And8Lookup => "and8_lookup",
        }
    }

    /// Reduces this AIR's statement boundary interactions to their LogUp contribution.
    ///
    /// `aux_inputs` follows the layout returned by [`PublicInputs::to_air_inputs`].
    pub fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        challenges: &Challenges<EF>,
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
            Self::Core => {
                CoreAir.boundary_correction(challenges, &[&aux_inputs[..AUX_KERNEL_DIGESTS]])
            },
            Self::Chiplets => {
                ChipletsAir.boundary_correction(challenges, &[&aux_inputs[AUX_KERNEL_DIGESTS..]])
            },
            Self::EidosCompression => EidosCompressionAir.boundary_correction(challenges, &[]),
            Self::And8Lookup => And8LookupAir.boundary_correction(challenges, &[]),
        }
    }
}

impl BaseAir<Felt> for MidenAir {
    fn width(&self) -> usize {
        match self {
            Self::Core => CoreAir.width(),
            Self::Chiplets => ChipletsAir.width(),
            Self::EidosCompression => EidosCompressionAir.width(),
            Self::And8Lookup => And8LookupAir.width(),
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        match self {
            Self::And8Lookup => Some(And8LookupAir.preprocessed_trace()),
            Self::Core | Self::Chiplets | Self::EidosCompression => None,
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::And8Lookup => And8LookupAir.preprocessed_width(),
            Self::Core | Self::Chiplets | Self::EidosCompression => 0,
        }
    }

    fn num_public_values(&self) -> usize {
        match self {
            Self::Core => NUM_PUBLIC_VALUES,
            Self::Chiplets | Self::EidosCompression | Self::And8Lookup => 0,
        }
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        Cow::Owned(match self {
            Self::Core => CoreAir.periodic_columns(),
            Self::Chiplets => ChipletsAir.periodic_columns(),
            Self::EidosCompression => EidosCompressionAir.periodic_columns(),
            Self::And8Lookup => Vec::new(),
        })
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
            Self::EidosCompression => EidosCompressionAir.aux_width(),
            Self::And8Lookup => And8LookupAir.aux_width(),
        }
    }

    fn num_aux_values(&self) -> usize {
        // One committed normalized LogUp sum `sigma_prime = sigma / n` per AIR instance.
        1
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        let preprocessed = self.preprocessed_trace();
        self.build_aux_trace_with_preprocessed(
            main,
            preprocessed.as_ref(),
            air_inputs,
            aux_inputs,
            challenges,
        )
    }

    fn build_aux_trace_with_preprocessed(
        &self,
        main: &RowMajorMatrix<Felt>,
        preprocessed: Option<&RowMajorMatrix<Felt>>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        let (aux_trace, committed) =
            build_logup_aux_trace_with_preprocessed(self, main, preprocessed, challenges);
        debug_assert_eq!(
            committed.len(),
            1,
            "build_logup_aux_trace returns one normalized LogUp sum per AIR"
        );
        (aux_trace, committed)
    }

    fn constraint_degree(&self) -> ConstraintDegrees {
        match self {
            Self::Core | Self::Chiplets => ConstraintDegrees { base: 9, ext: 9 },
            Self::EidosCompression => ConstraintDegrees { base: 3, ext: 3 },
            Self::And8Lookup => ConstraintDegrees { base: 0, ext: 3 },
        }
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        match self {
            Self::Core => CoreAir.eval(builder),
            Self::Chiplets => ChipletsAir.eval(builder),
            Self::EidosCompression => EidosCompressionAir.eval(builder),
            Self::And8Lookup => And8LookupAir.eval(builder),
        }
    }
}

impl<LB> LookupAir<LB> for MidenAir
where
    LB: MainLookupBuilder
        + ChipletLookupBuilder
        + EidosCompressionLookupBuilder
        + And8LookupBuilder,
{
    fn column_shape(&self) -> &[usize] {
        MidenAir::column_shape(*self)
    }

    fn max_message_width(&self) -> usize {
        match self {
            Self::Core => CoreAir.lookup_max_message_width(),
            Self::Chiplets => ChipletsAir.lookup_max_message_width(),
            Self::EidosCompression => EidosCompressionAir.lookup_max_message_width(),
            Self::And8Lookup => And8LookupAir.lookup_max_message_width(),
        }
    }

    fn num_bus_ids(&self) -> usize {
        match self {
            Self::Core => CoreAir.lookup_num_bus_ids(),
            Self::Chiplets => ChipletsAir.lookup_num_bus_ids(),
            Self::EidosCompression => EidosCompressionAir.lookup_num_bus_ids(),
            Self::And8Lookup => And8LookupAir.lookup_num_bus_ids(),
        }
    }

    fn eval(&self, builder: &mut LB) {
        match self {
            Self::Core => CoreAir.lookup_eval(builder),
            Self::Chiplets => ChipletsAir.lookup_eval(builder),
            Self::EidosCompression => EidosCompressionAir.lookup_eval(builder),
            Self::And8Lookup => And8LookupAir.lookup_eval(builder),
        }
    }

    fn eval_boundary<B>(&self, boundary: &mut B)
    where
        B: BoundaryBuilder<F = LB::F, EF = LB::EF>,
    {
        match self {
            Self::Core => CoreAir.lookup_eval_boundary(boundary),
            Self::Chiplets => ChipletsAir.lookup_eval_boundary(boundary),
            Self::EidosCompression => EidosCompressionAir.lookup_eval_boundary(boundary),
            Self::And8Lookup => And8LookupAir.lookup_eval_boundary(boundary),
        }
    }
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
        for air in AIRS {
            let symbolic = ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air);
            let declared = <MidenAir as LiftedAir<Felt, QuadFelt>>::constraint_degree(&air);
            assert_eq!(declared, symbolic, "static constraint_degree override is stale");
        }
    }

    #[test]
    fn core_shape_and_degree_match_design() {
        let air = MidenAir::CORE;
        let symbolic = ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air);

        assert_eq!(air.width(), 48);
        assert_eq!(constraints::columns::NUM_DECODER_COLS, 23);
        assert_eq!(LiftedAir::<Felt, QuadFelt>::aux_width(&air), 4);
        assert_eq!(symbolic, ConstraintDegrees { base: 9, ext: 9 });
        assert_eq!(
            LiftedAir::<Felt, QuadFelt>::constraint_degree(&air),
            symbolic,
            "Core's declared degree must match its handwritten constraints",
        );
        assert_eq!(miden_stark::log_quotient_degree::<Felt, QuadFelt, _>(&air), 3);
    }

    #[test]
    fn and8_lookup_shape_and_degree_match_design() {
        let air = MidenAir::AND8_LOOKUP;

        assert_eq!(air.width(), 7);
        assert_eq!(air.preprocessed_width(), 5);
        assert_eq!(LiftedAir::<Felt, QuadFelt>::aux_width(&air), 4);
        assert_eq!(constraints::lookup::and8_lookup_air::AND8_LOOKUP_COLUMN_SHAPE, [1, 2, 2, 2],);
        assert_eq!(
            LiftedAir::<Felt, QuadFelt>::constraint_degree(&air),
            ConstraintDegrees { base: 0, ext: 3 }
        );
        assert_eq!(miden_stark::log_quotient_degree::<Felt, QuadFelt, _>(&air), 1);
    }
}
