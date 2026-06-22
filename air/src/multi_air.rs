//! Per-trace AIR wrappers, AIR registry, proof-order tags, and the Miden `MultiAir` wrapper.

use alloc::{string::String, vec, vec::Vec};
use core::borrow::Borrow;

use miden_core::{WORD_SIZE, field::ExtensionField, utils::RowMajorMatrix};
use miden_crypto::stark::{
    air::{
        BaseAir, ConstraintDegrees, LiftedAir, LiftedAirBuilder, MultiAir, ReductionError,
        WindowAccess,
    },
    challenger::CanObserve,
};

use crate::{
    BlakeGCompressionCols, ChipletCols, CoreCols, Felt, MAX_KERNEL_PROC_DIGEST_INPUTS,
    MidenAirBuilder, NUM_BLAKEG_COMPRESSION_COLS, NUM_PUBLIC_VALUES,
    NUM_VAR_LEN_PUBLIC_INPUT_GROUPS,
    constraints::and8_lookup::{
        self,
        columns::{
            And8LookupCols, LOG_AND8_LOOKUP_TRACE_HEIGHT, NUM_AND8_LOOKUP_COLS,
            NUM_AND8_LOOKUP_PREPROCESSED_COLS,
        },
    },
    constraints::{
        self,
        blakeg_compression::{self, periodic::get_blakeg_periodic_column_values},
        lookup::blakeg_compression_air::{
            BLAKEG_COMPRESSION_COLUMN_SHAPE, emit_blakeg_compression_lookup_columns,
        },
    },
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
    lookup::{
        BoundaryBuilder, Challenges, ConstraintLookupBuilder, LookupAir, LookupMessage,
        build_logup_aux_trace,
    },
    trace,
};

use constraints::lookup::{
    and8_lookup_air::And8LookupBuilder,
    blakeg_compression_air::BlakeGCompressionLookupBuilder,
    chiplet_air::ChipletLookupBuilder,
    main_air::{MainLookupAir, MainLookupBuilder},
};

// PER-TRACE AIRS
// ================================================================================================

/// Core-trace AIR.
///
/// Owns the system, decoder, and stack segments.
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

/// Chiplets-trace AIR.
///
/// Owns the chiplet section and its LogUp accumulator columns.
#[derive(Copy, Clone, Debug, Default)]
pub struct ChipletsAir;

impl ChipletsAir {
    fn width(self) -> usize {
        constraints::columns::NUM_CHIPLETS_COLS
    }

    pub(crate) fn periodic_columns(self) -> Vec<Vec<Felt>> {
        constraints::chiplets::columns::PeriodicCols::periodic_columns()
    }

    fn aux_width(self) -> usize {
        constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE.len()
    }

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

/// Standalone BlakeG compression AIR.
///
/// Executes hasher-compute requests emitted through the compression-link bus.
#[derive(Copy, Clone, Debug, Default)]
pub struct BlakeGCompressionAir;

impl BlakeGCompressionAir {
    fn width(self) -> usize {
        NUM_BLAKEG_COMPRESSION_COLS
    }

    pub(crate) fn periodic_columns(self) -> Vec<Vec<Felt>> {
        get_blakeg_periodic_column_values()
    }

    fn aux_width(self) -> usize {
        BLAKEG_COMPRESSION_COLUMN_SHAPE.len()
    }

    fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        _challenges: &Challenges<EF>,
        _public_values: &[Felt],
        var_len_public_inputs: &[&[Felt]],
    ) -> Result<EF, ReductionError> {
        if !var_len_public_inputs.is_empty() {
            return Err(format!(
                "BlakeGCompressionAir expects 0 var-len public input slices, got {}",
                var_len_public_inputs.len()
            )
            .into());
        }
        Ok(EF::ZERO)
    }

    fn eval<AB: MidenAirBuilder>(self, builder: &mut AB) {
        blakeg_compression::enforce_main(builder);

        let mut lb = ConstraintLookupBuilder::new(builder, &MidenAir::BLAKEG_COMPRESSION);
        self.lookup_eval(&mut lb);
    }

    fn lookup_num_columns(self) -> usize {
        BLAKEG_COMPRESSION_COLUMN_SHAPE.len()
    }

    fn lookup_column_shape(self) -> &'static [usize] {
        &BLAKEG_COMPRESSION_COLUMN_SHAPE
    }

    fn lookup_max_message_width(self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn lookup_num_bus_ids(self) -> usize {
        BusId::COUNT
    }

    fn lookup_eval<LB: BlakeGCompressionLookupBuilder>(self, builder: &mut LB) {
        let main = builder.main();
        let local: &BlakeGCompressionCols<_> = main.current_slice().borrow();

        emit_blakeg_compression_lookup_columns(builder, local);
    }

    fn lookup_eval_boundary<B: BoundaryBuilder>(self, _boundary: &mut B) {}
}

/// Standalone byte-AND lookup table AIR.
#[derive(Copy, Clone, Debug, Default)]
pub struct And8LookupAir;

impl And8LookupAir {
    fn width(self) -> usize {
        NUM_AND8_LOOKUP_COLS
    }

    fn preprocessed_trace(self) -> Option<RowMajorMatrix<Felt>> {
        Some(and8_lookup::preprocessed_trace())
    }

    fn preprocessed_width(self) -> usize {
        NUM_AND8_LOOKUP_PREPROCESSED_COLS
    }

    fn periodic_columns(self) -> Vec<Vec<Felt>> {
        Vec::new()
    }

    fn aux_width(self) -> usize {
        constraints::lookup::and8_lookup_air::AND8_LOOKUP_COLUMN_SHAPE.len()
    }

    fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        _challenges: &Challenges<EF>,
        _public_values: &[Felt],
        var_len_public_inputs: &[&[Felt]],
    ) -> Result<EF, ReductionError> {
        if !var_len_public_inputs.is_empty() {
            return Err(format!(
                "And8LookupAir expects 0 var-len public input slices, got {}",
                var_len_public_inputs.len()
            )
            .into());
        }
        Ok(EF::ZERO)
    }

    fn eval<AB: MidenAirBuilder>(self, builder: &mut AB) {
        let mut lb = ConstraintLookupBuilder::new(builder, &MidenAir::AND8_LOOKUP);
        self.lookup_eval(&mut lb);
    }

    fn lookup_num_columns(self) -> usize {
        constraints::lookup::and8_lookup_air::AND8_LOOKUP_COLUMN_SHAPE.len()
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

// AIR REGISTRY AND PROOF ORDER
// ================================================================================================

/// Homogeneous wrapper for Miden's per-trace AIRs.
#[derive(Copy, Clone, Debug)]
pub enum MidenAir {
    Core(CoreAir),
    Chiplets(ChipletsAir),
    BlakeGCompression(BlakeGCompressionAir),
    And8Lookup(And8LookupAir),
}

impl MidenAir {
    pub const CORE: Self = Self::Core(CoreAir);
    pub const CHIPLETS: Self = Self::Chiplets(ChipletsAir);
    pub const BLAKEG_COMPRESSION: Self = Self::BlakeGCompression(BlakeGCompressionAir);
    pub const AND8_LOOKUP: Self = Self::And8Lookup(And8LookupAir);
}

/// Stable identity of an AIR in the Miden multi-AIR relation.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MidenAirId {
    Core,
    Chiplets,
    BlakeGCompression,
    And8Lookup,
}

impl MidenAirId {
    pub const fn instance_index(self) -> usize {
        match self {
            Self::Core => 0,
            Self::Chiplets => 1,
            Self::BlakeGCompression => 2,
            Self::And8Lookup => 3,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Core => "Core",
            Self::Chiplets => "Chiplets",
            Self::BlakeGCompression => "BlakeGCompression",
            Self::And8Lookup => "And8Lookup",
        }
    }

    pub const fn file_token(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Chiplets => "chiplets",
            Self::BlakeGCompression => "blakeg_compression",
            Self::And8Lookup => "and8_lookup",
        }
    }

    pub const fn air(self) -> MidenAir {
        match self {
            Self::Core => MidenAir::CORE,
            Self::Chiplets => MidenAir::CHIPLETS,
            Self::BlakeGCompression => MidenAir::BLAKEG_COMPRESSION,
            Self::And8Lookup => MidenAir::AND8_LOOKUP,
        }
    }

    pub const fn lookup_accumulator_mode(self) -> crate::lookup::LookupAccumulatorMode {
        match self {
            Self::Core | Self::Chiplets => crate::lookup::LookupAccumulatorMode::LastRowIdle,
            Self::BlakeGCompression | Self::And8Lookup => {
                crate::lookup::LookupAccumulatorMode::WrappedCentered
            },
        }
    }
}

/// Static metadata for one semantic AIR.
#[derive(Copy, Clone, Debug)]
pub struct AirSpec {
    pub id: MidenAirId,
    pub name: &'static str,
    pub air: MidenAir,
}

pub const MIDEN_AIR_COUNT: usize = 4;

/// Supported AIRs in semantic instance order.
pub const AIRS: [AirSpec; MIDEN_AIR_COUNT] = [
    AirSpec {
        id: MidenAirId::Core,
        name: MidenAirId::Core.name(),
        air: MidenAirId::Core.air(),
    },
    AirSpec {
        id: MidenAirId::Chiplets,
        name: MidenAirId::Chiplets.name(),
        air: MidenAirId::Chiplets.air(),
    },
    AirSpec {
        id: MidenAirId::BlakeGCompression,
        name: MidenAirId::BlakeGCompression.name(),
        air: MidenAirId::BlakeGCompression.air(),
    },
    AirSpec {
        id: MidenAirId::And8Lookup,
        name: MidenAirId::And8Lookup.name(),
        air: MidenAirId::And8Lookup.air(),
    },
];

/// Proof-order AIR permutation.
///
/// Proof order is the stable sort of `(log_trace_height, instance_index)`. The tag is the
/// Lehmer rank of that permutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofOrder {
    ids: Vec<MidenAirId>,
    tag: u32,
}

impl ProofOrder {
    pub fn new(ids: Vec<MidenAirId>) -> Self {
        assert_is_air_permutation(&ids);
        let tag = lehmer_rank(&ids);
        Self { ids, tag }
    }

    pub fn from_ids(ids: &[MidenAirId]) -> Self {
        Self::new(ids.to_vec())
    }

    pub fn instance_order() -> Self {
        Self::new(AIRS.iter().map(|spec| spec.id).collect())
    }

    pub fn variants() -> Vec<Self> {
        let ids: Vec<MidenAirId> = AIRS.iter().map(|spec| spec.id).collect();
        let mut variants = Vec::new();
        push_permutations(Vec::new(), ids, &mut variants);
        variants.sort_by_key(Self::tag);
        variants
    }

    pub fn from_tag(tag: u32) -> Option<Self> {
        Self::variants().into_iter().find(|order| order.tag == tag)
    }

    pub fn from_log_heights(log_heights: &[(MidenAirId, u8)]) -> Self {
        assert_eq!(log_heights.len(), AIRS.len(), "one log height is required per AIR");
        let mut ordered = log_heights.to_vec();
        ordered.sort_by_key(|(id, height)| (*height, id.instance_index()));
        Self::new(ordered.into_iter().map(|(id, _)| id).collect())
    }

    pub fn from_instance_log_heights(log_heights: &[u8]) -> Self {
        assert_eq!(log_heights.len(), AIRS.len(), "one log height is required per AIR");
        let pairs: Vec<(MidenAirId, u8)> = AIRS
            .iter()
            .zip(log_heights.iter().copied())
            .map(|(spec, height)| (spec.id, height))
            .collect();
        Self::from_log_heights(&pairs)
    }

    pub fn ids(&self) -> &[MidenAirId] {
        &self.ids
    }

    pub fn tag(&self) -> u32 {
        self.tag
    }

    pub fn position(&self, id: MidenAirId) -> Option<usize> {
        self.ids.iter().position(|candidate| *candidate == id)
    }

    pub fn file_stem(&self) -> String {
        let mut stem = String::from("constraints_eval_");
        for (i, id) in self.ids.iter().enumerate() {
            if i > 0 {
                stem.push_str("_then_");
            }
            stem.push_str(id.file_token());
        }
        stem
    }

    pub fn label(&self) -> String {
        let mut label = String::new();
        for (i, id) in self.ids.iter().enumerate() {
            if i > 0 {
                label.push_str(" then ");
            }
            label.push_str(id.name());
        }
        label
    }
}

fn push_permutations(
    prefix: Vec<MidenAirId>,
    remaining: Vec<MidenAirId>,
    out: &mut Vec<ProofOrder>,
) {
    if remaining.is_empty() {
        out.push(ProofOrder::new(prefix));
        return;
    }

    for i in 0..remaining.len() {
        let mut next_prefix = prefix.clone();
        next_prefix.push(remaining[i]);

        let mut next_remaining = remaining.clone();
        next_remaining.remove(i);

        push_permutations(next_prefix, next_remaining, out);
    }
}

fn assert_is_air_permutation(ids: &[MidenAirId]) {
    assert_eq!(ids.len(), AIRS.len(), "proof order must include every AIR exactly once");

    let mut seen = [false; MIDEN_AIR_COUNT];
    for id in ids {
        let index = id.instance_index();
        assert!(!seen[index], "proof order contains duplicate AIR id: {id:?}");
        seen[index] = true;
    }
}

fn lehmer_rank(ids: &[MidenAirId]) -> u32 {
    let mut rank = 0;
    for i in 0..ids.len() {
        let smaller_after = ids[i + 1..]
            .iter()
            .filter(|id| id.instance_index() < ids[i].instance_index())
            .count();
        rank += smaller_after as u32 * factorial(ids.len() - 1 - i);
    }
    rank
}

fn factorial(n: usize) -> u32 {
    (2..=n).fold(1, |acc, value| acc * value as u32)
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl BaseAir<Felt> for MidenAir {
    fn width(&self) -> usize {
        match self {
            Self::Core(a) => a.width(),
            Self::Chiplets(a) => a.width(),
            Self::BlakeGCompression(a) => a.width(),
            Self::And8Lookup(a) => a.width(),
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        match self {
            Self::Core(_) | Self::Chiplets(_) | Self::BlakeGCompression(_) => None,
            Self::And8Lookup(a) => a.preprocessed_trace(),
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
            Self::BlakeGCompression(a) => a.periodic_columns(),
            Self::And8Lookup(a) => a.periodic_columns(),
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Core(_) | Self::Chiplets(_) | Self::BlakeGCompression(_) => 0,
            Self::And8Lookup(a) => a.preprocessed_width(),
        }
    }

    fn num_randomness(&self) -> usize {
        trace::AUX_TRACE_RAND_CHALLENGES
    }

    fn aux_width(&self) -> usize {
        match self {
            Self::Core(a) => a.aux_width(),
            Self::Chiplets(a) => a.aux_width(),
            Self::BlakeGCompression(a) => a.aux_width(),
            Self::And8Lookup(a) => a.aux_width(),
        }
    }

    fn num_aux_values(&self) -> usize {
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
            Self::Core(_) | Self::Chiplets(_) => ConstraintDegrees { base: 9, ext: 9 },
            Self::BlakeGCompression(_) => ConstraintDegrees { base: 3, ext: 3 },
            Self::And8Lookup(_) => ConstraintDegrees { base: 0, ext: 2 },
        }
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        match self {
            Self::Core(a) => a.eval(builder),
            Self::Chiplets(a) => a.eval(builder),
            Self::BlakeGCompression(a) => a.eval(builder),
            Self::And8Lookup(a) => a.eval(builder),
        }
    }
}

impl<LB> LookupAir<LB> for MidenAir
where
    LB: MainLookupBuilder
        + ChipletLookupBuilder
        + BlakeGCompressionLookupBuilder
        + And8LookupBuilder,
{
    fn num_columns(&self) -> usize {
        match self {
            Self::Core(a) => a.lookup_num_columns(),
            Self::Chiplets(a) => a.lookup_num_columns(),
            Self::BlakeGCompression(a) => a.lookup_num_columns(),
            Self::And8Lookup(a) => a.lookup_num_columns(),
        }
    }

    fn column_shape(&self) -> &[usize] {
        match self {
            Self::Core(a) => a.lookup_column_shape(),
            Self::Chiplets(a) => a.lookup_column_shape(),
            Self::BlakeGCompression(a) => a.lookup_column_shape(),
            Self::And8Lookup(a) => a.lookup_column_shape(),
        }
    }

    fn accumulator_mode(&self) -> crate::lookup::LookupAccumulatorMode {
        match self {
            Self::Core(_) => MidenAirId::Core.lookup_accumulator_mode(),
            Self::Chiplets(_) => MidenAirId::Chiplets.lookup_accumulator_mode(),
            Self::BlakeGCompression(_) => MidenAirId::BlakeGCompression.lookup_accumulator_mode(),
            Self::And8Lookup(_) => MidenAirId::And8Lookup.lookup_accumulator_mode(),
        }
    }

    fn max_message_width(&self) -> usize {
        match self {
            Self::Core(a) => a.lookup_max_message_width(),
            Self::Chiplets(a) => a.lookup_max_message_width(),
            Self::BlakeGCompression(a) => a.lookup_max_message_width(),
            Self::And8Lookup(a) => a.lookup_max_message_width(),
        }
    }

    fn num_bus_ids(&self) -> usize {
        match self {
            Self::Core(a) => a.lookup_num_bus_ids(),
            Self::Chiplets(a) => a.lookup_num_bus_ids(),
            Self::BlakeGCompression(a) => a.lookup_num_bus_ids(),
            Self::And8Lookup(a) => a.lookup_num_bus_ids(),
        }
    }

    fn eval(&self, builder: &mut LB) {
        match self {
            Self::Core(a) => a.lookup_eval(builder),
            Self::Chiplets(a) => a.lookup_eval(builder),
            Self::BlakeGCompression(a) => a.lookup_eval(builder),
            Self::And8Lookup(a) => a.lookup_eval(builder),
        }
    }

    fn eval_boundary<B>(&self, boundary: &mut B)
    where
        B: BoundaryBuilder<F = LB::F, EF = LB::EF>,
    {
        match self {
            Self::Core(a) => a.lookup_eval_boundary(boundary),
            Self::Chiplets(a) => a.lookup_eval_boundary(boundary),
            Self::BlakeGCompression(a) => a.lookup_eval_boundary(boundary),
            Self::And8Lookup(a) => a.lookup_eval_boundary(boundary),
        }
    }
}

// MULTI-AIR WRAPPER
// ================================================================================================

/// Multi-AIR wrapper for the Miden proving relation.
#[derive(Clone, Debug)]
pub struct MidenMultiAir {
    airs: [MidenAir; MIDEN_AIR_COUNT],
}

impl MidenMultiAir {
    pub const fn new() -> Self {
        Self {
            airs: [AIRS[0].air, AIRS[1].air, AIRS[2].air, AIRS[3].air],
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
        MAX_KERNEL_PROC_DIGEST_INPUTS
    }

    /// Absorb the Miden VM statement using its word-aligned descriptor.
    ///
    /// The descriptor is `[NUM_PUBLIC_VALUES, NUM_VAR_LEN_PUBLIC_INPUT_GROUPS,
    /// aux_inputs.len(), 0]`, followed by fixed public inputs and kernel digest felts.
    fn observe<C: CanObserve<Felt>>(
        &self,
        challenger: &mut C,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        log_trace_heights: &[u8],
    ) {
        debug_assert_eq!(air_inputs.len(), NUM_PUBLIC_VALUES);
        debug_assert_eq!(aux_inputs.len() % WORD_SIZE, 0);
        debug_assert!(aux_inputs.len() <= MAX_KERNEL_PROC_DIGEST_INPUTS);
        debug_assert_eq!(log_trace_heights.len(), self.airs.len());

        challenger.observe(Felt::from(NUM_PUBLIC_VALUES as u32));
        challenger.observe(Felt::from(NUM_VAR_LEN_PUBLIC_INPUT_GROUPS as u32));
        challenger.observe(Felt::from(aux_inputs.len() as u32));
        challenger.observe(Felt::ZERO);
        for &value in air_inputs {
            challenger.observe(value);
        }
        for &value in aux_inputs {
            challenger.observe(value);
        }
    }

    fn eval_external(
        &self,
        challenges: &[EF],
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        aux_values: &[&[EF]],
        log_trace_heights: &[u8],
    ) -> Result<Vec<EF>, ReductionError> {
        if aux_values.len() != self.airs.len() {
            return Err(format!(
                "expected aux values for {} AIRs, got {}",
                self.airs.len(),
                aux_values.len()
            )
            .into());
        }
        if log_trace_heights.len() != self.airs.len() {
            return Err(format!(
                "expected log heights for {} AIRs, got {}",
                self.airs.len(),
                log_trace_heights.len()
            )
            .into());
        }
        if log_trace_heights[MidenAirId::And8Lookup.instance_index()]
            != LOG_AND8_LOOKUP_TRACE_HEIGHT
        {
            return Err(format!(
                "And8Lookup log height must be {LOG_AND8_LOOKUP_TRACE_HEIGHT}, got {}",
                log_trace_heights[MidenAirId::And8Lookup.instance_index()]
            )
            .into());
        }

        let challenges = Challenges::<EF>::new(
            challenges[0],
            challenges[1],
            MIDEN_MAX_MESSAGE_WIDTH,
            BusId::COUNT,
        );

        // Keep these calls explicit: only ChipletsAir consumes the kernel-digest VLPI slice.
        let core_correction = CoreAir.boundary_correction(&challenges, air_inputs, &[])?;
        let chiplets_correction =
            ChipletsAir.boundary_correction(&challenges, air_inputs, &[aux_inputs])?;
        let blakeg_correction =
            BlakeGCompressionAir.boundary_correction(&challenges, air_inputs, &[])?;
        let and8_correction = And8LookupAir.boundary_correction(&challenges, air_inputs, &[])?;

        let mut aux_sum = EF::ZERO;
        for ((spec, values), &log_height) in
            AIRS.iter().zip(aux_values.iter()).zip(log_trace_heights)
        {
            let expected = <MidenAir as LiftedAir<Felt, EF>>::num_aux_values(&spec.air);
            if values.len() != expected {
                return Err(format!(
                    "{} expects {expected} aux boundary values, got {}",
                    spec.id.name(),
                    values.len()
                )
                .into());
            }
            let weight = match spec.id.lookup_accumulator_mode() {
                crate::lookup::LookupAccumulatorMode::LastRowIdle => EF::ONE,
                crate::lookup::LookupAccumulatorMode::WrappedCentered => {
                    let trace_len = 1u64.checked_shl(u32::from(log_height)).ok_or_else(|| {
                        format!("{} AIR trace length log is too large", spec.id.name())
                    })?;
                    let trace_len = Felt::new(trace_len).map_err(|err| -> ReductionError {
                        format!("{} AIR trace length is not canonical: {err}", spec.id.name())
                            .into()
                    })?;
                    EF::from(trace_len)
                },
            };
            aux_sum += values.iter().copied().map(|value| value * weight).sum::<EF>();
        }
        Ok(vec![
            aux_sum + core_correction + chiplets_correction + blakeg_correction + and8_correction,
        ])
    }
}

// BOUNDARY REDUCTION
// ================================================================================================

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

#[cfg(test)]
mod tests {
    use miden_ace_codegen::{
        DagBuilder, InputCounts, InputKey, InputLayout, emit_circuit, testing::fill_inputs,
    };
    use miden_core::field::QuadFelt;

    use super::*;

    #[test]
    fn order_follows_height_then_instance_index() {
        assert_eq!(
            ProofOrder::from_instance_log_heights(&[8, 9, 10, 11]),
            ProofOrder::from_ids(&[
                MidenAirId::Core,
                MidenAirId::Chiplets,
                MidenAirId::BlakeGCompression,
                MidenAirId::And8Lookup,
            ]),
        );
        assert_eq!(
            ProofOrder::from_instance_log_heights(&[9, 8, 10, 11]),
            ProofOrder::from_ids(&[
                MidenAirId::Chiplets,
                MidenAirId::Core,
                MidenAirId::BlakeGCompression,
                MidenAirId::And8Lookup,
            ]),
        );
        assert_eq!(
            ProofOrder::from_instance_log_heights(&[8, 8, 8, 8]),
            ProofOrder::from_ids(&[
                MidenAirId::Core,
                MidenAirId::Chiplets,
                MidenAirId::BlakeGCompression,
                MidenAirId::And8Lookup,
            ]),
        );
    }

    #[test]
    fn tags_use_lehmer_rank() {
        assert_eq!(ProofOrder::variants().len(), 24);
        assert_eq!(
            ProofOrder::variants().first().unwrap().ids(),
            ProofOrder::instance_order().ids()
        );
        for (tag, order) in ProofOrder::variants().into_iter().enumerate() {
            assert_eq!(order.tag(), tag as u32);
            assert_eq!(ProofOrder::from_tag(tag as u32), Some(order));
        }
    }

    /// Guards the static `constraint_degree` override.
    #[test]
    fn constraint_degree_override_matches_symbolic() {
        for spec in AIRS {
            let air = spec.air;
            let symbolic = ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air);
            let declared = <MidenAir as LiftedAir<Felt, QuadFelt>>::constraint_degree(&air);
            assert_eq!(
                declared, symbolic,
                "{} static constraint_degree override is stale",
                spec.name,
            );
        }
    }

    #[test]
    fn eval_external_scales_wrapped_centered_aux_values_by_trace_length() {
        let air = MidenMultiAir::default();
        let challenges = [QuadFelt::from(Felt::from_u32(7)), QuadFelt::from(Felt::from_u32(11))];
        let public_values: Vec<Felt> = (0..NUM_PUBLIC_VALUES as u32).map(Felt::from_u32).collect();
        let kernel_digests = Vec::new();
        let log_heights = [6, 6, 6, LOG_AND8_LOOKUP_TRACE_HEIGHT];

        let zero = [QuadFelt::from(Felt::ZERO)];
        let centered = [QuadFelt::from(Felt::from_u32(3))];

        let base_aux_values: [&[QuadFelt]; MIDEN_AIR_COUNT] = [&zero, &zero, &zero, &zero];
        let base = air
            .eval_external(
                &challenges,
                &public_values,
                &kernel_digests,
                &base_aux_values,
                &log_heights,
            )
            .expect("base boundary reduction");

        for air_id in [MidenAirId::BlakeGCompression, MidenAirId::And8Lookup] {
            let mut shifted_aux_values = base_aux_values;
            shifted_aux_values[air_id.instance_index()] = &centered;

            let shifted = air
                .eval_external(
                    &challenges,
                    &public_values,
                    &kernel_digests,
                    &shifted_aux_values,
                    &log_heights,
                )
                .expect("shifted boundary reduction");

            let trace_len = Felt::new(1u64 << log_heights[air_id.instance_index()])
                .expect("trace length must be canonical");
            let expected_delta = centered[0] * QuadFelt::from(trace_len);
            assert_eq!(shifted[0] - base[0], expected_delta, "wrong boundary scale for {air_id:?}");
        }
    }

    #[test]
    fn ace_and_native_boundary_use_same_wrapped_centered_scale() {
        let counts = InputCounts {
            preprocessed_width: 0,
            width: 0,
            aux_width: 0,
            num_aux_boundary: MIDEN_AIR_COUNT,
            num_public: NUM_PUBLIC_VALUES,
            num_vlpi: NUM_VAR_LEN_PUBLIC_INPUT_GROUPS,
            num_randomness: 2,
            num_periodic: 0,
            num_quotient_chunks: 1,
        };
        let layout = InputLayout::new_multi_air_for_airs(counts, MIDEN_AIR_COUNT);
        let mut builder = DagBuilder::<QuadFelt>::new();
        let constraint_root = builder.constant(QuadFelt::from(Felt::ZERO));
        let root = crate::ace::batch_logup_boundary_into_builder(
            &mut builder,
            constraint_root,
            &crate::ace::LogUpBoundaryConfig {
                aux_terms: vec![
                    crate::ace::AuxBoundaryTerm { column: 0, scale: None },
                    crate::ace::AuxBoundaryTerm {
                        column: MidenAirId::BlakeGCompression.instance_index(),
                        scale: Some(InputKey::TraceLenAir(
                            MidenAirId::BlakeGCompression.instance_index(),
                        )),
                    },
                    crate::ace::AuxBoundaryTerm {
                        column: MidenAirId::And8Lookup.instance_index(),
                        scale: Some(InputKey::TraceLenAir(MidenAirId::And8Lookup.instance_index())),
                    },
                ],
                fractions: Vec::new(),
                scalar_corrections: Vec::new(),
            },
        );
        let circuit = emit_circuit(&builder.build(root), layout).expect("ACE boundary circuit");
        let layout = circuit.layout();
        let mut inputs = fill_inputs(layout);

        let log_heights = [6, 6, 6, LOG_AND8_LOOKUP_TRACE_HEIGHT];
        for (air_idx, &log_height) in log_heights.iter().enumerate() {
            let trace_len = Felt::new(1u64 << log_height).expect("trace length must be canonical");
            let idx = layout.index(InputKey::TraceLenAir(air_idx)).expect("trace length slot");
            inputs[idx] = QuadFelt::from(trace_len);
        }
        inputs[layout.index(InputKey::Gamma).expect("gamma slot")] =
            QuadFelt::from(Felt::from_u32(13));

        let centered = QuadFelt::from(Felt::from_u32(3));
        let core_boundary = layout.index(InputKey::AuxBusBoundary(0)).expect("core boundary slot");
        let blakeg_boundary =
            layout.index(InputKey::AuxBusBoundary(2)).expect("BlakeG boundary slot");
        let and8_boundary = layout.index(InputKey::AuxBusBoundary(3)).expect("AND8 boundary slot");

        let base = circuit.eval(&inputs).expect("ACE base eval");
        let mut core_shifted = inputs.clone();
        core_shifted[core_boundary] += centered;
        let core_delta = circuit.eval(&core_shifted).expect("ACE core-shift eval") - base;

        let mut blakeg_shifted = inputs.clone();
        blakeg_shifted[blakeg_boundary] += centered;
        let blakeg_delta = circuit.eval(&blakeg_shifted).expect("ACE BlakeG-shift eval") - base;

        let mut and8_shifted = inputs;
        and8_shifted[and8_boundary] += centered;
        let and8_delta = circuit.eval(&and8_shifted).expect("ACE AND8-shift eval") - base;
        assert_ne!(core_delta, QuadFelt::from(Felt::ZERO));

        let air = MidenMultiAir::default();
        let challenges = [QuadFelt::from(Felt::from_u32(7)), QuadFelt::from(Felt::from_u32(11))];
        let public_values: Vec<Felt> = (0..NUM_PUBLIC_VALUES as u32).map(Felt::from_u32).collect();
        let kernel_digests = Vec::new();

        let zero = [QuadFelt::from(Felt::ZERO)];
        let native_centered = [centered];
        let base_aux_values: [&[QuadFelt]; MIDEN_AIR_COUNT] = [&zero, &zero, &zero, &zero];
        let core_aux_values: [&[QuadFelt]; MIDEN_AIR_COUNT] =
            [&native_centered, &zero, &zero, &zero];
        let blakeg_aux_values: [&[QuadFelt]; MIDEN_AIR_COUNT] =
            [&zero, &zero, &native_centered, &zero];
        let and8_aux_values: [&[QuadFelt]; MIDEN_AIR_COUNT] =
            [&zero, &zero, &zero, &native_centered];

        let native_base = air
            .eval_external(
                &challenges,
                &public_values,
                &kernel_digests,
                &base_aux_values,
                &log_heights,
            )
            .expect("native base boundary");
        let native_core_delta = air
            .eval_external(
                &challenges,
                &public_values,
                &kernel_digests,
                &core_aux_values,
                &log_heights,
            )
            .expect("native core-shift boundary")[0]
            - native_base[0];
        let native_blakeg_delta = air
            .eval_external(
                &challenges,
                &public_values,
                &kernel_digests,
                &blakeg_aux_values,
                &log_heights,
            )
            .expect("native BlakeG-shift boundary")[0]
            - native_base[0];
        let native_and8_delta = air
            .eval_external(
                &challenges,
                &public_values,
                &kernel_digests,
                &and8_aux_values,
                &log_heights,
            )
            .expect("native AND8-shift boundary")[0]
            - native_base[0];

        assert_eq!(blakeg_delta * native_core_delta, core_delta * native_blakeg_delta);
        assert_eq!(and8_delta * native_core_delta, core_delta * native_and8_delta);
    }
}
