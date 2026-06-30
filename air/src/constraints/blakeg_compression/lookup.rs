//! Lookup columns for the 32-row BlakeG layout.

#[cfg(test)]
use alloc::vec::Vec;
use core::borrow::Borrow;

use miden_core::{Felt, field::PrimeCharacteristicRing};
#[cfg(test)]
use miden_crypto::stark::air::WindowAccess;

use super::{layout::*, selectors::BlakeGSelectors};
#[cfg(test)]
use crate::{
    constraints::lookup::MIDEN_MAX_MESSAGE_WIDTH,
    lookup::{LookupAccumulatorMode, LookupAir},
};
use crate::{
    constraints::lookup::messages::{
        AeadBlakeGInputMsg, AeadBlakeGOutputPairMsg, BusId, HasherCompressionLinkMsg,
        blakeg_rot7_bus, blakeg_rot12_bus,
    },
    lookup::{Deg, LookupBuilder, LookupColumn, LookupGroup},
};

#[cfg(test)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BlakeGCompressionMode {
    Compression,
    AeadXof,
}

#[cfg(test)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NarrowLookupKind {
    And8,
    Rot12,
    Rot7,
    MessageWord,
    InputPair,
    RangeCheck,
}

#[cfg(test)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NarrowLookup {
    pub kind: NarrowLookupKind,
    pub sign: i8,
}

#[cfg(test)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SingletonLookupKind {
    CompressionLink,
    AeadInput,
    AeadLowOutputPair,
    AeadHighOutputPair,
}

#[cfg(test)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SingletonLookup {
    pub kind: SingletonLookupKind,
    pub sign: i8,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupPlan {
    pub narrow: Vec<NarrowLookup>,
    pub singletons: Vec<SingletonLookup>,
}

#[cfg(test)]
impl LookupPlan {
    pub fn narrow_aux_columns(&self) -> usize {
        self.narrow.len().div_ceil(2)
    }

    pub fn narrow_aux_column(slot: usize) -> usize {
        slot / 2
    }

    pub fn singleton_aux_column(kind: SingletonLookupKind) -> usize {
        match kind {
            SingletonLookupKind::CompressionLink => COMPRESSION_LINK_COLUMN,
            SingletonLookupKind::AeadInput => AEAD_INPUT_COLUMN,
            SingletonLookupKind::AeadLowOutputPair => AEAD_LOW_OUTPUT_COLUMN,
            SingletonLookupKind::AeadHighOutputPair => AEAD_HIGH_OUTPUT_COLUMN,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct BlakeGCompressionCols<T> {
    pub columns: [T; NUM_COLS],
}

impl<T> Borrow<BlakeGCompressionCols<T>> for [T] {
    fn borrow(&self) -> &BlakeGCompressionCols<T> {
        debug_assert_eq!(self.len(), NUM_COLS);
        let (prefix, cols, suffix) = unsafe { self.align_to::<BlakeGCompressionCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(cols.len(), 1);
        &cols[0]
    }
}

pub const BLAKEG_LOOKUP_COLUMN_SHAPE: [usize; AUX_COLS] = [
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, //
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, //
    1, 1, 1, 1,
];

pub(crate) const NARROW_BATCH_COLUMNS: usize = 20;
pub(crate) const COMPRESSION_LINK_COLUMN: usize = 20;
pub(crate) const AEAD_INPUT_COLUMN: usize = 21;
pub(crate) const AEAD_LOW_OUTPUT_COLUMN: usize = 22;
pub(crate) const AEAD_HIGH_OUTPUT_COLUMN: usize = 23;

#[cfg(test)]
const FOOTER_HIGH_AND8_LOOKUPS: usize = 2 * BYTES_PER_WORD;
#[cfg(test)]
const FOOTER_LOW_AND8_LOOKUPS: usize = 2 * BYTES_PER_WORD;
#[cfg(test)]
const FOOTER_TOP_BIT_AND8_LOOKUPS: usize = 1;
#[cfg(test)]
const FOOTER_AND8_LOOKUPS: usize =
    FOOTER_HIGH_AND8_LOOKUPS + FOOTER_LOW_AND8_LOOKUPS + FOOTER_TOP_BIT_AND8_LOOKUPS;

const BATCH2_DEG: Deg = Deg { v: 2, u: 2 };
const SINGLETON_DEG: Deg = Deg { v: 2, u: 2 };
const COMPRESSION_LINK_DEG: Deg = Deg { v: 3, u: 2 };

fn selected_column_deg(aux_col: usize) -> Deg {
    match aux_col {
        0..NARROW_BATCH_COLUMNS => BATCH2_DEG,
        COMPRESSION_LINK_COLUMN => COMPRESSION_LINK_DEG,
        AEAD_INPUT_COLUMN..=AEAD_HIGH_OUTPUT_COLUMN => SINGLETON_DEG,
        _ => unreachable!("32-row BlakeG lookup aux column out of range"),
    }
}

#[cfg(test)]
#[derive(Copy, Clone, Debug, Default)]
pub struct BlakeGCompressionLookupAir;

pub trait BlakeGCompressionLookupBuilder: LookupBuilder<F = Felt> {}

impl<T> BlakeGCompressionLookupBuilder for T where T: LookupBuilder<F = Felt> {}

#[cfg(test)]
impl<LB> LookupAir<LB> for BlakeGCompressionLookupAir
where
    LB: BlakeGCompressionLookupBuilder,
{
    fn num_columns(&self) -> usize {
        BLAKEG_LOOKUP_COLUMN_SHAPE.len()
    }

    fn column_shape(&self) -> &[usize] {
        &BLAKEG_LOOKUP_COLUMN_SHAPE
    }

    fn accumulator_mode(&self) -> LookupAccumulatorMode {
        LookupAccumulatorMode::WrappedCentered
    }

    fn max_message_width(&self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        BusId::COUNT
    }

    fn eval(&self, builder: &mut LB) {
        let main = builder.main();
        let local: &BlakeGCompressionCols<_> = main.current_slice().borrow();
        let periodic_values: Vec<LB::Expr> =
            builder.periodic_values().iter().map(|value| (*value).into()).collect();
        let selectors = BlakeGSelectors::new(&periodic_values, 0);

        emit_lookup_columns(builder, local, &selectors);
    }
}

pub fn emit_lookup_columns<LB>(
    builder: &mut LB,
    local: &BlakeGCompressionCols<LB::Var>,
    selectors: &BlakeGSelectors<LB::Expr>,
) where
    LB: BlakeGCompressionLookupBuilder,
{
    for aux_col in 0..BLAKEG_LOOKUP_COLUMN_SHAPE.len() {
        let column_deg = selected_column_deg(aux_col);
        builder.next_column(
            |col| {
                col.group(
                    "blakeg_compression",
                    |group| emit_lookup_column::<LB, _>(group, local, selectors, aux_col),
                    column_deg,
                );
            },
            column_deg,
        );
    }
}

fn emit_lookup_column<LB, G>(
    group: &mut G,
    local: &BlakeGCompressionCols<LB::Var>,
    selectors: &BlakeGSelectors<LB::Expr>,
    aux_col: usize,
) where
    LB: BlakeGCompressionLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    match aux_col {
        0..NARROW_BATCH_COLUMNS => emit_narrow_pair::<LB, G>(group, local, selectors, aux_col),
        COMPRESSION_LINK_COLUMN..=AEAD_HIGH_OUTPUT_COLUMN => {
            emit_footer_singletons::<LB, G>(group, local, selectors, aux_col)
        },
        _ => unreachable!("32-row BlakeG lookup aux column out of range"),
    }
}

fn emit_narrow_pair<LB, G>(
    group: &mut G,
    local: &BlakeGCompressionCols<LB::Var>,
    selectors: &BlakeGSelectors<LB::Expr>,
    aux_col: usize,
) where
    LB: BlakeGCompressionLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let slot0 = 2 * aux_col;
    let slot1 = slot0 + 1;
    let slot0_multiplicity = narrow_slot_multiplicity::<LB>(slot0, selectors);
    let slot1_multiplicity = narrow_slot_multiplicity::<LB>(slot1, selectors);
    let slot0_encoding = narrow_slot_encoding::<LB, G>(&*group, local, selectors, slot0);
    let slot1_encoding = narrow_slot_encoding::<LB, G>(&*group, local, selectors, slot1);

    group.selected_batch2_encoded(
        "narrow_pair",
        "slot0",
        slot0_multiplicity,
        || slot0_encoding,
        "slot1",
        slot1_multiplicity,
        || slot1_encoding,
    );
}

fn emit_footer_singletons<LB, G>(
    group: &mut G,
    local: &BlakeGCompressionCols<LB::Var>,
    selectors: &BlakeGSelectors<LB::Expr>,
    aux_col: usize,
) where
    LB: BlakeGCompressionLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let mode = c::<LB>(local, F_MODE_COL);
    let compression_mode = LB::Expr::ONE - mode.clone();
    let is_f3 = selectors.is_footer_row(FOOTER_ROWS - 1);

    match aux_col {
        COMPRESSION_LINK_COLUMN => {
            group.insert(
                "compression_link",
                is_f3,
                -(c::<LB>(local, F_COMPRESSION_MULTIPLICITY_COL) * compression_mode),
                || compression_link_msg::<LB>(local),
                COMPRESSION_LINK_DEG,
            );
        },
        AEAD_INPUT_COLUMN => {
            group.insert(
                "aead_input",
                is_f3,
                -mode.clone(),
                || aead_input_msg::<LB>(local),
                SINGLETON_DEG,
            );
        },
        AEAD_LOW_OUTPUT_COLUMN => {
            for footer in 0..FOOTER_ROWS {
                emit_aead_output_pair::<LB, G>(group, local, selectors, footer, mode.clone(), 0);
            }
        },
        AEAD_HIGH_OUTPUT_COLUMN => {
            for footer in 0..FOOTER_ROWS {
                emit_aead_output_pair::<LB, G>(group, local, selectors, footer, mode.clone(), 8);
            }
        },
        _ => unreachable!("32-row BlakeG singleton aux column out of range"),
    }
}

fn emit_aead_output_pair<LB, G>(
    group: &mut G,
    local: &BlakeGCompressionCols<LB::Var>,
    selectors: &BlakeGSelectors<LB::Expr>,
    footer: usize,
    mode: LB::Expr,
    lane_offset: usize,
) where
    LB: BlakeGCompressionLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let values = if lane_offset == 0 {
        footer_output_word::<LB>(local)
    } else {
        footer_high_word::<LB>(local)
    };
    group.insert(
        "aead_output_pair",
        selectors.is_footer_row(footer),
        -mode,
        || aead_output_pair_msg::<LB>(local, footer, lane_offset, values),
        SINGLETON_DEG,
    );
}

fn narrow_slot_multiplicity<LB>(slot: usize, selectors: &BlakeGSelectors<LB::Expr>) -> LB::Expr
where
    LB: BlakeGCompressionLookupBuilder,
{
    let fused = is_fused::<LB>(selectors);
    let footer = selectors.is_footer();

    match slot {
        0..=16 => -(fused + footer),
        17 => -fused + footer,
        18..=21 => -fused - expr::<LB>(7) * footer,
        22..=29 => -(fused + footer),
        30..=31 => -fused,
        32..=35 => fused,
        36..=39 => -selectors.is_first_fused(),
        _ => unreachable!("32-row BlakeG narrow slot out of range"),
    }
}

fn narrow_slot_encoding<LB, G>(
    group: &G,
    local: &BlakeGCompressionCols<LB::Var>,
    selectors: &BlakeGSelectors<LB::Expr>,
    slot: usize,
) -> G::ExprEF
where
    LB: BlakeGCompressionLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let mut encoded = G::ExprEF::ZERO;

    if slot <= 15 {
        add_bus(&mut encoded, group, BusId::And8Lookup, is_fused::<LB>(selectors));
        add_bus(&mut encoded, group, BusId::And8Lookup, selectors.is_footer());
    } else if slot <= 31 {
        add_rot_bus::<LB, G>(&mut encoded, group, slot, selectors);
        add_footer_overlay_slot::<LB, G>(&mut encoded, group, selectors, slot);
    } else if slot <= 35 {
        add_bus(&mut encoded, group, BusId::BlakeGMessageWord, is_fused::<LB>(selectors));
    } else if slot <= 39 {
        add_bus(&mut encoded, group, BusId::BlakeGInputWord, selectors.is_first_fused());
    } else {
        unreachable!("32-row BlakeG narrow slot out of range");
    }

    let activity = narrow_slot_activity::<LB>(slot, selectors);
    add_bus(&mut encoded, group, BusId::RangeCheck, LB::Expr::ONE - activity);
    add_fields_direct(&mut encoded, group, narrow_slot_fields::<LB>(local, slot));
    encoded
}

fn narrow_slot_activity<LB>(slot: usize, selectors: &BlakeGSelectors<LB::Expr>) -> LB::Expr
where
    LB: BlakeGCompressionLookupBuilder,
{
    match slot {
        0..=29 => is_fused::<LB>(selectors) + selectors.is_footer(),
        30..=35 => is_fused::<LB>(selectors),
        36..=39 => selectors.is_first_fused(),
        _ => unreachable!("32-row BlakeG narrow slot out of range"),
    }
}

fn add_footer_overlay_slot<LB, G>(
    encoded: &mut G::ExprEF,
    group: &G,
    selectors: &BlakeGSelectors<LB::Expr>,
    slot: usize,
) where
    LB: BlakeGCompressionLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let branch = selectors.is_footer();
    match slot {
        16 => {
            add_bus(encoded, group, BusId::And8Lookup, branch.clone());
        },
        17 => {
            add_bus(encoded, group, BusId::BlakeGInputWord, branch.clone());
        },
        18..=21 => {
            add_bus(encoded, group, BusId::BlakeGMessageWord, branch.clone());
        },
        22..=29 => {
            add_bus(encoded, group, BusId::RangeCheck, branch.clone());
        },
        _ => {},
    }
}

fn add_rot_bus<LB, G>(
    encoded: &mut G::ExprEF,
    group: &G,
    slot: usize,
    selectors: &BlakeGSelectors<LB::Expr>,
) where
    LB: BlakeGCompressionLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let byte = slot % BYTES_PER_WORD;
    add_bus(encoded, group, blakeg_rot12_bus(byte), selectors.is_ab());
    add_bus(encoded, group, blakeg_rot7_bus(byte), selectors.is_cd());
}

fn add_bus<G>(encoded: &mut G::ExprEF, group: &G, bus: BusId, selector: G::Expr)
where
    G: LookupGroup,
{
    *encoded = encoded.clone() + group.bus_prefix(bus as usize) * selector;
}

fn add_fields_direct<G>(encoded: &mut G::ExprEF, group: &G, fields: [G::Expr; 3])
where
    G: LookupGroup,
{
    for (idx, field) in fields.into_iter().enumerate() {
        *encoded = encoded.clone() + group.beta_powers()[idx].clone() * field;
    }
}

fn compression_link_msg<LB>(
    local: &BlakeGCompressionCols<LB::Var>,
) -> HasherCompressionLinkMsg<LB::Expr>
where
    LB: BlakeGCompressionLookupBuilder,
{
    HasherCompressionLinkMsg {
        block: core::array::from_fn(|i| c::<LB>(local, F_R_BASE_COL + i)),
        cv_in: core::array::from_fn(|i| c::<LB>(local, F_C_BASE_COL + i)),
        cv_out: core::array::from_fn(|i| c::<LB>(local, F_D_BASE_COL + i)),
    }
}

fn aead_input_msg<LB>(local: &BlakeGCompressionCols<LB::Var>) -> AeadBlakeGInputMsg<LB::Expr>
where
    LB: BlakeGCompressionLookupBuilder,
{
    AeadBlakeGInputMsg {
        clk: c::<LB>(local, F_CLK_COL),
        state: core::array::from_fn(|i| {
            if i < 8 {
                c::<LB>(local, F_R_BASE_COL + i)
            } else {
                c::<LB>(local, F_C_BASE_COL + i - 8)
            }
        }),
    }
}

fn aead_output_pair_msg<LB>(
    local: &BlakeGCompressionCols<LB::Var>,
    footer: usize,
    lane_offset: usize,
    values: [LB::Expr; 2],
) -> AeadBlakeGOutputPairMsg<LB::Expr>
where
    LB: BlakeGCompressionLookupBuilder,
{
    AeadBlakeGOutputPairMsg {
        clk: c::<LB>(local, F_CLK_COL),
        first_lane_idx: expr::<LB>((lane_offset + 2 * footer) as u64),
        value0: values[0].clone(),
        value1: values[1].clone(),
    }
}

fn footer_output_word<LB>(local: &BlakeGCompressionCols<LB::Var>) -> [LB::Expr; 2]
where
    LB: BlakeGCompressionLookupBuilder,
{
    [
        footer_xor_word::<LB>(local, F_OUTPUT_EVEN_SLOT_BASE),
        footer_xor_word::<LB>(local, F_OUTPUT_ODD_SLOT_BASE),
    ]
}

fn footer_high_word<LB>(local: &BlakeGCompressionCols<LB::Var>) -> [LB::Expr; 2]
where
    LB: BlakeGCompressionLookupBuilder,
{
    [
        footer_xor_word::<LB>(local, F_HIGH_EVEN_SLOT_BASE),
        footer_xor_word::<LB>(local, F_HIGH_ODD_SLOT_BASE),
    ]
}

fn footer_xor_word<LB>(local: &BlakeGCompressionCols<LB::Var>, slot_base: usize) -> LB::Expr
where
    LB: BlakeGCompressionLookupBuilder,
{
    pack4::<LB>(
        footer_xor_byte::<LB>(local, slot_base),
        footer_xor_byte::<LB>(local, slot_base + 1),
        footer_xor_byte::<LB>(local, slot_base + 2),
        footer_xor_byte::<LB>(local, slot_base + 3),
    )
}

fn footer_xor_byte<LB>(local: &BlakeGCompressionCols<LB::Var>, slot: usize) -> LB::Expr
where
    LB: BlakeGCompressionLookupBuilder,
{
    let base = footer_xor_slot_col(slot, 0);
    let lhs = c::<LB>(local, base);
    let rhs = c::<LB>(local, base + 1);
    let and = c::<LB>(local, base + 2);
    lhs + rhs - and.clone() - and
}

fn first_input_pair_fields<LB>(local: &BlakeGCompressionCols<LB::Var>, pair: usize) -> [LB::Expr; 3]
where
    LB: BlakeGCompressionLookupBuilder,
{
    let word = |idx| {
        if idx < 4 {
            c::<LB>(local, G_A_BASE_COL + idx)
        } else {
            pack4::<LB>(
                c::<LB>(local, g_bd_rot_slot_col(idx - 4, 0, 0)),
                c::<LB>(local, g_bd_rot_slot_col(idx - 4, 1, 0)),
                c::<LB>(local, g_bd_rot_slot_col(idx - 4, 2, 0)),
                c::<LB>(local, g_bd_rot_slot_col(idx - 4, 3, 0)),
            )
        }
    };

    [expr::<LB>(pair as u64), word(2 * pair), word(2 * pair + 1)]
}

fn narrow_slot_fields<LB>(local: &BlakeGCompressionCols<LB::Var>, slot: usize) -> [LB::Expr; 3]
where
    LB: BlakeGCompressionLookupBuilder,
{
    match slot {
        0..=35 => fields_at::<LB>(local, byte_slot_base(0, slot)),
        36..=39 => first_input_pair_fields::<LB>(local, slot - 36),
        _ => unreachable!("32-row BlakeG narrow slot out of range"),
    }
}

fn fields_at<LB>(local: &BlakeGCompressionCols<LB::Var>, base: usize) -> [LB::Expr; 3]
where
    LB: BlakeGCompressionLookupBuilder,
{
    [c::<LB>(local, base), c::<LB>(local, base + 1), c::<LB>(local, base + 2)]
}

fn is_fused<LB>(selectors: &BlakeGSelectors<LB::Expr>) -> LB::Expr
where
    LB: BlakeGCompressionLookupBuilder,
{
    selectors.is_ab() + selectors.is_cd()
}

#[inline]
fn c<LB>(local: &BlakeGCompressionCols<LB::Var>, idx: usize) -> LB::Expr
where
    LB: BlakeGCompressionLookupBuilder,
{
    local.columns[idx].into()
}

#[inline]
fn expr<LB>(value: u64) -> LB::Expr
where
    LB: BlakeGCompressionLookupBuilder,
{
    LB::Expr::from(Felt::new_unchecked(value))
}

fn pack4<LB>(b0: LB::Expr, b1: LB::Expr, b2: LB::Expr, b3: LB::Expr) -> LB::Expr
where
    LB: BlakeGCompressionLookupBuilder,
{
    b0 + expr::<LB>(256) * b1 + expr::<LB>(1 << 16) * b2 + expr::<LB>(1 << 24) * b3
}

#[cfg(test)]
pub fn lookup_plan(row: usize, mode: BlakeGCompressionMode) -> LookupPlan {
    let mut plan = LookupPlan {
        narrow: Vec::new(),
        singletons: Vec::new(),
    };

    match row_kind(row) {
        RowKind::Ab => {
            add_fused_g_lookups(&mut plan, NarrowLookupKind::Rot12);
            if row == 0 {
                push_narrow(&mut plan, NarrowLookupKind::InputPair, -1, 4);
            }
        },
        RowKind::AbDiag => add_fused_g_lookups(&mut plan, NarrowLookupKind::Rot12),
        RowKind::Cd | RowKind::CdDiag => add_fused_g_lookups(&mut plan, NarrowLookupKind::Rot7),
        RowKind::Footer(footer) => add_footer_lookups(&mut plan, footer, mode),
    }

    plan
}

#[cfg(test)]
fn add_fused_g_lookups(plan: &mut LookupPlan, rotation_kind: NarrowLookupKind) {
    push_narrow(plan, NarrowLookupKind::And8, -1, BYTE_SLOTS_PER_STEP);
    push_narrow(plan, rotation_kind, -1, BYTE_SLOTS_PER_STEP);
    push_narrow(plan, NarrowLookupKind::MessageWord, 1, NUM_G);
}

#[cfg(test)]
fn add_footer_lookups(plan: &mut LookupPlan, footer: usize, mode: BlakeGCompressionMode) {
    push_narrow(plan, NarrowLookupKind::And8, -1, FOOTER_AND8_LOOKUPS);
    push_narrow(plan, NarrowLookupKind::InputPair, 1, 1);
    push_narrow(plan, NarrowLookupKind::MessageWord, -7, F_MSG_WORD_SLOTS);
    push_narrow(plan, NarrowLookupKind::RangeCheck, -1, F_RANGE_SLOTS);

    match mode {
        BlakeGCompressionMode::Compression => {
            if footer == FOOTER_ROWS - 1 {
                plan.singletons.push(SingletonLookup {
                    kind: SingletonLookupKind::CompressionLink,
                    sign: -1,
                });
            }
        },
        BlakeGCompressionMode::AeadXof => {
            if footer == FOOTER_ROWS - 1 {
                plan.singletons.push(SingletonLookup {
                    kind: SingletonLookupKind::AeadInput,
                    sign: -1,
                });
            }
            plan.singletons.push(SingletonLookup {
                kind: SingletonLookupKind::AeadLowOutputPair,
                sign: -1,
            });
            plan.singletons.push(SingletonLookup {
                kind: SingletonLookupKind::AeadHighOutputPair,
                sign: -1,
            });
        },
    }
}

#[cfg(test)]
fn push_narrow(plan: &mut LookupPlan, kind: NarrowLookupKind, sign: i8, count: usize) {
    plan.narrow.extend((0..count).map(|_| NarrowLookup { kind, sign }));
}
