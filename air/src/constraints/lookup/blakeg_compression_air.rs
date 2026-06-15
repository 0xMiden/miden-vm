//! BlakeG compression LogUp lookup AIR.

use miden_core::{Felt, field::PrimeCharacteristicRing};

use super::messages::{
    BlakeGInputPairMsg, BlakeGWordMsg, BusId, HasherPermLinkMsg, blakeg_rot7_bus, blakeg_rot12_bus,
};
use crate::{
    constraints::blakeg_compression::{
        BlakeGCompressionCols, IFACE_C_BASE_COL, IFACE_D_BASE_COL, IFACE_MULTIPLICITY_COL,
        IFACE_R_BASE_COL, periodic::*,
    },
    lookup::{Deg, LookupBuilder, LookupColumn, LookupGroup, LookupMessage},
};

pub(crate) trait BlakeGCompressionLookupBuilder: LookupBuilder<F = Felt> {}

pub(crate) const BLAKEG_COMPRESSION_COLUMN_SHAPE: [usize; 12] =
    [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1];

const BYTE_SLOT_WIDTH: usize = 3;
const AC_A_BASE_COL: usize = 60;
const AC_B_BASE_COL: usize = 64;
const NARROW_BATCH_COLUMNS: usize = 10;
const LAST_NARROW_BATCH_COLUMN: usize = NARROW_BATCH_COLUMNS - 1;
const NARROW_SLOT_PAIR_OFFSET: usize = NARROW_BATCH_COLUMNS;
const ANNEX0_COLUMN: usize = NARROW_BATCH_COLUMNS;
const ANNEX1_COLUMN: usize = ANNEX0_COLUMN + 1;
const NARROW_SLOT_COUNT: usize = 2 * NARROW_BATCH_COLUMNS;
const BYTE_SLOT_LAST: usize = 19;
const BYTE_COMMON_SLOT_LAST: usize = 13;
const BYTE_M0_SLOT_LAST: usize = 15;
const M0_ROUTE_OR_FIRST_B_HIN_SLOT: usize = 16;
const FOOTER_OUT_MASK_SLOT: usize = 17;
const AC_FOOTER_HIN_SLOT: usize = 18;
const AC_ONLY_SLOT: usize = 19;
const COMPACT_PAIR_BASE_COL: usize = AC_A_BASE_COL;
const COMPACT_M0_PAIR_INDEX_BASE: usize = 6;
const COMPACT_M1_PAIR_INDEX_BASE: usize = 14;
const WORD_BYTE_COUNT: usize = 4;

const ACTIVITY_COMMON_BYTE: usize = 0;
const ACTIVITY_M0_BYTE: usize = 1;
const ACTIVITY_M0_ROUTE_OR_FIRST_B_HIN: usize = 2;
const ACTIVITY_FOOTER_OUT_MASK: usize = 3;
const ACTIVITY_AC_FOOTER_HIN: usize = 4;
const ACTIVITY_AC_ONLY: usize = 5;
const ACTIVITY_GROUP_COUNT: usize = 6;

const MULTIPLICITY_INPUT_WORD_BYTE: usize = 0;
const MULTIPLICITY_LOW_MESSAGE_BYTE: usize = 1;
const MULTIPLICITY_COMMON_BYTE: usize = 2;
const MULTIPLICITY_M0_BYTE: usize = 3;
const MULTIPLICITY_M0_ROUTE_OR_FIRST_B_HIN: usize = 4;
const MULTIPLICITY_FOOTER_OUT_MASK: usize = 5;
const MULTIPLICITY_AC_FOOTER_HIN: usize = 6;
const MULTIPLICITY_AC_ONLY: usize = 7;
const MULTIPLICITY_GROUP_COUNT: usize = 8;

const BATCH_2: Deg = Deg { v: 2, u: 2 };
const ANNEX0: Deg = Deg { v: 1, u: 2 };
const ANNEX1: Deg = Deg { v: 2, u: 2 };

const _: () = assert!(BLAKEG_COMPRESSION_COLUMN_SHAPE.len() == ANNEX1_COLUMN + 1);

#[inline]
fn column_deg(aux_col: usize) -> Deg {
    match aux_col {
        0..=LAST_NARROW_BATCH_COLUMN => BATCH_2,
        ANNEX0_COLUMN => ANNEX0,
        ANNEX1_COLUMN => ANNEX1,
        _ => unreachable!("BlakeG lookup aux column out of range"),
    }
}

#[cold]
#[inline(never)]
fn unreachable_narrow_slot(slot: usize) -> ! {
    unreachable!("narrow slot {slot} must be in 0..{NARROW_SLOT_COUNT}")
}

#[inline]
fn expr<LB: BlakeGCompressionLookupBuilder>(value: u64) -> LB::Expr {
    LB::Expr::from(Felt::new_unchecked(value))
}

#[inline]
fn c<LB: BlakeGCompressionLookupBuilder>(
    local: &BlakeGCompressionCols<LB::Var>,
    idx: usize,
) -> LB::Expr {
    local.columns[idx].into()
}

#[inline]
fn first_input_word_value<LB: BlakeGCompressionLookupBuilder>(
    local: &BlakeGCompressionCols<LB::Var>,
    idx: usize,
) -> LB::Expr {
    // Row 0 maps h[0..3] to A/C `a` and h[4..7] to A/C `b`.
    let trace_col = if idx < 4 {
        AC_A_BASE_COL + idx
    } else {
        AC_B_BASE_COL + (idx - 4)
    };
    c::<LB>(local, trace_col)
}

fn first_input_pair<LB: BlakeGCompressionLookupBuilder>(
    local: &BlakeGCompressionCols<LB::Var>,
    pair_idx: usize,
) -> BlakeGInputPairMsg<LB::Expr> {
    BlakeGInputPairMsg {
        pair_index: expr::<LB>(pair_idx as u64),
        word_even: first_input_word_value::<LB>(local, 2 * pair_idx),
        word_odd: first_input_word_value::<LB>(local, 2 * pair_idx + 1),
    }
}

#[inline]
fn insert_signed_group<G, M>(g: &mut G, name: &'static str, flag: G::Expr, sign: i32, msg: M)
where
    G: LookupGroup,
    M: LookupMessage<G::Expr, G::ExprEF>,
{
    let multiplicity = if sign >= 0 {
        G::Expr::from_u32(sign as u32)
    } else {
        G::Expr::ZERO - G::Expr::from_u32((-sign) as u32)
    };
    g.insert(name, flag, multiplicity, || msg, Deg { v: 1, u: 1 });
}

#[inline]
fn scale_expr<E>(value: E, coeff: i32) -> E
where
    E: PrimeCharacteristicRing + Clone,
{
    if coeff >= 0 {
        value * E::from_u32(coeff as u32)
    } else {
        E::ZERO - value * E::from_u32((-coeff) as u32)
    }
}

#[derive(Clone)]
struct SlotSelectors<E> {
    is_first: E,
    is_first_b: E,
    is_ac: E,
    is_b: E,
    is_d: E,
    is_footer: E,
    is_msg_row0: E,
    is_msg_row1: E,
    is_msg: E,
    is_iface_in: E,
    byte_lookup_rows: E,
    msg_or_iface_rows: E,
    m0_or_iface_rows: E,
    activity: [E; ACTIVITY_GROUP_COUNT],
    multiplicity: [E; MULTIPLICITY_GROUP_COUNT],
}

impl<E> SlotSelectors<E>
where
    E: PrimeCharacteristicRing + Clone,
{
    fn new(
        is_first: E,
        is_first_b: E,
        is_ac_nonfirst: E,
        is_b: E,
        is_d: E,
        is_footer: E,
        is_msg_row0: E,
        is_msg_row1: E,
        is_iface_in: E,
    ) -> Self {
        let is_ac = is_first.clone() + is_ac_nonfirst.clone();
        let is_msg = is_msg_row0.clone() + is_msg_row1.clone();
        let byte_lookup_rows = is_ac.clone() + is_footer.clone();
        let msg_or_iface_rows = is_msg.clone() + is_iface_in.clone();
        let m0_or_iface_rows = is_msg_row0.clone() + is_iface_in.clone();

        let activity = core::array::from_fn(|group| match group {
            ACTIVITY_COMMON_BYTE => {
                byte_lookup_rows.clone()
                    + is_b.clone()
                    + is_d.clone()
                    + is_msg.clone()
                    + is_iface_in.clone()
            },
            ACTIVITY_M0_BYTE => {
                byte_lookup_rows.clone() + is_b.clone() + is_d.clone() + m0_or_iface_rows.clone()
            },
            ACTIVITY_M0_ROUTE_OR_FIRST_B_HIN => {
                is_ac.clone() + is_msg_row0.clone() + is_first_b.clone()
            },
            ACTIVITY_FOOTER_OUT_MASK => {
                byte_lookup_rows.clone() + is_msg_row0.clone() + is_first_b.clone()
            },
            ACTIVITY_AC_FOOTER_HIN => is_ac.clone() + is_footer.clone(),
            ACTIVITY_AC_ONLY => is_ac.clone(),
            _ => unreachable!("invalid BlakeG activity group"),
        });

        let multiplicity = core::array::from_fn(|group| match group {
            MULTIPLICITY_INPUT_WORD_BYTE => {
                scale_expr(is_ac.clone(), -1)
                    + scale_expr(is_b.clone(), -1)
                    + scale_expr(is_d.clone(), -1)
                    + scale_expr(is_footer.clone(), -1)
                    + scale_expr(is_msg_row0.clone(), -7)
                    + scale_expr(is_msg_row1.clone(), -7)
                    + scale_expr(is_iface_in.clone(), 2)
            },
            MULTIPLICITY_LOW_MESSAGE_BYTE => {
                scale_expr(is_ac.clone(), -1)
                    + scale_expr(is_b.clone(), -1)
                    + scale_expr(is_d.clone(), -1)
                    + scale_expr(is_footer.clone(), -1)
                    + scale_expr(is_msg_row0.clone(), -7)
                    + scale_expr(is_msg_row1.clone(), -7)
                    + scale_expr(is_iface_in.clone(), -1)
            },
            MULTIPLICITY_COMMON_BYTE => {
                scale_expr(is_ac.clone(), -1)
                    + scale_expr(is_b.clone(), -1)
                    + scale_expr(is_d.clone(), -1)
                    + scale_expr(is_footer.clone(), -1)
                    + scale_expr(is_msg_row0.clone(), -1)
                    + scale_expr(is_msg_row1.clone(), -1)
                    + scale_expr(is_iface_in.clone(), -1)
            },
            MULTIPLICITY_M0_BYTE => {
                scale_expr(is_ac.clone(), -1)
                    + scale_expr(is_b.clone(), -1)
                    + scale_expr(is_d.clone(), -1)
                    + scale_expr(is_footer.clone(), -1)
                    + scale_expr(is_msg_row0.clone(), -1)
                    + scale_expr(is_iface_in.clone(), -1)
            },
            MULTIPLICITY_M0_ROUTE_OR_FIRST_B_HIN => {
                is_ac.clone()
                    + scale_expr(is_msg_row0.clone(), -1)
                    + scale_expr(is_first_b.clone(), -1)
            },
            MULTIPLICITY_FOOTER_OUT_MASK => {
                is_ac.clone()
                    + scale_expr(is_footer.clone(), -1)
                    + scale_expr(is_msg_row0.clone(), -1)
                    + scale_expr(is_first_b.clone(), -1)
            },
            MULTIPLICITY_AC_FOOTER_HIN => is_ac.clone() + scale_expr(is_footer.clone(), -1),
            MULTIPLICITY_AC_ONLY => is_ac.clone(),
            _ => unreachable!("invalid BlakeG multiplicity group"),
        });

        Self {
            is_first,
            is_first_b,
            is_ac,
            is_b,
            is_d,
            is_footer,
            is_msg_row0,
            is_msg_row1,
            is_msg,
            is_iface_in,
            byte_lookup_rows,
            msg_or_iface_rows,
            m0_or_iface_rows,
            activity,
            multiplicity,
        }
    }
}

#[inline]
fn slot_activity_group(slot: usize) -> Option<usize> {
    match slot {
        0..=BYTE_COMMON_SLOT_LAST => Some(ACTIVITY_COMMON_BYTE),
        14..=BYTE_M0_SLOT_LAST => Some(ACTIVITY_M0_BYTE),
        M0_ROUTE_OR_FIRST_B_HIN_SLOT => Some(ACTIVITY_M0_ROUTE_OR_FIRST_B_HIN),
        FOOTER_OUT_MASK_SLOT => Some(ACTIVITY_FOOTER_OUT_MASK),
        AC_FOOTER_HIN_SLOT => Some(ACTIVITY_AC_FOOTER_HIN),
        AC_ONLY_SLOT => Some(ACTIVITY_AC_ONLY),
        _ => unreachable_narrow_slot(slot),
    }
}

#[inline]
fn slot_multiplicity_group(slot: usize) -> Option<usize> {
    match slot {
        0..=3 => Some(MULTIPLICITY_INPUT_WORD_BYTE),
        4..=5 => Some(MULTIPLICITY_LOW_MESSAGE_BYTE),
        6..=BYTE_COMMON_SLOT_LAST => Some(MULTIPLICITY_COMMON_BYTE),
        14..=BYTE_M0_SLOT_LAST => Some(MULTIPLICITY_M0_BYTE),
        M0_ROUTE_OR_FIRST_B_HIN_SLOT => Some(MULTIPLICITY_M0_ROUTE_OR_FIRST_B_HIN),
        FOOTER_OUT_MASK_SLOT => Some(MULTIPLICITY_FOOTER_OUT_MASK),
        AC_FOOTER_HIN_SLOT => Some(MULTIPLICITY_AC_FOOTER_HIN),
        AC_ONLY_SLOT => Some(MULTIPLICITY_AC_ONLY),
        _ => unreachable_narrow_slot(slot),
    }
}

#[inline]
fn add_bus<G>(acc: &mut G::ExprEF, group: &G, bus: BusId, selector: G::Expr)
where
    G: LookupGroup,
{
    *acc = acc.clone() + group.bus_prefix(bus as usize) * selector;
}

#[inline]
fn add_field<G>(acc: &mut G::ExprEF, group: &G, index: usize, value: G::Expr)
where
    G: LookupGroup,
{
    *acc = acc.clone() + group.beta_powers()[index].clone() * value;
}

fn selected_slot_fields<LB>(local: &BlakeGCompressionCols<LB::Var>, slot: usize) -> [LB::Expr; 3]
where
    LB: BlakeGCompressionLookupBuilder,
{
    match slot {
        0..=BYTE_SLOT_LAST => {
            let base = BYTE_SLOT_WIDTH * slot;
            [c::<LB>(local, base), c::<LB>(local, base + 1), c::<LB>(local, base + 2)]
        },
        _ => unreachable_narrow_slot(slot),
    }
}

fn selected_slot_activity<LB>(slot: usize, selectors: &SlotSelectors<LB::Expr>) -> LB::Expr
where
    LB: BlakeGCompressionLookupBuilder,
{
    match slot_activity_group(slot) {
        Some(group) => selectors.activity[group].clone(),
        None => LB::Expr::ZERO,
    }
}

fn selected_slot_multiplicity<LB>(slot: usize, selectors: &SlotSelectors<LB::Expr>) -> LB::Expr
where
    LB: BlakeGCompressionLookupBuilder,
{
    match slot_multiplicity_group(slot) {
        Some(group) => selectors.multiplicity[group].clone(),
        None => LB::Expr::ZERO,
    }
}

#[inline]
fn add_byte_slot_buses<LB, G>(
    encoded: &mut G::ExprEF,
    group: &G,
    slot: usize,
    selectors: &SlotSelectors<LB::Expr>,
) where
    LB: BlakeGCompressionLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    add_bus(encoded, group, BusId::And8Lookup, selectors.byte_lookup_rows.clone());
    add_bus(encoded, group, blakeg_rot12_bus(slot % WORD_BYTE_COUNT), selectors.is_b.clone());
    add_bus(encoded, group, blakeg_rot7_bus(slot % WORD_BYTE_COUNT), selectors.is_d.clone());
}

fn selected_slot_encoding<LB, G>(
    group: &G,
    local: &BlakeGCompressionCols<LB::Var>,
    slot: usize,
    selectors: &SlotSelectors<LB::Expr>,
) -> G::ExprEF
where
    LB: BlakeGCompressionLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let mut encoded = G::ExprEF::ZERO;

    match slot {
        0..=3 => {
            add_byte_slot_buses::<LB, G>(&mut encoded, group, slot, selectors);
            add_bus(&mut encoded, group, BusId::BlakeGMessageWord, selectors.is_msg.clone());
            add_bus(&mut encoded, group, BusId::BlakeGInputWord, selectors.is_iface_in.clone());
        },
        4..=5 => {
            add_byte_slot_buses::<LB, G>(&mut encoded, group, slot, selectors);
            add_bus(&mut encoded, group, BusId::BlakeGMessageWord, selectors.is_msg.clone());
            add_bus(&mut encoded, group, BusId::RangeCheck, selectors.is_iface_in.clone());
        },
        6..=BYTE_COMMON_SLOT_LAST => {
            add_byte_slot_buses::<LB, G>(&mut encoded, group, slot, selectors);
            add_bus(&mut encoded, group, BusId::RangeCheck, selectors.msg_or_iface_rows.clone());
        },
        14..=BYTE_M0_SLOT_LAST => {
            add_byte_slot_buses::<LB, G>(&mut encoded, group, slot, selectors);
            add_bus(&mut encoded, group, BusId::RangeCheck, selectors.m0_or_iface_rows.clone());
        },
        M0_ROUTE_OR_FIRST_B_HIN_SLOT => {
            add_bus(&mut encoded, group, BusId::BlakeGMessageWord, selectors.is_ac.clone());
            add_bus(&mut encoded, group, BusId::RangeCheck, selectors.is_msg_row0.clone());
            add_bus(&mut encoded, group, BusId::BlakeGInputWord, selectors.is_first_b.clone());
        },
        FOOTER_OUT_MASK_SLOT => {
            add_bus(&mut encoded, group, BusId::BlakeGMessageWord, selectors.is_ac.clone());
            add_bus(&mut encoded, group, BusId::And8Lookup, selectors.is_footer.clone());
            add_bus(&mut encoded, group, BusId::RangeCheck, selectors.is_msg_row0.clone());
            add_bus(&mut encoded, group, BusId::BlakeGInputWord, selectors.is_first_b.clone());
        },
        AC_FOOTER_HIN_SLOT => {
            add_bus(&mut encoded, group, BusId::BlakeGMessageWord, selectors.is_ac.clone());
            add_bus(&mut encoded, group, BusId::BlakeGInputWord, selectors.is_footer.clone());
        },
        AC_ONLY_SLOT => {
            add_bus(&mut encoded, group, BusId::BlakeGMessageWord, selectors.is_ac.clone());
        },
        _ => unreachable_narrow_slot(slot),
    }

    // Inactive slots use a fixed RangeCheck dummy denominator. This keeps every
    // batch denominator nonzero without selecting trace payloads by row type.
    let active = selected_slot_activity::<LB>(slot, selectors);
    add_bus(&mut encoded, group, BusId::RangeCheck, LB::Expr::ONE - active);

    let fields = selected_slot_fields::<LB>(local, slot);
    for (idx, field) in fields.into_iter().enumerate() {
        add_field(&mut encoded, group, idx, field);
    }
    encoded
}

pub(crate) fn emit_blakeg_compression_lookup_columns<LB>(
    builder: &mut LB,
    local: &BlakeGCompressionCols<LB::Var>,
) where
    LB: BlakeGCompressionLookupBuilder,
{
    let p = builder.periodic_values();
    let is_a: LB::Expr = p[P_IS_A].into();
    let is_b: LB::Expr = p[P_IS_B].into();
    let is_c: LB::Expr = p[P_IS_C].into();
    let is_d: LB::Expr = p[P_IS_D].into();
    let is_first: LB::Expr = p[P_IS_FIRST_COMP].into();
    let is_first_b: LB::Expr = p[P_IS_FIRST_B].into();
    let is_f0: LB::Expr = p[P_IS_F0].into();
    let is_f1: LB::Expr = p[P_IS_F1].into();
    let is_f2: LB::Expr = p[P_IS_F2].into();
    let is_f3: LB::Expr = p[P_IS_F3].into();
    let is_iface_in: LB::Expr = p[P_IS_IFACE_IN].into();
    let is_msg_row0: LB::Expr = p[P_IS_MSG_ROW0].into();
    let is_msg_row1: LB::Expr = p[P_IS_MSG_ROW1].into();
    let gate_add3 = is_a.clone() + is_c.clone();
    let gate_add3_nonfirst = gate_add3.clone() - is_first.clone();
    let is_footer = is_f0 + is_f1 + is_f2 + is_f3;
    let selectors = SlotSelectors::new(
        is_first.clone(),
        is_first_b.clone(),
        gate_add3_nonfirst.clone(),
        is_b.clone(),
        is_d.clone(),
        is_footer,
        is_msg_row0.clone(),
        is_msg_row1.clone(),
        is_iface_in.clone(),
    );

    for aux_col in 0..BLAKEG_COMPRESSION_COLUMN_SHAPE.len() {
        builder.next_column(
            |col| {
                emit_lookup_column::<LB, _>(col, local, aux_col, &selectors);
            },
            column_deg(aux_col),
        );
    }
}

fn emit_lookup_column<LB, C>(
    column: &mut C,
    local: &BlakeGCompressionCols<LB::Var>,
    aux_col: usize,
    selectors: &SlotSelectors<LB::Expr>,
) where
    LB: BlakeGCompressionLookupBuilder,
    C: LookupColumn<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    match aux_col {
        0..=LAST_NARROW_BATCH_COLUMN => column.group(
            "blakeg_compression",
            |g| emit_selected_slot_pair_batch::<LB, _>(g, local, aux_col, selectors),
            column_deg(aux_col),
        ),
        ANNEX0_COLUMN => column.group(
            "blakeg_compression",
            |g| emit_annex0::<LB, _>(g, local, selectors),
            column_deg(aux_col),
        ),
        ANNEX1_COLUMN => column.group(
            "blakeg_compression",
            |g| emit_annex1::<LB, _>(g, local, selectors),
            column_deg(aux_col),
        ),
        _ => unreachable!("BlakeG lookup aux column out of range"),
    }
}

fn emit_selected_slot_pair_batch<LB, G>(
    group: &mut G,
    local: &BlakeGCompressionCols<LB::Var>,
    low_slot: usize,
    selectors: &SlotSelectors<LB::Expr>,
) where
    LB: BlakeGCompressionLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let high_slot = low_slot + NARROW_SLOT_PAIR_OFFSET;
    let low_mult = selected_slot_multiplicity::<LB>(low_slot, selectors);
    let high_mult = selected_slot_multiplicity::<LB>(high_slot, selectors);
    let low_encoded = selected_slot_encoding::<LB, G>(&*group, local, low_slot, selectors);
    let high_encoded = selected_slot_encoding::<LB, G>(&*group, local, high_slot, selectors);

    group.selected_batch2_encoded(
        "selected_slot_pair",
        "low_slot",
        low_mult,
        || low_encoded,
        "high_slot",
        high_mult,
        || high_encoded,
    );
}

fn compact_message_word<LB: BlakeGCompressionLookupBuilder>(
    local: &BlakeGCompressionCols<LB::Var>,
    index: usize,
    pair_offset: usize,
) -> BlakeGWordMsg<LB::Expr> {
    BlakeGWordMsg {
        index: expr::<LB>(index as u64),
        word: c::<LB>(local, COMPACT_PAIR_BASE_COL + 2 * pair_offset),
    }
}

fn compression_link_msg<LB: BlakeGCompressionLookupBuilder>(
    local: &BlakeGCompressionCols<LB::Var>,
) -> HasherPermLinkMsg<LB::Expr> {
    HasherPermLinkMsg {
        block: core::array::from_fn(|i| c::<LB>(local, IFACE_R_BASE_COL + i)),
        cv_in: core::array::from_fn(|i| c::<LB>(local, IFACE_C_BASE_COL + i)),
        cv_out: core::array::from_fn(|i| c::<LB>(local, IFACE_D_BASE_COL + i)),
    }
}

fn emit_annex0<LB, G>(
    group: &mut G,
    local: &BlakeGCompressionCols<LB::Var>,
    selectors: &SlotSelectors<LB::Expr>,
) where
    LB: BlakeGCompressionLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    insert_signed_group(
        group,
        "first_hin_pair0",
        selectors.is_first.clone(),
        -1,
        first_input_pair::<LB>(local, 0),
    );

    insert_signed_group(
        group,
        "m0_compact_word6",
        selectors.is_msg_row0.clone(),
        -7,
        compact_message_word::<LB>(local, COMPACT_M0_PAIR_INDEX_BASE, 0),
    );
    insert_signed_group(
        group,
        "m1_compact_word14",
        selectors.is_msg_row1.clone(),
        -7,
        compact_message_word::<LB>(local, COMPACT_M1_PAIR_INDEX_BASE, 0),
    );
}

fn emit_annex1<LB, G>(
    group: &mut G,
    local: &BlakeGCompressionCols<LB::Var>,
    selectors: &SlotSelectors<LB::Expr>,
) where
    LB: BlakeGCompressionLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    insert_signed_group(
        group,
        "first_hin_pair1",
        selectors.is_first.clone(),
        -1,
        first_input_pair::<LB>(local, 1),
    );

    insert_signed_group(
        group,
        "m0_compact_word7",
        selectors.is_msg_row0.clone(),
        -7,
        compact_message_word::<LB>(local, COMPACT_M0_PAIR_INDEX_BASE + 1, 1),
    );
    insert_signed_group(
        group,
        "m1_compact_word15",
        selectors.is_msg_row1.clone(),
        -7,
        compact_message_word::<LB>(local, COMPACT_M1_PAIR_INDEX_BASE + 1, 1),
    );

    let mult = -c::<LB>(local, IFACE_MULTIPLICITY_COL);
    group.insert(
        "compression_link",
        selectors.is_iface_in.clone(),
        mult,
        || compression_link_msg::<LB>(local),
        ANNEX1,
    );
}
