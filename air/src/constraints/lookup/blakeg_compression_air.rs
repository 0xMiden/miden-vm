//! BlakeG compression LogUp lookup AIR.

use miden_core::{Felt, field::PrimeCharacteristicRing};

use super::messages::{
    AeadBlakeGInputMsg, AeadBlakeGOutputPairMsg, And8Msg, BlakeGInputPairMsg, BlakeGWordMsg,
    HasherCompressionLinkMsg, RangeMsg,
};
use crate::{
    constraints::blakeg_compression::{
        AEAD_XOF_CLK_COL, AEAD_XOF_MODE_COL, BlakeGCompressionCols, FOOTER_H_EVEN_WORD_COL,
        FOOTER_H_ODD_WORD_COL, FOOTER_OUT_MASKED_TOP_BIT_COL, FOOTER_OUT_ODD_TOP_BYTE_COL,
        FOOTER_OUT_TOP_MASK_COL, FOOTER_ROW_INDEX_COL, IFACE_C_BASE_COL, IFACE_D_BASE_COL,
        IFACE_MULTIPLICITY_COL, IFACE_R_BASE_COL, iface_h_word_col, msg_m0_range_col,
        msg_m1_range_col, msg_word_col, periodic::*,
    },
    lookup::{Deg, LookupBuilder, LookupColumn, LookupGroup},
};

pub(crate) trait BlakeGCompressionLookupBuilder: LookupBuilder<F = Felt> {}

pub(crate) const BLAKEG_COMPRESSION_COLUMN_SHAPE: [usize; 24] = [1; 24];

const BYTE_SLOT_WIDTH: usize = 3;
const BYTE_SLOTS_PER_ROW: usize = 16;
const AC_A_BASE_COL: usize = 60;
const AC_B_BASE_COL: usize = 64;

// Singleton layout: columns 0..15 carry byte/range facts, columns 16..23 carry word-level facts.
// Column 20 is shared by row-0 HIN pairs and the interface link; those row selectors are disjoint.
const LOCAL_BYTE_OR_RANGE_COLUMNS: core::ops::RangeInclusive<usize> = 0..=15;
const WORD_COLUMNS: core::ops::RangeInclusive<usize> = 16..=23;
const AEAD_XOF_LOW_COLUMN: usize = 18;
const AEAD_XOF_HIGH_COLUMN: usize = 19;
const IFACE_LINK_COLUMN: usize = 20;
const FIRST_HIN_COLUMN_BASE: usize = 20;
const FIRST_HIN_COLUMN_LAST: usize = 23;
const FOOTER_BYTE_SLOT_COUNT: usize = 18;
const FOOTER_HIGH_EVEN_SLOT_BASE: usize = 0;
const FOOTER_HIGH_ODD_SLOT_BASE: usize = 4;
const FOOTER_OUTPUT_EVEN_SLOT_BASE: usize = 8;
const FOOTER_OUTPUT_ODD_SLOT_BASE: usize = 12;
const WORD_BYTE_COUNT: usize = 4;

const ROW_SELECTED: Deg = Deg { v: 1, u: 2 };
const AEAD_XOF_PAIR: Deg = Deg { v: 2, u: 2 };
const AEAD_XOF_INPUT: Deg = Deg { v: 2, u: 2 };
const COMPRESSION_LINK: Deg = Deg { v: 3, u: 2 };
const INTERFACE_LINK: Deg = Deg { v: 3, u: 3 };

const _: () = assert!(BLAKEG_COMPRESSION_COLUMN_SHAPE.len() == FIRST_HIN_COLUMN_LAST + 1);

#[inline]
fn column_deg(aux_col: usize) -> Deg {
    match aux_col {
        0..=17 => ROW_SELECTED,
        AEAD_XOF_LOW_COLUMN | AEAD_XOF_HIGH_COLUMN => AEAD_XOF_PAIR,
        IFACE_LINK_COLUMN => INTERFACE_LINK,
        21..=FIRST_HIN_COLUMN_LAST => ROW_SELECTED,
        _ => unreachable!("BlakeG lookup aux column out of range"),
    }
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
fn pack4<LB: BlakeGCompressionLookupBuilder>(
    b0: LB::Expr,
    b1: LB::Expr,
    b2: LB::Expr,
    b3: LB::Expr,
) -> LB::Expr {
    b0 + b1 * expr::<LB>(256) + b2 * expr::<LB>(1 << 16) + b3 * expr::<LB>(1 << 24)
}

#[inline]
fn footer_slot_field(slot: usize, field: usize) -> usize {
    debug_assert!(slot < FOOTER_BYTE_SLOT_COUNT);
    debug_assert!(field < 3);
    BYTE_SLOT_WIDTH * slot + field
}

#[inline]
fn footer_xor_word<LB: BlakeGCompressionLookupBuilder>(
    local: &BlakeGCompressionCols<LB::Var>,
    slot_base: usize,
) -> LB::Expr {
    let two = expr::<LB>(2);
    pack4::<LB>(
        c::<LB>(local, footer_slot_field(slot_base, 0))
            + c::<LB>(local, footer_slot_field(slot_base, 1))
            - two.clone() * c::<LB>(local, footer_slot_field(slot_base, 2)),
        c::<LB>(local, footer_slot_field(slot_base + 1, 0))
            + c::<LB>(local, footer_slot_field(slot_base + 1, 1))
            - two.clone() * c::<LB>(local, footer_slot_field(slot_base + 1, 2)),
        c::<LB>(local, footer_slot_field(slot_base + 2, 0))
            + c::<LB>(local, footer_slot_field(slot_base + 2, 1))
            - two.clone() * c::<LB>(local, footer_slot_field(slot_base + 2, 2)),
        c::<LB>(local, footer_slot_field(slot_base + 3, 0))
            + c::<LB>(local, footer_slot_field(slot_base + 3, 1))
            - two * c::<LB>(local, footer_slot_field(slot_base + 3, 2)),
    )
}

#[inline]
fn footer_high_word<LB: BlakeGCompressionLookupBuilder>(
    local: &BlakeGCompressionCols<LB::Var>,
    odd: bool,
) -> LB::Expr {
    let slot_base = if odd {
        FOOTER_HIGH_ODD_SLOT_BASE
    } else {
        FOOTER_HIGH_EVEN_SLOT_BASE
    };
    footer_xor_word::<LB>(local, slot_base)
}

#[inline]
fn footer_output_word<LB: BlakeGCompressionLookupBuilder>(
    local: &BlakeGCompressionCols<LB::Var>,
    odd: bool,
) -> LB::Expr {
    let slot_base = if odd {
        FOOTER_OUTPUT_ODD_SLOT_BASE
    } else {
        FOOTER_OUTPUT_EVEN_SLOT_BASE
    };
    footer_xor_word::<LB>(local, slot_base)
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

fn iface_input_pair<LB: BlakeGCompressionLookupBuilder>(
    local: &BlakeGCompressionCols<LB::Var>,
    pair_idx: usize,
) -> BlakeGInputPairMsg<LB::Expr> {
    BlakeGInputPairMsg {
        pair_index: expr::<LB>(pair_idx as u64),
        word_even: c::<LB>(local, iface_h_word_col(2 * pair_idx)),
        word_odd: c::<LB>(local, iface_h_word_col(2 * pair_idx + 1)),
    }
}

fn footer_input_pair<LB: BlakeGCompressionLookupBuilder>(
    local: &BlakeGCompressionCols<LB::Var>,
) -> BlakeGInputPairMsg<LB::Expr> {
    BlakeGInputPairMsg {
        pair_index: c::<LB>(local, FOOTER_ROW_INDEX_COL),
        word_even: c::<LB>(local, FOOTER_H_EVEN_WORD_COL),
        word_odd: c::<LB>(local, FOOTER_H_ODD_WORD_COL),
    }
}

fn ac_message_word<LB: BlakeGCompressionLookupBuilder>(
    local: &BlakeGCompressionCols<LB::Var>,
    lane: usize,
) -> BlakeGWordMsg<LB::Expr> {
    let base = BYTE_SLOT_WIDTH * BYTE_SLOTS_PER_ROW + BYTE_SLOT_WIDTH * lane;
    BlakeGWordMsg {
        index: c::<LB>(local, base),
        word: c::<LB>(local, base + 1),
    }
}

fn message_row_word<LB: BlakeGCompressionLookupBuilder>(
    local: &BlakeGCompressionCols<LB::Var>,
    local_idx: usize,
    global_idx: usize,
) -> BlakeGWordMsg<LB::Expr> {
    BlakeGWordMsg {
        index: expr::<LB>(global_idx as u64),
        word: c::<LB>(local, msg_word_col(local_idx)),
    }
}

fn footer_top_bit_msg<LB: BlakeGCompressionLookupBuilder>(
    local: &BlakeGCompressionCols<LB::Var>,
) -> And8Msg<LB::Expr> {
    And8Msg::new(
        c::<LB>(local, FOOTER_OUT_ODD_TOP_BYTE_COL),
        c::<LB>(local, FOOTER_OUT_TOP_MASK_COL),
        c::<LB>(local, FOOTER_OUT_MASKED_TOP_BIT_COL),
    )
}

#[derive(Clone)]
struct RowSelectors<E> {
    is_first: E,
    is_ac: E,
    is_b: E,
    is_d: E,
    is_footer: E,
    is_msg_row0: E,
    is_msg_row1: E,
    is_iface_in: E,
}

impl<E> RowSelectors<E> {
    fn new(
        is_first: E,
        is_ac: E,
        is_b: E,
        is_d: E,
        is_footer: E,
        is_msg_row0: E,
        is_msg_row1: E,
        is_iface_in: E,
    ) -> Self {
        Self {
            is_first,
            is_ac,
            is_b,
            is_d,
            is_footer,
            is_msg_row0,
            is_msg_row1,
            is_iface_in,
        }
    }
}

fn byte_slot_fields<LB>(local: &BlakeGCompressionCols<LB::Var>, slot: usize) -> [LB::Expr; 3]
where
    LB: BlakeGCompressionLookupBuilder,
{
    debug_assert!(slot < BYTE_SLOTS_PER_ROW);
    let base = BYTE_SLOT_WIDTH * slot;
    [c::<LB>(local, base), c::<LB>(local, base + 1), c::<LB>(local, base + 2)]
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
    let is_f0: LB::Expr = p[P_IS_F0].into();
    let is_f1: LB::Expr = p[P_IS_F1].into();
    let is_f2: LB::Expr = p[P_IS_F2].into();
    let is_f3: LB::Expr = p[P_IS_F3].into();
    let is_iface_in: LB::Expr = p[P_IS_IFACE_IN].into();
    let is_msg_row0: LB::Expr = p[P_IS_MSG_ROW0].into();
    let is_msg_row1: LB::Expr = p[P_IS_MSG_ROW1].into();
    let gate_add3 = is_a.clone() + is_c.clone();
    let footer_gates = [is_f0, is_f1, is_f2, is_f3];
    let is_footer = footer_gates.iter().cloned().fold(LB::Expr::ZERO, |acc, gate| acc + gate);
    let selectors = RowSelectors::new(
        is_first.clone(),
        gate_add3.clone(),
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
                emit_lookup_column::<LB, _>(col, local, aux_col, &selectors, &footer_gates);
            },
            column_deg(aux_col),
        );
    }
}

fn emit_lookup_column<LB, C>(
    column: &mut C,
    local: &BlakeGCompressionCols<LB::Var>,
    aux_col: usize,
    selectors: &RowSelectors<LB::Expr>,
    footer_gates: &[LB::Expr; 4],
) where
    LB: BlakeGCompressionLookupBuilder,
    C: LookupColumn<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    match aux_col {
        0..=15 => column.group(
            "blakeg_compression",
            |g| emit_local_byte_or_range_column::<LB, _>(g, local, aux_col, selectors),
            column_deg(aux_col),
        ),
        16..=23 => column.group(
            "blakeg_compression",
            |g| emit_word_column::<LB, _>(g, local, aux_col, selectors, footer_gates),
            column_deg(aux_col),
        ),
        _ => unreachable!("BlakeG lookup aux column out of range"),
    }
}

fn emit_local_byte_or_range_column<LB, G>(
    group: &mut G,
    local: &BlakeGCompressionCols<LB::Var>,
    col: usize,
    selectors: &RowSelectors<LB::Expr>,
) where
    LB: BlakeGCompressionLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    debug_assert!(LOCAL_BYTE_OR_RANGE_COLUMNS.contains(&col));

    let fields = byte_slot_fields::<LB>(local, col);
    group.remove(
        "ac_and8_byte",
        selectors.is_ac.clone(),
        || And8Msg::new(fields[0].clone(), fields[1].clone(), fields[2].clone()),
        ROW_SELECTED,
    );
    group.remove(
        "b_rot12_byte",
        selectors.is_b.clone(),
        || {
            And8Msg::blakeg_rot12(
                col % WORD_BYTE_COUNT,
                fields[0].clone(),
                fields[1].clone(),
                fields[2].clone(),
            )
        },
        ROW_SELECTED,
    );
    group.remove(
        "d_rot7_byte",
        selectors.is_d.clone(),
        || {
            And8Msg::blakeg_rot7(
                col % WORD_BYTE_COUNT,
                fields[0].clone(),
                fields[1].clone(),
                fields[2].clone(),
            )
        },
        ROW_SELECTED,
    );
    group.remove(
        "footer_and8_byte",
        selectors.is_footer.clone(),
        || And8Msg::new(fields[0].clone(), fields[1].clone(), fields[2].clone()),
        ROW_SELECTED,
    );

    group.remove(
        "m0_range_limb",
        selectors.is_msg_row0.clone(),
        || RangeMsg {
            value: c::<LB>(local, msg_m0_range_col(col)),
        },
        ROW_SELECTED,
    );
    group.remove(
        "m1_range_limb",
        selectors.is_msg_row1.clone(),
        || RangeMsg {
            value: c::<LB>(local, msg_m1_range_col(col)),
        },
        ROW_SELECTED,
    );

    if col < 4 {
        group.insert(
            "iface_hin_pair",
            selectors.is_iface_in.clone(),
            expr::<LB>(2),
            || iface_input_pair::<LB>(local, col),
            ROW_SELECTED,
        );
    }
}

fn emit_word_column<LB, G>(
    group: &mut G,
    local: &BlakeGCompressionCols<LB::Var>,
    aux_col: usize,
    selectors: &RowSelectors<LB::Expr>,
    footer_gates: &[LB::Expr; 4],
) where
    LB: BlakeGCompressionLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    debug_assert!(WORD_COLUMNS.contains(&aux_col));
    let word_idx = aux_col - 16;

    if word_idx < 4 {
        group.add(
            "ac_message_word",
            selectors.is_ac.clone(),
            || ac_message_word::<LB>(local, word_idx),
            ROW_SELECTED,
        );
    }

    group.insert(
        "m0_message_word",
        selectors.is_msg_row0.clone(),
        -expr::<LB>(7),
        || message_row_word::<LB>(local, word_idx, word_idx),
        ROW_SELECTED,
    );
    group.insert(
        "m1_message_word",
        selectors.is_msg_row1.clone(),
        -expr::<LB>(7),
        || message_row_word::<LB>(local, word_idx, 8 + word_idx),
        ROW_SELECTED,
    );

    match word_idx {
        0 => group.remove(
            "footer_top_bit",
            selectors.is_footer.clone(),
            || footer_top_bit_msg::<LB>(local),
            ROW_SELECTED,
        ),
        1 => group.remove(
            "footer_hin_pair",
            selectors.is_footer.clone(),
            || footer_input_pair::<LB>(local),
            ROW_SELECTED,
        ),
        2 => emit_aead_xof_pair::<LB, G>(
            group,
            local,
            footer_gates,
            "aead_xof_low_pair",
            0,
            footer_output_word::<LB>(local, false),
            footer_output_word::<LB>(local, true),
        ),
        3 => emit_aead_xof_pair::<LB, G>(
            group,
            local,
            footer_gates,
            "aead_xof_high_pair",
            8,
            footer_high_word::<LB>(local, false),
            footer_high_word::<LB>(local, true),
        ),
        _ => {},
    }

    if (FIRST_HIN_COLUMN_BASE..=FIRST_HIN_COLUMN_LAST).contains(&aux_col) {
        let pair_idx = aux_col - FIRST_HIN_COLUMN_BASE;
        group.remove(
            "first_hin_pair",
            selectors.is_first.clone(),
            || first_input_pair::<LB>(local, pair_idx),
            ROW_SELECTED,
        );
    }
    if aux_col == IFACE_LINK_COLUMN {
        emit_iface_link::<LB, G>(group, local, selectors);
    }
}

fn emit_iface_link<LB, G>(
    group: &mut G,
    local: &BlakeGCompressionCols<LB::Var>,
    selectors: &RowSelectors<LB::Expr>,
) where
    LB: BlakeGCompressionLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let mode = c::<LB>(local, AEAD_XOF_MODE_COL);
    let compression_mode = LB::Expr::ONE - mode.clone();

    group.insert(
        "compression_link",
        selectors.is_iface_in.clone() * compression_mode,
        -c::<LB>(local, IFACE_MULTIPLICITY_COL),
        || compression_link_msg::<LB>(local),
        COMPRESSION_LINK,
    );
    group.insert(
        "aead_blakeg_input",
        selectors.is_iface_in.clone() * mode,
        -LB::Expr::ONE,
        || aead_blakeg_input_msg::<LB>(local),
        AEAD_XOF_INPUT,
    );
}

fn compression_link_msg<LB: BlakeGCompressionLookupBuilder>(
    local: &BlakeGCompressionCols<LB::Var>,
) -> HasherCompressionLinkMsg<LB::Expr> {
    HasherCompressionLinkMsg {
        block: core::array::from_fn(|i| c::<LB>(local, IFACE_R_BASE_COL + i)),
        cv_in: core::array::from_fn(|i| c::<LB>(local, IFACE_C_BASE_COL + i)),
        cv_out: core::array::from_fn(|i| c::<LB>(local, IFACE_D_BASE_COL + i)),
    }
}

fn aead_blakeg_input_msg<LB: BlakeGCompressionLookupBuilder>(
    local: &BlakeGCompressionCols<LB::Var>,
) -> AeadBlakeGInputMsg<LB::Expr> {
    AeadBlakeGInputMsg {
        clk: c::<LB>(local, AEAD_XOF_CLK_COL),
        state: core::array::from_fn(|i| {
            if i < 8 {
                c::<LB>(local, IFACE_R_BASE_COL + i)
            } else {
                c::<LB>(local, IFACE_C_BASE_COL + (i - 8))
            }
        }),
    }
}

fn emit_aead_xof_pair<LB, G>(
    group: &mut G,
    local: &BlakeGCompressionCols<LB::Var>,
    footer_gates: &[LB::Expr; 4],
    name: &'static str,
    first_lane_offset: usize,
    value0: LB::Expr,
    value1: LB::Expr,
) where
    LB: BlakeGCompressionLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let multiplicity = -c::<LB>(local, AEAD_XOF_MODE_COL);
    let clk = c::<LB>(local, AEAD_XOF_CLK_COL);

    for (footer_row, gate) in footer_gates.iter().enumerate() {
        group.insert(
            name,
            gate.clone(),
            multiplicity.clone(),
            || AeadBlakeGOutputPairMsg {
                clk: clk.clone(),
                first_lane_idx: expr::<LB>((first_lane_offset + 2 * footer_row) as u64),
                value0: value0.clone(),
                value1: value1.clone(),
            },
            AEAD_XOF_PAIR,
        );
    }
}
