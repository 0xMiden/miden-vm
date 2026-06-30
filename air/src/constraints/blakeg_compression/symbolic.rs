//! Symbolic constraints for the 32-row BlakeG layout.

use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_crypto::stark::air::{AirBuilder, LiftedAirBuilder};

use super::{
    layout::*,
    schedule::{G_IDX_COL, G_IDX_DIAG, LaneMap},
    selectors::BlakeGSelectors,
};

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub fn enforce_fused_rows<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    selectors: &BlakeGSelectors<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    enforce_fused_row_locals(builder, local, selectors);
    enforce_initial_iv(builder, local, selectors);
    enforce_fused_row_transitions(builder, local, next, selectors);
}

pub fn enforce_footer_rows<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    selectors: &BlakeGSelectors<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    enforce_last_fused_to_f0(builder, local, next, selectors);
    enforce_footer_locals(builder, local, selectors);
    enforce_footer_transitions(builder, local, next, selectors);
}

fn enforce_fused_row_locals<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    selectors: &BlakeGSelectors<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_fused = selectors.is_ab() + selectors.is_cd();

    for g in 0..NUM_G {
        let builder = &mut builder.when(is_fused.clone());
        let k3_bit0 = c::<AB>(local, G_K3_BIT0_BASE_COL + g);
        let k3_bit1 = c::<AB>(local, G_K3_BIT1_BASE_COL + g);
        let k2 = c::<AB>(local, G_K2_BASE_COL + g);
        let k3 = k3_bit0.clone() + expr::<AB>(2) * k3_bit1.clone();

        builder.assert_zero(k3_bit0.clone() * (AB::Expr::ONE - k3_bit0.clone()));
        builder.assert_zero(k3_bit1.clone() * (AB::Expr::ONE - k3_bit1.clone()));
        builder.assert_zero(k3_bit0 * k3_bit1);
        builder.assert_zero(k2.clone() * (AB::Expr::ONE - k2.clone()));

        builder.assert_zero(msg_index::<AB>(local, g) - selectors.sigma_msg_index(g));
        builder.assert_zero(msg_padding::<AB>(local, g));
        builder.assert_zero(
            input_a::<AB>(local, g) + input_b::<AB>(local, g) + msg_word::<AB>(local, g)
                - a_new::<AB>(local, g)
                - expr::<AB>(1u64 << 32) * k3,
        );

        let d_new = d_new::<AB>(local, g, selectors);
        builder.assert_zero(
            input_c::<AB>(local, g) + d_new - c_new::<AB>(local, g) - expr::<AB>(1u64 << 32) * k2,
        );
    }
}

fn enforce_initial_iv<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    selectors: &BlakeGSelectors<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_first = selectors.is_first_fused();

    for g in 0..NUM_G {
        let builder = &mut builder.when(is_first.clone());
        builder.assert_zero(input_c::<AB>(local, g) - expr::<AB>(IV[g] as u64));
        builder.assert_zero(input_d::<AB>(local, g) - expr::<AB>(IV[4 + g] as u64));
    }
}

fn enforce_fused_row_transitions<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    selectors: &BlakeGSelectors<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_col = AB::Expr::ONE - selectors.is_diag();
    let is_diag = selectors.is_diag();

    // The transition relation uses the row family's fixed first rotation. Selecting between
    // rotations inside the payload would raise the gated transition degree above 3.
    enforce_transition_for_maps::<AB>(
        builder,
        selectors.is_ab() * is_col.clone(),
        local,
        next,
        &G_IDX_COL,
        &G_IDX_COL,
        16,
    );
    enforce_transition_for_maps::<AB>(
        builder,
        selectors.is_cd() * is_col,
        local,
        next,
        &G_IDX_COL,
        &G_IDX_DIAG,
        8,
    );
    enforce_transition_for_maps::<AB>(
        builder,
        selectors.is_ab() * is_diag.clone(),
        local,
        next,
        &G_IDX_DIAG,
        &G_IDX_DIAG,
        16,
    );
    enforce_transition_for_maps::<AB>(
        builder,
        selectors.is_cd() * is_diag - selectors.is_last_fused(),
        local,
        next,
        &G_IDX_DIAG,
        &G_IDX_COL,
        8,
    );
}

fn enforce_transition_for_maps<AB>(
    builder: &mut AB,
    gate: AB::Expr,
    local: &[AB::Var],
    next: &[AB::Var],
    local_map: &LaneMap,
    next_map: &LaneMap,
    d_rotation: u32,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    for word_idx in 0..16 {
        let lhs = transition_output_word::<AB>(local, local_map, word_idx, d_rotation);
        let rhs = input_word::<AB>(next, next_map, word_idx);
        builder.when(gate.clone()).assert_zero(lhs - rhs);
    }
}

fn enforce_last_fused_to_f0<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    selectors: &BlakeGSelectors<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let gate = selectors.is_last_fused();
    let final_w = |idx| output_word::<AB>(local, &G_IDX_DIAG, idx, selectors);
    let f0_words = footer_words::<AB>(next);

    builder.when(gate.clone()).assert_zero(f0_words.v_low_even - final_w(0));
    builder.when(gate.clone()).assert_zero(f0_words.v_low_odd - final_w(1));
    builder.when(gate.clone()).assert_zero(f0_words.v_high_even - final_w(8));
    builder.when(gate.clone()).assert_zero(f0_words.v_high_odd - final_w(9));

    for (idx, word_idx) in [2, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15].into_iter().enumerate() {
        builder
            .when(gate.clone())
            .assert_zero(c::<AB>(next, F_FUTURE_W_BASE_COL + idx) - final_w(word_idx));
    }
}

fn enforce_footer_locals<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    selectors: &BlakeGSelectors<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_footer = selectors.is_footer();
    let words = footer_words::<AB>(local);

    builder
        .when(is_footer.clone())
        .assert_zero(words.high_even_duplicate.clone() - words.v_high_even.clone());
    builder
        .when(is_footer.clone())
        .assert_zero(words.high_odd_duplicate.clone() - words.v_high_odd.clone());
    builder
        .when(is_footer.clone())
        .assert_zero(c::<AB>(local, F_TOP_BIT_SLOT_BASE_COL) - words.out_odd_byte3.clone());
    builder.when(is_footer.clone()).assert_zero(
        c::<AB>(local, F_TOP_BIT_SLOT_BASE_COL + 1) - expr::<AB>(F_TOP_BIT_MASK as u64),
    );

    let mode = c::<AB>(local, F_MODE_COL);
    let compression_multiplicity = c::<AB>(local, F_COMPRESSION_MULTIPLICITY_COL);
    let inactive = AB::Expr::ONE - mode.clone();
    let top_bit = c::<AB>(local, F_TOP_BIT_SLOT_BASE_COL + 2);
    builder.when(is_footer.clone()).assert_zero(mode.clone() * inactive.clone());
    builder
        .when(is_footer.clone())
        .assert_zero(mode.clone() * compression_multiplicity);
    builder
        .when(is_footer.clone())
        .assert_zero(inactive * c::<AB>(local, F_CLK_COL));
    builder
        .when(is_footer.clone())
        .assert_zero(top_bit.clone() * (top_bit - expr::<AB>(F_TOP_BIT_MASK as u64)));

    for footer in 0..FOOTER_ROWS {
        enforce_footer_row_locals::<AB>(builder, local, selectors, footer, &words);
    }
}

fn enforce_footer_row_locals<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    selectors: &BlakeGSelectors<AB::Expr>,
    footer: usize,
    words: &FooterWords<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let gate = selectors.is_footer_row(footer);
    let top_bit_masked = c::<AB>(local, F_TOP_BIT_SLOT_BASE_COL + 2);

    builder
        .when(gate.clone())
        .assert_zero(c::<AB>(local, F_HIN_SLOT_BASE_COL) - expr::<AB>(footer as u64));
    builder
        .when(gate.clone())
        .assert_zero(c::<AB>(local, F_HIN_SLOT_BASE_COL + 1) - words.h_even.clone());
    builder
        .when(gate.clone())
        .assert_zero(c::<AB>(local, F_HIN_SLOT_BASE_COL + 2) - words.h_odd.clone());

    for word_slot in 0..F_MSG_WORD_SLOTS {
        let base = footer_msg_word_slot_col(word_slot, 0);
        let word = c::<AB>(local, base + 1);
        let lo = c::<AB>(local, footer_range_slot_col(2 * word_slot, 0));
        let hi = c::<AB>(local, footer_range_slot_col(2 * word_slot + 1, 0));

        builder.when(gate.clone()).assert_zero(
            c::<AB>(local, base) - expr::<AB>(footer_message_word_index(footer, word_slot) as u64),
        );
        builder.when(gate.clone()).assert_zero(c::<AB>(local, base + 2));
        builder.when(gate.clone()).assert_zero(word - lo - expr::<AB>(1 << 16) * hi);
    }

    for limb in 0..F_RANGE_SLOTS {
        let base = footer_range_slot_col(limb, 0);
        builder.when(gate.clone()).assert_zero(c::<AB>(local, base + 1));
        builder.when(gate.clone()).assert_zero(c::<AB>(local, base + 2));
    }

    for pair in 0..2 {
        let r_idx = 2 * footer + pair;
        let lo = c::<AB>(local, footer_msg_word_slot_col(2 * pair, 1));
        let hi = c::<AB>(local, footer_msg_word_slot_col(2 * pair + 1, 1));
        builder.when(gate.clone()).assert_zero(
            c::<AB>(local, F_R_BASE_COL + r_idx) - pack_pair::<AB>(lo.clone(), hi.clone()),
        );
        enforce_canonical_pair::<AB>(
            builder,
            gate.clone(),
            lo,
            hi,
            c::<AB>(local, F_R_CANON_INV_BASE_COL + pair),
            c::<AB>(local, F_R_CANON_Z_BASE_COL + pair),
        );
    }

    for idx in 2 * footer + 2..8 {
        builder.when(gate.clone()).assert_zero(c::<AB>(local, F_R_BASE_COL + idx));
    }

    builder.when(gate.clone()).assert_zero(
        c::<AB>(local, F_C_BASE_COL + footer)
            - pack_pair::<AB>(words.h_even.clone(), words.h_odd.clone()),
    );

    let masked_odd = words.out_odd.clone() - expr::<AB>(1 << 24) * top_bit_masked;
    builder.when(gate.clone()).assert_zero(
        c::<AB>(local, F_D_BASE_COL + footer) - pack_pair::<AB>(words.out_even.clone(), masked_odd),
    );

    for idx in footer + 1..4 {
        builder.when(gate.clone()).assert_zero(c::<AB>(local, F_C_BASE_COL + idx));
        builder.when(gate.clone()).assert_zero(c::<AB>(local, F_D_BASE_COL + idx));
    }

    enforce_canonical_pair::<AB>(
        builder,
        gate.clone(),
        words.h_even.clone(),
        words.h_odd.clone(),
        c::<AB>(local, F_C_CANON_INV_COL),
        c::<AB>(local, F_C_CANON_Z_COL),
    );

    for idx in future_w_len(footer)..F_FUTURE_W_COLS {
        builder
            .when(gate.clone())
            .assert_zero(c::<AB>(local, F_FUTURE_W_BASE_COL + idx));
    }
}

fn enforce_footer_transitions<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    selectors: &BlakeGSelectors<AB::Expr>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    for footer in 0..FOOTER_ROWS - 1 {
        let gate = selectors.is_footer_row(footer);
        let next_words = footer_words::<AB>(next);
        let consumed = [
            next_words.v_low_even,
            next_words.v_low_odd,
            next_words.v_high_even,
            next_words.v_high_odd,
        ];

        for idx in 0..=2 * footer + 1 {
            builder.when(gate.clone()).assert_zero(
                c::<AB>(local, F_R_BASE_COL + idx) - c::<AB>(next, F_R_BASE_COL + idx),
            );
        }
        for idx in 0..=footer {
            builder.when(gate.clone()).assert_zero(
                c::<AB>(local, F_C_BASE_COL + idx) - c::<AB>(next, F_C_BASE_COL + idx),
            );
            builder.when(gate.clone()).assert_zero(
                c::<AB>(local, F_D_BASE_COL + idx) - c::<AB>(next, F_D_BASE_COL + idx),
            );
        }
        for (idx, expected) in consumed.into_iter().enumerate() {
            builder
                .when(gate.clone())
                .assert_zero(c::<AB>(local, F_FUTURE_W_BASE_COL + idx) - expected);
        }
        for idx in 0..future_w_len(footer + 1) {
            builder.when(gate.clone()).assert_zero(
                c::<AB>(local, F_FUTURE_W_BASE_COL + 4 + idx)
                    - c::<AB>(next, F_FUTURE_W_BASE_COL + idx),
            );
        }

        builder
            .when(gate.clone())
            .assert_zero(c::<AB>(local, F_MODE_COL) - c::<AB>(next, F_MODE_COL));
        builder.when(gate.clone()).assert_zero(
            c::<AB>(local, F_COMPRESSION_MULTIPLICITY_COL)
                - c::<AB>(next, F_COMPRESSION_MULTIPLICITY_COL),
        );
        builder
            .when(gate)
            .assert_zero(c::<AB>(local, F_CLK_COL) - c::<AB>(next, F_CLK_COL));
    }
}

fn enforce_canonical_pair<AB>(
    builder: &mut AB,
    gate: AB::Expr,
    lo: AB::Expr,
    hi: AB::Expr,
    inv: AB::Expr,
    z: AB::Expr,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let h = hi - expr::<AB>((1u64 << 32) - 1);
    let builder = &mut builder.when(gate);
    builder.assert_zero(h.clone() * inv + z.clone() - AB::Expr::ONE);
    builder.assert_zero(z.clone() * h);
    builder.assert_zero(z * lo);
}

fn input_word<AB>(row: &[AB::Var], lane_map: &LaneMap, word_idx: usize) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    let (g, position) = lane_position(lane_map, word_idx);
    match position {
        0 => input_a::<AB>(row, g),
        1 => input_b::<AB>(row, g),
        2 => input_c::<AB>(row, g),
        3 => input_d::<AB>(row, g),
        _ => unreachable!("lane position must be in 0..4"),
    }
}

fn output_word<AB>(
    row: &[AB::Var],
    lane_map: &LaneMap,
    word_idx: usize,
    selectors: &BlakeGSelectors<AB::Expr>,
) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    let (g, position) = lane_position(lane_map, word_idx);
    match position {
        0 => a_new::<AB>(row, g),
        1 => b_new::<AB>(row, g),
        2 => c_new::<AB>(row, g),
        3 => d_new::<AB>(row, g, selectors),
        _ => unreachable!("lane position must be in 0..4"),
    }
}

fn transition_output_word<AB>(
    row: &[AB::Var],
    lane_map: &LaneMap,
    word_idx: usize,
    d_rotation: u32,
) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    let (g, position) = lane_position(lane_map, word_idx);
    match position {
        0 => a_new::<AB>(row, g),
        1 => b_new::<AB>(row, g),
        2 => c_new::<AB>(row, g),
        3 => d_new_for_rotation::<AB>(row, g, d_rotation),
        _ => unreachable!("lane position must be in 0..4"),
    }
}

#[derive(Clone)]
struct FooterWords<E> {
    v_low_even: E,
    v_low_odd: E,
    v_high_even: E,
    v_high_odd: E,
    high_even_duplicate: E,
    high_odd_duplicate: E,
    h_even: E,
    h_odd: E,
    out_even: E,
    out_odd: E,
    out_odd_byte3: E,
}

fn footer_words<AB>(row: &[AB::Var]) -> FooterWords<AB::Expr>
where
    AB: LiftedAirBuilder<F = Felt>,
{
    let (v_high_even, h_even, _) = footer_xor_word::<AB>(row, F_HIGH_EVEN_SLOT_BASE);
    let (v_high_odd, h_odd, _) = footer_xor_word::<AB>(row, F_HIGH_ODD_SLOT_BASE);
    let (v_low_even, high_even_duplicate, out_even) =
        footer_xor_word::<AB>(row, F_OUTPUT_EVEN_SLOT_BASE);
    let (v_low_odd, high_odd_duplicate, out_odd) =
        footer_xor_word::<AB>(row, F_OUTPUT_ODD_SLOT_BASE);
    let out_odd_byte3 = footer_xor_byte::<AB>(row, F_OUTPUT_ODD_SLOT_BASE + 3);

    FooterWords {
        v_low_even,
        v_low_odd,
        v_high_even,
        v_high_odd,
        high_even_duplicate,
        high_odd_duplicate,
        h_even,
        h_odd,
        out_even,
        out_odd,
        out_odd_byte3,
    }
}

fn footer_xor_word<AB>(row: &[AB::Var], slot_base: usize) -> (AB::Expr, AB::Expr, AB::Expr)
where
    AB: LiftedAirBuilder<F = Felt>,
{
    let lhs = pack4::<AB>(
        c::<AB>(row, footer_xor_slot_col(slot_base, 0)),
        c::<AB>(row, footer_xor_slot_col(slot_base + 1, 0)),
        c::<AB>(row, footer_xor_slot_col(slot_base + 2, 0)),
        c::<AB>(row, footer_xor_slot_col(slot_base + 3, 0)),
    );
    let rhs = pack4::<AB>(
        c::<AB>(row, footer_xor_slot_col(slot_base, 1)),
        c::<AB>(row, footer_xor_slot_col(slot_base + 1, 1)),
        c::<AB>(row, footer_xor_slot_col(slot_base + 2, 1)),
        c::<AB>(row, footer_xor_slot_col(slot_base + 3, 1)),
    );
    let xor = pack4::<AB>(
        footer_xor_byte::<AB>(row, slot_base),
        footer_xor_byte::<AB>(row, slot_base + 1),
        footer_xor_byte::<AB>(row, slot_base + 2),
        footer_xor_byte::<AB>(row, slot_base + 3),
    );

    (lhs, rhs, xor)
}

fn footer_xor_byte<AB>(row: &[AB::Var], slot: usize) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    let base = footer_xor_slot_col(slot, 0);
    let lhs = c::<AB>(row, base);
    let rhs = c::<AB>(row, base + 1);
    let and = c::<AB>(row, base + 2);
    lhs + rhs - and.clone() - and
}

fn lane_position(lane_map: &LaneMap, word_idx: usize) -> (usize, usize) {
    for (g, lane) in lane_map.iter().enumerate() {
        for (position, &idx) in lane.iter().enumerate() {
            if idx == word_idx {
                return (g, position);
            }
        }
    }
    unreachable!("word index must appear exactly once in the lane map");
}

#[inline]
fn c<AB>(row: &[AB::Var], idx: usize) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    row[idx].clone().into()
}

#[inline]
fn expr<AB>(value: u64) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    AB::Expr::from(Felt::new_unchecked(value))
}

fn pack4<AB>(b0: AB::Expr, b1: AB::Expr, b2: AB::Expr, b3: AB::Expr) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    b0 + expr::<AB>(256) * b1 + expr::<AB>(1 << 16) * b2 + expr::<AB>(1 << 24) * b3
}

fn pack_pair<AB>(lo: AB::Expr, hi: AB::Expr) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    lo + expr::<AB>(1u64 << 32) * hi
}

fn future_w_len(footer: usize) -> usize {
    match footer {
        0 => 12,
        1 => 8,
        2 => 4,
        3 => 0,
        _ => unreachable!("footer index must be in 0..4"),
    }
}

fn input_a<AB>(row: &[AB::Var], g: usize) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    c::<AB>(row, G_A_BASE_COL + g)
}

fn input_b<AB>(row: &[AB::Var], g: usize) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    pack4::<AB>(
        c::<AB>(row, g_bd_rot_slot_col(g, 0, 0)),
        c::<AB>(row, g_bd_rot_slot_col(g, 1, 0)),
        c::<AB>(row, g_bd_rot_slot_col(g, 2, 0)),
        c::<AB>(row, g_bd_rot_slot_col(g, 3, 0)),
    )
}

fn input_c<AB>(row: &[AB::Var], g: usize) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    c::<AB>(row, G_C_BASE_COL + g)
}

fn input_d<AB>(row: &[AB::Var], g: usize) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    pack4::<AB>(
        c::<AB>(row, g_ac_byte_slot_col(g, 0, 0)),
        c::<AB>(row, g_ac_byte_slot_col(g, 1, 0)),
        c::<AB>(row, g_ac_byte_slot_col(g, 2, 0)),
        c::<AB>(row, g_ac_byte_slot_col(g, 3, 0)),
    )
}

fn msg_index<AB>(row: &[AB::Var], g: usize) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    c::<AB>(row, g_msg_slot_col(g, 0))
}

fn msg_word<AB>(row: &[AB::Var], g: usize) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    c::<AB>(row, g_msg_slot_col(g, 1))
}

fn msg_padding<AB>(row: &[AB::Var], g: usize) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    c::<AB>(row, g_msg_slot_col(g, 2))
}

fn a_new<AB>(row: &[AB::Var], g: usize) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    pack4::<AB>(
        c::<AB>(row, g_ac_byte_slot_col(g, 0, 1)),
        c::<AB>(row, g_ac_byte_slot_col(g, 1, 1)),
        c::<AB>(row, g_ac_byte_slot_col(g, 2, 1)),
        c::<AB>(row, g_ac_byte_slot_col(g, 3, 1)),
    )
}

fn c_new<AB>(row: &[AB::Var], g: usize) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    pack4::<AB>(
        c::<AB>(row, g_bd_rot_slot_col(g, 0, 1)),
        c::<AB>(row, g_bd_rot_slot_col(g, 1, 1)),
        c::<AB>(row, g_bd_rot_slot_col(g, 2, 1)),
        c::<AB>(row, g_bd_rot_slot_col(g, 3, 1)),
    )
}

fn b_new<AB>(row: &[AB::Var], g: usize) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    (0..BYTES_PER_WORD)
        .fold(AB::Expr::ZERO, |acc, byte| acc + c::<AB>(row, g_bd_rot_slot_col(g, byte, 2)))
}

fn d_new<AB>(row: &[AB::Var], g: usize, selectors: &BlakeGSelectors<AB::Expr>) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    selectors.is_ab() * d_new_for_rotation::<AB>(row, g, 16)
        + selectors.is_cd() * d_new_for_rotation::<AB>(row, g, 8)
}

fn d_new_for_rotation<AB>(row: &[AB::Var], g: usize, rotation: u32) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    let xor = [
        xor_byte::<AB>(row, g, 0),
        xor_byte::<AB>(row, g, 1),
        xor_byte::<AB>(row, g, 2),
        xor_byte::<AB>(row, g, 3),
    ];

    match rotation {
        16 => pack4::<AB>(xor[2].clone(), xor[3].clone(), xor[0].clone(), xor[1].clone()),
        8 => pack4::<AB>(xor[1].clone(), xor[2].clone(), xor[3].clone(), xor[0].clone()),
        _ => unreachable!("BlakeG first rotation must be 16 or 8 bits"),
    }
}

fn xor_byte<AB>(row: &[AB::Var], g: usize, byte: usize) -> AB::Expr
where
    AB: LiftedAirBuilder<F = Felt>,
{
    let lhs = c::<AB>(row, g_ac_byte_slot_col(g, byte, 0));
    let rhs = c::<AB>(row, g_ac_byte_slot_col(g, byte, 1));
    let and = c::<AB>(row, g_ac_byte_slot_col(g, byte, 2));
    lhs + rhs - and.clone() - and
}
