//! Concrete trace validator for the 32-row BlakeG layout.
//!
//! These checks mirror the symbolic AIR constraints: row-local add/carry equations,
//! lookup-backed byte XOR/rotation payloads, and row-to-row state continuity.

use super::layout::*;
use super::model::initial_working_state;
use super::periodic::{NUM_PERIODIC_COLUMNS, get_periodic_column_values};
use super::schedule::fused_step_at;
use super::selectors::BlakeGSelectors;
use super::trace::{BlakeGRow, rot_contribution};
use core::array;
use miden_core::{Felt, field::PrimeField64};

const U32_BASE: u64 = 1u64 << 32;
const CANONICALITY_HIGH_WORD_MAX: u64 = u32::MAX as u64;

pub type ConstraintResult = Result<(), ConstraintViolation>;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ConstraintViolation {
    pub row: usize,
    pub check: &'static str,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct FooterWords {
    v_low_even: u32,
    v_low_odd: u32,
    v_high_even: u32,
    v_high_odd: u32,
    h_even: u32,
    h_odd: u32,
    out_even: u32,
    out_odd: u32,
}

pub fn validate_block(rows: &[BlakeGRow; BLOCK_PERIOD], h: [u32; 8]) -> ConstraintResult {
    validate_fused_g_block(rows, h)?;

    let final_state = read_output_state(&rows[FUSED_G_ROWS - 1], FUSED_G_ROWS - 1)?;
    validate_footer_bridge(&rows[FOOTER_START], final_state)?;
    validate_footer_block(rows)
}

pub fn validate_block_with_selectors(
    rows: &[BlakeGRow; BLOCK_PERIOD],
    h: [u32; 8],
) -> ConstraintResult {
    let periodic_columns = get_periodic_column_values();

    for row_idx in 0..BLOCK_PERIOD {
        let periodic_values: [Felt; NUM_PERIODIC_COLUMNS] =
            array::from_fn(|col| periodic_columns[col][row_idx]);
        let selectors = BlakeGSelectors::new(&periodic_values, 0);
        validate_row_selectors(row_idx, &selectors)?;

        match row_kind(row_idx) {
            RowKind::Ab | RowKind::Cd | RowKind::AbDiag | RowKind::CdDiag => {
                validate_fused_g_row(&rows[row_idx], row_idx)?;
                if row_idx == 0 {
                    validate_initial_state(&rows[row_idx], h)?;
                }
                if row_idx + 1 < FUSED_G_ROWS {
                    validate_fused_g_transition(&rows[row_idx], &rows[row_idx + 1], row_idx)?;
                } else {
                    let final_state = read_output_state(&rows[row_idx], row_idx)?;
                    validate_footer_bridge(&rows[FOOTER_START], final_state)?;
                }
            },
            RowKind::Footer(footer) => {
                validate_footer_row(&rows[row_idx], footer)?;
                if footer + 1 < FOOTER_ROWS {
                    validate_footer_transition(&rows[row_idx], &rows[row_idx + 1], footer)?;
                }
            },
        }
    }

    Ok(())
}

pub fn validate_row_selectors(
    row_idx: usize,
    selectors: &BlakeGSelectors<Felt>,
) -> ConstraintResult {
    let (is_ab, is_cd, is_diag, is_footer) = match row_kind(row_idx) {
        RowKind::Ab => (1, 0, 0, 0),
        RowKind::Cd => (0, 1, 0, 0),
        RowKind::AbDiag => (1, 0, 1, 0),
        RowKind::CdDiag => (0, 1, 1, 0),
        RowKind::Footer(_) => (0, 0, 0, 1),
    };

    ensure_selector(row_idx, "selector is_ab", selectors.is_ab(), is_ab)?;
    ensure_selector(row_idx, "selector is_cd", selectors.is_cd(), is_cd)?;
    ensure_selector(row_idx, "selector is_diag", selectors.is_diag(), is_diag)?;
    ensure_selector(row_idx, "selector is_footer", selectors.is_footer(), is_footer)?;
    ensure_selector(
        row_idx,
        "selector is_first_fused",
        selectors.is_first_fused(),
        usize::from(row_idx == 0) as u64,
    )?;
    ensure_selector(
        row_idx,
        "selector is_last_fused",
        selectors.is_last_fused(),
        usize::from(row_idx == FUSED_G_ROWS - 1) as u64,
    )?;

    for footer in 0..FOOTER_ROWS {
        ensure_selector(
            row_idx,
            "selector footer row",
            selectors.is_footer_row(footer),
            usize::from(row_idx == FOOTER_START + footer) as u64,
        )?;
    }

    Ok(())
}

pub fn validate_fused_g_block(rows: &[BlakeGRow; BLOCK_PERIOD], h: [u32; 8]) -> ConstraintResult {
    validate_initial_state(&rows[0], h)?;

    for row in 0..FUSED_G_ROWS {
        validate_fused_g_row(&rows[row], row)?;
        if row + 1 < FUSED_G_ROWS {
            validate_fused_g_transition(&rows[row], &rows[row + 1], row)?;
        }
    }

    Ok(())
}

pub fn validate_footer_block(rows: &[BlakeGRow; BLOCK_PERIOD]) -> ConstraintResult {
    for footer in 0..FOOTER_ROWS {
        validate_footer_row(&rows[FOOTER_START + footer], footer)?;

        if footer + 1 < FOOTER_ROWS {
            validate_footer_transition(
                &rows[FOOTER_START + footer],
                &rows[FOOTER_START + footer + 1],
                footer,
            )?;
        }
    }

    Ok(())
}

pub fn validate_initial_state(row: &BlakeGRow, h: [u32; 8]) -> ConstraintResult {
    let input = read_input_state(row, 0)?;
    ensure(0, "initial working state", input == initial_working_state(h))
}

pub fn validate_fused_g_row(row: &BlakeGRow, row_idx: usize) -> ConstraintResult {
    let step = fused_step_at(row_idx).expect("row is a fused G row");

    for g in 0..NUM_G {
        let msg_slot = g_msg_slot_col(g, 0);
        ensure(
            row_idx,
            "message schedule index",
            row[msg_slot] == step.message_indices[g] as u64,
        )?;
        ensure(row_idx, "message slot padding", row[msg_slot + 2] == 0)?;

        let a = read_u32(row, G_A_BASE_COL + g, row_idx, "a word")?;
        let b = read_bd_word(row, g, 0, row_idx, "b word")?;
        let c = read_u32(row, G_C_BASE_COL + g, row_idx, "c word")?;
        let msg = read_u32(row, msg_slot + 1, row_idx, "message word")?;
        let a_new = read_ac_word(row, g, 1, row_idx, "a_new word")?;
        let c_new = read_bd_word(row, g, 1, row_idx, "c_new word")?;

        validate_ac_and_slots(row, g, row_idx)?;
        validate_bd_rotation_slots(row, g, step.second_rotation, row_idx)?;

        let d_new = rotated_ac_xor_word(row, g, step.first_rotation, row_idx)?;
        let b_new = rotated_bd_xor_word(row, g, step.second_rotation, row_idx)?;

        let k3_bit0 = read_bit(row, G_K3_BIT0_BASE_COL + g, row_idx, "k3 bit 0")?;
        let k3_bit1 = read_bit(row, G_K3_BIT1_BASE_COL + g, row_idx, "k3 bit 1")?;
        let k3 = k3_bit0 + 2 * k3_bit1;
        ensure(row_idx, "k3 carry range", k3 <= 2)?;
        ensure(
            row_idx,
            "add3 carry equation",
            a as u64 + b as u64 + msg as u64 == a_new as u64 + k3 * U32_BASE,
        )?;

        let k2 = read_bit(row, G_K2_BASE_COL + g, row_idx, "k2 carry")?;
        ensure(
            row_idx,
            "add2 carry equation",
            c as u64 + d_new as u64 == c_new as u64 + k2 * U32_BASE,
        )?;

        let expected_b_new = (b ^ c_new).rotate_right(step.second_rotation);
        ensure(row_idx, "second rotation sum", b_new == expected_b_new)?;
    }

    Ok(())
}

pub fn validate_footer_row(row: &BlakeGRow, footer: usize) -> ConstraintResult {
    let row_idx = FOOTER_START + footer;
    let words = validate_footer_xor_surface(row, footer)?;

    ensure(
        row_idx,
        "footer HIN index",
        row[F_HIN_SLOT_BASE_COL] == footer_pair_index(footer) as u64,
    )?;
    ensure(
        row_idx,
        "footer HIN h_even",
        row[F_HIN_SLOT_BASE_COL + 1] == words.h_even as u64,
    )?;
    ensure(row_idx, "footer HIN h_odd", row[F_HIN_SLOT_BASE_COL + 2] == words.h_odd as u64)?;

    validate_footer_message_group(row, footer)?;
    validate_footer_prefixes(row, footer, words)?;
    validate_footer_canonicality(row, footer, words)?;
    validate_footer_future_w_tail(row, footer)?;
    ensure(row_idx, "footer mode bit", row[F_MODE_COL] <= 1)?;
    ensure(
        row_idx,
        "footer AEAD multiplicity",
        row[F_MODE_COL] == 0 || row[F_COMPRESSION_MULTIPLICITY_COL] == 0,
    )?;
    ensure(row_idx, "footer compression clk", row[F_MODE_COL] != 0 || row[F_CLK_COL] == 0)
}

pub fn validate_footer_transition(
    local: &BlakeGRow,
    next: &BlakeGRow,
    footer: usize,
) -> ConstraintResult {
    let row_idx = FOOTER_START + footer;
    let next_words = read_footer_words(next, footer + 1)?;

    for idx in 0..=2 * footer + 1 {
        ensure(
            row_idx,
            "footer R prefix transition",
            local[F_R_BASE_COL + idx] == next[F_R_BASE_COL + idx],
        )?;
    }
    for idx in 0..=footer {
        ensure(
            row_idx,
            "footer C prefix transition",
            local[F_C_BASE_COL + idx] == next[F_C_BASE_COL + idx],
        )?;
        ensure(
            row_idx,
            "footer D prefix transition",
            local[F_D_BASE_COL + idx] == next[F_D_BASE_COL + idx],
        )?;
    }

    let consumed = [
        next_words.v_low_even as u64,
        next_words.v_low_odd as u64,
        next_words.v_high_even as u64,
        next_words.v_high_odd as u64,
    ];
    for (idx, expected) in consumed.into_iter().enumerate() {
        ensure(row_idx, "footer future-W head", local[F_FUTURE_W_BASE_COL + idx] == expected)?;
    }

    let next_len = future_w_len(footer + 1);
    for idx in 0..next_len {
        ensure(
            row_idx,
            "footer future-W shift",
            local[F_FUTURE_W_BASE_COL + 4 + idx] == next[F_FUTURE_W_BASE_COL + idx],
        )?;
    }

    ensure(row_idx, "footer mode transition", local[F_MODE_COL] == next[F_MODE_COL])?;
    ensure(row_idx, "footer clk transition", local[F_CLK_COL] == next[F_CLK_COL])?;
    ensure(
        row_idx,
        "footer multiplicity transition",
        local[F_COMPRESSION_MULTIPLICITY_COL] == next[F_COMPRESSION_MULTIPLICITY_COL],
    )
}

pub fn validate_fused_g_transition(
    local: &BlakeGRow,
    next: &BlakeGRow,
    row_idx: usize,
) -> ConstraintResult {
    let local_output = read_output_state(local, row_idx)?;
    let next_input = read_input_state(next, row_idx + 1)?;

    for word_idx in 0..16 {
        ensure(row_idx, "fused row transition", local_output[word_idx] == next_input[word_idx])?;
    }

    Ok(())
}

pub fn read_input_state(row: &BlakeGRow, row_idx: usize) -> Result<[u32; 16], ConstraintViolation> {
    let step = fused_step_at(row_idx).expect("row is a fused G row");
    let mut state = [0; 16];

    for g in 0..NUM_G {
        let [ai, bi, ci, di] = step.lane_map[g];
        state[ai] = read_u32(row, G_A_BASE_COL + g, row_idx, "input a")?;
        state[bi] = read_bd_word(row, g, 0, row_idx, "input b")?;
        state[ci] = read_u32(row, G_C_BASE_COL + g, row_idx, "input c")?;
        state[di] = read_ac_word(row, g, 0, row_idx, "input d")?;
    }

    Ok(state)
}

pub fn read_output_state(
    row: &BlakeGRow,
    row_idx: usize,
) -> Result<[u32; 16], ConstraintViolation> {
    let step = fused_step_at(row_idx).expect("row is a fused G row");
    let mut state = read_input_state(row, row_idx)?;

    for g in 0..NUM_G {
        let [ai, bi, ci, di] = step.lane_map[g];
        let b = read_bd_word(row, g, 0, row_idx, "output b input")?;
        let c_new = read_bd_word(row, g, 1, row_idx, "output c_new")?;

        state[ai] = read_ac_word(row, g, 1, row_idx, "output a_new")?;
        state[di] = rotated_ac_xor_word(row, g, step.first_rotation, row_idx)?;
        state[ci] = c_new;
        state[bi] = (b ^ c_new).rotate_right(step.second_rotation);
    }

    Ok(state)
}

fn validate_footer_bridge(row: &BlakeGRow, final_state: [u32; 16]) -> ConstraintResult {
    let row_idx = FOOTER_START;
    let words = read_footer_words(row, 0)?;

    ensure(row_idx, "footer bridge low even", words.v_low_even == final_state[0])?;
    ensure(row_idx, "footer bridge low odd", words.v_low_odd == final_state[1])?;
    ensure(row_idx, "footer bridge high even", words.v_high_even == final_state[8])?;
    ensure(row_idx, "footer bridge high odd", words.v_high_odd == final_state[9])?;

    for (idx, &word_idx) in future_w_indices(0).iter().enumerate() {
        ensure(
            row_idx,
            "footer bridge future-W",
            row[F_FUTURE_W_BASE_COL + idx] == final_state[word_idx] as u64,
        )?;
    }

    Ok(())
}

fn validate_footer_xor_surface(
    row: &BlakeGRow,
    footer: usize,
) -> Result<FooterWords, ConstraintViolation> {
    let row_idx = FOOTER_START + footer;
    let (v_high_even, h_even, high_even) =
        read_footer_xor_word(row, F_HIGH_EVEN_SLOT_BASE, row_idx)?;
    let (v_high_odd, h_odd, high_odd) = read_footer_xor_word(row, F_HIGH_ODD_SLOT_BASE, row_idx)?;
    let (v_low_even, high_even_again, out_even) =
        read_footer_xor_word(row, F_OUTPUT_EVEN_SLOT_BASE, row_idx)?;
    let (v_low_odd, high_odd_again, out_odd) =
        read_footer_xor_word(row, F_OUTPUT_ODD_SLOT_BASE, row_idx)?;

    ensure(row_idx, "footer high even reuse", high_even_again == v_high_even)?;
    ensure(row_idx, "footer high odd reuse", high_odd_again == v_high_odd)?;
    ensure(row_idx, "footer xof even", high_even == (v_high_even ^ h_even))?;
    ensure(row_idx, "footer xof odd", high_odd == (v_high_odd ^ h_odd))?;
    ensure(row_idx, "footer output even", out_even == (v_low_even ^ v_high_even))?;
    ensure(row_idx, "footer output odd", out_odd == (v_low_odd ^ v_high_odd))?;

    let top_byte = read_byte(row, F_TOP_BIT_SLOT_BASE_COL, row_idx, "footer top byte")?;
    let mask = read_byte(row, F_TOP_BIT_SLOT_BASE_COL + 1, row_idx, "footer top-bit mask")?;
    let masked = read_byte(row, F_TOP_BIT_SLOT_BASE_COL + 2, row_idx, "footer top-bit and")?;
    ensure(row_idx, "footer top byte", top_byte == out_odd.to_le_bytes()[3])?;
    ensure(row_idx, "footer top-bit mask", mask == F_TOP_BIT_MASK)?;
    ensure(row_idx, "footer top-bit payload", masked == (top_byte & F_TOP_BIT_MASK))?;

    Ok(FooterWords {
        v_low_even,
        v_low_odd,
        v_high_even,
        v_high_odd,
        h_even,
        h_odd,
        out_even,
        out_odd,
    })
}

fn validate_footer_message_group(row: &BlakeGRow, footer: usize) -> ConstraintResult {
    let row_idx = FOOTER_START + footer;
    let mut words = [0u32; F_MSG_WORD_SLOTS];

    for (word_slot, word) in words.iter_mut().enumerate() {
        let col = footer_msg_word_slot_col(word_slot, 0);
        ensure(
            row_idx,
            "footer message index",
            row[col] == footer_message_word_index(footer, word_slot) as u64,
        )?;
        *word = read_u32(row, col + 1, row_idx, "footer message word")?;
        ensure(row_idx, "footer message padding", row[col + 2] == 0)?;
    }

    for limb in 0..F_RANGE_SLOTS {
        let col = footer_range_slot_col(limb, 0);
        let value = read_u16(row, col, row_idx, "footer range limb")?;
        ensure(row_idx, "footer range padding", row[col + 1] == 0 && row[col + 2] == 0)?;

        let word_slot = limb / 2;
        let expected = if footer_range_limb_is_high(limb) {
            words[word_slot] >> 16
        } else {
            words[word_slot] & 0xffff
        };
        ensure(row_idx, "footer range limb value", value as u32 == expected)?;
    }

    Ok(())
}

fn validate_footer_prefixes(
    row: &BlakeGRow,
    footer: usize,
    words: FooterWords,
) -> ConstraintResult {
    let row_idx = FOOTER_START + footer;
    let mut message_words = [0u32; F_MSG_WORD_SLOTS];

    for (word_slot, word) in message_words.iter_mut().enumerate() {
        *word =
            read_u32(row, footer_msg_word_slot_col(word_slot, 1), row_idx, "footer message word")?;
    }

    for pair in 0..2 {
        let r_idx = 2 * footer + pair;
        let lo = message_words[2 * pair];
        let hi = message_words[2 * pair + 1];
        ensure(row_idx, "footer R value", row[F_R_BASE_COL + r_idx] == pack_pair(lo, hi))?;
    }

    for idx in 2 * footer + 2..8 {
        ensure(row_idx, "footer R future zero", row[F_R_BASE_COL + idx] == 0)?;
    }

    ensure(
        row_idx,
        "footer C value",
        row[F_C_BASE_COL + footer] == pack_pair(words.h_even, words.h_odd),
    )?;

    let top_bit = read_byte(row, F_TOP_BIT_SLOT_BASE_COL + 2, row_idx, "footer top-bit and")?;
    let out_odd = words.out_odd - ((top_bit as u32) << 24);
    ensure(
        row_idx,
        "footer D value",
        row[F_D_BASE_COL + footer] == pack_pair(words.out_even, out_odd),
    )?;

    for idx in footer + 1..4 {
        ensure(row_idx, "footer C future zero", row[F_C_BASE_COL + idx] == 0)?;
        ensure(row_idx, "footer D future zero", row[F_D_BASE_COL + idx] == 0)?;
    }

    Ok(())
}

fn validate_footer_canonicality(
    row: &BlakeGRow,
    footer: usize,
    words: FooterWords,
) -> ConstraintResult {
    let row_idx = FOOTER_START + footer;

    for pair in 0..2 {
        let lo =
            read_u32(row, footer_msg_word_slot_col(2 * pair, 1), row_idx, "footer canonical R lo")?;
        let hi = read_u32(
            row,
            footer_msg_word_slot_col(2 * pair + 1, 1),
            row_idx,
            "footer canonical R hi",
        )?;
        validate_canonical_pair(
            row,
            row_idx,
            lo,
            hi,
            F_R_CANON_INV_BASE_COL + pair,
            F_R_CANON_Z_BASE_COL + pair,
            "footer R canonicality",
        )?;
    }

    validate_canonical_pair(
        row,
        row_idx,
        words.h_even,
        words.h_odd,
        F_C_CANON_INV_COL,
        F_C_CANON_Z_COL,
        "footer C canonicality",
    )
}

fn validate_footer_future_w_tail(row: &BlakeGRow, footer: usize) -> ConstraintResult {
    let row_idx = FOOTER_START + footer;

    for idx in future_w_len(footer)..F_FUTURE_W_COLS {
        ensure(row_idx, "footer future-W tail zero", row[F_FUTURE_W_BASE_COL + idx] == 0)?;
    }

    Ok(())
}

fn validate_ac_and_slots(row: &BlakeGRow, g: usize, row_idx: usize) -> ConstraintResult {
    for byte in 0..BYTES_PER_WORD {
        let lhs = read_byte(row, g_ac_byte_slot_col(g, byte, 0), row_idx, "AC lhs byte")?;
        let rhs = read_byte(row, g_ac_byte_slot_col(g, byte, 1), row_idx, "AC rhs byte")?;
        let and = read_byte(row, g_ac_byte_slot_col(g, byte, 2), row_idx, "AC and byte")?;
        ensure(row_idx, "AC AND payload", and == (lhs & rhs))?;
    }

    Ok(())
}

fn validate_bd_rotation_slots(
    row: &BlakeGRow,
    g: usize,
    rotation: u32,
    row_idx: usize,
) -> ConstraintResult {
    for byte in 0..BYTES_PER_WORD {
        let lhs = read_byte(row, g_bd_rot_slot_col(g, byte, 0), row_idx, "BD lhs byte")?;
        let rhs = read_byte(row, g_bd_rot_slot_col(g, byte, 1), row_idx, "BD rhs byte")?;
        let actual = read_u32(row, g_bd_rot_slot_col(g, byte, 2), row_idx, "BD rotation part")?;
        let expected = rot_contribution(byte, lhs, rhs, rotation);
        ensure(row_idx, "BD rotation payload", actual == expected)?;
    }

    Ok(())
}

fn read_footer_words(row: &BlakeGRow, footer: usize) -> Result<FooterWords, ConstraintViolation> {
    validate_footer_xor_surface(row, footer)
}

fn read_footer_xor_word(
    row: &BlakeGRow,
    slot_base: usize,
    row_idx: usize,
) -> Result<(u32, u32, u32), ConstraintViolation> {
    let mut lhs = [0u8; BYTES_PER_WORD];
    let mut rhs = [0u8; BYTES_PER_WORD];
    let mut xor = [0u8; BYTES_PER_WORD];

    for byte in 0..BYTES_PER_WORD {
        let col = footer_xor_slot_col(slot_base + byte, 0);
        lhs[byte] = read_byte(row, col, row_idx, "footer XOR lhs")?;
        rhs[byte] = read_byte(row, col + 1, row_idx, "footer XOR rhs")?;
        let and = read_byte(row, col + 2, row_idx, "footer XOR and")?;
        ensure(row_idx, "footer XOR payload", and == (lhs[byte] & rhs[byte]))?;
        xor[byte] = (lhs[byte] as u16 + rhs[byte] as u16 - 2 * and as u16) as u8;
    }

    Ok((u32::from_le_bytes(lhs), u32::from_le_bytes(rhs), u32::from_le_bytes(xor)))
}

fn validate_canonical_pair(
    row: &BlakeGRow,
    row_idx: usize,
    lo: u32,
    hi: u32,
    inv_col: usize,
    z_col: usize,
    check: &'static str,
) -> ConstraintResult {
    ensure(row_idx, check, row[inv_col] < Felt::ORDER_U64)?;
    ensure(row_idx, check, row[z_col] <= 1)?;

    let h = canonicality_high_word_offset(hi);
    let inv = Felt::new_unchecked(row[inv_col]);
    let z = Felt::new_unchecked(row[z_col]);

    ensure(row_idx, check, h * inv + z == Felt::ONE)?;
    ensure(row_idx, check, z * h == Felt::ZERO)?;
    ensure(row_idx, check, z * Felt::from_u32(lo) == Felt::ZERO)
}

fn canonicality_high_word_offset(hi: u32) -> Felt {
    match CANONICALITY_HIGH_WORD_MAX - hi as u64 {
        0 => Felt::ZERO,
        delta => Felt::new_unchecked(Felt::ORDER - delta),
    }
}

fn rotated_ac_xor_word(
    row: &BlakeGRow,
    g: usize,
    rotation: u32,
    row_idx: usize,
) -> Result<u32, ConstraintViolation> {
    let mut bytes = [0u8; BYTES_PER_WORD];
    for (byte, out) in bytes.iter_mut().enumerate() {
        let lhs = read_byte(row, g_ac_byte_slot_col(g, byte, 0), row_idx, "AC xor lhs")?;
        let rhs = read_byte(row, g_ac_byte_slot_col(g, byte, 1), row_idx, "AC xor rhs")?;
        let and = read_byte(row, g_ac_byte_slot_col(g, byte, 2), row_idx, "AC xor and")?;
        *out = (lhs as u16 + rhs as u16 - 2 * and as u16) as u8;
    }

    Ok(u32::from_le_bytes(bytes).rotate_right(rotation))
}

fn rotated_bd_xor_word(
    row: &BlakeGRow,
    g: usize,
    rotation: u32,
    row_idx: usize,
) -> Result<u32, ConstraintViolation> {
    let mut sum = 0u32;
    for byte in 0..BYTES_PER_WORD {
        let lhs = read_byte(row, g_bd_rot_slot_col(g, byte, 0), row_idx, "BD xor lhs")?;
        let rhs = read_byte(row, g_bd_rot_slot_col(g, byte, 1), row_idx, "BD xor rhs")?;
        let contribution = read_u32(row, g_bd_rot_slot_col(g, byte, 2), row_idx, "BD xor part")?;
        ensure(
            row_idx,
            "BD rotation part",
            contribution == rot_contribution(byte, lhs, rhs, rotation),
        )?;
        sum = sum.wrapping_add(contribution);
    }

    Ok(sum)
}

fn read_ac_word(
    row: &BlakeGRow,
    g: usize,
    field: usize,
    row_idx: usize,
    check: &'static str,
) -> Result<u32, ConstraintViolation> {
    read_slot_word(row, |byte| g_ac_byte_slot_col(g, byte, field), row_idx, check)
}

fn read_bd_word(
    row: &BlakeGRow,
    g: usize,
    field: usize,
    row_idx: usize,
    check: &'static str,
) -> Result<u32, ConstraintViolation> {
    read_slot_word(row, |byte| g_bd_rot_slot_col(g, byte, field), row_idx, check)
}

fn read_slot_word(
    row: &BlakeGRow,
    col: impl Fn(usize) -> usize,
    row_idx: usize,
    check: &'static str,
) -> Result<u32, ConstraintViolation> {
    let mut bytes = [0u8; BYTES_PER_WORD];
    for (byte, out) in bytes.iter_mut().enumerate() {
        *out = read_byte(row, col(byte), row_idx, check)?;
    }

    Ok(u32::from_le_bytes(bytes))
}

fn future_w_indices(footer: usize) -> &'static [usize] {
    match footer {
        0 => &[2, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15],
        1 => &[4, 5, 12, 13, 6, 7, 14, 15],
        2 => &[6, 7, 14, 15],
        3 => &[],
        _ => panic!("footer row must be in 0..4"),
    }
}

fn future_w_len(footer: usize) -> usize {
    future_w_indices(footer).len()
}

fn pack_pair(lo: u32, hi: u32) -> u64 {
    lo as u64 + ((hi as u64) << 32)
}

fn read_byte(
    row: &BlakeGRow,
    col: usize,
    row_idx: usize,
    check: &'static str,
) -> Result<u8, ConstraintViolation> {
    ensure(row_idx, check, row[col] <= u8::MAX as u64)?;
    Ok(row[col] as u8)
}

fn read_u32(
    row: &BlakeGRow,
    col: usize,
    row_idx: usize,
    check: &'static str,
) -> Result<u32, ConstraintViolation> {
    ensure(row_idx, check, row[col] <= u32::MAX as u64)?;
    Ok(row[col] as u32)
}

fn read_u16(
    row: &BlakeGRow,
    col: usize,
    row_idx: usize,
    check: &'static str,
) -> Result<u16, ConstraintViolation> {
    ensure(row_idx, check, row[col] <= u16::MAX as u64)?;
    Ok(row[col] as u16)
}

fn read_bit(
    row: &BlakeGRow,
    col: usize,
    row_idx: usize,
    check: &'static str,
) -> Result<u64, ConstraintViolation> {
    ensure(row_idx, check, row[col] <= 1)?;
    Ok(row[col])
}

fn ensure(row: usize, check: &'static str, condition: bool) -> ConstraintResult {
    if condition {
        Ok(())
    } else {
        Err(ConstraintViolation { row, check })
    }
}

fn ensure_selector(
    row: usize,
    check: &'static str,
    selector: Felt,
    expected: u64,
) -> ConstraintResult {
    ensure(row, check, selector.as_canonical_u64() == expected)
}
