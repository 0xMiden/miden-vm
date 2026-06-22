//! Periodic column values for the 64x80 BlakeG compression constraints.
//!
//! Block structure (64 rows per compression):
//!   Rows 0-55:  computation (7 rounds x 8 rows/round)
//!   Rows 56-59: footer (F0, F1, F2, F3)
//!   Row 60:     message row M0 (m[0..7])
//!   Row 61:     message row M1 (m[8..15])
//!   Row 62:     interface (I)
//!   Row 63:     idle row
//!
//! Row 63 has no constrained payload in the current layout.
//!
//! Computation row types (merged, 4 per half-round):
//!   A (row%4==0): add3(x) + xor_rot16   (rows 0,4,8,...,52)
//!   B (row%4==1): add2 + rot12           (rows 1,5,9,...,53)
//!   C (row%4==2): add3(y) + xor_rot8     (rows 2,6,10,...,54)
//!   D (row%4==3): add2 + rot7            (rows 3,7,11,...,55)
//!
//! Round schedule: A_col, B_col, C_col, D_col, A_diag, B_diag, C_diag, D_diag

use alloc::{vec, vec::Vec};

use miden_core::Felt;

/// Period of the BlakeG block (64 rows, power of 2).
pub const BLOCK_PERIOD: usize = 64;

/// Number of computation rows per block (7 rounds x 8 rows/round).
pub const COMPUTATION_ROWS: usize = 56;

/// Number of footer rows (F0, F1, F2, F3).
pub const FOOTER_ROWS: usize = 4;

/// Start of footer rows.
pub const FOOTER_START: usize = COMPUTATION_ROWS; // 56

/// Start of message rows (M0 = MSG_START, M1 = MSG_START + 1).
pub const MSG_START: usize = FOOTER_START + FOOTER_ROWS; // 60

/// Start of the interface row. The following row is idle in the current layout.
pub const IFACE_START: usize = MSG_START + 2; // 62

/// Number of BlakeG periodic columns.
pub const NUM_BLAKEG_PERIODIC_COLUMNS: usize = 21;

const SIGMA: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

// ---- Computation selectors (0-5) ----

/// 1 on row A (row%4==0 within computation). Merged: add3(x) + xor_rot.
pub const P_IS_A: usize = 0;
/// 1 on row B (row%4==1). Merged: add2 + rot12.
pub const P_IS_B: usize = 1;
/// 1 on row C (row%4==2). Merged: add3(y) + xor_rot8.
pub const P_IS_C: usize = 2;
/// 1 on row D (row%4==3). Merged: add2 + rot7.
pub const P_IS_D: usize = 3;
/// 1 on diagonal half-round rows (rows 4-7 of each 8-row round).
pub const P_IS_DIAG_HALF: usize = 4;
/// 1 on D rows that forward into the next A row.
pub const P_GATE_D_TO_NEXT_A: usize = 5;

// ---- Footer/message/interface selectors (6-12) ----

/// 1 on F0 (row 56).
pub const P_IS_F0: usize = 6;
/// 1 on F1 (row 57).
pub const P_IS_F1: usize = 7;
/// 1 on F2 (row 58).
pub const P_IS_F2: usize = 8;
/// 1 on F3 (row 59).
pub const P_IS_F3: usize = 9;
/// 1 on the interface row (row 62).
pub const P_IS_IFACE_IN: usize = 10;
/// 1 on M0 (row 60). Carries m[0..7] and binds R[0..3] = pack(m[0..7]).
pub const P_IS_MSG_ROW0: usize = 11;
/// 1 on M1 (row 61). Carries m[8..15] and binds R[4..7] = pack(m[8..15]).
pub const P_IS_MSG_ROW1: usize = 12;

// ---- First-row selector (13) ----

/// 1 only on the very first computation row (row 0) of each block.
pub const P_IS_FIRST_COMP: usize = 13;

// ---- Footer aggregate (14) ----

/// 1 on all footer rows (56-59).
pub const P_IS_FOOTER: usize = 14;

// ---- Boundary gates (15) ----

/// 1 only on the final D row (row 55).
pub const P_GATE_LAST_D: usize = 15;

// ---- A/C message schedule indices (16-19) ----

/// Expected BlakeG SIGMA message index for A/C lane 0.
pub const P_SIGMA_MSG_0: usize = 16;
/// Expected BlakeG SIGMA message index for A/C lane 1.
pub const P_SIGMA_MSG_1: usize = 17;
/// Expected BlakeG SIGMA message index for A/C lane 2.
pub const P_SIGMA_MSG_2: usize = 18;
/// Expected BlakeG SIGMA message index for A/C lane 3.
pub const P_SIGMA_MSG_3: usize = 19;

// ---- First B-row selector (20) ----

/// 1 only on the first B row (row 1) of each block.
pub const P_IS_FIRST_B: usize = 20;

/// Returns the periodic column values for BlakeG 64x80 constraints.
pub fn get_blakeg_periodic_column_values() -> Vec<Vec<Felt>> {
    let mut columns = Vec::with_capacity(NUM_BLAKEG_PERIODIC_COLUMNS);

    // Row-type selectors: A/B/C/D within computation (rows 0-55)
    let mut is_a = vec![Felt::ZERO; BLOCK_PERIOD];
    let mut is_b = vec![Felt::ZERO; BLOCK_PERIOD];
    let mut is_c = vec![Felt::ZERO; BLOCK_PERIOD];
    let mut is_d = vec![Felt::ZERO; BLOCK_PERIOD];
    for i in 0..COMPUTATION_ROWS {
        match i % 4 {
            0 => is_a[i] = Felt::ONE,
            1 => is_b[i] = Felt::ONE,
            2 => is_c[i] = Felt::ONE,
            3 => is_d[i] = Felt::ONE,
            _ => unreachable!(),
        }
    }
    columns.push(is_a);
    columns.push(is_b);
    columns.push(is_c);
    columns.push(is_d);

    // P_IS_DIAG_HALF: 1 on rows 4-7 of each 8-row round.
    let mut is_diag = vec![Felt::ZERO; BLOCK_PERIOD];
    for i in 0..COMPUTATION_ROWS {
        if (i % 8) >= 4 {
            is_diag[i] = Felt::ONE;
        }
    }
    columns.push(is_diag);

    // D rows that forward into the next A row. The final D row forwards into F0 instead.
    let mut gate_d_to_next_a = vec![Felt::ZERO; BLOCK_PERIOD];
    for i in (3..COMPUTATION_ROWS - 1).step_by(4) {
        gate_d_to_next_a[i] = Felt::ONE;
    }
    columns.push(gate_d_to_next_a);

    // Footer selectors F0-F3
    for t in 0..4 {
        let mut col = vec![Felt::ZERO; BLOCK_PERIOD];
        col[FOOTER_START + t] = Felt::ONE;
        columns.push(col);
    }

    // Interface selector: I at row 62. Row O is intentionally idle.
    let mut is_iface_in = vec![Felt::ZERO; BLOCK_PERIOD];
    is_iface_in[IFACE_START] = Felt::ONE;
    columns.push(is_iface_in);

    // Message-row selectors: M0 at row 60, M1 at row 61.
    let mut is_msg_row0 = vec![Felt::ZERO; BLOCK_PERIOD];
    is_msg_row0[MSG_START] = Felt::ONE;
    columns.push(is_msg_row0);

    let mut is_msg_row1 = vec![Felt::ZERO; BLOCK_PERIOD];
    is_msg_row1[MSG_START + 1] = Felt::ONE;
    columns.push(is_msg_row1);

    // P_IS_FIRST_COMP: 1 only on row 0.
    let mut is_first = vec![Felt::ZERO; BLOCK_PERIOD];
    is_first[0] = Felt::ONE;
    columns.push(is_first);

    // P_IS_FOOTER: 1 on rows 56-59.
    let mut is_footer = vec![Felt::ZERO; BLOCK_PERIOD];
    for t in 0..FOOTER_ROWS {
        is_footer[FOOTER_START + t] = Felt::ONE;
    }
    columns.push(is_footer);

    // Final D row: binds the last working state into F0.
    let mut gate_last_d = vec![Felt::ZERO; BLOCK_PERIOD];
    gate_last_d[COMPUTATION_ROWS - 1] = Felt::ONE;
    columns.push(gate_last_d);

    for g in 0..4 {
        let mut sigma_msg = vec![Felt::ZERO; BLOCK_PERIOD];
        for round in 0..7 {
            let base = round * 8;
            let s = &SIGMA[round];
            sigma_msg[base] = Felt::new_unchecked(s[2 * g] as u64);
            sigma_msg[base + 2] = Felt::new_unchecked(s[2 * g + 1] as u64);
            sigma_msg[base + 4] = Felt::new_unchecked(s[8 + 2 * g] as u64);
            sigma_msg[base + 6] = Felt::new_unchecked(s[8 + 2 * g + 1] as u64);
        }
        columns.push(sigma_msg);
    }

    // P_IS_FIRST_B: 1 only on row 1.
    let mut is_first_b = vec![Felt::ZERO; BLOCK_PERIOD];
    is_first_b[1] = Felt::ONE;
    columns.push(is_first_b);

    debug_assert_eq!(columns.len(), NUM_BLAKEG_PERIODIC_COLUMNS);
    columns
}
