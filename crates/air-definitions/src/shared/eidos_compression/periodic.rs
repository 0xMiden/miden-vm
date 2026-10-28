//! Periodic selector values for the 32-row Eidos compression layout.

use alloc::{vec, vec::Vec};

use miden_core::Felt;

use super::{layout::*, schedule::fused_step_at};

pub const P_IS_AB: usize = 0;
pub const P_IS_CD: usize = 1;
pub const P_IS_DIAG: usize = 2;
pub const P_IS_FIRST_FUSED: usize = 3;
pub const P_IS_LAST_FUSED: usize = 4;
pub const P_IS_FOOTER: usize = 5;
pub const P_IS_F0: usize = 6;
pub const P_IS_F1: usize = 7;
pub const P_IS_F2: usize = 8;
pub const P_IS_F3: usize = 9;
pub const P_SIGMA_MSG_0: usize = 10;
pub const P_SIGMA_MSG_1: usize = 11;
pub const P_SIGMA_MSG_2: usize = 12;
pub const P_SIGMA_MSG_3: usize = 13;

pub const NUM_PERIODIC_COLUMNS: usize = P_SIGMA_MSG_3 + 1;

pub fn get_periodic_column_values() -> Vec<Vec<Felt>> {
    let mut columns = Vec::with_capacity(NUM_PERIODIC_COLUMNS);

    // Each round follows AB, CD, diagonal AB, diagonal CD. The diagonal selector switches the
    // active G-lane map for the second pair.
    let mut is_ab = vec![Felt::ZERO; BLOCK_PERIOD];
    let mut is_cd = vec![Felt::ZERO; BLOCK_PERIOD];
    let mut is_diag = vec![Felt::ZERO; BLOCK_PERIOD];
    for row in 0..FUSED_G_ROWS {
        match row_kind(row) {
            RowKind::Ab | RowKind::AbDiag => is_ab[row] = Felt::ONE,
            RowKind::Cd | RowKind::CdDiag => is_cd[row] = Felt::ONE,
            RowKind::Footer(_) => unreachable!("footer rows are outside fused row range"),
        }
        if matches!(row_kind(row), RowKind::AbDiag | RowKind::CdDiag) {
            is_diag[row] = Felt::ONE;
        }
    }
    columns.push(is_ab);
    columns.push(is_cd);
    columns.push(is_diag);

    // These one-hot columns mark the ends of the fused-round region.
    let mut is_first = vec![Felt::ZERO; BLOCK_PERIOD];
    is_first[0] = Felt::ONE;
    columns.push(is_first);

    let mut is_last = vec![Felt::ZERO; BLOCK_PERIOD];
    is_last[FUSED_G_ROWS - 1] = Felt::ONE;
    columns.push(is_last);

    // The last four rows are footers. One selector covers the region and four more select its
    // individual rows.
    let mut is_footer = vec![Felt::ZERO; BLOCK_PERIOD];
    for footer in 0..FOOTER_ROWS {
        is_footer[FOOTER_START + footer] = Felt::ONE;
    }
    columns.push(is_footer);

    for footer in 0..FOOTER_ROWS {
        let mut col = vec![Felt::ZERO; BLOCK_PERIOD];
        col[FOOTER_START + footer] = Felt::ONE;
        columns.push(col);
    }

    // Each sigma column identifies the message word consumed by one G lane on a fused row.
    for g in 0..NUM_G {
        let mut col = vec![Felt::ZERO; BLOCK_PERIOD];
        for (row, value) in col.iter_mut().enumerate().take(FUSED_G_ROWS) {
            let step = fused_step_at(row).expect("row is a fused G row");
            *value = Felt::new_unchecked(step.message_indices[g] as u64);
        }
        columns.push(col);
    }

    assert_eq!(columns.len(), NUM_PERIODIC_COLUMNS);
    columns
}

const _: () = assert!(NUM_PERIODIC_COLUMNS == 14);
