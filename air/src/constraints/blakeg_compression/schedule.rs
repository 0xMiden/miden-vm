//! Fused BlakeG round schedule for the 32-row AIR.

use super::layout::{FUSED_G_ROWS, FUSED_G_ROWS_PER_ROUND, NUM_G, ROUNDS, RowKind};

pub type LaneMap = [[usize; NUM_G]; NUM_G];

pub const G_IDX_COL: LaneMap = [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]];

pub const G_IDX_DIAG: LaneMap = [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]];

pub const SIGMA: [[usize; 16]; ROUNDS] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FusedStep {
    pub row_kind: RowKind,
    pub round: usize,
    pub round_row: usize,
    pub lane_map: LaneMap,
    pub message_indices: [usize; NUM_G],
    pub first_rotation: u32,
    pub second_rotation: u32,
}

pub const fn fused_step_at(row: usize) -> Option<FusedStep> {
    if row >= FUSED_G_ROWS {
        return None;
    }

    let round = row / FUSED_G_ROWS_PER_ROUND;
    let round_row = row % FUSED_G_ROWS_PER_ROUND;
    Some(FusedStep {
        row_kind: row_kind_for_round_row(round_row),
        round,
        round_row,
        lane_map: lane_map_for_round_row(round_row),
        message_indices: message_indices_for_round_row(round, round_row),
        first_rotation: first_rotation_for_round_row(round_row),
        second_rotation: second_rotation_for_round_row(round_row),
    })
}

pub const fn row_kind_for_round_row(round_row: usize) -> RowKind {
    match round_row {
        0 => RowKind::Ab,
        1 => RowKind::Cd,
        2 => RowKind::AbDiag,
        3 => RowKind::CdDiag,
        _ => panic!("round row must be in 0..4"),
    }
}

pub const fn lane_map_for_round_row(round_row: usize) -> LaneMap {
    match round_row {
        0 | 1 => G_IDX_COL,
        2 | 3 => G_IDX_DIAG,
        _ => panic!("round row must be in 0..4"),
    }
}

pub const fn message_indices_for_round_row(round: usize, round_row: usize) -> [usize; NUM_G] {
    let s = SIGMA[round];
    match round_row {
        0 => [s[0], s[2], s[4], s[6]],
        1 => [s[1], s[3], s[5], s[7]],
        2 => [s[8], s[10], s[12], s[14]],
        3 => [s[9], s[11], s[13], s[15]],
        _ => panic!("round row must be in 0..4"),
    }
}

pub const fn first_rotation_for_round_row(round_row: usize) -> u32 {
    match round_row {
        0 | 2 => 16,
        1 | 3 => 8,
        _ => panic!("round row must be in 0..4"),
    }
}

pub const fn second_rotation_for_round_row(round_row: usize) -> u32 {
    match round_row {
        0 | 2 => 12,
        1 | 3 => 7,
        _ => panic!("round row must be in 0..4"),
    }
}
