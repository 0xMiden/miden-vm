use alloc::vec::Vec;

use super::air32_layout::{FUSED_G_ROWS, RowKind};
use super::air32_schedule::*;

#[test]
fn fused_rows_follow_column_then_diagonal_schedule() {
    let expected = [RowKind::Ab, RowKind::Cd, RowKind::AbDiag, RowKind::CdDiag];

    for row in 0..FUSED_G_ROWS {
        let step = fused_step_at(row).unwrap();
        assert_eq!(step.row_kind, expected[row % 4]);
        assert_eq!(step.round, row / 4);
        assert_eq!(step.round_row, row % 4);
    }

    assert_eq!(fused_step_at(FUSED_G_ROWS), None);
}

#[test]
fn fused_rows_use_expected_lane_maps() {
    for round_row in [0, 1] {
        assert_eq!(lane_map_for_round_row(round_row), G_IDX_COL);
    }
    for round_row in [2, 3] {
        assert_eq!(lane_map_for_round_row(round_row), G_IDX_DIAG);
    }
}

#[test]
fn fused_rows_use_expected_rotations() {
    assert_eq!((first_rotation_for_round_row(0), second_rotation_for_round_row(0),), (16, 12),);
    assert_eq!((first_rotation_for_round_row(1), second_rotation_for_round_row(1),), (8, 7),);
    assert_eq!((first_rotation_for_round_row(2), second_rotation_for_round_row(2),), (16, 12),);
    assert_eq!((first_rotation_for_round_row(3), second_rotation_for_round_row(3),), (8, 7),);
}

#[test]
fn message_indices_match_sigma_halves() {
    assert_eq!(message_indices_for_round_row(0, 0), [0, 2, 4, 6]);
    assert_eq!(message_indices_for_round_row(0, 1), [1, 3, 5, 7]);
    assert_eq!(message_indices_for_round_row(0, 2), [8, 10, 12, 14]);
    assert_eq!(message_indices_for_round_row(0, 3), [9, 11, 13, 15]);

    assert_eq!(message_indices_for_round_row(1, 0), [2, 3, 7, 4]);
    assert_eq!(message_indices_for_round_row(1, 1), [6, 10, 0, 13]);
    assert_eq!(message_indices_for_round_row(1, 2), [1, 12, 9, 15]);
    assert_eq!(message_indices_for_round_row(1, 3), [11, 5, 14, 8]);

    assert_eq!(message_indices_for_round_row(6, 0), [11, 5, 1, 8]);
    assert_eq!(message_indices_for_round_row(6, 1), [15, 0, 9, 6]);
    assert_eq!(message_indices_for_round_row(6, 2), [14, 2, 3, 7]);
    assert_eq!(message_indices_for_round_row(6, 3), [10, 12, 4, 13]);
}

#[test]
fn each_round_consumes_each_message_index_once() {
    for round in 0..SIGMA.len() {
        let mut indices = Vec::with_capacity(16);
        for round_row in 0..4 {
            indices.extend(message_indices_for_round_row(round, round_row));
        }

        indices.sort_unstable();
        assert_eq!(indices, (0..16).collect::<Vec<_>>());
    }
}

#[test]
fn fused_step_carries_schedule_fields() {
    let step = fused_step_at(27).unwrap();

    assert_eq!(step.row_kind, RowKind::CdDiag);
    assert_eq!(step.round, 6);
    assert_eq!(step.round_row, 3);
    assert_eq!(step.lane_map, G_IDX_DIAG);
    assert_eq!(step.message_indices, [10, 12, 4, 13]);
    assert_eq!((step.first_rotation, step.second_rotation), (8, 7));
}
