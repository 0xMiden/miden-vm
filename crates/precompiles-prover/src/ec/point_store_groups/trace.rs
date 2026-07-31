//! Trace generation for the merged point-store + ec-groups chiplet.

use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::QuadFelt,
    utils::{Matrix, RowMajorMatrix},
};

use crate::{
    ec::{
        NUM_MAIN_COLS as POINTS_NUM_MAIN_COLS,
        groups::NUM_MAIN_COLS as G_NUM_MAIN_COLS,
        point_store_groups::{EcPointStoreGroupsAir, NUM_MAIN_COLS},
        trace::{EcStoreRequires, groups_trace_padded_to, points_trace},
    },
    logup::build_logup_aux_trace,
};

/// Build the merged main trace at the largest component height. Point rows
/// can be zero-extended because they are activity-gated; group rows use
/// [`groups_trace_padded_to`] to preserve the ungated pointer chain.
pub fn generate_trace(requires: EcStoreRequires) -> RowMajorMatrix<Felt> {
    let mut points_main = points_trace(&requires);
    let points_height = points_main.height();
    let groups_main = groups_trace_padded_to(&requires, points_height);
    let height = groups_main.height();
    points_main.values.resize(height * POINTS_NUM_MAIN_COLS, Felt::ZERO);

    let mut vals = Vec::with_capacity(height * NUM_MAIN_COLS);
    for r in 0..height {
        vals.extend_from_slice(
            &points_main.values[r * POINTS_NUM_MAIN_COLS..(r + 1) * POINTS_NUM_MAIN_COLS],
        );
        vals.extend_from_slice(&groups_main.values[r * G_NUM_MAIN_COLS..(r + 1) * G_NUM_MAIN_COLS]);
    }
    debug_assert_eq!(vals.len(), height * NUM_MAIN_COLS);

    RowMajorMatrix::new(vals, NUM_MAIN_COLS)
}

/// Build the merged chiplet's LogUp trace.
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    build_logup_aux_trace(&EcPointStoreGroupsAir, main, challenges)
}
