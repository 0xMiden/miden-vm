use std::vec::Vec;

use miden_core::{Felt, field::PrimeCharacteristicRing};

use super::{
    constraints::{
        enforce_footer_rows as native_footer_rows, enforce_fused_rows as native_fused_rows,
    },
    layout::{BLOCK_PERIOD, FUSED_G_ROWS, G_COMPRESSION_CYCLE_ID_COL, NUM_COLS},
    testing::generate_felt_trace_block_with_cycle_id,
    trace::EidosCompressionFeltRow,
};
use crate::{
    shared::eidos::{EidosCompressionSelectors, test_utils::EidosRowEvaluator},
    vm::eidos_compression::testing as mvm,
};

fn enforce_fused_rows(
    builder: &mut EidosRowEvaluator<'_>,
    local: &[Felt],
    next: &[Felt],
    selectors: &EidosCompressionSelectors<Felt>,
) {
    builder.eval_with(|frame, _, sink| native_fused_rows(frame, sink, local, next, selectors));
}
fn enforce_footer_rows(
    builder: &mut EidosRowEvaluator<'_>,
    local: &[Felt],
    next: &[Felt],
    selectors: &EidosCompressionSelectors<Felt>,
) {
    builder.eval_with(|frame, _, sink| native_footer_rows(frame, sink, local, next, selectors));
}

fn mixed_felt(sample: usize, row: usize, window: usize, column: usize) -> Felt {
    // Scramble the unique coordinate tuple with SplitMix64's finalizer so column and window
    // differences are not affine across samples.
    let mut value = (((sample as u64 * BLOCK_PERIOD as u64 + row as u64) * 2 + window as u64)
        * NUM_COLS as u64
        + column as u64)
        .wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    Felt::from_u64(value ^ (value >> 31))
}

fn eval_main_row(trace: &[EidosCompressionFeltRow], row_idx: usize) -> Vec<Felt> {
    let next_idx = (row_idx + 1).min(trace.len() - 1);
    let local = &trace[row_idx];
    let next = &trace[next_idx];
    let mut builder = EidosRowEvaluator::new(local, next, row_idx, trace.len(), 1);
    let selectors = EidosCompressionSelectors::<Felt>::new(builder.periodic_values(), 0);
    enforce_fused_rows(&mut builder, local, next, &selectors);
    enforce_footer_rows(&mut builder, local, next, &selectors);
    builder.into_base_evaluations()
}

#[test]
fn pvm_wrapper_matches_mvm_mode_zero_constraints() {
    for sample in 0..8 {
        for row_idx in 0..BLOCK_PERIOD {
            let mut local = core::array::from_fn(|col| mixed_felt(sample, row_idx, 0, col));
            let mut next = core::array::from_fn(|col| mixed_felt(sample, row_idx, 1, col));

            // The PVM digest cells and MVM mode-zero output cells occupy the same four columns.
            local[mvm::MVM_MODE_COL] = Felt::ZERO;
            next[mvm::MVM_MODE_COL] = Felt::ZERO;

            let mut pvm_builder = EidosRowEvaluator::new(&local, &next, row_idx, BLOCK_PERIOD, 1);
            let pvm_selectors =
                EidosCompressionSelectors::<Felt>::new(pvm_builder.periodic_values(), 0);
            enforce_fused_rows(&mut pvm_builder, &local, &next, &pvm_selectors);
            enforce_footer_rows(&mut pvm_builder, &local, &next, &pvm_selectors);

            let mut shared_builder =
                EidosRowEvaluator::new(&local, &next, row_idx, BLOCK_PERIOD, 1);
            let shared_selectors =
                EidosCompressionSelectors::<Felt>::new(shared_builder.periodic_values(), 0);
            shared_builder.eval_with(|frame, _, sink| {
                mvm::enforce_fused_rows(frame, sink, &local, &next, &shared_selectors)
            });
            shared_builder.eval_with(|frame, _, sink| {
                mvm::enforce_common_footer_rows(frame, sink, &local, &next, &shared_selectors)
            });

            assert!(!pvm_builder.evaluations.is_empty(), "PVM wrapper emitted no constraints");
            assert_eq!(
                shared_builder.into_base_evaluations(),
                pvm_builder.into_base_evaluations(),
                "constraint mismatch in sample {sample}, row {row_idx}",
            );
        }
    }
}

#[test]
fn cross_row_cycle_id_constancy_rejects_internal_changes() {
    let block = core::array::from_fn(|i| 10 + i as u32);
    let cv = core::array::from_fn(|i| 1_000 + i as u32);
    let first = generate_felt_trace_block_with_cycle_id(block, cv, 0);
    let second = generate_felt_trace_block_with_cycle_id(block, cv, 1);
    let mut trace: Vec<_> = first.rows.into_iter().chain(second.rows).collect();

    // Rows 1..26 borrow cycle 1's ID. Only the cross-row constancy constraint can see the two
    // discontinuities at transitions 0->1 and 26->27.
    for row in trace.iter_mut().take(FUSED_G_ROWS - 1).skip(1) {
        row[G_COMPRESSION_CYCLE_ID_COL] = Felt::ONE;
    }

    for row_idx in 0..trace.len() {
        let rejected = eval_main_row(&trace, row_idx).iter().any(|&value| value != Felt::ZERO);
        assert_eq!(
            rejected,
            matches!(row_idx, 0 | 26),
            "unexpected constraint result on forged row {row_idx}",
        );
    }
}
