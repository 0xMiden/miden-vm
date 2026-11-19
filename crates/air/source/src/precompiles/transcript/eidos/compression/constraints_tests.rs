use std::{vec, vec::Vec};

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_stark::air;

use super::{
    constraints::{
        enforce_footer_rows as native_footer_rows, enforce_fused_rows as native_fused_rows,
    },
    layout::{BLOCK_PERIOD, FUSED_G_ROWS, G_COMPRESSION_CYCLE_ID_COL, NUM_COLS},
    testing::generate_felt_trace_block_with_cycle_id,
    trace::EidosCompressionFeltRow,
};
use crate::{
    shared::eidos::{EidosCompressionSelectors, get_periodic_column_values},
    vm::eidos_compression::testing as mvm,
};

impl ConstraintEvalBuilder {
    fn periodic_values(&self) -> &[Felt] {
        &self.periodic_values
    }

    fn eval_with(
        &mut self,
        evaluate: impl FnOnce(
            &air::AirFrame<'_, Felt, QuadFelt>,
            air::UniformInputs<'_, Felt, QuadFelt>,
            &mut NumericSink<'_>,
        ),
    ) {
        let width = self.main.width;
        let aux_width = self.aux.width;
        let frame = air::AirFrame {
            main: air::Rows {
                current: &self.main.values[..width],
                next: &self.main.values[width..2 * width],
            },
            preprocessed: air::Rows { current: &[], next: &[] },
            aux: air::Rows {
                current: &self.aux.values[..aux_width],
                next: &self.aux.values[aux_width..2 * aux_width],
            },
            periodic: &self.periodic_values,
            selectors: air::Selectors {
                first: self.is_first_row,
                last: self.is_last_row,
                transition: Felt::ONE - self.is_last_row,
            },
        };
        let inputs = air::UniformInputs {
            public_values: &[],
            challenges: &self.randomness,
            exports: &self.permutation_values,
        };
        let mut sink = NumericSink { base: &mut self.evaluations };
        evaluate(&frame, inputs, &mut sink);
    }
}

/// Numerical outputs are separate from the borrowed rows and uniform inputs.
struct NumericSink<'a> {
    base: &'a mut Vec<Felt>,
}

impl air::LiftedAirBuilder for NumericSink<'_> {
    type F = Felt;
    type Expr = Felt;
    type ExtExpr = QuadFelt;
    fn emit_base(&mut self, value: Felt, _: air::ConstraintMeta<'_>) {
        self.base.push(value);
    }
    fn emit_ext(&mut self, value: QuadFelt, _: air::ConstraintMeta<'_>) {
        let _ = value;
        panic!("EidosCompression base-constraint tests must not emit extension-field constraints");
    }
}

struct ConstraintEvalBuilder {
    main: RowMajorMatrix<Felt>,
    aux: RowMajorMatrix<QuadFelt>,
    randomness: Vec<QuadFelt>,
    permutation_values: Vec<QuadFelt>,
    periodic_values: Vec<Felt>,
    evaluations: Vec<Felt>,

    is_first_row: Felt,
    is_last_row: Felt,
}

// Preserve the test's independent scalar evaluator while supplying native row selectors.
fn enforce_fused_rows(
    builder: &mut ConstraintEvalBuilder,
    local: &[Felt],
    next: &[Felt],
    selectors: &EidosCompressionSelectors<Felt>,
) {
    builder.eval_with(|frame, _, sink| native_fused_rows(frame, sink, local, next, selectors));
}
fn enforce_footer_rows(
    builder: &mut ConstraintEvalBuilder,
    local: &[Felt],
    next: &[Felt],
    selectors: &EidosCompressionSelectors<Felt>,
) {
    builder.eval_with(|frame, _, sink| native_footer_rows(frame, sink, local, next, selectors));
}

impl ConstraintEvalBuilder {
    fn new(
        local: &[Felt; NUM_COLS],
        next: &[Felt; NUM_COLS],
        periodic_values: Vec<Felt>,
        row_idx: usize,
        trace_len: usize,
    ) -> Self {
        let mut main = Felt::zero_vec(2 * NUM_COLS);
        main[..NUM_COLS].copy_from_slice(local);
        main[NUM_COLS..].copy_from_slice(next);

        Self {
            main: RowMajorMatrix::new(main, NUM_COLS),
            aux: RowMajorMatrix::new(vec![QuadFelt::ZERO; 2], 1),
            randomness: vec![QuadFelt::ZERO; 2],
            permutation_values: vec![QuadFelt::ZERO],
            periodic_values,
            evaluations: Vec::new(),

            is_first_row: Felt::from_bool(row_idx == 0),
            is_last_row: Felt::from_bool(row_idx + 1 == trace_len),
        }
    }
}

fn periodic_row(row_idx: usize) -> Vec<Felt> {
    get_periodic_column_values()
        .iter()
        .map(|column| column[row_idx % column.len()])
        .collect()
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
    let mut builder =
        ConstraintEvalBuilder::new(local, next, periodic_row(row_idx), row_idx, trace.len());
    let selectors = EidosCompressionSelectors::<Felt>::new(builder.periodic_values(), 0);
    enforce_fused_rows(&mut builder, local, next, &selectors);
    enforce_footer_rows(&mut builder, local, next, &selectors);
    builder.evaluations
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

            let periodic_values = periodic_row(row_idx);
            let mut pvm_builder = ConstraintEvalBuilder::new(
                &local,
                &next,
                periodic_values.clone(),
                row_idx,
                BLOCK_PERIOD,
            );
            let pvm_selectors =
                EidosCompressionSelectors::<Felt>::new(pvm_builder.periodic_values(), 0);
            enforce_fused_rows(&mut pvm_builder, &local, &next, &pvm_selectors);
            enforce_footer_rows(&mut pvm_builder, &local, &next, &pvm_selectors);

            let mut shared_builder =
                ConstraintEvalBuilder::new(&local, &next, periodic_values, row_idx, BLOCK_PERIOD);
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
                shared_builder.evaluations, pvm_builder.evaluations,
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
