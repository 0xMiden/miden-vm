use std::{vec, vec::Vec};

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_crypto::stark::air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, RowWindow};

use super::{
    constraints::{enforce_footer_rows, enforce_fused_rows},
    layout::{BLOCK_PERIOD, FUSED_G_ROWS, G_COMPRESSION_CYCLE_ID_COL, NUM_COLS},
    periodic::get_periodic_column_values,
    selectors::EidosCompressionSelectors,
    trace::{EidosCompressionFeltRow, generate_felt_trace_block_with_cycle_id},
};

struct ConstraintEvalBuilder {
    main: RowMajorMatrix<Felt>,
    aux: RowMajorMatrix<QuadFelt>,
    randomness: Vec<QuadFelt>,
    permutation_values: Vec<QuadFelt>,
    periodic_values: Vec<Felt>,
    evaluations: Vec<Felt>,
    preprocessed_window: RowWindow<'static, Felt>,
    is_first_row: Felt,
    is_last_row: Felt,
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
            preprocessed_window: RowWindow::from_two_rows(&[], &[]),
            is_first_row: Felt::from_bool(row_idx == 0),
            is_last_row: Felt::from_bool(row_idx + 1 == trace_len),
        }
    }
}

impl AirBuilder for ConstraintEvalBuilder {
    type F = Felt;
    type Expr = Felt;
    type Var = Felt;
    type PreprocessedWindow = RowWindow<'static, Felt>;
    type MainWindow = RowMajorMatrix<Felt>;
    type PublicVar = Felt;
    type PeriodicVar = Felt;

    fn main(&self) -> Self::MainWindow {
        self.main.clone()
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed_window
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row
    }

    fn is_transition(&self) -> Self::Expr {
        Felt::ONE - self.is_last_row
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert_eq!(size, 2, "EidosCompression 32-row tests use two-row transition windows");
        self.is_transition()
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, value: I) {
        self.evaluations.push(value.into());
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        &[]
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        &self.periodic_values
    }
}

impl ExtensionBuilder for ConstraintEvalBuilder {
    type EF = QuadFelt;
    type ExprEF = QuadFelt;
    type VarEF = QuadFelt;

    fn assert_zero_ext<I>(&mut self, _value: I)
    where
        I: Into<Self::ExprEF>,
    {
        panic!("EidosCompression base-constraint tests must not emit extension-field constraints");
    }
}

impl PermutationAirBuilder for ConstraintEvalBuilder {
    type MP = RowMajorMatrix<QuadFelt>;
    type RandomVar = QuadFelt;
    type PermutationVar = QuadFelt;

    fn permutation(&self) -> Self::MP {
        self.aux.clone()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        &self.randomness
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        &self.permutation_values
    }
}

fn periodic_row(row_idx: usize) -> Vec<Felt> {
    get_periodic_column_values()
        .iter()
        .map(|column| column[row_idx % column.len()])
        .collect()
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
fn cross_row_cycle_id_constancy_is_independently_load_bearing() {
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

    assert_eq!(BLOCK_PERIOD, 32);
}
