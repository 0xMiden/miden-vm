use alloc::vec::Vec;

use miden_core::field::{PrimeCharacteristicRing, QuadFelt};
use miden_crypto::stark::{
    air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, RowWindow},
    matrix::RowMajorMatrix,
};

use super::layout::*;
use super::periodic::get_periodic_column_values;
use super::selectors::BlakeGSelectors;
use super::symbolic::{enforce_footer_rows, enforce_fused_rows};
use super::trace::{TraceMode, generate_felt_trace_block};
use crate::Felt;

struct ConstraintEvalBuilder {
    main: RowMajorMatrix<Felt>,
    aux: RowMajorMatrix<QuadFelt>,
    randomness: Vec<QuadFelt>,
    permutation_values: Vec<QuadFelt>,
    periodic_values: Vec<Felt>,
    evaluations: Vec<Felt>,
    preprocessed_window: RowWindow<'static, Felt>,
}

impl ConstraintEvalBuilder {
    fn new(local: &[Felt; NUM_COLS], next: &[Felt; NUM_COLS], periodic_values: Vec<Felt>) -> Self {
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
        Felt::ZERO
    }

    fn is_last_row(&self) -> Self::Expr {
        Felt::ZERO
    }

    fn is_transition(&self) -> Self::Expr {
        Felt::ONE
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert_eq!(size, 2, "BlakeG 32-row tests use two-row transition windows");
        self.is_transition()
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.evaluations.push(x.into());
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

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        let _value: QuadFelt = x.into();
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

fn test_block() -> [u32; 16] {
    [
        0x0000_0001,
        0x0000_0002,
        0x0000_0003,
        0x0000_0004,
        0x8000_0005,
        0x0000_0006,
        0x0000_0007,
        0x0000_0008,
        0x0000_0009,
        0x8000_000a,
        0x8000_000b,
        0x0000_000c,
        0x0000_000d,
        0x0000_000e,
        0x0000_000f,
        0x0000_0010,
    ]
}

fn test_h() -> [u32; 8] {
    [
        0x0000_0021,
        0x8000_0001,
        0x8000_0022,
        0x0000_0043,
        0x0000_0023,
        0x0000_0065,
        0x0000_0024,
        0x0000_0087,
    ]
}

fn periodic_row(row_idx: usize) -> Vec<Felt> {
    get_periodic_column_values().iter().map(|column| column[row_idx]).collect()
}

fn eval_fused_row(local: &[Felt; NUM_COLS], next: &[Felt; NUM_COLS], row_idx: usize) -> Vec<Felt> {
    let mut builder = ConstraintEvalBuilder::new(local, next, periodic_row(row_idx));
    let selectors = BlakeGSelectors::<Felt>::new(builder.periodic_values(), 0);
    enforce_fused_rows(&mut builder, local, next, &selectors);
    builder.evaluations
}

fn eval_footer_row(local: &[Felt; NUM_COLS], next: &[Felt; NUM_COLS], row_idx: usize) -> Vec<Felt> {
    let mut builder = ConstraintEvalBuilder::new(local, next, periodic_row(row_idx));
    let selectors = BlakeGSelectors::<Felt>::new(builder.periodic_values(), 0);
    enforce_footer_rows(&mut builder, local, next, &selectors);
    builder.evaluations
}

fn assert_all_zero(values: &[Felt]) {
    assert!(
        values.iter().all(|value| *value == Felt::ZERO),
        "expected all constraints to vanish"
    );
}

fn assert_any_nonzero(values: &[Felt]) {
    assert!(values.iter().any(|value| *value != Felt::ZERO), "expected a failing constraint");
}

#[test]
fn symbolic_fused_constraints_accept_generated_trace() {
    let trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);

    for row in 0..FUSED_G_ROWS {
        assert_all_zero(&eval_fused_row(&trace.rows[row], &trace.rows[row + 1], row));
    }
}

#[test]
fn symbolic_fused_constraints_reject_bad_message_index() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[0][g_msg_slot_col(0, 0)] += Felt::ONE;

    assert_any_nonzero(&eval_fused_row(&trace.rows[0], &trace.rows[1], 0));
}

#[test]
fn symbolic_fused_constraints_reject_bad_carry() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[0][G_K2_BASE_COL] = Felt::new_unchecked(2);

    assert_any_nonzero(&eval_fused_row(&trace.rows[0], &trace.rows[1], 0));
}

#[test]
fn symbolic_fused_constraints_reject_bad_initial_iv() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[0][G_C_BASE_COL] += Felt::ONE;

    assert_any_nonzero(&eval_fused_row(&trace.rows[0], &trace.rows[1], 0));
}

#[test]
fn symbolic_fused_constraints_reject_bad_transition() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[1][G_A_BASE_COL] += Felt::ONE;

    assert_any_nonzero(&eval_fused_row(&trace.rows[0], &trace.rows[1], 0));
}

#[test]
fn symbolic_footer_constraints_accept_generated_trace() {
    let trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::AeadXof { clk: 19 });

    for row in FUSED_G_ROWS - 1..BLOCK_PERIOD {
        let next = row.saturating_add(1).min(BLOCK_PERIOD - 1);
        assert_all_zero(&eval_footer_row(&trace.rows[row], &trace.rows[next], row));
    }
}

#[test]
fn symbolic_footer_constraints_reject_bad_bridge() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START][F_FUTURE_W_BASE_COL] += Felt::ONE;

    assert_any_nonzero(&eval_footer_row(
        &trace.rows[FUSED_G_ROWS - 1],
        &trace.rows[FOOTER_START],
        FUSED_G_ROWS - 1,
    ));
}

#[test]
fn symbolic_footer_constraints_reject_bad_message_limb() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START][footer_range_slot_col(0, 0)] += Felt::ONE;

    assert_any_nonzero(&eval_footer_row(
        &trace.rows[FOOTER_START],
        &trace.rows[FOOTER_START + 1],
        FOOTER_START,
    ));
}

#[test]
fn symbolic_footer_constraints_reject_bad_canonicality() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START][F_C_CANON_Z_COL] = Felt::ONE;

    assert_any_nonzero(&eval_footer_row(
        &trace.rows[FOOTER_START],
        &trace.rows[FOOTER_START + 1],
        FOOTER_START,
    ));
}

#[test]
fn symbolic_footer_constraints_reject_bad_footer_transition() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START + 1][F_R_BASE_COL] += Felt::ONE;

    assert_any_nonzero(&eval_footer_row(
        &trace.rows[FOOTER_START],
        &trace.rows[FOOTER_START + 1],
        FOOTER_START,
    ));
}

#[test]
fn symbolic_footer_constraints_reject_aead_compression_multiplicity() {
    let mut trace =
        generate_felt_trace_block(test_block(), test_h(), TraceMode::AeadXof { clk: 19 });
    trace.rows[FOOTER_START][F_COMPRESSION_MULTIPLICITY_COL] = Felt::ONE;

    assert_any_nonzero(&eval_footer_row(
        &trace.rows[FOOTER_START],
        &trace.rows[FOOTER_START + 1],
        FOOTER_START,
    ));
}

#[test]
fn symbolic_footer_constraints_reject_bad_multiplicity_transition() {
    let mut trace = generate_felt_trace_block(
        test_block(),
        test_h(),
        TraceMode::CompressionWithMultiplicity { multiplicity: 2 },
    );
    trace.rows[FOOTER_START + 1][F_COMPRESSION_MULTIPLICITY_COL] = Felt::new_unchecked(3);

    assert_any_nonzero(&eval_footer_row(
        &trace.rows[FOOTER_START],
        &trace.rows[FOOTER_START + 1],
        FOOTER_START,
    ));
}
