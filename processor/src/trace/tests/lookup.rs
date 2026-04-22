//! End-to-end collection-phase smoke test for the prover-side LogUp pipeline.
//!
//! Runs a tiny MASM basic block through `build_trace_from_ops`, materialises the resulting
//! main trace as a [`RowMajorMatrix<Felt>`], and pipes it through [`build_lookup_fractions`]
//! + [`accumulate`]. The test validates:
//!
//! 1. **Shape-const drift**: every bus emitter's declared `MAX_INTERACTIONS_PER_ROW` is large
//!    enough to accommodate real trace data (the `debug_assert!` inside
//!    `ProverLookupBuilder::column` panics on overflow).
//! 2. **Zero-denominator bugs**: every encoded `LookupMessage` evaluates to a non-zero
//!    extension-field element, so per-fraction `try_inverse` inside the accumulator does
//!    not panic.
//! 3. **Pipeline plumbing**: row slicing with wraparound, per-row periodic composition,
//!    `RowWindow` construction over a real matrix, and the dense `LookupFractions` buffer
//!    all line up.
//! 4. **Prover/constraint agreement**: the fused `accumulate` prover path must agree with
//!    the constraint-path `(U_col, V_col)` oracle bit-exactly on every `(row, col)` delta.
//!    If any pair disagrees, either the prover path or the oracle has a bug.
//!
//! The oracle cross-check in (4) subsumes the "does it run to completion?" shape of a
//! separate plumbing test, so both live in one function below.

use alloc::vec::Vec;

use miden_air::{
    LOGUP_AUX_TRACE_WIDTH, LiftedAir, ProcessorAir,
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
    lookup::{Challenges, accumulate, build_lookup_fractions, debug::collect_column_oracle_folds},
};
use miden_core::{
    field::{Field, QuadFelt},
    utils::Matrix,
};

use super::{Felt, build_trace_from_ops, rand_array};
use crate::operation::Operation;

/// Pad/Add/Mul/Drop inside a span — same flavour of ops the decoder/stack tests use, with
/// enough variety to exercise decoder, stack, and range-check bus emitters.
fn tiny_span() -> Vec<Operation> {
    vec![
        Operation::Pad,
        Operation::Pad,
        Operation::Add,
        Operation::Pad,
        Operation::Mul,
        Operation::Drop,
    ]
}

/// Cross-check: the fused `accumulate` prover path must agree with the constraint-path
/// `(U_col, V_col)` oracle bit-exactly on every `(row, col)` delta.
///
/// - **Prover path**: collect `(m_i, d_i)` fractions via `ProverLookupBuilder` on each row,
///   then `accumulate` runs batched Montgomery inversion + per-column partial sums to
///   produce `aux[col][r+1] - aux[col][r] = Σ m_i · d_i^{-1}`.
/// - **Constraint path**: `ColumnOracleBuilder` evaluates `ProcessorAir` row-by-row using
///   the same `(U_g, V_g)` algebra the constraint system uses, folded per column via
///   cross-multiplication, producing `expected_delta = V_col · U_col^{-1}`.
///
/// A divergence means either the prover path or the oracle has a bug — fix the root cause.
#[test]
fn build_lookup_fractions_matches_constraint_path_oracle() {
    let trace = build_trace_from_ops(tiny_span(), &[]);

    let main_trace = trace.main_trace().to_row_major();
    let public_vals = trace.to_public_values();
    let periodic = LiftedAir::<Felt, QuadFelt>::periodic_columns(&ProcessorAir);

    // QuadFelt challenges for LogUp, built from 4 random Felts (QuadFelt itself doesn't
    // implement Randomizable, so we draw base-field elements and pair them).
    let raw = rand_array::<Felt, 4>();
    let alpha = QuadFelt::new([raw[0], raw[1]]);
    let beta = QuadFelt::new([raw[2], raw[3]]);
    let air = ProcessorAir;
    let challenges =
        Challenges::<QuadFelt>::new(alpha, beta, MIDEN_MAX_MESSAGE_WIDTH, BusId::COUNT);

    // --- Prover path: collect fractions and run the fused accumulator. ---
    let fractions = build_lookup_fractions(&air, &main_trace, &periodic, &challenges);

    // Shape / non-degenerate smoke checks — if these trip, the oracle check below is moot.
    let num_rows = trace.main_trace().num_rows();
    assert_eq!(fractions.num_rows(), num_rows);
    assert_eq!(fractions.num_columns(), LOGUP_AUX_TRACE_WIDTH);
    assert_eq!(fractions.counts().len(), num_rows * LOGUP_AUX_TRACE_WIDTH);
    assert!(
        !fractions.fractions().is_empty(),
        "no fractions collected — trace is degenerate or emitters are broken",
    );

    // `accumulate` returns a row-major matrix with `num_rows + 1` rows and `num_cols`
    // columns. Col 0 is the running-sum accumulator; cols 1+ hold per-row fraction values.
    let aux = accumulate(&fractions);
    let aux_width = aux.width();
    let aux_values = &aux.values;
    assert_eq!(aux_width, LOGUP_AUX_TRACE_WIDTH);
    assert_eq!(aux.height(), num_rows + 1);

    // --- Constraint path: walk the trace through the oracle to collect per-row folded
    //     `(U_col, V_col)` pairs. ---
    let oracle_folds =
        collect_column_oracle_folds(&air, &main_trace, &periodic, &public_vals, &challenges);
    assert_eq!(oracle_folds.len(), num_rows);

    // --- Per-(row, col) value check. ---
    // Col 0 (accumulator): aux[r+1][0] - aux[r][0] == Σ_col per_row_value[col].
    // Cols 1+ (fraction): aux[r][col] == V/U per-row value.
    for (r, row_folds) in oracle_folds.iter().enumerate() {
        assert_eq!(row_folds.len(), LOGUP_AUX_TRACE_WIDTH);
        let per_row_values: Vec<QuadFelt> = row_folds
            .iter()
            .enumerate()
            .map(|(col, &(u_col, v_col))| {
                let u_inv = u_col.try_inverse().unwrap_or_else(|| {
                    panic!(
                        "row {r} col {col}: oracle U_col is zero — bus has a zero-denominator \
                         product, indicating a bug in the emitter or message encoding",
                    )
                });
                v_col * u_inv
            })
            .collect();

        // Accumulator (col 0): delta == sum of all columns' per-row values.
        let expected_delta: QuadFelt = per_row_values.iter().copied().sum();
        let actual_delta = aux_values[(r + 1) * aux_width] - aux_values[r * aux_width];
        assert_eq!(
            actual_delta, expected_delta,
            "row {r} col 0 (accumulator): prover vs constraint path mismatch",
        );

        // Fraction columns (cols 1+): aux[r][col] == per-row V/U.
        for col in 1..LOGUP_AUX_TRACE_WIDTH {
            let actual_value = aux_values[r * aux_width + col];
            assert_eq!(
                actual_value, per_row_values[col],
                "row {r} col {col} (fraction): prover vs constraint path mismatch",
            );
        }
    }
}
