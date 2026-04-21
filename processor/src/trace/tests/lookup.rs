//! End-to-end collection-phase smoke test for the prover-side LogUp pipeline.
//!
//! Runs a tiny MASM basic block through `build_trace_from_ops`, materialises the
//! resulting main trace as a [`RowMajorMatrix<Felt>`], and pipes it through
//! [`build_lookup_fractions`] + [`accumulate_slow`]. The test validates:
//!
//! 1. **Shape-const drift**: every bus emitter's declared `MAX_INTERACTIONS_PER_ROW` is large
//!    enough to accommodate real trace data (the `debug_assert!` inside
//!    `ProverLookupBuilder::column` panics on overflow).
//! 2. **Zero-denominator bugs**: every encoded `LookupMessage` evaluates to a non-zero
//!    extension-field element, so `accumulate_slow`'s per-fraction `try_inverse` does not panic.
//! 3. **Pipeline plumbing**: row slicing with wraparound, per-row periodic composition, `RowWindow`
//!    construction over a real matrix, and the dense `LookupFractions` buffer all line up.
//!
//! The test does **not** assert algebraic correctness of individual aux-column values
//! or terminal closure — those checks need the follow-up constraint-path round-trip
//! oracle.

use alloc::vec::Vec;

use miden_air::{
    LOGUP_AUX_TRACE_WIDTH, LiftedAir, ProcessorAir,
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH, MidenLookupAir},
    lookup::{
        Challenges, accumulate, accumulate_slow, build_lookup_fractions,
        debug::collect_column_oracle_folds,
    },
};
use miden_core::{
    field::{Field, PrimeCharacteristicRing, QuadFelt},
    utils::Matrix,
};

use super::{Felt, build_trace_from_ops, rand_array};
use crate::operation::Operation;

/// Smallest end-to-end check: run a tiny real trace through the LogUp collection
/// driver and verify the debug-mode shape check never trips, no zero denominators
/// are produced, and the accumulator runs to completion.
#[test]
fn build_lookup_fractions_on_tiny_span() {
    // A handful of ops inside a span. Pad/Add/Mul/Drop exercise decoder + stack +
    // range checks with minimal setup — same flavour of ops as the existing
    // `decoder.rs` / `stack.rs` tests use.
    let ops = vec![
        Operation::Pad,
        Operation::Pad,
        Operation::Add,
        Operation::Pad,
        Operation::Mul,
        Operation::Drop,
    ];
    let trace = build_trace_from_ops(ops, &[]);

    let main_trace = trace.main_trace().to_row_major();
    let periodic = LiftedAir::<Felt, QuadFelt>::periodic_columns(&ProcessorAir);

    // QuadFelt challenges for LogUp, built from 4 random Felts (QuadFelt itself doesn't
    // implement Randomizable, so we draw base-field elements and pair them). Distinct
    // from the legacy multiset path in decoder.rs which uses Felt challenges directly.
    let raw = rand_array::<Felt, 4>();
    let alpha = QuadFelt::new([raw[0], raw[1]]);
    let beta = QuadFelt::new([raw[2], raw[3]]);
    let air = MidenLookupAir;
    let challenges =
        Challenges::<QuadFelt>::new(alpha, beta, MIDEN_MAX_MESSAGE_WIDTH, BusId::COUNT);

    let fractions = build_lookup_fractions(&air, &main_trace, &periodic, &challenges);

    // --- Shape bookkeeping ---
    let num_rows = trace.main_trace().num_rows();
    assert_eq!(fractions.num_rows(), num_rows);
    assert_eq!(fractions.num_columns(), LOGUP_AUX_TRACE_WIDTH);
    assert_eq!(fractions.counts().len(), num_rows * LOGUP_AUX_TRACE_WIDTH);

    // --- Trace is not degenerate: at least one fraction was collected somewhere.
    //     If every column was empty the emitters, shape consts, or trace are broken. ---
    assert!(
        !fractions.fractions().is_empty(),
        "no fractions collected — trace is degenerate or emitters are broken",
    );

    // --- Slow accumulator runs without panicking. This is the real regression check:
    //     a bad emitter or a zero bus_prefix would produce a zero-denominator fraction
    //     and `try_inverse` inside `accumulate_slow` would panic. ---
    let aux = accumulate_slow(&fractions);
    assert_eq!(aux.len(), LOGUP_AUX_TRACE_WIDTH);
    for col_aux in &aux {
        assert_eq!(col_aux.len(), num_rows + 1);
    }
    assert_eq!(aux[0][0], QuadFelt::ZERO);
}

/// Cross-check: the fused `accumulate` prover path must agree with the constraint-path
/// `(U_col, V_col)` oracle bit-exactly on every `(row, col)` delta. This catches any
/// divergence between the two independent computations of the same algebraic quantity:
///
/// - **Prover path**: collect `(m_i, d_i)` fractions via `ProverLookupBuilder` on each row, then
///   `accumulate` runs batched Montgomery inversion + per-column partial sums to produce
///   `aux[col][r+1] - aux[col][r] = Σ m_i · d_i^{-1}`.
/// - **Constraint path**: `ColumnOracleBuilder` evaluates `MidenLookupAir` row-by-row using the
///   same `(U_g, V_g)` algebra the constraint system uses, folded per column via
///   cross-multiplication, producing `expected_delta = V_col · U_col^{-1}`.
///
/// If any `(row, col)` pair disagrees, either the prover path or the oracle has a bug
/// (and we must fix the root cause — do not paper over with tolerance).
#[test]
fn build_lookup_fractions_matches_constraint_path_oracle() {
    // Reuse the same tiny span as the plumbing smoke test so both tests exercise the
    // same trace shape.
    let ops = vec![
        Operation::Pad,
        Operation::Pad,
        Operation::Add,
        Operation::Pad,
        Operation::Mul,
        Operation::Drop,
    ];
    let trace = build_trace_from_ops(ops, &[]);

    let main_trace = trace.main_trace().to_row_major();
    let public_vals = trace.to_public_values();
    let periodic = LiftedAir::<Felt, QuadFelt>::periodic_columns(&ProcessorAir);

    let raw = rand_array::<Felt, 4>();
    let alpha = QuadFelt::new([raw[0], raw[1]]);
    let beta = QuadFelt::new([raw[2], raw[3]]);
    // --- Prover path: collect fractions and run the fused accumulator. ---
    let air = MidenLookupAir;
    let challenges =
        Challenges::<QuadFelt>::new(alpha, beta, MIDEN_MAX_MESSAGE_WIDTH, BusId::COUNT);
    let fractions = build_lookup_fractions(&air, &main_trace, &periodic, &challenges);
    // `accumulate` returns a row-major matrix with `num_rows + 1` rows and `num_cols`
    // columns. Col 0 is the running-sum accumulator; cols 1+ hold per-row fraction values.
    let aux = accumulate(&fractions);
    let aux_width = aux.width();
    let aux_values = &aux.values;

    let num_rows = trace.main_trace().num_rows();
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
