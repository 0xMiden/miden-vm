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
//! oracle. Column terminals are printed to stderr for manual inspection.

use miden_air::{
    LOGUP_AUX_TRACE_WIDTH, LiftedAir, ProcessorAir,
    lookup::{
        LookupChallenges, MidenLookupAir, accumulate, accumulate_slow, build_lookup_fractions,
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
    let public_vals = trace.to_public_values();
    let periodic = LiftedAir::<Felt, QuadFelt>::periodic_columns(&ProcessorAir);

    // QuadFelt challenges for LogUp, built from 4 random Felts (QuadFelt itself doesn't
    // implement Randomizable, so we draw base-field elements and pair them). Distinct
    // from the legacy multiset path in decoder.rs which uses Felt challenges directly.
    let raw = rand_array::<Felt, 4>();
    let alpha = QuadFelt::new([raw[0], raw[1]]);
    let beta = QuadFelt::new([raw[2], raw[3]]);
    let challenges = LookupChallenges::<QuadFelt>::new(alpha, beta);

    let air = MidenLookupAir;
    let fractions = build_lookup_fractions(&air, &main_trace, &periodic, &public_vals, &challenges);

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
        assert_eq!(col_aux[0], QuadFelt::ZERO);
    }

    // --- Informational: per-column terminals. A follow-up commit hardens these into
    //     concrete assertions once we know the expected boundary value for each column
    //     (some close to zero, log_precompile transcript has a non-zero boundary). ---
    for (col, col_aux) in aux.iter().enumerate() {
        std::eprintln!("lookup column {col} terminal = {:?}", col_aux[num_rows]);
    }
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
    let challenges = LookupChallenges::<QuadFelt>::new(alpha, beta);

    // --- Prover path: collect fractions and run the fused accumulator. ---
    let air = MidenLookupAir;
    let fractions = build_lookup_fractions(&air, &main_trace, &periodic, &public_vals, &challenges);
    // `accumulate` returns a row-major matrix with `num_rows + 1` rows and `num_cols`
    // columns; row 0 is the zero initial condition and row `r + 1` column `c` holds the
    // running sum of `m_i · d_i⁻¹` through main-trace row `r`.
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

    // --- Per-(row, col) delta check. ---
    for (r, row_folds) in oracle_folds.iter().enumerate() {
        assert_eq!(row_folds.len(), LOGUP_AUX_TRACE_WIDTH);
        for (col, &(u_col, v_col)) in row_folds.iter().enumerate() {
            let u_inv = u_col.try_inverse().unwrap_or_else(|| {
                panic!(
                    "row {r} col {col}: oracle U_col is zero — bus has a zero-denominator \
                     product, indicating a bug in the emitter or message encoding",
                )
            });
            let expected_delta = v_col * u_inv;
            let actual_delta =
                aux_values[(r + 1) * aux_width + col] - aux_values[r * aux_width + col];
            assert_eq!(
                actual_delta, expected_delta,
                "row {r} col {col}: prover path vs constraint path mismatch\n  \
                 prover delta = {actual_delta:?}\n  \
                 oracle (U, V) = ({u_col:?}, {v_col:?})\n  \
                 oracle delta  = {expected_delta:?}",
            );
        }
    }
}

/// Diagnostic: compute per-column terminals for the same Fibonacci MASM program that
/// `test_blake3_256_prove_verify` uses, built via the `Assembler` so HALT padding rows
/// are present. Used to isolate which columns close in-trace and which carry open
/// boundary contributions that need to appear in `reduced_aux_values`.
#[test]
fn diagnostic_assembler_path_terminals() {
    use miden_assembly::Assembler;

    use super::build_trace_from_program;

    let source = "
        begin
            repeat.149
                swap dup.1 add
            end
        end
    ";
    let program = Assembler::default().assemble_program(source).unwrap();
    let trace = build_trace_from_program(&program, &[0, 1]);

    let main_trace = trace.main_trace().to_row_major();
    let public_vals = trace.to_public_values();
    let periodic = LiftedAir::<Felt, QuadFelt>::periodic_columns(&ProcessorAir);

    let raw = rand_array::<Felt, 4>();
    let alpha = QuadFelt::new([raw[0], raw[1]]);
    let beta = QuadFelt::new([raw[2], raw[3]]);
    let challenges = LookupChallenges::<QuadFelt>::new(alpha, beta);

    let air = MidenLookupAir;
    let fractions = build_lookup_fractions(&air, &main_trace, &periodic, &public_vals, &challenges);
    let aux = accumulate_slow(&fractions);
    let num_rows = trace.main_trace().num_rows();

    std::eprintln!("assembler-path trace: {} rows", num_rows);
    let labels = [
        "M1 block_stack+range_table",
        "M_2+5 block_hash+op_group",
        "M3 chiplet_requests",
        "M4 range_logcap",
        "M5 stack_overflow",
        "C1 chiplet_responses",
        "C2 hash_kernel+sibling",
        "C3 ace_wiring",
    ];
    for (col, col_aux) in aux.iter().enumerate() {
        let terminal = col_aux[num_rows];
        let label = if terminal == QuadFelt::ZERO { " (CLOSED)" } else { "" };
        std::eprintln!("col {col} ({}) terminal = {terminal:?}{label}", labels[col]);
    }
}
