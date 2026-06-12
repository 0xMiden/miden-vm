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
//!    extension-field element, so per-fraction `try_inverse` inside the accumulator does not panic.
//! 3. **Pipeline plumbing**: row slicing with wraparound, per-row periodic composition, `RowWindow`
//!    construction over a real matrix, and the dense `LookupFractions` buffer all line up.
//! 4. **Prover/constraint agreement**: the fused `accumulate` prover path must agree with the
//!    constraint-path `(V_col, U_col)` oracle bit-exactly on every `(row, col)` delta. If any pair
//!    disagrees, either the prover path or the oracle has a bug.
//!
//! The oracle cross-check in (4) subsumes the "does it run to completion?" shape of a
//! separate plumbing test, so both live in one function below.

use alloc::vec::Vec;

use miden_air::{
    BaseAir, LiftedAir, MidenAir,
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
    lookup::{Challenges, accumulate, build_lookup_fractions, debug::collect_column_oracle_folds},
};
use miden_core::{
    field::{Field, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
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

/// Asserts the `accumulate` output matches the oracle folds bit-exactly on every
/// `(row, col)` delta. Data-only so it's free of AIR generics.
fn assert_prover_matches_oracle(
    label: &str,
    aux: &RowMajorMatrix<QuadFelt>,
    oracle_folds: &[Vec<(QuadFelt, QuadFelt)>],
    aux_width: usize,
) {
    let num_rows = oracle_folds.len();
    assert_eq!(aux.width(), aux_width, "{label}: aux width mismatch");
    assert_eq!(aux.height(), num_rows + 1, "{label}: aux height mismatch");
    let aux_values = &aux.values;

    // Col 0 (accumulator): aux[r+1][0] - aux[r][0] == Σ_col per_row_value[col].
    // Cols 1+ (fraction): aux[r][col] == V/U per-row value.
    for (r, row_folds) in oracle_folds.iter().enumerate() {
        assert_eq!(row_folds.len(), aux_width, "{label} row {r}: fold width mismatch");
        let per_row_values: Vec<QuadFelt> = row_folds
            .iter()
            .enumerate()
            .map(|(col, &(v_col, u_col))| {
                let u_inv = u_col.try_inverse().unwrap_or_else(|| {
                    panic!(
                        "{label} row {r} col {col}: oracle U_col is zero — bus has a \
                         zero-denominator product, indicating a bug in the emitter or \
                         message encoding",
                    )
                });
                v_col * u_inv
            })
            .collect();

        let expected_delta: QuadFelt = per_row_values.iter().copied().sum();
        let actual_delta = aux_values[(r + 1) * aux_width] - aux_values[r * aux_width];
        assert_eq!(
            actual_delta, expected_delta,
            "{label} row {r} col 0 (accumulator): prover vs constraint path mismatch",
        );

        for col in 1..aux_width {
            let actual_value = aux_values[r * aux_width + col];
            assert_eq!(
                actual_value, per_row_values[col],
                "{label} row {r} col {col} (fraction): prover vs constraint path mismatch",
            );
        }
    }
}

#[test]
fn build_lookup_fractions_matches_constraint_path_oracle() {
    let trace = build_trace_from_ops(tiny_span(), &[]);

    let (core_matrix, chip_matrix, p2_matrix, and8_matrix) = trace.main_trace().to_air_matrices();
    let public_vals = trace.to_public_values();
    // Core has no periodic columns.
    let chip_periodic = LiftedAir::<Felt, QuadFelt>::periodic_columns(&MidenAir::CHIPLETS);
    let p2_periodic =
        LiftedAir::<Felt, QuadFelt>::periodic_columns(&MidenAir::POSEIDON2_PERMUTATION);
    let and8_preprocessed = MidenAir::AND8_LOOKUP
        .preprocessed_trace()
        .expect("AND8 lookup AIR declares a preprocessed table");

    // QuadFelt challenges for LogUp, built from 4 random Felts (QuadFelt itself doesn't
    // implement Randomizable, so we draw base-field elements and pair them).
    let raw = rand_array::<Felt, 4>();
    let alpha = QuadFelt::new([raw[0], raw[1]]);
    let beta = QuadFelt::new([raw[2], raw[3]]);
    let challenges =
        Challenges::<QuadFelt>::new(alpha, beta, MIDEN_MAX_MESSAGE_WIDTH, BusId::COUNT);

    // --- Core ---
    let core_fractions =
        build_lookup_fractions(&MidenAir::CORE, &core_matrix, None, &[], &challenges);
    assert!(
        !core_fractions.fractions().is_empty(),
        "no Core fractions collected — trace is degenerate or emitters are broken",
    );
    let core_aux = accumulate(&core_fractions);
    let core_folds =
        collect_column_oracle_folds(&MidenAir::CORE, &core_matrix, &[], &public_vals, &challenges);
    assert_prover_matches_oracle(
        "Core",
        &core_aux,
        &core_folds,
        LiftedAir::<Felt, QuadFelt>::aux_width(&MidenAir::CORE),
    );

    // --- Chiplets ---
    let chip_fractions = build_lookup_fractions(
        &MidenAir::CHIPLETS,
        &chip_matrix,
        None,
        &chip_periodic,
        &challenges,
    );
    assert!(
        !chip_fractions.fractions().is_empty(),
        "no Chiplets fractions collected — trace is degenerate or emitters are broken",
    );
    let chip_aux = accumulate(&chip_fractions);
    let chip_folds = collect_column_oracle_folds(
        &MidenAir::CHIPLETS,
        &chip_matrix,
        &chip_periodic,
        &public_vals,
        &challenges,
    );
    assert_prover_matches_oracle(
        "Chiplets",
        &chip_aux,
        &chip_folds,
        LiftedAir::<Felt, QuadFelt>::aux_width(&MidenAir::CHIPLETS),
    );

    // --- Poseidon2 permutation ---
    let p2_fractions = build_lookup_fractions(
        &MidenAir::POSEIDON2_PERMUTATION,
        &p2_matrix,
        None,
        &p2_periodic,
        &challenges,
    );
    assert!(
        !p2_fractions.fractions().is_empty(),
        "no Poseidon2-permutation fractions collected — trace is degenerate or emitters are broken",
    );
    let p2_aux = accumulate(&p2_fractions);
    let p2_folds = collect_column_oracle_folds(
        &MidenAir::POSEIDON2_PERMUTATION,
        &p2_matrix,
        &p2_periodic,
        &public_vals,
        &challenges,
    );
    assert_prover_matches_oracle(
        "Poseidon2Permutation",
        &p2_aux,
        &p2_folds,
        LiftedAir::<Felt, QuadFelt>::aux_width(&MidenAir::POSEIDON2_PERMUTATION),
    );

    // --- AND8 lookup table ---
    let and8_fractions = build_lookup_fractions(
        &MidenAir::AND8_LOOKUP,
        &and8_matrix,
        Some(&and8_preprocessed),
        &[],
        &challenges,
    );
    assert!(
        and8_fractions.fractions().is_empty(),
        "the placeholder AND8 table should have zero dynamic multiplicity before consumers are wired",
    );
    let and8_aux = accumulate(&and8_fractions);
    let and8_folds = collect_column_oracle_folds(
        &MidenAir::AND8_LOOKUP,
        &and8_matrix,
        &[],
        &public_vals,
        &challenges,
    );
    assert_prover_matches_oracle(
        "And8Lookup",
        &and8_aux,
        &and8_folds,
        LiftedAir::<Felt, QuadFelt>::aux_width(&MidenAir::AND8_LOOKUP),
    );
}
