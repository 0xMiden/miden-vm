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
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use miden_air::{
    BaseAir, ChipletCols, ControllerCols, LiftedAir, MidenAir,
    logup::{BusId, HasherPermLinkMsg, MIDEN_MAX_MESSAGE_WIDTH},
    lookup::{
        Challenges, LookupMessage, accumulate, build_lookup_fractions,
        debug::collect_column_oracle_folds,
    },
    trace::CHIPLET_CONTROLLER_OFFSET,
};
use miden_core::{
    field::{Field, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};

use super::{Felt, build_trace_from_ops, rand_array};
use crate::operation::Operation;

const CONTROLLER_OFFSET: usize = CHIPLET_CONTROLLER_OFFSET;
const CONTROLLER_WIDTH: usize = size_of::<ControllerCols<u8>>();

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

fn perm_link_fractions(
    chip_matrix: &RowMajorMatrix<Felt>,
    poseidon2_matrix: &RowMajorMatrix<Felt>,
    challenges: &Challenges<QuadFelt>,
) -> Vec<(Felt, QuadFelt)> {
    let chip_periodic = MidenAir::Chiplets.periodic_columns();
    let poseidon2_periodic = MidenAir::Poseidon2Permutation.periodic_columns();
    let chip_fractions =
        build_lookup_fractions(&MidenAir::Chiplets, chip_matrix, &chip_periodic, challenges);
    let poseidon2_fractions = build_lookup_fractions(
        &MidenAir::Poseidon2Permutation,
        poseidon2_matrix,
        &poseidon2_periodic,
        challenges,
    );

    chip_fractions
        .fractions()
        .iter()
        .chain(poseidon2_fractions.fractions())
        .copied()
        .collect()
}

fn net_multiplicity(fractions: &[(Felt, QuadFelt)], denom: QuadFelt) -> Felt {
    let mut net = Felt::ZERO;
    for &(multiplicity, encoded) in fractions {
        if encoded == denom {
            net += multiplicity;
        }
    }
    net
}

fn chiplet_row(matrix: &RowMajorMatrix<Felt>, row: usize) -> &ChipletCols<Felt> {
    let width = matrix.width();
    matrix.values[row * width..(row + 1) * width].borrow()
}

fn controller_row(matrix: &RowMajorMatrix<Felt>, row: usize) -> &ControllerCols<Felt> {
    chiplet_row(matrix, row).controller()
}

fn controller_row_mut(matrix: &mut RowMajorMatrix<Felt>, row: usize) -> &mut ControllerCols<Felt> {
    let width = matrix.width();
    let start = row * width + CONTROLLER_OFFSET;
    matrix.values[start..start + CONTROLLER_WIDTH].borrow_mut()
}

#[test]
fn build_lookup_fractions_matches_constraint_path_oracle() {
    let trace = build_trace_from_ops(tiny_span(), &[]);

    let (core_matrix, chip_matrix, poseidon2_matrix) = trace.main_trace().to_air_matrices();
    let public_vals = trace.to_public_values();
    let chip_periodic = MidenAir::Chiplets.periodic_columns();
    let poseidon2_periodic = MidenAir::Poseidon2Permutation.periodic_columns();

    // QuadFelt challenges for LogUp, built from 4 random Felts (QuadFelt itself doesn't
    // implement Randomizable, so we draw base-field elements and pair them).
    let raw = rand_array::<Felt, 4>();
    let alpha = QuadFelt::new([raw[0], raw[1]]);
    let beta = QuadFelt::new([raw[2], raw[3]]);
    let challenges =
        Challenges::<QuadFelt>::new(alpha, beta, MIDEN_MAX_MESSAGE_WIDTH, BusId::COUNT);

    // --- Core ---
    let core_fractions = build_lookup_fractions(&MidenAir::Core, &core_matrix, &[], &challenges);
    assert!(
        !core_fractions.fractions().is_empty(),
        "no Core fractions collected — trace is degenerate or emitters are broken",
    );
    let core_aux = accumulate(&core_fractions);
    let core_folds =
        collect_column_oracle_folds(&MidenAir::Core, &core_matrix, &[], &public_vals, &challenges);
    assert_prover_matches_oracle(
        "Core",
        &core_aux,
        &core_folds,
        LiftedAir::<Felt, QuadFelt>::aux_width(&MidenAir::Core),
    );

    // --- Chiplets ---
    let chip_fractions =
        build_lookup_fractions(&MidenAir::Chiplets, &chip_matrix, &chip_periodic, &challenges);
    assert!(
        !chip_fractions.fractions().is_empty(),
        "no Chiplets fractions collected — trace is degenerate or emitters are broken",
    );
    let chip_aux = accumulate(&chip_fractions);
    let chip_folds = collect_column_oracle_folds(
        &MidenAir::Chiplets,
        &chip_matrix,
        &chip_periodic,
        &public_vals,
        &challenges,
    );
    assert_prover_matches_oracle(
        "Chiplets",
        &chip_aux,
        &chip_folds,
        LiftedAir::<Felt, QuadFelt>::aux_width(&MidenAir::Chiplets),
    );

    // --- Poseidon2 permutation ---
    let poseidon2_fractions = build_lookup_fractions(
        &MidenAir::Poseidon2Permutation,
        &poseidon2_matrix,
        &poseidon2_periodic,
        &challenges,
    );
    assert!(
        !poseidon2_fractions.fractions().is_empty(),
        "no Poseidon2 fractions collected; trace is degenerate or emitters are broken",
    );
    let poseidon2_aux = accumulate(&poseidon2_fractions);
    let poseidon2_folds = collect_column_oracle_folds(
        &MidenAir::Poseidon2Permutation,
        &poseidon2_matrix,
        &poseidon2_periodic,
        &public_vals,
        &challenges,
    );
    assert_prover_matches_oracle(
        "Poseidon2Permutation",
        &poseidon2_aux,
        &poseidon2_folds,
        LiftedAir::<Felt, QuadFelt>::aux_width(&MidenAir::Poseidon2Permutation),
    );
}

#[test]
fn perm_link_rejects_swapped_controller_outputs() {
    let trace =
        build_trace_from_ops(vec![Operation::HPerm, Operation::HPerm], &[8, 7, 6, 5, 4, 3, 2, 1]);
    let (_, mut chip_matrix, poseidon2_matrix) = trace.main_trace().to_air_matrices();

    let output_rows: Vec<_> = (0..chip_matrix.height())
        .filter(|&row| {
            let chiplet = chiplet_row(&chip_matrix, row);
            let ctrl = chiplet.controller();
            chiplet.chiplet_selectors()[0] == Felt::ZERO
                && ctrl.s0 == Felt::ZERO
                && ctrl.s1 == Felt::ZERO
                && ctrl.s2 == Felt::ONE
        })
        .take(2)
        .collect();
    assert_eq!(output_rows.len(), 2, "expected two controller output rows");

    let ctrl_a = controller_row(&chip_matrix, output_rows[0]);
    let ctrl_b = controller_row(&chip_matrix, output_rows[1]);
    let state_a = ctrl_a.state;
    let state_b = ctrl_b.state;
    assert_ne!(state_a, state_b, "test needs two distinct permutation outputs");

    let perm_id_a = ctrl_a.perm_id;
    let perm_id_b = ctrl_b.perm_id;
    assert_ne!(perm_id_a, perm_id_b, "test needs two distinct permutation ids");

    let challenges = Challenges::<QuadFelt>::new(
        QuadFelt::new([Felt::new_unchecked(7), Felt::ZERO]),
        QuadFelt::new([Felt::new_unchecked(11), Felt::ZERO]),
        MIDEN_MAX_MESSAGE_WIDTH,
        BusId::COUNT,
    );

    let honest_fractions = perm_link_fractions(&chip_matrix, &poseidon2_matrix, &challenges);
    for msg in [
        HasherPermLinkMsg::Output { perm_id: perm_id_a, state: state_a },
        HasherPermLinkMsg::Output { perm_id: perm_id_b, state: state_b },
    ] {
        assert_eq!(
            net_multiplicity(&honest_fractions, msg.encode(&challenges)),
            Felt::ZERO,
            "honest controller output link is balanced"
        );
    }

    controller_row_mut(&mut chip_matrix, output_rows[0]).state = state_b;
    controller_row_mut(&mut chip_matrix, output_rows[1]).state = state_a;

    let swapped_fractions = perm_link_fractions(&chip_matrix, &poseidon2_matrix, &challenges);
    for msg in [
        HasherPermLinkMsg::Output { perm_id: perm_id_a, state: state_b },
        HasherPermLinkMsg::Output { perm_id: perm_id_b, state: state_a },
    ] {
        assert_eq!(
            net_multiplicity(&swapped_fractions, msg.encode(&challenges)),
            Felt::ONE,
            "swapped controller output leaves an unmatched perm-link addition"
        );
    }
}
