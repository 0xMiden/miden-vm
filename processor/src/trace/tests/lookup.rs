//! End-to-end collection-phase tests for the prover-side LogUp pipeline.
//!
//! Runs real processor traces through `build_trace_from_ops`, materialises the resulting main
//! traces as [`RowMajorMatrix<Felt>`] values, and pipes them through [`build_lookup_fractions`] +
//! [`accumulate`]. The test validates:
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

use alloc::{format, string::String, vec::Vec};
use std::collections::HashMap;

use miden_air::{
    BaseAir, LiftedAir, MidenAir,
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
    lookup::{
        Challenges, LookupFractions, accumulate, build_lookup_fractions,
        debug::collect_column_oracle_folds,
    },
    trace::{
        and8_lookup::{AND8_TABLE_ROWS, NUM_AND8_LOOKUP_COLS},
        chiplets::hasher::HASH_CYCLE_LEN,
    },
};
use miden_core::{
    field::{Field, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};

use super::{ExecutionTrace, Felt, build_trace_from_ops, rand_array};
use crate::operation::Operation;

/// Pad/Add/Mul/Drop inside a span - same kind of ops the decoder/stack tests use, with
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

    // Col 0 (accumulator): aux[r+1][0] - aux[r][0] == sum_col per_row_value[col].
    // Cols 1+ (fraction): aux[r][col] == V/U per-row value.
    for (r, row_folds) in oracle_folds.iter().enumerate() {
        assert_eq!(row_folds.len(), aux_width, "{label} row {r}: fold width mismatch");
        let per_row_values: Vec<QuadFelt> = row_folds
            .iter()
            .enumerate()
            .map(|(col, &(v_col, u_col))| {
                let u_inv = u_col.try_inverse().unwrap_or_else(|| {
                    panic!(
                        "{label} row {r} col {col}: oracle U_col is zero - bus has a \
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
fn lookup_global_balance_closes_for_tiny_span() {
    let trace = build_trace_from_ops(tiny_span(), &[]);
    assert_global_lookup_balance(&trace);
}

#[test]
fn lookup_global_balance_closes_for_bcompress() {
    let trace = build_trace_from_ops(vec![Operation::BCompress], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_global_lookup_balance(&trace);
}

#[test]
fn lookup_global_balance_closes_for_fibonacci_span() {
    let mut ops = Vec::new();
    for _ in 0..149 {
        ops.extend([Operation::Swap, Operation::Dup1, Operation::Add]);
    }
    let trace = build_trace_from_ops(ops, &[0, 1]);
    assert_global_lookup_balance(&trace);
}

#[test]
fn blakeg_lookup_row_shape_matches_expected_interactions() {
    const BYTE_LOOKUP_REQUESTS_PER_BLAKEG_BLOCK: u64 = 964;

    let trace = build_trace_from_ops(tiny_span(), &[]);
    let (_, _, blakeg_matrix, and8_matrix) = trace.main_trace().to_air_matrices();

    assert_eq!(
        blakeg_matrix.height() % HASH_CYCLE_LEN,
        0,
        "BlakeG trace height must be a whole number of compression blocks",
    );

    let raw = rand_array::<Felt, 4>();
    let alpha = QuadFelt::new([raw[0], raw[1]]);
    let beta = QuadFelt::new([raw[2], raw[3]]);
    let challenges =
        Challenges::<QuadFelt>::new(alpha, beta, MIDEN_MAX_MESSAGE_WIDTH, BusId::COUNT);
    let blakeg_periodic =
        LiftedAir::<Felt, QuadFelt>::periodic_columns(&MidenAir::BLAKEG_COMPRESSION);
    let blakeg_fractions = build_lookup_fractions(
        &MidenAir::BLAKEG_COMPRESSION,
        &blakeg_matrix,
        None,
        &blakeg_periodic,
        &challenges,
    );

    assert_eq!(blakeg_fractions.num_rows(), blakeg_matrix.height());
    assert_blakeg_degree3_column_shape("row-shape test", &blakeg_fractions);

    for (row, column_counts) in
        blakeg_fractions.counts().chunks(blakeg_fractions.num_columns()).enumerate()
    {
        let cycle_row = row % HASH_CYCLE_LEN;
        let actual: usize = column_counts.iter().sum();
        let expected = expected_blakeg_degree3_fraction_entry_range_at_cycle_row(cycle_row);
        assert!(
            expected.contains(&actual),
            "BlakeG lookup count mismatch at row {row} cycle row {cycle_row}",
        );
    }

    let block_count = blakeg_matrix.height() / HASH_CYCLE_LEN;
    let expected_byte_lookup_total = block_count as u64 * BYTE_LOOKUP_REQUESTS_PER_BLAKEG_BLOCK;
    let actual_byte_lookup_total: u64 =
        and8_matrix.values.iter().map(|value| value.as_canonical_u64()).sum();
    assert_eq!(
        actual_byte_lookup_total, expected_byte_lookup_total,
        "byte-pair dynamic multiplicities do not match BlakeG byte lookup requests",
    );

    let padding_start = AND8_TABLE_ROWS * NUM_AND8_LOOKUP_COLS;
    let padding_byte_lookup_total: u64 = and8_matrix.values[padding_start..]
        .iter()
        .map(|value| value.as_canonical_u64())
        .sum();
    assert_eq!(
        padding_byte_lookup_total, 0,
        "byte-pair multiplicities must live only on real byte-pair table rows",
    );
}

fn expected_blakeg_degree3_routed_interactions_at_cycle_row(cycle_row: usize) -> usize {
    match cycle_row {
        // Row 0 sends the first message words, emits A/C byte-pair lookups, and routes HIN
        // pairs 0/1 through the singleton annex.
        0 => 22,
        // The first B row receives HIN pairs 2/3 in otherwise idle narrow slots.
        1 => 18,
        // Non-first A/C rows send message words and emit byte-pair lookups.
        2..=54 if cycle_row % 2 == 0 => 20,
        // B/D rows use one fused byte-pair lookup per rotated byte.
        3..=55 if cycle_row % 2 == 1 => 16,
        // Footer rows use byte-pair folds for the compression output.
        56..=59 => 18,
        // The two message rows receive the full message schedule and range-check the
        // non-routed message limbs. M1 routes four more limb checks to I than M0.
        // The canonicality rem-limb checks have been replaced by an inverse zero-test.
        60 => 20,
        61 => 16,
        // Interface row: four paired input-word sends, twelve routed message-row range checks,
        // and one compression-link slot.
        62 => 18,
        // Output row: no routed lookup traffic.
        63 => 0,
        _ => unreachable!("cycle row must be in 0..{HASH_CYCLE_LEN}"),
    }
}

fn expected_blakeg_degree3_fraction_entry_range_at_cycle_row(
    cycle_row: usize,
) -> core::ops::RangeInclusive<usize> {
    match cycle_row {
        // Padding blocks skip the interface links because their multiplicity is zero.
        62 => 16..=18,
        _ => {
            let expected = expected_blakeg_degree3_routed_interactions_at_cycle_row(cycle_row);
            expected..=expected
        },
    }
}

fn blakeg_degree3_annex_interactions_at_cycle_row(cycle_row: usize) -> usize {
    match cycle_row {
        0 | 60 | 61 | 62 => 2,
        1..=59 | 63 => 0,
        _ => unreachable!("cycle row must be in 0..{HASH_CYCLE_LEN}"),
    }
}

#[test]
fn blakeg_degree3_routing_ledger_fits_narrow_slot_cap() {
    const SLOTS_PER_BATCH_COLUMN: usize = 2;
    const CURRENT_DENOMINATORS_PER_BLOCK: usize = 1138;

    let trace = build_trace_from_ops(tiny_span(), &[]);
    let (_, _, blakeg_matrix, _) = trace.main_trace().to_air_matrices();
    let raw = rand_array::<Felt, 4>();
    let alpha = QuadFelt::new([raw[0], raw[1]]);
    let beta = QuadFelt::new([raw[2], raw[3]]);
    let challenges =
        Challenges::<QuadFelt>::new(alpha, beta, MIDEN_MAX_MESSAGE_WIDTH, BusId::COUNT);
    let blakeg_periodic =
        LiftedAir::<Felt, QuadFelt>::periodic_columns(&MidenAir::BLAKEG_COMPRESSION);
    let blakeg_fractions = build_lookup_fractions(
        &MidenAir::BLAKEG_COMPRESSION,
        &blakeg_matrix,
        None,
        &blakeg_periodic,
        &challenges,
    );
    let (narrow_batch_columns, _) =
        assert_blakeg_degree3_column_shape("routing ledger", &blakeg_fractions);
    let narrow_slot_cap = narrow_batch_columns * SLOTS_PER_BATCH_COLUMN;

    let mut total = 0;
    for cycle_row in 0..HASH_CYCLE_LEN {
        let pressure = expected_blakeg_degree3_routed_interactions_at_cycle_row(cycle_row);
        let narrow_pressure = pressure - blakeg_degree3_annex_interactions_at_cycle_row(cycle_row);
        assert!(
            narrow_pressure <= narrow_slot_cap,
            "cycle row {cycle_row} has narrow routed pressure {narrow_pressure}, above cap \
             {narrow_slot_cap}",
        );
        total += pressure;
    }

    assert_eq!(
        total, CURRENT_DENOMINATORS_PER_BLOCK,
        "routing should move lookup pressure, not change the denominator count",
    );
    assert!(
        total <= HASH_CYCLE_LEN * narrow_slot_cap,
        "routed ledger must fit the narrow batch-2 slot cap",
    );
}

fn assert_blakeg_degree3_column_shape(
    label: &str,
    fractions: &LookupFractions<Felt, QuadFelt>,
) -> (usize, usize) {
    let shape = fractions.shape();
    let singleton_annex_columns = shape.iter().rev().take_while(|&&count| count == 1).count();
    let narrow_batch_columns = shape
        .len()
        .checked_sub(singleton_annex_columns)
        .expect("annex count cannot exceed lookup width");

    assert!(
        narrow_batch_columns > 0,
        "{label}: BlakeG lookup shape must include narrow batch columns",
    );
    assert!(
        singleton_annex_columns > 0,
        "{label}: BlakeG lookup shape must include singleton annex columns",
    );

    for (col, &count) in shape.iter().enumerate() {
        let expected = if col < narrow_batch_columns { 2 } else { 1 };
        assert_eq!(
            count, expected,
            "{label}: BlakeG lookup column {col} has shape {count}, expected {expected}",
        );
    }

    assert_eq!(
        fractions.num_columns(),
        narrow_batch_columns + singleton_annex_columns,
        "{label}: BlakeG lookup aux width drifted",
    );

    (narrow_batch_columns, singleton_annex_columns)
}

fn assert_blakeg_degree3_oracle_coverage(label: &str, fractions: &LookupFractions<Felt, QuadFelt>) {
    assert_eq!(
        fractions.num_rows() % HASH_CYCLE_LEN,
        0,
        "{label}: BlakeG trace height must be a whole number of compression blocks",
    );

    let (narrow_batch_columns, singleton_annex_columns) =
        assert_blakeg_degree3_column_shape(label, fractions);

    let mut seen_cycle_rows = [false; HASH_CYCLE_LEN];
    let mut saw_annex_row = false;
    let mut saw_narrow_only_row = false;
    let mut saw_full_narrow_pair = false;
    let mut saw_single_narrow_slot = false;
    for (row, column_counts) in fractions.counts().chunks(fractions.num_columns()).enumerate() {
        let cycle_row = row % HASH_CYCLE_LEN;
        seen_cycle_rows[cycle_row] = true;

        for (col, &count) in column_counts[..narrow_batch_columns].iter().enumerate() {
            assert!(
                count <= 2,
                "{label}: row {row} cycle row {cycle_row} narrow column {col} pushed {count} \
                 fractions, above batch-2 capacity",
            );
            saw_full_narrow_pair |= count == 2;
            saw_single_narrow_slot |= count == 1;
        }

        let annex_counts = &column_counts[narrow_batch_columns..];
        assert_eq!(
            annex_counts.len(),
            singleton_annex_columns,
            "{label}: row {row} cycle row {cycle_row} annex width mismatch",
        );
        assert!(
            annex_counts.iter().all(|&count| count <= 1),
            "{label}: row {row} cycle row {cycle_row} singleton annex count exceeded capacity",
        );
        let annex_total: usize = annex_counts.iter().sum();
        match cycle_row {
            0 | 60 | 61 => assert_eq!(
                annex_total, singleton_annex_columns,
                "{label}: row {row} cycle row {cycle_row} should use both singleton annex columns",
            ),
            62 => assert!(
                annex_total <= singleton_annex_columns,
                "{label}: row {row} cycle row {cycle_row} interface annex count exceeded capacity",
            ),
            _ => assert_eq!(
                annex_total, 0,
                "{label}: row {row} cycle row {cycle_row} should not use singleton annex columns",
            ),
        }
        saw_annex_row |= annex_total > 0;
        saw_narrow_only_row |= annex_total == 0;

        let actual: usize = column_counts.iter().sum();
        let expected = expected_blakeg_degree3_fraction_entry_range_at_cycle_row(cycle_row);
        assert!(
            expected.contains(&actual),
            "{label}: BlakeG lookup count mismatch at row {row} cycle row {cycle_row}",
        );
    }

    assert!(
        seen_cycle_rows.into_iter().all(|seen| seen),
        "{label}: oracle trace must exercise every BlakeG cycle row",
    );
    assert!(
        saw_annex_row && saw_narrow_only_row,
        "{label}: oracle trace must exercise both annex-active and narrow-only rows",
    );
    assert!(
        saw_full_narrow_pair && saw_single_narrow_slot,
        "{label}: oracle trace must exercise both full batch-2 pairs and single-slot fallbacks",
    );
}

fn assert_global_lookup_balance(trace: &ExecutionTrace) {
    let (core_matrix, chip_matrix, blakeg_matrix, and8_matrix) =
        trace.main_trace().to_air_matrices();
    let (public_values, kernel_felts) = trace.public_inputs().to_air_inputs();

    let raw = rand_array::<Felt, 4>();
    let alpha = QuadFelt::new([raw[0], raw[1]]);
    let beta = QuadFelt::new([raw[2], raw[3]]);
    let challenges =
        Challenges::<QuadFelt>::new(alpha, beta, MIDEN_MAX_MESSAGE_WIDTH, BusId::COUNT);

    let chip_periodic = LiftedAir::<Felt, QuadFelt>::periodic_columns(&MidenAir::CHIPLETS);
    let blakeg_periodic =
        LiftedAir::<Felt, QuadFelt>::periodic_columns(&MidenAir::BLAKEG_COMPRESSION);

    let reports = [
        (
            "Core",
            miden_air::lookup::debug::check_trace_balance(
                &MidenAir::CORE,
                &core_matrix,
                &[],
                &public_values,
                &[],
                &challenges,
            ),
        ),
        (
            "Chiplets",
            miden_air::lookup::debug::check_trace_balance(
                &MidenAir::CHIPLETS,
                &chip_matrix,
                &chip_periodic,
                &public_values,
                &[&kernel_felts],
                &challenges,
            ),
        ),
        (
            "BlakeGCompression",
            miden_air::lookup::debug::check_trace_balance(
                &MidenAir::BLAKEG_COMPRESSION,
                &blakeg_matrix,
                &blakeg_periodic,
                &public_values,
                &[],
                &challenges,
            ),
        ),
        (
            "And8Lookup",
            miden_air::lookup::debug::check_trace_balance(
                &MidenAir::AND8_LOOKUP,
                &and8_matrix,
                &[],
                &public_values,
                &[],
                &challenges,
            ),
        ),
    ];

    let mut totals: HashMap<QuadFelt, (Felt, Vec<String>)> = HashMap::new();
    for (air_name, report) in reports {
        for unmatched in report.unmatched {
            let entry = totals.entry(unmatched.denom).or_insert_with(|| (Felt::ZERO, Vec::new()));
            entry.0 += unmatched.net_multiplicity;
            entry.1.push(format!("{air_name}: net {:?}", unmatched.net_multiplicity));
            for contribution in unmatched.contributions.iter().take(3) {
                entry.1.push(format!(
                    "  row={} col={} group={} mult={:?} msg={}",
                    contribution.row,
                    contribution.column_idx,
                    contribution.group_idx,
                    contribution.multiplicity,
                    contribution.msg_repr
                ));
            }
        }
    }

    let mut residuals: Vec<_> =
        totals.into_iter().filter(|(_, (net, _))| *net != Felt::ZERO).collect();
    residuals.sort_by_key(|(denom, _)| *denom);

    assert!(
        residuals.is_empty(),
        "global LogUp balance did not close:\n{}",
        residuals
            .into_iter()
            .take(8)
            .map(|(denom, (net, lines))| format!(
                "denom {denom:?} net {net:?}\n{}",
                lines.join("\n")
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn build_lookup_fractions_matches_constraint_path_oracle() {
    let trace = build_trace_from_ops(tiny_span(), &[]);
    assert_lookup_fractions_match_constraint_path_oracle("tiny span", &trace);
}

fn assert_lookup_fractions_match_constraint_path_oracle(label: &str, trace: &ExecutionTrace) {
    let (core_matrix, chip_matrix, blakeg_matrix, and8_matrix) =
        trace.main_trace().to_air_matrices();
    let public_vals = trace.to_public_values();
    // Core has no periodic columns.
    let chip_periodic = LiftedAir::<Felt, QuadFelt>::periodic_columns(&MidenAir::CHIPLETS);
    let blakeg_periodic =
        LiftedAir::<Felt, QuadFelt>::periodic_columns(&MidenAir::BLAKEG_COMPRESSION);
    let and8_preprocessed = MidenAir::AND8_LOOKUP
        .preprocessed_trace()
        .expect("byte-pair lookup AIR declares a preprocessed table");

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
        "no Core fractions collected - trace is degenerate or emitters are broken",
    );
    let core_aux = accumulate(&core_fractions);
    let core_folds =
        collect_column_oracle_folds(&MidenAir::CORE, &core_matrix, &[], &public_vals, &challenges);
    assert_prover_matches_oracle(
        &format!("{label} Core"),
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
        "no Chiplets fractions collected - trace is degenerate or emitters are broken",
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
        &format!("{label} Chiplets"),
        &chip_aux,
        &chip_folds,
        LiftedAir::<Felt, QuadFelt>::aux_width(&MidenAir::CHIPLETS),
    );

    // --- BlakeG compression ---
    let blakeg_fractions = build_lookup_fractions(
        &MidenAir::BLAKEG_COMPRESSION,
        &blakeg_matrix,
        None,
        &blakeg_periodic,
        &challenges,
    );
    assert!(
        !blakeg_fractions.fractions().is_empty(),
        "no BlakeG-compression fractions collected - trace is degenerate or emitters are broken",
    );
    assert_blakeg_degree3_oracle_coverage(label, &blakeg_fractions);
    let blakeg_aux = accumulate(&blakeg_fractions);
    let blakeg_folds = collect_column_oracle_folds(
        &MidenAir::BLAKEG_COMPRESSION,
        &blakeg_matrix,
        &blakeg_periodic,
        &public_vals,
        &challenges,
    );
    assert_prover_matches_oracle(
        &format!("{label} BlakeGCompression"),
        &blakeg_aux,
        &blakeg_folds,
        LiftedAir::<Felt, QuadFelt>::aux_width(&MidenAir::BLAKEG_COMPRESSION),
    );

    // --- Byte-pair lookup table ---
    let and8_fractions = build_lookup_fractions(
        &MidenAir::AND8_LOOKUP,
        &and8_matrix,
        Some(&and8_preprocessed),
        &[],
        &challenges,
    );
    assert!(
        !and8_fractions.fractions().is_empty(),
        "no byte-pair table fractions collected - BlakeG compression should drive byte lookups",
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
        &format!("{label} And8Lookup"),
        &and8_aux,
        &and8_folds,
        LiftedAir::<Felt, QuadFelt>::aux_width(&MidenAir::AND8_LOOKUP),
    );
}
