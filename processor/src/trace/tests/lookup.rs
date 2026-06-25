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
        CHIPLETS_MODE_COL, CHIPLETS_STREAM_MODE_COL,
        and8_lookup::{AND8_TABLE_ROWS, BYTE_LOOKUP_KIND_COUNT, NUM_AND8_LOOKUP_COLS},
        blakeg_compression::{
            BLAKEG_COMPRESSION_CYCLE_LEN, NUM_BLAKEG_COMPRESSION_COLS,
            air32::{F_COMPRESSION_MULTIPLICITY_COL, F_MODE_COL},
        },
    },
};
use miden_core::{
    Word,
    crypto::merkle::{MerkleStore, MerkleTree},
    field::{Field, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};

use super::{
    ExecutionTrace, Felt, build_trace_from_ops, build_trace_from_ops_with_inputs, rand_array,
};
use crate::operation::Operation;
use crate::{AdviceInputs, StackInputs};

const BLAKEG_NARROW_COLUMN_CAPACITY: usize = 2;
const BLAKEG_SINGLETON_COLUMN_CAPACITY: usize = 1;
const BLAKEG_NARROW_LOOKUP_COLUMNS: usize = 20;
const BLAKEG_SINGLETON_LOOKUP_COLUMNS: usize = 4;
const BLAKEG_LOOKUP_COLUMNS: usize = BLAKEG_NARROW_LOOKUP_COLUMNS + BLAKEG_SINGLETON_LOOKUP_COLUMNS;
const AEAD_STREAM_PAYLOAD_BASE_COL: usize = 2;
const AEAD_STREAM_MODE_COL: usize = CHIPLETS_STREAM_MODE_COL;
const AEAD_READ_LANE_BASE_OFFSET: usize = 3;
const AEAD_LOW_SECOND_SRC_PTR_OFFSET: usize = 2;
const CONTROLLER_S_CTRL_COL: usize = 0;
const CONTROLLER_BASE_COL: usize = 1;
const CONTROLLER_SELECTOR_COUNT: usize = 3;
const CONTROLLER_STATE_WIDTH: usize = 12;
const CONTROLLER_ROW_DATA_BASE_COL: usize =
    CONTROLLER_BASE_COL + CONTROLLER_SELECTOR_COUNT + CONTROLLER_STATE_WIDTH;
const CONTROLLER_S0_COL: usize = CONTROLLER_BASE_COL;
const CONTROLLER_S2_COL: usize = CONTROLLER_BASE_COL + 2;
const CONTROLLER_IS_START_COL: usize = CONTROLLER_ROW_DATA_BASE_COL + 2;
const CONTROLLER_MERKLE_OR_PADDING_COL: usize = CHIPLETS_MODE_COL;

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

fn aead_stream_trace() -> ExecutionTrace {
    // Stack layout: [K_CTR(4), counter, src_ptr, dst_ptr, remaining, tail(8)].
    build_trace_from_ops(
        vec![Operation::AeadStream],
        &[
            1, 2, 3, 4, // K_CTR
            0, // counter
            0, // src_ptr
            8, // dst_ptr
            1, // remaining
            0, 0, 0, 0, 0, 0, 0, 0, // tail
        ],
    )
}

fn mpverify_trace() -> ExecutionTrace {
    let leaves: Vec<Word> = (0..8).map(test_word).collect();
    let tree = MerkleTree::new(&leaves).expect("test Merkle tree should be valid");
    let store = MerkleStore::from(&tree);
    let leaf_idx = 5usize;
    let node = leaves[leaf_idx];
    let root = tree.root();
    let stack = [
        node[0],
        node[1],
        node[2],
        node[3],
        Felt::new_unchecked(tree.depth() as u64),
        Felt::new_unchecked(leaf_idx as u64),
        root[0],
        root[1],
        root[2],
        root[3],
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ];
    let advice_inputs = AdviceInputs::default().with_merkle_store(store);
    build_trace_from_ops_with_inputs(
        vec![Operation::MpVerify(Felt::ZERO)],
        StackInputs::new(&stack).expect("test stack inputs should be valid"),
        advice_inputs,
    )
}

fn test_word(value: usize) -> Word {
    [Felt::new_unchecked(value as u64), Felt::ZERO, Felt::ZERO, Felt::ZERO].into()
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
fn lookup_global_balance_closes_for_aead_stream() {
    let trace = aead_stream_trace();
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
        blakeg_matrix.height() % BLAKEG_COMPRESSION_CYCLE_LEN,
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
    assert_blakeg_air32_column_shape("row-shape test", &blakeg_fractions);

    for (row, column_counts) in
        blakeg_fractions.counts().chunks(blakeg_fractions.num_columns()).enumerate()
    {
        let cycle_row = row % BLAKEG_COMPRESSION_CYCLE_LEN;
        let actual: usize = column_counts.iter().sum();
        let row_start = row * NUM_BLAKEG_COMPRESSION_COLS;
        let is_aead = blakeg_matrix.values[row_start + F_MODE_COL] == Felt::ONE;
        let compression_multiplicity =
            blakeg_matrix.values[row_start + F_COMPRESSION_MULTIPLICITY_COL];
        let expected = expected_blakeg_air32_fraction_entry_range_at_cycle_row(
            cycle_row,
            is_aead,
            compression_multiplicity,
        );
        assert!(
            expected.contains(&actual),
            "BlakeG lookup count mismatch at row {row} cycle row {cycle_row}",
        );
    }

    let block_count = blakeg_matrix.height() / BLAKEG_COMPRESSION_CYCLE_LEN;
    let expected_blakeg_byte_lookup_total =
        block_count as u64 * BYTE_LOOKUP_REQUESTS_PER_BLAKEG_BLOCK;
    let mut actual_blakeg_byte_lookup_total = 0;
    for row in 0..AND8_TABLE_ROWS {
        let row_start = row * NUM_AND8_LOOKUP_COLS;
        for col in 0..BYTE_LOOKUP_KIND_COUNT {
            actual_blakeg_byte_lookup_total +=
                and8_matrix.values[row_start + col].as_canonical_u64();
        }
    }
    assert_eq!(
        actual_blakeg_byte_lookup_total, expected_blakeg_byte_lookup_total,
        "BlakeG byte-lookup multiplicities do not match BlakeG requests",
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

fn expected_blakeg_air32_narrow_interactions_at_cycle_row(cycle_row: usize) -> usize {
    match cycle_row {
        0 => 40,
        1..=27 => 36,
        28..=31 => 30,
        _ => unreachable!("cycle row must be in 0..{BLAKEG_COMPRESSION_CYCLE_LEN}"),
    }
}

fn expected_blakeg_air32_compression_singletons_at_cycle_row(cycle_row: usize) -> usize {
    match cycle_row {
        31 => 1,
        0..=30 => 0,
        _ => unreachable!("cycle row must be in 0..{BLAKEG_COMPRESSION_CYCLE_LEN}"),
    }
}

fn expected_blakeg_air32_fraction_entry_range_at_cycle_row(
    cycle_row: usize,
    is_aead: bool,
    compression_multiplicity: Felt,
) -> core::ops::RangeInclusive<usize> {
    match cycle_row {
        28..=31 if is_aead => {
            let expected = expected_blakeg_air32_narrow_interactions_at_cycle_row(cycle_row)
                + if cycle_row == 31 { 3 } else { 2 };
            expected..=expected
        },
        31 if compression_multiplicity != Felt::ZERO => 31..=31,
        _ => {
            let expected = expected_blakeg_air32_narrow_interactions_at_cycle_row(cycle_row);
            expected..=expected
        },
    }
}

#[test]
fn blakeg_air32_lookup_ledger_fits_narrow_slot_cap() {
    const SLOTS_PER_BATCH_COLUMN: usize = 2;
    const COMPRESSION_DENOMINATORS_PER_BLOCK: usize = 1133;

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
        assert_blakeg_air32_column_shape("lookup ledger", &blakeg_fractions);
    let narrow_slot_cap = narrow_batch_columns * SLOTS_PER_BATCH_COLUMN;
    let row_lookup_cap = narrow_slot_cap + BLAKEG_SINGLETON_LOOKUP_COLUMNS;

    let mut total = 0;
    for cycle_row in 0..BLAKEG_COMPRESSION_CYCLE_LEN {
        let narrow_pressure = expected_blakeg_air32_narrow_interactions_at_cycle_row(cycle_row);
        assert!(
            narrow_pressure <= narrow_slot_cap,
            "cycle row {cycle_row} has narrow lookup pressure {narrow_pressure}, above cap \
             {narrow_slot_cap}",
        );
        total +=
            narrow_pressure + expected_blakeg_air32_compression_singletons_at_cycle_row(cycle_row);
    }

    assert_eq!(total, COMPRESSION_DENOMINATORS_PER_BLOCK);
    assert!(
        total <= BLAKEG_COMPRESSION_CYCLE_LEN * row_lookup_cap,
        "lookup ledger must fit the fixed per-row lookup-column capacity",
    );
}

#[test]
fn lookup_balance_rejects_tampered_aead_output_pair_lane() {
    let trace = aead_stream_trace();
    let (core_matrix, mut chip_matrix, blakeg_matrix, and8_matrix) =
        trace.main_trace().to_air_matrices();

    let first_stream_row = aead_stream_rows(&chip_matrix)
        .into_iter()
        .next()
        .expect("AEAD stream trace should contain stream rows");
    mutate_chip_cell(
        &mut chip_matrix,
        first_stream_row,
        AEAD_STREAM_PAYLOAD_BASE_COL + AEAD_READ_LANE_BASE_OFFSET,
        Felt::ONE,
    );

    assert_global_lookup_balance_rejects(
        "tampered AEAD output pair lane",
        &trace,
        &core_matrix,
        &chip_matrix,
        &blakeg_matrix,
        &and8_matrix,
        "AeadBlakeGOutputPairMsg",
    );
}

#[test]
fn lookup_balance_rejects_tampered_aead_request_source_pointer() {
    let trace = aead_stream_trace();
    let (core_matrix, mut chip_matrix, blakeg_matrix, and8_matrix) =
        trace.main_trace().to_air_matrices();

    let stream_rows = aead_stream_rows(&chip_matrix);
    assert!(stream_rows.len() >= 3, "AEAD stream trace should contain low-second rows");
    let first_low_second_row = stream_rows[2];
    mutate_chip_cell(
        &mut chip_matrix,
        first_low_second_row,
        AEAD_STREAM_PAYLOAD_BASE_COL + AEAD_LOW_SECOND_SRC_PTR_OFFSET,
        Felt::ONE,
    );

    assert_global_lookup_balance_rejects(
        "tampered AEAD request source pointer",
        &trace,
        &core_matrix,
        &chip_matrix,
        &blakeg_matrix,
        &and8_matrix,
        "AeadStreamRequestMsg",
    );
}

#[test]
fn lookup_balance_rejects_tampered_merkle_start_flag() {
    let trace = mpverify_trace();
    let (core_matrix, mut chip_matrix, blakeg_matrix, and8_matrix) =
        trace.main_trace().to_air_matrices();

    let first_merkle_start = merkle_start_rows(&chip_matrix)
        .into_iter()
        .next()
        .expect("MPVERIFY trace should contain a Merkle start row");
    mutate_chip_cell(&mut chip_matrix, first_merkle_start, CONTROLLER_IS_START_COL, -Felt::ONE);

    assert_global_lookup_balance_rejects(
        "tampered Merkle start flag",
        &trace,
        &core_matrix,
        &chip_matrix,
        &blakeg_matrix,
        &and8_matrix,
        "HasherMerkleVerifyInit",
    );
}

fn assert_blakeg_air32_column_shape(
    label: &str,
    fractions: &LookupFractions<Felt, QuadFelt>,
) -> (usize, usize) {
    let shape = fractions.shape();

    assert_eq!(shape.len(), BLAKEG_LOOKUP_COLUMNS, "{label}: BlakeG lookup aux width drifted",);

    for (col, &count) in shape.iter().enumerate() {
        let expected = if col < BLAKEG_NARROW_LOOKUP_COLUMNS {
            BLAKEG_NARROW_COLUMN_CAPACITY
        } else {
            BLAKEG_SINGLETON_COLUMN_CAPACITY
        };
        assert_eq!(
            count, expected,
            "{label}: BlakeG lookup column {col} has shape {count}, expected {expected}",
        );
    }

    assert_eq!(
        fractions.num_columns(),
        BLAKEG_LOOKUP_COLUMNS,
        "{label}: BlakeG lookup aux width drifted",
    );

    (BLAKEG_NARROW_LOOKUP_COLUMNS, BLAKEG_SINGLETON_LOOKUP_COLUMNS)
}

fn assert_blakeg_air32_oracle_coverage(
    label: &str,
    blakeg_matrix: &RowMajorMatrix<Felt>,
    fractions: &LookupFractions<Felt, QuadFelt>,
) {
    assert_eq!(
        fractions.num_rows() % BLAKEG_COMPRESSION_CYCLE_LEN,
        0,
        "{label}: BlakeG trace height must be a whole number of compression blocks",
    );

    let (narrow_batch_columns, singleton_columns) =
        assert_blakeg_air32_column_shape(label, fractions);

    let mut seen_cycle_rows = [false; BLAKEG_COMPRESSION_CYCLE_LEN];
    let mut saw_narrow_only_row = false;
    let mut saw_full_narrow_pair = false;
    let mut saw_singleton_fraction = false;
    for (row, column_counts) in fractions.counts().chunks(fractions.num_columns()).enumerate() {
        let cycle_row = row % BLAKEG_COMPRESSION_CYCLE_LEN;
        seen_cycle_rows[cycle_row] = true;

        for (col, &count) in column_counts[..narrow_batch_columns].iter().enumerate() {
            assert!(
                count <= BLAKEG_NARROW_COLUMN_CAPACITY,
                "{label}: row {row} cycle row {cycle_row} narrow column {col} pushed {count} \
                 fractions, above batch-2 capacity",
            );
            saw_full_narrow_pair |= count == 2;
        }
        for (offset, &count) in column_counts[narrow_batch_columns..].iter().enumerate() {
            assert!(
                count <= BLAKEG_SINGLETON_COLUMN_CAPACITY,
                "{label}: row {row} cycle row {cycle_row} singleton column {} pushed {count} \
                 fractions, above singleton capacity",
                narrow_batch_columns + offset,
            );
            saw_singleton_fraction |= count == 1;
        }

        let singleton_total: usize = column_counts[narrow_batch_columns..].iter().sum();
        saw_narrow_only_row |= singleton_total == 0;

        let actual: usize = column_counts.iter().sum();
        let row_start = row * blakeg_matrix.width();
        let is_aead = blakeg_matrix.values[row_start + F_MODE_COL] == Felt::ONE;
        let compression_multiplicity =
            blakeg_matrix.values[row_start + F_COMPRESSION_MULTIPLICITY_COL];
        let expected = expected_blakeg_air32_fraction_entry_range_at_cycle_row(
            cycle_row,
            is_aead,
            compression_multiplicity,
        );
        assert!(
            expected.contains(&actual),
            "{label}: BlakeG lookup count mismatch at row {row} cycle row {cycle_row}",
        );
    }

    assert!(
        seen_cycle_rows.into_iter().all(|seen| seen),
        "{label}: oracle trace must exercise every BlakeG cycle row",
    );
    assert_eq!(singleton_columns, BLAKEG_SINGLETON_LOOKUP_COLUMNS);
    assert!(saw_narrow_only_row, "{label}: oracle trace must exercise narrow lookup rows");
    assert!(
        saw_full_narrow_pair && saw_singleton_fraction,
        "{label}: oracle trace must exercise full batch-2 pairs and singleton lookup columns",
    );
}

fn assert_global_lookup_balance(trace: &ExecutionTrace) {
    let (core_matrix, chip_matrix, blakeg_matrix, and8_matrix) =
        trace.main_trace().to_air_matrices();
    let residuals =
        global_lookup_residuals(trace, &core_matrix, &chip_matrix, &blakeg_matrix, &and8_matrix);

    assert!(
        residuals.is_empty(),
        "global LogUp balance did not close:\n{}",
        format_lookup_residuals(residuals)
    );
}

fn assert_global_lookup_balance_rejects(
    label: &str,
    trace: &ExecutionTrace,
    core_matrix: &RowMajorMatrix<Felt>,
    chip_matrix: &RowMajorMatrix<Felt>,
    blakeg_matrix: &RowMajorMatrix<Felt>,
    and8_matrix: &RowMajorMatrix<Felt>,
    expected_msg: &str,
) {
    let residuals =
        global_lookup_residuals(trace, core_matrix, chip_matrix, blakeg_matrix, and8_matrix);
    assert!(!residuals.is_empty(), "{label}: tampered trace unexpectedly balanced");

    let found_expected_msg = residuals
        .iter()
        .any(|(_, (_, lines))| lines.iter().any(|line| line.contains(expected_msg)));
    assert!(
        found_expected_msg,
        "{label}: expected residual containing {expected_msg}; got:\n{}",
        format_lookup_residuals(residuals),
    );
}

fn global_lookup_residuals(
    trace: &ExecutionTrace,
    core_matrix: &RowMajorMatrix<Felt>,
    chip_matrix: &RowMajorMatrix<Felt>,
    blakeg_matrix: &RowMajorMatrix<Felt>,
    and8_matrix: &RowMajorMatrix<Felt>,
) -> Vec<(QuadFelt, (Felt, Vec<String>))> {
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
    residuals
}

fn format_lookup_residuals(residuals: Vec<(QuadFelt, (Felt, Vec<String>))>) -> String {
    residuals
        .into_iter()
        .take(8)
        .map(|(denom, (net, lines))| format!("denom {denom:?} net {net:?}\n{}", lines.join("\n")))
        .collect::<Vec<_>>()
        .join("\n")
}

fn aead_stream_rows(chip_matrix: &RowMajorMatrix<Felt>) -> Vec<usize> {
    let width = chip_matrix.width();
    (0..chip_matrix.height())
        .filter(|&row| {
            let base = row * width;
            chip_matrix.values[base] == Felt::ZERO
                && chip_matrix.values[base + 1] == Felt::ZERO
                && chip_matrix.values[base + AEAD_STREAM_MODE_COL] == Felt::ONE
        })
        .collect()
}

fn merkle_start_rows(chip_matrix: &RowMajorMatrix<Felt>) -> Vec<usize> {
    let width = chip_matrix.width();
    (0..chip_matrix.height())
        .filter(|&row| {
            let base = row * width;
            chip_matrix.values[base + CONTROLLER_S_CTRL_COL] == Felt::ONE
                && chip_matrix.values[base + CONTROLLER_MERKLE_OR_PADDING_COL] == Felt::ONE
                && chip_matrix.values[base + CONTROLLER_S0_COL] == Felt::ONE
                && chip_matrix.values[base + CONTROLLER_S2_COL] == Felt::ONE
                && chip_matrix.values[base + CONTROLLER_IS_START_COL] == Felt::ONE
        })
        .collect()
}

fn mutate_chip_cell(chip_matrix: &mut RowMajorMatrix<Felt>, row: usize, col: usize, delta: Felt) {
    let width = chip_matrix.width();
    chip_matrix.values[row * width + col] += delta;
}

#[test]
fn build_lookup_fractions_matches_constraint_path_oracle() {
    let trace = build_trace_from_ops(tiny_span(), &[]);
    assert_lookup_fractions_match_constraint_path_oracle("tiny span", &trace);
}

#[test]
fn build_lookup_fractions_matches_constraint_path_oracle_for_aead_stream() {
    let trace = aead_stream_trace();
    assert_lookup_fractions_match_constraint_path_oracle("AEAD stream", &trace);
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
    assert_blakeg_air32_oracle_coverage(label, &blakeg_matrix, &blakeg_fractions);
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
        "no byte-pair table fractions collected - BlakeG compression must drive byte lookups",
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
