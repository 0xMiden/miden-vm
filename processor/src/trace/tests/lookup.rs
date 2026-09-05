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
//! 4. **Constraint agreement**: the trace and its prover-built auxiliary columns satisfy the AIR.

use alloc::{boxed::Box, vec::Vec};

use miden_air::{
    BaseAir, MidenAir, MidenMultiAir, ProverStatement, StarkConfig, Statement, config, debug,
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
    lookup::{Challenges, LookupFractions, accumulate, build_lookup_fractions},
    trace::{
        CHIPLETS_MODE_COL, CHIPLETS_STREAM_MODE_COL,
        and8_lookup::{AND8_TABLE_ROWS, BYTE_LOOKUP_KIND_COUNT, NUM_AND8_LOOKUP_COLS},
        eidos_compression::{
            EIDOS_COMPRESSION_CYCLE_LEN, F_COMPRESSION_MULTIPLICITY_COL, F_MODE_COL,
            NUM_EIDOS_COMPRESSION_COLS,
        },
    },
};
use miden_core::{
    Word,
    crypto::merkle::{MerkleStore, MerkleTree},
    field::QuadFelt,
    utils::{Matrix, RowMajorMatrix},
};

use super::{Felt, VmTrace, build_trace_from_ops, build_trace_from_ops_with_inputs, rand_array};
use crate::{AdviceInputs, StackInputs, operation::Operation};

const EIDOS_COMPRESSION_NARROW_COLUMN_CAPACITY: usize = 2;
const EIDOS_COMPRESSION_NARROW_LOOKUP_COLUMNS: usize = 18;
const EIDOS_COMPRESSION_FOOTER_LOOKUP_COLUMN_SHAPE: [usize; 2] = [2, 2];
const EIDOS_COMPRESSION_LOOKUP_COLUMNS: usize =
    EIDOS_COMPRESSION_NARROW_LOOKUP_COLUMNS + EIDOS_COMPRESSION_FOOTER_LOOKUP_COLUMN_SHAPE.len();
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
static PANIC_HOOK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Pad/Add/Mul/Drop inside a span — same kind of ops the decoder/stack tests use, with
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

fn aead_stream_trace() -> VmTrace {
    // Stack layout: [K_CTR(4), counter, src_ptr, dst_ptr, remaining, tail(8)].
    build_trace_from_ops(
        vec![Operation::CryptoStream],
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

fn mixed_bitwise_aead_stream_trace() -> VmTrace {
    // The first four operations leave the initial stack unchanged while recording one ordinary
    // bitwise row before the AEAD stream operation in execution order.
    build_trace_from_ops(
        vec![
            Operation::Pad,
            Operation::Pad,
            Operation::U32and,
            Operation::Drop,
            Operation::CryptoStream,
        ],
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

fn mpverify_trace() -> VmTrace {
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

#[test]
fn lookup_constraints_close_for_tiny_span() {
    let trace = build_trace_from_ops(tiny_span(), &[]);
    trace.check_constraints();
}

#[test]
fn lookup_constraints_close_for_compress() {
    let trace = build_trace_from_ops(vec![Operation::Compress], &[1, 2, 3, 4, 5, 6, 7, 8]);
    trace.check_constraints();
}

#[test]
fn lookup_constraints_close_for_aead_stream() {
    let trace = aead_stream_trace();
    trace.check_constraints();
}

#[test]
fn lookup_constraints_close_for_mixed_bitwise_aead_stream() {
    let trace = mixed_bitwise_aead_stream_trace();
    trace.check_constraints();
}

#[test]
fn lookup_constraints_close_for_fibonacci_span() {
    let mut ops = Vec::new();
    for _ in 0..149 {
        ops.extend([Operation::Swap, Operation::Dup1, Operation::Add]);
    }
    let trace = build_trace_from_ops(ops, &[0, 1]);
    trace.check_constraints();
}

#[test]
fn eidos_compression_lookup_row_shape_matches_expected_interactions() {
    const BYTE_LOOKUP_REQUESTS_PER_EIDOS_COMPRESSION_BLOCK: u64 = 964;

    let trace = build_trace_from_ops(tiny_span(), &[]);
    let (_, _, eidos_compression_matrix, and8_matrix) = trace.main_trace().clone_air_matrices();

    assert_eq!(
        eidos_compression_matrix.height() % EIDOS_COMPRESSION_CYCLE_LEN,
        0,
        "Eidos compression trace height must be a whole number of compression blocks",
    );

    let raw = rand_array::<Felt, 4>();
    let alpha = QuadFelt::new([raw[0], raw[1]]);
    let beta = QuadFelt::new([raw[2], raw[3]]);
    let challenges =
        Challenges::<QuadFelt>::new(alpha, beta, MIDEN_MAX_MESSAGE_WIDTH, BusId::COUNT);
    let eidos_compression_periodic =
        BaseAir::<Felt>::periodic_columns(&MidenAir::EIDOS_COMPRESSION);
    let eidos_compression_fractions = build_lookup_fractions(
        &MidenAir::EIDOS_COMPRESSION,
        &eidos_compression_matrix,
        None,
        &eidos_compression_periodic,
        &challenges,
    );

    assert_eq!(eidos_compression_fractions.num_rows(), eidos_compression_matrix.height());
    assert_eidos_compression_column_shape("row-shape test", &eidos_compression_fractions);

    for (row, column_counts) in eidos_compression_fractions
        .counts()
        .chunks(eidos_compression_fractions.num_columns())
        .enumerate()
    {
        let cycle_row = row % EIDOS_COMPRESSION_CYCLE_LEN;
        let actual: usize = column_counts.iter().sum();
        let row_start = row * NUM_EIDOS_COMPRESSION_COLS;
        let is_aead = eidos_compression_matrix.values[row_start + F_MODE_COL] == Felt::ONE;
        let compression_multiplicity =
            eidos_compression_matrix.values[row_start + F_COMPRESSION_MULTIPLICITY_COL];
        let expected = expected_eidos_compression_fraction_entry_range_at_cycle_row(
            cycle_row,
            is_aead,
            compression_multiplicity,
        );
        assert!(
            expected.contains(&actual),
            "EidosCompression lookup count mismatch at row {row} cycle row {cycle_row}",
        );
    }

    let block_count = eidos_compression_matrix.height() / EIDOS_COMPRESSION_CYCLE_LEN;
    let expected_eidos_compression_byte_lookup_total =
        block_count as u64 * BYTE_LOOKUP_REQUESTS_PER_EIDOS_COMPRESSION_BLOCK;
    let mut actual_eidos_compression_byte_lookup_total = 0;
    for row in 0..AND8_TABLE_ROWS {
        let row_start = row * NUM_AND8_LOOKUP_COLS;
        for col in 0..BYTE_LOOKUP_KIND_COUNT {
            actual_eidos_compression_byte_lookup_total +=
                and8_matrix.values[row_start + col].as_canonical_u64();
        }
    }
    assert_eq!(
        actual_eidos_compression_byte_lookup_total, expected_eidos_compression_byte_lookup_total,
        "EidosCompression byte-lookup multiplicities do not match EidosCompression requests",
    );

    let padding_start = AND8_TABLE_ROWS * NUM_AND8_LOOKUP_COLS;
    let padding_byte_lookup_total: u64 =
        and8_matrix.values[padding_start..].iter().map(Felt::as_canonical_u64).sum();
    assert_eq!(
        padding_byte_lookup_total, 0,
        "byte-pair multiplicities must live only on real byte-pair table rows",
    );
}

fn expected_eidos_compression_narrow_interactions_at_cycle_row(cycle_row: usize) -> usize {
    match cycle_row {
        0..=27 => 36,
        28..=31 => 29,
        _ => unreachable!("cycle row must be in 0..{EIDOS_COMPRESSION_CYCLE_LEN}"),
    }
}

fn expected_eidos_compression_footer_interactions_at_cycle_row(cycle_row: usize) -> usize {
    match cycle_row {
        0 => 1,
        31 => 2,
        1..=30 => 0,
        _ => unreachable!("cycle row must be in 0..{EIDOS_COMPRESSION_CYCLE_LEN}"),
    }
}

fn expected_eidos_compression_fraction_entry_range_at_cycle_row(
    cycle_row: usize,
    is_aead: bool,
    compression_multiplicity: Felt,
) -> core::ops::RangeInclusive<usize> {
    match cycle_row {
        0 => 37..=37,
        28..=31 if is_aead => {
            let expected = expected_eidos_compression_narrow_interactions_at_cycle_row(cycle_row)
                + if cycle_row == 31 { 4 } else { 2 };
            expected..=expected
        },
        31 if compression_multiplicity != Felt::ZERO => 31..=31,
        31 => 30..=30,
        _ => {
            let expected = expected_eidos_compression_narrow_interactions_at_cycle_row(cycle_row);
            expected..=expected
        },
    }
}

#[test]
fn eidos_compression_lookup_ledger_fits_narrow_slot_cap() {
    const SLOTS_PER_BATCH_COLUMN: usize = 2;
    const COMPRESSION_DENOMINATORS_PER_BLOCK: usize = 1127;

    let trace = build_trace_from_ops(tiny_span(), &[]);
    let (_, _, eidos_compression_matrix, _) = trace.main_trace().clone_air_matrices();
    let raw = rand_array::<Felt, 4>();
    let alpha = QuadFelt::new([raw[0], raw[1]]);
    let beta = QuadFelt::new([raw[2], raw[3]]);
    let challenges =
        Challenges::<QuadFelt>::new(alpha, beta, MIDEN_MAX_MESSAGE_WIDTH, BusId::COUNT);
    let eidos_compression_periodic =
        BaseAir::<Felt>::periodic_columns(&MidenAir::EIDOS_COMPRESSION);
    let eidos_compression_fractions = build_lookup_fractions(
        &MidenAir::EIDOS_COMPRESSION,
        &eidos_compression_matrix,
        None,
        &eidos_compression_periodic,
        &challenges,
    );
    let (narrow_batch_columns, _) =
        assert_eidos_compression_column_shape("lookup ledger", &eidos_compression_fractions);
    let narrow_slot_cap = narrow_batch_columns * SLOTS_PER_BATCH_COLUMN;
    let row_lookup_cap =
        narrow_slot_cap + EIDOS_COMPRESSION_FOOTER_LOOKUP_COLUMN_SHAPE.iter().sum::<usize>();

    let mut total = 0;
    for cycle_row in 0..EIDOS_COMPRESSION_CYCLE_LEN {
        let narrow_pressure =
            expected_eidos_compression_narrow_interactions_at_cycle_row(cycle_row);
        assert!(
            narrow_pressure <= narrow_slot_cap,
            "cycle row {cycle_row} has narrow lookup pressure {narrow_pressure}, above cap \
             {narrow_slot_cap}",
        );
        total += narrow_pressure
            + expected_eidos_compression_footer_interactions_at_cycle_row(cycle_row);
    }

    assert_eq!(total, COMPRESSION_DENOMINATORS_PER_BLOCK);
    assert!(
        total <= EIDOS_COMPRESSION_CYCLE_LEN * row_lookup_cap,
        "lookup ledger must fit the fixed per-row lookup-column capacity",
    );
}

#[test]
fn lookup_constraints_reject_tampered_aead_output_pair_lane() {
    let trace = aead_stream_trace();
    let (core_matrix, mut chip_matrix, eidos_compression_matrix, and8_matrix) =
        trace.main_trace().clone_air_matrices();

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

    assert_trace_constraints_reject(
        &trace,
        core_matrix,
        chip_matrix,
        eidos_compression_matrix,
        and8_matrix,
    );
}

#[test]
fn lookup_constraints_reject_tampered_aead_request_source_pointer() {
    let trace = aead_stream_trace();
    let (core_matrix, mut chip_matrix, eidos_compression_matrix, and8_matrix) =
        trace.main_trace().clone_air_matrices();

    let stream_rows = aead_stream_rows(&chip_matrix);
    assert!(stream_rows.len() >= 3, "AEAD stream trace should contain low-second rows");
    let first_low_second_row = stream_rows[2];
    mutate_chip_cell(
        &mut chip_matrix,
        first_low_second_row,
        AEAD_STREAM_PAYLOAD_BASE_COL + AEAD_LOW_SECOND_SRC_PTR_OFFSET,
        Felt::ONE,
    );

    assert_trace_constraints_reject(
        &trace,
        core_matrix,
        chip_matrix,
        eidos_compression_matrix,
        and8_matrix,
    );
}

#[test]
fn lookup_constraints_reject_tampered_merkle_start_flag() {
    let trace = mpverify_trace();
    let (core_matrix, mut chip_matrix, eidos_compression_matrix, and8_matrix) =
        trace.main_trace().clone_air_matrices();

    let first_merkle_start = merkle_start_rows(&chip_matrix)
        .into_iter()
        .next()
        .expect("MPVERIFY trace should contain a Merkle start row");
    mutate_chip_cell(&mut chip_matrix, first_merkle_start, CONTROLLER_IS_START_COL, -Felt::ONE);

    assert_trace_constraints_reject(
        &trace,
        core_matrix,
        chip_matrix,
        eidos_compression_matrix,
        and8_matrix,
    );
}

fn assert_eidos_compression_column_shape(
    label: &str,
    fractions: &LookupFractions<Felt, QuadFelt>,
) -> (usize, usize) {
    let shape = fractions.shape();

    assert_eq!(
        shape.len(),
        EIDOS_COMPRESSION_LOOKUP_COLUMNS,
        "{label}: EidosCompression lookup aux width drifted",
    );

    for (col, &count) in shape.iter().enumerate() {
        let expected = if col < EIDOS_COMPRESSION_NARROW_LOOKUP_COLUMNS {
            EIDOS_COMPRESSION_NARROW_COLUMN_CAPACITY
        } else {
            EIDOS_COMPRESSION_FOOTER_LOOKUP_COLUMN_SHAPE
                [col - EIDOS_COMPRESSION_NARROW_LOOKUP_COLUMNS]
        };
        assert_eq!(
            count, expected,
            "{label}: EidosCompression lookup column {col} has shape {count}, expected {expected}",
        );
    }

    assert_eq!(
        fractions.num_columns(),
        EIDOS_COMPRESSION_LOOKUP_COLUMNS,
        "{label}: EidosCompression lookup aux width drifted",
    );

    (
        EIDOS_COMPRESSION_NARROW_LOOKUP_COLUMNS,
        EIDOS_COMPRESSION_FOOTER_LOOKUP_COLUMN_SHAPE.len(),
    )
}

fn assert_eidos_compression_oracle_coverage(
    label: &str,
    eidos_compression_matrix: &RowMajorMatrix<Felt>,
    fractions: &LookupFractions<Felt, QuadFelt>,
) {
    assert_eq!(
        fractions.num_rows() % EIDOS_COMPRESSION_CYCLE_LEN,
        0,
        "{label}: Eidos compression trace height must be a whole number of compression blocks",
    );

    let (narrow_batch_columns, footer_columns) =
        assert_eidos_compression_column_shape(label, fractions);

    let mut seen_cycle_rows = [false; EIDOS_COMPRESSION_CYCLE_LEN];
    let mut saw_narrow_only_row = false;
    let mut saw_full_narrow_pair = false;
    let mut saw_footer_fraction = false;
    for (row, column_counts) in fractions.counts().chunks(fractions.num_columns()).enumerate() {
        let cycle_row = row % EIDOS_COMPRESSION_CYCLE_LEN;
        seen_cycle_rows[cycle_row] = true;

        for (col, &count) in column_counts[..narrow_batch_columns].iter().enumerate() {
            assert!(
                count <= EIDOS_COMPRESSION_NARROW_COLUMN_CAPACITY,
                "{label}: row {row} cycle row {cycle_row} narrow column {col} pushed {count} \
                 fractions, above batch-2 capacity",
            );
            saw_full_narrow_pair |= count == 2;
        }
        for (offset, &count) in column_counts[narrow_batch_columns..].iter().enumerate() {
            let capacity = EIDOS_COMPRESSION_FOOTER_LOOKUP_COLUMN_SHAPE[offset];
            assert!(
                count <= capacity,
                "{label}: row {row} cycle row {cycle_row} footer column {} pushed {count} \
                 fractions, above capacity {capacity}",
                narrow_batch_columns + offset,
            );
            saw_footer_fraction |= count != 0;
        }

        let overlay_total: usize = column_counts[narrow_batch_columns..].iter().sum();
        saw_narrow_only_row |= overlay_total == 0;

        let actual: usize = column_counts.iter().sum();
        let row_start = row * eidos_compression_matrix.width();
        let is_aead = eidos_compression_matrix.values[row_start + F_MODE_COL] == Felt::ONE;
        let compression_multiplicity =
            eidos_compression_matrix.values[row_start + F_COMPRESSION_MULTIPLICITY_COL];
        let expected = expected_eidos_compression_fraction_entry_range_at_cycle_row(
            cycle_row,
            is_aead,
            compression_multiplicity,
        );
        assert!(
            expected.contains(&actual),
            "{label}: EidosCompression lookup count mismatch at row {row} cycle row {cycle_row}",
        );
    }

    assert!(
        seen_cycle_rows.into_iter().all(|seen| seen),
        "{label}: oracle trace must exercise every Eidos compression cycle row",
    );
    assert_eq!(footer_columns, EIDOS_COMPRESSION_FOOTER_LOOKUP_COLUMN_SHAPE.len());
    assert!(saw_narrow_only_row, "{label}: oracle trace must exercise narrow lookup rows");
    assert!(
        saw_full_narrow_pair && saw_footer_fraction,
        "{label}: oracle trace must exercise full batch-2 pairs and footer lookup columns",
    );
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

/// Asserts that caller-supplied Eidos per-AIR matrices violate at least one AIR constraint.
///
/// This keeps mutation tests on the same four-AIR statement and transcript configuration as the
/// production prover. The panic hook is temporarily suppressed because the debug checker reports
/// the first violated constraint by panicking.
pub(super) fn assert_trace_constraints_reject(
    trace: &VmTrace,
    core_matrix: RowMajorMatrix<Felt>,
    chip_matrix: RowMajorMatrix<Felt>,
    eidos_compression_matrix: RowMajorMatrix<Felt>,
    and8_matrix: RowMajorMatrix<Felt>,
) {
    let (public_values, aux_inputs) = trace.public_inputs().to_air_inputs();
    let statement =
        Statement::<Felt, QuadFelt, _>::new(MidenMultiAir::new(), public_values, aux_inputs)
            .expect("valid statement inputs");
    let prover_statement = ProverStatement::new(
        statement,
        vec![core_matrix, chip_matrix, eidos_compression_matrix, and8_matrix],
    )
    .expect("valid trace shapes");

    let config = config::eidos_config(config::pcs_params(), config::RELATION_DIGEST);
    let _guard = PANIC_HOOK_LOCK.lock().expect("panic hook lock poisoned");
    let panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        debug::check_constraints(&prover_statement, config.challenger());
    }));
    std::panic::set_hook(panic_hook);
    assert!(result.is_err(), "mutated trace should violate AIR constraints");
}

#[test]
fn build_lookup_fractions_runs_on_execution_trace() {
    let trace = build_trace_from_ops(tiny_span(), &[]);
    assert_lookup_fractions_run("tiny span", &trace);
}

#[test]
fn build_lookup_fractions_run_for_aead_stream() {
    let trace = aead_stream_trace();
    assert_lookup_fractions_run("AEAD stream", &trace);
}

#[test]
fn build_lookup_fractions_run_for_mixed_bitwise_aead_stream() {
    let trace = mixed_bitwise_aead_stream_trace();
    assert_lookup_fractions_run("mixed bitwise/AEAD stream", &trace);
}

fn assert_lookup_fractions_run(label: &str, trace: &VmTrace) {
    let (core_matrix, chip_matrix, eidos_compression_matrix, and8_matrix) =
        trace.main_trace().clone_air_matrices();
    // Core has no periodic columns.
    let chip_periodic = BaseAir::<Felt>::periodic_columns(&MidenAir::CHIPLETS);
    let eidos_compression_periodic =
        BaseAir::<Felt>::periodic_columns(&MidenAir::EIDOS_COMPRESSION);
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
        "{label}: no Core fractions collected — trace is degenerate or emitters are broken",
    );
    let _ = accumulate(&core_fractions);

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
        "{label}: no Chiplets fractions collected — trace is degenerate or emitters are broken",
    );
    let _ = accumulate(&chip_fractions);

    // --- Eidos compression ---
    let eidos_compression_fractions = build_lookup_fractions(
        &MidenAir::EIDOS_COMPRESSION,
        &eidos_compression_matrix,
        None,
        &eidos_compression_periodic,
        &challenges,
    );
    assert!(
        !eidos_compression_fractions.fractions().is_empty(),
        "{label}: no Eidos compression fractions collected — trace is degenerate or emitters are broken",
    );
    assert_eidos_compression_oracle_coverage(
        label,
        &eidos_compression_matrix,
        &eidos_compression_fractions,
    );
    let _ = accumulate(&eidos_compression_fractions);

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
        "{label}: no byte-pair table fractions collected - Eidos compression must drive byte lookups",
    );
    let _ = accumulate(&and8_fractions);

    trace.check_constraints();
}
