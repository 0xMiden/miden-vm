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
use std::collections::HashMap;

use miden_air::{
    BaseAir, MidenAir, MidenMultiAir, ProverStatement, StarkConfig, Statement, config, debug,
    logup::{BusId, HasherCompressionLinkMsg, MIDEN_MAX_MESSAGE_WIDTH},
    lookup::{Challenges, LookupFractions, LookupMessage, accumulate, build_lookup_fractions},
    trace::{
        CHIPLETS_MODE_COL, CHIPLETS_STREAM_MODE_COL,
        and8_lookup::{
            AND8_TABLE_ROWS, BYTE_PAIR_RELATION_COUNT, BytePairRelation, NUM_AND8_LOOKUP_COLS,
            RANGE_CHECK_LOOKUP_COL,
        },
        eidos_compression::{
            EIDOS_COMPRESSION_CYCLE_LEN, F_COMPRESSION_MULTIPLICITY_COL, F_MODE_COL,
            NUM_EIDOS_COMPRESSION_COLS,
        },
    },
};
use miden_core::{
    Word,
    crypto::{
        hash::Eidos,
        merkle::{MerkleStore, MerkleTree},
    },
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};

use super::{
    Felt, VmTrace, build_trace_from_ops, build_trace_from_ops_with_inputs,
    lookup_harness::InteractionLog, rand_array,
};
use crate::{AdviceInputs, StackInputs, operation::Operation};

const EIDOS_COMPRESSION_NARROW_COLUMN_CAPACITY: usize = 2;
const EIDOS_COMPRESSION_NARROW_LOOKUP_COLUMNS: usize = 18;
const EIDOS_COMPRESSION_FOOTER_LOOKUP_COLUMN_SHAPE: [usize; 2] = [2, 2];
const EIDOS_COMPRESSION_LOOKUP_COLUMNS: usize =
    EIDOS_COMPRESSION_NARROW_LOOKUP_COLUMNS + EIDOS_COMPRESSION_FOOTER_LOOKUP_COLUMN_SHAPE.len();
const AND8_COLUMN_SHAPE: [usize; 4] = [1, 2, 2, 2];
const AND8_PAIRED_MAIN_COLUMNS: [(usize, usize); 3] = [
    (BytePairRelation::Rot12Pos1 as usize, BytePairRelation::Rot7Pos0 as usize),
    (BytePairRelation::Rot7Pos2 as usize, BytePairRelation::Rot12Pos3 as usize),
    (BytePairRelation::Rot7Pos3 as usize, RANGE_CHECK_LOOKUP_COL),
];
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

/// Cross-multiply each row-local lookup column directly from the prover's raw fractions.
///
/// Keeping this helper data-only tests the public prover-fraction boundary without coupling these
/// assertions to the internal constraint builder.
fn lookup_column_folds(
    fractions: &LookupFractions<Felt, QuadFelt>,
) -> Vec<Vec<(QuadFelt, QuadFelt)>> {
    let num_columns = fractions.num_columns();
    let mut cursor = 0;
    let mut rows = Vec::with_capacity(fractions.num_rows());

    for row_counts in fractions.counts().chunks(num_columns) {
        let mut row = Vec::with_capacity(num_columns);
        for &count in row_counts {
            let mut numerator = QuadFelt::ZERO;
            let mut denominator = QuadFelt::ONE;
            for &(multiplicity, encoded) in &fractions.fractions()[cursor..cursor + count] {
                let multiplicity = QuadFelt::new([multiplicity, Felt::ZERO]);
                numerator = numerator * encoded + multiplicity * denominator;
                denominator *= encoded;
            }
            cursor += count;
            row.push((numerator, denominator));
        }
        rows.push(row);
    }

    assert_eq!(cursor, fractions.fractions().len());
    rows
}

/// Checks the exact cross-multiplied constraints emitted by the lookup AIR. Column zero is the
/// normalized cyclic accumulator; the remaining columns store their row-local batched fractions.
fn and8_aux_constraints_hold(
    aux: &RowMajorMatrix<QuadFelt>,
    sigma_prime: QuadFelt,
    column_folds: &[Vec<(QuadFelt, QuadFelt)>],
) -> bool {
    let num_rows = column_folds.len();
    let width = aux.width();
    if width != AND8_COLUMN_SHAPE.len()
        || aux.height() != num_rows
        || aux.values[0] != QuadFelt::ZERO
    {
        return false;
    }

    for (row, folds) in column_folds.iter().enumerate() {
        if folds.len() != width {
            return false;
        }

        let current = &aux.values[row * width..(row + 1) * width];
        let current_sum: QuadFelt = current.iter().copied().sum();
        let next_acc = aux.values[((row + 1) % num_rows) * width];
        let (v, u) = folds[0];
        if u * (next_acc - current_sum + sigma_prime) != v {
            return false;
        }

        for col in 1..width {
            let (v, u) = folds[col];
            if u * current[col] != v {
                return false;
            }
        }
    }

    true
}

fn and8_aux_column_constraint_holds_at(
    aux: &RowMajorMatrix<QuadFelt>,
    sigma_prime: QuadFelt,
    column_folds: &[Vec<(QuadFelt, QuadFelt)>],
    row: usize,
    col: usize,
) -> bool {
    let width = aux.width();
    let current = &aux.values[row * width..(row + 1) * width];
    let (v, u) = column_folds[row][col];
    if col == 0 {
        let current_sum: QuadFelt = current.iter().copied().sum();
        let next_acc = aux.values[((row + 1) % aux.height()) * width];
        u * (next_acc - current_sum + sigma_prime) == v
    } else {
        u * current[col] == v
    }
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
fn deduplicated_compress_keeps_unit_controller_multiplicity() {
    // The fourth word backs up the input CV. After the first compression, swap that backup into
    // the CV position so the second COMPRESS issues the identical physical request.
    let trace = build_trace_from_ops(
        vec![
            Operation::Compress,
            Operation::SwapW2,
            Operation::SwapW3,
            Operation::SwapW2,
            Operation::Compress,
        ],
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 9, 10, 11, 12],
    );
    let (_, chip_matrix, eidos_compression_matrix, _) = trace.main_trace().clone_air_matrices();
    let log = InteractionLog::new(&trace);

    let block = [1, 2, 3, 4, 5, 6, 7, 8].map(Felt::new_unchecked);
    let cv_in = [9, 10, 11, 12].map(Felt::new_unchecked);
    let output = Eidos::compress(Word::new(cv_in), block);
    let message = HasherCompressionLinkMsg {
        block,
        cv_in,
        cv_out: core::array::from_fn(|idx| output[idx]),
    };
    let denominator = message.encode(&log.challenges);

    let chip_fractions = build_lookup_fractions(
        &MidenAir::CHIPLETS,
        &chip_matrix,
        None,
        &BaseAir::<Felt>::periodic_columns(&MidenAir::CHIPLETS),
        &log.challenges,
    );
    let eidos_compression_fractions = build_lookup_fractions(
        &MidenAir::EIDOS_COMPRESSION,
        &eidos_compression_matrix,
        None,
        &BaseAir::<Felt>::periodic_columns(&MidenAir::EIDOS_COMPRESSION),
        &log.challenges,
    );
    let matching_multiplicities = |fractions: &LookupFractions<Felt, QuadFelt>| {
        fractions
            .fractions()
            .iter()
            .filter_map(|&(multiplicity, encoded)| (encoded == denominator).then_some(multiplicity))
            .collect::<Vec<_>>()
    };

    let two = Felt::new_unchecked(2);
    assert_eq!(matching_multiplicities(&chip_fractions), vec![Felt::ONE, Felt::ONE]);
    assert_eq!(matching_multiplicities(&eidos_compression_fractions), vec![-two]);
    assert_eq!(log.net_multiplicity(&message), Felt::ZERO);

    // The aggregate provider cancels both unit controller emissions in the complete four-AIR
    // ledger, and the composed constraints close as well.
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
    const CANONICAL_REQUESTS_PER_BLOCK: u64 = 684;
    const REQUESTS_PER_DEDICATED_ROTATION_RELATION: u64 = 56;
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
        for col in 0..BYTE_PAIR_RELATION_COUNT {
            actual_eidos_compression_byte_lookup_total +=
                and8_matrix.values[row_start + col].as_canonical_u64();
        }
    }
    assert_eq!(
        actual_eidos_compression_byte_lookup_total, expected_eidos_compression_byte_lookup_total,
        "EidosCompression byte-lookup multiplicities do not match EidosCompression requests",
    );

    // Each block has fourteen rows per rotation family. Canonical XOR aggregates 16 ordinary
    // ANDs per fused row, rot12 positions 0/2, rot7 position 1, and 17 ANDs per footer row. Each
    // dedicated rotation relation receives four requests on each of its fourteen active fused rows.
    let relation_totals: [u64; BYTE_PAIR_RELATION_COUNT] = core::array::from_fn(|relation| {
        (0..AND8_TABLE_ROWS)
            .map(|row| and8_matrix.values[row * NUM_AND8_LOOKUP_COLS + relation].as_canonical_u64())
            .sum()
    });
    assert_eq!(
        relation_totals[BytePairRelation::CanonicalXor.index()],
        block_count as u64 * CANONICAL_REQUESTS_PER_BLOCK,
    );
    for relation in [
        BytePairRelation::Rot12Pos1,
        BytePairRelation::Rot7Pos0,
        BytePairRelation::Rot7Pos2,
        BytePairRelation::Rot12Pos3,
        BytePairRelation::Rot7Pos3,
    ] {
        assert_eq!(
            relation_totals[relation.index()],
            block_count as u64 * REQUESTS_PER_DEDICATED_ROTATION_RELATION,
            "unexpected multiplicity total for {relation:?}",
        );
    }

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

/// Checks the honest trace against the complete composed AIR, including global lookup closure.
pub(super) fn assert_global_lookup_balance(trace: &VmTrace) {
    trace.check_constraints();
}

/// Checks that caller-supplied matrices change the prover-emitted lookup multiset.
///
/// Boundary interactions are unchanged, so a nonzero delta against the honest matrices implies
/// that the mutated complete lookup ledger cannot close. Comparing raw encoded interactions keeps
/// this regression independent of constraint-builder diagnostics.
pub(super) fn assert_global_lookup_balance_rejects(
    label: &str,
    trace: &VmTrace,
    core_matrix: &RowMajorMatrix<Felt>,
    chip_matrix: &RowMajorMatrix<Felt>,
    eidos_compression_matrix: &RowMajorMatrix<Felt>,
    and8_matrix: &RowMajorMatrix<Felt>,
    expected_bus: &str,
) {
    let (honest_core, honest_chiplets, honest_eidos, honest_and8) =
        trace.main_trace().clone_air_matrices();
    let raw = rand_array::<Felt, 4>();
    let challenges = Challenges::<QuadFelt>::new(
        QuadFelt::new([raw[0], raw[1]]),
        QuadFelt::new([raw[2], raw[3]]),
        MIDEN_MAX_MESSAGE_WIDTH,
        BusId::COUNT,
    );

    let honest = lookup_multiplicities(
        &honest_core,
        &honest_chiplets,
        &honest_eidos,
        &honest_and8,
        &challenges,
    );
    let attacked = lookup_multiplicities(
        core_matrix,
        chip_matrix,
        eidos_compression_matrix,
        and8_matrix,
        &challenges,
    );

    let mut delta = honest;
    for (denominator, multiplicity) in attacked {
        *delta.entry(denominator).or_insert(Felt::ZERO) -= multiplicity;
    }
    delta.retain(|_, multiplicity| *multiplicity != Felt::ZERO);

    assert!(
        !delta.is_empty(),
        "{label}: mutation did not change the {expected_bus} lookup multiset",
    );
}

fn lookup_multiplicities(
    core_matrix: &RowMajorMatrix<Felt>,
    chip_matrix: &RowMajorMatrix<Felt>,
    eidos_compression_matrix: &RowMajorMatrix<Felt>,
    and8_matrix: &RowMajorMatrix<Felt>,
    challenges: &Challenges<QuadFelt>,
) -> HashMap<QuadFelt, Felt> {
    let chip_periodic = BaseAir::<Felt>::periodic_columns(&MidenAir::CHIPLETS);
    let eidos_compression_periodic =
        BaseAir::<Felt>::periodic_columns(&MidenAir::EIDOS_COMPRESSION);
    let and8_preprocessed = MidenAir::AND8_LOOKUP
        .preprocessed_trace()
        .expect("And8 lookup AIR declares a preprocessed table");
    let fractions = [
        build_lookup_fractions(&MidenAir::CORE, core_matrix, None, &[], challenges),
        build_lookup_fractions(&MidenAir::CHIPLETS, chip_matrix, None, &chip_periodic, challenges),
        build_lookup_fractions(
            &MidenAir::EIDOS_COMPRESSION,
            eidos_compression_matrix,
            None,
            &eidos_compression_periodic,
            challenges,
        ),
        build_lookup_fractions(
            &MidenAir::AND8_LOOKUP,
            and8_matrix,
            Some(&and8_preprocessed),
            &[],
            challenges,
        ),
    ];

    let mut totals = HashMap::new();
    for fractions in fractions {
        for &(multiplicity, denominator) in fractions.fractions() {
            *totals.entry(denominator).or_insert(Felt::ZERO) += multiplicity;
        }
    }
    totals
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

#[test]
fn and8_columns_bind_every_aux_column_through_the_cyclic_wrap() {
    let trace = build_trace_from_ops(tiny_span(), &[]);
    let (_, _, _, and8_matrix) = trace.main_trace().clone_air_matrices();
    let preprocessed = MidenAir::AND8_LOOKUP
        .preprocessed_trace()
        .expect("And8 AIR must declare its fixed byte-pair table");

    let raw = rand_array::<Felt, 4>();
    let challenges = Challenges::<QuadFelt>::new(
        QuadFelt::new([raw[0], raw[1]]),
        QuadFelt::new([raw[2], raw[3]]),
        MIDEN_MAX_MESSAGE_WIDTH,
        BusId::COUNT,
    );
    let fractions = build_lookup_fractions(
        &MidenAir::AND8_LOOKUP,
        &and8_matrix,
        Some(&preprocessed),
        &[],
        &challenges,
    );
    assert_eq!(fractions.shape(), &AND8_COLUMN_SHAPE);

    let (aux, sigma_prime) = accumulate(&fractions);
    let folds = lookup_column_folds(&fractions);
    assert!(
        and8_aux_constraints_hold(&aux, sigma_prime, &folds),
        "honest And8 auxiliary trace must satisfy every cross-multiplied equation",
    );

    let final_row = aux.height() - 1;
    assert!(
        and8_aux_column_constraint_holds_at(&aux, sigma_prime, &folds, final_row, 0),
        "the last-row accumulator constraint must close through the wrapped next row",
    );

    for row in [AND8_TABLE_ROWS / 2 + 37, final_row] {
        for col in 0..AND8_COLUMN_SHAPE.len() {
            let mut tampered = aux.clone();
            tampered.values[row * AND8_COLUMN_SHAPE.len() + col] += QuadFelt::ONE;
            assert!(
                !and8_aux_column_constraint_holds_at(&tampered, sigma_prime, &folds, row, col,),
                "And8 auxiliary mutation survived at row {row}, column {col}",
            );
        }
    }
}

#[test]
fn and8_paired_columns_reject_opposite_multiplicity_deltas_across_domains() {
    let trace = build_trace_from_ops(tiny_span(), &[]);
    let (core_matrix, chip_matrix, eidos_compression_matrix, honest_and8_matrix) =
        trace.main_trace().clone_air_matrices();
    let preprocessed = MidenAir::AND8_LOOKUP
        .preprocessed_trace()
        .expect("And8 AIR must declare its fixed byte-pair table");

    let raw = rand_array::<Felt, 4>();
    let challenges = Challenges::<QuadFelt>::new(
        QuadFelt::new([raw[0], raw[1]]),
        QuadFelt::new([raw[2], raw[3]]),
        MIDEN_MAX_MESSAGE_WIDTH,
        BusId::COUNT,
    );
    let honest_fractions = build_lookup_fractions(
        &MidenAir::AND8_LOOKUP,
        &honest_and8_matrix,
        Some(&preprocessed),
        &[],
        &challenges,
    );
    let (honest_aux, honest_sigma_prime) = accumulate(&honest_fractions);

    // Each attack preserves the untagged sum of the two multiplicities. Distinct bus prefixes
    // and payloads must nevertheless keep both denominators independently binding.
    let attack_rows = [1025, 4097, AND8_TABLE_ROWS - 1];
    let mut attacked_and8_matrix = honest_and8_matrix;
    let main_width = attacked_and8_matrix.width();
    for (pair, &row) in AND8_PAIRED_MAIN_COLUMNS.iter().zip(&attack_rows) {
        attacked_and8_matrix.values[row * main_width + pair.0] += Felt::ONE;
        attacked_and8_matrix.values[row * main_width + pair.1] -= Felt::ONE;
    }

    let attacked_fractions = build_lookup_fractions(
        &MidenAir::AND8_LOOKUP,
        &attacked_and8_matrix,
        Some(&preprocessed),
        &[],
        &challenges,
    );
    let attacked_folds = lookup_column_folds(&attacked_fractions);
    for (pair_idx, &row) in attack_rows.iter().enumerate() {
        let col = pair_idx + 1;
        assert!(
            !and8_aux_column_constraint_holds_at(
                &honest_aux,
                honest_sigma_prime,
                &attacked_folds,
                row,
                col,
            ),
            "opposite multiplicity deltas survived in And8 pair column {col}",
        );
    }

    // A prover can rebuild locally valid auxiliary columns for the mutated provider trace, but
    // the tagged global buses must still reject those changed multiplicities.
    let (attacked_aux, attacked_sigma_prime) = accumulate(&attacked_fractions);
    assert!(and8_aux_constraints_hold(&attacked_aux, attacked_sigma_prime, &attacked_folds,));
    assert_trace_constraints_reject(
        &trace,
        core_matrix,
        chip_matrix,
        eidos_compression_matrix,
        attacked_and8_matrix,
    );
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
