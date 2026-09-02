//! Range-check bus tests.
//!
//! Verifies `RangeMsg` interactions from u32, Merkle, and memory operations. [`InteractionLog`]
//! collects messages across every Eidos AIR and auxiliary column, so the tests do not depend on
//! the current width-neutral packing.

use alloc::vec::Vec;
use core::{borrow::BorrowMut, mem::size_of};

use miden_air::{
    ControllerCols, CoreCols,
    logup::{HasherMsg, RangeMsg},
    trace::{
        MainTrace,
        and8_lookup::{NUM_AND8_LOOKUP_COLS, RANGE_CHECK_LOOKUP_COL},
        chiplets::hasher::{
            CONTROLLER_ROWS_PER_HASHER_OP_FELT, MAX_MERKLE_DEPTH, MERKLE_DEPTH_RANGE_SCALE,
        },
    },
};
use miden_core::{
    Felt, Word, ZERO,
    crypto::{
        hash::Eidos,
        merkle::{MerklePath, MerkleStore, SimpleSmt},
    },
    field::{PrimeCharacteristicRing, PrimeField64},
    operations::{Operation, opcodes},
    utils::{Matrix, RowMajorMatrix},
};
use miden_utils_testing::{stack, stack_inputs_from_ints};

use super::{
    build_trace_from_ops, build_trace_from_ops_with_inputs,
    lookup_harness::{Expectations, InteractionLog},
};
use crate::{AdviceInputs, RowIndex};

const CONTROLLER_WIDTH: usize = size_of::<ControllerCols<u8>>();
// The Eidos controller overlay occupies chiplet columns 1..20; column 0 is `s_ctrl`.
const CONTROLLER_OFFSET: usize = 1;

/// `U32add` range-checks its four decoder helper columns: for `1 + 255 = 256`, the four
/// values are `{0, 256, 0, 0}`, so we expect exactly three removes of `RangeMsg { value: 0 }`
/// and one remove of `RangeMsg { value: 256 }` at the U32add row.
#[test]
fn u32_stack_op_emits_range_check_removes() {
    let stack = [1, 255];
    let operations = vec![Operation::U32add];
    let trace = build_trace_from_ops(operations, &stack);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let u32add_row = find_op_row(main, opcodes::U32ADD);
    let helper_values: [Felt; 4] = core::array::from_fn(|i| main.helper_register(i, u32add_row));
    assert_eq!(
        helper_values.iter().filter(|&&value| value == ZERO).count(),
        3,
        "expected three zero-valued helpers"
    );
    assert_eq!(
        helper_values.iter().filter(|&&value| value == Felt::from_u16(256)).count(),
        1,
        "expected one helper with value 256"
    );

    let mut exp = Expectations::new(&log);
    for value in helper_values {
        exp.remove(usize::from(u32add_row), &RangeMsg { value });
    }
    log.assert_contains(&exp);

    for value in helper_values {
        assert_eq!(
            log.net_multiplicity(&RangeMsg { value }),
            ZERO,
            "unbalanced u32 range-check value {value}"
        );
    }
}

/// MPVERIFY at depth 1 and MRUPDATE at the supported maximum depth exercise both opcode gates and
/// both accepted endpoints. Besides checking the request interactions, this verifies that execution
/// replay adds both values to the range-check table with the expected multiplicities.
#[test]
fn merkle_ops_emit_depth_range_checks_at_accepted_boundaries() {
    let mpverify_trace = build_mpverify_trace::<1>(0);
    assert_merkle_depth_range_checks(&mpverify_trace, opcodes::MPVERIFY, 1);

    let mrupdate_trace = build_mrupdate_trace::<MAX_MERKLE_DEPTH>(0);
    assert_merkle_depth_range_checks(&mrupdate_trace, opcodes::MRUPDATE, MAX_MERKLE_DEPTH.into());
}

/// Checks honest helper witnesses at the small and maximum-depth boundaries, including the two
/// largest canonical field representatives and both Merkle opcodes. The five index-witness range
/// requests are intentionally split across three existing Core lookup columns; this test is
/// column-blind and therefore pins their semantic multiset rather than their physical placement.
#[test]
fn merkle_index_helpers_are_constrained_and_range_checked() {
    build_mpverify_trace::<1>(1).check_constraints();
    build_mpverify_trace::<MAX_MERKLE_DEPTH>(Felt::ORDER_U64 - 2).check_constraints();
    build_mpverify_trace::<MAX_MERKLE_DEPTH>(Felt::ORDER_U64 - 1).check_constraints();
    build_mrupdate_trace::<MAX_MERKLE_DEPTH>(Felt::ORDER_U64 - 1).check_constraints();

    let trace = build_mpverify_trace::<MAX_MERKLE_DEPTH>(0);
    trace.check_constraints();
    assert_merkle_index_range_checks(&trace, opcodes::MPVERIFY);

    let trace = build_mrupdate_trace::<MAX_MERKLE_DEPTH>(0);
    trace.check_constraints();
    assert_merkle_index_range_checks(&trace, opcodes::MRUPDATE);

    // A helper-limb mutation is rejected by the gated reconstruction equation (and also leaves an
    // unmatched range request). This mutation touches no controller row.
    let main = trace.main_trace();
    let op_row = find_op_row(main, opcodes::MRUPDATE);
    let (mut core, chiplets, eidos_compression, and8) = main.to_air_matrices();
    let changed = main.helper_register(2, op_row) + Felt::ONE;
    set_helper_register(&mut core, op_row, 2, changed);
    super::lookup::assert_trace_constraints_reject(&trace, core, chiplets, eidos_compression, and8);
}

/// Replaces all 64 controller direction bits by the bits of `index + Q`, while keeping the Core
/// helper bit honest. Equal siblings make the Merkle hash invariant under every left/right swap,
/// so the otherwise-valid controller alias is rejected specifically by the typed Merkle-init bus
/// that binds its derived first bit to helper `b`.
#[test]
fn merkle_init_bus_binds_the_first_direction_bit() {
    const INDEX: u64 = 1_000;

    let trace = build_equal_sibling_mpverify_trace(INDEX);
    trace.check_constraints();
    let main = trace.main_trace();
    let op_row = find_op_row(main, opcodes::MPVERIFY);
    let helper_addr = main.helper_register(0, op_row);
    let honest_bit = main.helper_register(1, op_row);
    let word = core::array::from_fn(|i| main.stack_element(i, op_row));
    let honest_message =
        HasherMsg::merkle_verify_init(helper_addr, Felt::new_unchecked(INDEX), honest_bit, word);

    let (core, mut chiplets, eidos_compression, and8) = main.to_air_matrices();
    let alias = INDEX + Felt::ORDER_U64;
    set_mpverify_controller_indices(main, &mut chiplets, alias);

    let log = InteractionLog::from_air_matrices(&core, &chiplets, &eidos_compression, &and8);
    assert_eq!(
        log.net_multiplicity(&honest_message),
        -Felt::ONE,
        "the honest Core init must be left unmatched by the aliased controller bit"
    );
    super::lookup::assert_trace_constraints_reject(&trace, core, chiplets, eidos_compression, and8);
}

/// Completes the `index + Q` controller alias with helper values that satisfy
/// `n + b + 2*y = Q - 1` in the field. The required integer lift has `y >= 2^63`, so the emitted
/// `2*y3` request lies outside the 16-bit table and the otherwise-consistent alias is rejected.
#[test]
fn merkle_index_alias_emits_out_of_range_doubled_top_limb() {
    const INDEX: u64 = 1_000;

    let trace = build_equal_sibling_mpverify_trace(INDEX);
    let main = trace.main_trace();
    let op_row = find_op_row(main, opcodes::MPVERIFY);
    let alias = INDEX + Felt::ORDER_U64;
    let alias_bit = alias & 1;
    let alias_y =
        ((u128::from(Felt::ORDER_U64) * 2 - 1 - u128::from(INDEX) - alias_bit as u128) / 2) as u64;
    let limbs = split_u64_into_u16_limbs(alias_y);
    assert!(limbs[3] >= 1 << 15, "alias witness must violate y < 2^63");

    let (mut core, mut chiplets, eidos_compression, and8) = main.to_air_matrices();
    set_mpverify_controller_indices(main, &mut chiplets, alias);
    set_helper_register(&mut core, op_row, 1, Felt::new_unchecked(alias_bit));
    for (i, limb) in limbs.into_iter().enumerate() {
        set_helper_register(&mut core, op_row, i + 2, Felt::from_u16(limb));
    }

    let y = reconstruct_u64_limbs(limbs.map(Felt::from_u16));
    assert_eq!(
        Felt::new_unchecked(INDEX) + Felt::new_unchecked(alias_bit) + y.double(),
        Felt::NEG_ONE,
        "the aliased helper must satisfy the local field equation"
    );

    let doubled_top = Felt::from_u16(limbs[3]).double();
    assert!(doubled_top.as_canonical_u64() >= 1 << 16);
    let message = RangeMsg { value: doubled_top };
    let log = InteractionLog::from_air_matrices(&core, &chiplets, &eidos_compression, &and8);
    let mut expected = Expectations::new(&log);
    expected.remove(usize::from(op_row), &message);
    log.assert_contains(&expected);
    assert_eq!(log.net_multiplicity(&message), -Felt::ONE);

    super::lookup::assert_trace_constraints_reject(&trace, core, chiplets, eidos_compression, and8);
}

/// Mutate a real maximum-depth MPVERIFY row and verify that the forged value drives both the range
/// requests and the hasher return address. The honest tables cannot balance either request.
#[test]
fn forged_merkle_depths_emit_unbalanced_lookup_requests() {
    let trace = build_mpverify_trace::<MAX_MERKLE_DEPTH>(0);

    let main = trace.main_trace();
    let op_row = find_op_row(main, opcodes::MPVERIFY);
    let helper0 = main.helper_register(0, op_row);
    let root = core::array::from_fn(|i| main.stack_element(6 + i, op_row));
    let (honest_core, chip_matrix, eidos_compression_matrix, and8_matrix) = main.to_air_matrices();
    let first_unsupported_depth = Felt::new_unchecked(u64::from(MAX_MERKLE_DEPTH) + 1);

    for forged_depth in [ZERO, first_unsupported_depth, Felt::NEG_ONE] {
        let mut forged_core = honest_core.clone();
        set_stack_element(&mut forged_core, op_row, 4, forged_depth);

        let log = InteractionLog::from_air_matrices(
            &forged_core,
            &chip_matrix,
            &eidos_compression_matrix,
            &and8_matrix,
        );
        let scaled_depth = (forged_depth - Felt::ONE) * Felt::from_u16(MERKLE_DEPTH_RANGE_SCALE);
        let messages = [RangeMsg { value: forged_depth }, RangeMsg { value: scaled_depth }];
        let mut exp = Expectations::new(&log);
        for message in &messages {
            exp.remove(usize::from(op_row), message);
        }
        let return_addr = helper0 + forged_depth * CONTROLLER_ROWS_PER_HASHER_OP_FELT - Felt::ONE;
        let return_message = HasherMsg::return_hash(return_addr, root);
        exp.remove(usize::from(op_row), &return_message);
        log.assert_contains(&exp);
        for message in &messages {
            assert_eq!(log.net_multiplicity(message), -Felt::ONE);
        }
        assert_eq!(log.net_multiplicity(&return_message), -Felt::ONE);
    }
}

/// U32DIV uses four helper limbs for the quotient and remainder and two more for
/// `divisor - remainder - 1`. All six must reach the range-check bus, even though the final pair
/// is packed into a different lookup column.
#[test]
fn u32div_emits_all_range_check_removes() {
    let operations = vec![Operation::U32div, Operation::Drop, Operation::Drop, Operation::U32div];
    let trace = build_trace_from_ops(operations, &[0x0008_000b, 0x003b_0051, 3, 0x0003_0004]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let rows: Vec<RowIndex> = (0..main.core_height())
        .map(RowIndex::from)
        .filter(|&row| main.get_op_code(row) == Felt::from_u8(opcodes::U32DIV))
        .collect();
    assert_eq!(rows.len(), 2, "expected two U32DIV rows");

    // The first division has nonzero limbs for the remainder and its bound. The second has a
    // nonzero high quotient limb. Distinct values in the first row also expose limb swaps.
    let expected_helpers = [[7, 0, 4, 3, 6, 5], [1, 1, 1, 0, 1, 0]];
    let mut expected = Expectations::new(&log);
    for (row, expected_row) in rows.into_iter().zip(expected_helpers) {
        let helpers: [Felt; 6] = core::array::from_fn(|i| main.helper_register(i, row));
        assert_eq!(helpers, expected_row.map(Felt::new_unchecked));
        for value in helpers {
            expected.remove(usize::from(row), &RangeMsg { value });
        }
    }
    log.assert_contains(&expected);
}

/// Two memory ops (`MStoreW` + `MLoadW`) on the same word address emit 5 `RangeMsg` removes
/// per memory chiplet row: `d0`, `d1` (the 16-bit delta limbs used for sorted-access
/// constraints) and `w0`, `w1`, `4 * w1` (the word-address decomposition).
///
/// The address `262148 = 4 * 65537` is word-aligned with `word_index = 65537 = 0x10001`, so
/// `w0 = 1`, `w1 = 1`, `4 * w1 = 4` - a non-trivial decomposition that exercises the full
/// five-way range-check batch.
#[test]
fn memory_chiplet_row_emits_range_check_removes() {
    let addr: u64 = 262148;
    let stack_input = stack![addr, 1, 2, 3, 4, addr];

    // MStoreW + 4xDrop + MLoadW, followed by enough Noops to keep the memory-row checks
    // separated from the byte-pair table rows used later in this file.
    let mut operations = vec![
        Operation::MStoreW,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::MLoadW,
    ];
    operations.resize(operations.len() + 60, Operation::Noop);
    let trace = build_trace_from_ops(operations, &stack_input);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    // Collect every memory chiplet row; we expect exactly two for the two memory ops.
    let mut mem_rows: Vec<RowIndex> = Vec::new();
    for row in 0..main.chiplets_height() {
        let idx = RowIndex::from(row);
        if main.is_memory_row(idx) {
            mem_rows.push(idx);
        }
    }
    assert_eq!(mem_rows.len(), 2, "expected exactly two memory chiplet rows");

    let mut exp = Expectations::new(&log);
    let mut requested_values = Vec::with_capacity(5 * mem_rows.len());
    for mem_row in &mem_rows {
        let row = usize::from(*mem_row);
        let mem = main.chiplet_cols(*mem_row).memory();
        let d0 = mem.d0;
        let d1 = mem.d1;
        let w0 = main.chiplet_memory_word_addr_lo(*mem_row);
        let w1 = main.chiplet_memory_word_addr_hi(*mem_row);
        let four_w1 = w1 * Felt::from_u8(4);

        for value in [d0, d1, w0, w1, four_w1] {
            exp.remove(row, &RangeMsg { value });
            requested_values.push(value);
        }
    }

    log.assert_contains(&exp);
    for value in requested_values {
        assert_eq!(
            log.net_multiplicity(&RangeMsg { value }),
            ZERO,
            "unbalanced memory range-check value {value}"
        );
    }
}

/// Byte-pair rows with nonzero range-check multiplicity emit a `RangeMsg { value: v }` add with
/// runtime multiplicity `m`. This test verifies the table add side of the range-check bus.
///
/// Catches regressions where the byte-pair add-back emitter misreads the multiplicity column or
/// the `value = 256 * a + b` row mapping; bugs that the per-request removes-only tests
/// above cannot detect.
#[test]
fn range_checker_table_emits_per_row_adds() {
    // U32add issues 4 range-check requests for values {0, 256, 0, 0} on 1 + 255 = 256. The
    // byte-pair lookup AIR then adds back four multiplicities of those values from row 0 and row
    // 256. We scan all rows so the test also catches accidental extra nonzero range counts.
    let stack = [1, 255];
    let operations = vec![Operation::U32add];
    let trace = build_trace_from_ops(operations, &stack);
    let log = InteractionLog::new(&trace);
    let (_, _, _, and8_matrix) = trace.main_trace().to_air_matrices();

    let mut nonzero_mult_rows = 0usize;
    let mut exp = Expectations::new(&log);
    for row in 0..and8_matrix.height() {
        let m = and8_matrix.values[row * NUM_AND8_LOOKUP_COLS + RANGE_CHECK_LOOKUP_COL];
        if m != Felt::from_u8(0) {
            nonzero_mult_rows += 1;
            exp.push(row, m, &RangeMsg { value: Felt::from_u32(row as u32) });
        }
    }

    assert!(nonzero_mult_rows > 0, "range-check table side is empty - test is vacuous");
    log.assert_contains(&exp);
}

// HELPERS
// ================================================================================================

fn find_op_row(main: &MainTrace, opcode: u8) -> RowIndex {
    for row in 0..main.core_height() {
        let idx = RowIndex::from(row);
        if main.get_op_code(idx) == Felt::from_u8(opcode) {
            return idx;
        }
    }
    panic!("no row with opcode 0x{opcode:02x} in trace");
}

fn assert_merkle_depth_range_checks(trace: &super::VmTrace, opcode: u8, expected_depth: u16) {
    let log = InteractionLog::new(trace);
    let main = trace.main_trace();
    let op_row = find_op_row(main, opcode);

    let depth = main.stack_element(4, op_row);
    assert_eq!(depth, Felt::from_u16(expected_depth));
    let scaled_depth = (depth - Felt::ONE) * Felt::from_u16(MERKLE_DEPTH_RANGE_SCALE);

    let mut exp = Expectations::new(&log);
    exp.remove(usize::from(op_row), &RangeMsg { value: depth });
    exp.remove(usize::from(op_row), &RangeMsg { value: scaled_depth });
    log.assert_contains(&exp);

    for value in [depth, scaled_depth] {
        assert_eq!(
            log.net_multiplicity(&RangeMsg { value }),
            ZERO,
            "unbalanced Merkle-depth range-check value {value}"
        );
    }
}

fn assert_merkle_index_range_checks(trace: &super::VmTrace, opcode: u8) {
    let log = InteractionLog::new(trace);
    let main = trace.main_trace();
    let op_row = find_op_row(main, opcode);
    let y_limbs: [Felt; 4] = core::array::from_fn(|i| main.helper_register(i + 2, op_row));
    let requested = [y_limbs[0], y_limbs[1], y_limbs[2], y_limbs[3], y_limbs[3].double()];

    let mut expected = Expectations::new(&log);
    for value in requested {
        expected.remove(usize::from(op_row), &RangeMsg { value });
    }
    log.assert_contains(&expected);

    for value in requested {
        assert_eq!(
            log.net_multiplicity(&RangeMsg { value }),
            ZERO,
            "unbalanced Merkle-index range-check value {value}"
        );
    }
}

fn set_mpverify_controller_indices(
    main: &MainTrace,
    chip_matrix: &mut RowMajorMatrix<Felt>,
    index: u64,
) {
    let rows: Vec<RowIndex> = (0..main.chiplets_height())
        .map(RowIndex::from)
        .filter(|&row| {
            if !main.is_hash_row(row) {
                return false;
            }
            let ctrl = main.chiplet_cols(row).controller();
            ctrl.s0 == Felt::ONE && ctrl.s1 == ZERO && ctrl.s2 == Felt::ONE
        })
        .collect();
    assert_eq!(rows.len(), MAX_MERKLE_DEPTH as usize);

    for (level, row) in rows.into_iter().enumerate() {
        let current = index.checked_shr(level as u32).unwrap_or(0);
        let next = index.checked_shr((level + 1) as u32).unwrap_or(0);
        let ctrl = controller_row_mut(chip_matrix, row);
        ctrl.row_data[0] = Felt::new_unchecked(current % Felt::ORDER_U64);
        ctrl.row_data[1] = Felt::new_unchecked(next % Felt::ORDER_U64);
    }
}

fn controller_row_mut(
    chip_matrix: &mut RowMajorMatrix<Felt>,
    row: RowIndex,
) -> &mut ControllerCols<Felt> {
    let width = chip_matrix.width();
    let start = usize::from(row) * width + CONTROLLER_OFFSET;
    chip_matrix.values[start..start + CONTROLLER_WIDTH].borrow_mut()
}

fn set_stack_element(
    core_matrix: &mut RowMajorMatrix<Felt>,
    row: RowIndex,
    stack_idx: usize,
    value: Felt,
) {
    let width = core_matrix.width();
    let start = usize::from(row) * width;
    let core_row: &mut CoreCols<Felt> = core_matrix.values[start..start + width].borrow_mut();
    core_row.stack.top[stack_idx] = value;
}

fn set_helper_register(
    core_matrix: &mut RowMajorMatrix<Felt>,
    row: RowIndex,
    helper_idx: usize,
    value: Felt,
) {
    let width = core_matrix.width();
    let start = usize::from(row) * width;
    let core_row: &mut CoreCols<Felt> = core_matrix.values[start..start + width].borrow_mut();
    core_row.decoder.hasher_state[helper_idx + 2] = value;
}

fn split_u64_into_u16_limbs(value: u64) -> [u16; 4] {
    [value as u16, (value >> 16) as u16, (value >> 32) as u16, (value >> 48) as u16]
}

fn reconstruct_u64_limbs(limbs: [Felt; 4]) -> Felt {
    limbs[0]
        + limbs[1] * Felt::from_u64(1_u64 << 16)
        + limbs[2] * Felt::from_u64(1_u64 << 32)
        + limbs[3] * Felt::from_u64(1_u64 << 48)
}

fn build_equal_sibling_mpverify_trace(index: u64) -> super::VmTrace {
    const DEPTH: usize = MAX_MERKLE_DEPTH as usize;

    let value = test_word(7);
    let mut current = value;
    let mut siblings = Vec::with_capacity(DEPTH);
    for _ in 0..DEPTH {
        siblings.push(current);
        current = Eidos::merge(&[current, current]);
    }

    let path = MerklePath::new(siblings);
    let mut store = MerkleStore::new();
    let root = store.add_merkle_path(index, value, path).unwrap();
    assert_eq!(root, current);

    let mut runtime_stack = Vec::new();
    runtime_stack.extend(word_to_ints(value));
    runtime_stack.push(DEPTH as u64);
    runtime_stack.push(index);
    runtime_stack.extend(word_to_ints(root));
    build_trace_from_ops_with_inputs(
        vec![Operation::MpVerify(ZERO)],
        stack_inputs_from_ints(runtime_stack),
        AdviceInputs::default().with_merkle_store(store),
    )
}

fn build_mpverify_trace<const DEPTH: u8>(index: u64) -> super::VmTrace {
    let value = test_word(7);
    let tree = SimpleSmt::<DEPTH>::with_leaves([(index, value)]).unwrap();

    let mut runtime_stack = Vec::new();
    runtime_stack.extend(word_to_ints(value));
    runtime_stack.push(DEPTH.into());
    runtime_stack.push(index);
    runtime_stack.extend(word_to_ints(tree.root()));

    build_trace_from_ops_with_inputs(
        vec![Operation::MpVerify(ZERO)],
        stack_inputs_from_ints(runtime_stack),
        AdviceInputs::default().with_merkle_store(MerkleStore::from(&tree)),
    )
}

fn build_mrupdate_trace<const DEPTH: u8>(index: u64) -> super::VmTrace {
    let old_value = test_word(7);
    let new_value = test_word(11);
    let tree = SimpleSmt::<DEPTH>::with_leaves([(index, old_value)]).unwrap();

    let mut runtime_stack = Vec::new();
    runtime_stack.extend(word_to_ints(old_value));
    runtime_stack.push(DEPTH.into());
    runtime_stack.push(index);
    runtime_stack.extend(word_to_ints(tree.root()));
    runtime_stack.extend(word_to_ints(new_value));

    build_trace_from_ops_with_inputs(
        vec![Operation::MrUpdate],
        stack_inputs_from_ints(runtime_stack),
        AdviceInputs::default().with_merkle_store(MerkleStore::from(&tree)),
    )
}

fn test_word(value: u64) -> Word {
    [Felt::new_unchecked(value), ZERO, ZERO, ZERO].into()
}

fn word_to_ints(word: Word) -> [u64; 4] {
    word.map(|value| value.as_canonical_u64())
}
