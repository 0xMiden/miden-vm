//! Range-check bus tests.
//!
//! Verifies `RangeMsg` interactions from u32, Merkle, and memory operations. [`InteractionLog`]
//! collects messages across all auxiliary columns, so these tests do not depend on the current
//! column packing.

use alloc::vec::Vec;
use core::{borrow::BorrowMut, mem::size_of};

use miden_air::{
    ControllerCols, CoreCols,
    logup::{HasherMsg, RangeMsg},
    trace::{
        CHIPLET_CONTROLLER_OFFSET, MainTrace,
        chiplets::hasher::{
            CONTROLLER_ROWS_PER_PERM_FELT, MAX_MERKLE_DEPTH, MAX_MERKLE_INDEX_HALF,
            MERKLE_DEPTH_RANGE_SCALE, RATE_LEN,
        },
    },
};
use miden_core::{
    Felt, Word, ZERO,
    crypto::{
        hash::Poseidon2,
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

/// Checks valid canonicality witnesses at small and maximum depths, including index zero, the
/// largest field index, and both MRUPDATE paths.
#[test]
fn merkle_index_canonicality_witness_is_constrained_and_range_checked() {
    build_mpverify_trace::<1>(1).check_constraints();
    build_mpverify_trace::<2>(3).check_constraints();

    let trace = build_mpverify_trace::<MAX_MERKLE_DEPTH>(Felt::ORDER_U64 - 1);
    trace.check_constraints();
    let main = trace.main_trace();
    let boundary_row = find_merkle_boundary_input_row(main);

    // Changing one limb breaks the local slack equation.
    let (core, mut chiplets, poseidon2) = main.to_air_matrices();
    let controller = controller_row_mut(&mut chiplets, boundary_row);
    controller.state[RATE_LEN] += Felt::ONE;
    super::lookup::assert_trace_constraints_reject(&trace, core, chiplets, poseidon2);

    build_mrupdate_trace::<MAX_MERKLE_DEPTH>(Felt::ORDER_U64 - 1).check_constraints();

    // At index 0, the four limbs are {0x0000, 0x8000, 0xFFFF, 0x7FFF}. Their distinct values make
    // a missing or duplicated request visible. The lookup log checks the set of requests for the
    // row; their placement among lookup columns is not semantically relevant.
    let trace = build_mpverify_trace::<MAX_MERKLE_DEPTH>(0);
    trace.check_constraints();
    let main = trace.main_trace();
    let boundary_row = find_merkle_boundary_input_row(main);
    let capacity = main.chiplet_cols(boundary_row).controller().capacity();
    let expected_values =
        [capacity[0], capacity[1], capacity[2], capacity[3], capacity[3].double()];
    for (i, value) in capacity.into_iter().enumerate() {
        for other in capacity.into_iter().skip(i + 1) {
            assert_ne!(value, other, "witness limbs must stay pairwise distinct");
        }
    }

    let log = InteractionLog::new(&trace);
    let mut exp = Expectations::new(&log);
    for value in expected_values {
        exp.remove(usize::from(boundary_row), &RangeMsg { value });
    }
    log.assert_contains(&exp);
    for value in expected_values {
        assert_eq!(
            log.net_multiplicity(&RangeMsg { value }),
            ZERO,
            "unbalanced Merkle-index range-check value {value}"
        );
    }
}

/// Rejects nonzero capacity on a Merkle input after level 0.
///
/// The controller constraint requires zero capacity. This test changes only the controller trace,
/// so the controller-to-permutation lookup also detects the mismatch; the lookup itself requires
/// equal capacities in the two traces, not zero capacity.
#[test]
fn merkle_later_level_capacity_tamper_is_rejected() {
    let trace = build_mpverify_trace::<2>(3);
    let main = trace.main_trace();
    let boundary_row = find_merkle_boundary_input_row(main);
    let level_1_input_row = boundary_row + 2;
    let ctrl = main.chiplet_cols(level_1_input_row).controller();
    assert_eq!(ctrl.is_boundary, ZERO, "row after the boundary pair must be a later level");
    assert_eq!(ctrl.s0, Felt::ONE, "expected a Merkle input row");

    let (core, mut chiplets, poseidon2) = main.to_air_matrices();
    controller_row_mut(&mut chiplets, level_1_input_row).state[RATE_LEN] += Felt::ONE;
    super::lookup::assert_trace_constraints_reject(&trace, core, chiplets, poseidon2);
}

/// For the non-canonical representative `index + Q`, the wrapped slack has `y3 = 2^16 - 1`.
/// The emitted check for `2*y3` is therefore outside the 16-bit range, even though the four plain
/// limb checks and the field equations still pass.
#[test]
fn merkle_index_alias_emits_out_of_range_doubled_top_limb() {
    const INDEX: u64 = 1_000;

    let trace = build_mpverify_trace::<MAX_MERKLE_DEPTH>(INDEX);
    let main = trace.main_trace();
    let boundary_row = find_merkle_boundary_input_row(main);
    let (core, mut chiplets, poseidon2) = main.to_air_matrices();

    let non_canonical_index = INDEX + Felt::ORDER_U64;
    let index_next = non_canonical_index >> 1;
    let direction_bit = non_canonical_index & 1;
    let slack_limbs = canonicality_slack_limbs(index_next, direction_bit);
    assert_eq!(slack_limbs[3], Felt::from_u16(u16::MAX));

    {
        let input = controller_row_mut(&mut chiplets, boundary_row);
        input.direction_bit = Felt::new_unchecked(direction_bit);
        input.state[RATE_LEN..].copy_from_slice(&slack_limbs);
    }
    controller_row_mut(&mut chiplets, boundary_row + 1).node_index =
        Felt::new_unchecked(index_next);

    // Both the level-0 decomposition and the slack equation still hold in the field.
    assert_eq!(
        Felt::new_unchecked(INDEX),
        Felt::new_unchecked(index_next).double() + Felt::new_unchecked(direction_bit)
    );
    let reconstructed_slack = slack_limbs[0]
        + slack_limbs[1] * Felt::from_u64(1 << 16)
        + slack_limbs[2] * Felt::from_u64(1 << 32)
        + slack_limbs[3] * Felt::from_u64(1 << 48);
    assert_eq!(
        Felt::new_unchecked(index_next) + reconstructed_slack + Felt::new_unchecked(direction_bit),
        Felt::new_unchecked(MAX_MERKLE_INDEX_HALF)
    );

    let doubled_top_limb = slack_limbs[3].double();
    assert!(doubled_top_limb.as_canonical_u64() >= 1 << 16);
    let message = RangeMsg { value: doubled_top_limb };
    let log = InteractionLog::from_air_matrices(&core, &chiplets, &poseidon2);
    let mut exp = Expectations::new(&log);
    exp.remove(usize::from(boundary_row), &message);
    log.assert_contains(&exp);
    assert_eq!(log.net_multiplicity(&message), -Felt::ONE);
}

/// Replaces all 64 path bits with the bits of `index + Q`. Equal siblings keep every hash unchanged
/// when the direction bits change, so rejection must come from the level-0 canonicality check.
#[test]
fn merkle_index_canonicality_rejects_depth_64_i_plus_q_representative() {
    const INDEX: u64 = 1_000;
    const DEPTH: usize = MAX_MERKLE_DEPTH as usize;

    let value = test_word(7);
    let mut current = value;
    let mut siblings = Vec::with_capacity(DEPTH);
    for _ in 0..DEPTH {
        siblings.push(current);
        current = Poseidon2::merge(&[current, current]);
    }

    let path = MerklePath::new(siblings);
    let mut store = MerkleStore::new();
    let root = store.add_merkle_path(INDEX, value, path).unwrap();
    assert_eq!(root, current);

    let mut runtime_stack = Vec::new();
    runtime_stack.extend(word_to_ints(value));
    runtime_stack.push(DEPTH as u64);
    runtime_stack.push(INDEX);
    runtime_stack.extend(word_to_ints(root));
    let trace = build_trace_from_ops_with_inputs(
        vec![Operation::MpVerify(ZERO)],
        stack_inputs_from_ints(runtime_stack),
        AdviceInputs::default().with_merkle_store(store),
    );
    trace.check_constraints();

    let main = trace.main_trace();
    let input_rows: Vec<RowIndex> = (0..main.chiplets_height())
        .map(RowIndex::from)
        .filter(|&row| {
            if !main.is_hash_row(row) {
                return false;
            }
            let ctrl = main.chiplet_cols(row).controller();
            ctrl.s0 == Felt::ONE && ctrl.s1 == ZERO && ctrl.s2 == Felt::ONE
        })
        .collect();
    assert_eq!(input_rows.len(), DEPTH);

    let non_canonical_index = INDEX + Felt::ORDER_U64;
    let (core, mut chiplets, poseidon2) = main.to_air_matrices();
    for (level, input_row) in input_rows.into_iter().enumerate() {
        let input_index = non_canonical_index >> level;
        let output_index = non_canonical_index.checked_shr((level + 1) as u32).unwrap_or(0);
        let input_bit = input_index & 1;
        let output_bit = if level + 1 == DEPTH { 0 } else { output_index & 1 };

        {
            let input = controller_row_mut(&mut chiplets, input_row);
            input.node_index = Felt::new_unchecked(input_index % Felt::ORDER_U64);
            input.direction_bit = Felt::new_unchecked(input_bit);
        }

        let output = controller_row_mut(&mut chiplets, input_row + 1);
        output.node_index = Felt::new_unchecked(output_index);
        output.direction_bit = Felt::new_unchecked(output_bit);
    }

    super::lookup::assert_trace_constraints_reject(&trace, core, chiplets, poseidon2);
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
    let (honest_core, chip_matrix, poseidon2_matrix) = main.to_air_matrices();
    let first_unsupported_depth = Felt::new_unchecked(u64::from(MAX_MERKLE_DEPTH) + 1);

    for forged_depth in [ZERO, first_unsupported_depth, Felt::NEG_ONE] {
        let mut forged_core = honest_core.clone();
        set_stack_element(&mut forged_core, op_row, 4, forged_depth);

        let log = InteractionLog::from_air_matrices(&forged_core, &chip_matrix, &poseidon2_matrix);
        let scaled_depth = (forged_depth - Felt::ONE) * Felt::from_u16(MERKLE_DEPTH_RANGE_SCALE);
        let messages = [RangeMsg { value: forged_depth }, RangeMsg { value: scaled_depth }];
        let mut exp = Expectations::new(&log);
        for message in &messages {
            exp.remove(usize::from(op_row), message);
        }
        let return_addr = helper0 + forged_depth * CONTROLLER_ROWS_PER_PERM_FELT - Felt::ONE;
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
/// constraints) and `w0`, `w1`, `4·w1` (the word-address decomposition).
///
/// The address `262148 = 4 · 65537` is word-aligned with `word_index = 65537 = 0x10001`, so
/// `w0 = 1`, `w1 = 1`, `4·w1 = 4` — a non-trivial decomposition that exercises the full
/// five-way range-check batch.
#[test]
fn memory_chiplet_row_emits_range_check_removes() {
    let addr: u64 = 262148;
    let stack_input = stack![addr, 1, 2, 3, 4, addr];

    let operations = vec![
        Operation::MStoreW,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::MLoadW,
    ];
    let trace = build_trace_from_ops(operations, &stack_input);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    // Collect every memory chiplet row — we expect exactly two for the two memory ops.
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

/// Every Core row carries the range table's response: a `RangeMsg { value: v }` add with runtime
/// multiplicity `m`. A `U32add` with inputs 1 and 255 provides known demand: three checks of 0 and
/// one check of 256.
///
/// This pins the raw per-row table interactions in addition to the aggregate bus-balance checks
/// above, catching a misread multiplicity or value column and a missing always-active gate.
#[test]
fn range_checker_table_emits_per_row_adds() {
    let stack = [1, 255];
    let operations = vec![Operation::U32add];
    let trace = build_trace_from_ops(operations, &stack);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    assert_eq!(range_table_multiplicity(main, ZERO), 3);
    assert_eq!(range_table_multiplicity(main, Felt::from_u16(256)), 1);

    // Include zero-multiplicity rows: the table emitter is structurally active on every Core row.
    let mut exp = Expectations::new(&log);
    for row in 0..main.core_height() {
        let idx = RowIndex::from(row);
        let range = &main.core_row(idx).range;
        let m = range.multiplicity;
        let v = range.value;
        exp.push(row, m, &RangeMsg { value: v });
    }

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

fn range_table_multiplicity(main: &MainTrace, value: Felt) -> u64 {
    (0..main.core_height())
        .map(RowIndex::from)
        .filter_map(|row| {
            let range = &main.core_row(row).range;
            (range.value == value).then(|| range.multiplicity.as_canonical_u64())
        })
        .sum()
}

fn find_merkle_boundary_input_row(main: &MainTrace) -> RowIndex {
    (0..main.chiplets_height())
        .map(RowIndex::from)
        .find(|&row| {
            if !main.is_hash_row(row) {
                return false;
            }
            let ctrl = main.chiplet_cols(row).controller();
            ctrl.s0 == Felt::ONE
                && (ctrl.s1 == Felt::ONE || ctrl.s2 == Felt::ONE)
                && ctrl.is_boundary == Felt::ONE
        })
        .expect("missing Merkle boundary input row")
}

fn controller_row_mut(
    chip_matrix: &mut RowMajorMatrix<Felt>,
    row: RowIndex,
) -> &mut ControllerCols<Felt> {
    let width = chip_matrix.width();
    let start = usize::from(row) * width + CHIPLET_CONTROLLER_OFFSET;
    chip_matrix.values[start..start + CONTROLLER_WIDTH].borrow_mut()
}

fn canonicality_slack_limbs(index_next: u64, direction_bit: u64) -> [Felt; 4] {
    const LIMB_MASK: u64 = (1 << 16) - 1;

    let slack = (Felt::new_unchecked(MAX_MERKLE_INDEX_HALF)
        - Felt::new_unchecked(index_next)
        - Felt::new_unchecked(direction_bit))
    .as_canonical_u64();
    core::array::from_fn(|i| Felt::new_unchecked((slack >> (16 * i)) & LIMB_MASK))
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
