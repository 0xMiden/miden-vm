//! Hasher-chiplet bus tests.
//!
//! For each of the main hasher scenarios (SPAN/END control block, RESPAN, SPLIT merge, HPERM,
//! LOGPRECOMPILE, MPVERIFY, MRUPDATE) the test registers the decoder-side `remove` requests and
//! the chiplet-side `add` responses it expects to see, then lets
//! [`InteractionLog::assert_contains`] confirm every one of them fires somewhere in the trace.
//!
//! Because request and response messages share a `bus_prefix` and the same payload shape,
//! an add at a controller row and a remove at the matching decoder row produce the same
//! encoded denominator with opposite multiplicities — which is what makes the bus balance.
//! We don't need to pin the running-product walk row-by-row the way the legacy
//! `verify_b_chip_step_by_step` did; the subset matcher verifies each claimed interaction
//! lands, and their pairing is an algebraic consequence.
//!
//! Each test pairs the `assert_contains` call with explicit request/response-count guardrails
//! so a silent-pass bug (e.g. the subset matcher ignoring a whole category of expectations
//! because nothing was registered) is caught structurally, not just by shape.

use alloc::vec::Vec;

use miden_air::{
    logup::{HasherMsg, SiblingBit, SiblingMsg},
    trace::{
        MainTrace,
        chiplets::hasher::CONTROLLER_ROWS_PER_PERM_FELT,
        log_precompile::{
            HELPER_ADDR_IDX, HELPER_CAP_PREV_RANGE, STACK_CAP_NEXT_RANGE, STACK_COMM_RANGE,
            STACK_R0_RANGE, STACK_R1_RANGE, STACK_TAG_RANGE,
        },
    },
};
use miden_core::{
    Felt, ONE, Word, ZERO,
    crypto::merkle::{MerkleStore, MerkleTree, NodeIndex},
    mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor, SplitNodeBuilder},
    operations::{Operation, opcodes},
    program::Program,
};
use miden_utils_testing::stack;
use rstest::rstest;

use super::super::{
    build_trace_from_ops_with_inputs, build_trace_from_program,
    lookup_harness::{Expectations, InteractionLog},
};
use crate::{AdviceInputs, RowIndex, StackInputs, trace::utils::build_span_with_respan_ops};

// RESPONSE-SIDE DISPATCH
// ================================================================================================

/// Hasher controller response kinds, keyed on the emitter's `(hs0, hs1, hs2, is_boundary)` mux.
///
/// Shared across every test so each can `match` on the semantic kind instead of re-deriving
/// the selector combinations (`ctrl · hs0 · not_hs1 · not_hs2 · is_boundary`, etc.) by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HasherResponseKind {
    SpongeStart,
    SpongeRespan,
    MpInput,
    MvOldInput,
    MuNewInput,
    Hout,
    Sout,
}

/// Walk every hasher controller row in `main` and yield a [`HasherResponseKind`] for each row
/// that matches one of the 7 emitter patterns (see `chiplet_responses.rs::emit_chiplet_responses`
/// and `docs/src/design/chiplets/hasher.md`).
///
/// Controller rows where no response fires (e.g. Merkle tree continuation rows where
/// `is_boundary = 0`) are skipped.
fn hasher_response_rows(
    main: &MainTrace,
) -> impl Iterator<Item = (RowIndex, HasherResponseKind)> + '_ {
    (0..main.num_rows()).filter_map(move |row| {
        let idx = RowIndex::from(row);
        if !is_hasher_controller_row(main, idx) {
            return None;
        }
        let hs0 = main.chiplet_selector_1(idx);
        let hs1 = main.chiplet_selector_2(idx);
        let hs2 = main.chiplet_selector_3(idx);
        let is_boundary = main.chiplet_is_boundary(idx);
        let kind = if hs0 == ONE && hs1 == ZERO && hs2 == ZERO && is_boundary == ONE {
            HasherResponseKind::SpongeStart
        } else if hs0 == ONE && hs1 == ZERO && hs2 == ZERO && is_boundary == ZERO {
            HasherResponseKind::SpongeRespan
        } else if hs0 == ONE && hs1 == ZERO && hs2 == ONE && is_boundary == ONE {
            HasherResponseKind::MpInput
        } else if hs0 == ONE && hs1 == ONE && hs2 == ZERO && is_boundary == ONE {
            HasherResponseKind::MvOldInput
        } else if hs0 == ONE && hs1 == ONE && hs2 == ONE && is_boundary == ONE {
            HasherResponseKind::MuNewInput
        } else if hs0 == ZERO && hs1 == ZERO && hs2 == ZERO {
            HasherResponseKind::Hout
        } else if hs0 == ZERO && hs1 == ZERO && hs2 == ONE && is_boundary == ONE {
            HasherResponseKind::Sout
        } else {
            return None;
        };
        Some((idx, kind))
    })
}

// TESTS
// ================================================================================================

#[test]
fn span_end_hasher_bus() {
    let program = single_block_program(vec![Operation::Add, Operation::Mul]);

    let trace = build_trace_from_program(&program, &[]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut exp = Expectations::new(&log);
    let mut request_count = 0usize;

    for row in 0..main.num_rows() {
        let idx = RowIndex::from(row);
        let op = main.get_op_code(idx).as_canonical_u64();

        if op == opcodes::SPAN as u64 {
            let addr_next = main.addr(RowIndex::from(row + 1));
            let rate = rate_from_hasher_state(main, idx);
            exp.remove(row, &HasherMsg::control_block(addr_next, &rate, 0));
            request_count += 1;
        } else if op == opcodes::END as u64 {
            let parent = main.addr(idx) + CONTROLLER_ROWS_PER_PERM_FELT - ONE;
            let h = rate_from_hasher_state(main, idx);
            let digest: [Felt; 4] = [h[0], h[1], h[2], h[3]];
            exp.remove(row, &HasherMsg::return_hash(parent, digest));
            request_count += 1;
        }
    }

    let mut response_count = 0usize;
    for (idx, kind) in hasher_response_rows(main) {
        let addr = main.clk(idx) + ONE;
        let state = main.chiplet_hasher_state(idx);
        match kind {
            HasherResponseKind::SpongeStart => {
                exp.add(usize::from(idx), &HasherMsg::linear_hash_init(addr, state));
                response_count += 1;
            },
            HasherResponseKind::Hout => {
                let digest: [Felt; 4] = [state[0], state[1], state[2], state[3]];
                exp.add(usize::from(idx), &HasherMsg::return_hash(addr, digest));
                response_count += 1;
            },
            _ => {},
        }
    }

    assert_eq!(request_count, 2, "SPAN+END: expected 2 removes (SPAN + END)");
    assert_eq!(response_count, 2, "SPAN+END: expected 2 adds (sponge_start + HOUT)");
    log.assert_contains(&exp);
}

#[test]
fn respan_hasher_bus() {
    let (ops, _iv) = build_span_with_respan_ops();
    let program = single_block_program(ops);

    let trace = build_trace_from_program(&program, &[]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut exp = Expectations::new(&log);
    let mut respan_request_count = 0usize;

    for row in 0..main.num_rows() {
        let idx = RowIndex::from(row);
        let op = main.get_op_code(idx).as_canonical_u64();
        if op != opcodes::RESPAN as u64 {
            continue;
        }
        let addr_next = main.addr(RowIndex::from(row + 1));
        let rate = rate_from_hasher_state(main, idx);
        exp.remove(row, &HasherMsg::absorption(addr_next, rate));
        respan_request_count += 1;
    }

    let mut sponge_respan_count = 0usize;
    for (idx, kind) in hasher_response_rows(main) {
        if kind != HasherResponseKind::SpongeRespan {
            continue;
        }
        let addr = main.clk(idx) + ONE;
        let state = main.chiplet_hasher_state(idx);
        let rate: [Felt; 8] =
            [state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]];
        exp.add(usize::from(idx), &HasherMsg::absorption(addr, rate));
        sponge_respan_count += 1;
    }

    assert!(respan_request_count > 0, "multi-batch span should emit at least one RESPAN");
    assert_eq!(
        respan_request_count, sponge_respan_count,
        "each RESPAN request must be paired with a sponge_respan response",
    );
    log.assert_contains(&exp);
}

#[test]
fn merge_hasher_bus() {
    let program = {
        let mut mast_forest = MastForest::new();
        let t_branch = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let f_branch = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let split_id = SplitNodeBuilder::new([t_branch, f_branch])
            .add_to_forest(&mut mast_forest)
            .unwrap();
        mast_forest.make_root(split_id);
        Program::new(mast_forest.into(), split_id)
    };

    let trace = build_trace_from_program(&program, &[]);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut exp = Expectations::new(&log);
    let mut split_request_count = 0usize;

    for row in 0..main.num_rows() {
        let idx = RowIndex::from(row);
        let op = main.get_op_code(idx).as_canonical_u64();
        if op != opcodes::SPLIT as u64 {
            continue;
        }
        let addr_next = main.addr(RowIndex::from(row + 1));
        let rate = rate_from_hasher_state(main, idx);
        exp.remove(row, &HasherMsg::control_block(addr_next, &rate, opcodes::SPLIT));
        split_request_count += 1;
    }

    let mut split_response_count = 0usize;
    for (idx, kind) in hasher_response_rows(main) {
        if kind != HasherResponseKind::SpongeStart {
            continue;
        }
        let addr = main.clk(idx) + ONE;
        let state = main.chiplet_hasher_state(idx);
        // SPLIT's own hasher response carries opcode `SPLIT` at capacity[1] (position 9 of the
        // 12-lane state); sibling SPAN sponge_start rows carry opcode 0.
        if state[9] == Felt::from(opcodes::SPLIT) {
            exp.add(usize::from(idx), &HasherMsg::linear_hash_init(addr, state));
            split_response_count += 1;
        }
    }

    assert_eq!(split_request_count, 1, "single SPLIT program should emit one SPLIT remove");
    assert_eq!(
        split_response_count, 1,
        "single SPLIT program should emit one SPLIT-capacity sponge_start",
    );
    log.assert_contains(&exp);
}

#[test]
fn hperm_hasher_bus() {
    let program = single_block_program(vec![Operation::HPerm]);
    let stack = vec![8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 8];
    let trace = build_trace_from_program(&program, &stack);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut exp = Expectations::new(&log);
    let mut request_count = 0usize;
    let mut hperm_helper0: Option<Felt> = None;
    for row in 0..main.num_rows() {
        let idx = RowIndex::from(row);
        let op = main.get_op_code(idx).as_canonical_u64();
        if op != opcodes::HPERM as u64 {
            continue;
        }

        let helper0 = main.helper_register(0, idx);
        hperm_helper0 = Some(helper0);
        let next = RowIndex::from(row + 1);
        let stk_state: [Felt; 12] = core::array::from_fn(|i| main.stack_element(i, idx));
        let stk_next_state: [Felt; 12] = core::array::from_fn(|i| main.stack_element(i, next));
        exp.remove(row, &HasherMsg::linear_hash_init(helper0, stk_state));
        exp.remove(
            row,
            &HasherMsg::return_state(helper0 + CONTROLLER_ROWS_PER_PERM_FELT - ONE, stk_next_state),
        );
        request_count += 2;
    }
    let hperm_helper0 = hperm_helper0.expect("program should contain an HPERM row");
    let hperm_return_addr = hperm_helper0 + CONTROLLER_ROWS_PER_PERM_FELT - ONE;

    let mut sponge_start_count = 0usize;
    let mut sout_count = 0usize;
    for (idx, kind) in hasher_response_rows(main) {
        let addr = main.clk(idx) + ONE;
        let state = main.chiplet_hasher_state(idx);
        match kind {
            HasherResponseKind::SpongeStart => {
                exp.add(usize::from(idx), &HasherMsg::linear_hash_init(addr, state));
                // Only the HPERM-paired sponge_start matches `hperm_helper0`; the outer
                // SPAN/END controller rows live on their own `addr` track.
                if addr == hperm_helper0 {
                    sponge_start_count += 1;
                }
            },
            HasherResponseKind::Sout => {
                exp.add(usize::from(idx), &HasherMsg::return_state(addr, state));
                if addr == hperm_return_addr {
                    sout_count += 1;
                }
            },
            _ => {},
        }
    }

    assert_eq!(request_count, 2, "HPERM: expected 2 removes (init + return)");
    assert_eq!(sponge_start_count, 1, "HPERM: expected 1 HPERM-paired sponge_start");
    assert_eq!(sout_count, 1, "HPERM: expected 1 HPERM-paired SOUT");
    log.assert_contains(&exp);
}

#[test]
fn logprecompile_hasher_bus() {
    let program = single_block_program(vec![Operation::LogPrecompile]);
    let stack_inputs = stack![5, 6, 7, 8, 1, 2, 3, 4];
    let trace = build_trace_from_program(&program, &stack_inputs);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut exp = Expectations::new(&log);
    let mut request_count = 0usize;
    let mut logprecompile_addr: Option<Felt> = None;
    for row in 0..main.num_rows() {
        let idx = RowIndex::from(row);
        let op = main.get_op_code(idx).as_canonical_u64();
        if op != opcodes::LOGPRECOMPILE as u64 {
            continue;
        }

        let next = RowIndex::from(row + 1);
        let log_addr = main.helper_register(HELPER_ADDR_IDX, idx);
        logprecompile_addr = Some(log_addr);

        // Input: [COMM, TAG, CAP_PREV] — 8 stack lanes + 4 helper registers.
        let input_state: [Felt; 12] = core::array::from_fn(|i| {
            if i < 4 {
                main.stack_element(STACK_COMM_RANGE.start + i, idx)
            } else if i < 8 {
                main.stack_element(STACK_TAG_RANGE.start + (i - 4), idx)
            } else {
                main.helper_register(HELPER_CAP_PREV_RANGE.start + (i - 8), idx)
            }
        });

        // Output (next row): [R0, R1, CAP_NEXT] — all 12 lanes from stack.
        let output_state: [Felt; 12] = core::array::from_fn(|i| {
            if i < 4 {
                main.stack_element(STACK_R0_RANGE.start + i, next)
            } else if i < 8 {
                main.stack_element(STACK_R1_RANGE.start + (i - 4), next)
            } else {
                main.stack_element(STACK_CAP_NEXT_RANGE.start + (i - 8), next)
            }
        });

        exp.remove(row, &HasherMsg::linear_hash_init(log_addr, input_state));
        exp.remove(
            row,
            &HasherMsg::return_state(log_addr + CONTROLLER_ROWS_PER_PERM_FELT - ONE, output_state),
        );
        request_count += 2;
    }
    let log_addr = logprecompile_addr.expect("program should contain a LOGPRECOMPILE row");
    let log_return_addr = log_addr + CONTROLLER_ROWS_PER_PERM_FELT - ONE;

    let mut sponge_start_count = 0usize;
    let mut sout_count = 0usize;
    for (idx, kind) in hasher_response_rows(main) {
        let addr = main.clk(idx) + ONE;
        let state = main.chiplet_hasher_state(idx);
        match kind {
            HasherResponseKind::SpongeStart => {
                exp.add(usize::from(idx), &HasherMsg::linear_hash_init(addr, state));
                if addr == log_addr {
                    sponge_start_count += 1;
                }
            },
            HasherResponseKind::Sout => {
                exp.add(usize::from(idx), &HasherMsg::return_state(addr, state));
                if addr == log_return_addr {
                    sout_count += 1;
                }
            },
            _ => {},
        }
    }

    assert_eq!(request_count, 2, "LOGPRECOMPILE: expected 2 removes (init + return)");
    assert_eq!(
        sponge_start_count, 1,
        "LOGPRECOMPILE: expected 1 LOGPRECOMPILE-paired sponge_start"
    );
    assert_eq!(sout_count, 1, "LOGPRECOMPILE: expected 1 LOGPRECOMPILE-paired SOUT");
    log.assert_contains(&exp);
}

#[test]
fn mpverify_hasher_bus() {
    let index = 5usize;
    let leaves = init_leaves(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(&leaves).unwrap();

    let mut runtime_stack = Vec::new();
    runtime_stack.extend_from_slice(&word_to_ints(leaves[index]));
    runtime_stack.push(tree.depth() as u64);
    runtime_stack.push(index as u64);
    runtime_stack.extend_from_slice(&word_to_ints(tree.root()));
    let stack_inputs = StackInputs::try_from_ints(runtime_stack).unwrap();
    let store = MerkleStore::from(&tree);
    let advice_inputs = AdviceInputs::default().with_merkle_store(store);

    let trace = build_trace_from_ops_with_inputs(
        vec![Operation::MpVerify(ZERO)],
        stack_inputs,
        advice_inputs,
    );
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut exp = Expectations::new(&log);
    let mut request_count = 0usize;

    for row in 0..main.num_rows() {
        let idx = RowIndex::from(row);
        let op = main.get_op_code(idx).as_canonical_u64();
        if op != opcodes::MPVERIFY as u64 {
            continue;
        }
        let helper0 = main.helper_register(0, idx);
        let mp_depth = main.stack_element(4, idx);
        let mp_index = main.stack_element(5, idx);
        let leaf_word: [Felt; 4] = core::array::from_fn(|i| main.stack_element(i, idx));
        let old_root: [Felt; 4] = core::array::from_fn(|i| main.stack_element(6 + i, idx));

        let return_addr = helper0 + mp_depth * CONTROLLER_ROWS_PER_PERM_FELT - ONE;
        exp.remove(row, &HasherMsg::merkle_verify_init(helper0, mp_index, leaf_word));
        exp.remove(row, &HasherMsg::return_hash(return_addr, old_root));
        request_count += 2;
    }

    let mut mp_input_count = 0usize;
    let mut hout_count = 0usize;
    for (idx, kind) in hasher_response_rows(main) {
        let addr = main.clk(idx) + ONE;
        let state = main.chiplet_hasher_state(idx);
        let rate_0: [Felt; 4] = [state[0], state[1], state[2], state[3]];
        let rate_1: [Felt; 4] = [state[4], state[5], state[6], state[7]];
        match kind {
            HasherResponseKind::MpInput => {
                let node_index = main.chiplet_node_index(idx);
                // Match the emitter's own `bit = node_index - 2·node_index_next` formula rather
                // than reading `chiplet_direction_bit`: keeps this assertion independent of the
                // column whose constraints are under test.
                let bit = merkle_direction_bit(main, idx);
                let word: [Felt; 4] = if bit == ZERO { rate_0 } else { rate_1 };
                exp.add(usize::from(idx), &HasherMsg::merkle_verify_init(addr, node_index, word));
                mp_input_count += 1;
            },
            HasherResponseKind::Hout => {
                // `chiplet_node_index(idx)` is `ZERO` at MPVERIFY's final HOUT row (Merkle walk
                // terminates with node_index halved to 0). Using `return_hash` keeps the test
                // aligned with the decoder-side `HasherMsg::return_hash(...)` shape.
                exp.add(usize::from(idx), &HasherMsg::return_hash(addr, rate_0));
                hout_count += 1;
            },
            _ => {},
        }
    }

    assert_eq!(request_count, 2, "MPVERIFY: expected 2 removes (init + return)");
    assert_eq!(mp_input_count, 1, "MPVERIFY: expected 1 mp_verify_input add");
    // Depth-3 MPVERIFY emits HOUT on every merkle-verify sub-cycle return (one per level).
    assert_eq!(hout_count, 2, "MPVERIFY: expected exactly 2 HOUT adds");
    log.assert_contains(&exp);
}

#[test]
fn mrupdate_hasher_bus() {
    let index = 5usize;
    let leaves = init_leaves(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(&leaves).unwrap();
    let new_leaf_value = leaves[0];

    let mut runtime_stack = Vec::new();
    runtime_stack.extend_from_slice(&word_to_ints(leaves[index]));
    runtime_stack.push(tree.depth() as u64);
    runtime_stack.push(index as u64);
    runtime_stack.extend_from_slice(&word_to_ints(tree.root()));
    runtime_stack.extend_from_slice(&word_to_ints(new_leaf_value));
    let stack_inputs = StackInputs::try_from_ints(runtime_stack).unwrap();
    let store = MerkleStore::from(&tree);
    let advice_inputs = AdviceInputs::default().with_merkle_store(store);

    let trace =
        build_trace_from_ops_with_inputs(vec![Operation::MrUpdate], stack_inputs, advice_inputs);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    let mut exp = Expectations::new(&log);
    let mut request_count = 0usize;

    for row in 0..main.num_rows() {
        let idx = RowIndex::from(row);
        let op = main.get_op_code(idx).as_canonical_u64();
        if op != opcodes::MRUPDATE as u64 {
            continue;
        }
        let helper0 = main.helper_register(0, idx);
        let next = RowIndex::from(row + 1);
        let mr_depth = main.stack_element(4, idx);
        let mr_index = main.stack_element(5, idx);
        let old_leaf: [Felt; 4] = core::array::from_fn(|i| main.stack_element(i, idx));
        let old_root: [Felt; 4] = core::array::from_fn(|i| main.stack_element(6 + i, idx));
        let new_leaf: [Felt; 4] = core::array::from_fn(|i| main.stack_element(10 + i, idx));
        let new_root: [Felt; 4] = core::array::from_fn(|i| main.stack_element(i, next));

        let old_return = helper0 + mr_depth * CONTROLLER_ROWS_PER_PERM_FELT - ONE;
        let new_init = helper0 + mr_depth * CONTROLLER_ROWS_PER_PERM_FELT;
        let new_return = helper0
            + mr_depth * (CONTROLLER_ROWS_PER_PERM_FELT + CONTROLLER_ROWS_PER_PERM_FELT)
            - ONE;

        exp.remove(row, &HasherMsg::merkle_old_init(helper0, mr_index, old_leaf));
        exp.remove(row, &HasherMsg::return_hash(old_return, old_root));
        exp.remove(row, &HasherMsg::merkle_new_init(new_init, mr_index, new_leaf));
        exp.remove(row, &HasherMsg::return_hash(new_return, new_root));
        request_count += 4;
    }

    let mut mv_count = 0usize;
    let mut mu_count = 0usize;
    let mut hout_count = 0usize;
    for (idx, kind) in hasher_response_rows(main) {
        let addr = main.clk(idx) + ONE;
        let state = main.chiplet_hasher_state(idx);
        let rate_0: [Felt; 4] = [state[0], state[1], state[2], state[3]];
        let rate_1: [Felt; 4] = [state[4], state[5], state[6], state[7]];
        let node_index = main.chiplet_node_index(idx);
        let bit = merkle_direction_bit(main, idx);
        let word: [Felt; 4] = if bit == ZERO { rate_0 } else { rate_1 };

        match kind {
            HasherResponseKind::MvOldInput => {
                exp.add(usize::from(idx), &HasherMsg::merkle_old_init(addr, node_index, word));
                mv_count += 1;
            },
            HasherResponseKind::MuNewInput => {
                exp.add(usize::from(idx), &HasherMsg::merkle_new_init(addr, node_index, word));
                mu_count += 1;
            },
            HasherResponseKind::Hout => {
                exp.add(usize::from(idx), &HasherMsg::return_hash(addr, rate_0));
                hout_count += 1;
            },
            _ => {},
        }
    }

    assert_eq!(
        request_count, 4,
        "MRUPDATE: expected 4 removes (old_init + old_return + new_init + new_return)",
    );
    assert_eq!(mv_count, 1, "MRUPDATE: expected 1 mr_update_old_input add");
    assert_eq!(mu_count, 1, "MRUPDATE: expected 1 mr_update_new_input add");
    // Depth-3 MRUPDATE emits HOUT on each old-path and new-path sub-cycle return.
    assert_eq!(hout_count, 3, "MRUPDATE: expected exactly 3 HOUT adds");
    log.assert_contains(&exp);
}

// HELPERS
// ================================================================================================

fn single_block_program(ops: Vec<Operation>) -> Program {
    let mut mast_forest = MastForest::new();
    let id = BasicBlockNodeBuilder::new(ops, Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    mast_forest.make_root(id);
    Program::new(mast_forest.into(), id)
}

fn rate_from_hasher_state(main: &MainTrace, row: RowIndex) -> [Felt; 8] {
    let first = main.decoder_hasher_state_first_half(row);
    let second = main.decoder_hasher_state_second_half(row);
    [
        first[0], first[1], first[2], first[3], second[0], second[1], second[2], second[3],
    ]
}

fn is_hasher_controller_row(main: &MainTrace, row: RowIndex) -> bool {
    main.chiplet_selector_0(row) == ONE && main.chiplet_s_perm(row) == ZERO
}

/// Recompute the Merkle direction bit the emitter uses: `bit = node_index - 2·node_index_next`
/// (see `chiplet_responses.rs::mp_verify_input`). Independent of the `chiplet_direction_bit`
/// column, so bugs in that column don't make the assertion vacuously pass.
fn merkle_direction_bit(main: &MainTrace, row: RowIndex) -> Felt {
    let next = RowIndex::from(usize::from(row) + 1);
    main.chiplet_node_index(row) - main.chiplet_node_index(next).double()
}

// SIBLING TABLE BUS (MRUPDATE add/remove pairing)
// ================================================================================================
//
// MRUPDATE verifies the old Merkle root (MV leg, adds to sibling table) and then recomputes
// the new root (MU leg, removes from sibling table). Each of the 3 levels of a depth-3 tree
// emits one add on the MV leg and one remove on the MU leg, matched by `(mrupdate_id,
// node_index, sibling_word)`.
//
// The test iterates every hasher controller row, picks out the MV/MU sibling-emitting rows
// via the `(s0, s1, s2)` sub-selectors, and attaches a `SiblingMsg` expectation tagged with
// the direction bit. Column-blind — the subset matcher finds each message regardless of
// where the M4/C2 packing puts it.

/// Drive a depth-3 Merkle MRUPDATE and assert the sibling-table bus fires one add per MV
/// controller row and one remove per MU controller row (3 levels → 3 adds + 3 removes).
#[rstest]
#[case(5_u64)]
#[case(4_u64)]
fn mrupdate_emits_sibling_add_and_remove_per_level(#[case] index: u64) {
    let (tree, _) = build_merkle_tree();
    let old_node = tree.get_node(NodeIndex::new(3, index).unwrap()).unwrap();
    let new_node = init_leaf(11);

    // Build the program inputs the way the legacy test did.
    let mut init_stack = Vec::new();
    init_stack.extend_from_slice(&word_to_ints(old_node));
    init_stack.extend_from_slice(&[3, index]);
    init_stack.extend_from_slice(&word_to_ints(tree.root()));
    init_stack.extend_from_slice(&word_to_ints(new_node));
    let stack_inputs = StackInputs::try_from_ints(init_stack).unwrap();
    let store = MerkleStore::from(&tree);
    let advice_inputs = AdviceInputs::default().with_merkle_store(store);

    let ops = vec![Operation::MrUpdate];
    let trace = build_trace_from_ops_with_inputs(ops, stack_inputs, advice_inputs);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    // Collect MV / MU controller rows. A row is a sibling-table add/remove site when
    // `chiplet_active.controller = 1` (s_ctrl column) AND the hasher internal
    // `(s0, s1, s2)` sub-selectors pick out the MV-all (`s0·s1·(1-s2)`) or MU-all
    // (`s0·s1·s2`) pattern. See `air/src/constraints/lookup/buses/hash_kernel.rs`.
    let mut mv_rows: Vec<RowIndex> = Vec::new();
    let mut mu_rows: Vec<RowIndex> = Vec::new();
    for row in 0..main.num_rows() {
        let idx = RowIndex::from(row);
        if main.chiplet_selector_0(idx) != ONE || main.chiplet_s_perm(idx) != ZERO {
            continue;
        }
        let hs0 = main.chiplet_selector_1(idx);
        let hs1 = main.chiplet_selector_2(idx);
        let hs2 = main.chiplet_selector_3(idx);
        if hs0 == ONE && hs1 == ONE && hs2 == ZERO {
            mv_rows.push(idx);
        } else if hs0 == ONE && hs1 == ONE && hs2 == ONE {
            mu_rows.push(idx);
        }
    }
    assert_eq!(mv_rows.len(), 3, "depth-3 MRUPDATE should emit 3 MV sibling adds");
    assert_eq!(mu_rows.len(), 3, "depth-3 MRUPDATE should emit 3 MU sibling removes");

    let mut exp = Expectations::new(&log);
    for &row in &mv_rows {
        push_sibling(&mut exp, row, main, SiblingSide::Add);
    }
    for &row in &mu_rows {
        push_sibling(&mut exp, row, main, SiblingSide::Remove);
    }

    log.assert_contains(&exp);
}

enum SiblingSide {
    Add,
    Remove,
}

fn push_sibling(exp: &mut Expectations<'_>, row: RowIndex, main: &MainTrace, side: SiblingSide) {
    let mrupdate_id = main.chiplet_mrupdate_id(row);
    let node_index = main.chiplet_node_index(row);
    let state = main.chiplet_hasher_state(row);
    let rate_0: [Felt; 4] = [state[0], state[1], state[2], state[3]];
    let rate_1: [Felt; 4] = [state[4], state[5], state[6], state[7]];

    // Direction bit drives which rate half the sibling lives in. The trace's
    // `chiplet_direction_bit` column carries the extracted bit on Merkle controller rows.
    let bit = main.chiplet_direction_bit(row);
    let row_usize = usize::from(row);
    let (bit_tag, h) = if bit == ZERO {
        (SiblingBit::Zero, rate_1)
    } else {
        (SiblingBit::One, rate_0)
    };
    let msg = SiblingMsg { bit: bit_tag, mrupdate_id, node_index, h };
    match side {
        SiblingSide::Add => exp.add(row_usize, &msg),
        SiblingSide::Remove => exp.remove(row_usize, &msg),
    };
}

fn build_merkle_tree() -> (MerkleTree, Vec<Word>) {
    let leaves = init_leaves(&[1, 2, 3, 4, 5, 6, 7, 8]);
    (MerkleTree::new(leaves.clone()).unwrap(), leaves)
}

// MERKLE TEST HELPERS
// ================================================================================================

fn init_leaves(values: &[u64]) -> Vec<Word> {
    values.iter().map(|&v| init_leaf(v)).collect()
}

fn init_leaf(value: u64) -> Word {
    [Felt::new_unchecked(value), ZERO, ZERO, ZERO].into()
}

fn word_to_ints(word: Word) -> [u64; 4] {
    [
        word[0].as_canonical_u64(),
        word[1].as_canonical_u64(),
        word[2].as_canonical_u64(),
        word[3].as_canonical_u64(),
    ]
}

