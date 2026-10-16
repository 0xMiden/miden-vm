//! Regression tests for MRUPDATE sibling-level binding.
//!
//! An update recomputes the root along the old path and along the new path, and the sibling table
//! requires both legs of one invocation to consume the same siblings. Its key is
//! `(level, mrupdate_id, node_index, sibling)`, with direction-dependent sibling lanes. The hasher
//! shifts `node_index` right by one bit per level, so once it reaches zero every remaining level
//! carries the same `node_index` and direction bit. Omitting the level would let the new path
//! exchange siblings at those positions while keeping the sibling table balanced.
//!
//! The forgery starts from two honest updates of leaf 0 at depth 2, each replacing a node by
//! itself, with old paths `[a, b]` and `[b, a]`. Exchanging the new-path controller payloads of the
//! two invocations keeps every Eidos compression valid and the compression multiset unchanged, but
//! each update now returns the other tree's root, so a self-update changes the public outputs.

use alloc::vec::Vec;

use miden_air::trace::chiplets::hasher::{DIGEST_LEN, MR_UPDATE_NEW, NUM_SELECTORS, STATE_WIDTH};
use miden_core::{
    Felt, Word,
    advice::AdviceInputs,
    mast::{BasicBlockNodeBuilder, DenseMastForestBuilder},
    operations::{Operation, opcodes},
    program::{Program, StackOutputs},
    utils::{Matrix, RowMajorMatrix},
};
use miden_crypto::merkle::{MerklePath, store::MerkleStore};
use miden_processor::{DefaultHost, FastProcessor, StackInputs};

use crate::{
    Prover,
    repro_harness::{ReproTrace, core_row_mut},
};

/// The controller overlay starts after `s_ctrl`, the first chiplets column.
const CONTROLLER_OFFSET: usize = 1;

/// The controller payload `state[12] || row_data[4]` follows the three row-kind selectors.
const PAYLOAD_OFFSET: usize = CONTROLLER_OFFSET + NUM_SELECTORS;
const PAYLOAD_WIDTH: usize = STATE_WIDTH + DIGEST_LEN;

/// Ops that may carry a live forged result through the tail of the program.
const OPS_WITHOUT_STACK_EFFECT: [u8; 4] =
    [opcodes::NOOP, opcodes::RESPAN, opcodes::END, opcodes::HALT];

struct Fixture {
    repro: ReproTrace,
    core: RowMajorMatrix<Felt>,
    chiplets: RowMajorMatrix<Felt>,
    eidos_compression: RowMajorMatrix<Felt>,
    and8: RowMajorMatrix<Felt>,
    core_height: usize,
    /// Honest roots of the two trees, in invocation order.
    roots: [Word; 2],
    honest_outputs: [Felt; 16],
}

fn word(value: u64) -> Word {
    Word::new([Felt::new_unchecked(value); 4])
}

fn opcode_of(bits: [Felt; 7]) -> u8 {
    (0..7).map(|i| (bits[i].as_canonical_u64() as u8) << i).sum()
}

fn build_fixture() -> Fixture {
    let leaf = word(3);
    let a = word(5);
    let b = word(7);
    let mut store = MerkleStore::default();
    let roots = [
        store.add_merkle_path(0, leaf, MerklePath::new(alloc::vec![a, b])).unwrap(),
        store.add_merkle_path(0, leaf, MerklePath::new(alloc::vec![b, a])).unwrap(),
    ];
    assert_ne!(roots[0], roots[1], "the two trees must have distinct roots");

    // Each update replaces `leaf` by `leaf` at index 0, depth 2. The second update keeps two
    // result lanes on the stack while the drops empty the overflow table.
    let mut operations = Vec::new();
    for (position, root) in roots.iter().enumerate() {
        let mut stack = Vec::from(leaf.as_elements());
        stack.extend([Felt::new_unchecked(2), Felt::ZERO]);
        stack.extend(root.as_elements());
        stack.extend(leaf.as_elements());
        operations.extend(stack.into_iter().rev().map(Operation::Push));
        operations.push(Operation::MrUpdate);
        if position == 1 {
            operations.push(Operation::SwapW3);
        }
        operations.extend([Operation::Drop; 14]);
    }
    let mut builder = DenseMastForestBuilder::new();
    let root = builder.push_node(BasicBlockNodeBuilder::new(operations)).unwrap();
    builder.mark_root(root);
    let (forest, mapping) = builder.build_with_id_map().unwrap();
    let program = Program::new(forest.into(), mapping.get(root).unwrap());

    let mut host = DefaultHost::default();
    let (trace, precompile_witness) = FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default().with_merkle_store(store))
        .unwrap()
        .execute_and_build_trace_sync(&program, &mut host, Prover::DEFAULT_MAX_PROVER_MEMORY_BYTES)
        .unwrap();
    assert!(precompile_witness.is_none());

    let (core, chiplets, eidos_compression, and8) = trace.clone_air_matrices();
    let honest_outputs =
        core::array::from_fn(|lane| trace.stack_outputs().get_element(lane).unwrap());
    Fixture {
        repro: ReproTrace::new(&trace),
        core,
        chiplets,
        eidos_compression,
        and8,
        core_height: trace.main_trace().core_height(),
        roots,
        honest_outputs,
    }
}

/// Makes each update return the other tree's root and propagates that result through the stack
/// to the public outputs. Returns the forged core matrix and the forged outputs.
fn forge_core(fixture: &Fixture) -> (RowMajorMatrix<Felt>, StackOutputs) {
    let mut core = fixture.core.clone();
    let mut delta = [Felt::ZERO; 16];
    let mut update_count = 0;
    for row in 0..fixture.core_height {
        let cols = core_row_mut(&mut core, row);
        for (lane, d) in delta.iter().enumerate() {
            cols.stack.top[lane] += *d;
        }
        let opcode = opcode_of(cols.decoder.op_bits);
        match opcode {
            opcodes::MRUPDATE => {
                let position = update_count;
                update_count += 1;
                assert_eq!(delta, [Felt::ZERO; 16], "no live result may reach an update");
                for (lane, cell) in delta.iter_mut().take(4).enumerate() {
                    *cell = fixture.roots[1 - position][lane] - fixture.roots[position][lane];
                }
            },
            opcodes::DROP => {
                delta.rotate_left(1);
                delta[15] = Felt::ZERO;
            },
            opcodes::PUSH => {
                delta.rotate_right(1);
                delta[0] = Felt::ZERO;
            },
            opcodes::SWAPW3 => {
                for lane in 0..4 {
                    delta.swap(lane, 12 + lane);
                }
            },
            _ => assert!(
                delta == [Felt::ZERO; 16] || OPS_WITHOUT_STACK_EFFECT.contains(&opcode),
                "opcode {opcode} at row {row} carries a live result"
            ),
        }
    }
    assert_eq!(update_count, 2, "the program must contain exactly two updates");

    let outputs: [Felt; 16] =
        core::array::from_fn(|lane| fixture.honest_outputs[lane] + delta[lane]);
    assert_ne!(outputs, fixture.honest_outputs, "the forgery must change the public outputs");
    (core, StackOutputs::from(outputs))
}

/// Exchanges the new-path controller payloads of the two invocations level by level. Invocation
/// ids, row kinds and the old-path legs are untouched.
fn forge_chiplets(fixture: &Fixture) -> RowMajorMatrix<Felt> {
    let mut chiplets = fixture.chiplets.clone();
    let width = chiplets.width();
    let new_path_rows: Vec<usize> = (0..chiplets.height())
        .filter(|&row| {
            let cells = &chiplets.values[row * width..(row + 1) * width];
            cells[0] == Felt::ONE
                && cells[CONTROLLER_OFFSET..CONTROLLER_OFFSET + NUM_SELECTORS] == MR_UPDATE_NEW
        })
        .collect();
    assert_eq!(new_path_rows.len(), 4, "two updates at depth 2 have four new-path rows");
    for level in 0..2 {
        let (first, second) = (new_path_rows[level], new_path_rows[2 + level]);
        for column in PAYLOAD_OFFSET..PAYLOAD_OFFSET + PAYLOAD_WIDTH {
            chiplets.values.swap(first * width + column, second * width + column);
        }
    }
    chiplets
}

#[test]
fn honest_trace_verifies() {
    let fixture = build_fixture();
    let result = fixture.repro.prove_and_verify_current();
    assert!(result.is_ok(), "honest trace must verify: {result:?}");
}

#[test]
fn exchanged_new_path_siblings_are_rejected() {
    let fixture = build_fixture();
    let (core, outputs) = forge_core(&fixture);
    let chiplets = forge_chiplets(&fixture);

    let result = fixture.repro.prove_and_verify_parts_allowing_lookup_rejection(
        core,
        chiplets,
        fixture.eidos_compression.clone(),
        fixture.and8.clone(),
        outputs,
    );
    assert!(
        result.is_err(),
        "replacing a node by itself must not change the root or the outputs: {result:?}"
    );
}
