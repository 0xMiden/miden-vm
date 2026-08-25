//! Regression tests for decoder span-entry soundness.

use alloc::vec;

use miden_air::trace::RowIndex;
use miden_core::{
    Felt,
    operations::opcodes,
    program::StackOutputs,
    utils::{Matrix, RowMajorMatrix},
};
use miden_processor::{DefaultHost, FastProcessor, StackInputs};

use crate::{
    Prover,
    repro_harness::{ReproTrace, core_row_mut},
};

/// Width of the trailing `RangeCols { multiplicity, value }` segment of `CoreCols`.
///
/// `CoreCols` is `#[repr(C)]` laid out as `{ system, decoder, stack, range }`, so the range-check
/// table occupies the last two columns. It is an independent sorted table joined to the execution
/// rows by a multiset bus, so row indices are irrelevant to it. The splice therefore shifts only
/// the leading `width - RANGE_WIDTH` columns and leaves the range table exactly as generated.
const RANGE_WIDTH: usize = 2;

/// Ops that may appear at or after the splice point.
///
/// The splice renumbers `clk` on every row it moves, so no moved row may carry a clk-keyed bus
/// message. None of these four does: the hasher requests raised by `SPAN`/`END` are addressed by
/// `addr`, not `clk`, and `NOOP`/`HALT` raise nothing.
const OPS_ALLOWED_IN_TAIL: [u8; 4] = [opcodes::SPAN, opcodes::NOOP, opcodes::END, opcodes::HALT];

struct Fixture {
    repro: ReproTrace,
    height: usize,
    /// The `SPAN` row that the splice displaces. Its predecessor is the `END` of the JOIN's first
    /// child, whose `is_first_child` is already 1.
    splice_row: usize,
    honest_outputs: StackOutputs,
}

fn op_bits(opcode: u8) -> [Felt; 7] {
    core::array::from_fn(|i| Felt::from_u8((opcode >> i) & 1))
}

fn build_fixture() -> Fixture {
    // The trailing `nop` makes the program a JOIN of two children. The first child's END is then
    // followed by the second child's SPAN -- the splice site the bus arguments do not notice.
    // Nothing from that SPAN onward touches the stack, so a spliced SWAP propagates unchanged into
    // the public outputs.
    let source = "
        begin
            if.true
                nop
            end
            nop
        end
    ";
    let program = miden_assembly::Assembler::default()
        .assemble_program("program", source)
        .unwrap()
        .unwrap_program();

    // Top of stack: the condition, then two distinct values so a SWAP is observable.
    let mut stack_values = vec![Felt::ZERO; 16];
    stack_values[0] = Felt::ONE;
    stack_values[1] = Felt::new_unchecked(7);
    stack_values[2] = Felt::new_unchecked(3);
    let stack_inputs = StackInputs::new(&stack_values).unwrap();

    let mut host = DefaultHost::default();
    let (trace, precompile_witness) = FastProcessor::new(stack_inputs)
        .execute_and_build_trace_sync(&program, &mut host, Prover::DEFAULT_MAX_PROVER_MEMORY_BYTES)
        .unwrap();
    assert!(precompile_witness.is_none());

    let main = trace.main_trace();
    let height = main.core_height();
    let op_at = |row: usize| main.get_op_code(RowIndex::from(row));
    let is = |row: usize, op: u8| op_at(row) == Felt::from_u8(op);

    let splice_row = (2..height)
        .find(|&row| {
            is(row - 1, opcodes::END)
                && is(row, opcodes::SPAN)
                && is(row + 1, opcodes::NOOP)
                && (row..height).all(|r| OPS_ALLOWED_IN_TAIL.iter().any(|&op| is(r, op)))
        })
        .expect("trace must contain a first-child END -> SPAN -> NOOP window with an inert tail");

    // The predecessor END must be a first child. The window above pins the next row to SPAN, so
    // this is implied by the block-hash encoding; assert it anyway because this is load-bearing.
    for op in [opcodes::END, opcodes::REPEAT, opcodes::RESPAN, opcodes::HALT] {
        assert!(!is(splice_row, op), "predecessor END must already encode is_first_child = 1");
    }

    // Everything from the splice point on must leave the stack untouched. This lets a spliced SWAP
    // be propagated by swapping the top two slots uniformly across the tail.
    for row in splice_row..height {
        for slot in 0..16 {
            assert_eq!(
                main.stack_element(slot, RowIndex::from(row)),
                main.stack_element(slot, RowIndex::from(splice_row)),
                "stack must be constant from the splice point on (row {row}, slot {slot})"
            );
        }
    }

    for row in 0..height {
        assert_eq!(
            main.core_row(RowIndex::from(row)).system.clk,
            Felt::new_unchecked(row as u64),
            "clk must equal the row index at row {row}"
        );
    }

    let honest_outputs = *trace.stack_outputs();
    let repro = ReproTrace::new(&trace);

    Fixture {
        repro,
        height,
        splice_row,
        honest_outputs,
    }
}

/// Splices one row carrying `opcode` at `fixture.splice_row`, shifting the tail down by one and
/// dropping the final HALT-padding row.
///
/// The spliced row inherits the displaced `SPAN` row's state, so it is the operation's input row;
/// its effect lands on the row after it.
fn splice_op(fixture: &Fixture, opcode: u8) -> RowMajorMatrix<Felt> {
    let mut core = fixture.repro.core.clone();
    let width = core.width();
    let splice = fixture.splice_row;
    let height = fixture.height;
    let prefix = width - RANGE_WIDTH;

    // Shift rows [splice, height-1) down by one, excluding the trailing range-table columns.
    // Iterate in reverse because the copies overlap.
    for row in (splice + 1..height).rev() {
        let (src, dst) = ((row - 1) * width, row * width);
        core.values.copy_within(src..src + prefix, dst);
    }

    // The range table must be untouched by the shift.
    for row in 0..height {
        assert_eq!(
            core.values[row * width + prefix..(row + 1) * width],
            fixture.repro.core.values[row * width + prefix..(row + 1) * width],
            "the splice must leave the range-check table bit-identical (row {row})"
        );
    }

    {
        let decoder = &mut core_row_mut(&mut core, splice).decoder;
        let bits = op_bits(opcode);
        decoder.op_bits = bits;
        decoder.hasher_state = [Felt::ZERO; 8];
        decoder.in_span = Felt::ONE;
        decoder.op_index = Felt::ZERO;
        decoder.batch_flags = [Felt::ZERO; 3];
        let [_, _, _, _, b4, b5, b6] = bits;
        decoder.extra = [b6 * (Felt::ONE - b5) * b4, b6 * b5];
    }

    for row in 0..height {
        core_row_mut(&mut core, row).system.clk = Felt::new_unchecked(row as u64);
    }

    core
}

fn apply_swap_effect(fixture: &Fixture, core: &mut RowMajorMatrix<Felt>) {
    for row in (fixture.splice_row + 1)..fixture.height {
        core_row_mut(core, row).stack.top.swap(0, 1);
    }
}

fn swapped_outputs(fixture: &Fixture) -> StackOutputs {
    let mut elements: [Felt; 16] =
        core::array::from_fn(|i| fixture.honest_outputs.get_element(i).unwrap());
    elements.swap(0, 1);
    assert_ne!(elements[0], elements[1], "the swap must be observable");
    StackOutputs::from(elements)
}

#[test]
fn honest_trace_verifies() {
    let fixture = build_fixture();
    let result = fixture.repro.prove_and_verify_current();
    assert!(result.is_ok(), "honest trace must verify: {result:?}");
}

#[test]
fn uncommitted_noop_between_end_and_span_is_rejected() {
    let fixture = build_fixture();
    let core = splice_op(&fixture, opcodes::NOOP);

    let result = fixture.repro.prove_and_verify_with_outputs(core, fixture.honest_outputs);
    assert!(
        result.is_err(),
        "an in-span row cannot be entered without SPAN/RESPAN or an in-span predecessor: {result:?}"
    );
}

#[test]
fn uncommitted_swap_between_end_and_span_is_rejected() {
    let fixture = build_fixture();
    let mut core = splice_op(&fixture, opcodes::SWAP);
    apply_swap_effect(&fixture, &mut core);

    let result = fixture.repro.prove_and_verify_with_outputs(core, swapped_outputs(&fixture));
    assert!(
        result.is_err(),
        "an uncommitted SWAP must not verify against forged public outputs: {result:?}"
    );
}

#[test]
fn spliced_noop_with_swapped_stack_is_rejected() {
    let fixture = build_fixture();
    let mut core = splice_op(&fixture, opcodes::NOOP);
    apply_swap_effect(&fixture, &mut core);

    let result = fixture.repro.prove_and_verify_with_outputs(core, swapped_outputs(&fixture));
    assert!(result.is_err(), "a NOOP must not swap the stack: {result:?}");
}

#[test]
fn swapped_stack_without_splice_is_rejected() {
    let fixture = build_fixture();
    let mut core = fixture.repro.core.clone();
    apply_swap_effect(&fixture, &mut core);

    let result = fixture.repro.prove_and_verify_with_outputs(core, swapped_outputs(&fixture));
    assert!(result.is_err(), "the stack forgery alone must be rejected: {result:?}");
}
