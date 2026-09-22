//! Regression tests: DYNCALL must zero the bottom stack slot when overflow is empty.
//!
//! Before the fix nothing pinned it, for four compounding reasons:
//!
//! DYNCALL left-shifts the visible stack (it consumes the callee address operand) and resets the
//! depth to 16. With an empty overflow table the honest value shifted into position 15 is 0.
//!
//! - `stack/general.rs` position 15 uses `flag_sum = no_shift_at(15) + right_shift_at(14)` -- there
//!   is deliberately no left-shift term at the bottom slot, and DYNCALL is in neither of those two
//!   arrays, so `flag_sum = 0` and the constraint reads `0 = 0`.
//! - the `s15' = 0` zeroing in `stack/overflow.rs` was gated only on the aggregate left-shift flag,
//!   which excludes DYNCALL by construction: DYNCALL records its caller's post-pop stack depth and
//!   overflow address in decoder helper columns and uses a dedicated overflow-table interaction.
//! - the stack-overflow bus branch that would bind `s15'` for DYNCALL is gated on `dyncall() *
//!   overflow()`, and `overflow() = (b0 - 16) * h0` is 0 exactly when the depth is 16.
//! - the output boundary binds `s15` to the claimed output, which the forgery changes to match
//!   the forged trace.
//!
//! So a DYNCALL executed at depth 16 -- the ordinary case, no overflow -- leaves the callee's
//! bottom stack slot a free variable. The value sits at a live position of the callee's fresh
//! 16-element stack and survives to the public outputs.

use alloc::vec;

use miden_air::trace::RowIndex;
use miden_core::{Felt, Word, operations::opcodes, program::StackOutputs};
use miden_processor::{DefaultHost, FastProcessor, StackInputs};

use crate::{
    Prover,
    repro_harness::{ReproTrace, core_row_mut},
};

const ADDR: u64 = 40;

struct Fixture {
    trace: ReproTrace,
    height: usize,
    /// Row carrying the DYNCALL opcode.
    dyncall_row: usize,
    /// Depth-preserving row after the DYNCALL (the control: `s15` is pinned there).
    control_row: usize,
}

/// Builds a trace whose DYNCALL executes at depth exactly 16 with an empty overflow table.
///
/// The pointer to the callee digest is supplied as a stack *input* rather than pushed, so the
/// depth at the DYNCALL row is 16 and `overflow() = (b0 - 16) * h0` vanishes.
fn build_fixture() -> Fixture {
    // `foo` must not shift the stack, so the forged bottom slot stays at position 15.
    let source = "
        proc foo
            nop
        end
        begin
            call.foo
            mem_storew_le.40
            movup.4
            dyncall
        end
    ";
    let program = miden_assembly::Assembler::default()
        .assemble_program("program", source)
        .unwrap()
        .unwrap_program();
    // `call.foo` keeps `foo` in the forest as its own MAST node (a bare `dyncall` reference
    // is dynamic, so `foo` would otherwise be eliminated as dead code) and gives us its digest.
    let root = program.hash();
    let foo_digest: Word = program
        .mast_forest()
        .procedure_digests()
        .find(|d| *d != root)
        .expect("foo must survive as its own procedure");

    // Stack (top first): [d0, d1, d2, d3, addr, 0...]. `mem_storew_le.40` writes the top word
    // (the digest) to memory without popping, then `movup.4` lifts `addr` to the top. Both are
    // depth-preserving, so DYNCALL executes at depth 16 and the overflow table stays empty.
    let mut stack_values = vec![Felt::ZERO; 16];
    for (i, limb) in foo_digest.as_elements().iter().enumerate() {
        stack_values[i] = *limb;
    }
    stack_values[4] = Felt::new_unchecked(ADDR);
    let stack_inputs = StackInputs::new(&stack_values).unwrap();

    let mut host = DefaultHost::default();
    let (trace, precompile_witness) = FastProcessor::new(stack_inputs)
        .execute_and_build_trace_sync(&program, &mut host, Prover::DEFAULT_MAX_PROVER_MEMORY_BYTES)
        .unwrap();
    assert!(precompile_witness.is_none());

    let main = trace.main_trace();
    let height = main.core_height();
    let op_at = |row: usize| main.get_op_code(RowIndex::from(row));

    let dyncall_row = (0..height)
        .find(|&row| op_at(row) == Felt::from_u8(opcodes::DYNCALL))
        .expect("program must contain a DYNCALL");

    // The gap requires an empty overflow table at the DYNCALL row.
    assert_eq!(
        main.stack_depth(RowIndex::from(dyncall_row)),
        Felt::new_unchecked(16),
        "the DYNCALL must execute at depth 16 for the overflow-gated branch to vanish"
    );
    assert_eq!(main.stack_element(15, RowIndex::from(dyncall_row + 1)), Felt::ZERO);

    // Negative control row: an ordinary in-span no-shift op where `general.rs` pins
    // `s15' = s15` via `no_shift_at(15)`.
    //
    // It must sit *after* the DYNCALL. A control before it would have its mutated suffix cross
    // the DYNCALL row, where the new zeroing constraint rejects independently -- so the control
    // would still fail with `no_shift_at(15)` removed and would prove nothing.
    let control_row = ((dyncall_row + 1)..height)
        .find(|&row| op_at(row) == Felt::from_u8(opcodes::NOOP))
        .expect("program must contain a NOOP after the DYNCALL (the callee body)");

    Fixture {
        trace: ReproTrace::new(&trace),
        height,
        dyncall_row,
        control_row,
    }
}

/// Control: the unmodified trace verifies against its honest outputs.
#[test]
fn honest_dyncall_trace_verifies() {
    let fixture = build_fixture();
    assert!(fixture.trace.prove_and_verify_current().is_ok(), "honest trace must verify");
}

/// The gap: forge the bottom stack slot shifted in by DYNCALL, and claim the forged value as
/// a public output.
#[test]
fn forged_s15_after_dyncall_is_rejected() {
    let fixture = build_fixture();
    let forged = Felt::new_unchecked(12345);

    let mut core_matrix = fixture.trace.core.clone();
    for row in (fixture.dyncall_row + 1)..fixture.height {
        core_row_mut(&mut core_matrix, row).stack.top[15] = forged;
    }

    let mut elements: [Felt; 16] =
        core::array::from_fn(|i| fixture.trace.outputs().get_element(i).unwrap());
    assert_eq!(elements[15], Felt::ZERO);
    elements[15] = forged;
    let forged_outputs = StackOutputs::from(elements);
    assert_ne!(forged_outputs, fixture.trace.outputs());

    let result = fixture.trace.prove_and_verify_with_outputs(core_matrix, forged_outputs);
    assert!(
        result.is_err(),
        "the verifier must reject a forged bottom stack slot across DYNCALL: the s15 zeroing \
         now covers DYNCALL when the overflow table is empty: {result:?}"
    );
}

/// Negative control: the same forgery across an ordinary no-shift row *after* the DYNCALL,
/// where `general.rs` pins `s15' = s15` via `no_shift_at(15)` -- must be rejected.
///
/// Placing it after the DYNCALL is what makes it a control: the mutated suffix then never
/// crosses the DYNCALL row, so the rejection is attributable to `no_shift_at(15)` alone and not
/// to the DYNCALL zeroing constraint the main test exercises.
#[test]
fn forged_s15_after_noshift_row_is_rejected() {
    let fixture = build_fixture();
    let forged = Felt::new_unchecked(12345);

    let mut core_matrix = fixture.trace.core.clone();
    for row in (fixture.control_row + 1)..fixture.height {
        core_row_mut(&mut core_matrix, row).stack.top[15] = forged;
    }

    let mut elements: [Felt; 16] =
        core::array::from_fn(|i| fixture.trace.outputs().get_element(i).unwrap());
    elements[15] = forged;
    let forged_outputs = StackOutputs::from(elements);

    let result = fixture.trace.prove_and_verify_with_outputs(core_matrix, forged_outputs);
    assert!(
        result.is_err(),
        "the verifier must reject a forged bottom slot across an ordinary no-shift row -- \
         `no_shift_at(15)` pins it there: {result:?}"
    );
}
