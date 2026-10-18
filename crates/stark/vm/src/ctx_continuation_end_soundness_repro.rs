//! Regression tests: `ctx` and `fn_hash` are preserved across a continuation END.
//!
//! `air/src/constraints/system/mod.rs` used to gate the preservation of both columns on the
//! *coarse* END flag:
//!
//! ```ignore
//! let change_ctx_flag = f_call + f_syscall + f_dyncall + f_end;
//! let default_flag = change_ctx_flag.not();
//! builder.when_transition().when(default_flag).assert_eq(ctx_next, ctx);
//! ...
//! let f_preserve = (f_call + f_dyncall + f_end).not();
//! builder.when_transition().when(f_preserve).assert_eq_arrays(next.fn_hash, local.fn_hash);
//! ```
//!
//! On *any* END row that made `default_flag = f_preserve = 0`, leaving both columns pinned by
//! nothing. Restoration through the block-stack relation covers only caller-frame ENDs:
//! `end_caller_frame` removes a `BlockStackMsg::CallerFrame` carrying `ctx_next` /
//! `fn_hash_next`, while `end_continuation` removes a `BlockStackMsg::Continuation` carrying only
//! `(block_id, parent_id, is_loop)`. A prover could therefore jump `ctx` at any continuation END --
//! including one nested inside a call, re-entering the caller's memory context -- or forge
//! `fn_hash`, which CALLER copies onto the stack as a public output.
//!
//! The fix gates both on the same precise caller-frame restoration selector already used for
//! stack depth `b0` and the overflow pointer `b1` in stack/overflow.rs.
//!
//! Each forgery below is paired with a control applying the same mutation across an ordinary
//! transition. The controls failed before the fix as well, so they are what pins each
//! rejection to the END transition specifically rather than to the harness.

use alloc::{vec, vec::Vec};

use miden_air::trace::RowIndex;
use miden_core::{
    Felt,
    mast::{BasicBlockNodeBuilder, MastForest},
    operations::{Operation, opcodes},
    program::Program,
};
use miden_processor::{DefaultHost, FastProcessor, StackInputs};

use crate::{
    Prover,
    repro_harness::{ReproTrace, core_row_mut},
};

// HARNESS
// ================================================================================================

fn set_ctx(trace: &mut ReproTrace, rows: impl Iterator<Item = usize>, ctx: Felt) {
    for row in rows {
        core_row_mut(&mut trace.core, row).system.ctx = ctx;
    }
}

fn set_fn_hash(trace: &mut ReproTrace, rows: impl Iterator<Item = usize>, fn_hash: [Felt; 4]) {
    for row in rows {
        core_row_mut(&mut trace.core, row).system.fn_hash = fn_hash;
    }
}

const FORGED_CTX: Felt = Felt::new_unchecked(7);
const FORGED_FN_HASH: [Felt; 4] = [
    Felt::new_unchecked(11),
    Felt::new_unchecked(22),
    Felt::new_unchecked(33),
    Felt::new_unchecked(44),
];

// SINGLE BASIC BLOCK: THE MINIMAL GAP
// ================================================================================================

/// Row indices of interest in the single-basic-block program.
struct BasicRows {
    /// Continuation END of the basic block: both caller-frame flags are zero.
    continuation_end: usize,
    /// An ordinary transition, where `default_flag = 1` pins both columns.
    noop: usize,
    height: usize,
}

fn build_basic_harness() -> (ReproTrace, BasicRows) {
    let operations = vec![
        Operation::Push(Felt::new_unchecked(101)),
        Operation::Noop,
        Operation::Drop,
        Operation::Noop,
    ];
    let mut mast_forest = MastForest::new();
    let basic_block_id =
        BasicBlockNodeBuilder::new(operations).add_to_forest(&mut mast_forest).unwrap();
    mast_forest.make_root(basic_block_id);
    let program = Program::new(mast_forest.into(), basic_block_id);

    let stack_values = (1..17).rev().map(Felt::new_unchecked).collect::<Vec<_>>();
    let stack_inputs = StackInputs::new(&stack_values).unwrap();
    let mut host = DefaultHost::default();
    let (trace, precompile_witness) = FastProcessor::new(stack_inputs)
        .execute_and_build_trace_sync(&program, &mut host, Prover::DEFAULT_MAX_PROVER_MEMORY_BYTES)
        .unwrap();
    assert!(precompile_witness.is_none());

    let main = trace.main_trace();
    let height = main.core_height();
    let op_at = |row: usize| main.get_op_code(RowIndex::from(row));

    let continuation_end = (0..height)
        .find(|&row| {
            let idx = RowIndex::from(row);
            op_at(row) == Felt::from_u8(opcodes::END)
                && main.restores_caller_frame_flag(idx) == Felt::ZERO
        })
        .expect("the basic block must end with a continuation END");
    let noop = (0..height)
        .find(|&row| op_at(row) == Felt::from_u8(opcodes::NOOP))
        .expect("the program must contain a NOOP");
    assert!(noop < continuation_end);

    // The honest trace runs entirely in the root context with a zero function hash.
    assert_eq!(main.ctx(RowIndex::from(continuation_end)), Felt::ZERO);
    assert_eq!(main.fn_hash(RowIndex::from(continuation_end)), [Felt::ZERO; 4]);

    let repro = ReproTrace::new(&trace);
    (repro, BasicRows { continuation_end, noop, height })
}

/// Control: the unmodified trace verifies, so rejections below are attributable to the
/// mutation rather than to the harness.
#[test]
fn honest_basic_block_trace_verifies() {
    let (repro, _) = build_basic_harness();
    assert!(repro.prove_and_verify_current().is_ok(), "the honest trace must verify");
}

/// `ctx` jumps from 0 to 7 across the continuation END and is preserved (as the default-flag
/// constraint requires) through the remaining HALT rows.
#[test]
fn forged_context_at_continuation_end_is_rejected() {
    let (mut repro, rows) = build_basic_harness();
    set_ctx(&mut repro, (rows.continuation_end + 1)..rows.height, FORGED_CTX);

    let result = repro.prove_and_verify_current();
    assert!(
        result.is_err(),
        "the verifier must reject a context change across a continuation END: {result:?}"
    );
}

/// Control for the above: the identical mutation across an ordinary NOOP transition, where
/// `default_flag = 1`, must be rejected. This proves the mutation reaches the proven trace
/// and that the verifier does police `ctx`.
#[test]
fn forged_context_at_ordinary_row_is_rejected() {
    let (mut repro, rows) = build_basic_harness();
    set_ctx(&mut repro, (rows.noop + 1)..rows.height, FORGED_CTX);

    let result = repro.prove_and_verify_current();
    assert!(
        result.is_err(),
        "the verifier must reject a context change on an ordinary (non-END) transition; \
         if this passes, the harness is not exercising what these tests claim: {result:?}"
    );
}

/// `fn_hash` feeds the CALLER operation (`stack/ops.rs`), which copies it onto the top four
/// stack slots -- so a forged digest becomes a forged public output.
#[test]
fn forged_fn_hash_at_continuation_end_is_rejected() {
    let (mut repro, rows) = build_basic_harness();
    set_fn_hash(&mut repro, (rows.continuation_end + 1)..rows.height, FORGED_FN_HASH);

    let result = repro.prove_and_verify_current();
    assert!(
        result.is_err(),
        "the verifier must reject a function-digest change across a continuation END: {result:?}"
    );
}

/// Control for the above.
#[test]
fn forged_fn_hash_at_ordinary_row_is_rejected() {
    let (mut repro, rows) = build_basic_harness();
    set_fn_hash(&mut repro, (rows.noop + 1)..rows.height, FORGED_FN_HASH);

    let result = repro.prove_and_verify_current();
    assert!(
        result.is_err(),
        "the verifier must reject a function-digest change on an ordinary transition: {result:?}"
    );
}

// INSIDE A CALL: THE ISOLATION-RELEVANT CASE
// ================================================================================================

/// Row indices of interest in the program containing a `call`.
struct CallRows {
    /// An ordinary transition inside the callee body.
    ordinary_in_callee: usize,
    /// The if/else arm's END, strictly inside the callee body.
    nested_continuation_end: usize,
    /// The END of the CALL block itself: it restores a CALL/DYNCALL caller frame.
    call_end: usize,
}

/// Builds a trace for `begin call.inner end`, where `inner` contains a nested block -- so the
/// callee body has a continuation END with further callee rows after it.
fn build_call_harness() -> (ReproTrace, CallRows) {
    let source = "
        proc inner
            push.1
            if.true
                push.7 drop
            else
                push.8 drop
            end
            push.9 drop
        end
        begin
            call.inner
        end
    ";
    let program = miden_assembly::Assembler::default()
        .assemble_program("program", source)
        .unwrap()
        .unwrap_program();

    let mut host = DefaultHost::default();
    let (trace, precompile_witness) = FastProcessor::new(StackInputs::default())
        .execute_and_build_trace_sync(&program, &mut host, Prover::DEFAULT_MAX_PROVER_MEMORY_BYTES)
        .unwrap();
    assert!(precompile_witness.is_none());

    let main = trace.main_trace();
    let height = main.core_height();
    let op_at = |row: usize| main.get_op_code(RowIndex::from(row));

    let call_row = (0..height)
        .find(|&row| op_at(row) == Felt::from_u8(opcodes::CALL))
        .expect("program must contain a CALL");
    let call_end = (call_row..height)
        .find(|&row| {
            op_at(row) == Felt::from_u8(opcodes::END)
                && main.restores_caller_frame_flag(RowIndex::from(row)) == Felt::ONE
        })
        .expect("the CALL block must have a caller-frame END row");

    // The callee's own context, established by `ctx' = clk + 1` on the CALL row, and the
    // caller's context restored by the block-stack bus on the caller-frame END row.
    let callee_ctx = main.ctx(RowIndex::from(call_row + 1));
    assert_ne!(callee_ctx, Felt::ZERO, "the callee must run in a non-root context");
    assert_eq!(main.ctx(RowIndex::from(call_end + 1)), Felt::ZERO);

    let nested_continuation_end = ((call_row + 1)..call_end)
        .find(|&row| {
            let idx = RowIndex::from(row);
            op_at(row) == Felt::from_u8(opcodes::END)
                && main.restores_caller_frame_flag(idx) == Felt::ZERO
        })
        .expect("the callee body must contain a nested continuation END");
    assert!(
        nested_continuation_end + 1 < call_end,
        "there must be callee rows after the nested continuation END for the forgery to matter"
    );

    // An ordinary (non-END) callee row strictly before the nested continuation END, used as the
    // control. Every row in the callee body runs at `callee_ctx`.
    let ordinary_in_callee = ((call_row + 1)..nested_continuation_end)
        .find(|&row| op_at(row) != Felt::from_u8(opcodes::END))
        .expect("the callee body must contain an ordinary row");
    assert_eq!(main.ctx(RowIndex::from(ordinary_in_callee)), callee_ctx);

    let repro = ReproTrace::new(&trace);
    (
        repro,
        CallRows {
            ordinary_in_callee,
            nested_continuation_end,
            call_end,
        },
    )
}

/// Control: the unmodified call-program trace verifies.
#[test]
fn honest_call_program_trace_verifies() {
    let (repro, _) = build_call_harness();
    assert!(repro.prove_and_verify_current().is_ok(), "the honest trace must verify");
}

/// The isolation-relevant case: a nested continuation END lets the callee drop back into the
/// *caller's* execution context for the remainder of the call.
///
/// `call` resets `ctx` to `clk + 1` on entry, and the block-stack bus pins `ctx` back to the
/// caller's value only on the END *of the call*. Between those two points the only thing
/// holding `ctx` at the callee value is the default-flag preservation constraint, which goes
/// vacuous at every nested continuation END. Memory requests read `ctx` straight from this column
/// (`chiplet_requests.rs`), so a callee tail running at `ctx = 0` addresses caller memory.
#[test]
fn callee_reentering_caller_context_at_nested_continuation_end_is_rejected() {
    let (mut repro, rows) = build_call_harness();
    set_ctx(&mut repro, (rows.nested_continuation_end + 1)..=rows.call_end, Felt::ZERO);

    let result = repro.prove_and_verify_current();
    assert!(
        result.is_err(),
        "the verifier must reject a callee re-entering the caller's context at a nested \
         continuation END (memory-isolation break): {result:?}"
    );
}

/// Control for the above: dropping into the caller's context one transition earlier -- across
/// an ordinary callee row rather than the nested continuation END -- must be rejected. This pins
/// the acceptance to the END transition specifically, not to `ctx` being loose inside calls.
#[test]
fn callee_reentering_caller_context_at_ordinary_row_is_rejected() {
    let (mut repro, rows) = build_call_harness();
    set_ctx(&mut repro, (rows.ordinary_in_callee + 1)..=rows.call_end, Felt::ZERO);

    let result = repro.prove_and_verify_current();
    assert!(
        result.is_err(),
        "the verifier must reject a context change on an ordinary callee transition: {result:?}"
    );
}
