//! Regression tests: a caller-frame block-stack entry must not be substitutable for a continuation.
//!
//! Continuation and caller-frame entries previously shared one untagged encoding domain, so a
//! caller frame whose saved fields were all zero encoded to the same field element as a
//! continuation. The block-stack relation therefore could not authenticate which interpretation
//! an END selected. That distinction matters because caller-frame restoration controls the
//! preservation masks for `ctx`, `fn_hash`, `b0`, and `b1`. The relation now includes an explicit
//! entry-kind tag, and `decoder/mod.rs` additionally constrains the caller-frame restoration
//! selector to be boolean on END rows.
//!
//! The mechanism it guards against, in past tense: `impl LookupMessage for BlockStackMsg` used
//! to encode both variants against the same bus prefix at the same slot offsets, with the
//! continuation zero-padding the caller-state slots. So, identically as field elements:
//!
//! ```text
//! encode(CallerFrame { b, p, caller_ctx: 0, caller_stack_depth: 0,
//!                      caller_overflow_addr: 0, caller_fn_hash: [0;4] })
//!     == encode(Continuation { b, p, is_loop: 0 })
//! ```
//!
//! and the caller-frame flags formerly stored in decoder `h6` / `h7` were not constrained jointly
//! boolean anywhere. Selecting `h6 = 1` on the END of an ordinary block zeroes every mask keyed on
//! caller-frame restoration -- `default_flag` (ctx), `f_preserve` (fn_hash), `normal_mask` (b0),
//! and `pointer_changes` (b1). With an untagged relation, a zero-payload caller-frame removal also
//! has the same relation encoding as the pending continuation addition.
//!
//! The forced zero is security-relevant because zero is the **root context**. Code inside a CALL
//! runs at `ctx = clk + 1`; propagating this mutation would select `ctx = 0` without a SYSCALL or
//! kernel-ROM digest check.
//!
//! This fixture contains the resulting zero-state excursion inside a call: the enclosing CALL's
//! own END restores `b0`/`b1`/`ctx`/`fn_hash` from the values its CALL row recorded before the
//! last-row boundary. The test establishes that the fixed proof pipeline rejects the compound
//! substitution, and selective ablation attributes that rejection to the entry-kind tag: with only
//! the tag removed from `BlockStackMsg::encode` -- every other fix in place and the evaluator
//! regenerated -- this witness verifies at 96-bit security, while the honest trace and both
//! single-half controls below are unaffected.

use miden_air::trace::RowIndex;
use miden_core::{Felt, field::Field, operations::opcodes, utils::RowMajorMatrix};
use miden_processor::{DefaultHost, FastProcessor, StackInputs};

use crate::{
    Prover,
    repro_harness::{ReproTrace, core_row_mut},
};

struct Fixture {
    trace: ReproTrace,
    /// END of the callee's basic block: a continuation END strictly inside the CALL.
    continuation_end_row: usize,
    /// END of the CALL block itself, the row after `continuation_end_row`.
    call_end_row: usize,
    /// Honest values at `call_end_row`, for the assertions below.
    honest_ctx: Felt,
    honest_fn_hash: [Felt; 4],
    honest_b0: Felt,
}

fn build_fixture() -> Fixture {
    let program = miden_assembly::Assembler::default()
        .assemble_program("program", "proc inner nop nop end begin call.inner end")
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

    let call_end_row = (0..height)
        .find(|&row| {
            op_at(row) == Felt::from_u8(opcodes::END)
                && main.restores_caller_frame_flag(RowIndex::from(row)) == Felt::ONE
        })
        .expect("program must have a caller-frame END row");

    // The callee's basic block closes with a continuation END immediately before the CALL END.
    let continuation_end_row = call_end_row - 1;
    assert_eq!(op_at(continuation_end_row), Felt::from_u8(opcodes::END));
    assert_eq!(
        main.restores_caller_frame_flag(RowIndex::from(continuation_end_row)),
        Felt::ZERO
    );

    // Honest state at the call's END row: the callee's context, non-root.
    let honest_ctx = main.ctx(RowIndex::from(call_end_row));
    let honest_fn_hash = main.fn_hash(RowIndex::from(call_end_row));
    let honest_b0 = main.stack_depth(RowIndex::from(call_end_row));
    assert_ne!(honest_ctx, Felt::ZERO, "the callee must run in a non-root context");
    assert_ne!(honest_fn_hash, [Felt::ZERO; 4], "the callee must have a non-zero fn_hash");

    // The CALL's END restores from what the CALL row recorded, so the excursion is erased.
    assert_eq!(main.ctx(RowIndex::from(call_end_row + 1)), Felt::ZERO);
    assert_eq!(main.stack_depth(RowIndex::from(call_end_row + 1)), Felt::new_unchecked(16));

    Fixture {
        trace: ReproTrace::new(&trace),
        continuation_end_row,
        call_end_row,
        honest_ctx,
        honest_fn_hash,
        honest_b0,
    }
}

/// Zeroes the caller-frame payload columns at the CALL's END row. In the old untagged relation,
/// that gives the forged caller-frame removal emitted by the previous row the same encoding as a
/// continuation removal.
fn zero_caller_frame_payload(f: &Fixture, core: &mut RowMajorMatrix<Felt>) {
    let row = core_row_mut(core, f.call_end_row);
    row.system.ctx = Felt::ZERO;
    row.system.fn_hash = [Felt::ZERO; 4];
    row.stack.b0 = Felt::ZERO;
    row.stack.b1 = Felt::ZERO;
    // `overflow() = (b0 - 16) * h0` feeds `(1 - overflow) * (depth - 16) = 0`. With b0 forced
    // to 0, h0 must be the true inverse or that constraint demands depth == 16.
    row.stack.h0 = (Felt::ZERO - Felt::new_unchecked(16)).inverse();
}

/// Control: the unmodified trace verifies.
#[test]
fn honest_trace_verifies() {
    let f = build_fixture();
    assert!(f.trace.prove_and_verify_current().is_ok(), "honest trace must verify");
}

/// Mark the callee's continuation END as restoring a CALL/DYNCALL frame and zero the saved-state
/// payload on the next row. Preservation of ctx / fn_hash / b0 / b1 is switched off, but the
/// authenticated entry kind prevents the removal from matching the SPAN's continuation addition.
#[test]
fn forged_caller_frame_flag_on_continuation_end_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();

    // Forge the CALL/DYNCALL caller-frame flag on a continuation END.
    core_row_mut(&mut core, f.continuation_end_row).decoder.hasher_state[6] = Felt::ONE;
    zero_caller_frame_payload(&f, &mut core);

    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "the proof pipeline must reject a caller-frame flag forged on a continuation END: the entry \
         kind tag prevents a zero-payload caller-frame removal from matching the pending \
         continuation addition: {result:?}"
    );
}

/// Control isolating the mechanism: the identical payload zeroing without forging a caller-frame
/// flag must be rejected, because then the preservation constraints are still live.
#[test]
fn zeroed_payload_without_forged_caller_frame_flag_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();

    // Same value changes, but leave the continuation END correctly classified.
    zero_caller_frame_payload(&f, &mut core);

    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "without the forged caller-frame flag the proof pipeline must reject this: \
         {result:?}"
    );
}

/// Control isolating the bus: forging the caller-frame flag while leaving the payload at its
/// honest non-zero values must be rejected, because the caller-frame removal matches no addition.
#[test]
fn forged_caller_frame_flag_without_zeroed_payload_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();

    core_row_mut(&mut core, f.continuation_end_row).decoder.hasher_state[6] = Felt::ONE;
    // Payload left honest: ctx != 0, fn_hash != 0, b0 == 16.
    assert_ne!(f.honest_ctx, Felt::ZERO);
    assert_ne!(f.honest_fn_hash, [Felt::ZERO; 4]);
    assert_eq!(f.honest_b0, Felt::new_unchecked(16));

    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "a caller-frame removal with a non-zero payload matches no addition and must unbalance \
         the block-stack bus: {result:?}"
    );
}
