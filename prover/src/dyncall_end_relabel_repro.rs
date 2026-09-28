//! Regression test: a DYNCALL's caller-frame END must not be relabelled as a continuation END.
//!
//! DYNCALL records its saved caller frame into decoder cells rather than the real columns:
//! `block_stack_and_range_logcap.rs` builds a caller-frame addition with
//! `caller_stack_depth = h4` and `caller_overflow_addr = h5` (CALL/SYSCALL use the real `b0`/`b1`).
//! At the root, `caller_ctx = 0`, `caller_fn_hash = [0;4]`, and `caller_overflow_addr = 0`, so the
//! honest saved stack depth of 16 is the frame's only nonzero saved-state slot.
//!
//! With `h4 = 0`, the inserted caller frame's payload matches a continuation except for its
//! entry-kind tag. Clearing decoder `h6` on the DYNCALL's END would then select continuation
//! preservation rules. The AIR binds `h4` to the saved depth, and the tag authenticates the entry
//! kind. This regression exercises both checks together.

use alloc::vec;

use miden_air::trace::RowIndex;
use miden_core::{Felt, Word, operations::opcodes, utils::RowMajorMatrix};
use miden_processor::{DefaultHost, FastProcessor, StackInputs};

use crate::{
    Prover,
    repro_harness::{ReproTrace, core_row_mut},
};

const ADDR: u64 = 40;

struct Fixture {
    trace: ReproTrace,
    height: usize,
    dyncall_row: usize,
    dyncall_end: usize,
    /// The callee's context and digest, honestly restored to root at `dyncall_end + 1`.
    callee_ctx: Felt,
    callee_fn_hash: [Felt; 4],
}

fn build_fixture() -> Fixture {
    // A DYNCALL at root depth 16 with an empty overflow table, so h4 = 16 is the sole nonzero
    // caller-frame payload slot. `call.foo` keeps `foo` in the forest for the dynamic reference.
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
    let root = program.hash();
    let foo_digest: Word = program
        .mast_forest()
        .procedure_digests()
        .find(|d| *d != root)
        .expect("foo must survive as its own procedure");

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
    let op = |r: usize| main.get_op_code(RowIndex::from(r)).as_canonical_u64() as u8;

    let dyncall_row = (0..height).find(|&r| op(r) == opcodes::DYNCALL).expect("has DYNCALL");
    let dyncall_end = (dyncall_row..height)
        .find(|&r| {
            op(r) == opcodes::END && main.restores_caller_frame_flag(RowIndex::from(r)) == Felt::ONE
        })
        .expect("DYNCALL block has a caller-frame END");

    // Preconditions the forgery relies on.
    assert_eq!(main.stack_depth(RowIndex::from(dyncall_row)), Felt::new_unchecked(16));
    assert_eq!(main.ctx(RowIndex::from(dyncall_row)), Felt::ZERO);
    assert_eq!(main.fn_hash(RowIndex::from(dyncall_row)), [Felt::ZERO; 4]);
    assert_eq!(
        main.decoder_hasher_state_element(4, RowIndex::from(dyncall_row)),
        Felt::new_unchecked(16),
        "h4 must honestly hold the caller depth 16 (the sole nonzero saved-state slot)"
    );

    // Callee context and digest, honestly restored to root right after the caller-frame END.
    let callee_ctx = main.ctx(RowIndex::from(dyncall_end));
    let callee_fn_hash = main.fn_hash(RowIndex::from(dyncall_end));
    assert_ne!(callee_ctx, Felt::ZERO, "the callee runs in a non-root context");
    assert_ne!(callee_fn_hash, [Felt::ZERO; 4]);
    assert_eq!(main.ctx(RowIndex::from(dyncall_end + 1)), Felt::ZERO, "honestly restored");
    assert_eq!(main.decoder_hasher_state_element(6, RowIndex::from(dyncall_end)), Felt::ONE);

    Fixture {
        trace: ReproTrace::new(&trace),
        height,
        dyncall_row,
        dyncall_end,
        callee_ctx,
        callee_fn_hash,
    }
}

/// Carries the callee's `ctx`/`fn_hash` forward from `dyncall_end` through the tail of the
/// trace, instead of the honest root values -- i.e. the caller's context is never restored.
fn carry_callee_context_forward(f: &Fixture, core: &mut RowMajorMatrix<Felt>) {
    for row in (f.dyncall_end + 1)..f.height {
        let r = core_row_mut(core, row);
        r.system.ctx = f.callee_ctx;
        r.system.fn_hash = f.callee_fn_hash;
    }
}

/// Control: the unmodified trace verifies.
#[test]
fn honest_trace_verifies() {
    let f = build_fixture();
    assert!(f.trace.prove_and_verify_current().is_ok(), "honest trace must verify");
}

/// Zero the DYNCALL's saved depth, relabel its caller-frame END as a continuation END, and carry
/// the callee context forward. This compound mutation checks the complete repaired path; it does
/// not attribute rejection to either protection in isolation.
#[test]
fn relabelled_dyncall_end_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();

    core_row_mut(&mut core, f.dyncall_row).decoder.hasher_state[4] = Felt::ZERO;
    core_row_mut(&mut core, f.dyncall_end).decoder.hasher_state[6] = Felt::ZERO;
    carry_callee_context_forward(&f, &mut core);

    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "the proof pipeline must reject a relabelled DYNCALL END: {result:?}"
    );
    // The direct `h4 = b0 - overflow()` constraint rejects this forgery before the tag is used.
    // `block_stack_entry_kind_repro` checks the tag with an unchanged DYNCALL row.
}

/// Control: relabel the END and carry the context forward, but leave `h4 = 16`. The DYNCALL
/// addition remains a caller-frame entry, so the continuation removal matches no addition.
/// Carrying the callee context forward satisfies continuation preservation; rejection comes
/// from the block-stack relation. The entry-kind tag is isolated in `block_stack_entry_kind_repro`.
#[test]
fn relabel_without_degenerating_the_addition_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();

    // h4 left at its honest 16.
    core_row_mut(&mut core, f.dyncall_end).decoder.hasher_state[6] = Felt::ZERO;
    carry_callee_context_forward(&f, &mut core);

    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "with h4 = 16, relabelling the caller-frame END and carrying the callee context forward \
         must be rejected by the block-stack relation: {result:?}"
    );
}

/// Control: degenerate the addition and carry the context forward, but leave the caller-frame flag
/// set on the END. This is rejected independently by the direct `h4` binding and by the
/// caller-frame relation, whose removal no longer matches the state DYNCALL recorded. It is a
/// combined regression control, not an attribution test for either mechanism alone.
#[test]
fn degenerate_addition_without_relabelling_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();

    core_row_mut(&mut core, f.dyncall_row).decoder.hasher_state[4] = Felt::ZERO;
    // The CALL/DYNCALL caller-frame flag is left at one on the END.
    carry_callee_context_forward(&f, &mut core);

    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "degenerating h4 while leaving the caller-frame END honest must be rejected by the direct \
         h4 binding and the mismatched caller-frame payload: {result:?}"
    );
}
