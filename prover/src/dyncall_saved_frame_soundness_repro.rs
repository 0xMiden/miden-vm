//! Regression tests: DYNCALL's saved caller-frame depth and overflow pointer must match reality.
//!
//! Before the fix `h4` was unconstrained, so the caller could be made to resume at an arbitrary
//! depth through an otherwise honest caller-frame restoration, with the frame kind unchanged.
//!
//! DYNCALL's block-stack addition records the saved caller depth from decoder `hasher_state[4]`
//! (`caller_stack_depth = h4` in `block_stack_and_range_logcap.rs`), where CALL/SYSCALL use the
//! real column `b0`. Honestly `h4` is the caller stack depth (16 at root). Nothing bound it, and
//! the matching caller-frame removal reads `caller_stack_depth = b0_next`, so the bus forced the
//! *restored* depth to equal whatever `h4` held -- not the real caller depth. `decoder/mod.rs` now
//! pins `h4 = b0 - overflow()` on every DYNCALL row.
//!
//! This is distinct from the entry-kind relabelling forgery: here the entry remains a caller frame
//! at both ends and the only forged input is `h4`. The entry-kind tag does NOT catch this, which
//! is precisely why the `h4` binding is needed as well.
//!
//! To keep the rest of the trace valid, the forged restored depth `D` is contained inside an
//! enclosing `call`: the dyncall runs inside a called procedure, the dyncall's END restores the
//! caller (the enclosing procedure) to depth `D`, and the enclosing call's own END restores the
//! root to 16 -- erasing the excursion before the last-row `b0 = 16` boundary.

use alloc::{format, vec, vec::Vec};

use miden_air::trace::RowIndex;
use miden_core::{Felt, Word, field::Field, operations::opcodes, utils::RowMajorMatrix};
use miden_processor::{DefaultHost, FastProcessor, StackInputs};

use crate::{
    Prover,
    repro_harness::{ReproTrace, core_row_mut},
};

const ADDR: u64 = 40;
/// The forged caller depth. Any value != 16 exercises the gap.
const FORGED_DEPTH: u64 = 99;

struct Fixture {
    trace: ReproTrace,
    dyncall_row: usize,
    dyncall_end: usize,
    /// The enclosing procedure's caller-frame END, after which the root is restored.
    outer_end: usize,
}

fn build_fixture() -> Fixture {
    build_fixture_with_setup("mem_storew_le.40 movup.4 dyncall", 16)
}

fn build_fixture_with_setup(dyncall_setup: &str, pre_dyncall_depth: u64) -> Fixture {
    // The dyncall runs inside a called procedure `bar`, so the excursion it opens is erased by
    // bar's own END. `foo` (the dyncall target, a no-op) is kept in the forest by `call.foo`.
    let source = format!(
        "
        proc foo
            nop
        end
        proc bar
            {dyncall_setup}
        end
        begin
            call.foo
            call.bar
        end
    "
    );
    let program = miden_assembly::Assembler::default()
        .assemble_program("program", source.as_str())
        .unwrap()
        .unwrap_program();
    let root = program.hash();
    // `foo` is the first-declared procedure, so the first non-root digest; assert exactly one
    // dyncall below confirms it resolved to the no-op rather than recursing into `bar`.
    let foo_digest: Word = program
        .mast_forest()
        .procedure_digests()
        .find(|d| *d != root)
        .expect("a non-root procedure digest");

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

    let dyncalls: Vec<usize> = (0..height).filter(|&r| op(r) == opcodes::DYNCALL).collect();
    assert_eq!(dyncalls.len(), 1, "the dyncall must resolve to `foo`, not recurse into `bar`");
    let dyncall_row = dyncalls[0];

    let restores_caller_frame = |r: usize| {
        op(r) == opcodes::END && main.restores_caller_frame_flag(RowIndex::from(r)) == Felt::ONE
    };
    let dyncall_end =
        (dyncall_row..height).find(|&r| restores_caller_frame(r)).expect("dyncall END");
    let outer_end = ((dyncall_end + 1)..height)
        .find(|&r| restores_caller_frame(r))
        .expect("bar END");

    // Preconditions.
    assert_eq!(
        main.stack_depth(RowIndex::from(dyncall_row)),
        Felt::new_unchecked(pre_dyncall_depth),
    );
    assert_eq!(
        main.decoder_hasher_state_element(4, RowIndex::from(dyncall_row)),
        Felt::new_unchecked(16),
        "h4 honestly holds the parent depth 16"
    );
    assert_eq!(
        main.decoder_hasher_state_element(5, RowIndex::from(dyncall_row)),
        Felt::ZERO,
        "h5 honestly holds the post-pop overflow pointer"
    );
    // The dyncall's END honestly restores the caller (bar) to depth 16 ...
    assert_eq!(main.stack_depth(RowIndex::from(dyncall_end + 1)), Felt::new_unchecked(16));
    // ... and bar's END restores the root to depth 16.
    assert_eq!(main.stack_depth(RowIndex::from(outer_end + 1)), Felt::new_unchecked(16));

    Fixture {
        trace: ReproTrace::new(&trace),
        dyncall_row,
        dyncall_end,
        outer_end,
    }
}

/// Holds `b0` at the forged depth `D` across the excursion window `[dyncall_end+1 ..= outer_end]`,
/// with the overflow helper `h0 = 1/(D-16)` so the flag constraint `(1-overflow)(b0-16)=0` holds.
fn apply_depth_excursion(f: &Fixture, core: &mut RowMajorMatrix<Felt>) {
    let d = Felt::new_unchecked(FORGED_DEPTH);
    let h0 = (d - Felt::new_unchecked(16)).inverse();
    // Forge the saved caller depth on the dyncall row.
    core_row_mut(core, f.dyncall_row).decoder.hasher_state[4] = d;
    // Carry the forged depth through the window so the block-stack bus balances.
    for row in (f.dyncall_end + 1)..=f.outer_end {
        let r = core_row_mut(core, row);
        r.stack.b0 = d;
        r.stack.h0 = h0;
    }
}

/// Control: the unmodified trace verifies.
#[test]
fn honest_trace_verifies() {
    let f = build_fixture();
    assert!(f.trace.prove_and_verify_current().is_ok(), "honest trace must verify");
}

/// The former gap: forge `h4` to an arbitrary depth while keeping the caller-frame entry kind
/// honest, then match it with a contained `b0` excursion. The caller used to resume at a depth the
/// prover chose.
#[test]
fn forged_caller_depth_via_caller_frame_path_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();
    apply_depth_excursion(&f, &mut core);

    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "the proof pipeline must reject a forged saved caller depth: h4 is now bound to \
         b0 - overflow() on every DYNCALL row: {result:?}"
    );
}

/// Control: forge `h4` alone, leaving `b0` honest.
///
/// The direct `h4 = b0 - overflow()` constraint rejects this mutation. The block-stack relation
/// also rejects it because the caller-frame addition and removal disagree on the saved depth.
#[test]
fn forged_h4_without_matching_excursion_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();
    core_row_mut(&mut core, f.dyncall_row).decoder.hasher_state[4] =
        Felt::new_unchecked(FORGED_DEPTH);

    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(result.is_err(), "the proof pipeline must reject forged h4: {result:?}");
}

/// The sibling gap: DYNCALL's saved caller *overflow pointer* (`h5`) is likewise recorded from a
/// decoder cell. The stack-overflow relation pins it only when the overflow table is non-empty
/// (that branch is gated on `dyncall * overflow`), so the empty case — the common one — was open.
///
/// Forged the same way as `h4`: set `h5` on the DYNCALL row and carry the matching `b1` across
/// the excursion window, which bar's enclosing END erases before the last-row `b1 = 0` boundary.
#[test]
fn forged_caller_overflow_pointer_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();
    let forged = Felt::new_unchecked(1234);

    core_row_mut(&mut core, f.dyncall_row).decoder.hasher_state[5] = forged;
    for row in (f.dyncall_end + 1)..=f.outer_end {
        core_row_mut(&mut core, row).stack.b1 = forged;
    }

    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "the proof pipeline must reject a forged saved caller overflow pointer: h5 is now pinned to \
         zero on a DYNCALL taken from an empty overflow table: {result:?}"
    );
}

/// Control for the above: forging `h5` with `b1` left honest must be rejected by the
/// block-stack relation regardless, since the addition then records a pointer the matching
/// removal does not restore.
#[test]
fn forged_h5_without_matching_pointer_is_rejected() {
    let f = build_fixture();
    let mut core = f.trace.core.clone();
    core_row_mut(&mut core, f.dyncall_row).decoder.hasher_state[5] = Felt::new_unchecked(1234);

    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "forging h5 with b1 left honest must be rejected (the direct h5 constraint fires \
         first; before the fix this rejected via the block-stack relation): {result:?}"
    );
}

/// With one overflow row, DYNCALL must authenticate that row's predecessor as the saved caller
/// pointer. The forged pointer is carried to the matching END, so the caller-frame relation still
/// balances; only the overflow relation can reject it.
#[test]
fn forged_caller_overflow_pointer_with_nonempty_table_is_rejected() {
    let f = build_fixture_with_setup("mem_storew_le.40 push.111 movup.5 dyncall", 17);
    let mut core = f.trace.core.clone();
    let forged = Felt::new_unchecked(1234);

    core_row_mut(&mut core, f.dyncall_row).decoder.hasher_state[5] = forged;
    for row in (f.dyncall_end + 1)..=f.outer_end {
        core_row_mut(&mut core, row).stack.b1 = forged;
    }

    let result = f.trace.prove_and_verify_allowing_lookup_rejection(core);
    assert!(
        result.is_err(),
        "the proof pipeline must reject a saved pointer that is not the predecessor of the overflow row \
         consumed by DYNCALL: {result:?}"
    );
}
