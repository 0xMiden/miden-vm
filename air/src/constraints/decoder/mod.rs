//! Decoder constraints module.
//!
//! This module contains constraints for the decoder component of the Miden VM.
//! The decoder handles instruction decoding, control flow, and basic block management.
//!
//! ## Constraint Categories
//!
//! 1. **In-span constraints**: Ensure the in-span flag transitions correctly.
//! 2. **Op-bit binary constraints**: Ensure operation bits are binary.
//! 3. **Extra columns (e0, e1)**: Degree-reduction columns for operation flag computation.
//! 4. **Opcode-bit group constraints**: Reject unused encodings in the upper prefix groups.
//! 5. **General opcode-semantic constraints**: Per-operation invariants (SPLIT/LOOP, DYN, REPEAT,
//!    END, HALT).
//! 6. **Group count constraints**: Group-count transitions inside basic blocks.
//! 7. **Op group decoding (h0) constraints**: Base-128 opcode packing in h0.
//! 8. **Op index constraints**: Position tracking within an operation group.
//! 9. **Batch flag constraints**: Batch size encoding and unused-lane zeroing.
//! 10. **Block address (addr) constraints**: Hasher-table address management.
//! 11. **Control flow constraint**: Mutual exclusivity of `in_span` and `f_ctrl`.
//!
//! ## Mental Model
//!
//! The decoder trace is the control-flow spine of the VM. Each row is either:
//! - **inside a basic block** (`in_span` = 1) where ops execute and counters advance, or
//! - **a control-flow row** (`in_span` = 0) that starts/ends/reshapes a block.
//!
//! The constraints below enforce three linked ideas:
//! 1. **Opcode decoding is well-formed** (op bits and degree-reduction columns are consistent).
//! 2. **Span state is coherent** (`in_span`, `group_count`, `op_index` evolve exactly as
//!    control-flow allows).
//! 3. **Hasher lanes match batch semantics** (batch flags and h0..h7 encode the pending groups).
//!
//! Read the sections in that order: first the binary/format checks, then the span state machine,
//! then the counters and packing rules that make group decoding deterministic.
//!
//! ## Decoder Trace Layout
//!
//! ```text
//! addr | b0 b1 b2 b3 b4 b5 b6 | h0 h1 h2 h3 h4 h5 h6 h7 | sp | gc | ox | c0 c1 c2 | e0 e1
//!  (1)        (7 op bits)             (8 hasher state)    (1)  (1)  (1)    (3)        (2)
//! ```
//!
//! ### Hasher state dual-purpose (`h0`–`h7`)
//!
//! The 8 hasher-state columns serve different roles depending on the current operation:
//!
//! | Context     | h0         | h1..h3    | h4             | h5      | h6      | h7         |
//! |-------------|------------|-----------|----------------|---------|---------|------------|
//! | SPAN/RESPAN | packed ops | op groups | op group       | op group| op group| op group   |
//! | END         | block hash₀| hash₁..₃ | is_loop_body   | is_loop | restores_caller_frame | 0 |
//! | User ops    | packed ops | op groups | user_op_helper | ...     | ...     | ...        |
//!
//! ## Operation Flag Degrees
//!
//! | Operation | Flag         | Degree |
//! |-----------|:------------:|:------:|
//! | JOIN      | f_join       |   5    |
//! | SPLIT     | f_split      |   5    |
//! | LOOP      | f_loop       |   5    |
//! | REPEAT    | f_repeat     |   4    |
//! | SPAN      | f_span       |   5    |
//! | RESPAN    | f_respan     |   4    |
//! | DYN       | f_dyn        |   5    |
//! | END       | f_end        |   4    |
//! | HALT      | f_halt       |   4    |
//! | PUSH      | f_push       |   5    |
//! | f_ctrl    | (composite)  |   5    |

pub mod columns;

use miden_crypto::stark::air::AirBuilder;
use p3_field::Dup;

use crate::{
    CoreCols, Felt, MidenAirBuilder,
    constraints::{
        constants::{F_1, F_128},
        decoder::columns::DecoderCols,
        op_flags::OpFlags,
        utils::{BoolNot, horner_eval_bits},
    },
    trace::chiplets::hasher::CONTROLLER_ROWS_PER_PERM_FELT,
};

// ENTRY POINTS
// ================================================================================================

/// Enforces decoder main-trace constraints (entry point).
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &CoreCols<AB::Var>,
    next: &CoreCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // --- Destructure current-row decoder columns ------------------------------------------------
    let DecoderCols {
        addr,
        op_bits,
        hasher_state,
        in_span,
        group_count,
        op_index,
        batch_flags,
        extra,
    } = local.decoder;
    let [b0, b1, b2, b3, b4, b5, b6] = op_bits;
    let [bc0, bc1, bc2] = batch_flags;
    let [e0, e1] = extra;
    let h0 = hasher_state[0];

    // End-block flags occupy hasher_state[4..8] during END operations.
    let end_flags = local.decoder.end_block_flags();
    let is_loop_body = end_flags.is_loop_body;
    let is_loop = end_flags.is_loop;

    // --- Destructure next-row decoder columns ---------------------------------------------------
    let DecoderCols {
        addr: addr_next,
        op_bits: op_bits_next,
        hasher_state: hasher_state_next,
        in_span: in_span_next,
        group_count: group_count_next,
        op_index: op_index_next,
        ..
    } = next.decoder;
    let h0_next = hasher_state_next[0];

    // --- Cached derived expressions -------------------------------------------------------------
    // These values appear in multiple constraint sections below.

    // The change in group count across one row.
    // Inside a span, delta_group_count is constrained to be boolean (0 or 1).
    // When delta_group_count = 1, a group has been consumed (either a completed op group or a PUSH
    // immediate). When delta_group_count = 0, the current group is still being decoded.
    let delta_group_count: AB::Expr = group_count - group_count_next;

    // PUSH is the only operation with an immediate value. When PUSH executes, it consumes
    // an op group from h0 to read the immediate value pushed onto the stack, causing
    // delta_group_count = 1. However, this is NOT a "new group start" for decoding purposes — the
    // distinction matters for the new_group flag: new_group = delta_group_count - is_push.
    let is_push = op_flags.push();

    // =============================================
    // In-span constraints
    // =============================================
    // The in_span flag indicates whether we are inside a basic block:
    //   in_span = 1 when executing user operations,
    //   in_span = 0 on control-flow rows (SPAN, RESPAN, END, JOIN, SPLIT, LOOP, etc.).
    //
    // in_span is pinned to 1 - f_ctrl on every row by the control-flow constraint at
    // the end of this function (in_span + f_ctrl = 1). The transition constraint below links
    // adjacent rows so that spans can only be entered and exited through the intended operations.

    // Execution starts outside any basic block.
    builder.when_first_row().assert_zero(in_span);

    // The in-span flag is binary.
    builder.assert_bool(in_span);

    // SPAN/RESPAN enter a span; END/RESPAN exit one.
    let enters_span = op_flags.span() + op_flags.respan();
    let exits_span_next = op_flags.end_next() + op_flags.respan_next();
    let continues_span = in_span * exits_span_next.not();

    // Gate this row-to-row rule for defense in depth, so correctness does not rely on the cyclic
    // final-to-first instance. That instance would also hold: the final HALT row has in_span = 0,
    // and the first row independently constrains in_span = 0.
    builder.when_transition().assert_eq(in_span_next, enters_span + continues_span);

    // =============================================
    // Op-bit binary constraints
    // =============================================
    // Each opcode bit must be 0 or 1.
    builder.assert_bools(op_bits);

    // =============================================
    // Extra columns (e0, e1) — degree reduction
    // =============================================
    // e0 and e1 reduce flag degrees for prefixes 101 and 11 so their operation-specific
    // constraints fit the degree-9 budget.
    //
    //   e0 = b6 · (1 - b5) · b4    selects the "101" prefix (degree-5 ops)
    //   e1 = b6 · b5               selects the "11" prefix (degree-4 ops)

    // e0 must equal b6 · (1 - b5) · b4.
    let e0_expected = b6 * b5.into().not() * b4;
    builder.assert_eq(e0, e0_expected);

    // e1 must equal b6 · b5.
    let e1_expected = b6 * b5;
    builder.assert_eq(e1, e1_expected);

    // =============================================
    // Opcode-bit group constraints
    // =============================================
    // Restrict unused opcode encodings in the upper prefix groups:
    //
    //   b6 b5 b4 | Constraint
    //   ---------+----------------------
    //   1  0  0  | b0 = 0
    //   1  0  1  | exclude opcode 95
    //   1  1  *  | b0 = b1 = 0
    //
    // With Boolean opcode bits and constrained e0, b6 - e0 selects prefixes 100 and 11,
    // disjoint from e0's 101 prefix. Under prefix 101, b0 is forbidden only for slot 95.
    let prefix_100_or_11 = b6 - e0;
    let prefix_101_with_low_bits_111 = e0 * b3 * b2 * b1;
    builder.when(prefix_100_or_11 + prefix_101_with_low_bits_111).assert_zero(b0);

    // Prefix 11 also requires b1 = 0.
    builder.when(e1).assert_zero(b1);

    // =============================================
    // General opcode-semantic constraints
    // =============================================
    // Per-operation invariants that don't fit into the generic counter/decoding sections.
    //
    // Operation | Constraint                          | Why
    // ----------+-------------------------------------+------------------------------------
    // SPLIT     | s0 in {0, 1}                        | s0 selects true/false branch
    // DYN       | h4 = h5 = h6 = h7 = 0               | callee digest lives in h0..h3 only
    // REPEAT    | s0 = 1                              | loop condition must be true
    // END+loop  | is_loop (h5) => s0 = 0              | exiting loop: condition became false
    // END+REP'  | is_loop_body (h4) = 1               | REPEAT follows a loop-body END
    // HALT      | f_halt => f_halt'                   | absorbing / terminal state

    // SPLIT: branch selector must be binary.
    let branch_condition = local.stack.get(0);
    builder.when(op_flags.split()).assert_bool(branch_condition);

    // DYN: the upper hasher lanes must be zero so the callee digest in h0..h3 is the
    // only input to the hash chiplet.
    {
        let builder = &mut builder.when(op_flags.dyn_op());
        let hasher_zeros = [hasher_state[4], hasher_state[5], hasher_state[6], hasher_state[7]];
        builder.assert_zeros(hasher_zeros)
    }

    // DYNCALL records its caller's post-pop stack depth and overflow pointer in h4/h5. Bind the
    // depth directly; the overflow relation binds h5 when non-empty, and the constraint below
    // handles the empty case.
    {
        let overflow = op_flags.overflow();
        let builder = &mut builder.when(op_flags.dyncall());
        builder.assert_eq(hasher_state[4], local.stack.b0 - overflow.dup());
        builder.when(overflow.not()).assert_zero(hasher_state[5]);
    }

    // REPEAT consumes a true loop condition.
    builder.when(op_flags.repeat()).assert_one(local.stack.get(0));

    // END inside a loop: when ending a loop block (is_loop = h5 = 1), top-of-stack must
    // be 0 — the loop exits because the condition became false.
    let loop_condition = local.stack.get(0);
    builder.when(op_flags.end()).when(is_loop).assert_zero(loop_condition);

    // END entry-kind selectors form the same tagged union as `BlockStackMsg`. They are boolean and
    // mutually exclusive: an END consumes either a LOOP continuation or a caller frame, never
    // both. h7 has no END semantics and is fixed to zero rather than carrying unauthenticated
    // metadata.
    {
        let restores_caller_frame = end_flags.restores_caller_frame;
        let builder = &mut builder.when(op_flags.end());
        builder.assert_bool(is_loop);
        builder.assert_bool(restores_caller_frame);
        builder.assert_zero(hasher_state[7]);
        builder.assert_zero(is_loop * restores_caller_frame);
    }

    // `is_loop_body` is intentionally not authenticated by a standalone decoder constraint. The
    // block-hash relation includes it in the END key. A value of one can match only a LoopBody
    // entry emitted by the unique LOOP row that owns `addr_next`; a value of zero can match only a
    // non-loop child entry. The block-stack relation separately authenticates the END's
    // child-to-parent edge.

    // REPEAT can follow only a loop-body END; its own h0..h4 do not authorize the next body.
    builder
        .when_transition()
        .when(op_flags.repeat_next())
        .assert_one(op_flags.end() * is_loop_body);

    // Prevent LOOP -> END, which would skip the body when its lookup multiplicity is zero.
    builder
        .when_transition()
        .when(op_flags.loop_op())
        .assert_zero(op_flags.end_next());

    // The first row has no END predecessor, so it cannot be REPEAT.
    builder.when_first_row().assert_zero(op_flags.repeat());

    // HALT is absorbing: once entered, the VM stays in HALT for all remaining rows.
    builder.when_transition().when(op_flags.halt()).assert_one(op_flags.halt_next());

    // =============================================
    // Group count constraints
    // =============================================
    // The group_count column tracks remaining operation groups in the current basic block. On
    // LOOP control-flow rows, it is also reused by the block-hash lookup as the multiplicity of
    // the LOOP-committed body digest. That LOOP-side value is ignored by the op-group relation
    // because control-flow rows have `in_span = 0`.
    //
    // ## Lifecycle
    //
    // 1. SPAN/RESPAN: the prover sets group_count non-deterministically to the batch's group count.
    //    The constraint below forces delta_group_count = 1 on these rows.
    // 2. Normal execution: each time a group is fully decoded (h0 reaches 0) or a PUSH consumes an
    //    immediate, group_count decrements by 1 (delta_group_count = 1).
    // 3. END: group_count must be 0 — all groups in the span have been consumed.

    // Inside a span, group_count changes by at most 1. When it does change and this is not a PUSH,
    // h0 must already be 0 (the group was fully decoded).
    {
        let gate = builder.is_transition() * in_span;
        let builder = &mut builder.when(gate);
        builder.assert_bool(delta_group_count.clone());
        builder.when(delta_group_count.clone()).when(is_push.not()).assert_zero(h0);
    }

    // SPAN, RESPAN, and PUSH each consume exactly one group (delta_group_count = 1).
    builder
        .when(op_flags.span() + op_flags.respan() + is_push.clone())
        .assert_one(delta_group_count.clone());

    // If delta_group_count = 1 on this row, the next row cannot be END or RESPAN — those ops need
    // a fresh batch or span closure, not a mid-batch decrement.
    builder
        .when_transition()
        .when(delta_group_count.clone())
        .assert_zero(op_flags.end_next() + op_flags.respan_next());

    // By the time END executes, all groups must have been consumed.
    builder.when(op_flags.end()).assert_zero(group_count);

    // =============================================
    // Op group decoding (h0) constraints
    // =============================================
    // Register h0 holds the current operation group as a base-128 packed integer.
    // Operations are packed least-significant first (each opcode is 7 bits):
    //
    //   h0 = op_0 + 128·op_1 + 128²·op_2 + ... + 128^(k-1)·op_(k-1)
    //
    // Each step, the VM peels off the lowest 7 bits of h0 — these bits equal the
    // opcode that will appear in op_bits on the *next* row (op'). What remains
    // after removing op' becomes h0':
    //
    //   h0 = h0' · 128 + op'        (no field division needed)
    //
    // ## same_group_count flag
    //
    //   same_group_count = in_span · in_span' · (1 - delta_group_count)
    //
    // This is 1 when we are inside a span on BOTH this and the next row AND the group
    // count did not change — meaning we are still decoding ops from the same group.
    // Note: same_group_count is mutually exclusive with f_span, f_respan, and is_push
    // because those three always set delta_group_count = 1.
    //
    // ## h0_active flag
    //
    //   h0_active = f_span + f_respan + is_push + same_group_count
    //
    // The h0 shift constraint fires in exactly 4 situations:
    // - f_span/f_respan: a new batch was just loaded; h0 has the first group.
    // - is_push: PUSH consumed an immediate; h0 shifts to reveal the next op.
    // - same_group_count: normal op execution within a group; h0 shifts by one opcode.
    {
        let f_span = op_flags.span();
        let f_respan = op_flags.respan();

        let same_group_count: AB::Expr = in_span * in_span_next * delta_group_count.not();
        let op_next: AB::Expr = horner_eval_bits(&op_bits_next);

        // When h0 is active, verify the base-128 shift.
        let h0_shift = h0 - h0_next * F_128 - op_next;
        let h0_active = f_span + f_respan + is_push.clone() + same_group_count;
        builder.when_transition().when(h0_active).assert_zero(h0_shift);

        // Before END or RESPAN, h0 must be empty (all ops in the group consumed).
        let end_or_respan_next = op_flags.end_next() + op_flags.respan_next();
        builder.when_transition().when(in_span).when(end_or_respan_next).assert_zero(h0);
    }

    // =============================================
    // Op index constraints
    // =============================================
    // The op_index column tracks the position of the current operation within its operation
    // group. op_index ranges from 0 to 8 (up to 9 operations per group), resets to 0 when
    // entering a new group, and increments by 1 for each operation within a group.
    //
    // ## new_group flag
    //
    //   new_group = delta_group_count - is_push
    //
    // When new_group = 1, a genuine new group is starting: group_count decremented and it
    // was NOT because of a PUSH immediate. When new_group = 0, we are still in the same
    // group (either group_count didn't change, or it changed only because of PUSH).
    {
        let new_group: AB::Expr = delta_group_count - is_push;

        // SPAN/RESPAN start a fresh batch, so op_index' = 0.
        builder.when(op_flags.span() + op_flags.respan()).assert_zero(op_index_next);

        // When a new group starts inside a span, op_index' = 0.
        // Gated by in_span to exclude SPAN/RESPAN rows (which are handled above).
        builder
            .when_transition()
            .when(in_span)
            .when(new_group.clone())
            .assert_zero(op_index_next);

        // When staying in the same group inside a span, op_index increments by 1.
        // Gated by in_span_next to exclude the row before END/RESPAN (where in_span' = 0).
        builder
            .when_transition()
            .when(in_span)
            .when(in_span_next)
            .when(new_group.not())
            .assert_eq(op_index_next, op_index + F_1);

        // op_index must be in [0, 8] — 9 ops per group max.
        let mut range_check: AB::Expr = op_index.into();
        for i in 1..=8u64 {
            range_check *= op_index - Felt::new_unchecked(i);
        }
        builder.assert_zero(range_check);
    }

    // =============================================
    // Batch flag constraints
    // =============================================
    // Batch flags (c0, c1, c2) encode the number of op groups in the current batch.
    // This matters for the last batch in a basic block (or the only batch), since all
    // other batches must be completely full (8 groups).
    //
    // The flags are mutually exclusive (exactly one is set during SPAN/RESPAN).
    // Unused hasher lanes must be zero to prevent the prover from smuggling
    // arbitrary values through unused group slots. The zeroed lanes cascade:
    //
    //   Groups | Zeroed lanes
    //   -------+--------------
    //      8   | (none)
    //      4   | h4..h7
    //      2   | h2..h7
    //      1   | h1..h7
    {
        // Batch flag bits must be binary.
        builder.assert_bools([bc0, bc1, bc2]);

        // 8 groups: c0 = 1 (c1, c2 don't matter).
        let groups_8 = bc0;
        // 4 groups: c0 = 0, c1 = 1, c2 = 0.
        let not_bc0 = bc0.into().not();
        let groups_4 = not_bc0.clone() * bc1 * bc2.into().not();
        // 2 groups: c0 = 0, c1 = 0, c2 = 1.
        let groups_2 = not_bc0.clone() * bc1.into().not() * bc2;
        // 1 group: c0 = 0, c1 = 1, c2 = 1.
        let groups_1 = not_bc0 * bc1 * bc2;

        // Combined flags for the cascading lane-zeroing constraints.
        let groups_1_or_2 = groups_1.clone() + groups_2;
        let groups_1_or_2_or_4 = groups_1_or_2.clone() + groups_4;

        let span_or_respan = op_flags.span() + op_flags.respan();

        // During SPAN/RESPAN, exactly one batch flag must be set.
        builder.assert_eq(span_or_respan.clone(), groups_1_or_2_or_4.clone() + groups_8);

        // Outside SPAN/RESPAN, all batch flags must be zero.
        builder.when(span_or_respan.not()).assert_zero(bc0 + bc1 + bc2);

        // Fewer than 8 groups: h4..h7 are unused and must be zero.
        {
            let builder = &mut builder.when(groups_1_or_2_or_4);
            for i in 0..4 {
                builder.assert_zero(hasher_state[4 + i]);
            }
        }

        // Fewer than 4 groups: h2..h3 are also unused.
        {
            let builder = &mut builder.when(groups_1_or_2);
            for i in 0..2 {
                builder.assert_zero(hasher_state[2 + i]);
            }
        }

        // Only 1 group: h1 is also unused.
        builder.when(groups_1).assert_zero(hasher_state[1]);
    }

    // =============================================
    // Block address (addr) constraints
    // =============================================
    // The block address links decoder rows to the hasher table, which computes Poseidon2
    // hashes of MAST node contents. Each hash uses a controller input/output pair
    // (CONTROLLER_ROWS_PER_PERMUTATION = 2 rows in the hasher table).
    //
    // When RESPAN starts a new batch within the same span, the hasher table needs a new
    // controller pair, so addr increments by CONTROLLER_ROWS_PER_PERMUTATION.

    // Inside a basic block, addr must stay the same (all ops in one batch share the same
    // hasher-table address). REPEAT also re-enters the same loop parent for another body
    // iteration.
    builder
        .when_transition()
        .when(in_span + op_flags.repeat())
        .assert_eq(addr_next, addr);

    // RESPAN moves to the next hash block (addr += CONTROLLER_ROWS_PER_PERMUTATION).
    builder
        .when(op_flags.respan())
        .assert_eq(addr_next, addr + CONTROLLER_ROWS_PER_PERM_FELT);

    // HALT forces addr = 0 (execution ends at the root block).
    builder.when(op_flags.halt()).assert_zero(addr);

    // =============================================
    // Control flow constraint
    // =============================================
    // Every row is either inside a basic block (in_span = 1) or executing a control-flow
    // operation (f_ctrl = 1). These two states are mutually exclusive and exhaustive.
    //
    // f_ctrl covers: JOIN, SPLIT, LOOP, SPAN, RESPAN, END, REPEAT, HALT, DYN, DYNCALL,
    //                CALL, SYSCALL.
    //
    // This also implies in_span = 1 - f_ctrl, so in_span is automatically 0 on
    // control-flow rows and 1 otherwise (given that in_span is binary, enforced above).
    builder.assert_one(in_span + op_flags.control_flow());

    // Last-row boundary: the final row must be HALT. The processor pads the trace with
    // HALT rows and the absorbing transition constraint keeps them there; this constraint
    // makes it explicit in the AIR.
    builder.when_last_row().assert_one(op_flags.halt());
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::{
        Felt, ONE,
        field::{Field, PrimeCharacteristicRing, QuadFelt},
        operations::opcodes,
    };

    use super::{CONTROLLER_ROWS_PER_PERM_FELT, enforce_main};
    use crate::{
        CoreCols,
        constraints::{
            op_flags::{OpFlags, generate_test_row},
            stack::test_utils::ConstraintEvalBuilder,
        },
    };

    fn eval_decoder(local: &CoreCols<Felt>, next: &CoreCols<Felt>) -> Vec<QuadFelt> {
        let op_flags = OpFlags::new(&local.decoder, &local.stack, &next.decoder);
        let mut builder = ConstraintEvalBuilder::new();
        enforce_main(&mut builder, local, next, &op_flags);
        builder.evaluations
    }

    fn decoder_accepts(local: &CoreCols<Felt>, next: &CoreCols<Felt>) -> bool {
        eval_decoder(local, next).iter().all(|v| *v == QuadFelt::ZERO)
    }

    #[test]
    fn decoder_rejects_exit_from_span_without_end_or_respan() {
        let mut local = generate_test_row(opcodes::EQ.into());
        local.decoder.in_span = ONE;
        local.decoder.addr = ONE;
        local.decoder.group_count = Felt::from_u8(3);
        local.decoder.hasher_state[0] = Felt::from_u8(opcodes::ASSERT);

        let mut next = generate_test_row(opcodes::SPAN.into());
        next.decoder.addr = ONE;
        next.decoder.group_count = Felt::from_u8(3);

        assert!(
            !decoder_accepts(&local, &next),
            "leaving a span without END or RESPAN must violate the decoder AIR",
        );
    }

    #[test]
    fn decoder_rejects_entry_into_span_without_span_or_respan() {
        let mut local = generate_test_row(opcodes::REPEAT.into());
        local.stack.top[0] = ONE;
        local.decoder.hasher_state[4] = ONE;

        let mut next = generate_test_row(opcodes::NOOP.into());
        next.decoder.in_span = ONE;
        next.decoder.group_count = Felt::from_u8(3);

        assert!(
            !decoder_accepts(&local, &next),
            "entering a span without SPAN or RESPAN must violate the decoder AIR",
        );
    }

    fn honest_in_span_pair() -> (CoreCols<Felt>, CoreCols<Felt>) {
        let mut local = generate_test_row(opcodes::NOOP.into());
        let mut next = generate_test_row(opcodes::NOOP.into());
        local.decoder.addr = Felt::new_unchecked(17);
        next.decoder.addr = local.decoder.addr;
        local.decoder.in_span = Felt::ONE;
        next.decoder.in_span = Felt::ONE;
        local.decoder.group_count = Felt::ONE;
        next.decoder.group_count = Felt::ONE;
        local.decoder.op_index = Felt::ZERO;
        next.decoder.op_index = Felt::ONE;
        (local, next)
    }

    fn span_row_with_single_group() -> CoreCols<Felt> {
        let mut row = generate_test_row(opcodes::SPAN.into());
        row.decoder.addr = Felt::new_unchecked(17);
        row.decoder.group_count = Felt::new_unchecked(2);
        row.decoder.batch_flags[1] = Felt::ONE;
        row.decoder.batch_flags[2] = Felt::ONE;
        row
    }

    fn repeat_row_with_true_condition() -> CoreCols<Felt> {
        let mut row = generate_test_row(opcodes::REPEAT.into());
        row.stack.top[0] = Felt::ONE;
        row
    }

    fn set_opcode(row: &mut CoreCols<Felt>, opcode: usize) {
        let opcode_row = generate_test_row(opcode);
        row.decoder.op_bits = opcode_row.decoder.op_bits;
        row.decoder.extra = opcode_row.decoder.extra;
    }

    #[test]
    fn permitted_decoder_adjacency_pairs_are_accepted() {
        let (in_span_local, in_span_next) = honest_in_span_pair();
        assert!(
            decoder_accepts(&in_span_local, &in_span_next),
            "an ordinary in-span transition must be accepted"
        );

        let span = span_row_with_single_group();
        let mut first_op = generate_test_row(opcodes::NOOP.into());
        first_op.decoder.addr = span.decoder.addr;
        first_op.decoder.in_span = Felt::ONE;
        first_op.decoder.group_count = Felt::ONE;
        assert!(decoder_accepts(&span, &first_op), "SPAN must be allowed to enter a basic block");

        let mut respan = span_row_with_single_group();
        set_opcode(&mut respan, opcodes::RESPAN.into());
        first_op.decoder.addr = respan.decoder.addr + CONTROLLER_ROWS_PER_PERM_FELT;
        assert!(
            decoder_accepts(&respan, &first_op),
            "RESPAN must be allowed to enter the next batch"
        );

        for exit_opcode in [opcodes::END, opcodes::RESPAN] {
            let mut in_span = generate_test_row(opcodes::NOOP.into());
            let mut exit = generate_test_row(exit_opcode.into());
            in_span.decoder.addr = Felt::new_unchecked(17);
            exit.decoder.addr = in_span.decoder.addr;
            in_span.decoder.in_span = Felt::ONE;
            assert!(
                decoder_accepts(&in_span, &exit),
                "an in-span row must be allowed to exit via opcode {exit_opcode}"
            );
        }

        let mut end = generate_test_row(opcodes::END.into());
        let mut repeat = repeat_row_with_true_condition();
        end.stack.top[0] = Felt::ONE;
        end.decoder.hasher_state[4] = Felt::ONE;
        repeat.decoder.hasher_state[0] = Felt::new_unchecked(7);
        assert!(
            decoder_accepts(&end, &repeat),
            "a loop-body END may precede REPEAT without copying its helper lanes"
        );

        end.stack.top[0] = Felt::ZERO;
        end.decoder.hasher_state[5] = Felt::ONE;
        assert!(
            decoder_accepts(&end, &repeat),
            "the completed loop body may itself be a nested LOOP"
        );
    }

    #[test]
    fn malformed_decoder_adjacency_pairs_are_rejected() {
        let (mut in_span, _) = honest_in_span_pair();
        let mut repeat = repeat_row_with_true_condition();
        repeat.decoder.addr = in_span.decoder.addr;
        assert!(
            !decoder_accepts(&in_span, &repeat),
            "an in-span row cannot exit directly to REPEAT"
        );

        let loop_row = generate_test_row(opcodes::LOOP.into());
        assert!(!decoder_accepts(&loop_row, &repeat), "REPEAT's predecessor must be END");

        let non_loop_body_end = generate_test_row(opcodes::END.into());
        assert!(
            !decoder_accepts(&non_loop_body_end, &repeat_row_with_true_condition()),
            "REPEAT must follow an END marked as a loop body"
        );

        let end = generate_test_row(opcodes::END.into());
        let mut illegal_entry = generate_test_row(opcodes::NOOP.into());
        illegal_entry.decoder.in_span = Felt::ONE;
        assert!(
            !decoder_accepts(&end, &illegal_entry),
            "an in-span successor must be entered by SPAN/RESPAN or another in-span row"
        );

        in_span.decoder.in_span = Felt::ONE;
        let split = generate_test_row(opcodes::SPLIT.into());
        assert!(
            !decoder_accepts(&in_span, &split),
            "a basic-block row cannot exit via arbitrary control flow"
        );
    }

    #[test]
    fn loop_cannot_jump_directly_to_its_end() {
        let loop_row = generate_test_row(opcodes::LOOP.into());
        let span = span_row_with_single_group();
        assert!(decoder_accepts(&loop_row, &span), "LOOP must be allowed to enter its body");

        let end = generate_test_row(opcodes::END.into());
        assert!(
            !decoder_accepts(&loop_row, &end),
            "LOOP must not skip its do-while body by jumping directly to END"
        );
    }

    #[test]
    fn opcode_prefix_boundaries() {
        let (mut local, next) = honest_in_span_pair();
        for opcode in [opcodes::U32ADD, opcodes::LOGDEFERRED, opcodes::MRUPDATE] {
            set_opcode(&mut local, opcode.into());
            assert!(decoder_accepts(&local, &next), "opcode {opcode} must be accepted");
        }

        for opcode in [65, 95, 97, 98] {
            set_opcode(&mut local, opcode);
            assert!(!decoder_accepts(&local, &next), "unused opcode {opcode} must be rejected");
        }
    }

    /// END entry-kind selectors must encode exactly one valid semantic kind.
    ///
    /// Every other soundness test in this tree keeps these selectors valid, so the invalid cases
    /// here are what make each domain constraint mutation-sensitive.
    #[test]
    fn block_stack_entry_kind_selectors_must_encode_a_valid_kind() {
        let accepts = |is_loop: Felt, restores_caller_frame: Felt, h7: Felt| {
            let mut local = generate_test_row(opcodes::END.into());
            local.decoder.hasher_state[5] = is_loop;
            local.decoder.hasher_state[6] = restores_caller_frame;
            local.decoder.hasher_state[7] = h7;
            let next = generate_test_row(0);
            eval_decoder(&local, &next).iter().all(|v| *v == QuadFelt::ZERO)
        };

        // Every semantic END block-stack entry kind: non-loop continuation, LOOP continuation,
        // and caller frame.
        for (is_loop, restores_caller_frame, h7) in [
            (Felt::ZERO, Felt::ZERO, Felt::ZERO),
            (Felt::ONE, Felt::ZERO, Felt::ZERO),
            (Felt::ZERO, Felt::ONE, Felt::ZERO),
        ] {
            assert!(
                accepts(is_loop, restores_caller_frame, h7),
                "a valid END entry kind must be permitted"
            );
        }

        assert!(
            !accepts(Felt::new_unchecked(3), Felt::ZERO, Felt::ZERO),
            "a non-boolean LOOP selector must be rejected"
        );
        assert!(
            !accepts(Felt::ONE, Felt::ONE, Felt::ZERO),
            "an END cannot be both a LOOP continuation and a caller frame"
        );
        assert!(
            !accepts(Felt::ZERO, Felt::ONE, Felt::ONE),
            "the unused h7 lane must be zero on an END row"
        );
        assert!(
            !accepts(Felt::ZERO, Felt::new_unchecked(3), Felt::ZERO),
            "a non-boolean caller-frame restoration selector must be rejected"
        );
    }

    /// Control against over-constraining: outside END rows these lanes are user-op helper
    /// registers, and the booleanity constraint is gated on the END flag so it must not reach
    /// them. Uses NOOP, which reads no helper registers.
    #[test]
    fn helper_lanes_are_unconstrained_off_end_rows() {
        let mut local = generate_test_row(opcodes::NOOP.into());
        local.decoder.hasher_state[5] = Felt::new_unchecked(3);
        local.decoder.hasher_state[6] = Felt::new_unchecked(5);
        local.decoder.hasher_state[7] = Felt::new_unchecked(7);
        let next = generate_test_row(0);

        // Re-evaluate with the lanes zeroed; the two runs must agree, i.e. no constraint in
        // this module reacted to them.
        let with_values = eval_decoder(&local, &next);
        let mut cleared = local;
        cleared.decoder.hasher_state[5] = Felt::ZERO;
        cleared.decoder.hasher_state[6] = Felt::ZERO;
        cleared.decoder.hasher_state[7] = Felt::ZERO;
        let with_zeros = eval_decoder(&cleared, &next);

        assert_eq!(
            with_values, with_zeros,
            "the END-gated booleanity constraint must not reach helper lanes on a NOOP row"
        );
    }

    /// DYNCALL records the caller state after consuming its address operand. The decoder binds
    /// the saved depth in both overflow regimes and binds the saved pointer directly only in the
    /// empty regime; with overflow present, the stack-overflow relation owns that pointer.
    #[test]
    fn dyncall_saved_frame_cells_follow_the_post_pop_state() {
        let accepts = |depth: Felt, overflow_helper: Felt, h4: Felt, h5: Felt| {
            let mut local = generate_test_row(opcodes::DYNCALL.into());
            local.stack.b0 = depth;
            local.stack.h0 = overflow_helper;
            local.decoder.hasher_state[4] = h4;
            local.decoder.hasher_state[5] = h5;
            let next = generate_test_row(0);
            eval_decoder(&local, &next).iter().all(|v| *v == QuadFelt::ZERO)
        };

        // Empty overflow: consuming the address leaves the represented depth clamped at 16 and
        // there is no previous overflow row, so both saved values are fixed directly.
        assert!(accepts(Felt::from_u8(16), Felt::ZERO, Felt::from_u8(16), Felt::ZERO));
        assert!(!accepts(Felt::from_u8(16), Felt::ZERO, Felt::from_u8(15), Felt::ZERO));
        assert!(!accepts(Felt::from_u8(16), Felt::ZERO, Felt::from_u8(16), Felt::ONE));

        // Non-empty overflow: at depth 18 the inverse helper makes `overflow() = 1`, so the
        // post-pop saved depth is 17. h5 is deliberately outside this module's authority here;
        // the DYNCALL removal in the stack-overflow relation binds it to the prior row address.
        let inverse_two = Felt::from_u8(2).inverse();
        let relation_owned_h5 = Felt::new_unchecked(123);
        assert!(accepts(Felt::from_u8(18), inverse_two, Felt::from_u8(17), relation_owned_h5));
        assert!(!accepts(Felt::from_u8(18), inverse_two, Felt::from_u8(18), relation_owned_h5));
    }
}
