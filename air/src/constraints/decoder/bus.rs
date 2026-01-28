//! Decoder virtual table bus constraints.
//!
//! This module enforces the running product constraints for the decoder's three virtual tables:
//! - p1: Block stack table (tracks block nesting during control flow)
//! - p2: Block hash table (tracks blocks awaiting execution)
//! - p3: Op group table (tracks operation groups within spans)
//!
//! ## Running Product Protocol
//!
//! Each table uses a running product protocol:
//! - p1: p1' * requests = p1 * responses, initial/final = 1
//! - p2: p2' * requests = p2 * responses, initial = program_hash_message (TODO), final = 1
//! - p3: p3' * requests = p3 * responses, initial/final = 1
//!
//! ## Message Format
//!
//! Messages are encoded as linear combinations: `sum(alpha[i] * element[i])`
//! where elements[0] is always 1 (the constant term).
//!
//! ## Constraint Degree Management
//!
//! Each operation type gets its own constraint with a `when` clause to keep degree manageable:
//! - Operation flags are degree 7 (product of opcode bits)
//! - Message expressions are degree 1 (linear combinations)
//! - Per-operation constraint: `flag * (p1' - p1 * message) = 0` has degree ~8
//!
//! This follows the air-script pattern from `decoder.air`:
//! ```text
//! bus_0_decoder_p1.insert(addr', addr, 0, ...) when fjoin;
//! bus_0_decoder_p1.insert(addr', addr, 0, ...) when fsplit;
//! ```
//!
//! ## Reference Implementation
//!
//! The processor's implementation is in:
//! - `processor/src/decoder/aux_trace/block_stack_table.rs` (p1)
//! - `processor/src/decoder/aux_trace/block_hash_table.rs` (p2)
//! - `processor/src/decoder/aux_trace/op_group_table.rs` (p3)
//!
//! The air-script reference is in:
//! - `~/air-script/constraints/decoder.air` (lines 123-154)

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;
use p3_matrix::Matrix;

use crate::{
    Felt, MainTraceRow,
    constraints::{bus::indices::P1_BLOCK_STACK, stack::op_flags::OpFlags},
};

// CONSTANTS
// ================================================================================================

/// Decoder column indices (relative to decoder trace).
mod decoder_cols {
    /// Block address column.
    pub const ADDR: usize = 0;
    /// Hasher state offset within decoder trace.
    pub const HASHER_STATE_OFFSET: usize = 8;
    /// is_loop_flag column (hasher_state[5]).
    pub const IS_LOOP_FLAG: usize = HASHER_STATE_OFFSET + 5;
    /// is_call_flag column (hasher_state[6]).
    pub const IS_CALL_FLAG: usize = HASHER_STATE_OFFSET + 6;
    /// is_syscall_flag column (hasher_state[7]).
    pub const IS_SYSCALL_FLAG: usize = HASHER_STATE_OFFSET + 7;
}

/// Stack column indices (relative to stack trace).
mod stack_cols {
    /// B0 column - stack depth.
    pub const B0: usize = 16;
    /// B1 column - overflow address.
    pub const B1: usize = 17;
}

/// Op group table column indices (relative to decoder trace).
mod op_group_cols {
    /// HASHER_STATE_RANGE.end (hasher state is 8 columns starting at offset 8).
    const HASHER_STATE_END: usize = super::decoder_cols::HASHER_STATE_OFFSET + 8;

    /// is_in_span flag column.
    pub const IS_IN_SPAN: usize = HASHER_STATE_END;

    /// Group count column.
    pub const GROUP_COUNT: usize = IS_IN_SPAN + 1;

    /// Op index column (not used directly here but defines layout).
    const OP_INDEX: usize = GROUP_COUNT + 1;

    /// Batch flag columns (c0, c1, c2).
    const BATCH_FLAGS_OFFSET: usize = OP_INDEX + 1;
    pub const BATCH_FLAG_0: usize = BATCH_FLAGS_OFFSET;
    pub const BATCH_FLAG_1: usize = BATCH_FLAGS_OFFSET + 1;
    pub const BATCH_FLAG_2: usize = BATCH_FLAGS_OFFSET + 2;
}

// ENTRY POINTS
// ================================================================================================

/// Enforces all decoder bus constraints (p1, p2, p3).
pub fn enforce_bus<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    enforce_block_stack_table_constraint(builder, local, next, op_flags);
    enforce_block_hash_table_constraint(builder, local, next, op_flags);
    enforce_op_group_table_constraint(builder, local, next, op_flags);
}

// CONSTRAINT HELPERS
// ================================================================================================

// BLOCK STACK TABLE (p1)
// ================================================================================================

/// Enforces the block stack table (p1) bus constraint.
///
/// The block stack table tracks block nesting state. Entries are added when blocks start
/// and removed when blocks end or transition (RESPAN).
///
/// ## Constraint Structure
///
/// ```text
/// p1' * (u_end + u_respan + 1 - (f_end + f_respan)) =
/// p1 * (v_join + v_split + v_loop + v_span + v_respan + v_dyn + v_dyncall + v_call + v_syscall
///       + 1 - (f_join + f_split + f_loop + f_span + f_respan + f_dyn + f_dyncall + f_call + f_syscall))
/// ```
///
/// Where:
/// - `v_xxx = f_xxx * message_xxx` (insertion contribution, degree 7+1=8)
/// - `u_xxx = f_xxx * message_xxx` (removal contribution, degree 7+1=8)
/// - Full constraint degree: 1 + 8 = 9
///
/// ## Message Format
///
/// Messages are linear combinations: `alpha[0]*1 + alpha[1]*block_id + alpha[2]*parent_id + ...`
/// - Simple blocks: 4 elements `[1, block_id, parent_id, is_loop]`
/// - CALL/SYSCALL/DYNCALL: 11 elements with context `[..., ctx, fmp, b0, b1, fn_hash[0..4]]`
pub fn enforce_block_stack_table_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Auxiliary trace must be present
    debug_assert!(
        builder.permutation().height() > 0,
        "Auxiliary trace must be present for block stack table constraint"
    );

    // Extract auxiliary trace values
    let (p1_local, p1_next) = {
        let aux = builder.permutation();
        let aux_local = aux.row_slice(0).expect("Matrix should have at least 1 row");
        let aux_next = aux.row_slice(1).expect("Matrix should have at least 2 rows");
        (aux_local[P1_BLOCK_STACK], aux_next[P1_BLOCK_STACK])
    };

    // Get challenges for message encoding (11 alphas)
    let challenges = builder.permutation_randomness();
    let alphas: [AB::ExprEF; 11] = core::array::from_fn(|i| challenges[i].into());

    let one = AB::Expr::ONE;
    let zero = AB::Expr::ZERO;
    let one_ef = AB::ExprEF::ONE;

    // Helper to convert trace value to base field expression
    let to_expr = |v: AB::Var| -> AB::Expr { v.into() };

    // =========================================================================
    // BOUNDARY CONSTRAINTS
    // =========================================================================

    // p1 must start and end at 1 (balanced multiset)
    builder.when_first_row().assert_eq_ext(p1_local.into(), one_ef.clone());
    builder.when_last_row().assert_eq_ext(p1_local.into(), one_ef.clone());

    // =========================================================================
    // TRACE VALUE EXTRACTION
    // =========================================================================

    // Block addresses
    let addr_local = to_expr(local.decoder[decoder_cols::ADDR].clone());
    let addr_next = to_expr(next.decoder[decoder_cols::ADDR].clone());

    // Hasher state element 1 (for RESPAN parent_id)
    let h1_next = to_expr(next.decoder[decoder_cols::HASHER_STATE_OFFSET + 1].clone());

    // Stack top (for LOOP is_loop condition)
    let s0 = to_expr(local.stack[0].clone());

    // Context info for CALL/SYSCALL/DYNCALL insertions (from current row)
    let ctx_local = to_expr(local.ctx.clone());
    let b0_local = to_expr(local.stack[stack_cols::B0].clone());
    let b1_local = to_expr(local.stack[stack_cols::B1].clone());
    let fn_hash_local: [AB::Expr; 4] = [
        to_expr(local.fn_hash[0].clone()),
        to_expr(local.fn_hash[1].clone()),
        to_expr(local.fn_hash[2].clone()),
        to_expr(local.fn_hash[3].clone()),
    ];

    // Hasher state for DYNCALL (h4, h5 contain post-shift stack state)
    let h4_local = to_expr(local.decoder[decoder_cols::HASHER_STATE_OFFSET + 4].clone());
    let h5_local = to_expr(local.decoder[decoder_cols::HASHER_STATE_OFFSET + 5].clone());

    // Flags for END context detection
    let is_loop_flag = to_expr(local.decoder[decoder_cols::IS_LOOP_FLAG].clone());
    let is_call_flag = to_expr(local.decoder[decoder_cols::IS_CALL_FLAG].clone());
    let is_syscall_flag = to_expr(local.decoder[decoder_cols::IS_SYSCALL_FLAG].clone());

    // Context info for END after CALL/SYSCALL (from next row)
    let ctx_next = to_expr(next.ctx.clone());
    let b0_next = to_expr(next.stack[stack_cols::B0].clone());
    let b1_next = to_expr(next.stack[stack_cols::B1].clone());
    let fn_hash_next: [AB::Expr; 4] = [
        to_expr(next.fn_hash[0].clone()),
        to_expr(next.fn_hash[1].clone()),
        to_expr(next.fn_hash[2].clone()),
        to_expr(next.fn_hash[3].clone()),
    ];

    // =========================================================================
    // MESSAGE BUILDERS
    // =========================================================================

    // Simple message: alpha[0] + alpha[1]*block_id + alpha[2]*parent_id + alpha[3]*is_loop
    let simple_msg =
        |block_id: &AB::Expr, parent_id: &AB::Expr, is_loop: &AB::Expr| -> AB::ExprEF {
            alphas[0].clone()
                + alphas[1].clone() * block_id.clone()
                + alphas[2].clone() * parent_id.clone()
                + alphas[3].clone() * is_loop.clone()
        };

    // Full message with context (for CALL/SYSCALL/DYNCALL)
    let full_msg = |block_id: &AB::Expr,
                    parent_id: &AB::Expr,
                    is_loop: &AB::Expr,
                    ctx: &AB::Expr,
                    depth: &AB::Expr,
                    overflow: &AB::Expr,
                    fh: &[AB::Expr; 4]|
     -> AB::ExprEF {
        alphas[0].clone()
            + alphas[1].clone() * block_id.clone()
            + alphas[2].clone() * parent_id.clone()
            + alphas[3].clone() * is_loop.clone()
            + alphas[4].clone() * ctx.clone()
            + alphas[5].clone() * depth.clone()
            + alphas[6].clone() * overflow.clone()
            + alphas[7].clone() * fh[0].clone()
            + alphas[8].clone() * fh[1].clone()
            + alphas[9].clone() * fh[2].clone()
            + alphas[10].clone() * fh[3].clone()
    };

    // =========================================================================
    // INSERTION CONTRIBUTIONS (v_xxx = f_xxx * message)
    // =========================================================================

    // Get operation flags
    let f_join = op_flags.join();
    let f_split = op_flags.split();
    let f_span = op_flags.span();
    let f_dyn = op_flags.dyn_op();
    let f_loop = op_flags.loop_op();
    let f_respan = op_flags.respan();
    let f_call = op_flags.call();
    let f_syscall = op_flags.syscall();
    let f_dyncall = op_flags.dyncall();
    let f_end = op_flags.end();

    // JOIN/SPLIT/SPAN/DYN: insert(addr', addr, 0, ...)
    let msg_simple = simple_msg(&addr_next, &addr_local, &zero);
    let v_join = msg_simple.clone() * f_join.clone();
    let v_split = msg_simple.clone() * f_split.clone();
    let v_span = msg_simple.clone() * f_span.clone();
    let v_dyn = msg_simple.clone() * f_dyn.clone();

    // LOOP: insert(addr', addr, s0, ...)
    let msg_loop = simple_msg(&addr_next, &addr_local, &s0);
    let v_loop = msg_loop * f_loop.clone();

    // RESPAN: insert(addr', h1', 0, ...)
    let msg_respan_insert = simple_msg(&addr_next, &h1_next, &zero);
    let v_respan = msg_respan_insert * f_respan.clone();

    // CALL/SYSCALL: insert(addr', addr, 0, ctx, fmp, b0, b1, fn_hash[0..4])
    let msg_call =
        full_msg(&addr_next, &addr_local, &zero, &ctx_local, &b0_local, &b1_local, &fn_hash_local);
    let v_call = msg_call.clone() * f_call.clone();
    let v_syscall = msg_call * f_syscall.clone();

    // DYNCALL: insert(addr', addr, 0, ctx, h4, h5, fn_hash[0..4])
    let msg_dyncall =
        full_msg(&addr_next, &addr_local, &zero, &ctx_local, &h4_local, &h5_local, &fn_hash_local);
    let v_dyncall = msg_dyncall * f_dyncall.clone();

    // Sum of insertion flags
    let insert_flag_sum = f_join.clone()
        + f_split.clone()
        + f_span.clone()
        + f_dyn.clone()
        + f_loop.clone()
        + f_respan.clone()
        + f_call.clone()
        + f_syscall.clone()
        + f_dyncall.clone();

    // Total insertion contribution
    let insertion_sum =
        v_join + v_split + v_span + v_dyn + v_loop + v_respan + v_call + v_syscall + v_dyncall;

    // Response side: insertion_sum + (1 - insert_flag_sum)
    let response = insertion_sum + (one_ef.clone() - insert_flag_sum);

    // =========================================================================
    // REMOVAL CONTRIBUTIONS (u_xxx = f_xxx * message)
    // =========================================================================

    // RESPAN removal: remove(addr, h1', 0, ...)
    let msg_respan_remove = simple_msg(&addr_local, &h1_next, &zero);
    let u_respan = msg_respan_remove * f_respan.clone();

    // END for simple blocks: remove(addr, addr', is_loop_flag, 0, ...)
    let is_simple_end = one.clone() - is_call_flag.clone() - is_syscall_flag.clone();
    let msg_end_simple = simple_msg(&addr_local, &addr_next, &is_loop_flag);
    let end_simple_gate = f_end.clone() * is_simple_end;
    let u_end_simple = msg_end_simple * end_simple_gate;

    // END for CALL/SYSCALL: remove(addr, addr', is_loop_flag, ctx', b0', b1', fn_hash'[0..4])
    // Note: The is_loop value is the is_loop_flag from the current row (same as simple END)
    // Context values come from the next row's dedicated columns (not hasher state)
    let is_call_or_syscall = is_call_flag.clone() + is_syscall_flag.clone();
    let msg_end_call = full_msg(
        &addr_local,
        &addr_next,
        &is_loop_flag,
        &ctx_next,
        &b0_next,
        &b1_next,
        &fn_hash_next,
    );
    let end_call_gate = f_end.clone() * is_call_or_syscall;
    let u_end_call = msg_end_call * end_call_gate;

    // Total END contribution
    let u_end = u_end_simple + u_end_call;

    // Sum of removal flags
    let remove_flag_sum = f_end.clone() + f_respan.clone();

    // Total removal contribution
    let removal_sum = u_end + u_respan;

    // Request side: removal_sum + (1 - remove_flag_sum)
    let request = removal_sum + (one_ef.clone() - remove_flag_sum);

    // =========================================================================
    // RUNNING PRODUCT CONSTRAINT
    // =========================================================================

    // p1' * request = p1 * response
    let lhs: AB::ExprEF = p1_next.into() * request;
    let rhs: AB::ExprEF = p1_local.into() * response;

    builder.when_transition().assert_zero_ext(lhs - rhs);
}

// BLOCK HASH TABLE (p2)
// ================================================================================================

/// Enforces the block hash table (p2) bus constraint.
///
/// The block hash table tracks blocks awaiting execution. The program hash is added at
/// initialization and removed when the program completes.
///
/// ## Operations
///
/// **Responses (additions)**: JOIN (2x), SPLIT, LOOP (conditional), REPEAT, DYN, DYNCALL, CALL,
/// SYSCALL **Requests (removals)**: END
///
/// ## Message Format
///
/// `[1, parent_block_id, hash[0], hash[1], hash[2], hash[3], is_first_child, is_loop_body]`
///
/// ## Constraint Structure
///
/// ```text
/// p2' * request = p2 * response
///
/// response = f_join * (msg_left * msg_right)
///          + f_split * msg_split
///          + f_loop * (s0 * msg_loop + (1 - s0))
///          + f_repeat * msg_repeat
///          + f_dyn * msg_dyn + f_dyncall * msg_dyncall + f_call * msg_call + f_syscall * msg_syscall
///          + (1 - f_join - f_split - f_loop - f_repeat - f_dyn - f_dyncall - f_call - f_syscall)
///
/// request = f_end * msg_end + (1 - f_end)
/// ```
pub fn enforce_block_hash_table_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Auxiliary trace must be present
    debug_assert!(
        builder.permutation().height() > 0,
        "Auxiliary trace must be present for block hash table constraint"
    );

    // Extract auxiliary trace values
    let (p2_local, p2_next) = {
        let aux = builder.permutation();
        let aux_local = aux.row_slice(0).expect("Matrix should have at least 1 row");
        let aux_next = aux.row_slice(1).expect("Matrix should have at least 2 rows");
        (
            aux_local[crate::constraints::bus::indices::P2_BLOCK_HASH],
            aux_next[crate::constraints::bus::indices::P2_BLOCK_HASH],
        )
    };

    // Get challenges for message encoding (8 alphas for p2)
    let challenges = builder.permutation_randomness();
    let alphas: [AB::ExprEF; 8] = core::array::from_fn(|i| challenges[i].into());

    let one = AB::Expr::ONE;
    let zero = AB::Expr::ZERO;
    let one_ef = AB::ExprEF::ONE;

    // Helper to convert trace value to base field expression
    let to_expr = |v: AB::Var| -> AB::Expr { v.into() };

    // =========================================================================
    // BOUNDARY CONSTRAINTS
    // =========================================================================

    // p2[last] must equal 1 (all blocks processed)
    builder.when_last_row().assert_eq_ext(p2_local.into(), one_ef.clone());

    // NOTE: p2[0] should equal the program hash message
    // The initial value is: msg(0, program_hash[0..4], 0, 0)
    // where program_hash is from PublicInputs::program_info().program_hash()
    // This boundary constraint requires MidenAirBuilder to provide public_inputs() access.
    // TODO(Al): this will change when we uniformize all buses to start with 0/1 and use aux_finals

    // =========================================================================
    // TRACE VALUE EXTRACTION
    // =========================================================================

    // Parent block ID (next row's address for all insertions)
    let parent_id = to_expr(next.decoder[decoder_cols::ADDR].clone());

    // Hasher state for child hashes
    // First half: h[0..4]
    let h0 = to_expr(local.decoder[decoder_cols::HASHER_STATE_OFFSET].clone());
    let h1 = to_expr(local.decoder[decoder_cols::HASHER_STATE_OFFSET + 1].clone());
    let h2 = to_expr(local.decoder[decoder_cols::HASHER_STATE_OFFSET + 2].clone());
    let h3 = to_expr(local.decoder[decoder_cols::HASHER_STATE_OFFSET + 3].clone());
    // Second half: h[4..8]
    let h4 = to_expr(local.decoder[decoder_cols::HASHER_STATE_OFFSET + 4].clone());
    let h5 = to_expr(local.decoder[decoder_cols::HASHER_STATE_OFFSET + 5].clone());
    let h6 = to_expr(local.decoder[decoder_cols::HASHER_STATE_OFFSET + 6].clone());
    let h7 = to_expr(local.decoder[decoder_cols::HASHER_STATE_OFFSET + 7].clone());

    // Stack top (for SPLIT and LOOP conditions)
    let s0: AB::Expr = to_expr(local.stack[0].clone());

    // For END: block hash comes from current row's hasher state first half
    let end_parent_id = to_expr(next.decoder[decoder_cols::ADDR].clone());
    let end_hash_0 = h0.clone();
    let end_hash_1 = h1.clone();
    let end_hash_2 = h2.clone();
    let end_hash_3 = h3.clone();

    // is_loop_body flag for END (stored at hasher_state[4] = IS_LOOP_BODY_FLAG)
    let is_loop_body_flag = to_expr(local.decoder[decoder_cols::HASHER_STATE_OFFSET + 4].clone());

    // is_first_child detection for END:
    // A block is first_child if the NEXT row's opcode is NOT (END, REPEAT, or HALT).
    // From processor: is_first_child = !(next_op in {END, REPEAT, HALT})
    // We compute op flags from the next row and check these three opcodes.
    //
    // Note: END (112), REPEAT (116), HALT (124) are all degree-4 operations,
    // so is_first_child has degree 4, keeping total constraint degree under max.
    let accessor_next =
        crate::constraints::stack::op_flags::ExprDecoderAccess::<AB::Var, AB::Expr>::new(next);
    let op_flags_next = crate::constraints::stack::op_flags::OpFlags::new(accessor_next);

    let f_end_next = op_flags_next.end();
    let f_repeat_next = op_flags_next.repeat();
    let f_halt_next = op_flags_next.halt();

    // is_first_child = 1 when next op is NOT end/repeat/halt
    let is_not_first_child = f_end_next + f_repeat_next + f_halt_next;
    let is_first_child = one.clone() - is_not_first_child;

    // =========================================================================
    // MESSAGE BUILDERS
    // =========================================================================

    // Message format: alpha[0] + alpha[1]*parent_id + alpha[2..6]*hash[0..4] +
    // alpha[6]*is_first_child + alpha[7]*is_loop_body
    let msg = |parent: &AB::Expr,
               hash: [&AB::Expr; 4],
               first_child: &AB::Expr,
               loop_body: &AB::Expr|
     -> AB::ExprEF {
        alphas[0].clone()
            + alphas[1].clone() * parent.clone()
            + alphas[2].clone() * hash[0].clone()
            + alphas[3].clone() * hash[1].clone()
            + alphas[4].clone() * hash[2].clone()
            + alphas[5].clone() * hash[3].clone()
            + alphas[6].clone() * first_child.clone()
            + alphas[7].clone() * loop_body.clone()
    };

    // =========================================================================
    // OPERATION FLAGS
    // =========================================================================

    let f_join = op_flags.join();
    let f_split = op_flags.split();
    let f_loop = op_flags.loop_op();
    let f_repeat = op_flags.repeat();
    let f_dyn = op_flags.dyn_op();
    let f_dyncall = op_flags.dyncall();
    let f_call = op_flags.call();
    let f_syscall = op_flags.syscall();
    let f_end = op_flags.end();

    // =========================================================================
    // RESPONSE CONTRIBUTIONS (insertions)
    // =========================================================================

    // JOIN: Insert both children
    // Left child (is_first_child=1): hash from first half
    let msg_join_left = msg(&parent_id, [&h0, &h1, &h2, &h3], &one, &zero);
    // Right child (is_first_child=0): hash from second half
    let msg_join_right = msg(&parent_id, [&h4, &h5, &h6, &h7], &zero, &zero);
    let v_join = (msg_join_left * msg_join_right) * f_join.clone();

    // SPLIT: Insert selected child based on s0
    // If s0=1: left child (h0-h3), else right child (h4-h7)
    let split_h0 = s0.clone() * h0.clone() + (one.clone() - s0.clone()) * h4.clone();
    let split_h1 = s0.clone() * h1.clone() + (one.clone() - s0.clone()) * h5.clone();
    let split_h2 = s0.clone() * h2.clone() + (one.clone() - s0.clone()) * h6.clone();
    let split_h3 = s0.clone() * h3.clone() + (one.clone() - s0.clone()) * h7.clone();
    let msg_split = msg(&parent_id, [&split_h0, &split_h1, &split_h2, &split_h3], &zero, &zero);
    let v_split = msg_split * f_split.clone();

    // LOOP: Conditionally insert body if s0=1
    let msg_loop = msg(&parent_id, [&h0, &h1, &h2, &h3], &zero, &one);
    // When s0=1: insert msg_loop; when s0=0: multiply by 1 (no insertion)
    let v_loop = (msg_loop * s0.clone() + (one_ef.clone() - s0.clone())) * f_loop.clone();

    // REPEAT: Insert loop body
    let msg_repeat = msg(&parent_id, [&h0, &h1, &h2, &h3], &zero, &one);
    let v_repeat = msg_repeat * f_repeat.clone();

    // DYN/DYNCALL/CALL/SYSCALL: Insert child hash from first half
    let msg_call_like = msg(&parent_id, [&h0, &h1, &h2, &h3], &zero, &zero);
    let v_dyn = msg_call_like.clone() * f_dyn.clone();
    let v_dyncall = msg_call_like.clone() * f_dyncall.clone();
    let v_call = msg_call_like.clone() * f_call.clone();
    let v_syscall = msg_call_like * f_syscall.clone();

    // Sum of insertion flags
    let insert_flag_sum = f_join.clone()
        + f_split.clone()
        + f_loop.clone()
        + f_repeat.clone()
        + f_dyn.clone()
        + f_dyncall.clone()
        + f_call.clone()
        + f_syscall.clone();

    // Response side
    let response = v_join
        + v_split
        + v_loop
        + v_repeat
        + v_dyn
        + v_dyncall
        + v_call
        + v_syscall
        + (one_ef.clone() - insert_flag_sum);

    // =========================================================================
    // REQUEST CONTRIBUTIONS (removals)
    // =========================================================================

    // END: Remove the block
    // is_first_child is computed above from next row's opcode flags
    let msg_end = msg(
        &end_parent_id,
        [&end_hash_0, &end_hash_1, &end_hash_2, &end_hash_3],
        &is_first_child,
        &is_loop_body_flag,
    );
    let u_end = msg_end * f_end.clone();

    // Request side
    let request = u_end + (one_ef.clone() - f_end);

    // =========================================================================
    // RUNNING PRODUCT CONSTRAINT
    // =========================================================================

    // p2' * request = p2 * response
    let lhs: AB::ExprEF = p2_next.into() * request;
    let rhs: AB::ExprEF = p2_local.into() * response;

    builder.when_transition().assert_zero_ext(lhs - rhs);
}

// OP GROUP TABLE (p3)
// ================================================================================================

/// Enforces the op group table (p3) bus constraint.
///
/// The op group table tracks operation groups within span blocks. Groups are added
/// when entering a span and removed as operations are executed.
///
/// ## Operations
///
/// **Responses (additions)**: SPAN, RESPAN (based on batch flags)
/// - 8-group batch: Insert h1-h7 (7 groups)
/// - 4-group batch: Insert h1-h3 (3 groups)
/// - 2-group batch: Insert h1 (1 group)
/// - 1-group batch: Insert nothing
///
/// **Requests (removals)**: When delta_group_count * is_in_span = 1
///
/// ## Message Format
///
/// `[1, block_id, group_count, op_value]`
///
/// ## Constraint Structure (from docs/src/design/decoder/constraints.md)
///
/// ```text
/// p3' * (f_dg * u + 1 - f_dg) = p3 * (f_g1 + f_g2 * v_1 + f_g4 * ∏v_1..3 + f_g8 * ∏v_1..7 + 1 - (f_span + f_respan))
/// ```
///
/// Where:
/// - f_dg = sp * (gc - gc') - flag for group removal
/// - u = removal message
/// - f_g1, f_g2, f_g4, f_g8 = batch size flags
/// - v_i = insertion message for group i
///
/// ## Degree Analysis
///
/// - f_g8 * prod_7: degree 1 + 7 = 8
/// - f_g4 * prod_3: degree 3 + 3 = 6
/// - f_span: degree 6
/// - f_dg * u: degree 2 + 7 = 9 (u includes f_push which is degree ~5)
/// - Total constraint: degree 9
pub fn enforce_op_group_table_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Auxiliary trace must be present
    debug_assert!(
        builder.permutation().height() > 0,
        "Auxiliary trace must be present for op group table constraint"
    );

    // Extract auxiliary trace values
    let (p3_local, p3_next) = {
        let aux = builder.permutation();
        let aux_local = aux.row_slice(0).expect("Matrix should have at least 1 row");
        let aux_next = aux.row_slice(1).expect("Matrix should have at least 2 rows");
        (
            aux_local[crate::constraints::bus::indices::P3_OP_GROUP],
            aux_next[crate::constraints::bus::indices::P3_OP_GROUP],
        )
    };

    // Get challenges for message encoding (4 alphas for p3)
    let challenges = builder.permutation_randomness();
    let alphas: [AB::ExprEF; 4] = core::array::from_fn(|i| challenges[i].into());

    let one = AB::Expr::ONE;
    let one_ef = AB::ExprEF::ONE;

    // Helper to convert trace value to base field expression
    let to_expr = |v: AB::Var| -> AB::Expr { v.into() };

    // =========================================================================
    // BOUNDARY CONSTRAINTS
    // =========================================================================

    // p3 must start and end at 1 (balanced multiset)
    builder.when_first_row().assert_eq_ext(p3_local.into(), one_ef.clone());
    builder.when_last_row().assert_eq_ext(p3_local.into(), one_ef.clone());

    // =========================================================================
    // TRACE VALUE EXTRACTION
    // =========================================================================

    // Block ID (next row's address for insertions, current for removals)
    let block_id_insert = to_expr(next.decoder[decoder_cols::ADDR].clone());
    let block_id_remove = to_expr(local.decoder[decoder_cols::ADDR].clone());

    // Group count
    let gc = to_expr(local.decoder[op_group_cols::GROUP_COUNT].clone());
    let gc_next = to_expr(next.decoder[op_group_cols::GROUP_COUNT].clone());

    // Hasher state for group values (h1-h7, h0 is decoded immediately)
    let h1 = to_expr(local.decoder[decoder_cols::HASHER_STATE_OFFSET + 1].clone());
    let h2 = to_expr(local.decoder[decoder_cols::HASHER_STATE_OFFSET + 2].clone());
    let h3 = to_expr(local.decoder[decoder_cols::HASHER_STATE_OFFSET + 3].clone());
    let h4 = to_expr(local.decoder[decoder_cols::HASHER_STATE_OFFSET + 4].clone());
    let h5 = to_expr(local.decoder[decoder_cols::HASHER_STATE_OFFSET + 5].clone());
    let h6 = to_expr(local.decoder[decoder_cols::HASHER_STATE_OFFSET + 6].clone());
    let h7 = to_expr(local.decoder[decoder_cols::HASHER_STATE_OFFSET + 7].clone());

    // Batch flag columns (c0, c1, c2)
    let c0 = to_expr(local.decoder[op_group_cols::BATCH_FLAG_0].clone());
    let c1 = to_expr(local.decoder[op_group_cols::BATCH_FLAG_1].clone());
    let c2 = to_expr(local.decoder[op_group_cols::BATCH_FLAG_2].clone());

    // For removal: h0' and s0' from next row
    let h0_next = to_expr(next.decoder[decoder_cols::HASHER_STATE_OFFSET].clone());
    let s0_next = to_expr(next.stack[0].clone());

    // is_in_span flag (sp)
    let sp = to_expr(local.decoder[op_group_cols::IS_IN_SPAN].clone());

    // =========================================================================
    // MESSAGE BUILDER
    // =========================================================================

    // Message format: alpha[0] + alpha[1]*block_id + alpha[2]*group_count + alpha[3]*op_value
    let msg = |bid: &AB::Expr, gc: &AB::Expr, val: &AB::Expr| -> AB::ExprEF {
        alphas[0].clone()
            + alphas[1].clone() * bid.clone()
            + alphas[2].clone() * gc.clone()
            + alphas[3].clone() * val.clone()
    };

    // =========================================================================
    // OPERATION FLAGS
    // =========================================================================

    let f_span = op_flags.span();
    let f_respan = op_flags.respan();
    let f_push = op_flags.push();

    // Combined SPAN/RESPAN flag for the default case
    let f_span_respan = f_span + f_respan;

    // =========================================================================
    // BATCH FLAGS
    // =========================================================================

    // Compute batch flags from c0, c1, c2 based on trace constants:
    // OP_BATCH_8_GROUPS = [1, 0, 0] -> f_g8 = c0
    // OP_BATCH_4_GROUPS = [0, 1, 0] -> f_g4 = (1-c0) * c1 * (1-c2)
    // OP_BATCH_2_GROUPS = [0, 0, 1] -> f_g2 = (1-c0) * (1-c1) * c2
    // OP_BATCH_1_GROUPS = [0, 1, 1] -> f_g1 = (1-c0) * c1 * c2
    let f_g8 = c0.clone();
    let f_g4 = (one.clone() - c0.clone()) * c1.clone() * (one.clone() - c2.clone());
    let f_g2 = (one.clone() - c0.clone()) * (one.clone() - c1.clone()) * c2.clone();
    let f_g1 = (one.clone() - c0) * c1 * c2;

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    // Build base field constants.
    let two = AB::Expr::from_u16(2);
    let three = AB::Expr::from_u16(3);
    let four = AB::Expr::from_u16(4);
    let five = AB::Expr::from_u16(5);
    let six = AB::Expr::from_u16(6);
    let seven = AB::Expr::from_u16(7);
    let eight = AB::Expr::from_u16(8);
    let sixteen = AB::Expr::from_u16(16);
    let thirtytwo = AB::Expr::from_u16(32);
    let sixtyfour = AB::Expr::from_u16(64);
    let onetwentyeight = AB::Expr::from_u16(128);

    // =========================================================================
    // RESPONSE (insertions during SPAN/RESPAN)
    // =========================================================================

    // Build messages for each group: v_i = msg(block_id', gc - i, h_i)
    let v_1 = msg(&block_id_insert, &(gc.clone() - one.clone()), &h1);
    let v_2 = msg(&block_id_insert, &(gc.clone() - two.clone()), &h2);
    let v_3 = msg(&block_id_insert, &(gc.clone() - three.clone()), &h3);
    let v_4 = msg(&block_id_insert, &(gc.clone() - four.clone()), &h4);
    let v_5 = msg(&block_id_insert, &(gc.clone() - five.clone()), &h5);
    let v_6 = msg(&block_id_insert, &(gc.clone() - six.clone()), &h6);
    let v_7 = msg(&block_id_insert, &(gc.clone() - seven.clone()), &h7);

    // Compute products for each batch size
    let prod_3 = v_1.clone() * v_2.clone() * v_3.clone();
    let prod_7 = v_1.clone() * v_2 * v_3 * v_4 * v_5 * v_6 * v_7;

    // Response formula (from docs/src/design/decoder/constraints.md):
    // response = f_g1 + f_g2 * v_1 + f_g4 * ∏(v_1..v_3) + f_g8 * ∏(v_1..v_7) + (1 - (f_span +
    // f_respan))
    //
    // This works because:
    // - 1-group batch: f_g1=1, others=0, f_span=1 → response = 1 + 0 + 0 + 0 + 0 = 1 (no insertion)
    // - 2-group batch: f_g2=1 → response = v_1
    // - 4-group batch: f_g4=1 → response = prod_3
    // - 8-group batch: f_g8=1 → response = prod_7
    // - non-SPAN/RESPAN: all f_gX=0, f_span_respan=0 → response = 1
    let response = (v_1.clone() * f_g2.clone())
        + (prod_3 * f_g4.clone())
        + (prod_7 * f_g8.clone())
        + (one_ef.clone() - f_span_respan)
        + f_g1;

    // =========================================================================
    // REQUEST (removals when group count decrements inside span)
    // =========================================================================

    // f_dg = sp * (gc - gc') - flag for decrementing group count
    // This is non-zero when inside a span (sp=1) and group count decreased
    let delta_gc = gc.clone() - gc_next;
    let f_dg = sp * delta_gc;

    // Compute op_code' from next row's opcode bits (b0' + 2*b1' + ... + 64*b6')
    // Opcode bits are at columns 1-7 in the decoder trace
    let op_code_next = {
        let b0 = to_expr(next.decoder[1].clone());
        let b1 = to_expr(next.decoder[2].clone());
        let b2 = to_expr(next.decoder[3].clone());
        let b3 = to_expr(next.decoder[4].clone());
        let b4 = to_expr(next.decoder[5].clone());
        let b5 = to_expr(next.decoder[6].clone());
        let b6 = to_expr(next.decoder[7].clone());

        b0 + two.clone() * b1
            + four.clone() * b2
            + eight.clone() * b3
            + sixteen.clone() * b4
            + thirtytwo.clone() * b5
            + sixtyfour.clone() * b6
    };

    // Removal value formula:
    // u = (h0' * 128 + op_code') * (1 - f_push) + s0' * f_push
    //
    // When PUSH: the immediate value is on the stack (s0')
    // Otherwise: the group value is h0' * 128 + op_code'
    let group_value_non_push = h0_next * onetwentyeight + op_code_next;
    let group_value = f_push.clone() * s0_next + (one.clone() - f_push) * group_value_non_push;

    // Removal message: u = msg(block_id, gc, group_value)
    let u = msg(&block_id_remove, &gc, &group_value);

    // Request formula: f_dg * u + (1 - f_dg)
    let request = u * f_dg.clone() + (one_ef.clone() - f_dg);

    // =========================================================================
    // RUNNING PRODUCT CONSTRAINT
    // =========================================================================

    // p3' * request = p3 * response
    let lhs: AB::ExprEF = p3_next.into() * request;
    let rhs: AB::ExprEF = p3_local.into() * response;

    builder.when_transition().assert_zero_ext(lhs - rhs);
}
