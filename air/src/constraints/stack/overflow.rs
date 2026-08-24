//! Stack overflow constraints.
//!
//! This module contains constraints for the stack overflow table bookkeeping columns.
//! The stack overflow table tracks items that have "overflowed" below the accessible portion
//! of the operand stack (the top 16 positions).
//!
//! ## Columns
//!
//! - `b0`: Stack depth (always >= 16)
//! - `b1`: Address of the top row in the overflow table (clk value when item was pushed)
//! - `h0`: Overflow flag helper = 1/(b0 - 16) when b0 > 16, else 0
//!
//! ## Constraints
//!
//! 1. **Stack depth transition** (degree 7):
//!    - No shift: depth stays the same
//!    - Right shift: depth increases by 1
//!    - Left shift with non-empty overflow: depth decreases by 1 (we pop from the overflow table)
//!    - CALL/SYSCALL/DYNCALL: depth resets to 16
//!
//! 2. **Overflow flag** (degree 3):
//!    - When overflow table is empty (b0 = 16), h0 must be 0
//!    - When overflow table has values (b0 > 16), h0 = 1/(b0 - 16)
//!
//! 3. **Overflow index** (degree 7, 8):
//!    - On right shift: b1' = clk (record when item was pushed)
//!    - On CALL/SYSCALL/DYNCALL: b1' = 0 (start with an empty overflow table)
//!    - On operations which do not modify or restore the overflow table: b1' = b1
//!    - On left shift with depth = 16: stack[15]' = 0 (no item to restore)

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::AirBuilder;

use crate::{
    CoreCols, MidenAirBuilder,
    constraints::{constants::*, op_flags::OpFlags, utils::BoolNot},
};

// ENTRY POINTS
// ================================================================================================

/// Enforces all stack overflow constraints.
///
/// This function enforces:
/// 1. Stack depth transitions correctly based on the operation type
/// 2. Overflow flag h0 is set correctly
/// 3. Overflow bookkeeping index b1 is updated correctly on shifts
/// 4. Last stack item is zeroed on left shift when depth = 16
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &CoreCols<AB::Var>,
    next: &CoreCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // Boundary constraints: stack depth and overflow pointer must start/end clean.
    builder.when_first_row().assert_eq(local.stack.b0, F_16);
    builder.when_last_row().assert_eq(local.stack.b0, F_16);
    builder.when_first_row().assert_zero(local.stack.b1);
    builder.when_last_row().assert_zero(local.stack.b1);

    // Transition constraints: depth bookkeeping, overflow flag, and pointer updates.
    enforce_stack_depth_constraints(builder, local, next, op_flags);

    // Overflow flag: (1 - overflow) * (depth - 16) = 0
    // When depth > 16, overflow must be 1; when depth = 16, satisfied for any h0.
    {
        let depth = local.stack.b0;
        builder.when(op_flags.overflow().not()).assert_eq(depth, F_16);
    }

    enforce_overflow_index_constraints(builder, local, next, op_flags);
}

// CONSTRAINT HELPERS
// ================================================================================================

/// Enforces stack depth transition constraints.
///
/// The stack depth (b0) changes based on the operation:
/// - No shift operations: depth unchanged
/// - Right shift operations: depth += 1
/// - Left shift operations with non-empty overflow: depth -= 1 (we pop from the overflow table)
/// - CALL/SYSCALL/DYNCALL: depth = 16 (reset)
///
/// The END operation exiting a CALL/SYSCALL block is handled separately via multiset constraints.
fn enforce_stack_depth_constraints<AB>(
    builder: &mut AB,
    local: &CoreCols<AB::Var>,
    next: &CoreCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let depth = local.stack.b0;
    let depth_next = next.stack.b0;

    // Flag for CALL, DYNCALL, or SYSCALL operations
    let call_or_dyncall_or_syscall = op_flags.call() + op_flags.dyncall() + op_flags.syscall();

    // Flag for END operation that ends a CALL/DYNCALL or SYSCALL block
    let is_call_or_dyncall_end = local.decoder.hasher_state[6];
    let is_syscall_end = local.decoder.hasher_state[7];
    let call_or_dyncall_or_syscall_end = op_flags.end() * (is_call_or_dyncall_end + is_syscall_end);

    // Invariants relied on here:
    // - Aggregate left_shift/right_shift flags are 0 on CALL/SYSCALL/END rows.
    // - DYNCALL is excluded from the aggregate left_shift flag (its stack effect is handled via
    //   per-position left_shift_at flags plus the call-entry depth reset).
    //
    // We have three regimes:
    //
    // 1) CALL/SYSCALL/DYNCALL entry: force b0' = 16 (handled by call_part below).
    // 2) END-of-call: depth restoration is validated by block stack constraints; we don't enforce
    //    the shift law here.
    // 3) All other rows ("normal ops"): depth follows the shift law b0' - b0 + f_shl * f_ov - f_shr
    //    = 0.
    //
    // Why we mask only the (b0' - b0) term:
    //
    // - On CALL/SYSCALL/END rows, the aggregate shift flags are 0 by construction. (CALL/SYSCALL
    //   are explicitly no-shift ops; END sets left_shift only for loop exits; DYNCALL is
    //   intentionally excluded from the aggregate left_shift flag.)
    // - Therefore, the shift terms already vanish on those rows, and masking them would only
    //   increase polynomial degree.
    // - We still need to suppress the raw (b0' - b0) term on END-of-call rows, hence the mask.
    let normal_mask =
        AB::Expr::ONE - call_or_dyncall_or_syscall.clone() - call_or_dyncall_or_syscall_end;
    let depth_delta_part = (depth_next.into() - depth.into()) * normal_mask;

    // Left shift with non-empty overflow: when f_shl=1 and f_ov=1, depth must decrement by 1.
    // This contributes +1 to the LHS, enforcing b0' = b0 - 1.
    let left_shift_part = op_flags.left_shift() * op_flags.overflow();

    // Right shift: when f_shr=1, depth must increment by 1.
    // This contributes -1 to the LHS, enforcing b0' = b0 + 1.
    let right_shift_part = op_flags.right_shift();

    // CALL/SYSCALL/DYNCALL: depth resets to 16 when entering a new context.
    let call_part = call_or_dyncall_or_syscall * (depth_next.into() - F_16);

    // Combined constraint: normal depth update + shift effects + call reset = 0.
    builder
        .when_transition()
        .assert_zero(depth_delta_part + left_shift_part - right_shift_part + call_part);
}

/// Enforces overflow bookkeeping index constraints.
///
/// Overflow pointer constraints:
/// 1. On right shift: b1' = clk (record the clock cycle when item was pushed to overflow)
/// 2. On CALL/SYSCALL/DYNCALL: b1' = 0 (start the new context with no overflow)
/// 3. On operations which do not modify or restore the overflow table: b1' = b1
/// 4. On left shift with depth = 16: stack[15]' = 0 (no item to restore from overflow)
fn enforce_overflow_index_constraints<AB>(
    builder: &mut AB,
    local: &CoreCols<AB::Var>,
    next: &CoreCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let overflow_addr = local.stack.b1;
    let overflow_addr_next = next.stack.b1;
    let clk = local.system.clk;
    let last_stack_item_next = next.stack.get(15);

    // On right shift, the overflow address should be set to current clk
    builder.when(op_flags.right_shift()).assert_eq(overflow_addr_next, clk);

    // A new call context starts with an empty overflow table.
    let context_start = op_flags.call() + op_flags.dyncall() + op_flags.syscall();
    builder
        .when_transition()
        .when(context_start.clone())
        .assert_zero(overflow_addr_next);

    // END restores the caller's overflow address through the block stack lookup. The call and
    // syscall end flags are mutually exclusive: the block-stack relation has one Full removal to
    // match the corresponding CALL or SYSCALL addition (see block_stack_and_range_logcap). Thus,
    // their sum is boolean on valid traces. A right shift creates a new overflow record, while a
    // left shift with non-empty overflow restores the previous address through the overflow table
    // lookup. All other transitions preserve b1.
    let end_flags = local.decoder.end_block_flags();
    let context_end = op_flags.end() * (end_flags.is_call.into() + end_flags.is_syscall.into());
    let updates_overflow_addr = context_start
        + context_end
        + op_flags.right_shift()
        + op_flags.left_shift() * op_flags.overflow();
    builder
        .when_transition()
        .when(AB::Expr::ONE - updates_overflow_addr)
        .assert_eq(overflow_addr_next, overflow_addr);

    // On left shift when depth = 16 (no overflow), last stack item should be zero
    builder
        .when(op_flags.overflow().not())
        .when(op_flags.left_shift())
        .assert_zero(last_stack_item_next);
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::{
        Felt, ONE, ZERO,
        field::{PrimeCharacteristicRing, QuadFelt},
        operations::opcodes,
    };

    use super::enforce_main;
    use crate::constraints::{
        columns::CoreCols,
        op_flags::{OpFlags, generate_test_row},
        stack::test_utils::ConstraintEvalBuilder,
    };

    fn eval_stack_overflow(local: &CoreCols<Felt>, next: &CoreCols<Felt>) -> Vec<QuadFelt> {
        let mut builder = ConstraintEvalBuilder::new();
        let op_flags = OpFlags::new(&local.decoder, &local.stack, &next.decoder);
        enforce_main(&mut builder, local, next, &op_flags);
        builder.evaluations
    }

    #[test]
    fn frie2f4_decrements_non_empty_overflow_depth() {
        let mut local = generate_test_row(opcodes::FRIE2F4.into());
        local.stack.b0 = Felt::new_unchecked(17);
        local.stack.h0 = ONE;

        let mut next = generate_test_row(0);
        next.stack.b0 = Felt::new_unchecked(16);

        let evaluations = eval_stack_overflow(&local, &next);
        assert!(evaluations.iter().all(|value| *value == QuadFelt::ZERO));

        next.stack.b0 = Felt::new_unchecked(17);
        let evaluations = eval_stack_overflow(&local, &next);
        assert!(
            evaluations.iter().any(|value| *value != QuadFelt::ZERO),
            "FRIE2F4 must decrement stack depth when overflow is non-empty"
        );
    }

    #[test]
    fn frie2f4_zeros_s15_when_overflow_is_empty() {
        let mut local = generate_test_row(opcodes::FRIE2F4.into());
        local.stack.b0 = Felt::new_unchecked(16);
        local.stack.h0 = ZERO;

        let mut next = generate_test_row(0);
        next.stack.b0 = Felt::new_unchecked(16);
        next.stack.top[15] = ZERO;

        let evaluations = eval_stack_overflow(&local, &next);
        assert!(evaluations.iter().all(|value| *value == QuadFelt::ZERO));

        next.stack.top[15] = ONE;
        let evaluations = eval_stack_overflow(&local, &next);
        assert!(
            evaluations.iter().any(|value| *value != QuadFelt::ZERO),
            "FRIE2F4 must zero s15 when no overflow item can be restored"
        );
    }

    #[test]
    fn overflow_address_transitions() {
        for (opcode, next_depth, next_overflow_addr, transition) in [
            (opcodes::NOOP, 17, 11, "preserve"),
            (opcodes::CALL, 16, 0, "reset"),
            (opcodes::DYNCALL, 16, 0, "reset"),
            (opcodes::SYSCALL, 16, 0, "reset"),
            (opcodes::END, 17, 11, "preserve"),
        ] {
            let mut local = generate_test_row(opcode.into());
            local.stack.b0 = Felt::new_unchecked(17);
            local.stack.b1 = Felt::new_unchecked(11);
            local.stack.h0 = ONE;

            let mut next = generate_test_row(0);
            next.stack.b0 = Felt::new_unchecked(next_depth);
            next.stack.b1 = Felt::new_unchecked(next_overflow_addr);

            let evaluations = eval_stack_overflow(&local, &next);
            assert!(evaluations.iter().all(|value| *value == QuadFelt::ZERO));

            next.stack.b1 = ONE;
            let evaluations = eval_stack_overflow(&local, &next);
            assert!(
                evaluations.iter().any(|value| *value != QuadFelt::ZERO),
                "opcode {opcode} must {transition} the overflow address"
            );
        }
    }

    #[test]
    fn call_end_allows_overflow_address_restoration() {
        let mut local = generate_test_row(opcodes::END.into());
        local.decoder.hasher_state[6] = ONE;
        local.stack.b0 = Felt::new_unchecked(17);
        local.stack.b1 = Felt::new_unchecked(11);
        local.stack.h0 = ONE;

        let mut next = generate_test_row(0);
        next.stack.b0 = Felt::new_unchecked(23);
        next.stack.b1 = Felt::new_unchecked(7);
        next.stack.h0 = ONE;

        let evaluations = eval_stack_overflow(&local, &next);
        assert!(evaluations.iter().all(|value| *value == QuadFelt::ZERO));
    }
}
