//! System operations constraints.
//!
//! This module contains constraints for system operations:
//! - ASSERT: verifies that the top stack element equals ONE
//! - CALLER: overwrites top 4 stack elements with caller's function hash
//!
//! Note: FMP (frame pointer) operations have been refactored to use regular
//! memory load/store operations, so no special FMP constraints are needed.
//!
//! TODO: Update reference constraints implementation in air-script.

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use super::op_flags::OpFlags;
use crate::MainTraceRow;

#[cfg(test)]
pub mod tests;

// CONSTANTS
// ================================================================================================

/// Number of system operations constraints.
#[allow(dead_code)]
pub const NUM_CONSTRAINTS: usize = 5;

/// The degrees of the system operations constraints.
#[allow(dead_code)]
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    8, // ASSERT constraint (degree 7 flag + degree 1 equality check)
    8, 8, 8, 8, // CALLER constraints (degree 7 flag + degree 1 equality check for s0'-s3')
];

// ENTRY POINTS
// ================================================================================================

/// Enforces all system operations constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    enforce_assert_constraint(builder, local, op_flags);
    enforce_caller_constraints(builder, local, next, op_flags);
}

// CONSTRAINT HELPERS
// ================================================================================================

/// Enforces the ASSERT operation constraint.
///
/// The ASSERT operation verifies that the top element of the stack equals ONE.
/// If it doesn't, the constraint fails and proof verification will fail.
///
/// ```text
/// s0 = 1
/// ```
fn enforce_assert_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let top: AB::Expr = local.stack[0].clone().into();

    // s0 = 1, so s0 - 1 = 0
    let constraint = top - AB::Expr::ONE;
    builder.when_transition().assert_zero(op_flags.assert_op() * constraint);
}

/// Enforces the CALLER operation constraints.
///
/// The CALLER operation overwrites the top 4 stack elements with the hash
/// of the function that initiated the current SYSCALL. This operation can
/// only be executed inside a SYSCALL code block.
///
/// ```text
/// s0' = fn_hash[0]
/// s1' = fn_hash[1]
/// s2' = fn_hash[2]
/// s3' = fn_hash[3]
/// ```
///
/// The fn_hash is stored in the system columns of the trace.
fn enforce_caller_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let flag = op_flags.caller();

    let s0_next: AB::Expr = next.stack[0].clone().into();
    let fn_hash_0: AB::Expr = local.fn_hash[0].clone().into();
    let s1_next: AB::Expr = next.stack[1].clone().into();
    let fn_hash_1: AB::Expr = local.fn_hash[1].clone().into();
    let s2_next: AB::Expr = next.stack[2].clone().into();
    let fn_hash_2: AB::Expr = local.fn_hash[2].clone().into();
    let s3_next: AB::Expr = next.stack[3].clone().into();
    let fn_hash_3: AB::Expr = local.fn_hash[3].clone().into();

    // Use a combined gate to share `is_transition * caller_flag` across all constraints.
    let gate = builder.is_transition() * flag;
    builder.when(gate).assert_zeros([
        s0_next - fn_hash_0,
        s1_next - fn_hash_1,
        s2_next - fn_hash_2,
        s3_next - fn_hash_3,
    ]);
}
