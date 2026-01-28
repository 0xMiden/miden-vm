//! Stack manipulation operations constraints.
//!
//! This module contains constraints for stack manipulation operations that need
//! explicit constraints for positions not covered by general shift constraints.
//!
//! ## Constraints
//!
//! - PAD: Push 0 onto stack (1 constraint)
//! - DUP: Duplicate top element (1 constraint)
//! - DUP1-DUP7, DUP9, DUP11, DUP13, DUP15: Duplicate element at position n (11 constraints)
//! - CLK: Push current clock cycle (1 constraint)
//! - SWAP: Exchange top two elements (2 constraints)
//! - MOVUP2-MOVUP8: Move element to top (7 constraints for position 0)
//! - MOVDN2-MOVDN8: Move top element down (7 constraints for destination position)
//! - SWAPW: Swap words at positions 0-3 and 4-7 (8 constraints)
//! - SWAPW2: Swap words at positions 0-3 and 8-11 (8 constraints)
//! - SWAPW3: Swap words at positions 0-3 and 12-15 (8 constraints)
//! - SWAPDW: Swap double-words at positions 0-7 and 8-15 (16 constraints)
//! - CSWAP: Conditional swap of 2 elements (2 constraints)
//! - CSWAPW: Conditional swap of 2 words (8 constraints)
//!
//! Total: 80 constraints

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use super::op_flags::OpFlags;
use crate::MainTraceRow;

#[cfg(test)]
pub mod tests;

// CONSTANTS
// ================================================================================================

/// Number of stack manipulation constraints.
#[allow(dead_code)]
pub const NUM_CONSTRAINTS: usize = 80;

/// The degrees of the stack manipulation constraints.
/// Each constraint is degree 8 (flag degree 7 + value degree 1) or degree 9 (flag + degree 2 body).
#[allow(dead_code)]
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    8, // PAD
    8, // DUP (dup0)
    8, 8, 8, 8, 8, 8, 8, // DUP1-DUP7
    8, 8, 8, 8, // DUP9, DUP11, DUP13, DUP15
    8, // CLK
    8, 8, // SWAP (2 constraints)
    8, 8, 8, 8, 8, 8, 8, // MOVUP2-MOVUP8 (7 constraints)
    8, 8, 8, 8, 8, 8, 8, // MOVDN2-MOVDN8 (7 constraints)
    8, 8, 8, 8, 8, 8, 8, 8, // SWAPW (8 constraints)
    8, 8, 8, 8, 8, 8, 8, 8, // SWAPW2 (8 constraints)
    8, 8, 8, 8, 8, 8, 8, 8, // SWAPW3 (8 constraints)
    8, 8, 8, 8, 8, 8, 8, 8, // SWAPDW first 8
    8, 8, 8, 8, 8, 8, 8, 8, // SWAPDW second 8
    9, 9, // CSWAP (2 constraints, degree 9 = 7 + 2)
    9, 9, 9, 9, 9, 9, 9, 9, // CSWAPW (8 constraints, degree 9 = 7 + 2)
];

// ENTRY POINTS
// ================================================================================================

/// Enforces all stack manipulation constraints.
///
/// These constraints ensure that the NEW values are correct for
/// stack manipulation operations:
/// - PAD: s0' = 0
/// - DUPn: s0' = s[n]
/// - CLK: s0' = clk
/// - SWAP: s0' = s1, s1' = s0
/// - MOVUPn: s0' = s[n]
/// - MOVDNn: s[n]' = s0
/// - SWAPW/SWAPW2/SWAPW3: swap two words
/// - SWAPDW: swap two double-words
/// - CSWAP: conditional swap of s1 and s2
/// - CSWAPW: conditional swap of words at s1-s4 and s5-s8
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    enforce_pad_constraint(builder, next, op_flags);
    enforce_dup_constraints(builder, local, next, op_flags);
    enforce_clk_constraint(builder, local, next, op_flags);
    enforce_swap_constraints(builder, local, next, op_flags);
    enforce_movup_constraints(builder, local, next, op_flags);
    enforce_movdn_constraints(builder, local, next, op_flags);
    enforce_swapw_constraints(builder, local, next, op_flags);
    enforce_swapw2_constraints(builder, local, next, op_flags);
    enforce_swapw3_constraints(builder, local, next, op_flags);
    enforce_swapdw_constraints(builder, local, next, op_flags);
    enforce_cswap_constraints(builder, local, next, op_flags);
    enforce_cswapw_constraints(builder, local, next, op_flags);
}

// CONSTRAINT HELPERS
// ================================================================================================

/// Enforces the PAD operation constraint.
///
/// PAD pushes 0 onto the stack:
/// `s0' = 0`
fn enforce_pad_constraint<AB>(
    builder: &mut AB,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let next_top: AB::Expr = next.stack[0].clone().into();

    // s0' = 0
    builder.when_transition().assert_zero(op_flags.pad() * next_top);
}

/// Enforces the DUP operation constraints.
///
/// DUPn duplicates the element at position n to the top of the stack.
/// - DUP (DUP0): s0' = s0
/// - DUP1: s0' = s1
/// - DUP2: s0' = s2
/// - ... and so on for DUP3-DUP7, DUP9, DUP11, DUP13, DUP15
fn enforce_dup_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let next_top: AB::Expr = next.stack[0].clone().into();

    // DUP (DUP0): s0' = s0
    let s0: AB::Expr = local.stack[0].clone().into();
    let constraint = next_top.clone() - s0;
    builder.when_transition().assert_zero(op_flags.dup() * constraint);

    // DUP1: s0' = s1
    let s1: AB::Expr = local.stack[1].clone().into();
    let constraint = next_top.clone() - s1;
    builder.when_transition().assert_zero(op_flags.dup1() * constraint);

    // DUP2: s0' = s2
    let s2: AB::Expr = local.stack[2].clone().into();
    let constraint = next_top.clone() - s2;
    builder.when_transition().assert_zero(op_flags.dup2() * constraint);

    // DUP3: s0' = s3
    let s3: AB::Expr = local.stack[3].clone().into();
    let constraint = next_top.clone() - s3;
    builder.when_transition().assert_zero(op_flags.dup3() * constraint);

    // DUP4: s0' = s4
    let s4: AB::Expr = local.stack[4].clone().into();
    let constraint = next_top.clone() - s4;
    builder.when_transition().assert_zero(op_flags.dup4() * constraint);

    // DUP5: s0' = s5
    let s5: AB::Expr = local.stack[5].clone().into();
    let constraint = next_top.clone() - s5;
    builder.when_transition().assert_zero(op_flags.dup5() * constraint);

    // DUP6: s0' = s6
    let s6: AB::Expr = local.stack[6].clone().into();
    let constraint = next_top.clone() - s6;
    builder.when_transition().assert_zero(op_flags.dup6() * constraint);

    // DUP7: s0' = s7
    let s7: AB::Expr = local.stack[7].clone().into();
    let constraint = next_top.clone() - s7;
    builder.when_transition().assert_zero(op_flags.dup7() * constraint);

    // DUP9: s0' = s9
    let s9: AB::Expr = local.stack[9].clone().into();
    let constraint = next_top.clone() - s9;
    builder.when_transition().assert_zero(op_flags.dup9() * constraint);

    // DUP11: s0' = s11
    let s11: AB::Expr = local.stack[11].clone().into();
    let constraint = next_top.clone() - s11;
    builder.when_transition().assert_zero(op_flags.dup11() * constraint);

    // DUP13: s0' = s13
    let s13: AB::Expr = local.stack[13].clone().into();
    let constraint = next_top.clone() - s13;
    builder.when_transition().assert_zero(op_flags.dup13() * constraint);

    // DUP15: s0' = s15
    let s15: AB::Expr = local.stack[15].clone().into();
    let constraint = next_top - s15;
    builder.when_transition().assert_zero(op_flags.dup15() * constraint);
}

/// Enforces the CLK operation constraint.
///
/// CLK pushes the current clock cycle onto the stack:
/// `s0' = clk`
fn enforce_clk_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let clk: AB::Expr = local.clk.clone().into();
    let next_top: AB::Expr = next.stack[0].clone().into();

    // s0' = clk
    let constraint = next_top - clk;
    builder.when_transition().assert_zero(op_flags.clk() * constraint);
}

/// Enforces the SWAP operation constraints.
///
/// SWAP exchanges the top two elements:
/// Stack: [a, b, ...] -> [b, a, ...]
///
/// Constraints:
/// 1. s0' = s1
/// 2. s1' = s0
fn enforce_swap_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let s0: AB::Expr = local.stack[0].clone().into();
    let s1: AB::Expr = local.stack[1].clone().into();
    let s0_next: AB::Expr = next.stack[0].clone().into();
    let s1_next: AB::Expr = next.stack[1].clone().into();

    // Constraint 1: s0' = s1
    let constraint1 = s0_next - s1;

    // Constraint 2: s1' = s0
    let constraint2 = s1_next - s0;

    // Use a combined gate to share `is_transition * swap_flag` across both constraints.
    let gate = builder.is_transition() * op_flags.swap();
    builder.when(gate).assert_zeros([constraint1, constraint2]);
}

/// Enforces the MOVUP operation constraints for position 0.
///
/// MOVUPn moves the element at position n to the top of the stack.
/// The general constraints handle the shift for positions 1 to n, but
/// position 0 needs explicit constraints since it gets a value from position n.
///
/// - MOVUP2: s0' = s2
/// - MOVUP3: s0' = s3
/// - ... and so on for MOVUP4-MOVUP8
fn enforce_movup_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let s0_next: AB::Expr = next.stack[0].clone().into();

    // MOVUP2: s0' = s2
    let s2: AB::Expr = local.stack[2].clone().into();
    let constraint = s0_next.clone() - s2;
    builder.when_transition().assert_zero(op_flags.movup2() * constraint);

    // MOVUP3: s0' = s3
    let s3: AB::Expr = local.stack[3].clone().into();
    let constraint = s0_next.clone() - s3;
    builder.when_transition().assert_zero(op_flags.movup3() * constraint);

    // MOVUP4: s0' = s4
    let s4: AB::Expr = local.stack[4].clone().into();
    let constraint = s0_next.clone() - s4;
    builder.when_transition().assert_zero(op_flags.movup4() * constraint);

    // MOVUP5: s0' = s5
    let s5: AB::Expr = local.stack[5].clone().into();
    let constraint = s0_next.clone() - s5;
    builder.when_transition().assert_zero(op_flags.movup5() * constraint);

    // MOVUP6: s0' = s6
    let s6: AB::Expr = local.stack[6].clone().into();
    let constraint = s0_next.clone() - s6;
    builder.when_transition().assert_zero(op_flags.movup6() * constraint);

    // MOVUP7: s0' = s7
    let s7: AB::Expr = local.stack[7].clone().into();
    let constraint = s0_next.clone() - s7;
    builder.when_transition().assert_zero(op_flags.movup7() * constraint);

    // MOVUP8: s0' = s8
    let s8: AB::Expr = local.stack[8].clone().into();
    let constraint = s0_next - s8;
    builder.when_transition().assert_zero(op_flags.movup8() * constraint);
}

/// Enforces the MOVDN operation constraints for the destination position.
///
/// MOVDNn moves the top element to position n.
/// The general constraints handle the left-shift for positions 0 to n-1, but
/// position n needs explicit constraints since it gets the value from position 0.
///
/// - MOVDN2: s2' = s0
/// - MOVDN3: s3' = s0
/// - ... and so on for MOVDN4-MOVDN8
fn enforce_movdn_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let s0: AB::Expr = local.stack[0].clone().into();

    // MOVDN2: s2' = s0
    let s2_next: AB::Expr = next.stack[2].clone().into();
    let constraint = s2_next - s0.clone();
    builder.when_transition().assert_zero(op_flags.movdn2() * constraint);

    // MOVDN3: s3' = s0
    let s3_next: AB::Expr = next.stack[3].clone().into();
    let constraint = s3_next - s0.clone();
    builder.when_transition().assert_zero(op_flags.movdn3() * constraint);

    // MOVDN4: s4' = s0
    let s4_next: AB::Expr = next.stack[4].clone().into();
    let constraint = s4_next - s0.clone();
    builder.when_transition().assert_zero(op_flags.movdn4() * constraint);

    // MOVDN5: s5' = s0
    let s5_next: AB::Expr = next.stack[5].clone().into();
    let constraint = s5_next - s0.clone();
    builder.when_transition().assert_zero(op_flags.movdn5() * constraint);

    // MOVDN6: s6' = s0
    let s6_next: AB::Expr = next.stack[6].clone().into();
    let constraint = s6_next - s0.clone();
    builder.when_transition().assert_zero(op_flags.movdn6() * constraint);

    // MOVDN7: s7' = s0
    let s7_next: AB::Expr = next.stack[7].clone().into();
    let constraint = s7_next - s0.clone();
    builder.when_transition().assert_zero(op_flags.movdn7() * constraint);

    // MOVDN8: s8' = s0
    let s8_next: AB::Expr = next.stack[8].clone().into();
    let constraint = s8_next - s0;
    builder.when_transition().assert_zero(op_flags.movdn8() * constraint);
}

/// Enforces the SWAPW operation constraints.
///
/// SWAPW swaps the first word (positions 0-3) with the second word (positions 4-7).
/// Stack: [a0, a1, a2, a3, b0, b1, b2, b3, ...] -> [b0, b1, b2, b3, a0, a1, a2, a3, ...]
fn enforce_swapw_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // Use a combined gate to share `is_transition * swapw_flag` across all constraints.
    let gate = builder.is_transition() * op_flags.swapw();
    let mut b = builder.when(gate);

    // First word (0-3) gets values from second word (4-7)
    for i in 0..4 {
        let s_next: AB::Expr = next.stack[i].clone().into();
        let s_from: AB::Expr = local.stack[i + 4].clone().into();
        let constraint = s_next - s_from;
        b.assert_zero(constraint);
    }

    // Second word (4-7) gets values from first word (0-3)
    for i in 0..4 {
        let s_next: AB::Expr = next.stack[i + 4].clone().into();
        let s_from: AB::Expr = local.stack[i].clone().into();
        let constraint = s_next - s_from;
        b.assert_zero(constraint);
    }
}

/// Enforces the SWAPW2 operation constraints.
///
/// SWAPW2 swaps the first word (positions 0-3) with the third word (positions 8-11).
/// Stack: [a0-a3, b0-b3, c0-c3, ...] -> [c0-c3, b0-b3, a0-a3, ...]
fn enforce_swapw2_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // Use a combined gate to share `is_transition * swapw2_flag` across all constraints.
    let gate = builder.is_transition() * op_flags.swapw2();
    let mut b = builder.when(gate);

    // First word (0-3) gets values from third word (8-11)
    for i in 0..4 {
        let s_next: AB::Expr = next.stack[i].clone().into();
        let s_from: AB::Expr = local.stack[i + 8].clone().into();
        let constraint = s_next - s_from;
        b.assert_zero(constraint);
    }

    // Third word (8-11) gets values from first word (0-3)
    for i in 0..4 {
        let s_next: AB::Expr = next.stack[i + 8].clone().into();
        let s_from: AB::Expr = local.stack[i].clone().into();
        let constraint = s_next - s_from;
        b.assert_zero(constraint);
    }
}

/// Enforces the SWAPW3 operation constraints.
///
/// SWAPW3 swaps the first word (positions 0-3) with the fourth word (positions 12-15).
/// Stack: [a0-a3, b0-b3, c0-c3, d0-d3] -> [d0-d3, b0-b3, c0-c3, a0-a3]
fn enforce_swapw3_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // Use a combined gate to share `is_transition * swapw3_flag` across all constraints.
    let gate = builder.is_transition() * op_flags.swapw3();
    let mut b = builder.when(gate);

    // First word (0-3) gets values from fourth word (12-15)
    for i in 0..4 {
        let s_next: AB::Expr = next.stack[i].clone().into();
        let s_from: AB::Expr = local.stack[i + 12].clone().into();
        let constraint = s_next - s_from;
        b.assert_zero(constraint);
    }

    // Fourth word (12-15) gets values from first word (0-3)
    for i in 0..4 {
        let s_next: AB::Expr = next.stack[i + 12].clone().into();
        let s_from: AB::Expr = local.stack[i].clone().into();
        let constraint = s_next - s_from;
        b.assert_zero(constraint);
    }
}

/// Enforces the SWAPDW operation constraints.
///
/// SWAPDW swaps the first double-word (positions 0-7) with the second double-word (positions 8-15).
/// Stack: [a0-a7, b0-b7] -> [b0-b7, a0-a7]
fn enforce_swapdw_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // Use a combined gate to share `is_transition * swapdw_flag` across all constraints.
    let gate = builder.is_transition() * op_flags.swapdw();
    let mut b = builder.when(gate);

    // First double-word (0-7) gets values from second double-word (8-15)
    for i in 0..8 {
        let s_next: AB::Expr = next.stack[i].clone().into();
        let s_from: AB::Expr = local.stack[i + 8].clone().into();
        let constraint = s_next - s_from;
        b.assert_zero(constraint);
    }

    // Second double-word (8-15) gets values from first double-word (0-7)
    for i in 0..8 {
        let s_next: AB::Expr = next.stack[i + 8].clone().into();
        let s_from: AB::Expr = local.stack[i].clone().into();
        let constraint = s_next - s_from;
        b.assert_zero(constraint);
    }
}

/// Enforces the CSWAP operation constraints.
///
/// CSWAP conditionally swaps the elements at positions 1 and 2 based on the control bit at s0.
/// Stack: [c, a, b, ...] -> [a', b', ...] (left shift, control bit consumed)
/// - If c = 0: a' = a, b' = b (no swap)
/// - If c = 1: a' = b, b' = a (swap)
///
/// Constraints:
/// 1. s0' = c * s2 + (1 - c) * s1
/// 2. s1' = c * s1 + (1 - c) * s2
fn enforce_cswap_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let c: AB::Expr = local.stack[0].clone().into(); // control bit
    let s1: AB::Expr = local.stack[1].clone().into(); // a
    let s2: AB::Expr = local.stack[2].clone().into(); // b

    let s0_next: AB::Expr = next.stack[0].clone().into();
    let s1_next: AB::Expr = next.stack[1].clone().into();

    // Constraint 1: s0' = c * s2 + (1 - c) * s1
    let expected0 = c.clone() * s2.clone() + (AB::Expr::ONE - c.clone()) * s1.clone();
    let constraint1 = s0_next - expected0;

    // Constraint 2: s1' = c * s1 + (1 - c) * s2
    let expected1 = c.clone() * s1 + (AB::Expr::ONE - c.clone()) * s2;
    let constraint2 = s1_next - expected1;

    // Use a combined gate to share `is_transition * cswap_flag` across both constraints,
    // and enforce c is binary.
    let gate = builder.is_transition() * op_flags.cswap();
    let binary_c = c.clone() * (c.clone() - AB::Expr::ONE);
    builder.when(gate).assert_zeros([binary_c, constraint1, constraint2]);
}

/// Enforces the CSWAPW operation constraints.
///
/// CSWAPW conditionally swaps two 4-element words based on the control bit at s0.
/// Stack: [c, a0, a1, a2, a3, b0, b1, b2, b3, ...] -> [a0', a1', a2', a3', b0', b1', b2', b3', ...]
/// - If c = 0: word A stays first, word B stays second (no swap)
/// - If c = 1: word B comes first, word A comes second (swap)
///
/// Constraints:
/// - Positions 0-3: s_i' = c * s_(i+5) + (1 - c) * s_(i+1) for i in [0,4)
/// - Positions 4-7: s_(i+4)' = c * s_(i+1) + (1 - c) * s_(i+5) for i in [0,4)
fn enforce_cswapw_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let c: AB::Expr = local.stack[0].clone().into(); // control bit

    // Use a combined gate to share `is_transition * cswapw_flag` across all constraints.
    let gate = builder.is_transition() * op_flags.cswapw();
    let mut b = builder.when(gate.clone());

    // First word output (positions 0-3): select between word A (s1-s4) and word B (s5-s8)
    for i in 0..4 {
        let a_i: AB::Expr = local.stack[i + 1].clone().into(); // word A element
        let b_i: AB::Expr = local.stack[i + 5].clone().into(); // word B element
        let s_next: AB::Expr = next.stack[i].clone().into();

        // s_i' = c * b_i + (1 - c) * a_i
        let expected = c.clone() * b_i + (AB::Expr::ONE - c.clone()) * a_i;
        let constraint = s_next - expected;
        b.assert_zero(constraint);
    }

    // Second word output (positions 4-7): select between word B (s5-s8) and word A (s1-s4)
    for i in 0..4 {
        let a_i: AB::Expr = local.stack[i + 1].clone().into(); // word A element
        let b_i: AB::Expr = local.stack[i + 5].clone().into(); // word B element
        let s_next: AB::Expr = next.stack[i + 4].clone().into();

        // s_(i+4)' = c * a_i + (1 - c) * b_i
        let expected = c.clone() * a_i + (AB::Expr::ONE - c.clone()) * b_i;
        let constraint = s_next - expected;
        b.assert_zero(constraint);
    }

    // Enforce c is binary
    let binary_c = c.clone() * (c - AB::Expr::ONE);
    builder.when(gate).assert_zero(binary_c);
}
