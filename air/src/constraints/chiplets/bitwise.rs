//! Bitwise chiplet constraints.
//!
//! The bitwise chiplet handles AND and XOR operations on 32-bit values.
//! Each operation spans 8 rows, processing 4 bits per row.
//!
//! ## Periodic Columns
//!
//! The bitwise chiplet uses two periodic patterns over 8 rows:
//! - `k_first`: [1, 0, 0, 0, 0, 0, 0, 0] - marks first row of cycle
//! - `k_transition`: [1, 1, 1, 1, 1, 1, 1, 0] - marks non-last rows
//!
//! ## Column Layout (within chiplet, offset by selectors)
//!
//! | Column    | Purpose                           |
//! |-----------|-----------------------------------|
//! | op_flag   | Operation type: 0=AND, 1=XOR      |
//! | a         | Aggregated value of input a       |
//! | b         | Aggregated value of input b       |
//! | a_limb[4] | 4-bit decomposition of a          |
//! | b_limb[4] | 4-bit decomposition of b          |
//! | zp        | Previous aggregated output        |
//! | z         | Current aggregated output         |

use alloc::vec::Vec;

use miden_core::field::PrimeCharacteristicRing;

use super::{
    hasher::periodic::NUM_PERIODIC_COLUMNS as HASHER_NUM_PERIODIC_COLUMNS, selectors::ChipletFlags,
};
use crate::{
    Felt, MainTraceRow, MidenAirBuilder,
    constraints::{
        constants::{F_1, F_16},
        utils::horner_eval_bits,
    },
    trace::{BitwiseCols, chiplets::borrow_chiplet},
};

// CONSTANTS
// ================================================================================================

/// Index of k_first periodic column (marks first row of 8-row cycle).
/// Placed after hasher periodic columns.
pub const P_BITWISE_K_FIRST: usize = HASHER_NUM_PERIODIC_COLUMNS;

/// Index of k_transition periodic column (marks non-last rows of 8-row cycle).
pub const P_BITWISE_K_TRANSITION: usize = HASHER_NUM_PERIODIC_COLUMNS + 1;

// ENTRY POINTS
// ================================================================================================

/// Enforce all bitwise chiplet constraints.
///
/// This enforces:
/// 1. Operation flag constraints (binary, constant within cycle)
/// 2. Input decomposition constraints (binary bits, aggregation)
/// 3. Output aggregation constraints
pub fn enforce_bitwise_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    flags: &ChipletFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let (k_first, k_transition) = {
        // Clone out what we need to avoid holding a borrow of `builder` while asserting
        // constraints.
        let periodic = builder.periodic_values();
        debug_assert!(periodic.len() > P_BITWISE_K_TRANSITION);
        (periodic[P_BITWISE_K_FIRST].into(), periodic[P_BITWISE_K_TRANSITION].into())
    };

    let bitwise_flag = flags.is_active.clone();

    // Load bitwise columns via zero-copy borrow into the typed struct
    let cols: &BitwiseCols<AB::Var> = borrow_chiplet(&local.chiplets[2..15]);
    let cols_next: &BitwiseCols<AB::Var> = borrow_chiplet(&next.chiplets[2..15]);

    // Convert bit arrays to AB::Expr for arithmetic
    let a_bits: [AB::Expr; 4] = cols.a_bits.map(Into::into);
    let b_bits: [AB::Expr; 4] = cols.b_bits.map(Into::into);
    let a_bits_next: [AB::Expr; 4] = cols_next.a_bits.map(Into::into);
    let b_bits_next: [AB::Expr; 4] = cols_next.b_bits.map(Into::into);

    // ==========================================================================
    // OPERATION FLAG CONSTRAINTS
    // ==========================================================================

    // op_flag must be binary (0 for AND, 1 for XOR)
    let op_flag: AB::Expr = cols.op_flag.into();
    builder.assert_zero(bitwise_flag.clone() * op_flag.clone() * (op_flag.clone() - F_1));

    // op_flag must remain constant within the 8-row cycle (can only change when k1=0)
    let op_flag_next: AB::Expr = cols_next.op_flag.into();
    let gate_transition = k_transition.clone() * bitwise_flag.clone();
    builder.assert_zero(gate_transition.clone() * (op_flag.clone() - op_flag_next));

    // ==========================================================================
    // INPUT DECOMPOSITION CONSTRAINTS
    // ==========================================================================

    // Bit decomposition columns must be binary
    let gate = bitwise_flag.clone();
    for bit in &a_bits {
        builder.assert_zero(gate.clone() * bit.clone() * (bit.clone() - F_1));
    }

    for bit in &b_bits {
        builder.assert_zero(gate.clone() * bit.clone() * (bit.clone() - F_1));
    }

    // First row of cycle (k0=1): a = aggregated bits, b = aggregated bits
    let a_agg = horner_eval_bits(&a_bits);
    let b_agg = horner_eval_bits(&b_bits);
    let a: AB::Expr = cols.a.into();
    let b: AB::Expr = cols.b.into();
    let prev_output: AB::Expr = cols.prev_output.into();
    let gate_first = k_first.clone() * bitwise_flag.clone();
    for expr in [a.clone() - a_agg, b.clone() - b_agg, prev_output.clone()] {
        builder.assert_zero(gate_first.clone() * expr);
    }

    // Transition rows (k1=1): a' = 16*a + agg(a'_bits), b' = 16*b + agg(b'_bits)
    let a_agg_next = horner_eval_bits(&a_bits_next);
    let b_agg_next = horner_eval_bits(&b_bits_next);
    let a_next: AB::Expr = cols_next.a.into();
    let b_next: AB::Expr = cols_next.b.into();
    for expr in [
        a_next - (a.clone() * F_16 + a_agg_next),
        b_next - (b * F_16 + b_agg_next),
    ] {
        builder.assert_zero(gate_transition.clone() * expr);
    }

    // ==========================================================================
    // OUTPUT AGGREGATION CONSTRAINTS
    // ==========================================================================

    // Transition rows (k1=1): output_prev' = output
    let output: AB::Expr = cols.output.into();
    let prev_output_next: AB::Expr = cols_next.prev_output.into();
    builder.assert_zero(gate_transition * (prev_output_next - output.clone()));

    // Every row: output = 16*output_prev + bitwise_result

    // Compute AND of 4-bit limbs: sum(2^i * (a[i] * b[i]))
    let a_and_b_bits: [AB::Expr; 4] =
        core::array::from_fn(|i| a_bits[i].clone() * b_bits[i].clone());
    let a_and_b = horner_eval_bits(&a_and_b_bits);

    // Compute XOR of 4-bit limbs: sum(2^i * (a[i] + b[i] - 2*a[i]*b[i]))
    // Reuses a_and_b_bits: xor_bit = a + b - 2*and_bit
    let a_xor_b_bits: [AB::Expr; 4] = core::array::from_fn(|i| {
        a_bits[i].clone() + b_bits[i].clone() - a_and_b_bits[i].clone().double()
    });
    let a_xor_b = horner_eval_bits(&a_xor_b_bits);

    // z = zp * 16 + (op_flag ? a_xor_b : a_and_b)
    // Equivalent: z = zp * 16 + a_and_b + op_flag * (a_xor_b - a_and_b)
    let expected_z =
        prev_output * F_16 + a_and_b.clone() + op_flag * (a_xor_b - a_and_b);

    builder.assert_zero(bitwise_flag * (output - expected_z));
}

// =============================================================================
// PERIODIC COLUMNS
// =============================================================================

/// Generate periodic columns for the bitwise chiplet.
///
/// Returns [k_first, k_transition] where:
/// - k_first: [1, 0, 0, 0, 0, 0, 0, 0] (period 8)
/// - k_transition: [1, 1, 1, 1, 1, 1, 1, 0] (period 8)
pub fn periodic_columns() -> [Vec<Felt>; 2] {
    let k_first = vec![
        Felt::ONE,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ];

    let k_transition = vec![
        Felt::ONE,
        Felt::ONE,
        Felt::ONE,
        Felt::ONE,
        Felt::ONE,
        Felt::ONE,
        Felt::ONE,
        Felt::ZERO,
    ];

    [k_first, k_transition]
}
