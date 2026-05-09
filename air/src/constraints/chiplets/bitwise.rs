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

use core::{array, borrow::Borrow};

use miden_core::field::PrimeCharacteristicRing;

use super::selectors::ChipletFlags;
use crate::{
    AirBuilder, MainCols, MidenAirBuilder,
    constraints::{
        chiplets::columns::{BitwiseCols, PeriodicCols},
        constants::F_16,
        utils::horner_eval_bits,
    },
};

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
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    flags: &ChipletFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let periodic: &PeriodicCols<_> = builder.periodic_values().borrow();
    let k_first = periodic.bitwise.k_first;
    let k_transition = periodic.bitwise.k_transition;

    let bitwise_flag = flags.is_active.clone();

    let cols: &BitwiseCols<AB::Var> = local.bitwise();
    let cols_next: &BitwiseCols<AB::Var> = next.bitwise();

    // All bitwise constraints are gated on the bitwise chiplet being active.
    let bitwise_builder = &mut builder.when(bitwise_flag);

    // ==========================================================================
    // OPERATION FLAG CONSTRAINTS
    // ==========================================================================

    // op_flag must be binary (0 for AND, 1 for XOR)
    let op_flag = cols.op_flag;
    bitwise_builder.assert_bool(op_flag);

    // op_flag must remain constant within the 8-row cycle (can only change when k1=0)
    let op_flag_next = cols_next.op_flag;
    bitwise_builder.when(k_transition).assert_eq(op_flag, op_flag_next);

    // ==========================================================================
    // INPUT DECOMPOSITION CONSTRAINTS
    // ==========================================================================
    let (a, a_bits) = (cols.a, cols.a_bits);
    let (b, b_bits) = (cols.b, cols.b_bits);

    // Bit decomposition columns must be binary
    bitwise_builder.assert_bools(a_bits);
    bitwise_builder.assert_bools(b_bits);

    // First row of cycle (k0=1): a = aggregated bits, b = aggregated bits
    // First row: input aggregation must match, and previous output must be zero.
    {
        let builder = &mut bitwise_builder.when(k_first);

        let a_expected = horner_eval_bits(&a_bits);
        builder.assert_eq(a, a_expected);

        let b_expected = horner_eval_bits(&b_bits);
        builder.assert_eq(b, b_expected);

        builder.assert_zero(cols.prev_output);
    }

    let (a_next, a_next_bits) = (cols_next.a, cols_next.a_bits);
    let (b_next, b_next_bits) = (cols_next.b, cols_next.b_bits);

    // Transition rows (k1=1): a' = 16*a + agg(a'_bits), b' = 16*b + agg(b'_bits)
    // Transition rows: inputs aggregate with 16x shift.
    {
        let builder = &mut bitwise_builder.when(k_transition);

        let a_next_expected = a * F_16 + horner_eval_bits(&a_next_bits);
        builder.assert_eq(a_next, a_next_expected);

        let b_next_expected = b * F_16 + horner_eval_bits(&b_next_bits);
        builder.assert_eq(b_next, b_next_expected);
    }

    // ==========================================================================
    // OUTPUT AGGREGATION CONSTRAINTS
    // ==========================================================================

    // Transition rows (k1=1): output_prev' = output
    let output = cols.output;
    let prev_output_next = cols_next.prev_output;
    bitwise_builder.when(k_transition).assert_eq(output, prev_output_next);

    // Every row: output = 16*output_prev + bitwise_result

    // Compute AND of 4-bit limbs: sum(2^i * (a[i] * b[i]))
    let a_and_b_bits: [AB::Expr; 4] = array::from_fn(|i| a_bits[i] * b_bits[i]);
    let a_and_b: AB::Expr = horner_eval_bits(&a_and_b_bits);

    // Compute XOR of 4-bit limbs: sum(2^i * (a[i] + b[i] - 2*a[i]*b[i]))
    // Reuses a_and_b_bits: xor_bit = a + b - 2*and_bit
    let a_xor_b_bits: [AB::Expr; 4] =
        array::from_fn(|i| a_bits[i] + b_bits[i] - a_and_b_bits[i].clone().double());
    let a_xor_b: AB::Expr = horner_eval_bits(&a_xor_b_bits);

    // z = zp * 16 + (op_flag ? a_xor_b : a_and_b)
    // Equivalent: z = zp * 16 + a_and_b + op_flag * (a_xor_b - a_and_b)
    let zp = cols.prev_output;
    let expected_z = zp * F_16 + a_and_b.clone() + op_flag * (a_xor_b - a_and_b);

    let z = cols.output;
    bitwise_builder.assert_eq(z, expected_z);
}
