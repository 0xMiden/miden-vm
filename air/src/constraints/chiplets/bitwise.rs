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
//! ## Column Layout (within chiplet, offset by chiplet selectors)
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

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

// CONSTANTS
// ================================================================================================
use super::hasher::periodic::NUM_PERIODIC_COLUMNS as HASHER_NUM_PERIODIC_COLUMNS;
use super::selectors::bitwise_chiplet_flag;
use crate::{
    Felt, MainTraceRow,
    trace::{
        CHIPLETS_OFFSET,
        chiplets::{
            BITWISE_A_COL_IDX, BITWISE_A_COL_RANGE, BITWISE_B_COL_IDX, BITWISE_B_COL_RANGE,
            BITWISE_OUTPUT_COL_IDX, BITWISE_PREV_OUTPUT_COL_IDX, BITWISE_SELECTOR_COL_IDX,
        },
    },
};

/// Index of k_first periodic column (marks first row of 8-row cycle).
/// Placed after hasher periodic columns.
pub const P_BITWISE_K_FIRST: usize = HASHER_NUM_PERIODIC_COLUMNS;

/// Index of k_transition periodic column (marks non-last rows of 8-row cycle).
pub const P_BITWISE_K_TRANSITION: usize = HASHER_NUM_PERIODIC_COLUMNS + 1;

/// Number of bits processed per row.
const NUM_BITS_PER_ROW: usize = 4;

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
    k_first: AB::Expr,
    k_transition: AB::Expr,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Compute bitwise active flag from top-level selectors
    let s0: AB::Expr = local.chiplets[0].clone().into();
    let s1: AB::Expr = local.chiplets[1].clone().into();
    let bitwise_flag = bitwise_chiplet_flag(s0, s1);

    // Periodic column values for 8-row cycle (base field)
    let k0: AB::Expr = k_first;
    let k1: AB::Expr = k_transition;

    // Load bitwise columns using typed struct
    let cols: BitwiseColumns<AB::Expr> = BitwiseColumns::from_row::<AB>(local);
    let cols_next: BitwiseColumns<AB::Expr> = BitwiseColumns::from_row::<AB>(next);

    let one: AB::Expr = AB::Expr::ONE;
    let sixteen: AB::Expr = AB::Expr::from_u32(16);

    // ==========================================================================
    // OPERATION FLAG CONSTRAINTS
    // ==========================================================================

    // op_flag must be binary (0 for AND, 1 for XOR)
    builder.assert_zero(
        bitwise_flag.clone() * cols.op_flag.clone() * (cols.op_flag.clone() - one.clone()),
    );

    // op_flag must remain constant within the 8-row cycle (can only change when k1=0)
    let gate_transition = k1.clone() * bitwise_flag.clone();
    builder
        .when(gate_transition.clone())
        .assert_zero(cols.op_flag.clone() - cols_next.op_flag.clone());

    // ==========================================================================
    // INPUT DECOMPOSITION CONSTRAINTS
    // ==========================================================================

    // Bit decomposition columns must be binary
    let gate = bitwise_flag.clone();
    builder.assert_zeros(core::array::from_fn::<_, NUM_BITS_PER_ROW, _>(|i| {
        gate.clone() * cols.a_bits[i].clone() * (cols.a_bits[i].clone() - one.clone())
    }));
    builder.assert_zeros(core::array::from_fn::<_, NUM_BITS_PER_ROW, _>(|i| {
        gate.clone() * cols.b_bits[i].clone() * (cols.b_bits[i].clone() - one.clone())
    }));

    // First row of cycle (k0=1): a = aggregated bits, b = aggregated bits
    let a_agg = aggregate_limbs(&cols.a_bits);
    let b_agg = aggregate_limbs(&cols.b_bits);
    let gate_first = k0.clone() * bitwise_flag.clone();
    builder.when(gate_first).assert_zeros([
        cols.a.clone() - a_agg,
        cols.b.clone() - b_agg,
        cols.prev_output.clone(),
    ]);

    // Transition rows (k1=1): a' = 16*a + agg(a'_bits), b' = 16*b + agg(b'_bits)
    let a_agg_next = aggregate_limbs(&cols_next.a_bits);
    let b_agg_next = aggregate_limbs(&cols_next.b_bits);
    builder.when(gate_transition.clone()).assert_zeros([
        cols_next.a.clone() - (cols.a.clone() * sixteen.clone() + a_agg_next),
        cols_next.b.clone() - (cols.b.clone() * sixteen.clone() + b_agg_next),
    ]);

    // ==========================================================================
    // OUTPUT AGGREGATION CONSTRAINTS
    // ==========================================================================

    // Transition rows (k1=1): output_prev' = output
    builder
        .when(gate_transition)
        .assert_zero(cols_next.prev_output.clone() - cols.output.clone());

    // Every row: output = 16*output_prev + bitwise_result
    let a_and_b = compute_limb_and(&cols.a_bits, &cols.b_bits);
    let a_xor_b = compute_limb_xor(&cols.a_bits, &cols.b_bits);

    // z = zp * 16 + (op_flag ? a_xor_b : a_and_b)
    // Equivalent: z = zp * 16 + a_and_b + op_flag * (a_xor_b - a_and_b)
    let expected_z = cols.prev_output.clone() * sixteen
        + a_and_b.clone()
        + cols.op_flag.clone() * (a_xor_b.clone() - a_and_b);

    builder.assert_zero(bitwise_flag * (cols.output.clone() - expected_z));
}

// INTERNAL HELPERS
// ================================================================================================

/// Typed access to bitwise chiplet columns.
///
/// This struct provides named access to bitwise columns, eliminating error-prone
/// index arithmetic. Created from a `MainTraceRow` reference.
pub struct BitwiseColumns<E> {
    /// Operation flag: 0=AND, 1=XOR
    pub op_flag: E,
    /// Aggregated value of input a
    pub a: E,
    /// Aggregated value of input b
    pub b: E,
    /// 4-bit decomposition of a (little-endian)
    pub a_bits: [E; NUM_BITS_PER_ROW],
    /// 4-bit decomposition of b (little-endian)
    pub b_bits: [E; NUM_BITS_PER_ROW],
    /// Previous aggregated output
    pub prev_output: E,
    /// Current aggregated output
    pub output: E,
}

impl<E: Clone> BitwiseColumns<E> {
    /// Extract bitwise columns from a main trace row.
    pub fn from_row<AB>(row: &MainTraceRow<AB::Var>) -> Self
    where
        AB: MidenAirBuilder<F = Felt>,
        AB::Var: Into<E> + Clone,
    {
        let op_idx = BITWISE_SELECTOR_COL_IDX - CHIPLETS_OFFSET;
        let a_idx = BITWISE_A_COL_IDX - CHIPLETS_OFFSET;
        let b_idx = BITWISE_B_COL_IDX - CHIPLETS_OFFSET;
        let a_bits_start = BITWISE_A_COL_RANGE.start - CHIPLETS_OFFSET;
        let b_bits_start = BITWISE_B_COL_RANGE.start - CHIPLETS_OFFSET;
        let zp_idx = BITWISE_PREV_OUTPUT_COL_IDX - CHIPLETS_OFFSET;
        let z_idx = BITWISE_OUTPUT_COL_IDX - CHIPLETS_OFFSET;

        BitwiseColumns {
            op_flag: row.chiplets[op_idx].clone().into(),
            a: row.chiplets[a_idx].clone().into(),
            b: row.chiplets[b_idx].clone().into(),
            a_bits: core::array::from_fn(|i| row.chiplets[a_bits_start + i].clone().into()),
            b_bits: core::array::from_fn(|i| row.chiplets[b_bits_start + i].clone().into()),
            prev_output: row.chiplets[zp_idx].clone().into(),
            output: row.chiplets[z_idx].clone().into(),
        }
    }
}

/// Aggregate 4 bits into a value (little-endian): sum(2^i * limb[i])
/// Uses Horner's method: ((b3*2 + b2)*2 + b1)*2 + b0
fn aggregate_limbs<E: PrimeCharacteristicRing>(limbs: &[E; 4]) -> E {
    limbs.iter().rev().fold(E::ZERO, |acc, bit| acc.double() + bit.clone())
}

/// Compute AND of 4-bit limbs: sum(2^i * (a[i] * b[i]))
/// Uses Horner's method for aggregation
fn compute_limb_and<E: PrimeCharacteristicRing>(a: &[E; 4], b: &[E; 4]) -> E {
    let and_bits: [E; 4] = core::array::from_fn(|i| a[i].clone() * b[i].clone());
    and_bits.iter().rev().fold(E::ZERO, |acc, bit| acc.double() + bit.clone())
}

/// Compute XOR of 4-bit limbs: sum(2^i * (a[i] + b[i] - 2*a[i]*b[i]))
/// Uses Horner's method for aggregation
fn compute_limb_xor<E: PrimeCharacteristicRing>(a: &[E; 4], b: &[E; 4]) -> E {
    let xor_bits: [E; 4] = core::array::from_fn(|i| {
        a[i].clone() + b[i].clone() - (a[i].clone() * b[i].clone()).double()
    });
    xor_bits.iter().rev().fold(E::ZERO, |acc, bit| acc.double() + bit.clone())
}

// =============================================================================
// PERIODIC COLUMNS
// =============================================================================

/// Generate periodic columns for the bitwise chiplet.
///
/// Returns [k_first, k_transition] where:
/// - k_first: [1, 0, 0, 0, 0, 0, 0, 0] (period 8)
/// - k_transition: [1, 1, 1, 1, 1, 1, 1, 0] (period 8)
pub fn periodic_columns() -> [alloc::vec::Vec<Felt>; 2] {
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
