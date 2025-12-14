use alloc::vec::Vec;

use winter_air::TransitionConstraintDegree;

use super::{EvaluationFrame, Felt};
use crate::{
    ONE, ZERO,
    trace::chiplets::{
        BITWISE_A_COL_IDX, BITWISE_A_COL_RANGE, BITWISE_B_COL_IDX, BITWISE_B_COL_RANGE,
        BITWISE_OUTPUT_COL_IDX, BITWISE_PREV_OUTPUT_COL_IDX, BITWISE_SELECTOR_COL_IDX,
        bitwise::{NUM_DECOMP_BITS, NUM_SELECTORS, OP_CYCLE_LEN},
    },
    utils::{EvaluationResult, are_equal, binary_not, is_binary, is_zero},
};

#[cfg(test)]
pub mod tests;

// CONSTANTS
// ================================================================================================

/// The number of transition constraints on the bitwise chiplet.
pub const NUM_CONSTRAINTS: usize = 17;

// PERIODIC COLUMNS
// ================================================================================================

/// Returns the set of periodic columns required by the Bitwise chiplet.
///
/// The columns consist of:
/// - k0 column, which has a repeating pattern of a single one followed by 7 zeros.
/// - k1 column, which has a repeating pattern of a 7 ones followed by a single zero.
pub fn get_periodic_column_values() -> Vec<Vec<Felt>> {
    vec![BITWISE_K0_MASK.to_vec(), BITWISE_K1_MASK.to_vec()]
}

// BITWISE TRANSITION CONSTRAINTS
// ================================================================================================

/// Builds the transition constraint degrees for the bitwise chiplet.
pub fn get_transition_constraint_degrees() -> Vec<TransitionConstraintDegree> {
    // The degrees of constraints on the bitwise chiplet. The degree of all bitwise
    // constraints is increased by 3 due to the chiplet selector flag (degree 2) and the internal
    // selector flag specifying the bitwise operation (degree 1). The degree of internal selector
    // is also increased by 2 due to the selector flag from the Chiplets.
    let degrees: [TransitionConstraintDegree; NUM_CONSTRAINTS] = [
        // Internal Selector flag should be binary.
        TransitionConstraintDegree::new(4),
        // Internal selector flag should remain the same throughout the cycle.
        TransitionConstraintDegree::with_cycles(3, vec![OP_CYCLE_LEN]),
        // Input decomposition values should be binary.
        TransitionConstraintDegree::new(4),
        TransitionConstraintDegree::new(4),
        TransitionConstraintDegree::new(4),
        TransitionConstraintDegree::new(4),
        TransitionConstraintDegree::new(4),
        TransitionConstraintDegree::new(4),
        TransitionConstraintDegree::new(4),
        TransitionConstraintDegree::new(4),
        // Enforce correct initial values of a and b columns.
        TransitionConstraintDegree::with_cycles(3, vec![OP_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(3, vec![OP_CYCLE_LEN]),
        // Enforce correct aggregation of a and b columns during transitions.
        TransitionConstraintDegree::with_cycles(3, vec![OP_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(3, vec![OP_CYCLE_LEN]),
        // Ensure correct output aggregation.
        TransitionConstraintDegree::with_cycles(3, vec![OP_CYCLE_LEN]),
        TransitionConstraintDegree::with_cycles(3, vec![OP_CYCLE_LEN]),
        TransitionConstraintDegree::new(5),
    ];

    degrees.into()
}

/// Returns the number of transition constraints for the bitwise chiplet.
pub fn get_transition_constraint_count() -> usize {
    NUM_CONSTRAINTS
}

/// Enforces constraints for the bitwise chiplet, which includes the constraints for the
/// internal selector & bitwise operations.
pub fn enforce_constraints<E: >(
    frame: &EvaluationFrame<E>,
    periodic_values: &[E],
    result: &mut [E],
    bitwise_flag: E,
) {
    // Enforce that the internal selector is binary & remain the same throughout the cycle.
    let mut index = enforce_selectors(frame, periodic_values, result, bitwise_flag);
    // Enforce correct decomposition of the input values into the a and b columns.
    index +=
        enforce_input_decomposition(frame, periodic_values, &mut result[index..], bitwise_flag);

    // Enforce that the operation result is aggregated into the output column correctly.
    enforce_output_aggregation(frame, periodic_values, &mut result[index..], bitwise_flag);
}

/// Constraint evaluation function to enforce that the Bitwise internal selector column
/// must be binary and remain the same throughout the cycle.
fn enforce_selectors<E: >(
    frame: &EvaluationFrame<E>,
    periodic_values: &[E],
    result: &mut [E],
    processor_flag: E,
) -> usize {
    let k1 = periodic_values[1];
    let mut constraint_offset = 0;
    // Selector must be binary for the entire table.
    result[0] = processor_flag * is_binary(frame.selector());
    constraint_offset += NUM_SELECTORS;

    // Selector values should stay the same for the entire cycle. In other words, the value can
    // only change when there is a transition to a new cycle i.e. from the last row of a cycle &
    // the first row of the new cycle when periodic column k1=0.
    result[constraint_offset] = processor_flag * k1 * (frame.selector() - frame.selector_next());
    constraint_offset += NUM_SELECTORS;

    constraint_offset
}

// TRANSITION CONSTRAINT HELPERS
// ================================================================================================

/// Enforces correct decomposition of the input values `a` and `b` in each row. This requires the
/// following constraints:
/// - All values in decomposition columns must be binary.
/// - In the first row, the values in `a` and `b` must be the aggregation of their respective bit
///   columns.
/// - For every row except the last, the aggregated input value in the next row must be 16 times the
///   the value in the current row plus the aggregation of the bit decomposition in the next row.
fn enforce_input_decomposition<E: >(
    frame: &EvaluationFrame<E>,
    periodic_values: &[E],
    result: &mut [E],
    processor_flag: E,
) -> usize {
    let mut constraint_offset = 0;

    // Values in bit decomposition columns a0..a3 should be binary.
    for (idx, result) in result.iter_mut().take(NUM_DECOMP_BITS).enumerate() {
        *result = processor_flag * is_binary(frame.a_bit(idx));
    }
    constraint_offset += NUM_DECOMP_BITS;

    // Values in bit decomposition columns b0..b3 should be binary.
    for (idx, result) in result[constraint_offset..].iter_mut().take(NUM_DECOMP_BITS).enumerate() {
        *result = processor_flag * is_binary(frame.b_bit(idx));
    }
    constraint_offset += NUM_DECOMP_BITS;

    // The values in column a in the first row should be the aggregation of the decomposed bit
    // columns a0..a3.
    let first_row_flag = processor_flag * periodic_values[0];
    result[constraint_offset] = first_row_flag * (frame.a() - frame.a_agg_bits());
    constraint_offset += 1;

    // The values in column b in the first row should be the aggregation of the decomposed bit
    // columns b0..b3.
    result[constraint_offset] = first_row_flag * (frame.b() - frame.b_agg_bits());
    constraint_offset += 1;

    // During a transition between rows, the next value in the a column should be 16 times the
    // previous value plus the aggregation of the next row's bit values.
    let transition_flag = processor_flag * periodic_values[1];
    result[constraint_offset] =
        transition_flag * (frame.a_next() - (E::from(16_u8) * frame.a() + frame.a_agg_bits_next()));
    constraint_offset += 1;

    // During a transition between rows, the next value in the b column should be 16 times the
    // previous value plus the aggregation of the next row's bit values.
    result[constraint_offset] =
        transition_flag * (frame.b_next() - (E::from(16_u8) * frame.b() + frame.b_agg_bits_next()));
    constraint_offset += 1;

    constraint_offset
}

/// Enforces correct output aggregation for the operation. This requires the following 3 constraints
/// for each operation:
/// - In the first row, `output_prev` should be set to 0.
/// - For all the rows except the last one, the next value of `output_prev` should be the same as
///   the current value of `output`.
/// - For all rows, the current output value (`output`) should equal 16 times the output value
///   copied from the previous row (`output_prev`) plus the aggregated result of the bitwise
///   operation applied to the current row's set of bits.
///
/// Because the selectors for the AND and XOR operations are mutually exclusive, the
/// constraints for different operations can be aggregated into the same result indices.
fn enforce_output_aggregation<E: >(
    frame: &EvaluationFrame<E>,
    periodic_values: &[E],
    result: &mut [E],
    processor_flag: E,
) -> usize {
    let mut constraint_offset = 0;
    // Periodic column flags
    let k0_flag = periodic_values[0];
    let k1_flag = periodic_values[1];
    // Operator flags
    let bitwise_and_flag = processor_flag * frame.bitwise_and_flag();
    let bitwise_xor_flag = processor_flag * frame.bitwise_xor_flag();
    // Enforce value of `output_prev` is 0 for the first row.
    result[constraint_offset] = k0_flag * processor_flag * is_zero(frame.output_prev());
    constraint_offset += 1;

    // For all rows except the last one, enforce the next value of `output_prev` is the same as
    // the current value of `output`.
    result[constraint_offset] =
        k1_flag * processor_flag * are_equal(frame.output_prev_next(), frame.output());
    constraint_offset += 1;

    // During a transition between rows, the value in the output column should be 16 times the
    // previous value plus the aggregation of the row's operation output.
    let shifted_output = frame.output_prev() * E::from(16_u8);
    result.agg_constraint(
        constraint_offset,
        bitwise_and_flag,
        frame.output() - (shifted_output + bitwise_and(frame.bit_decomp())),
    );
    result.agg_constraint(
        constraint_offset,
        bitwise_xor_flag,
        frame.output() - (shifted_output + bitwise_xor(frame.bit_decomp())),
    );
    constraint_offset += 1;

    constraint_offset
}

/// Calculates the result of bitwise AND applied to the decomposed values provided as a bit array.
/// The result will be the AND of the first 4 bits in the provided array with the latter 4 bits.
pub fn bitwise_and<E: >(decomposed_values: &[E]) -> E {
    let mut result = E::ZERO;
    // Aggregate the result of the bitwise AND over the decomposed bits in the row.
    for idx in 0..NUM_DECOMP_BITS {
        let a = decomposed_values[idx];
        let b = decomposed_values[idx + NUM_DECOMP_BITS];
        result += E::from(2_u32.pow(idx as u32)) * a * b
    }
    result
}

/// Calculates the result of bitwise XOR applied to the decomposed values provided as a bit array.
/// The result will be the XOR of the first 4 bits in the provided array with the latter 4 bits.
pub fn bitwise_xor<E: >(decomposed_values: &[E]) -> E {
    let mut result = E::ZERO;
    // Aggregate the result of the bitwise XOR over the decomposed bits in the row.
    for idx in 0..NUM_DECOMP_BITS {
        let a = decomposed_values[idx];
        let b = decomposed_values[idx + NUM_DECOMP_BITS];
        result += E::from(2_u32.pow(idx as u32)) * (a + b - E::from(2_u8) * a * b)
    }
    result
}

// BITWISE FRAME EXTENSION TRAIT
// ================================================================================================
trait EvaluationFrameExt<E: > {
    // --- Column accessors -----------------------------------------------------------------------

    /// Gets the current value of the specified selector column.
    fn selector(&self) -> E;
    /// Gets the next value of the specified selector column.
    fn selector_next(&self) -> E;
    /// Gets the current value of the aggregated `a` input.
    fn a(&self) -> E;
    /// Gets the value of the aggregated `a` input in the next row.
    fn a_next(&self) -> E;
    /// Gets the value of the decomposed bit of `a` at the specified index in the current row.
    fn a_bit(&self, index: usize) -> E;
    /// Gets the current value of the aggregated `b` input.
    fn b(&self) -> E;
    /// Gets the value of the aggregated `b` input in the next row.
    fn b_next(&self) -> E;
    /// Gets the value of the decomposed bit of `b` at the specified index in the current row.
    fn b_bit(&self, index: usize) -> E;
    /// Gets the entire range of decomposed input values for `a` and `b` in the current row.
    fn bit_decomp(&self) -> &[E];
    /// Gets the value of the aggregated output in the previous row.
    fn output_prev(&self) -> E;
    /// Gets the value of the aggregated output of the current row, or
    /// the previous row with respect to the next row.
    fn output_prev_next(&self) -> E;
    /// Gets the value of the aggregated output in the current row.
    fn output(&self) -> E;

    // --- Intermediate variables & helpers -------------------------------------------------------
    /// The aggregated value of the decomposed bits from `a` in the current row.
    fn a_agg_bits(&self) -> E;
    /// The aggregated value of the decomposed bits from `a` in the next row.
    fn a_agg_bits_next(&self) -> E;
    /// The aggregated value of the decomposed bits from `b` in the current row.
    fn b_agg_bits(&self) -> E;
    /// The aggregated value of the decomposed bits from `b` in the next row.
    fn b_agg_bits_next(&self) -> E;

    // --- Flags ----------------------------------------------------------------------------------

    /// The selector flag for the bitwise AND operation.
    fn bitwise_and_flag(&self) -> E;
    /// The selector flag for the bitwise XOR operation.
    fn bitwise_xor_flag(&self) -> E;
}

impl<E: > EvaluationFrameExt<E> for &EvaluationFrame<E> {
    // --- Column accessors -----------------------------------------------------------------------

    #[inline(always)]
    fn selector(&self) -> E {
        self.current()[BITWISE_SELECTOR_COL_IDX]
    }

    #[inline(always)]
    fn selector_next(&self) -> E {
        self.next()[BITWISE_SELECTOR_COL_IDX]
    }

    #[inline(always)]
    fn a(&self) -> E {
        self.current()[BITWISE_A_COL_IDX]
    }

    #[inline(always)]
    fn a_next(&self) -> E {
        self.next()[BITWISE_A_COL_IDX]
    }

    #[inline(always)]
    fn a_bit(&self, index: usize) -> E {
        self.current()[BITWISE_A_COL_RANGE.start + index]
    }

    #[inline(always)]
    fn b(&self) -> E {
        self.current()[BITWISE_B_COL_IDX]
    }

    #[inline(always)]
    fn b_next(&self) -> E {
        self.next()[BITWISE_B_COL_IDX]
    }

    #[inline(always)]
    fn b_bit(&self, index: usize) -> E {
        self.current()[BITWISE_B_COL_RANGE.start + index]
    }

    #[inline(always)]
    fn bit_decomp(&self) -> &[E] {
        &self.current()[BITWISE_A_COL_RANGE.start..BITWISE_B_COL_RANGE.end]
    }

    #[inline(always)]
    fn output_prev(&self) -> E {
        self.current()[BITWISE_PREV_OUTPUT_COL_IDX]
    }

    #[inline(always)]
    fn output_prev_next(&self) -> E {
        self.next()[BITWISE_PREV_OUTPUT_COL_IDX]
    }

    #[inline(always)]
    fn output(&self) -> E {
        self.current()[BITWISE_OUTPUT_COL_IDX]
    }

    // --- Intermediate variables & helpers -------------------------------------------------------
    #[inline(always)]
    fn a_agg_bits(&self) -> E {
        agg_bits(self.current(), BITWISE_A_COL_RANGE.start)
    }

    #[inline(always)]
    fn a_agg_bits_next(&self) -> E {
        agg_bits(self.next(), BITWISE_A_COL_RANGE.start)
    }

    #[inline(always)]
    fn b_agg_bits(&self) -> E {
        agg_bits(self.current(), BITWISE_B_COL_RANGE.start)
    }

    #[inline(always)]
    fn b_agg_bits_next(&self) -> E {
        agg_bits(self.next(), BITWISE_B_COL_RANGE.start)
    }

    // --- Flags ----------------------------------------------------------------------------------

    #[inline(always)]
    fn bitwise_and_flag(&self) -> E {
        binary_not(self.current()[BITWISE_SELECTOR_COL_IDX])
    }

    #[inline(always)]
    fn bitwise_xor_flag(&self) -> E {
        self.current()[BITWISE_SELECTOR_COL_IDX]
    }
}

// HELPER FUNCTIONS
// ================================================================================================
/// Aggregate 4 decomposed bits representing a 4-bit binary value into a decimal value, starting
/// from `start_idx` in the provided row.
pub fn agg_bits<E: >(row: &[E], start_idx: usize) -> E {
    let mut result = E::ZERO;
    // TODO: this can be optimized.
    // From Bobbin: "we are multiplying by a small power of two and then summing up the results -
    // thus, in theory, we could just aggregate results in a 128-bit integer and perform only a
    // single reduction in the end. This works only when we are in the base field."
    for bit_idx in 0..NUM_DECOMP_BITS {
        result += E::from(2_u32.pow(bit_idx as u32)) * row[start_idx + bit_idx];
    }
    result
}

// CYCLE MASKS
// ================================================================================================
pub const BITWISE_K0_MASK: [Felt; OP_CYCLE_LEN] = [ONE, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO];

pub const BITWISE_K1_MASK: [Felt; OP_CYCLE_LEN] = [ONE, ONE, ONE, ONE, ONE, ONE, ONE, ZERO];
