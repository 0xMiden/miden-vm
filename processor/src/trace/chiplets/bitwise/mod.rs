use alloc::vec::Vec;

use miden_air::trace::chiplets::bitwise::{
    A_COL_IDX, A_COL_RANGE, B_COL_IDX, B_COL_RANGE, BITWISE_AND, BITWISE_XOR, OUTPUT_COL_IDX,
    PREV_OUTPUT_COL_IDX, TRACE_WIDTH,
};
use miden_core::utils::{Matrix, RowMajorMatrix};

use crate::{Felt, ZERO, operation::OperationError, trace::ChipletTraceFragment};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Initial capacity of each column.
const INIT_TRACE_CAPACITY: usize = 128;

// BITWISE
// ================================================================================================

/// Helper for the VM that computes AND and XOR bitwise operations on 32-bit values.
/// It also builds an execution trace of these operations.
///
/// ## Bitwise operation execution trace (AND and XOR)
/// The execution trace for each operation consists of 8 rows and 14 columns. At a high level,
/// we break input values into 4-bit limbs, apply the bitwise operation to these limbs at every
/// row starting with the most significant limb, and accumulate the result in the result column.
///
/// The layout of the table is illustrated below.
///
///    s     a     b      a0     a1     a2     a3     b0     b1     b2     b3    zp     z
/// ├─────┴─────┴─────┴───────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┴─────┴─────┤
///
/// In the above, the meaning of the columns is as follows:
/// - Selector column s is used to specify the bitwise operator for each row.
/// - Columns `a` and `b` contain accumulated 4-bit limbs of input values. Specifically, at the
///   first row, the values of columns `a` and `b` are set to the most significant 4-bit limb of
///   each input value. With all subsequent rows, the next most significant limb is appended to each
///   column for the corresponding value. Thus, by the 8th row, columns `a` and `b` contain full
///   input values for the bitwise operation.
/// - Columns `a0` through `a3` and `b0` through `b3` contain bits of the least significant 4-bit
///   limb of the values in `a` and `b` columns respectively.
/// - Column `zp` contains the accumulated result of applying the bitwise operation to 4-bit limbs,
///   but for the previous row. In the first row, it is 0.
/// - Column `z` contains the accumulated result of applying the bitwise operation to 4-bit limbs.
///   At the first row, column `z` contains the result of bitwise operation applied to the most
///   significant 4-bit limbs of the input values. With every subsequent row, the next most
///   significant 4-bit limb of the result is appended to it. Thus, by the 8th row, column `z`
///   contains the full result of the bitwise operation.
#[derive(Debug)]
pub struct Bitwise {
    trace: RowMajorMatrix<Felt>,
}

impl Bitwise {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [Bitwise] initialized with an empty trace.
    pub fn new() -> Self {
        Self {
            trace: RowMajorMatrix::new(
                Vec::with_capacity(INIT_TRACE_CAPACITY * TRACE_WIDTH),
                TRACE_WIDTH,
            ),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns length of execution trace required to describe bitwise operations executed on the
    /// VM.
    pub fn trace_len(&self) -> usize {
        self.trace.height()
    }

    // TRACE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Computes a bitwise AND of `a` and `b` and returns the result. We assume that `a` and `b`
    /// are 32-bit values. If that's not the case, the result of the computation is undefined.
    ///
    /// This also adds 8 rows to the internal execution trace table required for computing the
    /// operation.
    pub fn u32and(&mut self, a: Felt, b: Felt) -> Result<Felt, OperationError> {
        let a = assert_u32(a)? as u64;
        let b = assert_u32(b)? as u64;
        let mut result = 0u64;

        // append 8 rows to the trace, each row computing bitwise AND in 4 bit limbs starting with
        // the most significant limb.
        for bit_offset in (0..32).step_by(4).rev() {
            let prev_output = result;
            // shift a and b so that the next 4-bit limb is in the least significant position
            let a = a >> bit_offset;
            let b = b >> bit_offset;

            // compute bitwise AND of the 4 least significant bits of a and b
            let result_4_bit = (a & b) & 0xf;
            result = (result << 4) | result_4_bit;

            self.push_bitwise_row(BITWISE_AND, a, b, prev_output, result);
        }

        Ok(Felt::new_unchecked(result))
    }

    /// Computes a bitwise XOR of `a` and `b` and returns the result. We assume that `a` and `b`
    /// are 32-bit values. If that's not the case, the result of the computation is undefined.
    ///
    /// This also adds 8 rows to the internal execution trace table required for computing the
    /// operation.
    pub fn u32xor(&mut self, a: Felt, b: Felt) -> Result<Felt, OperationError> {
        let a = assert_u32(a)? as u64;
        let b = assert_u32(b)? as u64;
        let mut result = 0u64;

        // append 8 rows to the trace, each row computing bitwise XOR in 4 bit limbs starting with
        // the most significant limb.
        for bit_offset in (0..32).step_by(4).rev() {
            let prev_output = result;
            // shift a and b so that the next 4-bit limb is in the least significant position
            let a = a >> bit_offset;
            let b = b >> bit_offset;

            // compute bitwise XOR of the 4 least significant bits of a and b
            let result_4_bit = (a ^ b) & 0xf;
            result = (result << 4) | result_4_bit;

            self.push_bitwise_row(BITWISE_XOR, a, b, prev_output, result);
        }

        Ok(Felt::new_unchecked(result))
    }

    // EXECUTION TRACE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Fills the provided trace fragment with trace data from this bitwise helper instance.
    pub fn fill_trace(self, trace: &mut ChipletTraceFragment) {
        // make sure fragment dimensions are consistent with the dimensions of this trace
        debug_assert_eq!(self.trace_len(), trace.len(), "inconsistent trace lengths");
        debug_assert_eq!(TRACE_WIDTH, trace.width(), "inconsistent trace widths");

        trace.copy_rows_from(&self.trace.values);
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Appends one full row (in column order) to the row-major trace buffer:
    /// - Column 0: the selector value for the bitwise operation being executed.
    /// - Column `A_COL_IDX`: the current value of `a`.
    /// - Column `B_COL_IDX`: the current value of `b`.
    /// - `A_COL_RANGE`: the 4 least-significant bits of `a`.
    /// - `B_COL_RANGE`: the 4 least-significant bits of `b`.
    /// - `PREV_OUTPUT_COL_IDX` / `OUTPUT_COL_IDX`: the previous and current accumulated output.
    fn push_bitwise_row(&mut self, selector: Felt, a: u64, b: u64, prev_output: u64, output: u64) {
        let mut row = [ZERO; TRACE_WIDTH];
        row[0] = selector;
        row[A_COL_IDX] = Felt::new_unchecked(a);
        row[B_COL_IDX] = Felt::new_unchecked(b);

        row[A_COL_RANGE.start] = Felt::new_unchecked(a & 1);
        row[A_COL_RANGE.start + 1] = Felt::new_unchecked((a >> 1) & 1);
        row[A_COL_RANGE.start + 2] = Felt::new_unchecked((a >> 2) & 1);
        row[A_COL_RANGE.start + 3] = Felt::new_unchecked((a >> 3) & 1);

        row[B_COL_RANGE.start] = Felt::new_unchecked(b & 1);
        row[B_COL_RANGE.start + 1] = Felt::new_unchecked((b >> 1) & 1);
        row[B_COL_RANGE.start + 2] = Felt::new_unchecked((b >> 2) & 1);
        row[B_COL_RANGE.start + 3] = Felt::new_unchecked((b >> 3) & 1);

        row[PREV_OUTPUT_COL_IDX] = Felt::new_unchecked(prev_output);
        row[OUTPUT_COL_IDX] = Felt::new_unchecked(output);

        self.trace.values.extend_from_slice(&row);
    }
}

impl Default for Bitwise {
    fn default() -> Self {
        Self::new()
    }
}

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

pub fn assert_u32(value: Felt) -> Result<u32, OperationError> {
    u32::try_from(value.as_canonical_u64())
        .map_err(|_| OperationError::NotU32Values { values: vec![value] })
}
