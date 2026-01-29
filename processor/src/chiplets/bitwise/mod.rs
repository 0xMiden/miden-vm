use alloc::vec::Vec;

use miden_air::trace::chiplets::bitwise::{
    A_COL_IDX, A_COL_RANGE, B_COL_IDX, B_COL_RANGE, BITWISE_AND, BITWISE_XOR, OUTPUT_COL_IDX,
    PREV_OUTPUT_COL_IDX, TRACE_WIDTH,
};

use super::{Felt, TraceFragment};
use crate::{OperationError, PrimeField64};

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
    trace: [Vec<Felt>; TRACE_WIDTH],
}

impl Bitwise {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [Bitwise] initialized with an empty trace.
    pub fn new() -> Self {
        let trace = (0..TRACE_WIDTH)
            .map(|_| Vec::with_capacity(INIT_TRACE_CAPACITY))
            .collect::<Vec<_>>()
            .try_into()
            .expect("failed to convert vector to array");
        Self { trace }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns length of execution trace required to describe bitwise operations executed on the
    /// VM.
    pub fn trace_len(&self) -> usize {
        self.trace[0].len()
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
            // append the previous row's result to the column for previous output values
            self.trace[PREV_OUTPUT_COL_IDX].push(Felt::new(result));
            // shift a and b so that the next 4-bit limb is in the least significant position
            let a = a >> bit_offset;
            let b = b >> bit_offset;

            // add a new row to the trace table and populate it with binary decomposition of the 4
            // least significant bits of a and b.
            self.add_bitwise_trace_row(BITWISE_AND, a, b);

            // compute bitwise AND of the 4 least significant bits of a and b
            let result_4_bit = (a & b) & 0xf;

            // append the 4 bit result to the result accumulator, and save the current result into
            // the output column in the trace.
            result = (result << 4) | result_4_bit;
            self.trace[OUTPUT_COL_IDX].push(Felt::new(result));
        }

        Ok(Felt::new(result))
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
            // append the previous row's result to the column for previous output values
            self.trace[PREV_OUTPUT_COL_IDX].push(Felt::new(result));
            // shift a and b so that the next 4-bit limb is in the least significant position
            let a = a >> bit_offset;
            let b = b >> bit_offset;

            // add a new row to the trace table and populate it with binary decomposition of the 4
            // least significant bits of a and b.
            self.add_bitwise_trace_row(BITWISE_XOR, a, b);

            // compute bitwise XOR of the 4 least significant bits of a and b
            let result_4_bit = (a ^ b) & 0xf;

            // append the 4 bit result to the result accumulator, and save the current result into
            // the output column in the trace.
            result = (result << 4) | result_4_bit;
            self.trace[OUTPUT_COL_IDX].push(Felt::new(result));
        }

        Ok(Felt::new(result))
    }

    // EXECUTION TRACE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Fills the provided trace fragment with trace data from this bitwise helper instance.
    pub fn fill_trace(self, trace: &mut TraceFragment) {
        // make sure fragment dimensions are consistent with the dimensions of this trace
        debug_assert_eq!(self.trace_len(), trace.len(), "inconsistent trace lengths");
        debug_assert_eq!(TRACE_WIDTH, trace.width(), "inconsistent trace widths");

        // copy trace into the fragment column-by-column
        // TODO: this can be parallelized to copy columns in multiple threads
        for (out_column, column) in trace.columns().zip(self.trace) {
            out_column.copy_from_slice(&column);
        }
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Appends a new row to the trace table and populates the first 14 columns of trace as follows:
    /// - Column 0 is set to the selector value for the bitwise operation being executed.
    /// - Column 1 is set to the current value of `a`.
    /// - Column 2 is set to the current value of `b`.
    /// - Columns 3 to 6 are set to the 4 least-significant bits of `a`.
    /// - Columns 7 to 10 are set to the 4 least-significant bits of `b`.
    /// - Columns 11 and 12 are left for the output value and that of the previous row, which are
    ///   set elsewhere.
    fn add_bitwise_trace_row(&mut self, selector: Felt, a: u64, b: u64) {
        self.trace[0].push(selector);
        self.trace[A_COL_IDX].push(Felt::new(a));
        self.trace[B_COL_IDX].push(Felt::new(b));

        self.trace[A_COL_RANGE.start].push(Felt::new(a & 1));
        self.trace[A_COL_RANGE.start + 1].push(Felt::new((a >> 1) & 1));
        self.trace[A_COL_RANGE.start + 2].push(Felt::new((a >> 2) & 1));
        self.trace[A_COL_RANGE.start + 3].push(Felt::new((a >> 3) & 1));

        self.trace[B_COL_RANGE.start].push(Felt::new(b & 1));
        self.trace[B_COL_RANGE.start + 1].push(Felt::new((b >> 1) & 1));
        self.trace[B_COL_RANGE.start + 2].push(Felt::new((b >> 2) & 1));
        self.trace[B_COL_RANGE.start + 3].push(Felt::new((b >> 3) & 1));
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
