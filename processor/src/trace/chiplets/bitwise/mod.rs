use alloc::vec::Vec;
use core::borrow::BorrowMut;

use miden_air::{
    BitwiseCols,
    trace::chiplets::bitwise::{BITWISE_AND, BITWISE_XOR, OP_CYCLE_LEN, TRACE_WIDTH},
};

use crate::{Felt, ZERO, operation::OperationError, trace::ChipletTraceFragment};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Initial capacity, in ops.
const INIT_OPS_CAPACITY: usize = 128;

// BITWISE OPERATION
// ================================================================================================

/// Which bitwise operation a row encodes.
#[derive(Debug, Clone, Copy)]
enum Op {
    And,
    Xor,
}

impl Op {
    fn selector(self) -> Felt {
        match self {
            Self::And => BITWISE_AND,
            Self::Xor => BITWISE_XOR,
        }
    }

    fn apply(self, a: u32, b: u32) -> u32 {
        match self {
            Self::And => a & b,
            Self::Xor => a ^ b,
        }
    }
}

/// A single bitwise operation recorded for later trace materialization.
#[derive(Debug, Clone, Copy)]
struct BitwiseOp {
    op: Op,
    a: u32,
    b: u32,
}

// BITWISE
// ================================================================================================

/// Helper for the VM that computes AND and XOR bitwise operations on 32-bit values.
/// It also builds an execution trace of these operations.
///
/// ## Bitwise operation execution trace (AND and XOR)
/// The execution trace for each operation consists of 8 rows and 13 columns. At a high level,
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
    ops: Vec<BitwiseOp>,
}

impl Bitwise {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [Bitwise] initialized with an empty op log.
    pub fn new() -> Self {
        Self {
            ops: Vec::with_capacity(INIT_OPS_CAPACITY),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns length of execution trace required to describe bitwise operations executed on the
    /// VM.
    pub fn trace_len(&self) -> usize {
        self.ops.len() * OP_CYCLE_LEN
    }

    // TRACE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Computes a bitwise AND of `a` and `b` and returns the result. We assume that `a` and `b`
    /// are 32-bit values. If that's not the case, the result of the computation is undefined.
    ///
    /// Records the op for later trace generation in [`Self::fill_trace`].
    pub fn u32and(&mut self, a: Felt, b: Felt) -> Result<Felt, OperationError> {
        self.record(Op::And, a, b)
    }

    /// Computes a bitwise XOR of `a` and `b` and returns the result. We assume that `a` and `b`
    /// are 32-bit values. If that's not the case, the result of the computation is undefined.
    ///
    /// Records the op for later trace generation in [`Self::fill_trace`].
    pub fn u32xor(&mut self, a: Felt, b: Felt) -> Result<Felt, OperationError> {
        self.record(Op::Xor, a, b)
    }

    fn record(&mut self, op: Op, a: Felt, b: Felt) -> Result<Felt, OperationError> {
        let a = assert_u32(a)?;
        let b = assert_u32(b)?;
        self.ops.push(BitwiseOp { op, a, b });
        Ok(Felt::from_u32(op.apply(a, b)))
    }

    // EXECUTION TRACE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Fills the provided trace fragment with the row-major trace materialized from the recorded
    /// op log: 8 rows per op, 4-bit limbs accumulated MSB first.
    pub fn fill_trace(self, trace: &mut ChipletTraceFragment) {
        debug_assert_eq!(self.trace_len(), trace.len(), "inconsistent trace lengths");
        debug_assert_eq!(TRACE_WIDTH, trace.width(), "inconsistent trace widths");

        let mut chunk = [ZERO; TRACE_WIDTH * OP_CYCLE_LEN];

        for (op_idx, &BitwiseOp { op, a, b }) in self.ops.iter().enumerate() {
            let (chunk_rows, _) = chunk.as_mut_slice().as_chunks_mut::<TRACE_WIDTH>();
            let a = a as u64;
            let b = b as u64;
            let selector = op.selector();

            // 8 rows per op, MSB-limb first. Each row contains the cumulative `a`, `b`, and
            // result after appending one more 4-bit limb to the accumulators.
            let mut result: u64 = 0;
            for (i, bit_offset) in (0..32).step_by(4).rev().enumerate() {
                let prev_output = result;
                let a_acc = a >> bit_offset;
                let b_acc = b >> bit_offset;
                let result_4_bit = match op {
                    Op::And => (a_acc & b_acc) & 0xf,
                    Op::Xor => (a_acc ^ b_acc) & 0xf,
                };
                result = (result << 4) | result_4_bit;

                let cols: &mut BitwiseCols<Felt> = chunk_rows[i].as_mut_slice().borrow_mut();
                cols.op_flag = selector;
                cols.a = Felt::new_unchecked(a_acc);
                cols.b = Felt::new_unchecked(b_acc);
                cols.a_bits = [
                    Felt::new_unchecked(a_acc & 1),
                    Felt::new_unchecked((a_acc >> 1) & 1),
                    Felt::new_unchecked((a_acc >> 2) & 1),
                    Felt::new_unchecked((a_acc >> 3) & 1),
                ];
                cols.b_bits = [
                    Felt::new_unchecked(b_acc & 1),
                    Felt::new_unchecked((b_acc >> 1) & 1),
                    Felt::new_unchecked((b_acc >> 2) & 1),
                    Felt::new_unchecked((b_acc >> 3) & 1),
                ];
                cols.prev_output = Felt::new_unchecked(prev_output);
                cols.output = Felt::new_unchecked(result);
            }

            trace.copy_rows_into(op_idx * OP_CYCLE_LEN, &chunk);
        }
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
