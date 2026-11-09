use alloc::vec::Vec;
use core::borrow::BorrowMut;

use miden_air_definitions::vm::{
    BitwiseOpCols,
    trace::chiplets::bitwise::{BITWISE_AND, BITWISE_XOR, OP_CYCLE_LEN, TRACE_WIDTH},
};

use super::{assert_u32, count_and8};
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
/// Each operation uses one row. The row stores the operation flag, little-endian bytes of both
/// inputs, and bytewise `a & b` witnesses. Four AND8 lookups prove the byte witnesses. The
/// response bus reconstructs the VM-facing values and derives XOR as `a + b - 2*(a & b)`.
///
/// The layout of the table is illustrated below.
///
///    s     a0    a1    a2    a3    b0    b1    b2    b3    c0    c1    c2    c3
/// |-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----|
///
/// In the above, the meaning of the columns is as follows:
/// - `s` selects the bitwise operator: 0 = AND, 1 = XOR.
/// - `a*` and `b*` are little-endian input bytes.
/// - `c*` are bytewise `a & b` witnesses.
#[derive(Debug)]
pub struct Bitwise {
    entries: Vec<BitwiseOp>,
}

impl Bitwise {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [Bitwise] initialized with an empty op log.
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(INIT_OPS_CAPACITY),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns length of execution trace required to describe bitwise operations executed on the
    /// VM.
    pub fn trace_len(&self) -> usize {
        self.entries.len() * OP_CYCLE_LEN
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
        self.entries.push(BitwiseOp { op, a, b });
        Ok(Felt::from_u32(op.apply(a, b)))
    }

    /// Writes one payload row per operation and accumulates its AND8 lookup counts.
    pub fn fill_trace(self, trace: &mut ChipletTraceFragment, and8_counts: &mut [u64]) {
        debug_assert_eq!(self.trace_len(), trace.len(), "inconsistent trace lengths");
        debug_assert_eq!(trace.width(), TRACE_WIDTH, "inconsistent trace widths");

        for (row, BitwiseOp { op, a, b }) in self.entries.into_iter().enumerate() {
            let a_bytes = a.to_le_bytes();
            let b_bytes = b.to_le_bytes();

            let mut payload = [ZERO; TRACE_WIDTH];
            let cols: &mut BitwiseOpCols<Felt> = payload.as_mut_slice().borrow_mut();
            cols.op_flag = op.selector();
            cols.a_bytes = a_bytes.map(Felt::from_u8);
            cols.b_bytes = b_bytes.map(Felt::from_u8);
            cols.and_bytes = core::array::from_fn(|idx| {
                let and = a_bytes[idx] & b_bytes[idx];
                count_and8(and8_counts, a_bytes[idx], b_bytes[idx]);
                Felt::from_u8(and)
            });
            trace.copy_rows_into(row, &payload);
        }
    }
}

impl Default for Bitwise {
    fn default() -> Self {
        Self::new()
    }
}
