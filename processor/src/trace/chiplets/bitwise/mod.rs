use alloc::{vec, vec::Vec};
use core::{borrow::BorrowMut, mem::size_of};

use miden_air::{
    AeadStreamCols, BitwiseCols,
    trace::{
        and8_lookup::{
            BYTE_LOOKUP_COUNT_LEN, BYTE_LOOKUP_KIND_AND8, BYTE_PAIR_ROWS, byte_lookup_result,
        },
        chiplets::bitwise::{BITWISE_AND, BITWISE_XOR, OP_CYCLE_LEN, TRACE_WIDTH},
    },
};
use miden_core::{chiplets::blakeg, field::Field};

use crate::{Felt, ONE, ZERO, operation::OperationError, trace::ChipletTraceFragment};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Initial capacity, in ops.
const INIT_OPS_CAPACITY: usize = 128;
const AEAD_STREAM_CYCLE_LEN: usize = 8;
const AEAD_STREAM_WIDTH: usize = size_of::<AeadStreamCols<u8>>();
const STREAM_MODE_OFFSET: usize = AEAD_STREAM_WIDTH;
const AEAD_STREAM_ACTIVE_OFFSET: usize = STREAM_MODE_OFFSET + 1;
pub(crate) const AEAD_STREAM_FRAGMENT_WIDTH: usize = AEAD_STREAM_ACTIVE_OFFSET + 1;

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

#[derive(Debug, Clone, Copy)]
struct AeadStreamOp {
    ctx: Felt,
    clk: Felt,
    src_ptr: Felt,
    dst_ptr: Felt,
    lane_base: Felt,
    plaintext: [Felt; 4],
    keystream: [Felt; 8],
    ciphertext: [Felt; 8],
}

#[derive(Debug, Clone, Copy)]
enum Entry {
    Bitwise(BitwiseOp),
    AeadStream(AeadStreamOp),
}

impl Entry {
    fn row_count(self) -> usize {
        match self {
            Self::Bitwise(_) => OP_CYCLE_LEN,
            Self::AeadStream(_) => AEAD_STREAM_CYCLE_LEN,
        }
    }
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
/// |-----+-----+-----+-------+------+------+------+------+------+------+------+-----+-----|
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
    entries: Vec<Entry>,
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
        self.entries.iter().copied().map(Entry::row_count).sum()
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
        self.entries.push(Entry::Bitwise(BitwiseOp { op, a, b }));
        Ok(Felt::from_u32(op.apply(a, b)))
    }

    /// Records one 8-row AEAD stream entry.
    pub(crate) fn aead_stream(
        &mut self,
        ctx: Felt,
        clk: Felt,
        src_ptr: Felt,
        dst_ptr: Felt,
        lane_base: Felt,
        plaintext: [Felt; 4],
        keystream: [Felt; 8],
        ciphertext: [Felt; 8],
    ) {
        self.entries.push(Entry::AeadStream(AeadStreamOp {
            ctx,
            clk,
            src_ptr,
            dst_ptr,
            lane_base,
            plaintext,
            keystream,
            ciphertext,
        }));
    }

    // EXECUTION TRACE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Fills the provided trace fragment with the row-major trace materialized from the recorded
    /// op log: 8 rows per op, 4-bit limbs accumulated MSB first.
    pub fn fill_trace(self, trace: &mut ChipletTraceFragment) -> Vec<u64> {
        debug_assert_eq!(self.trace_len(), trace.len(), "inconsistent trace lengths");
        debug_assert!(trace.width() >= TRACE_WIDTH, "inconsistent trace widths");
        let has_stream_rows =
            self.entries.iter().any(|entry| matches!(entry, Entry::AeadStream(_)));
        debug_assert!(
            !has_stream_rows || trace.width() >= AEAD_STREAM_FRAGMENT_WIDTH,
            "trace fragment too narrow for AEAD stream rows",
        );

        let row_width = trace.width();
        let mut row_offset = 0;
        let mut and8_counts = vec![0u64; BYTE_LOOKUP_COUNT_LEN];

        for entry in self.entries.iter().copied() {
            let row_count = entry.row_count();
            let mut chunk = vec![ZERO; row_width * row_count];
            match entry {
                Entry::Bitwise(op) => fill_bitwise_chunk(&mut chunk, row_width, op),
                Entry::AeadStream(op) => {
                    fill_aead_stream_chunk(&mut chunk, row_width, op, &mut and8_counts);
                },
            }
            trace.copy_rows_into(row_offset, &chunk);
            row_offset += row_count;
        }

        and8_counts
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

fn fill_bitwise_chunk(chunk: &mut [Felt], row_width: usize, BitwiseOp { op, a, b }: BitwiseOp) {
    debug_assert_eq!(chunk.len(), row_width * OP_CYCLE_LEN);

    let a = a as u64;
    let b = b as u64;
    let selector = op.selector();

    // 8 rows per op, MSB-limb first. Each row contains the cumulative `a`, `b`, and result after
    // appending one more 4-bit limb to the accumulators.
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

        let row = &mut chunk[i * row_width..i * row_width + TRACE_WIDTH];
        let cols: &mut BitwiseCols<Felt> = row.borrow_mut();
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
}

fn fill_aead_stream_chunk(
    chunk: &mut [Felt],
    row_width: usize,
    op: AeadStreamOp,
    and8_counts: &mut [u64],
) {
    debug_assert_eq!(chunk.len(), row_width * AEAD_STREAM_CYCLE_LEN);

    let plaintext = op.plaintext;
    let limbs = plaintext.map(blakeg::unpack);
    let limb_data: [(u32, Felt, Felt); 8] = core::array::from_fn(|idx| {
        let (lo, hi) = limbs[idx / 2];
        let plaintext_limb = if idx % 2 == 0 { lo } else { hi };
        let ks = op.keystream[idx];
        let ciphertext = op.ciphertext[idx];
        debug_assert_eq!(
            Felt::from_u32(plaintext_limb ^ felt_to_u32(ks)),
            ciphertext,
            "AEAD stream ciphertext mismatch at limb {idx}",
        );
        (plaintext_limb, ks, ciphertext)
    });

    let witnesses = limb_data.map(|(plaintext_limb, ks, ciphertext)| {
        limb_xor_witness(plaintext_limb, felt_to_u32(ks), felt_to_u32(ciphertext))
    });
    for witness in witnesses {
        count_and8_witness(and8_counts, witness.bytes);
    }

    for row_idx in 0..AEAD_STREAM_CYCLE_LEN {
        let row = &mut chunk[row_idx * row_width..(row_idx + 1) * row_width];
        row[STREAM_MODE_OFFSET] = ONE;
        row[AEAD_STREAM_ACTIVE_OFFSET] = ONE;
    }

    fill_stream_word_pair(
        &mut chunk[..4 * row_width],
        row_width,
        op,
        plaintext,
        0,
        0,
        [limbs[0], limbs[1]],
        [witnesses[0], witnesses[1], witnesses[2], witnesses[3]],
    );

    fill_stream_word_pair(
        &mut chunk[4 * row_width..8 * row_width],
        row_width,
        op,
        plaintext,
        2,
        4,
        [limbs[2], limbs[3]],
        [witnesses[4], witnesses[5], witnesses[6], witnesses[7]],
    );
}

fn fill_stream_word_pair(
    chunk: &mut [Felt],
    row_width: usize,
    op: AeadStreamOp,
    plaintext: [Felt; 4],
    plaintext_offset: usize,
    lane_offset: usize,
    limbs: [(u32, u32); 2],
    witnesses: [LimbXorWitness; 4],
) {
    let lane_base = op.lane_base + Felt::new_unchecked(lane_offset as u64);
    let dst_ptr = op.dst_ptr + Felt::new_unchecked(lane_offset as u64);

    {
        let row = &mut chunk[0..row_width];
        let cols: &mut AeadStreamCols<Felt> = row[..AEAD_STREAM_WIDTH].borrow_mut();
        let cols = cols.read_mut();
        cols.ctx = op.ctx;
        cols.clk = op.clk;
        cols.src_ptr = op.src_ptr;
        cols.lane_base = lane_base;
        cols.plaintext = plaintext;
        cols.bytes = witnesses[0].bytes;
    }

    {
        let row = &mut chunk[row_width..2 * row_width];
        let cols: &mut AeadStreamCols<Felt> = row[..AEAD_STREAM_WIDTH].borrow_mut();
        let cols = cols.high_first_mut();
        cols.ctx = op.ctx;
        cols.clk = op.clk;
        cols.src_ptr = op.src_ptr;
        cols.lane_base = lane_base;
        cols.next_plaintext = plaintext[plaintext_offset + 1];
        cols.c_prev0 = op.ciphertext[lane_offset];
        cols.hi_quotient = canonical_hi_quotient(limbs[0]);
        cols.bytes = witnesses[1].bytes;
    }

    {
        let row = &mut chunk[2 * row_width..3 * row_width];
        let cols: &mut AeadStreamCols<Felt> = row[..AEAD_STREAM_WIDTH].borrow_mut();
        let cols = cols.low_second_mut();
        cols.ctx = op.ctx;
        cols.clk = op.clk;
        cols.src_ptr = op.src_ptr;
        cols.dst_ptr = dst_ptr;
        cols.lane_base = lane_base;
        cols.active_plaintext = plaintext[plaintext_offset + 1];
        cols.c_prev0 = op.ciphertext[lane_offset];
        cols.c_prev1 = op.ciphertext[lane_offset + 1];
        cols.bytes = witnesses[2].bytes;
    }

    {
        let row = &mut chunk[3 * row_width..4 * row_width];
        let cols: &mut AeadStreamCols<Felt> = row[..AEAD_STREAM_WIDTH].borrow_mut();
        let cols = cols.high_second_mut();
        cols.ctx = op.ctx;
        cols.clk = op.clk;
        cols.dst_ptr = dst_ptr;
        cols.lane_base = lane_base;
        cols.c_prev0 = op.ciphertext[lane_offset];
        cols.c_prev1 = op.ciphertext[lane_offset + 1];
        cols.c_prev2 = op.ciphertext[lane_offset + 2];
        cols.hi_quotient = canonical_hi_quotient(limbs[1]);
        cols.bytes = witnesses[3].bytes;
    }
}

#[derive(Debug, Clone, Copy)]
struct LimbXorWitness {
    bytes: [Felt; 12],
}

fn limb_xor_witness(a: u32, b: u32, c: u32) -> LimbXorWitness {
    debug_assert_eq!(a ^ b, c, "invalid u32 XOR witness");
    let a = a.to_le_bytes();
    let b = b.to_le_bytes();

    LimbXorWitness { bytes: and8_bytes(a, b) }
}

fn and8_bytes(a: [u8; 4], b: [u8; 4]) -> [Felt; 12] {
    [
        Felt::from_u8(a[0]),
        Felt::from_u8(a[1]),
        Felt::from_u8(a[2]),
        Felt::from_u8(a[3]),
        Felt::from_u8(b[0]),
        Felt::from_u8(b[1]),
        Felt::from_u8(b[2]),
        Felt::from_u8(b[3]),
        Felt::from_u8(a[0] & b[0]),
        Felt::from_u8(a[1] & b[1]),
        Felt::from_u8(a[2] & b[2]),
        Felt::from_u8(a[3] & b[3]),
    ]
}

fn count_and8_witness(counts: &mut [u64], bytes: [Felt; 12]) {
    for idx in 0..4 {
        count_and8(
            counts,
            felt_to_u8(bytes[idx]),
            felt_to_u8(bytes[4 + idx]),
            felt_to_u8(bytes[8 + idx]),
        );
    }
}

fn count_and8(counts: &mut [u64], a: u8, b: u8, result: u8) {
    debug_assert_eq!(
        byte_lookup_result(BYTE_LOOKUP_KIND_AND8, a, b),
        result as u32,
        "AEAD stream witness does not match the byte-pair table",
    );
    counts[BYTE_LOOKUP_KIND_AND8 * BYTE_PAIR_ROWS + ((a as usize) << 8) + b as usize] += 1;
}

fn canonical_hi_quotient((lo, hi): (u32, u32)) -> Felt {
    let gap = Felt::from_u32(u32::MAX) - Felt::from_u32(hi);
    Felt::from_u32(lo) * gap.try_inverse().unwrap_or(ZERO)
}

fn felt_to_u32(value: Felt) -> u32 {
    u32::try_from(value.as_canonical_u64()).expect("AEAD stream value is not u32")
}

fn felt_to_u8(value: Felt) -> u8 {
    u8::try_from(value.as_canonical_u64()).expect("AEAD stream byte is not u8")
}
