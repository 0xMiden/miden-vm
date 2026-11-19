use alloc::vec::Vec;
use core::{borrow::BorrowMut, mem::size_of};

use miden_air_definitions::vm::AeadStreamCols;
use miden_core::{chiplets::eidos_compression, field::Field};

use super::{assert_u32, count_and8};
use crate::{
    Felt, ZERO,
    operation::OperationError,
    trace::{ChipletTraceFragment, trace_state::AeadStreamReplayEntry},
};

pub(super) const TRACE_WIDTH: usize = size_of::<AeadStreamCols<u8>>();
pub(crate) const AEAD_STREAM_CYCLE_LEN: usize = 8;

/// Records AEAD stream entries and writes their eight-row payloads.
#[derive(Debug, Default)]
pub(crate) struct AeadStream {
    entries: Vec<AeadStreamReplayEntry>,
}

impl AeadStream {
    pub(crate) fn trace_len(&self) -> usize {
        self.entries.len() * AEAD_STREAM_CYCLE_LEN
    }

    /// Checks that the keystream and ciphertext lanes are u32 values and that each ciphertext
    /// lane is the plaintext lane XOR its keystream lane.
    pub(crate) fn record(&mut self, entry: AeadStreamReplayEntry) -> Result<(), OperationError> {
        let limbs = entry.plaintext.map(eidos_compression::unpack);
        for (idx, (&ks, &c)) in entry.keystream.iter().zip(&entry.ciphertext).enumerate() {
            let (lo, hi) = limbs[idx / 2];
            let plaintext_limb = if idx % 2 == 0 { lo } else { hi };
            if plaintext_limb ^ assert_u32(ks)? != assert_u32(c)? {
                return Err(OperationError::Internal(
                    "AEAD stream ciphertext does not match plaintext XOR keystream",
                ));
            }
        }

        self.entries.push(entry);
        Ok(())
    }

    pub(crate) fn fill_trace(self, trace: &mut ChipletTraceFragment, and8_counts: &mut [u64]) {
        debug_assert_eq!(self.trace_len(), trace.len(), "inconsistent trace lengths");
        debug_assert_eq!(trace.width(), TRACE_WIDTH, "inconsistent trace widths");

        for (index, entry) in self.entries.iter().enumerate() {
            let mut payload = [ZERO; TRACE_WIDTH * AEAD_STREAM_CYCLE_LEN];
            fill_aead_stream_chunk(&mut payload, entry, and8_counts);
            trace.copy_rows_into(index * AEAD_STREAM_CYCLE_LEN, &payload);
        }
    }
}

fn fill_aead_stream_chunk(
    chunk: &mut [Felt; TRACE_WIDTH * AEAD_STREAM_CYCLE_LEN],
    op: &AeadStreamReplayEntry,
    and8_counts: &mut [u64],
) {
    let limbs = op.plaintext.map(eidos_compression::unpack);
    let witnesses: [[Felt; 12]; 8] = core::array::from_fn(|idx| {
        let (lo, hi) = limbs[idx / 2];
        let plaintext_limb = if idx % 2 == 0 { lo } else { hi };
        let ks = felt_to_u32(op.keystream[idx]);
        let ciphertext = felt_to_u32(op.ciphertext[idx]);
        debug_assert_eq!(
            plaintext_limb ^ ks,
            ciphertext,
            "AEAD stream ciphertext mismatch at limb {idx}",
        );
        limb_xor_witness(plaintext_limb, ks, and8_counts)
    });

    // Each four-row half reads the same plaintext word and handles four consecutive u32 lanes.
    fill_stream_word_pair(
        &mut chunk[..4 * TRACE_WIDTH],
        op,
        0,
        0,
        [limbs[0], limbs[1]],
        &[witnesses[0], witnesses[1], witnesses[2], witnesses[3]],
    );

    fill_stream_word_pair(
        &mut chunk[4 * TRACE_WIDTH..8 * TRACE_WIDTH],
        op,
        2,
        4,
        [limbs[2], limbs[3]],
        &[witnesses[4], witnesses[5], witnesses[6], witnesses[7]],
    );
}

fn fill_stream_word_pair(
    chunk: &mut [Felt],
    op: &AeadStreamReplayEntry,
    plaintext_offset: usize,
    lane_offset: usize,
    limbs: [(u32, u32); 2],
    witnesses: &[[Felt; 12]; 4],
) {
    let lane_base = op.lane_base + Felt::new_unchecked(lane_offset as u64);
    let dst_ptr = op.dst_ptr + Felt::new_unchecked(lane_offset as u64);

    {
        let row = &mut chunk[0..TRACE_WIDTH];
        let cols: &mut AeadStreamCols<Felt> = row.borrow_mut();
        let cols = cols.read_mut();
        cols.ctx = op.ctx;
        cols.clk = op.clk;
        cols.src_ptr = op.src_ptr;
        cols.lane_base = lane_base;
        cols.plaintext = op.plaintext;
        cols.bytes = witnesses[0];
    }

    {
        let row = &mut chunk[TRACE_WIDTH..2 * TRACE_WIDTH];
        let cols: &mut AeadStreamCols<Felt> = row.borrow_mut();
        let cols = cols.high_first_mut();
        cols.ctx = op.ctx;
        cols.clk = op.clk;
        cols.src_ptr = op.src_ptr;
        cols.lane_base = lane_base;
        cols.next_plaintext = op.plaintext[plaintext_offset + 1];
        cols.c_prev0 = op.ciphertext[lane_offset];
        cols.hi_quotient = canonical_hi_quotient(limbs[0]);
        cols.bytes = witnesses[1];
    }

    {
        let row = &mut chunk[2 * TRACE_WIDTH..3 * TRACE_WIDTH];
        let cols: &mut AeadStreamCols<Felt> = row.borrow_mut();
        let cols = cols.low_second_mut();
        cols.ctx = op.ctx;
        cols.clk = op.clk;
        cols.src_ptr = op.src_ptr;
        cols.dst_ptr = dst_ptr;
        cols.lane_base = lane_base;
        cols.active_plaintext = op.plaintext[plaintext_offset + 1];
        cols.c_prev0 = op.ciphertext[lane_offset];
        cols.c_prev1 = op.ciphertext[lane_offset + 1];
        cols.bytes = witnesses[2];
    }

    {
        let row = &mut chunk[3 * TRACE_WIDTH..4 * TRACE_WIDTH];
        let cols: &mut AeadStreamCols<Felt> = row.borrow_mut();
        let cols = cols.high_second_mut();
        cols.ctx = op.ctx;
        cols.clk = op.clk;
        cols.dst_ptr = dst_ptr;
        cols.lane_base = lane_base;
        cols.c_prev0 = op.ciphertext[lane_offset];
        cols.c_prev1 = op.ciphertext[lane_offset + 1];
        cols.c_prev2 = op.ciphertext[lane_offset + 2];
        cols.hi_quotient = canonical_hi_quotient(limbs[1]);
        cols.bytes = witnesses[3];
    }
}

fn limb_xor_witness(a: u32, b: u32, and8_counts: &mut [u64]) -> [Felt; 12] {
    let a = a.to_le_bytes();
    let b = b.to_le_bytes();
    let and: [Felt; 4] = core::array::from_fn(|idx| {
        let result = a[idx] & b[idx];
        count_and8(and8_counts, a[idx], b[idx]);
        Felt::from_u8(result)
    });

    [
        Felt::from_u8(a[0]),
        Felt::from_u8(a[1]),
        Felt::from_u8(a[2]),
        Felt::from_u8(a[3]),
        Felt::from_u8(b[0]),
        Felt::from_u8(b[1]),
        Felt::from_u8(b[2]),
        Felt::from_u8(b[3]),
        and[0],
        and[1],
        and[2],
        and[3],
    ]
}

fn canonical_hi_quotient((lo, hi): (u32, u32)) -> Felt {
    let gap = Felt::from_u32(u32::MAX) - Felt::from_u32(hi);
    Felt::from_u32(lo) * gap.try_inverse().unwrap_or(ZERO)
}

fn felt_to_u32(value: Felt) -> u32 {
    u32::try_from(value.as_canonical_u64()).expect("AEAD stream value is not u32")
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use core::borrow::Borrow;

    use miden_air_definitions::vm::trace::and8_lookup::BYTE_LOOKUP_COUNT_LEN;

    use super::*;

    #[test]
    fn aead_stream_trace() {
        let plaintext_limbs = [1_u32, 2, 3, 4, 5, 6, 7, 8];
        let plaintext = core::array::from_fn(|idx| {
            eidos_compression::pack(plaintext_limbs[2 * idx], plaintext_limbs[2 * idx + 1])
        });
        let keystream = core::array::from_fn(|idx| Felt::from_u32(20 + idx as u32));
        let ciphertext = core::array::from_fn(|idx| {
            Felt::from_u32(plaintext_limbs[idx] ^ keystream[idx].as_canonical_u64() as u32)
        });

        let ctx = Felt::from_u32(3);
        let clk = Felt::from_u32(11);
        let src_ptr = Felt::from_u32(100);
        let dst_ptr = Felt::from_u32(200);
        let lane_base = Felt::from_u32(40);
        let mut stream = AeadStream::default();
        stream
            .record(AeadStreamReplayEntry {
                ctx,
                clk,
                src_ptr,
                dst_ptr,
                lane_base,
                plaintext,
                keystream,
                ciphertext,
            })
            .expect("consistent AEAD stream entry");
        assert_eq!(stream.trace_len(), AEAD_STREAM_CYCLE_LEN);

        let mut band = [ZERO; TRACE_WIDTH * AEAD_STREAM_CYCLE_LEN];
        let mut trace = ChipletTraceFragment::row_major(&mut band, TRACE_WIDTH);
        let mut and8_counts = vec![0; BYTE_LOOKUP_COUNT_LEN];
        stream.fill_trace(&mut trace, &mut and8_counts);
        assert_eq!(and8_counts.iter().sum::<u64>(), 32);

        // Row 0 reads the plaintext word and proves the first low limb.
        let cols: &AeadStreamCols<Felt> = band[..TRACE_WIDTH].borrow();
        let read = cols.read();
        assert_eq!(read.ctx, ctx);
        assert_eq!(read.clk, clk);
        assert_eq!(read.src_ptr, src_ptr);
        assert_eq!(read.lane_base, lane_base);
        assert_eq!(read.plaintext, plaintext);
        assert_eq!(read.bytes[0], Felt::from_u8(plaintext_limbs[0] as u8));
        assert_eq!(read.bytes[4], keystream[0]);
        assert_eq!(
            read.bytes[8],
            Felt::from_u8((plaintext_limbs[0] as u8) & (keystream[0].as_canonical_u64() as u8)),
        );

        // Row 1 carries ciphertext limb 0 and plaintext[1].
        let cols: &AeadStreamCols<Felt> = band[TRACE_WIDTH..2 * TRACE_WIDTH].borrow();
        assert_eq!(cols.high_first().next_plaintext, plaintext[1]);
        assert_eq!(cols.high_first().c_prev0, ciphertext[0]);

        // Row 4 starts the second word pair at lane_base + 4.
        let cols: &AeadStreamCols<Felt> = band[4 * TRACE_WIDTH..5 * TRACE_WIDTH].borrow();
        assert_eq!(cols.read().lane_base, lane_base + Felt::from_u32(4));
        assert_eq!(cols.read().plaintext, plaintext);
    }
}
