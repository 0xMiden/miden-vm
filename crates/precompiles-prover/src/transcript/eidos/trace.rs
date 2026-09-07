//! Trace generation for the deferred transcript's 32-row Eidos compression chiplet.

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::ops::Range;

use miden_core::{
    Felt, Word,
    deferred::EidosFrame,
    field::{Field, PrimeCharacteristicRing, PrimeField64},
    utils::RowMajorMatrix,
};
use miden_crypto::hash::eidos::Eidos;

use super::compression::{
    layout::{BLOCK_PERIOD as EIDOS_COMPRESSION_CYCLE_LEN, NUM_COLS as NUM_EIDOS_COMPRESSION_COLS},
    trace::{
        ByteLookupRecorder, EidosCompressionByteLookup,
        write_felt_trace_block_into_zeroed_with_lookups,
    },
};
use crate::{
    primitives::byte_pair_lut::{BytePairLutRequires, BytePairOp},
    relations::ProvideMult,
    transcript::eidos::{
        COL_CHAIN_HEAD_ID, COL_IN_MULTIPLICITY, COL_IS_CONTINUATION, COL_OUT_MULTIPLICITY,
        NUM_MAIN_COLS, digest::EidosDigest,
    },
};

#[cfg(test)]
pub(crate) mod testing;

// ABSORPTION OUTPUT
// ================================================================================================

/// Physical Eidos compression-cycle identifier used by the surrounding transcript relations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbsorptionId(u32);

impl AbsorptionId {
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

/// Contiguous physical compression-cycle span occupied by one absorption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbsorptionSpan {
    start: u32,
    len: u32,
}

impl AbsorptionSpan {
    fn new(range: Range<u32>) -> Self {
        Self {
            start: range.start,
            len: range.end - range.start,
        }
    }

    pub fn head(self) -> AbsorptionId {
        AbsorptionId(self.start)
    }

    pub fn tail(self) -> AbsorptionId {
        AbsorptionId(self.start + self.len - 1)
    }
}

#[derive(Debug, Clone)]
pub struct AbsorptionOutput {
    pub digest: EidosDigest,
    pub span: AbsorptionSpan,
}

impl AbsorptionOutput {
    pub fn head(&self) -> AbsorptionId {
        self.span.head()
    }
}

// EIDOS ORACLE
// ================================================================================================

fn block_from_words(block_lo: [Felt; 4], block_hi: [Felt; 4]) -> [Felt; 8] {
    let mut block = [Felt::ZERO; 8];
    block[..4].copy_from_slice(&block_lo);
    block[4..].copy_from_slice(&block_hi);
    block
}

fn absorb_oracle(frame: EidosFrame, blocks: &[([Felt; 4], [Felt; 4])]) -> EidosDigest {
    let mut cv = frame.initial_chaining_word();
    for &(block_lo, block_hi) in blocks {
        cv = Eidos::compress(cv, block_from_words(block_lo, block_hi));
    }
    EidosDigest(cv.into_elements())
}

// REQUIRES ACCUMULATOR
// ================================================================================================

#[derive(Debug, Clone)]
struct RecordedAbsorption {
    frame: EidosFrame,
    blocks: Vec<([Felt; 4], [Felt; 4])>,
    digest: EidosDigest,
    range: Range<u32>,
    in_mult: ProvideMult,
    out_mult: ProvideMult,
}

#[derive(Debug, Clone, Default)]
pub struct EidosRequires {
    absorptions: Vec<RecordedAbsorption>,
    by_digest: BTreeMap<EidosDigest, usize>,
    next_seq: u32,
}

impl EidosRequires {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn digest_of(frame: EidosFrame, blocks: &[([Felt; 4], [Felt; 4])]) -> EidosDigest {
        assert!(!blocks.is_empty(), "absorption needs at least one block");
        absorb_oracle(frame, blocks)
    }

    pub fn require_absorption(
        &mut self,
        frame: EidosFrame,
        blocks: impl IntoIterator<Item = ([Felt; 4], [Felt; 4])>,
    ) -> AbsorptionOutput {
        let blocks: Vec<_> = blocks.into_iter().collect();
        assert!(!blocks.is_empty(), "absorption needs at least one block");
        let digest = absorb_oracle(frame, &blocks);

        if let Some(&idx) = self.by_digest.get(&digest) {
            let rec = &mut self.absorptions[idx];
            debug_assert_eq!(rec.frame, frame, "equal digest must identify the same frame");
            debug_assert_eq!(rec.blocks, blocks, "equal digest must identify the same payload");
            rec.in_mult =
                rec.in_mult.checked_add(1).expect("Eidos input multiplicity must fit in u32");
            return AbsorptionOutput {
                digest,
                span: AbsorptionSpan::new(rec.range.clone()),
            };
        }

        let n = u32::try_from(blocks.len()).expect("absorption block count must fit in u32");
        let next_seq = self.next_seq.checked_add(n).expect("absorption sequence must fit in u32");
        let range = self.next_seq..next_seq;
        self.next_seq = next_seq;
        let idx = self.absorptions.len();
        self.absorptions.push(RecordedAbsorption {
            frame,
            blocks,
            digest,
            range: range.clone(),
            in_mult: 1,
            out_mult: 0,
        });
        self.by_digest.insert(digest, idx);
        AbsorptionOutput { digest, span: AbsorptionSpan::new(range) }
    }

    pub fn require_one_shot(
        &mut self,
        frame: EidosFrame,
        block_lo: [Felt; 4],
        block_hi: [Felt; 4],
    ) -> AbsorptionOutput {
        self.require_absorption(frame, core::iter::once((block_lo, block_hi)))
    }

    pub fn require_digest(&mut self, digest: EidosDigest) -> Option<AbsorptionSpan> {
        let &idx = self.by_digest.get(&digest)?;
        let rec = &mut self.absorptions[idx];
        rec.out_mult =
            rec.out_mult.checked_add(1).expect("Eidos output multiplicity must fit in u32");
        Some(AbsorptionSpan::new(rec.range.clone()))
    }
}

// TRACE GENERATION
// ================================================================================================

#[derive(Debug)]
struct CompressionCycle {
    in_mult: ProvideMult,
    out_mult: ProvideMult,
    is_continuation: bool,
    chain_head_id: u32,
    block: [Felt; 8],
    cv_in: Word,
}

impl CompressionCycle {
    fn append_metadata(&self, row: &mut Vec<Felt>) {
        let start = row.len();
        row.resize(start + (NUM_MAIN_COLS - NUM_EIDOS_COMPRESSION_COLS), Felt::ZERO);
        let meta = &mut row[start..];
        let col = |absolute: usize| absolute - NUM_EIDOS_COMPRESSION_COLS;
        meta[col(COL_IN_MULTIPLICITY)] = Felt::from(self.in_mult);
        meta[col(COL_OUT_MULTIPLICITY)] = Felt::from(self.out_mult);
        meta[col(COL_IS_CONTINUATION)] = Felt::from_u8(self.is_continuation as u8);
        meta[col(COL_CHAIN_HEAD_ID)] = Felt::from(self.chain_head_id);
    }
}

struct EidosCompressionLookupCounter<'a> {
    requires: &'a mut BytePairLutRequires,
}

impl ByteLookupRecorder for EidosCompressionLookupCounter<'_> {
    fn record(&mut self, lookup: EidosCompressionByteLookup, lhs: u8, rhs: u8, result: u32) {
        let expected = match lookup {
            EidosCompressionByteLookup::And8 => {
                self.requires.require(BytePairOp::And, lhs, rhs) as u32
            },
            EidosCompressionByteLookup::Rotation { rotation, byte } => {
                self.requires.require_eidos_rotation(rotation, byte, lhs, rhs)
            },
        };
        debug_assert_eq!(expected, result);
    }
}

fn unpack_felts<const N: usize>(values: &[Felt]) -> [u32; N] {
    assert_eq!(
        2 * values.len(),
        N,
        "packed Felt slice must contain exactly {N} EidosCompression words",
    );

    let mut words = [0; N];
    for (idx, value) in values.iter().enumerate() {
        let packed = value.as_canonical_u64();
        words[2 * idx] = packed as u32;
        words[2 * idx + 1] = (packed >> 32) as u32;
    }
    words
}

fn record_message_range_checks(requires: &mut BytePairLutRequires, block: [u32; 16]) {
    for word in block {
        for limb in [word as u16, (word >> 16) as u16] {
            requires.require_range16(limb);
        }
    }
}

fn build_eidos_compression_trace(
    cycles: &[CompressionCycle],
    byte_pairs: &mut BytePairLutRequires,
) -> RowMajorMatrix<Felt> {
    let real_cycles = cycles.len();
    let height = (real_cycles * EIDOS_COMPRESSION_CYCLE_LEN)
        .next_power_of_two()
        .max(EIDOS_COMPRESSION_CYCLE_LEN);
    let cycle_count = height / EIDOS_COMPRESSION_CYCLE_LEN;
    let mut values = vec![Felt::ZERO; height * NUM_EIDOS_COMPRESSION_COLS];
    let (rows, remainder) = values.as_chunks_mut::<NUM_EIDOS_COMPRESSION_COLS>();
    debug_assert!(remainder.is_empty());
    for (physical_cycle_id, cycle_rows) in
        rows.as_chunks_mut::<EIDOS_COMPRESSION_CYCLE_LEN>().0.iter_mut().enumerate()
    {
        let (block, cv) = if let Some(cycle) = cycles.get(physical_cycle_id) {
            let block = unpack_felts::<16>(&cycle.block);
            let cv = unpack_felts::<8>(cycle.cv_in.as_slice());
            (block, cv)
        } else {
            ([0; 16], [0; 8])
        };

        record_message_range_checks(byte_pairs, block);
        let mut recorder = EidosCompressionLookupCounter { requires: byte_pairs };
        write_felt_trace_block_into_zeroed_with_lookups(
            cycle_rows,
            block,
            cv,
            physical_cycle_id as u64,
            &mut recorder,
        );
    }

    debug_assert_eq!(cycle_count, rows.len() / EIDOS_COMPRESSION_CYCLE_LEN);
    RowMajorMatrix::new(values, NUM_EIDOS_COMPRESSION_COLS)
}

pub(crate) fn generate_trace_with_byte_lookups(
    requires: EidosRequires,
    byte_pairs: &mut BytePairLutRequires,
) -> RowMajorMatrix<Felt> {
    let cycle_count = requires.absorptions.iter().map(|rec| rec.blocks.len()).sum();
    let mut cycles = Vec::with_capacity(cycle_count);

    for rec in &requires.absorptions {
        let mut cv = rec.frame.initial_chaining_word();

        for (idx, &(block_lo, block_hi)) in rec.blocks.iter().enumerate() {
            let block = block_from_words(block_lo, block_hi);
            let cv_out = Eidos::compress(cv, block);
            cycles.push(CompressionCycle {
                in_mult: rec.in_mult,
                out_mult: rec.out_mult,
                is_continuation: idx > 0,
                chain_head_id: rec.range.start,
                block,
                cv_in: cv,
            });
            cv = cv_out;
        }

        debug_assert_eq!(EidosDigest(cv.into_elements()), rec.digest);
    }

    let eidos_compression = build_eidos_compression_trace(&cycles, byte_pairs);
    let height = eidos_compression.values.len() / eidos_compression.width;
    debug_assert_eq!(height % EIDOS_COMPRESSION_CYCLE_LEN, 0);
    debug_assert!(cycles.len() * EIDOS_COMPRESSION_CYCLE_LEN <= height);

    let mut values = Vec::with_capacity(height * NUM_MAIN_COLS);
    for (row_idx, base_row) in
        eidos_compression.values.chunks_exact(eidos_compression.width).enumerate()
    {
        values.extend_from_slice(base_row);
        let cycle_idx = row_idx / EIDOS_COMPRESSION_CYCLE_LEN;
        if let Some(cycle) = cycles.get(cycle_idx) {
            cycle.append_metadata(&mut values);
        } else {
            let start = values.len();
            values.resize(start + (NUM_MAIN_COLS - NUM_EIDOS_COMPRESSION_COLS), Felt::ZERO);
            let physical_cycle_id =
                u32::try_from(cycle_idx).expect("Eidos compression cycle ID must fit in u32");
            values[start + COL_CHAIN_HEAD_ID - NUM_EIDOS_COMPRESSION_COLS] =
                Felt::from(physical_cycle_id);
        }
    }

    RowMajorMatrix::new(values, NUM_MAIN_COLS)
}

const _: () = assert!(EIDOS_COMPRESSION_CYCLE_LEN == 32);
