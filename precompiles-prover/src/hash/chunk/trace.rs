//! Trace generation for the chunk chiplet.
//!
//! Callers hold a [`ChunkRequires`] accumulator and submit
//! [`Invocation`]s to it via [`ChunkRequires::require`]. Each call
//! packs the invocation into 32-byte chunks, claims a fresh
//! `chunk_seq_id` range, and delegates to the caller-supplied
//! [`Poseidon2Requires`] for the absorption (P2 itself interns by
//! content digest, so identical chunk content shares one cycle range
//! with `in_mult` tallied — even when the chunk rows themselves are
//! duplicated here).
//!
//! Chunk-side dedup lives at the orchestrator layer above (e.g. the
//! Keccak-node chiplet's `Requires`, keyed on the Keccak digest =
//! `(content, len_bytes)`), not here. Chunk-row Memory64 provides
//! stay at `−act` (mult 1 per active row): each chunk row has
//! exactly one downstream hasher consumer by CR-dedup invariant.
//!
//! [`generate_trace`] takes a `&ChunkRequires` and walks the recorded
//! invocations in allocation order, emitting one row per chunk;
//! trailing rows are inactive (`act = 0`) with `chunk_seq_id` and
//! `perm_seq_id` continuing `+1` to satisfy the relaxed chain on dead
//! rows.

use alloc::vec::Vec;
use core::ops::Range;

use miden_core::{Felt, deferred::Node, field::QuadFelt};
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    hash::chunk::{ChunkAir, NUM_F, NUM_MAIN_COLS},
    logup::build_logup_aux_trace,
    transcript::poseidon2::{
        digest::{P2Cap, P2Digest},
        trace::{PermSpan, Poseidon2Requires},
    },
};

/// One hash invocation: the byte sequence whose chunks this chiplet
/// emits. The chunk chiplet doesn't apply hasher-specific padding —
/// it just tiles the raw input into 32-byte chunks.
#[derive(Debug, Clone)]
pub struct Invocation {
    pub input: Vec<u8>,
}

// REQUIRES ACCUMULATOR
// ================================================================================================

/// What a `ChunkRequires::require` call returns: the content digest
/// and the `(chunk_seq_id, perm_seq_id)` ranges the invocation
/// occupies. The chunk range is what the downstream hasher uses as
/// its chunk-chain head; the perm span holds the P2 cycles the chunk
/// chiplet stamps into `COL_PERM_SEQ_ID`.
#[derive(Debug, Clone)]
pub struct ChunkOutput {
    pub digest: P2Digest,
    /// First chunk row of the invocation's chain (rows are laid
    /// contiguously; the count is the layout's chunk count).
    pub chunk_head: ChunkSeqId,
    pub perm_span: PermSpan,
}

/// Handle to one chunk row — minted only by the chunk accumulator's
/// allocator, so cross-chiplet records reference chunks by handle.
/// Trace cells read the raw sequence number via [`seq`](Self::seq);
/// the sponge's word-address view converts via [`ptr`](Self::ptr).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChunkSeqId(u32);

impl ChunkSeqId {
    /// The raw chunk row number (trace cells, the `ChunkChain` bus).
    pub fn seq(self) -> u32 {
        self.0
    }

    /// The chunk's [`Memory64`](crate::relations::BusId::Memory64) base
    /// word address — a 32-byte chunk spans four u64 words, so
    /// `ptr = 4·seq`. The explicit seam between the chunk-row namespace
    /// and the sponge's word-address space.
    pub fn ptr(self) -> u32 {
        self.0 * 4
    }

    /// Mint a handle from a raw row number, bypassing the accumulator —
    /// for bare-chiplet tests that lay rows with no backing chunk
    /// requires.
    #[cfg(test)]
    pub(crate) fn forged(seq: u32) -> Self {
        Self(seq)
    }
}

#[derive(Debug, Clone)]
struct ChunkRecord {
    f_per_chunk: Vec<[Felt; NUM_F]>,
    chunk_seq_id_range: Range<u32>,
    perm_span: PermSpan,
}

/// Pure-allocator streaming accumulator for chunked invocations. Each
/// [`require`](Self::require) call lays fresh chunk rows and delegates
/// to [`Poseidon2Requires`] for the absorption (which itself interns
/// by content digest). No chunk-level dedup: same byte content with
/// different downstream `len_bytes` collides at the P2 layer but needs
/// its own chunk-row set because each chunk row has exactly one
/// downstream Memory64 consumer (CR-dedup at the orchestrator above is
/// what guarantees that invariant).
#[derive(Debug, Clone, Default)]
pub struct ChunkRequires {
    records: Vec<ChunkRecord>,
    /// Running `chunk_seq_id` allocator = total chunks laid so far.
    next_chunk_seq: u32,
}

impl ChunkRequires {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an invocation; lays a fresh chunk-row span and calls
    /// `p2.require_absorption` to claim its P2 cycle range. Empty input
    /// lays one canonical all-zero chunk (see `Invocation::num_chunks`),
    /// so the span is always non-empty.
    pub fn require(&mut self, inv: &Invocation, p2: &mut Poseidon2Requires) -> ChunkOutput {
        let f_per_chunk = Node::chunks_from_bytes(&inv.input)
            .payload()
            .as_data()
            .expect("chunks_from_bytes creates data payload")
            .to_vec();
        debug_assert!(!f_per_chunk.is_empty(), "chunks_from_bytes guarantees ≥1 chunk",);
        let rate_pairs: Vec<([Felt; 4], [Felt; 4])> = f_per_chunk
            .iter()
            .map(|f| {
                let rate0: [Felt; 4] = f[0..4].try_into().expect("rate0 slice");
                let rate1: [Felt; 4] = f[4..8].try_into().expect("rate1 slice");
                (rate0, rate1)
            })
            .collect();
        let p2_out = p2.require_absorption(P2Cap::chunk(), rate_pairs.iter().copied());
        let n = f_per_chunk.len() as u32;
        let chunk_head = ChunkSeqId(self.next_chunk_seq);
        let chunk_seq_id_range = self.next_chunk_seq..self.next_chunk_seq + n;
        self.next_chunk_seq += n;
        self.records.push(ChunkRecord {
            f_per_chunk,
            chunk_seq_id_range,
            perm_span: p2_out.span,
        });
        ChunkOutput {
            digest: p2_out.digest,
            chunk_head,
            perm_span: p2_out.span,
        }
    }

    /// Total chunk rows laid so far.
    pub fn total_chunks(&self) -> u32 {
        self.next_chunk_seq
    }
}

// TRACE GENERATION
// ================================================================================================

/// Build the chunk chiplet's main trace from the recorded
/// invocations. Walks records in allocation order, stamping each at
/// its `chunk_seq_id_range.start`; trailing rows up to the next power
/// of two are inactive (`act = 0`), with `chunk_seq_id` and
/// `perm_seq_id` continuing `+1` to satisfy the relaxed chain on
/// dead rows. Returns a 12-column trace.
pub fn generate_trace(requires: ChunkRequires) -> RowMajorMatrix<Felt> {
    let total_chunks = requires.total_chunks() as usize;
    let height = total_chunks.next_power_of_two().max(2);

    let mut trace = Vec::with_capacity(height * NUM_MAIN_COLS);

    // Running row index = global chunk_seq_id (records tile it contiguously
    // in allocation order). Where the perm_seq_id chain lands at the end of
    // the active section, so dead rows can continue +1 from there.
    let mut chunk_seq_id = 0u32;
    let mut next_perm_seq_id = 0u32;

    for rec in &requires.records {
        debug_assert_eq!(chunk_seq_id, rec.chunk_seq_id_range.start, "contiguous chunk_seq_id");
        let perm_start = rec.perm_span.head().seq();
        for (c, f) in rec.f_per_chunk.iter().enumerate() {
            // chunk_seq_id, perm_seq_id, act, is_head, f[8].
            trace.extend([
                Felt::new(chunk_seq_id as u64).expect("chunk_seq_id fits"),
                Felt::new((perm_start + c as u32) as u64).expect("perm_seq_id fits"),
                Felt::ONE,
                Felt::from(u8::from(c == 0)),
            ]);
            trace.extend(*f);
            chunk_seq_id += 1;
        }
        next_perm_seq_id = rec.perm_span.tail().seq() + 1;
    }

    // Padding rows: act = 0 (f = is_head = 0), but chunk_seq_id and
    // perm_seq_id continue +1 to satisfy the relaxed chain on dead rows.
    for _ in total_chunks..height {
        trace.extend([
            Felt::new(chunk_seq_id as u64).expect("chunk_seq_id fits"),
            Felt::new(next_perm_seq_id as u64).expect("perm_seq_id fits"),
            Felt::ZERO,
            Felt::ZERO,
        ]);
        trace.extend([Felt::ZERO; NUM_F]);
        chunk_seq_id += 1;
        next_perm_seq_id += 1;
    }

    debug_assert_eq!(trace.len(), height * NUM_MAIN_COLS);
    RowMajorMatrix::new(trace, NUM_MAIN_COLS)
}

// PROVER
// ================================================================================================

/// Build the chunk chiplet's aux trace via the generic
/// [`build_logup_aux_trace`] driver.
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    build_logup_aux_trace(&ChunkAir, main, challenges)
}
