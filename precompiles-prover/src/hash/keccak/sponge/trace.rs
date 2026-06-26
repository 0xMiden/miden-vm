//! Trace generation for the Keccak sponge chiplet.
//!
//! Callers hold a [`SpongeRequires`] accumulator and submit
//! [`Invocation`]s to it via [`SpongeRequires::require`]. Each call
//! delegates to the caller-supplied [`ChunkRequires`] (which lays the
//! invocation's chunk-tape segment via [`Poseidon2Requires`]), runs
//! the Keccak-f permutations as a trace-gen oracle, allocates a
//! fresh `sponge_seq_id` range, and returns a [`SpongeOutput`]
//! (Keccak digest + chunk-content P2 digest + range stamps).
//!
//! No dedup at this layer — sponge is a pure allocator. The Keccak-
//! node chiplet above dedupes by Keccak digest (`(content,
//! len_bytes)` identity); below this layer, chunks duplicate per
//! invocation (CR-dedup invariant).
//!
//! [`generate_trace`] takes a `&SpongeRequires` and walks records in
//! allocation order, stamping the 27-column trace; trailing rows up
//! to the next power of two are inactive (`act = 0`).

use miden_core::{Felt, field::QuadFelt};
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    hash::{
        chunk::trace::{ChunkRequires, ChunkSeqId, Invocation as ChunkInvocation},
        keccak::{
            digest::KeccakDigest,
            reference::{KECCAK_RC, keccak_f1600, keccak_round},
            round::{NUM_ROUNDS, RoundRequires},
            sponge::{
                COL_ACT, COL_B_BEGIN, COL_BYTES_LEFT, COL_CHUNK_LO, COL_CHUNK_PTR, COL_CLEARED_LO,
                COL_IS_CHUNK_AVAIL, COL_IS_FIRST_BLOCK_OF_INVOCATION, COL_IS_ZERO, COL_PADDED_LO,
                COL_SPONGE_SEQ_ID, COL_STATE_NEW_LO, COL_STATE_OUT_LO, COL_STATE_PREV_LO,
                KeccakSpongeAir, NUM_MAIN_COLS, SPONGE_PERIOD,
                program::{EXTRA_BLOCK_BEGIN, NOP_SLACK_BEGIN},
            },
        },
    },
    logup::build_logup_aux_trace,
    primitives::{
        bitwise64::{Bitwise64Requires, Logic64Op},
        byte_pair_lut::BytePairLutRequires,
    },
    transcript::poseidon2::{
        digest::P2Digest,
        trace::{PermSpan, Poseidon2Requires},
    },
    utils::split_u64,
};

/// Keccak rate (bytes per absorption block).
const RATE_BYTES: usize = 136;
/// Keccak rate in 64-bit lanes.
const RATE_LANES: usize = 17;
/// Chunk granularity in bytes (one Poseidon-transcript chunk = 256 bits).
const CHUNK_BYTES: usize = 32;
/// Chunk granularity in lanes.
const CHUNK_LANES: usize = CHUNK_BYTES / 8;
/// Lane index where the trailing `0x80` pad byte lives.
const LANE_16: usize = 16;
/// Trailing-`0x80` constant for the lane-16 mixin: `0x80` placed at
/// byte 7 of lane 16, i.e. the high byte.
const PAD_CONST: u64 = 0x8000_0000_0000_0000;

/// One Keccak invocation: the byte sequence to hash. FIPS 202
/// pad10*1 is applied internally during trace generation; the
/// caller just supplies the raw message bytes.
#[derive(Debug, Clone)]
pub struct Invocation {
    pub input: Vec<u8>,
}

impl Invocation {
    /// Number of absorption blocks (periods) this invocation occupies.
    /// Each block is one Keccak permutation = one `SPONGE_PERIOD`-row
    /// period in the sponge trace.
    pub fn num_blocks(&self) -> usize {
        (self.input.len() + RATE_BYTES) / RATE_BYTES
    }

    /// Total chunk lanes the chunk chiplet emits for this invocation,
    /// padded up to 32-byte chunk granularity. Empty input still emits
    /// one canonical zero chunk (4 lanes): the block loop consumes it as
    /// a full garbage-tail since the pad fires at byte 0, so none of it
    /// is absorbed. See `ChunkInvocation::num_chunks`.
    pub fn chunk_lanes(&self) -> usize {
        // max(1, ceil(input.len() / 32)) chunks · 4 lanes each.
        self.input.len().div_ceil(CHUNK_BYTES).max(1) * CHUNK_LANES
    }
}

/// Per-invocation derived layout — `num_blocks` and the last-block
/// pad position. Computed once and threaded through both the
/// permutation oracle and the row-filling loop.
#[derive(Debug, Clone)]
struct InvocationLayout {
    num_blocks: usize,
    /// Slot within the last block where the pad row fires.
    pad_lane_idx: usize,
    /// Byte offset within the pad lane for the leading `0x01`.
    byte_offset: usize,
    /// Total chunk-tape lanes this invocation's segment occupies.
    chunk_lanes: usize,
}

impl InvocationLayout {
    fn of(inv: &Invocation) -> Self {
        let num_blocks = inv.num_blocks();
        let bytes_in_last_block = inv.input.len() - RATE_BYTES * (num_blocks - 1);
        Self {
            num_blocks,
            pad_lane_idx: bytes_in_last_block / 8,
            byte_offset: bytes_in_last_block % 8,
            chunk_lanes: inv.chunk_lanes(),
        }
    }
}

// REQUIRES ACCUMULATOR
// ================================================================================================

/// Handle to one sponge row — minted only by the sponge accumulator's
/// allocator. Trace cells read the raw sequence number via
/// [`seq`](Self::seq).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpongeSeqId(u32);

impl SpongeSeqId {
    /// The raw sponge row number (trace cells, the `KeccakSponge` bus).
    pub fn seq(self) -> u32 {
        self.0
    }

    /// Mint a handle from a raw row number, bypassing the accumulator —
    /// for bare-chiplet tests that lay rows with no backing sponge
    /// requires.
    #[cfg(test)]
    pub(crate) fn forged(seq: u32) -> Self {
        Self(seq)
    }
}

/// What a `SpongeRequires::require` call returns: the Keccak digest
/// of this invocation, the chunk-content P2 digest, the chunk-content
/// P2 absorption span (so the Keccak-node layer can read OutRate0 at
/// its tail), the invocation's sponge-row head, and its chunk-chain
/// head. Empty input still lays one canonical zero chunk, so the span
/// is non-empty and `chunk_content_digest` binds that chunk's P2
/// digest.
#[derive(Debug, Clone)]
pub struct SpongeOutput {
    pub keccak_digest: KeccakDigest,
    pub chunk_content_digest: P2Digest,
    pub chunk_content_perm_span: PermSpan,
    pub sponge_head: SpongeSeqId,
    pub chunk_head: ChunkSeqId,
}

#[derive(Debug, Clone)]
struct BlockSnapshot {
    state_at_block_start: [u64; 25],
    post_xorin: [u64; 25],
    perm_out: [u64; 25],
}

#[derive(Debug, Clone)]
struct SpongeRecord {
    input: Vec<u8>,
    layout: InvocationLayout,
    chunk_head: ChunkSeqId,
    sponge_head: SpongeSeqId,
    blocks: Vec<BlockSnapshot>,
}

/// Pure-allocator streaming accumulator for Keccak sponge
/// invocations. Each [`require`](Self::require) call delegates to the
/// caller-supplied [`ChunkRequires`] to lay the chunk-tape segment,
/// runs the Keccak-f permutations as a trace-gen oracle, allocates a
/// fresh `sponge_seq_id` range, and records the per-block snapshots
/// [`generate_trace`] later replays.
///
/// No dedup at this layer — the Keccak-node chiplet above owns the
/// dedup point.
#[derive(Debug, Clone, Default)]
pub struct SpongeRequires {
    invocations: Vec<SpongeRecord>,
    /// Running `sponge_seq_id` allocator = total sponge rows laid so
    /// far (= `Σ num_blocks · SPONGE_PERIOD` across records).
    next_sponge_seq: u32,
}

impl SpongeRequires {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a Keccak invocation. Empty input is supported: it lays
    /// one pad block (`keccak256("")`) and one canonical zero chunk,
    /// consumed by the block loop as a full garbage-tail (the pad fires
    /// at byte 0), so the digest is unperturbed while `H_input_chunks`
    /// still binds a real P2 chain tail.
    ///
    /// Drives the supplied `round_req` for the 24 rounds of each
    /// block's Keccak permutation, and `bw64_req` / `bpl_req` for
    /// the per-row Logic64 messages on rate-XORin / pad / lane-16
    /// 0x80 rows (matching what the sponge AIR consumes).
    pub fn require(
        &mut self,
        inv: &Invocation,
        chunk_req: &mut ChunkRequires,
        round_req: &mut RoundRequires,
        bw64_req: &mut Bitwise64Requires,
        bpl_req: &mut BytePairLutRequires,
        p2: &mut Poseidon2Requires,
    ) -> SpongeOutput {
        // Always lay a chunk segment. Empty input yields one canonical
        // zero chunk (see `ChunkInvocation::num_chunks`), which the block
        // loop below consumes as a full garbage-tail (pad at byte 0), so
        // the keccak digest is `keccak256("")` while `H_input_chunks`
        // still binds a real P2 chain tail.
        let chunk_out = chunk_req.require(&ChunkInvocation { input: inv.input.clone() }, p2);
        let (chunk_head, chunk_content_digest, chunk_content_perm_span) =
            (chunk_out.chunk_head, chunk_out.digest, chunk_out.perm_span);

        let layout = InvocationLayout::of(inv);
        let blocks = compute_block_snapshots_driving(inv, &layout, round_req, bw64_req, bpl_req);
        let keccak_digest =
            KeccakDigest::from_state(&blocks.last().expect("≥1 block per invocation").perm_out);

        let sponge_head = SpongeSeqId(self.next_sponge_seq);
        self.next_sponge_seq += (layout.num_blocks * SPONGE_PERIOD) as u32;

        self.invocations.push(SpongeRecord {
            input: inv.input.clone(),
            layout,
            chunk_head,
            sponge_head,
            blocks,
        });

        SpongeOutput {
            keccak_digest,
            chunk_content_digest,
            chunk_content_perm_span,
            sponge_head,
            chunk_head,
        }
    }

    /// Total sponge rows laid (= `Σ num_blocks · SPONGE_PERIOD`).
    pub fn total_active_rows(&self) -> u32 {
        self.next_sponge_seq
    }
}

/// Compute the Keccak digest of `input` without recording anything —
/// a thin wrapper around the FIPS 202 multi-rate-10*1 pad + Keccak-f
/// sponge construction. Used by [`KeccakNodeRequires`] to pre-check
/// dedup before calling [`SpongeRequires::require`] (which would
/// otherwise lay sponge rows that the node-layer dedup hit then
/// discards).
pub fn keccak_oracle(input: &[u8]) -> KeccakDigest {
    let inv = Invocation { input: input.to_vec() };
    let layout = InvocationLayout::of(&inv);
    let blocks = compute_block_snapshots(&inv, &layout);
    KeccakDigest::from_state(
        &blocks.last().expect("compute_block_snapshots yields ≥1 block").perm_out,
    )
}

/// Same as [`compute_block_snapshots`] but also drives the supplied
/// `round_req` (24 `require_round` calls per block, threading state
/// through `keccak_round` + `KECCAK_RC`) and `bw64_req` / `bpl_req`
/// for the per-row Logic64 emissions the sponge AIR consumes:
/// rate-XORin (verbatim Xor or 3-message pad-row AndNot/Xor/Xor) and
/// the lane-16 0x80 Xor on last blocks.
fn compute_block_snapshots_driving(
    inv: &Invocation,
    layout: &InvocationLayout,
    round_req: &mut RoundRequires,
    bw64_req: &mut Bitwise64Requires,
    bpl_req: &mut BytePairLutRequires,
) -> Vec<BlockSnapshot> {
    let mut state = [0u64; 25];
    let mut tape = pack_chunk_tape(inv);

    (0..layout.num_blocks)
        .map(|block_n| {
            let is_last_block = block_n + 1 == layout.num_blocks;
            let state_at_block_start = state;

            for (k, lane) in state.iter_mut().enumerate().take(RATE_LANES) {
                let chunk_lane = tape.next().unwrap_or(0);
                let is_verbatim = !is_last_block || k < layout.pad_lane_idx;
                let is_pad_row = is_last_block && k == layout.pad_lane_idx;
                if is_verbatim {
                    bw64_req.require(bpl_req, Logic64Op::Xor, *lane, chunk_lane);
                    *lane ^= chunk_lane;
                } else if is_pad_row {
                    let andnot_mask_val = andnot_mask(layout.byte_offset);
                    let padding_mask_val = padding_mask(layout.byte_offset);
                    let cleared =
                        bw64_req.require(bpl_req, Logic64Op::AndNot, andnot_mask_val, chunk_lane);
                    let padded =
                        bw64_req.require(bpl_req, Logic64Op::Xor, cleared, padding_mask_val);
                    let state_new = bw64_req.require(bpl_req, Logic64Op::Xor, *lane, padded);
                    *lane = state_new;
                }
                // past-pad: no XOR, no Logic64 emission.
            }

            let post_xorin = state;
            if is_last_block {
                bw64_req.require(bpl_req, Logic64Op::Xor, state[LANE_16], PAD_CONST);
                state[LANE_16] ^= PAD_CONST;
            }

            // 24 round submissions per block, evolving state via the
            // reference round function so the chunk-content P2 layer
            // sees identical state_ins to what round.generate_trace
            // will replay.
            for r in 0..NUM_ROUNDS {
                round_req.require_round(state);
                keccak_round(&mut state, KECCAK_RC[r]);
            }
            let perm_out = state;

            BlockSnapshot {
                state_at_block_start,
                post_xorin,
                perm_out,
            }
        })
        .collect()
}

/// Materialise the per-block state snapshots (state-at-start /
/// post-rate-XORin / post-permutation). Used by
/// [`keccak_oracle`] (digest-only pre-check); the
/// [`SpongeRequires::require`] path uses
/// [`compute_block_snapshots_driving`] instead so it can drive the
/// round / bw64 / bpl ledgers alongside.
fn compute_block_snapshots(inv: &Invocation, layout: &InvocationLayout) -> Vec<BlockSnapshot> {
    let mut state = [0u64; 25];
    let mut tape = pack_chunk_tape(inv);

    (0..layout.num_blocks)
        .map(|block_n| {
            let is_last_block = block_n + 1 == layout.num_blocks;
            let state_at_block_start = state;

            for (k, lane) in state.iter_mut().enumerate().take(RATE_LANES) {
                let chunk_lane = tape.next().unwrap_or(0);
                let is_verbatim = !is_last_block || k < layout.pad_lane_idx;
                let is_pad_row = is_last_block && k == layout.pad_lane_idx;
                if is_verbatim {
                    *lane ^= chunk_lane;
                } else if is_pad_row {
                    let cleared = !andnot_mask(layout.byte_offset) & chunk_lane;
                    let padded = cleared ^ padding_mask(layout.byte_offset);
                    *lane ^= padded;
                }
            }

            let post_xorin = state;
            if is_last_block {
                state[LANE_16] ^= PAD_CONST;
            }
            let perm_out = keccak_f1600(state);
            state = perm_out;
            BlockSnapshot {
                state_at_block_start,
                post_xorin,
                perm_out,
            }
        })
        .collect()
}

// TRACE GENERATION
// ================================================================================================

/// Build the sponge chiplet's main trace from the recorded
/// invocations. Walks records in allocation order, stamping
/// `SPONGE_PERIOD` rows per block; trailing rows up to the next power
/// of two are inactive (`act = 0`). Returns a 27-column trace.
pub fn generate_trace(requires: SpongeRequires) -> RowMajorMatrix<Felt> {
    let active_rows = requires.total_active_rows() as usize;
    let height = active_rows.next_power_of_two().max(SPONGE_PERIOD);

    let mut trace = Vec::with_capacity(height * NUM_MAIN_COLS);

    // Period-absolute state, updated across the whole trace.
    // `bytes_left` is tracked as a `Felt` to keep the chain in
    // field arithmetic — it goes negative past the last input byte
    // and ≡ −136·M mod p over the cyclic wrap.
    let mut row = 0usize;
    let mut chunk_ptr: u64 = 0;
    let mut bytes_left = Felt::ZERO;
    let eight = Felt::from(8u8);

    for record in &requires.invocations {
        // At each invocation seam, the chain's non-absorb gate goes
        // vacuous (`p_last · is_first_block' = 1`), so `bytes_left`
        // and `chunk_ptr` are free to jump.
        bytes_left = Felt::new(record.input.len() as u64).expect("input.len() < p");
        chunk_ptr = record.chunk_head.ptr() as u64;

        let layout = &record.layout;
        let mut tape = pack_chunk_tape_from_bytes(&record.input, layout.chunk_lanes);
        let mut chunks_consumed_in_inv = 0usize;

        for (block_n, block) in record.blocks.iter().enumerate() {
            let is_last_block = block_n + 1 == layout.num_blocks;
            let chunks_in_block = if is_last_block {
                layout.chunk_lanes - chunks_consumed_in_inv
            } else {
                RATE_LANES
            };
            let rate_avail = chunks_in_block.min(RATE_LANES);
            let overshoot = chunks_in_block - rate_avail;

            for slot in 0..SPONGE_PERIOD {
                // Scattered row: per-lane lo/hi pairs land at non-adjacent
                // columns by branch (see `fill_state_lane_row`), so fill a
                // stack scratch by `COL_*` index, then extend.
                let mut r = [Felt::ZERO; NUM_MAIN_COLS];

                r[COL_SPONGE_SEQ_ID] = Felt::new(row as u64).expect("row index fits");
                r[COL_ACT] = Felt::ONE;
                r[COL_BYTES_LEFT] = bytes_left;
                r[COL_IS_FIRST_BLOCK_OF_INVOCATION] =
                    if block_n == 0 { Felt::ONE } else { Felt::ZERO };
                r[COL_CHUNK_PTR] = Felt::new(chunk_ptr).expect("chunk_ptr fits");

                let is_rate_slot = slot < RATE_LANES;
                let is_zero = is_last_block && slot > layout.pad_lane_idx;
                r[COL_IS_ZERO] = Felt::from(is_zero as u8);
                let is_extra_slot = (EXTRA_BLOCK_BEGIN..NOP_SLACK_BEGIN).contains(&slot);
                let consume = (is_rate_slot && slot < rate_avail)
                    || (is_extra_slot && slot - EXTRA_BLOCK_BEGIN < overshoot);
                let avail_end = if overshoot > 0 {
                    EXTRA_BLOCK_BEGIN + overshoot
                } else {
                    rate_avail
                };
                r[COL_IS_CHUNK_AVAIL] = Felt::from((slot < avail_end) as u8);
                if is_last_block {
                    r[COL_B_BEGIN + layout.byte_offset] = Felt::ONE;
                }

                let chunk_lane = if consume { tape.next().unwrap_or(0) } else { 0 };
                write_u64(&mut r, COL_CHUNK_LO, chunk_lane);

                fill_state_lane_row(
                    &mut r,
                    slot,
                    is_last_block,
                    layout,
                    chunk_lane,
                    &block.state_at_block_start,
                    &block.post_xorin,
                    &block.perm_out,
                );

                trace.extend(r);

                if consume {
                    chunk_ptr += 1;
                    chunks_consumed_in_inv += 1;
                }
                if is_rate_slot {
                    bytes_left -= eight;
                }
                row += 1;
            }
        }

        // Sanity: the sponge_seq_id we just stamped past should match
        // the record's allocated range end.
        debug_assert_eq!(
            row,
            (record.sponge_head.seq() + (layout.num_blocks * SPONGE_PERIOD) as u32) as usize
        );
    }

    // Trailing inactive rows: act = 0; bytes_left chain still decrements
    // per rate slot to close the cyclic wrap, chunk_ptr holds steady.
    while row < height {
        let mut r = [Felt::ZERO; NUM_MAIN_COLS];
        r[COL_SPONGE_SEQ_ID] = Felt::new(row as u64).expect("row index fits");
        r[COL_BYTES_LEFT] = bytes_left;
        r[COL_CHUNK_PTR] = Felt::new(chunk_ptr).expect("chunk_ptr fits");
        trace.extend(r);
        if row % SPONGE_PERIOD < RATE_LANES {
            bytes_left -= eight;
        }
        row += 1;
    }

    debug_assert_eq!(trace.len(), height * NUM_MAIN_COLS);
    RowMajorMatrix::new(trace, NUM_MAIN_COLS)
}

/// Pack `inv.input` into 64-bit LE lanes, zero-padded up to the
/// invocation's chunk-aligned lane count. Returned as an iterator so
/// callers can consume lanes one at a time without materializing a
/// `Vec<u64>` for the segment.
fn pack_chunk_tape(inv: &Invocation) -> impl Iterator<Item = u64> + '_ {
    pack_chunk_tape_from_bytes(&inv.input, inv.chunk_lanes())
}

/// Same as [`pack_chunk_tape`] but driven by an explicit byte slice +
/// lane count — used by [`generate_trace`] which holds the bytes in
/// each [`SpongeRecord`] but rebuilds the iterator per record.
fn pack_chunk_tape_from_bytes(input: &[u8], chunk_lanes: usize) -> impl Iterator<Item = u64> + '_ {
    input
        .chunks(8)
        .map(|c| {
            let mut buf = [0u8; 8];
            buf[..c.len()].copy_from_slice(c);
            u64::from_le_bytes(buf)
        })
        .chain(core::iter::repeat(0u64))
        .take(chunk_lanes)
}

/// Fill the state-lane and per-row intermediate columns for one row,
/// writing into the row's column slice directly.
#[allow(clippy::too_many_arguments)]
fn fill_state_lane_row(
    r: &mut [Felt],
    slot: usize,
    is_last_block: bool,
    layout: &InvocationLayout,
    chunk_lane: u64,
    state_at_block_start: &[u64; 25],
    post_xorin_this_block: &[u64; 25],
    perm_out_last_block: &[u64; 25],
) {
    let is_rate_slot = slot < RATE_LANES;
    let is_capacity_slot = (RATE_LANES..RATE_LANES + 8).contains(&slot);
    let is_lane16_0x80 = slot == 25;

    if is_rate_slot {
        let state_prev = state_at_block_start[slot];
        write_u64(r, COL_STATE_PREV_LO, state_prev);
        let (state_new, cleared, padded) = if is_last_block && slot == layout.pad_lane_idx {
            // Pad row.
            let cleared = !andnot_mask(layout.byte_offset) & chunk_lane;
            let padded = cleared ^ padding_mask(layout.byte_offset);
            (state_prev ^ padded, cleared, padded)
        } else if is_last_block && slot > layout.pad_lane_idx {
            // Past-pad: state_new = state_prev.
            (state_prev, 0, 0)
        } else {
            // Verbatim XORin.
            (state_prev ^ chunk_lane, 0, 0)
        };
        write_u64(r, COL_STATE_NEW_LO, state_new);
        write_u64(r, COL_CLEARED_LO, cleared);
        write_u64(r, COL_PADDED_LO, padded);
        if is_last_block {
            // Squeeze provides the perm-`last`'s output for
            // non-digest lanes (slots [4, 17) of the last block).
            // Filling all slots simplifies the per-row code; the
            // bus gate (`p_squeeze_active`) decides which actually
            // fire.
            write_u64(r, COL_STATE_OUT_LO, perm_out_last_block[slot]);
        }
    } else if is_capacity_slot {
        // Capacity passthrough: state_new = state_prev.
        let state_prev = state_at_block_start[slot];
        write_u64(r, COL_STATE_PREV_LO, state_prev);
        write_u64(r, COL_STATE_NEW_LO, state_prev);
        if is_last_block {
            write_u64(r, COL_STATE_OUT_LO, perm_out_last_block[slot]);
        }
    } else if is_lane16_0x80 {
        // Lane-16 0x80 row: `state_prev` = lane-16 intermediate
        // (post-rate-XORin, pre-`0x80` mixin); `state_new` =
        // state_prev XOR pad_const. The bus consume of `state_prev`
        // matches the lane-16 rate-XORin row's provide at the same
        // Memory64 address (`100·sponge_seq_id − 2484`), so the
        // post-XORin value pinned here must match what the rate
        // row produced. The Logic64 mult is gated by
        // `is_last_block_period`, but trace generation fills the
        // values uniformly for layout consistency.
        let state_prev = post_xorin_this_block[LANE_16];
        write_u64(r, COL_STATE_PREV_LO, state_prev);
        let state_new = if is_last_block {
            state_prev ^ PAD_CONST
        } else {
            state_prev
        };
        write_u64(r, COL_STATE_NEW_LO, state_new);
    }
    // Slots 26..32 (NOP slack): all column values left at zero.
}

fn write_u64(row: &mut [Felt], col_lo: usize, value: u64) {
    let [lo, hi] = split_u64(value);
    row[col_lo] = lo;
    row[col_lo + 1] = hi;
}

/// `0xFFFF_FFFF_FFFF_FFFF << (8·byte_offset)` — zeroes the low
/// `byte_offset` bytes when ANDed with `chunk`, keeping the high
/// bytes for the pad row's `cleared` intermediate.
fn andnot_mask(byte_offset: usize) -> u64 {
    u64::MAX << (8 * byte_offset)
}

/// `0x01 << (8·byte_offset)` — places the leading `0x01` pad byte
/// at the pad position.
fn padding_mask(byte_offset: usize) -> u64 {
    1u64 << (8 * byte_offset)
}

// PROVER
// ================================================================================================

/// Build the aux trace for [`KeccakSpongeAir`]. The aux trace is
/// produced by the generic [`build_logup_aux_trace`] driver — no
/// chiplet-specific aux-trace code lives here.
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    build_logup_aux_trace(&KeccakSpongeAir, main, challenges)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn num_blocks_matches_fips_202_rule() {
        // Smallest: empty input still needs one padding block.
        assert_eq!(Invocation { input: vec![] }.num_blocks(), 1);
        // Just-fits cases.
        assert_eq!(Invocation { input: vec![0; 7] }.num_blocks(), 1);
        assert_eq!(Invocation { input: vec![0; 135] }.num_blocks(), 1);
        // 136-byte input needs a trailing pad block (the 0x01 byte
        // can't fit alongside a full rate-block of input).
        assert_eq!(Invocation { input: vec![0; 136] }.num_blocks(), 2);
        assert_eq!(Invocation { input: vec![0; 200] }.num_blocks(), 2);
        assert_eq!(Invocation { input: vec![0; 272] }.num_blocks(), 3);
    }

    #[test]
    fn chunk_lanes_round_up_to_32_byte_granularity() {
        // 0 input bytes → one canonical zero chunk = 4 lanes (consumed
        // as a full garbage-tail; see `chunk_lanes` docs).
        assert_eq!(Invocation { input: vec![] }.chunk_lanes(), 4);
        // Any positive input → at least 4 lanes (one chunk).
        assert_eq!(Invocation { input: vec![0] }.chunk_lanes(), 4);
        assert_eq!(Invocation { input: vec![0; 32] }.chunk_lanes(), 4);
        assert_eq!(Invocation { input: vec![0; 33] }.chunk_lanes(), 8);
        // 200 bytes → 7 chunks = 28 lanes (block 0 consumes 17,
        // block 1 consumes the remaining 11 incl. 3 garbage-tail
        // lanes past the input).
        assert_eq!(Invocation { input: vec![0; 200] }.chunk_lanes(), 28);
    }
}
