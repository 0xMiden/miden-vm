//! Keccak sponge chiplet.
//!
//! Sponge AIR over the [round chiplet's](super::round) 25-round /
//! 3200-IP permutation cycle. One row per state lane, period 32 →
//! α = 100. See the design notes for the design.
//!
//! Status: incremental landing — currently exposes the
//! [`KeccakSpongeMsg`] tuple, the period-32 program, and the AIR
//! struct + witness column layout. Local constraints, lookups, and
//! trace generation follow in subsequent commits.

pub mod message;
pub mod program;
pub mod trace;

use alloc::vec::Vec;
use core::{array, ops::Range};

pub use message::KeccakSpongeMsg;
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};
pub use program::{NUM_PERIODIC_COLS, SPONGE_PERIOD, sponge_program};

use crate::{
    hash::memory64::{CHUNK_ADDR_BASE, Memory64Msg},
    logup::{
        CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
        LookupGroup, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, NUM_SIGMA_VALUES, frac_col,
    },
    primitives::byte_pair_lut::{BytePairLutMsg, BytePairOp},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{current_main, halves_le, next_main},
};

// MAIN COLUMN LAYOUT
// ================================================================================================
//
// 67 main witness columns split into four groups:
//
// - Structural (5):    sponge_seq_id, act, bytes_left, is_first_block_of_invocation, chunk_ptr.
// - Padding state (10): is_zero_p, is_chunk_avail, b_0..b_7.
// - Per-row lane (12): chunk, state_prev, state_new, state_out, cleared, padded — each as u32
//   lo/hi.
// - Byte-shadow (40): chunk, state_prev, state_new, cleared, padded — each an 8-byte little-endian
//   decomposition, linked to its lo/hi halves above and verified against the `BytePairLut` chiplet
//   directly.
//
// See the design notes §"Columns" for the definitions.

// Structural columns.
// --------------------------------------------------------------------

/// Global sponge row counter, +1 per row. Plays the role of the round
/// chiplet's `ip`; every per-row address is a degree-1 expression in
/// `sponge_seq_id` and the period-32 `p_idx`. Carried in the
/// `KeccakSponge` request tuple so the transcript chiplet can derive
/// the digest address in the round chiplet's IP space.
pub const COL_SPONGE_SEQ_ID: usize = 0;
/// Sticky-downward activity flag. Multiplied into every bus mult so
/// trace-tail rows contribute zero regardless of other witness state.
pub const COL_ACT: usize = 1;
/// Bytes remaining to absorb at row `r`. Pinned to `len_bytes` at the
/// first row of each invocation by the `KeccakSponge` bus require,
/// decrements by 8 per rate XORin row, holds on non-absorb rows.
pub const COL_BYTES_LEFT: usize = 2;
/// 1 throughout the first absorption period of an invocation, 0 on
/// every other period within the invocation. Gates the prev-perm
/// consume *off* on first-block state-lane rows, the capacity-init
/// "provide 0" *on*, and the `state_prev = 0` local pin.
pub const COL_IS_FIRST_BLOCK_OF_INVOCATION: usize = 3;
/// Sponge-side cursor into the chunk chiplet's flat Memory64 tape.
/// Pinned to the invocation's chunk-tape base by the `KeccakSponge`
/// request at the first row of each invocation; increments by
/// `(p_rate_block + p_extra · b_sum) · is_chunk_avail` within the
/// invocation (rate rows on every block, plus the last block's extra
/// rows mopping up overshoot lanes); jumps freely at invocation seams
/// (the chain is gated off there — see the `chunk_ptr` increment chain
/// in `eval`). Used as the address
/// offset in `chunk-consume-addr = CHUNK_ADDR_BASE + chunk_ptr`.
pub const COL_CHUNK_PTR: usize = 4;

// Padding state machine columns.
// --------------------------------------------------------------------

/// Past-pad indicator on rate XORin rows; monotone non-decreasing
/// across the 32 rows of the period. On rows past slot 17 it equals
/// `is_last_block_period`.
pub const COL_IS_ZERO: usize = 5;
/// Chunks-available indicator on rate XORin rows; monotone
/// non-increasing within the period (once chunks run out, they stay
/// out — a single contiguous prefix). 1 iff the chunk chiplet provides
/// at this row, else 0. On a last block that overshoots the rate, the
/// prefix carries through the inert capacity / 0x80 rows so the rate
/// rows and the extra rows [26,29) stay one prefix.
pub const COL_IS_CHUNK_AVAIL: usize = 6;
/// First column of the unary `b_j` selector bits for
/// `byte_offset ∈ [0, 7]`. The 8 selectors occupy
/// `COL_B_BEGIN .. COL_B_BEGIN + NUM_B_SELECTORS`. Per-invocation
/// broadcast: exactly one fires on the last absorption period, none
/// fire elsewhere. The inline sum `Σ_j b_j` is the canonical
/// `is_last_block_period` signal across the period.
pub const COL_B_BEGIN: usize = 7;
/// Number of unary `b_j` selector columns (one per `byte_offset`
/// value in `[0, 8)`).
pub const NUM_B_SELECTORS: usize = 8;
/// Range covered by the `b_j` selectors:
/// `COL_B_RANGE = COL_B_BEGIN..(COL_B_BEGIN + NUM_B_SELECTORS)`.
pub const COL_B_RANGE: core::ops::Range<usize> = COL_B_BEGIN..(COL_B_BEGIN + NUM_B_SELECTORS);

// Per-row lane-value columns.
// --------------------------------------------------------------------

/// Chunk lane value at this row. Bus-pinned by the chunk-bus require
/// (Memory64 at `CHUNK_ADDR_BASE + chunk_ptr`) when
/// `is_chunk_avail = 1`; unconstrained otherwise.
pub const COL_CHUNK_LO: usize = 15;
pub const COL_CHUNK_HI: usize = 16;
/// Prev-perm output lane value (consumed from Memory64) on state-lane
/// rows. On the lane-16 0x80 row (`p_idx = 25`) holds the
/// *intermediate* (pre-`0x80`) lane-16 value.
pub const COL_STATE_PREV_LO: usize = 17;
pub const COL_STATE_PREV_HI: usize = 18;
/// New lane value (provided to Memory64) on state-lane rows = perm-n
/// round-0 input. On the lane-16 0x80 row holds the *final*
/// (post-`0x80`) lane-16 value.
pub const COL_STATE_NEW_LO: usize = 19;
pub const COL_STATE_NEW_HI: usize = 20;
/// Perm-n's last-perm output for lane `p_idx`, consumed from Memory64
/// by the squeeze on last-block state-lane rows. Bus-pinned by the
/// round chiplet's perm-n output provide (at IP `n·3200 + 3072 + p_idx`,
/// mult 2). Unconstrained when the squeeze gate is off.
pub const COL_STATE_OUT_LO: usize = 21;
pub const COL_STATE_OUT_HI: usize = 22;
/// Pad-row intermediate: `cleared = AndNot(andnot_mask, chunk_lane)`.
/// Committed on all rate XORin rows for layout uniformity but
/// algebraically meaningful only on the pad row.
pub const COL_CLEARED_LO: usize = 23;
pub const COL_CLEARED_HI: usize = 24;
/// Pad-row intermediate: `padded = cleared XOR padding_mask`. Same
/// uniform-commit pattern as `cleared`.
pub const COL_PADDED_LO: usize = 25;
pub const COL_PADDED_HI: usize = 26;

// Byte-decomposed shadow columns.
// --------------------------------------------------------------------
//
// `chunk`, `state_prev`, `state_new`, `cleared`, `padded` each also carry
// an 8-byte little-endian decomposition, linked to their `_lo`/`_hi`
// halves above by an ungated local constraint (`eval`'s "byte-shadow
// linking" block). The bytes are what the `BytePairLut` requires below
// verify each pad/absorb XOR/ANDNOT against directly — no intermediate
// chiplet or chain trick, every row commits its own bytes.
pub const CHUNK_BYTES_RANGE: Range<usize> = 27..35;
pub const STATE_PREV_BYTES_RANGE: Range<usize> = 35..43;
pub const STATE_NEW_BYTES_RANGE: Range<usize> = 43..51;
pub const CLEARED_BYTES_RANGE: Range<usize> = 51..59;
pub const PADDED_BYTES_RANGE: Range<usize> = 59..67;

/// Total number of main witness columns (5 structural + 10 padding-
/// state-machine + 12 per-row lane values, halves + 40 byte-shadow
/// columns for the same five values).
pub const NUM_MAIN_COLS: usize = 67;

// AUX / PUBLIC LAYOUT
// ================================================================================================

/// Aux columns. Columns 0–2 are FLATTENED to lqd 2 (the mutex outer flags
/// folded into each insert's multiplicity — sound: the one-hot flags are
/// binary, the same precondition the mutex-group fold already relies on):
///
/// - col 0 (running σ): Memory64 `new-state` + `prev-perm` (the two lowest-degree fractions; the
///   gated last-row close adds +1, so it lands at degree 5).
/// - col 1: Memory64 `rc` + lane-16 0x80 consume / provide.
/// - col 2: Memory64 `squeeze` (the degree-4 multiplicity, alone → degree 4).
/// - cols 3–22: `BytePairLut` byte requires (8 bytes each) verifying the pad-row `andnot` +
///   `xor-padding` + `xor-state`, the verbatim `xor-state`, and the lane-16 0x80 `xor` directly
///   against the byte-shadow columns — no intermediate chiplet, two fractions per column.
/// - col 23: the KeccakSponge request + the chunk consume (the second degree-4 multiplicity, paired
///   → degree 5).
///
/// Max per-LogUp-column constraint deg = 5 → `log_quotient_degree = 2`. The
/// degree-4 multiplicities (`squeeze`, `chunk-consume`) are the floor; dropping
/// to lqd 1 would need them witness-decomposed. Width disregarded. See
/// the design notes §"Aux columns and σ exposure".
pub const NUM_AUX_COLS: usize = 24;

// The single exposed σ ([`NUM_SIGMA_VALUES`]) follows the VM-wide σ
// contract in [`crate::logup`]. The sponge's σ aggregates its net
// contribution across all three buses (Memory64, BytePairLut, KeccakSponge)
// into one residue — bus-prefix-distinguished encodings + Schwartz-Zippel
// on random α enforce per-bus balance; the single-σ count is the shared
// shape, not a sponge-specific choice. The shared public values
// ([`NUM_PUBLIC_VALUES`]) are the transcript root alone — declared but
// not read here; the natural last-row closing needs no `inv_n` height
// input.

// PERIODIC COLUMN INDICES (re-exported from `program`)
// ================================================================================================

pub use program::{
    COL_CAPACITY as PCOL_CAPACITY, COL_EXTRA as PCOL_EXTRA, COL_FIRST as PCOL_FIRST,
    COL_IDX as PCOL_IDX, COL_LAST as PCOL_LAST, COL_PAD_0X80 as PCOL_PAD_0X80,
    COL_RATE_BLOCK as PCOL_RATE_BLOCK, COL_RC_ACTIVE as PCOL_RC_ACTIVE, COL_RC_HI as PCOL_RC_HI,
    COL_RC_LO as PCOL_RC_LO, COL_SQUEEZE_ACTIVE as PCOL_SQUEEZE_ACTIVE,
};

// AIR
// ================================================================================================

/// Keccak sponge chiplet AIR. Period-32 program (one period = one
/// Keccak permutation) drives rate XORin / capacity passthrough /
/// padding state machine over the
/// [`Memory64`](crate::hash::memory64) bus, verifying its own pad/absorb
/// XOR/ANDNOT ops directly against
/// [`BytePairLut`](crate::primitives::byte_pair_lut), with the
/// per-invocation request consumed from the
/// [`KeccakSponge`](crate::relations::BusId::KeccakSponge) bus.
///
/// Trace generation lands in a subsequent commit. The verifier-side
/// machinery (column layout, periodic program, constraints, lookups)
/// is complete here.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeccakSpongeAir;

impl BaseAir<Felt> for KeccakSpongeAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        sponge_program().to_vec()
    }
}

// PAD-ROW MASK TABLES (indexed by `byte_offset ∈ [0, 8)`)
// ================================================================================================
//
// The pad-row `BytePairLut` requests need two masks whose values are
// selected by the unary `b_j` selector bits: `andnot_mask` clears
// the bytes at and past `byte_offset`, and `padding_mask` places a
// `0x01` byte at `byte_offset`. The arrays below hold the
// per-`byte_offset` u32-half constants (kept as the verified source of
// truth); `eval` extracts each byte from them via [`mask_byte`] and
// builds `andnot_mask_bytes[i] = Σ_j b_j · mask_byte(ANDNOT_MASK_LO[j],
// ANDNOT_MASK_HI[j], i)` (and likewise for padding) as a degree-1
// witness inline.

/// `ANDNOT_MASK[j].lo` (u32) for `byte_offset = j`. Equals the low
/// 32 bits of `0xFFFF_FFFF_FFFF_FFFF << (8·j)`. Used by the pad-row
/// ANDNOT message: `cleared = (NOT andnot_mask) AND chunk` zeroes
/// chunk bytes at positions `[j, 8)`.
pub const ANDNOT_MASK_LO: [u32; 8] = [
    0xffff_ffff,
    0xffff_ff00,
    0xffff_0000,
    0xff00_0000,
    0x0000_0000,
    0x0000_0000,
    0x0000_0000,
    0x0000_0000,
];

/// `ANDNOT_MASK[j].hi` (u32) for `byte_offset = j`.
pub const ANDNOT_MASK_HI: [u32; 8] = [
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ff00,
    0xffff_0000,
    0xff00_0000,
];

/// `PADDING_MASK[j].lo` (u32) for `byte_offset = j`. Equals the low
/// 32 bits of `0x01 << (8·j)`. Used by the pad-row XOR(padding)
/// message: places the leading `0x01` padding byte at `byte_offset`.
pub const PADDING_MASK_LO: [u32; 8] = [
    0x0000_0001,
    0x0000_0100,
    0x0001_0000,
    0x0100_0000,
    0x0000_0000,
    0x0000_0000,
    0x0000_0000,
    0x0000_0000,
];

/// `PADDING_MASK[j].hi` (u32) for `byte_offset = j`.
pub const PADDING_MASK_HI: [u32; 8] = [
    0x0000_0000,
    0x0000_0000,
    0x0000_0000,
    0x0000_0000,
    0x0000_0001,
    0x0000_0100,
    0x0001_0000,
    0x0100_0000,
];

/// Low u32 half of the lane-16 trailing-`0x80` constant (= `0`).
pub const PAD_CONST_LO: u32 = 0;
/// High u32 half of the lane-16 trailing-`0x80` constant
/// (`0x80 << 56` falls in the top byte of the hi half).
pub const PAD_CONST_HI: u32 = 0x8000_0000;
/// Byte `i` (LSB-first) of the lane-16 trailing-`0x80` constant.
pub const PAD_CONST_BYTES: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0x80];

/// Byte `byte_idx` (LSB-first, `< 8`) of the 64-bit value whose 32-bit
/// halves are `lo`/`hi`. Extracts from the already-verified `_LO`/`_HI`
/// per-`byte_offset` mask constants, so the per-byte view is correct by
/// construction rather than a hand-rederived bit pattern.
const fn mask_byte(lo: u32, hi: u32, byte_idx: usize) -> u8 {
    let word = if byte_idx < 4 { lo } else { hi };
    ((word >> (8 * (byte_idx % 4))) & 0xff) as u8
}

// LIFTED AIR
// ================================================================================================

impl LiftedAir<Felt, QuadFelt> for KeccakSpongeAir {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        NUM_AUX_COLS
    }

    fn num_aux_values(&self) -> usize {
        NUM_SIGMA_VALUES
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        trace::build_aux(main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        // Phase 1: local row constraints.
        let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        // Next-row window: the same 27 columns at row r+1. Cyclic at
        // row N-1 (`when_transition` gates out the wrap explicitly
        // where needed; other transition constraints rely on
        // `p_last`/`p_rate_block` factors making the wrap vacuous).
        let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);

        let periodic = builder.periodic_values();
        let p_first: AB::Expr = periodic[PCOL_FIRST].into();
        let p_last: AB::Expr = periodic[PCOL_LAST].into();
        let p_rate_block: AB::Expr = periodic[PCOL_RATE_BLOCK].into();
        let p_capacity: AB::Expr = periodic[PCOL_CAPACITY].into();
        let p_extra: AB::Expr = periodic[PCOL_EXTRA].into();
        let p_state_lane: AB::Expr = p_rate_block.clone() + p_capacity.clone();

        // Frequently-used local / next-row expressions.
        let act: AB::Expr = local[COL_ACT].into();
        let act_next: AB::Expr = next[COL_ACT].into();
        let sponge_seq_id: AB::Expr = local[COL_SPONGE_SEQ_ID].into();
        let sponge_seq_id_next: AB::Expr = next[COL_SPONGE_SEQ_ID].into();
        let bytes_left: AB::Expr = local[COL_BYTES_LEFT].into();
        let bytes_left_next: AB::Expr = next[COL_BYTES_LEFT].into();
        let chunk_ptr: AB::Expr = local[COL_CHUNK_PTR].into();
        let chunk_ptr_next: AB::Expr = next[COL_CHUNK_PTR].into();
        let is_first_block: AB::Expr = local[COL_IS_FIRST_BLOCK_OF_INVOCATION].into();
        let is_first_block_next: AB::Expr = next[COL_IS_FIRST_BLOCK_OF_INVOCATION].into();
        let is_zero: AB::Expr = local[COL_IS_ZERO].into();
        let is_zero_next: AB::Expr = next[COL_IS_ZERO].into();
        let is_chunk_avail: AB::Expr = local[COL_IS_CHUNK_AVAIL].into();
        let is_chunk_avail_next: AB::Expr = next[COL_IS_CHUNK_AVAIL].into();
        let state_prev_lo: AB::Expr = local[COL_STATE_PREV_LO].into();
        let state_prev_hi: AB::Expr = local[COL_STATE_PREV_HI].into();
        let state_new_lo: AB::Expr = local[COL_STATE_NEW_LO].into();
        let state_new_hi: AB::Expr = local[COL_STATE_NEW_HI].into();

        // Σ b_j (= `is_last_block_period`) and Σ j·b_j (= byte_offset).
        let mut b_sum = AB::Expr::ZERO;
        let mut b_weighted = AB::Expr::ZERO;
        for (j, col) in COL_B_RANGE.enumerate() {
            let b_j: AB::Expr = local[col].into();
            b_sum += b_j.clone();
            b_weighted += AB::Expr::from(Felt::from(j as u32)) * b_j;
        }

        // Boundary (`when_first_row`) ---------------------------
        // `sponge_seq_id` starts at 0 (row counter convention). No
        // `chunk_ptr` boundary: the chunk-tape base is pinned per
        // invocation by the `KeccakSponge` request (the first
        // invocation supplies base 0 by convention), and the chain is
        // relaxed at invocation seams — see the `chunk_ptr` chain below.
        builder.when_first_row().assert_zero(sponge_seq_id.clone());

        // Activity ----------------------------------------------
        // Binary: act ∈ {0, 1}. Deg 2.
        builder.assert_bool(local[COL_ACT]);
        // Sticky-downward: forbids 0 → 1 within [0, N-2]. The cyclic
        // wrap is intentionally unconstrained so a 1's-prefix / 0's-
        // suffix trace cycles back to `act_0 = 1` on the next loop.
        builder
            .when_transition()
            .assert_zero((AB::Expr::ONE - act.clone()) * act_next.clone());
        // Drop placement: the unique 1 → 0 transition must land at
        // slot 31 (where `p_last = 1`) of a last-block period
        // (`Σ b_j = 1`). Equivalent to `act · (1 - act')` under the
        // sticky-down constraint above; the linear form costs one
        // fewer witness multiplication.
        builder.when_transition().assert_zero(
            (act.clone() - act_next) * (AB::Expr::ONE - p_last.clone() * b_sum.clone()),
        );

        // Row counter -------------------------------------------
        // sponge_seq_id' - sponge_seq_id - 1 = 0. Deg 1.
        // `when_transition` keeps the cyclic wrap (which would force
        // sponge_seq_id_0 = N) unconstrained.
        builder
            .when_transition()
            .assert_zero(sponge_seq_id_next - sponge_seq_id - AB::Expr::ONE);

        // `is_first_block_of_invocation` structure --------------
        builder.assert_bool(local[COL_IS_FIRST_BLOCK_OF_INVOCATION]);
        // Constant within period. `(1 - p_last)` makes the wrap
        // vacuous (p_last_{N-1} = 1) and lets `is_first_block` toggle
        // at period boundaries.
        builder.assert_zero(
            (AB::Expr::ONE - p_last.clone())
                * (is_first_block_next.clone() - is_first_block.clone()),
        );

        // `bytes_left` decrement chain --------------------------
        // Both branches are gated by `act`: on dead rows `bytes_left` is
        // unconstrained, so the all-dead (zero-invocation) trace is
        // admissible — the only valid empty-transcript trace (see
        // the design notes §`bytes_left` decrement chain).
        // On active rows the chain is identical, so it still forbids the
        // `act = 1 ∧ is_first_block = 0` cyclic-fixed-point forgery via the
        // `M · 136 ≢ 0 mod p` argument (`act` doesn't weaken it — the forgery
        // it rules out is fully active). Dead rows are bus-inert, so leaving
        // `bytes_left` free there is sound.
        //
        // Absorb row (`p_rate_block = 1`): decrements by 8.
        builder.assert_zero(
            act.clone()
                * p_rate_block.clone()
                * (bytes_left_next.clone() - bytes_left.clone() + AB::Expr::from(Felt::from(8u8))),
        );
        // Non-absorb row + no invocation boundary at next row: holds steady.
        let enters_new_invocation = p_last.clone() * is_first_block_next.clone();
        builder.assert_zero(
            act.clone()
                * (AB::Expr::ONE - enters_new_invocation.clone())
                * (AB::Expr::ONE - p_rate_block.clone())
                * (bytes_left_next - bytes_left.clone()),
        );

        // `chunk_ptr` increment chain ---------------------------
        // Within an invocation: chunk_ptr' - chunk_ptr -
        // (p_rate_block + p_extra · b_sum) · is_chunk_avail = 0 (advance
        // by 1 per consumed chunk lane). Rate rows consume on every
        // block; the extra rows consume the last block's overshoot
        // lanes (gated to the last block by `b_sum`), so `chunk_ptr`
        // walks all 4·num_chunks tape lanes contiguously. Gated off at
        // invocation seams (`enters_new_invocation`), where the
        // `KeccakSponge` request re-pins chunk_ptr to the next
        // invocation's chunk-tape base. No global enumeration from 0 —
        // per-invocation overlap/gap freedom is enforced by Memory64
        // bus balance against the chunk chiplet's contiguous emissions,
        // not by the chain. `when_transition` also keeps the cyclic
        // wrap unconstrained.
        builder.when_transition().assert_zero(
            (AB::Expr::ONE - enters_new_invocation)
                * (chunk_ptr_next
                    - chunk_ptr
                    - (p_rate_block.clone() + p_extra * b_sum.clone()) * is_chunk_avail.clone()),
        );

        // Chunk zero-fill on `is_chunk_avail = 0` --------------
        // When the chunk chiplet doesn't provide at this row, pin
        // `chunk_lo = chunk_hi = 0` so the witness is canonical and
        // pre-pad verbatim XORs can't be steered by a
        // prover-chosen unpinned chunk value. Effect: any
        // under-emission by the chunk chiplet yields a deterministic
        // zero-extended digest, caught by the downstream digest
        // check at the transcript chiplet. Ungated — pinning chunk
        // to 0 on non-rate / dead rows is benign since those rows
        // never consume the chunk columns elsewhere.
        let chunk_lo_local: AB::Expr = local[COL_CHUNK_LO].into();
        let chunk_hi_local: AB::Expr = local[COL_CHUNK_HI].into();
        builder.assert_zero((AB::Expr::ONE - is_chunk_avail.clone()) * chunk_lo_local);
        builder.assert_zero((AB::Expr::ONE - is_chunk_avail.clone()) * chunk_hi_local);

        // Padding state machine ---------------------------------
        // Binarity.
        builder.assert_bool(local[COL_IS_ZERO]);
        builder.assert_bool(local[COL_IS_CHUNK_AVAIL]);
        for col in COL_B_RANGE {
            builder.assert_bool(local[col]);
        }

        // `is_zero` non-decreasing within period.
        builder.assert_zero(
            (AB::Expr::ONE - p_last.clone())
                * is_zero.clone()
                * (AB::Expr::ONE - is_zero_next.clone()),
        );
        // `is_chunk_avail` non-increasing within period.
        builder.assert_zero(
            (AB::Expr::ONE - p_last.clone())
                * (AB::Expr::ONE - is_chunk_avail)
                * is_chunk_avail_next,
        );
        // Period boundary: pad hasn't fired yet at slot 0.
        builder.assert_zero(p_first * is_zero.clone());
        // Selector bits constant within period.
        for col in COL_B_RANGE {
            let b_j: AB::Expr = local[col].into();
            let b_j_next: AB::Expr = next[col].into();
            builder.assert_zero((AB::Expr::ONE - p_last.clone()) * (b_j_next - b_j));
        }
        // Selector sum ties to `is_zero` on non-absorb rows.
        builder.assert_zero(
            (AB::Expr::ONE - p_rate_block.clone()) * (b_sum.clone() - is_zero.clone()),
        );

        // Pad-must-fire (gated by `act`) ------------------------
        // At slot 31 of any *active* period followed by a new
        // invocation, force `is_zero = 1` (the pad fired earlier in
        // this period) — i.e. a new invocation may only start right
        // after a last block, so no invocation is truncated. Covers
        // active→active seams. The last active invocation's last block
        // is instead pinned by `act` drop placement (act may drop only
        // after a `b_sum = 1` period). The `act` gate makes the cyclic
        // wrap from the trailing dead pad region into row 0 vacuous
        // (dead rows carry `is_zero = 0`), so an invocation set whose
        // total block count isn't a power of two — padded out with dead
        // rows — is admissible. Without the gate the wrap would demand
        // `is_zero = 1` on the final dead row.
        builder.assert_zero(act * p_last * is_first_block_next * (AB::Expr::ONE - is_zero.clone()));

        // Pad-lane tie-down -------------------------------------
        // On the unique pad transition row (`p_rate_block = 1`,
        // `is_pad = 1`), pin `byte_offset = bytes_left`. Vacuous
        // everywhere else. The `p_rate_block` gate also absorbs
        // the period-wrap `is_pad = −1` case, which always lands
        // on `p_idx = 31` where `p_rate_block = 0`.
        let is_pad: AB::Expr = is_zero_next - is_zero.clone();
        builder.assert_zero(p_rate_block.clone() * is_pad * (b_weighted - bytes_left));

        // state_prev = 0 on first-block state-lane rows ---------
        builder.assert_zero(p_state_lane.clone() * is_first_block.clone() * state_prev_lo.clone());
        builder.assert_zero(p_state_lane * is_first_block * state_prev_hi.clone());

        // State propagation (no BytePairLut request fires) --------
        // Past-pad rate XORin rows: `state_new = state_prev`.
        builder.assert_zero(
            p_rate_block.clone() * is_zero.clone() * (state_new_lo.clone() - state_prev_lo.clone()),
        );
        builder
            .assert_zero(p_rate_block * is_zero * (state_new_hi.clone() - state_prev_hi.clone()));
        // Capacity rows: identity passthrough.
        builder.assert_zero(p_capacity.clone() * (state_new_lo.clone() - state_prev_lo.clone()));
        builder.assert_zero(p_capacity * (state_new_hi.clone() - state_prev_hi.clone()));

        // Byte-shadow linking (ungated) --------------------------
        // Every `_lo`/`_hi` pair below also has an 8-byte little-endian
        // shadow (used by the `BytePairLut` requires in Phase 2, which
        // range-check and byte-verify the pad/absorb XOR/ANDNOT ops
        // directly). Without this link the byte columns would be a
        // second, independent free witness disconnected from the halves
        // every other bus message (Memory64 prev-perm consume, new-state
        // provide, chunk consume) actually reads — pinning them together
        // is what makes a `BytePairLut`-verified byte result also the
        // value committed elsewhere. Ungated: both sides are otherwise
        // free witness on rows where the value is unused, so an honest
        // prover always satisfies this by construction.
        let chunk_lo: AB::Expr = local[COL_CHUNK_LO].into();
        let chunk_hi: AB::Expr = local[COL_CHUNK_HI].into();
        let cleared_lo: AB::Expr = local[COL_CLEARED_LO].into();
        let cleared_hi: AB::Expr = local[COL_CLEARED_HI].into();
        let padded_lo: AB::Expr = local[COL_PADDED_LO].into();
        let padded_hi: AB::Expr = local[COL_PADDED_HI].into();
        let link = |builder: &mut AB, range: Range<usize>, lo: AB::Expr, hi: AB::Expr| {
            let bytes: [AB::Var; 8] = array::from_fn(|i| local[range.start + i]);
            let [lo_from_bytes, hi_from_bytes]: [AB::Expr; 2] = halves_le(&bytes, 256);
            builder.assert_zero(lo_from_bytes - lo);
            builder.assert_zero(hi_from_bytes - hi);
        };
        link(builder, CHUNK_BYTES_RANGE, chunk_lo, chunk_hi);
        link(builder, STATE_PREV_BYTES_RANGE, state_prev_lo, state_prev_hi);
        link(builder, STATE_NEW_BYTES_RANGE, state_new_lo, state_new_hi);
        link(builder, CLEARED_BYTES_RANGE, cleared_lo, cleared_hi);
        link(builder, PADDED_BYTES_RANGE, padded_lo, padded_hi);

        // Phase 2: LogUp argument via the LogUp adapter.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR
// ================================================================================================

/// Per-column insert counts (FLATTENED to lqd 2): the 13 flag-folded
/// fractions split ≤ 3 per column (col 0 two low-degree fractions; the
/// degree-4 `squeeze` alone, the degree-4 `chunk-consume` paired) so every
/// closing constraint is degree ≤ 5. The chunk-consume fires on rate rows
/// and, on the last block, the extra rows [26,29) that mop up overshoot
/// lanes (gated by `p_extra · b_sum`).
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = build_column_shape();

const fn build_column_shape() -> [usize; NUM_AUX_COLS] {
    let mut shape = [2usize; NUM_AUX_COLS];
    shape[0] = 2;
    shape[1] = 3;
    shape[2] = 1;
    shape[NUM_AUX_COLS - 1] = 2;
    shape
}

impl<LB> LookupAir<LB> for KeccakSpongeAir
where
    LB: LookupBuilder<F = Felt>,
{
    fn num_columns(&self) -> usize {
        NUM_AUX_COLS
    }

    fn column_shape(&self) -> &[usize] {
        &COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        NUM_BUS_IDS
    }

    fn eval(&self, builder: &mut LB) {
        let local: [LB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next: [LB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);
        let periodic = builder.periodic_values();
        let p_first: LB::Expr = periodic[PCOL_FIRST].into();
        let p_rate_block: LB::Expr = periodic[PCOL_RATE_BLOCK].into();
        let p_capacity: LB::Expr = periodic[PCOL_CAPACITY].into();
        let p_rc_active: LB::Expr = periodic[PCOL_RC_ACTIVE].into();
        let p_squeeze_active: LB::Expr = periodic[PCOL_SQUEEZE_ACTIVE].into();
        let p_pad_0x80: LB::Expr = periodic[PCOL_PAD_0X80].into();
        let p_extra: LB::Expr = periodic[PCOL_EXTRA].into();
        let p_idx: LB::Expr = periodic[PCOL_IDX].into();
        let rc_lo: LB::Expr = periodic[PCOL_RC_LO].into();
        let rc_hi: LB::Expr = periodic[PCOL_RC_HI].into();
        let p_state_lane: LB::Expr = p_rate_block.clone() + p_capacity;

        let act: LB::Expr = local[COL_ACT].into();
        let sponge_seq_id: LB::Expr = local[COL_SPONGE_SEQ_ID].into();
        let chunk_ptr: LB::Expr = local[COL_CHUNK_PTR].into();
        let bytes_left: LB::Expr = local[COL_BYTES_LEFT].into();
        let is_first_block: LB::Expr = local[COL_IS_FIRST_BLOCK_OF_INVOCATION].into();
        let is_chunk_avail: LB::Expr = local[COL_IS_CHUNK_AVAIL].into();
        let is_zero: LB::Expr = local[COL_IS_ZERO].into();
        let is_zero_next: LB::Expr = next[COL_IS_ZERO].into();
        let chunk_lo: LB::Expr = local[COL_CHUNK_LO].into();
        let chunk_hi: LB::Expr = local[COL_CHUNK_HI].into();
        let state_prev_lo: LB::Expr = local[COL_STATE_PREV_LO].into();
        let state_prev_hi: LB::Expr = local[COL_STATE_PREV_HI].into();
        let state_new_lo: LB::Expr = local[COL_STATE_NEW_LO].into();
        let state_new_hi: LB::Expr = local[COL_STATE_NEW_HI].into();
        let state_out_lo: LB::Expr = local[COL_STATE_OUT_LO].into();
        let state_out_hi: LB::Expr = local[COL_STATE_OUT_HI].into();
        let cleared_bytes: [LB::Var; 8] = array::from_fn(|i| local[CLEARED_BYTES_RANGE.start + i]);
        let padded_bytes: [LB::Var; 8] = array::from_fn(|i| local[PADDED_BYTES_RANGE.start + i]);
        let chunk_bytes: [LB::Var; 8] = array::from_fn(|i| local[CHUNK_BYTES_RANGE.start + i]);
        let state_prev_bytes: [LB::Var; 8] =
            array::from_fn(|i| local[STATE_PREV_BYTES_RANGE.start + i]);
        let state_new_bytes: [LB::Var; 8] =
            array::from_fn(|i| local[STATE_NEW_BYTES_RANGE.start + i]);

        // Σ b_j (= `is_last_block_period`); `andnot_mask` and
        // `padding_mask`, byte-decomposed, as `Σ_j b_j · MASK_BYTE[i][j]`
        // inlines (`mask_byte` extracts byte `i` from the existing
        // verifier-known `*_LO`/`*_HI` per-`byte_offset` constants, so the
        // per-byte tables are correct by construction from the
        // already-verified 32-bit ones).
        let mut b_sum = LB::Expr::ZERO;
        let mut andnot_mask_bytes: [LB::Expr; 8] = array::from_fn(|_| LB::Expr::ZERO);
        let mut padding_mask_bytes: [LB::Expr; 8] = array::from_fn(|_| LB::Expr::ZERO);
        for (j, col) in COL_B_RANGE.enumerate() {
            let b_j: LB::Expr = local[col].into();
            b_sum += b_j.clone();
            for i in 0..8 {
                let andnot_byte = mask_byte(ANDNOT_MASK_LO[j], ANDNOT_MASK_HI[j], i);
                let padding_byte = mask_byte(PADDING_MASK_LO[j], PADDING_MASK_HI[j], i);
                andnot_mask_bytes[i] += LB::Expr::from(Felt::from(andnot_byte)) * b_j.clone();
                padding_mask_bytes[i] += LB::Expr::from(Felt::from(padding_byte)) * b_j.clone();
            }
        }

        // Derived signals (see the design notes
        // §"Derived multiplicity signals").
        let is_intra: LB::Expr = LB::Expr::ONE - is_first_block.clone();
        let is_first_row_of_invocation: LB::Expr = p_first * is_first_block;
        let is_pad: LB::Expr = is_zero_next.clone() - is_zero;
        let is_verbatim: LB::Expr = LB::Expr::ONE - is_zero_next;

        // Per-row address expressions.
        let hundred_seq = LB::Expr::from(Felt::from(100u8)) * sponge_seq_id.clone();
        let ninety_nine_idx = LB::Expr::from(Felt::from(99u8)) * p_idx.clone();
        let addr_state_lane_prev =
            hundred_seq.clone() - ninety_nine_idx.clone() - LB::Expr::from(Felt::from(128u8));
        let addr_state_lane_new = hundred_seq.clone() - ninety_nine_idx.clone();
        let addr_rc = hundred_seq.clone()
            + LB::Expr::from(Felt::from(28u8)) * p_idx
            + LB::Expr::from(Felt::from(25u8));
        let addr_squeeze =
            hundred_seq.clone() - ninety_nine_idx + LB::Expr::from(Felt::from(3072u32));
        let addr_lane16 = hundred_seq - LB::Expr::from(Felt::from(2484u32));
        let chunk_addr_base =
            Felt::new(CHUNK_ADDR_BASE).expect("CHUNK_ADDR_BASE fits in canonical Goldilocks");
        let addr_chunk = LB::Expr::from(chunk_addr_base) + chunk_ptr.clone();

        // Per-message multiplicity factors, all gated by `act`.
        let mult_prev_perm: LB::Expr = LB::Expr::from(Felt::from(2u8)) * act.clone() * is_intra;
        let mult_new_state: LB::Expr =
            LB::Expr::ZERO - LB::Expr::from(Felt::from(2u8)) * act.clone();
        let mult_rc: LB::Expr =
            LB::Expr::ZERO - LB::Expr::from(Felt::from(1u8)) * act.clone() * p_rc_active;
        let mult_squeeze: LB::Expr =
            LB::Expr::from(Felt::from(2u8)) * act.clone() * p_squeeze_active * b_sum.clone();
        let mult_lane16_consume: LB::Expr =
            LB::Expr::from(Felt::from(2u8)) * act.clone() * b_sum.clone();
        let mult_lane16_provide: LB::Expr =
            LB::Expr::ZERO - LB::Expr::from(Felt::from(2u8)) * act.clone() * b_sum.clone();

        let andnot_tag = LB::Expr::from(Felt::from(BytePairOp::AndNot.tag()));
        let xor_tag = LB::Expr::from(Felt::from(BytePairOp::Xor.tag()));

        let interaction_deg = Deg { v: 1, u: 1 };
        // FLATTENED to lqd 2: the mutex outer flags are folded into each
        // insert's multiplicity (sound — the one-hot flags are binary on the
        // rows where they fire, the precondition the mutex fold already
        // relied on), and the 13 fractions are partitioned ≤ 3 per column
        // so every closing constraint is degree ≤ 5. Column-degree hints are
        // ignored on the constraint path.
        let pair_deg = Deg { v: 4, u: 2 };
        let triple_deg = Deg { v: 5, u: 3 };
        let solo_deg = Deg { v: 4, u: 1 };
        let mixed_deg = Deg { v: 5, u: 2 };

        // col 0 (running sum): Memory64 state-lane new-state + prev-perm — the
        // two lowest-degree fractions, so the gated last-row close stays ≤ 5.
        frac_col!(
            builder,
            "memory64",
            pair_deg,
            (
                "new-state",
                p_state_lane.clone() * mult_new_state.clone(),
                Memory64Msg {
                    addr: addr_state_lane_new.clone(),
                    lo: state_new_lo.clone(),
                    hi: state_new_hi.clone(),
                },
                interaction_deg
            ),
            (
                "prev-perm",
                p_state_lane.clone() * mult_prev_perm.clone(),
                Memory64Msg {
                    addr: addr_state_lane_prev.clone(),
                    lo: state_prev_lo.clone(),
                    hi: state_prev_hi.clone(),
                },
                interaction_deg
            ),
        );
        // col 1: Memory64 state-lane rc + lane-16 0x80 consume / provide.
        frac_col!(
            builder,
            "memory64",
            triple_deg,
            (
                "rc",
                p_state_lane.clone() * mult_rc.clone(),
                Memory64Msg {
                    addr: addr_rc.clone(),
                    lo: rc_lo.clone(),
                    hi: rc_hi.clone()
                },
                interaction_deg
            ),
            (
                "lane16-consume",
                p_pad_0x80.clone() * mult_lane16_consume.clone(),
                Memory64Msg {
                    addr: addr_lane16.clone(),
                    lo: state_prev_lo.clone(),
                    hi: state_prev_hi.clone(),
                },
                interaction_deg
            ),
            (
                "lane16-provide",
                p_pad_0x80.clone() * mult_lane16_provide.clone(),
                Memory64Msg {
                    addr: addr_lane16.clone(),
                    lo: state_new_lo.clone(),
                    hi: state_new_hi.clone(),
                },
                interaction_deg
            ),
        );
        // col 2: Memory64 squeeze — a degree-4 multiplicity, alone (closing 4).
        frac_col!(
            builder,
            "memory64",
            solo_deg,
            (
                "squeeze",
                p_state_lane.clone() * mult_squeeze.clone(),
                Memory64Msg {
                    addr: addr_squeeze.clone(),
                    lo: state_out_lo.clone(),
                    hi: state_out_hi.clone()
                },
                interaction_deg
            ),
        );

        // cols 3..7: pad-row `BytePairLut` byte requires, 8 bytes each —
        // `andnot` (mask, chunk) → cleared, `xor-padding` (cleared,
        // padding_mask) → padded, `xor-state` (state_prev, padded) →
        // state_new. Same 8-byte-request pattern the round chiplet uses;
        // each op verifies its own row's bytes directly, no intermediate
        // chiplet or chain trick.
        let pad_mult = p_rate_block.clone() * is_pad * act.clone();
        for pair in 0..4 {
            let i0 = pair * 2;
            let i1 = i0 + 1;
            frac_col!(
                builder,
                "byte-pair-lut",
                pair_deg,
                (
                    "andnot",
                    pad_mult.clone(),
                    BytePairLutMsg {
                        op: andnot_tag.clone(),
                        a: andnot_mask_bytes[i0].clone(),
                        b: chunk_bytes[i0].into(),
                        c: cleared_bytes[i0].into()
                    },
                    interaction_deg
                ),
                (
                    "andnot",
                    pad_mult.clone(),
                    BytePairLutMsg {
                        op: andnot_tag.clone(),
                        a: andnot_mask_bytes[i1].clone(),
                        b: chunk_bytes[i1].into(),
                        c: cleared_bytes[i1].into()
                    },
                    interaction_deg
                ),
            );
        }
        for pair in 0..4 {
            let i0 = pair * 2;
            let i1 = i0 + 1;
            frac_col!(
                builder,
                "byte-pair-lut",
                pair_deg,
                (
                    "xor-padding",
                    pad_mult.clone(),
                    BytePairLutMsg {
                        op: xor_tag.clone(),
                        a: cleared_bytes[i0].into(),
                        b: padding_mask_bytes[i0].clone(),
                        c: padded_bytes[i0].into()
                    },
                    interaction_deg
                ),
                (
                    "xor-padding",
                    pad_mult.clone(),
                    BytePairLutMsg {
                        op: xor_tag.clone(),
                        a: cleared_bytes[i1].into(),
                        b: padding_mask_bytes[i1].clone(),
                        c: padded_bytes[i1].into()
                    },
                    interaction_deg
                ),
            );
        }
        for pair in 0..4 {
            let i0 = pair * 2;
            let i1 = i0 + 1;
            frac_col!(
                builder,
                "byte-pair-lut",
                pair_deg,
                (
                    "xor-state",
                    pad_mult.clone(),
                    BytePairLutMsg {
                        op: xor_tag.clone(),
                        a: state_prev_bytes[i0].into(),
                        b: padded_bytes[i0].into(),
                        c: state_new_bytes[i0].into()
                    },
                    interaction_deg
                ),
                (
                    "xor-state",
                    pad_mult.clone(),
                    BytePairLutMsg {
                        op: xor_tag.clone(),
                        a: state_prev_bytes[i1].into(),
                        b: padded_bytes[i1].into(),
                        c: state_new_bytes[i1].into()
                    },
                    interaction_deg
                ),
            );
        }

        // cols 7..11: verbatim `xor-state` (state_prev, chunk) →
        // state_new, 8 bytes.
        let verbatim_mult = p_rate_block.clone() * is_verbatim * act.clone();
        for pair in 0..4 {
            let i0 = pair * 2;
            let i1 = i0 + 1;
            frac_col!(
                builder,
                "byte-pair-lut",
                pair_deg,
                (
                    "xor-state-verbatim",
                    verbatim_mult.clone(),
                    BytePairLutMsg {
                        op: xor_tag.clone(),
                        a: state_prev_bytes[i0].into(),
                        b: chunk_bytes[i0].into(),
                        c: state_new_bytes[i0].into()
                    },
                    interaction_deg
                ),
                (
                    "xor-state-verbatim",
                    verbatim_mult.clone(),
                    BytePairLutMsg {
                        op: xor_tag.clone(),
                        a: state_prev_bytes[i1].into(),
                        b: chunk_bytes[i1].into(),
                        c: state_new_bytes[i1].into()
                    },
                    interaction_deg
                ),
            );
        }

        // cols 11..15: lane-16 `xor-lane16` (state_prev, PAD_CONST) →
        // state_new, 8 bytes. `PAD_CONST_BYTES` is a plain constant (not
        // selector-dependent), so the `b` field is a literal per byte.
        let lane16_mult = p_pad_0x80.clone() * b_sum.clone() * act.clone();
        for pair in 0..4 {
            let i0 = pair * 2;
            let i1 = i0 + 1;
            frac_col!(
                builder,
                "byte-pair-lut",
                pair_deg,
                (
                    "xor-lane16",
                    lane16_mult.clone(),
                    BytePairLutMsg {
                        op: xor_tag.clone(),
                        a: state_prev_bytes[i0].into(),
                        b: LB::Expr::from(Felt::from(PAD_CONST_BYTES[i0])),
                        c: state_new_bytes[i0].into()
                    },
                    interaction_deg
                ),
                (
                    "xor-lane16",
                    lane16_mult.clone(),
                    BytePairLutMsg {
                        op: xor_tag.clone(),
                        a: state_prev_bytes[i1].into(),
                        b: LB::Expr::from(Felt::from(PAD_CONST_BYTES[i1])),
                        c: state_new_bytes[i1].into()
                    },
                    interaction_deg
                ),
            );
        }

        // col 5: the KeccakSponge request + the chunk consume (a degree-4
        // multiplicity, paired → closing 5). Two independent inserts on
        // different buses, bus-prefix-distinguished encodings keeping the
        // contributions algebraically distinct.
        frac_col!(
            builder,
            "ks-and-chunk",
            mixed_deg,
            (
                "ks-request",
                act.clone() * is_first_row_of_invocation.clone(),
                KeccakSpongeMsg {
                    sponge_seq_id: sponge_seq_id.clone(),
                    chunk_ptr: chunk_ptr.clone(),
                    len_bytes: bytes_left.clone(),
                },
                interaction_deg
            ),
            (
                "chunk-consume",
                act.clone()
                    * (p_rate_block.clone() + p_extra.clone() * b_sum.clone())
                    * is_chunk_avail.clone(),
                Memory64Msg {
                    addr: addr_chunk.clone(),
                    lo: chunk_lo.clone(),
                    hi: chunk_hi.clone()
                },
                interaction_deg
            ),
        );
    }
}
