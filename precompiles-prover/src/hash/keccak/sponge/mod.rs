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
        LookupGroup, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, NUM_SIGMA_VALUES,
    },
    primitives::bitwise64::{Logic64Msg, Logic64Op},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{current_main, next_main},
};

// MAIN COLUMN LAYOUT
// ================================================================================================
//
// 27 main witness columns split into three groups:
//
// - Structural (5):    sponge_seq_id, act, bytes_left, is_first_block_of_invocation, chunk_ptr.
// - Padding state (10): is_zero_p, is_chunk_avail, b_0..b_7.
// - Per-row lane (12): chunk, state_prev, state_new, state_out, cleared, padded — each as u32
//   lo/hi.
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

/// Total number of main witness columns (5 structural + 10 padding-
/// state-machine + 12 per-row lane values).
pub const NUM_MAIN_COLS: usize = 27;

// AUX / PUBLIC LAYOUT
// ================================================================================================

/// Aux columns following the `bitwise64` chaining pattern. Col 0 is
/// the running-sum σ, hosts its own Memory64 mutex group, and
/// absorbs the per-row fraction values from cols 1, 2:
///
/// - col 0: running σ + Memory64 fractions (mutex group of state-lane + lane-16 0x80 batches, `u_g`
///   deg 4); absorbs col 1 and col 2 values into its running-sum recurrence.
/// - col 1: Logic64 fractions (mutex group of pad-row + verbatim + lane-16 0x80 batches).
/// - col 2: KeccakSponge + Memory64 chunk-consume fractions (one batch of 2 independent inserts;
///   different buses, bus-prefix- distinguished encodings).
///
/// Max per-LogUp-column constraint deg = 7 → `log_quotient_degree = 3`.
/// Col 0 hosts the σ-closing, so its last-row close is gated by the
/// degree-1 `is_transition` / `is_last_row` selector: it lands at
/// `deg(u_g) + 2 = 7` (was `1 + deg(u_g) = 5` under the older ungated
/// σ/n form). Col 1's per-row fraction degree lands at 6 (deg-2 outer
/// flags), col 2 at 5; col 0 dominates. See
/// the design notes §"Aux columns and σ exposure".
pub const NUM_AUX_COLS: usize = 3;

// The single exposed σ ([`NUM_SIGMA_VALUES`]) follows the VM-wide σ
// contract in [`crate::logup`]. The sponge's σ aggregates its net
// contribution across all three buses (Memory64, Logic64, KeccakSponge)
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
/// [`Memory64`](crate::hash::memory64) bus and the Bitwise64
/// chiplet's Logic64 bus, with the per-invocation request consumed
/// from the new [`KeccakSponge`](crate::relations::BusId::KeccakSponge)
/// bus.
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

// LOGIC64 MASK TABLES (indexed by `byte_offset ∈ [0, 8)`)
// ================================================================================================
//
// The pad-row Logic64 messages need two masks whose values are
// selected by the unary `b_j` selector bits: `andnot_mask` clears
// the bytes at and past `byte_offset`, and `padding_mask` places a
// `0x01` byte at `byte_offset`. Both are 64-bit values committed to
// the Logic64 bus as u32 lo/hi halves. The arrays below hold the
// per-`byte_offset` constants; the eval body builds
// `andnot_mask_lo = Σ_j b_j · ANDNOT_MASK_LO[j]` (and likewise for
// the other three halves) as a degree-1 witness inline.

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
        // pre-pad verbatim Bitwise64 XORs can't be steered by a
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

        // State propagation (no Bitwise64 fires) ----------------
        // Past-pad rate XORin rows: `state_new = state_prev`.
        builder.assert_zero(
            p_rate_block.clone() * is_zero.clone() * (state_new_lo.clone() - state_prev_lo.clone()),
        );
        builder
            .assert_zero(p_rate_block * is_zero * (state_new_hi.clone() - state_prev_hi.clone()));
        // Capacity rows: identity passthrough.
        builder.assert_zero(p_capacity.clone() * (state_new_lo - state_prev_lo));
        builder.assert_zero(p_capacity * (state_new_hi - state_prev_hi));

        // Phase 2: LogUp argument via the LogUp adapter.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR
// ================================================================================================

/// Per-column emission shape:
/// - col 0: 6 inserts (Memory64 group with 2 mutex batches — state-lane batch of 4, lane-16 0x80
///   batch of 2).
/// - col 1: 5 inserts (Logic64 group with 3 mutex batches — pad-row of 3, verbatim of 1, lane-16
///   0x80 of 1).
/// - col 2: 2 inserts (KeccakSponge + Memory64 chunk-consume, one batch of two independent
///   inserts). The chunk-consume fires on rate rows and, on the last block, the extra rows [26,29)
///   that mop up overshoot lanes (gated by `p_extra · b_sum`).
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [6, 5, 2];

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
        let cleared_lo: LB::Expr = local[COL_CLEARED_LO].into();
        let cleared_hi: LB::Expr = local[COL_CLEARED_HI].into();
        let padded_lo: LB::Expr = local[COL_PADDED_LO].into();
        let padded_hi: LB::Expr = local[COL_PADDED_HI].into();

        // Σ b_j (= `is_last_block_period`); `andnot_mask` and
        // `padding_mask` u32 halves as `Σ_j b_j · MASK[j]` inlines.
        let mut b_sum = LB::Expr::ZERO;
        let mut andnot_mask_lo = LB::Expr::ZERO;
        let mut andnot_mask_hi = LB::Expr::ZERO;
        let mut padding_mask_lo = LB::Expr::ZERO;
        let mut padding_mask_hi = LB::Expr::ZERO;
        for (j, col) in COL_B_RANGE.enumerate() {
            let b_j: LB::Expr = local[col].into();
            b_sum += b_j.clone();
            andnot_mask_lo += LB::Expr::from(Felt::from(ANDNOT_MASK_LO[j])) * b_j.clone();
            andnot_mask_hi += LB::Expr::from(Felt::from(ANDNOT_MASK_HI[j])) * b_j.clone();
            padding_mask_lo += LB::Expr::from(Felt::from(PADDING_MASK_LO[j])) * b_j.clone();
            padding_mask_hi += LB::Expr::from(Felt::from(PADDING_MASK_HI[j])) * b_j;
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
            LB::Expr::ZERO - LB::Expr::from(Felt::from(3u8)) * act.clone() * p_rc_active;
        let mult_squeeze: LB::Expr =
            LB::Expr::from(Felt::from(2u8)) * act.clone() * p_squeeze_active * b_sum.clone();
        let mult_lane16_consume: LB::Expr =
            LB::Expr::from(Felt::from(2u8)) * act.clone() * b_sum.clone();
        let mult_lane16_provide: LB::Expr =
            LB::Expr::ZERO - LB::Expr::from(Felt::from(2u8)) * act.clone() * b_sum.clone();

        let andnot_op = LB::Expr::from(Felt::from(Logic64Op::AndNot.tag()));
        let xor_op = LB::Expr::from(Felt::from(Logic64Op::Xor.tag()));

        let interaction_deg = Deg { v: 1, u: 1 };
        // Col 0 Memory64 mutex group: d_A = 4 (state-lane batch),
        // d_B = 2 (lane-16 0x80 batch); periodic outer flags.
        let m64_batch_a_deg = Deg { v: 4, u: 4 };
        let m64_batch_b_deg = Deg { v: 2, u: 2 };
        let m64_group_deg = Deg { v: 5, u: 4 };
        // Col 1 Logic64 mutex group: d_C = 3 (pad-row batch), d_D
        // = d_E = 1 (verbatim, lane-16); witness outer flags (deg 1).
        let l64_batch_c_deg = Deg { v: 3, u: 3 };
        let l64_batch_d_deg = Deg { v: 1, u: 1 };
        let l64_batch_e_deg = Deg { v: 1, u: 1 };
        let l64_group_deg = Deg { v: 4, u: 4 };
        // Col 2 KS + chunk-consume batch. The chunk-consume mult now
        // carries `p_extra · b_sum` (last-block extra-lane gate), so its
        // degree is 4 (act · (p_rate_block + p_extra·b_sum) ·
        // is_chunk_avail); the KS-request mult stays deg 3. Still one
        // tier below the col-0 group → the chiplet stays log_quot 3.
        let aux_batch_deg = Deg { v: 4, u: 2 };

        // ---- col 0: Memory64 — state-lane (4) ⊕ lane-16 0x80 (2) ----
        builder.next_column(
            |col| {
                col.group(
                    "memory64",
                    |g| {
                        // Batch A — state-lane rows.
                        g.batch(
                            "state-lane",
                            p_state_lane.clone(),
                            |b| {
                                b.insert(
                                    "prev-perm",
                                    mult_prev_perm,
                                    Memory64Msg {
                                        addr: addr_state_lane_prev,
                                        lo: state_prev_lo.clone(),
                                        hi: state_prev_hi.clone(),
                                    },
                                    interaction_deg,
                                );
                                b.insert(
                                    "new-state",
                                    mult_new_state,
                                    Memory64Msg {
                                        addr: addr_state_lane_new,
                                        lo: state_new_lo.clone(),
                                        hi: state_new_hi.clone(),
                                    },
                                    interaction_deg,
                                );
                                b.insert(
                                    "rc",
                                    mult_rc,
                                    Memory64Msg { addr: addr_rc, lo: rc_lo, hi: rc_hi },
                                    interaction_deg,
                                );
                                b.insert(
                                    "squeeze",
                                    mult_squeeze,
                                    Memory64Msg {
                                        addr: addr_squeeze,
                                        lo: state_out_lo,
                                        hi: state_out_hi,
                                    },
                                    interaction_deg,
                                );
                            },
                            m64_batch_a_deg,
                        );
                        // Batch B — lane-16 0x80 row.
                        g.batch(
                            "lane16-0x80",
                            p_pad_0x80.clone(),
                            |b| {
                                b.insert(
                                    "lane16-consume",
                                    mult_lane16_consume,
                                    Memory64Msg {
                                        addr: addr_lane16.clone(),
                                        lo: state_prev_lo.clone(),
                                        hi: state_prev_hi.clone(),
                                    },
                                    interaction_deg,
                                );
                                b.insert(
                                    "lane16-provide",
                                    mult_lane16_provide,
                                    Memory64Msg {
                                        addr: addr_lane16,
                                        lo: state_new_lo.clone(),
                                        hi: state_new_hi.clone(),
                                    },
                                    interaction_deg,
                                );
                            },
                            m64_batch_b_deg,
                        );
                    },
                    m64_group_deg,
                );
            },
            m64_group_deg,
        );

        // ---- col 1: Logic64 — pad (3) ⊕ verbatim (1) ⊕ lane-16 (1) ----
        builder.next_column(
            |col| {
                col.group(
                    "logic64",
                    |g| {
                        // Batch C — pad row.
                        g.batch(
                            "pad-row",
                            p_rate_block.clone() * is_pad,
                            |b| {
                                b.insert(
                                    "andnot",
                                    act.clone(),
                                    Logic64Msg {
                                        op: andnot_op.clone(),
                                        a_lo: andnot_mask_lo,
                                        a_hi: andnot_mask_hi,
                                        b_lo: chunk_lo.clone(),
                                        b_hi: chunk_hi.clone(),
                                        c_lo: cleared_lo.clone(),
                                        c_hi: cleared_hi.clone(),
                                    },
                                    interaction_deg,
                                );
                                b.insert(
                                    "xor-padding",
                                    act.clone(),
                                    Logic64Msg {
                                        op: xor_op.clone(),
                                        a_lo: cleared_lo,
                                        a_hi: cleared_hi,
                                        b_lo: padding_mask_lo,
                                        b_hi: padding_mask_hi,
                                        c_lo: padded_lo.clone(),
                                        c_hi: padded_hi.clone(),
                                    },
                                    interaction_deg,
                                );
                                b.insert(
                                    "xor-state",
                                    act.clone(),
                                    Logic64Msg {
                                        op: xor_op.clone(),
                                        a_lo: state_prev_lo.clone(),
                                        a_hi: state_prev_hi.clone(),
                                        b_lo: padded_lo,
                                        b_hi: padded_hi,
                                        c_lo: state_new_lo.clone(),
                                        c_hi: state_new_hi.clone(),
                                    },
                                    interaction_deg,
                                );
                            },
                            l64_batch_c_deg,
                        );
                        // Batch D — verbatim row.
                        g.batch(
                            "verbatim",
                            p_rate_block.clone() * is_verbatim,
                            |b| {
                                b.insert(
                                    "xor-state",
                                    act.clone(),
                                    Logic64Msg {
                                        op: xor_op.clone(),
                                        a_lo: state_prev_lo.clone(),
                                        a_hi: state_prev_hi.clone(),
                                        b_lo: chunk_lo.clone(),
                                        b_hi: chunk_hi.clone(),
                                        c_lo: state_new_lo.clone(),
                                        c_hi: state_new_hi.clone(),
                                    },
                                    interaction_deg,
                                );
                            },
                            l64_batch_d_deg,
                        );
                        // Batch E — lane-16 0x80 row.
                        g.batch(
                            "lane16-0x80",
                            p_pad_0x80.clone() * b_sum.clone(),
                            |b| {
                                b.insert(
                                    "xor",
                                    act.clone(),
                                    Logic64Msg {
                                        op: xor_op,
                                        a_lo: state_prev_lo,
                                        a_hi: state_prev_hi,
                                        b_lo: LB::Expr::from(Felt::from(PAD_CONST_LO)),
                                        b_hi: LB::Expr::from(Felt::from(PAD_CONST_HI)),
                                        c_lo: state_new_lo,
                                        c_hi: state_new_hi,
                                    },
                                    interaction_deg,
                                );
                            },
                            l64_batch_e_deg,
                        );
                    },
                    l64_group_deg,
                );
            },
            l64_group_deg,
        );

        // ---- col 2: KeccakSponge + Memory64 chunk consume -----
        // Two independent inserts on different buses, outer flag 1.
        // Bus-prefix-distinguished encodings keep the contributions
        // algebraically distinct.
        builder.next_column(
            |col| {
                col.group(
                    "ks-and-chunk",
                    |g| {
                        g.batch(
                            "fractions",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "ks-request",
                                    act.clone() * is_first_row_of_invocation,
                                    KeccakSpongeMsg {
                                        sponge_seq_id,
                                        chunk_ptr: chunk_ptr.clone(),
                                        len_bytes: bytes_left,
                                    },
                                    interaction_deg,
                                );
                                b.insert(
                                    "chunk-consume",
                                    act * (p_rate_block + p_extra * b_sum) * is_chunk_avail,
                                    Memory64Msg {
                                        addr: addr_chunk,
                                        lo: chunk_lo,
                                        hi: chunk_hi,
                                    },
                                    interaction_deg,
                                );
                            },
                            aux_batch_deg,
                        );
                    },
                    aux_batch_deg,
                );
            },
            aux_batch_deg,
        );
    }
}
