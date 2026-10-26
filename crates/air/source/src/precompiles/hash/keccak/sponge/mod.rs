//! Keccak sponge chiplet.
//!
//! Sponge AIR over the [round chiplet's](super::round) 25-round /
//! 3200-IP permutation cycle. One row per state lane, period 32 →
//! α = 100.

pub mod message;
pub mod program;

use alloc::{borrow::Cow, vec::Vec};
use core::{array, ops::Range};

pub use message::KeccakSpongeMsg;
use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_stark::air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};
use miden_utils_sync::LazyLock;
pub use program::{NUM_PERIODIC_COLS, SPONGE_PERIOD, sponge_program};

use miden_stark::lookup::{
    ConstraintLookupBuilder,
    Deg,
    LookupAir,
    LookupBatch,
    LookupBuilder,
    LookupColumn,
    LookupGroup,
};
use crate::precompiles::{
    hash::memory64::{CHUNK_ADDR_BASE, Memory64Msg},
    logup::{NUM_LOGUP_VALUES, NUM_RANDOMNESS, frac_col},
    primitives::byte_pair_lut::BytePairLutMsg,
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{current_main, halves_le, next_main},
};

// MAIN COLUMN LAYOUT
// ================================================================================================
//
// Forty columns bind the input tape, compact padding state, and Keccak permutation lanes:
//
// - Structural (5):    sponge_seq_id, act, bytes_left, is_first_block_of_invocation, chunk_ptr.
// - Padding state (9): is_zero, is_chunk_avail, pad block, three offset bits, their low-bit
//   product, and two suffix limbs.
// - Squeeze value (2): state_out as u32 lo/hi.
// - Byte lanes (24): chunk, state_prev, state_new, each an 8-byte little-endian decomposition.
//   Their u32 halves are reconstructed linearly where needed.
//
// Structural columns.
// --------------------------------------------------------------------

/// Global sponge row counter, +1 per row. Plays the role of the round
/// chiplet's `ip`; every per-row address is a degree-1 expression in
/// `sponge_seq_id` and the period-32 `p_idx`. Carried in the
/// `KeccakSponge` request tuple so the transcript chiplet can derive
/// the digest address in the round chiplet's IP space.
pub const COL_SPONGE_SEQ_ID: usize = 0;
/// Sticky-downward activity flag. Inactive rows are forced past absorption with no pad block,
/// so all lookup multiplicities vanish on the trace tail.
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
/// `(p_rate_block + p_extra · pad_block) · is_chunk_avail` within the
/// invocation (rate rows on absorption blocks, plus the padded block's extra
/// rows mopping up overshoot lanes); jumps freely at invocation seams
/// (the chain is gated off there — see the `chunk_ptr` increment chain
/// in `eval`). Used as the address
/// offset in `chunk-consume-addr = CHUNK_ADDR_BASE + chunk_ptr`.
pub const COL_CHUNK_PTR: usize = 4;

// Padding state machine columns.
// --------------------------------------------------------------------

/// One after this block's padding lane and on inactive rows.
/// Monotone non-decreasing within each 32-row period.
pub const COL_IS_ZERO: usize = 5;
/// Chunks-available indicator on rate XORin rows; monotone
/// non-increasing within the period (once chunks run out, they stay
/// out — a single contiguous prefix). A rate row (or, on the last block,
/// an extra row) with `is_chunk_avail = 1` consumes a tape lane; the flag
/// is forced to 1 on every rate row whose lane carries message bytes. On a
/// last block that overshoots the rate, the prefix carries through the
/// inert capacity / 0x80 rows so the rate rows and the extra rows [26,29)
/// stay one prefix.
pub const COL_IS_CHUNK_AVAIL: usize = 6;
/// One on the padded absorption block; zero elsewhere.
pub const COL_IS_PAD_BLOCK: usize = 7;
/// Three little-endian bits of the suffix byte offset, constant within a period.
pub const OFFSET_BITS_RANGE: Range<usize> = 8..11;
/// Product of the two low offset bits, reducing offset selectors to degree two.
pub const COL_OFFSET_PRODUCT: usize = 11;
/// Delimited suffix shifted to its byte position, as two u32 limbs on the pad row.
pub const COL_PAD_LO: usize = 12;
pub const COL_PAD_HI: usize = 13;

// Squeeze-value columns.
// --------------------------------------------------------------------

/// Current permutation's output lane, as two u32 halves. The sponge consumes the round-output
/// copies not used by the next permutation or the node's fixed Keccak digest read.
pub const COL_STATE_OUT_LO: usize = 14;
pub const COL_STATE_OUT_HI: usize = 15;

// Byte-decomposed lane columns.
// --------------------------------------------------------------------
//
// The chunk bytes include the delimited suffix on the pad row. Subtracting COL_PAD_LO/HI
// reconstructs the committed input lane; byte-pair lookups verify the state XORs.
pub const CHUNK_BYTES_RANGE: Range<usize> = 16..24;
pub const STATE_PREV_BYTES_RANGE: Range<usize> = 24..32;
pub const STATE_NEW_BYTES_RANGE: Range<usize> = 32..40;

/// Total number of main witness columns.
pub const NUM_MAIN_COLS: usize = 40;

// AUX / PUBLIC LAYOUT
// ================================================================================================

/// Five lookup columns: two for state/round memory, two for byte operations, and one for
/// the input handshake and chunks. Maximum degree is five.
pub const NUM_AUX_COLS: usize = 5;

// One accumulator combines Memory64, BytePairLut, and KeccakSponge interactions.
// Encoded bus prefixes distinguish the relations under the shared LogUp challenges.

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

/// Keccak sponge chiplet AIR. The period-32 program drives one permutation's absorption,
/// capacity passthrough, and padding over the [`Memory64`](crate::precompiles::hash::memory64) bus.
/// Local constraints enforce zero input padding and select the suffix; state XORs are checked
/// against [`BytePairLut`](crate::precompiles::primitives::byte_pair_lut). The per-invocation
/// request is consumed from the
/// [`KeccakSponge`](crate::precompiles::relations::BusId::KeccakSponge) bus.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeccakSpongeAir;

static PERIODIC_COLUMNS: LazyLock<[Vec<Felt>; NUM_PERIODIC_COLS]> = LazyLock::new(sponge_program);

impl BaseAir<Felt> for KeccakSpongeAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        Cow::Borrowed(PERIODIC_COLUMNS.as_slice())
    }
}

/// Byte `i` (LSB-first) of the lane-16 trailing-`0x80` constant.
pub const PAD_CONST_BYTES: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0x80];

/// For boolean bits and `product = b0 * b1`, returns one-hot offset selectors of degree two.
fn offset_selectors<E: Algebra<Felt>>([b0, b1, b2]: [E; 3], product: E) -> [E; 8] {
    let low = [
        E::ONE - b0.clone() - b1.clone() + product.clone(),
        b0 - product.clone(),
        b1 - product.clone(),
        product,
    ];
    array::from_fn(|i| low[i % 4].clone() * if i < 4 { E::ONE - b2.clone() } else { b2.clone() })
}

// LIFTED AIR
// ================================================================================================

impl LiftedAir<Felt, QuadFelt> for KeccakSpongeAir {
    fn max_periodic_length(&self) -> usize {
        SPONGE_PERIOD
    }

    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        NUM_AUX_COLS
    }

    fn num_aux_values(&self) -> usize {
        NUM_LOGUP_VALUES
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        miden_stark::lookup::build_logup_aux_trace(&KeccakSpongeAir, main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        eval_main(builder, 0);

        // Phase 2: LogUp.
        let mut lb = ConstraintLookupBuilder::new(builder, self);
        <Self as LookupAir<_>>::eval(self, &mut lb);
        lb.finish();
    }
}

/// Evaluate this component's base constraints in a main-trace column band.
pub(crate) fn eval_main<AB>(builder: &mut AB, main_col_offset: usize)
where
    AB: LiftedAirBuilder<F = Felt>,
{
    eval_main_inner(builder, main_col_offset, false);
}

/// Evaluate sponge constraints without zero-filling capacity-row chunk cells.
///
/// The composite node/chunk AIR uses these cells for its serialized records.
pub(crate) fn eval_main_with_shared_capacity<AB: LiftedAirBuilder<F = Felt>>(
    builder: &mut AB,
    main_col_offset: usize,
) {
    eval_main_inner(builder, main_col_offset, true);
}

fn eval_main_inner<AB: LiftedAirBuilder<F = Felt>>(
    builder: &mut AB,
    main_col_offset: usize,
    shared_capacity: bool,
) {
    // Phase 1: local row constraints.
    let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), main_col_offset);
    // Next-row window at row r+1. Cyclic at
    // row N-1 (`when_transition` gates out the wrap explicitly
    // where needed; other transition constraints rely on
    // `p_last`/`p_rate_block` factors making the wrap vacuous).
    let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), main_col_offset);

    let periodic = builder.periodic_values();
    let p_first: AB::Expr = periodic[PCOL_FIRST].into();
    let p_last: AB::Expr = periodic[PCOL_LAST].into();
    let p_rate_block: AB::Expr = periodic[PCOL_RATE_BLOCK].into();
    let p_capacity: AB::Expr = periodic[PCOL_CAPACITY].into();
    let p_extra: AB::Expr = periodic[PCOL_EXTRA].into();
    let p_pad_0x80: AB::Expr = periodic[PCOL_PAD_0X80].into();
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
    let pad_block: AB::Expr = local[COL_IS_PAD_BLOCK].into();
    let is_zero: AB::Expr = local[COL_IS_ZERO].into();
    let is_zero_next: AB::Expr = next[COL_IS_ZERO].into();
    let is_chunk_avail: AB::Expr = local[COL_IS_CHUNK_AVAIL].into();
    let is_chunk_avail_next: AB::Expr = next[COL_IS_CHUNK_AVAIL].into();
    let chunk_bytes: [AB::Var; 8] = array::from_fn(|i| local[CHUNK_BYTES_RANGE.start + i]);
    let state_prev_bytes: [AB::Var; 8] =
        array::from_fn(|i| local[STATE_PREV_BYTES_RANGE.start + i]);
    let state_new_bytes: [AB::Var; 8] = array::from_fn(|i| local[STATE_NEW_BYTES_RANGE.start + i]);
    let [chunk_lo, chunk_hi]: [AB::Expr; 2] = halves_le(&chunk_bytes, 256);
    let chunk_lo = chunk_lo - local[COL_PAD_LO];
    let chunk_hi = chunk_hi - local[COL_PAD_HI];
    let [state_prev_lo, state_prev_hi]: [AB::Expr; 2] = halves_le(&state_prev_bytes, 256);
    let [state_new_lo, state_new_hi]: [AB::Expr; 2] = halves_le(&state_new_bytes, 256);

    let bits: [AB::Expr; 3] = array::from_fn(|i| local[OFFSET_BITS_RANGE.start + i].into());
    let product: AB::Expr = local[COL_OFFSET_PRODUCT].into();
    builder.assert_eq(product.clone(), bits[0].clone() * bits[1].clone());
    let selected = offset_selectors(bits.clone(), product.clone());
    let byte_offset = bits[0].clone()
        + AB::Expr::from(Felt::from(2u8)) * bits[1].clone()
        + AB::Expr::from(Felt::from(4u8)) * bits[2].clone();

    // The padded bytes contain only the suffix at and after the selected offset. The two
    // suffix limbs are subtracted for the input read, leaving canonical zero input padding.
    let pad_row = p_rate_block.clone() * (is_zero_next.clone() - is_zero.clone());
    // Linear expansion of 256^(b0 + 2*b1) using the witnessed low-bit product.
    let shift = AB::Expr::ONE
        + AB::Expr::from(Felt::from(255u8)) * bits[0].clone()
        + AB::Expr::from(Felt::from(65535u32)) * bits[1].clone()
        + AB::Expr::from(Felt::from(16711425u32)) * product;
    builder.assert_eq(
        local[COL_PAD_LO],
        pad_row.clone() * (AB::Expr::ONE - bits[2].clone()) * shift.clone(),
    );
    builder.assert_eq(local[COL_PAD_HI], pad_row.clone() * bits[2].clone() * shift);
    let mut past_suffix = AB::Expr::ZERO;
    for (i, selector) in selected.iter().enumerate() {
        let byte: AB::Expr = chunk_bytes[i].into();
        past_suffix += selector.clone();
        builder.assert_zero(pad_row.clone() * (past_suffix.clone() * byte - selector.clone()));
    }
    // On the active lane-16 padding row, BytePairLut checks chunk_bytes[7] + 128 as a byte
    // and the other seven bytes directly, so the top byte lies in [-128, 127]. Its lower
    // three bytes cannot cancel a nonzero top byte in a zero packed high half, and all
    // magnitudes are below the field modulus. Both zero halves therefore pin every chunk
    // byte to zero, leaving only the fixed 0x80 lookup operand.
    builder.assert_zero(p_pad_0x80.clone() * chunk_lo.clone());
    builder.assert_zero(p_pad_0x80 * chunk_hi.clone());

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
    // (`pad_block = 1`). Equivalent to `act · (1 - act')` under the
    // sticky-down constraint above; the linear form costs one
    // fewer witness multiplication.
    builder.when_transition().assert_zero(
        (act.clone() - act_next) * (AB::Expr::ONE - p_last.clone() * pad_block.clone()),
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
        (AB::Expr::ONE - p_last.clone()) * (is_first_block_next.clone() - is_first_block.clone()),
    );

    // `bytes_left` decrement chain --------------------------
    // Activity gating admits the zero-invocation trace. Counter transitions out of inactive
    // rows are unconstrained; active rows can reset the counter only at invocation seams.
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
    // (p_rate_block + p_extra · pad_block) · is_chunk_avail = 0 (advance
    // by 1 per consumed chunk lane). Rate rows consume on every
    // absorption block; the extra rows consume the padded block's overshoot
    // lanes (gated by `pad_block`), so `chunk_ptr`
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
                - (p_rate_block.clone() + p_extra.clone() * pad_block.clone())
                    * is_chunk_avail.clone()),
    );

    // Chunk zero-fill on `is_chunk_avail = 0` --------------
    // An unavailable input lane reconstructs as zero. Its padded bytes can still contain
    // the suffix when the message ends at byte zero.
    let zero_fill = if shared_capacity {
        AB::Expr::ONE - p_capacity.clone()
    } else {
        AB::Expr::ONE
    };
    builder.assert_zero(
        zero_fill.clone() * (AB::Expr::ONE - is_chunk_avail.clone()) * chunk_lo.clone(),
    );
    builder.assert_zero(zero_fill * (AB::Expr::ONE - is_chunk_avail.clone()) * chunk_hi.clone());

    // Message lanes come from the tape ----------------------
    // A rate row whose lane carries message bytes must consume a tape
    // lane: every verbatim row, and the pad row unless the pad sits at
    // byte 0. Otherwise such a row would absorb a zero lane while the
    // skipped tape lanes are consumed later, on rows that ignore them.
    builder.assert_zero(
        act.clone()
            * p_rate_block.clone()
            * (AB::Expr::ONE - is_zero.clone())
            * bytes_left.clone()
            * (AB::Expr::ONE - is_chunk_avail.clone()),
    );

    // Tape bytes after the message are zero -----------------
    // The chunk encoding zero-pads the last chunk: a lane consumed past
    // the pad is zero. The pad lane's suffix and higher bytes are constrained above.
    let past_pad = (p_rate_block.clone() + p_extra) * is_zero.clone();
    builder.assert_zero(act.clone() * past_pad.clone() * chunk_lo);
    builder.assert_zero(act.clone() * past_pad * chunk_hi);

    // Padding state machine ---------------------------------
    // Binarity.
    builder.assert_bool(local[COL_IS_ZERO]);
    builder.assert_bool(local[COL_IS_CHUNK_AVAIL]);
    builder.assert_bool(local[COL_IS_PAD_BLOCK]);
    for col in OFFSET_BITS_RANGE {
        builder.assert_bool(local[col]);
        builder.assert_zero((AB::Expr::ONE - pad_block.clone()) * local[col]);
    }

    // `is_zero` non-decreasing within period.
    builder.assert_zero(
        (AB::Expr::ONE - p_last.clone()) * is_zero.clone() * (AB::Expr::ONE - is_zero_next.clone()),
    );
    // `is_chunk_avail` non-increasing within period.
    builder.assert_zero(
        (AB::Expr::ONE - p_last.clone()) * (AB::Expr::ONE - is_chunk_avail) * is_chunk_avail_next,
    );
    // Active blocks start before padding; inactive blocks start past it.
    builder.assert_zero(p_first * (is_zero.clone() + act.clone() - AB::Expr::ONE));
    // Pad-block and offset bits are constant within a period.
    for col in COL_IS_PAD_BLOCK..OFFSET_BITS_RANGE.end {
        builder.assert_zero((AB::Expr::ONE - p_last.clone()) * (next[col] - local[col]));
    }
    // At active capacity/slack rows, is_zero identifies the padded block; inactive rows use 1.
    builder.assert_zero(
        (AB::Expr::ONE - p_rate_block.clone())
            * (pad_block.clone() + AB::Expr::ONE - act.clone() - is_zero.clone()),
    );

    // An active first row starts an invocation; an active last row belongs to a padded block.
    builder
        .when_first_row()
        .assert_zero(act.clone() * (AB::Expr::ONE - is_first_block.clone()));
    builder.when_last_row().assert_zero(act * (AB::Expr::ONE - pad_block.clone()));
    // A new invocation follows exactly a padded block, preventing truncation. Check only active
    // successors and non-wrapping transitions so inactive tails remain admissible.
    builder
        .when_transition()
        .assert_zero(p_last * next[COL_ACT] * (is_first_block_next - pad_block));

    // Pad-lane tie-down -------------------------------------
    // On the unique pad transition row (`p_rate_block = 1`,
    // `is_pad = 1`), pin `byte_offset = bytes_left`. Vacuous
    // everywhere else. The `p_rate_block` gate also absorbs
    // the period-wrap `is_pad = −1` case, which always lands
    // on `p_idx = 31` where `p_rate_block = 0`.
    let is_pad: AB::Expr = is_zero_next - is_zero.clone();
    builder.assert_zero(p_rate_block.clone() * is_pad * (byte_offset - bytes_left));

    // state_prev = 0 on first-block state-lane rows ---------
    builder.assert_zero(p_state_lane.clone() * is_first_block.clone() * state_prev_lo.clone());
    builder.assert_zero(p_state_lane * is_first_block * state_prev_hi.clone());

    // State propagation (no BytePairLut request fires) --------
    // Past-pad rate XORin rows: `state_new = state_prev`.
    builder.assert_zero(
        p_rate_block.clone() * is_zero.clone() * (state_new_lo.clone() - state_prev_lo.clone()),
    );
    builder.assert_zero(p_rate_block * is_zero * (state_new_hi.clone() - state_prev_hi.clone()));
    // Capacity rows: identity passthrough.
    builder.assert_zero(p_capacity.clone() * (state_new_lo - state_prev_lo));
    builder.assert_zero(p_capacity * (state_new_hi - state_prev_hi));
}

// LOOKUP AIR
// ================================================================================================

/// Lookup insert counts. Linear byte operands permit four-fraction batches at degree five.
pub(crate) const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [
    3, 3, // Memory64 state/round outputs, rc/lane-16.
    4, 4, // State XOR bytes.
    2, // KeccakSponge request + chunk consume.
];

impl<LB> LookupAir<LB> for KeccakSpongeAir
where
    LB: LookupBuilder<F = Felt>,
{
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
        eval_lookups(builder, 0);
    }
}

/// Evaluate this component's LogUp columns in a main-trace column band.
pub(crate) fn eval_lookups<LB>(builder: &mut LB, main_col_offset: usize)
where
    LB: LookupBuilder<F = Felt>,
{
    let local: [LB::Var; NUM_MAIN_COLS] = current_main(builder.main(), main_col_offset);
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
    let state_out_lo: LB::Expr = local[COL_STATE_OUT_LO].into();
    let state_out_hi: LB::Expr = local[COL_STATE_OUT_HI].into();
    let chunk_bytes: [LB::Var; 8] = array::from_fn(|i| local[CHUNK_BYTES_RANGE.start + i]);
    let state_prev_bytes: [LB::Var; 8] =
        array::from_fn(|i| local[STATE_PREV_BYTES_RANGE.start + i]);
    let state_new_bytes: [LB::Var; 8] = array::from_fn(|i| local[STATE_NEW_BYTES_RANGE.start + i]);
    let [chunk_lo, chunk_hi]: [LB::Expr; 2] = halves_le(&chunk_bytes, 256);
    let chunk_lo = chunk_lo - local[COL_PAD_LO];
    let chunk_hi = chunk_hi - local[COL_PAD_HI];
    let [state_prev_lo, state_prev_hi]: [LB::Expr; 2] = halves_le(&state_prev_bytes, 256);
    let [state_new_lo, state_new_hi]: [LB::Expr; 2] = halves_le(&state_new_bytes, 256);

    let pad_block: LB::Expr = local[COL_IS_PAD_BLOCK].into();

    // Derived multiplicity signals.
    let is_intra: LB::Expr = LB::Expr::ONE - is_first_block.clone();
    let is_first_row_of_invocation: LB::Expr = p_first * is_first_block;
    let is_absorb: LB::Expr = LB::Expr::ONE - is_zero;

    // Per-row address expressions.
    let hundred_seq = LB::Expr::from(Felt::from(100u8)) * sponge_seq_id.clone();
    let ninety_nine_idx = LB::Expr::from(Felt::from(99u8)) * p_idx.clone();
    let addr_state_lane_prev =
        hundred_seq.clone() - ninety_nine_idx.clone() - LB::Expr::from(Felt::from(128u8));
    let addr_state_lane_new = hundred_seq.clone() - ninety_nine_idx.clone();
    let addr_rc = hundred_seq.clone()
        + LB::Expr::from(Felt::from(28u8)) * p_idx
        + LB::Expr::from(Felt::from(25u8));
    let addr_squeeze = hundred_seq.clone() - ninety_nine_idx + LB::Expr::from(Felt::from(3072u32));
    let addr_lane16 = hundred_seq - LB::Expr::from(Felt::from(2484u32));
    let chunk_addr_base =
        Felt::new(CHUNK_ADDR_BASE).expect("CHUNK_ADDR_BASE fits in canonical Goldilocks");
    let addr_chunk = LB::Expr::from(chunk_addr_base) + chunk_ptr.clone();

    // Memory multiplicities vanish on inactive rows, where act and pad_block are zero.
    let mult_prev_perm: LB::Expr = act.clone() * is_intra;
    let mult_new_state: LB::Expr = LB::Expr::ZERO - LB::Expr::from(Felt::from(2u8)) * act.clone();
    let mult_rc: LB::Expr =
        LB::Expr::ZERO - LB::Expr::from(Felt::from(1u8)) * act.clone() * p_rc_active;
    // Each round output has two copies. A continuation reads one; the final digest reader
    // reads one of lanes 0..4. This band consumes the remaining copies.
    let mult_squeeze = act.clone() * p_state_lane.clone() + pad_block.clone() * p_squeeze_active;
    let mult_lane16_consume: LB::Expr =
        LB::Expr::from(Felt::from(2u8)) * act.clone() * pad_block.clone();
    let mult_lane16_provide: LB::Expr =
        LB::Expr::ZERO - LB::Expr::from(Felt::from(2u8)) * act.clone() * pad_block.clone();

    let new_state_deg = Deg { v: 2, u: 1 };
    let selected_interaction_deg = Deg { v: 3, u: 1 };
    let squeeze_interaction_deg = Deg { v: 2, u: 1 };
    let chunk_interaction_deg = Deg { v: 4, u: 1 };
    // Direct product batching preserves each original fraction. Group and column hints encode the
    // per-entry multiplicity and denominator degrees listed below.
    let triple_deg = Deg { v: 5, u: 3 };
    let mixed_deg = Deg { v: 5, u: 2 };

    // The centered Memory64 column combines input-state and round-output reads at degree five.
    frac_col!(
        builder,
        "memory64",
        triple_deg,
        (
            "new-state",
            p_state_lane.clone() * mult_new_state.clone(),
            Memory64Msg {
                addr: addr_state_lane_new.clone(),
                lo: state_new_lo.clone(),
                hi: state_new_hi.clone(),
            },
            new_state_deg
        ),
        (
            "prev-perm",
            p_state_lane.clone() * mult_prev_perm.clone(),
            Memory64Msg {
                addr: addr_state_lane_prev.clone(),
                lo: state_prev_lo.clone(),
                hi: state_prev_hi.clone(),
            },
            selected_interaction_deg
        ),
        (
            "squeeze",
            mult_squeeze,
            Memory64Msg {
                addr: addr_squeeze,
                lo: state_out_lo,
                hi: state_out_hi,
            },
            squeeze_interaction_deg
        ),
    );
    // Memory64 round constants and lane-16 0x80 consume/provide.
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
            selected_interaction_deg
        ),
        (
            "lane16-consume",
            p_pad_0x80.clone() * mult_lane16_consume.clone(),
            Memory64Msg {
                addr: addr_lane16.clone(),
                lo: state_prev_lo.clone(),
                hi: state_prev_hi.clone(),
            },
            selected_interaction_deg
        ),
        (
            "lane16-provide",
            p_pad_0x80.clone() * mult_lane16_provide.clone(),
            Memory64Msg {
                addr: addr_lane16.clone(),
                lo: state_new_lo.clone(),
                hi: state_new_hi.clone(),
            },
            selected_interaction_deg
        ),
    );

    // Inactive rows are already past absorption and have no pad-block flag.
    let xor_mult = p_rate_block.clone() * is_absorb + p_pad_0x80.clone() * pad_block.clone();
    for begin in [0, 4] {
        let degree = Deg { v: 5, u: 4 };
        builder.next_column(
            |column| {
                column.group(
                    "byte-pair-lut",
                    |group| {
                        group.batch(
                            "bytes",
                            LB::Expr::ONE,
                            |batch| {
                                for (i, &byte) in chunk_bytes.iter().enumerate().skip(begin).take(4)
                                {
                                    let operand = LB::Expr::from(byte)
                                        + p_pad_0x80.clone()
                                            * LB::Expr::from(Felt::from(PAD_CONST_BYTES[i]));
                                    batch.insert(
                                        "xor-state",
                                        xor_mult.clone(),
                                        BytePairLutMsg::from_xor(
                                            state_prev_bytes[i].into(),
                                            operand,
                                            state_new_bytes[i].into(),
                                        ),
                                        Deg { v: 2, u: 1 },
                                    );
                                }
                            },
                            degree,
                        );
                    },
                    degree,
                );
            },
            degree,
        );
    }

    // The KeccakSponge request + the chunk consume (a degree-4
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
            selected_interaction_deg
        ),
        (
            "chunk-consume",
            act.clone()
                * (p_rate_block.clone() + p_extra.clone() * pad_block.clone())
                * is_chunk_avail.clone(),
            Memory64Msg {
                addr: addr_chunk.clone(),
                lo: chunk_lo.clone(),
                hi: chunk_hi.clone()
            },
            chunk_interaction_deg
        ),
    );
}
