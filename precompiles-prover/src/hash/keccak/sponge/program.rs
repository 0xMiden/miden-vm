//! Sponge program: 32-slot period encoded as 9 periodic columns.
//!
//! Each period drives one Keccak permutation. The slot layout is:
//!
//! ```text
//! [ 0, 17)  Rate XORin (lane i = p_idx, RC[i] provide on i ∈ [0, 24))
//! [17, 25)  Capacity (lane i = p_idx, RC[i] provide on i ∈ [17, 24))
//! [25, 26)  Lane-16 trailing-`0x80` row (Bitwise64 XOR with 0x80…00)
//! [26, 29)  Extra chunk-consume (last-block overshoot lanes)
//! [29, 32)  NOP slack
//! ```
//!
//! See `docs/chiplets/keccak-sponge.md` for the design.
//!
//! Periodic columns:
//!
//! - `p_idx` — integer `[0, 32)`; degree-1 base for address expressions.
//! - `p_first` — 1 iff `p_idx == 0`; row-0-of-period boundary.
//! - `p_rate_block` — 1 iff `p_idx ∈ [0, 17)`; rate XORin rows.
//! - `p_capacity` — 1 iff `p_idx ∈ [17, 25)`; capacity rows.
//! - `p_rc_active` — 1 iff `p_idx ∈ [0, 24)`; rows where the sponge provides `RC[p_idx]` to the
//!   round chiplet (Keccak has only 24 RCs, so slot 24 — the last capacity lane — carries no RC).
//! - `p_squeeze_active` — 1 iff `p_idx ∈ [4, 25)`; non-digest state-lane rows that consume the
//!   last-perm output on last-block periods.
//! - `p_pad_0x80` — 1 iff `p_idx == 25`; the dedicated lane-16 0x80 row.
//! - `p_extra` — 1 iff `p_idx ∈ [26, 29)`; extra chunk-consume rows where the last block mops up
//!   overshoot lanes past the rate (gated to the last block by `b_sum` in the AIR; pure NOP
//!   otherwise).
//! - `rc_val_lo`, `rc_val_hi` — the u32 halves of `RC[p_idx]` on `p_rc_active` rows, `0` elsewhere.
//!   Provided to Memory64 at the round chiplet's RC slot IP.

use alloc::{vec, vec::Vec};

use miden_core::Felt;

/// Length of one sponge period (= 32 rows / 1 Keccak permutation).
pub const SPONGE_PERIOD: usize = 32;

/// Number of preprocessed columns produced by [`sponge_program`].
pub const NUM_PERIODIC_COLS: usize = 11;

// COLUMN INDICES
// ================================================================================================

/// Integer row index within the period, `p_idx ∈ [0, SPONGE_PERIOD)`.
pub const COL_IDX: usize = 0;
/// 1 iff `p_idx == 0`. Used for period-boundary constraints.
pub const COL_FIRST: usize = 1;
/// 1 iff `p_idx == SPONGE_PERIOD - 1` (= 31). Equals `p_first` at
/// the next row (by periodicity), but accessible at the current row
/// — the framework doesn't expose next-row periodics directly, so
/// transition constraints that need `p_first_{r+1}` consume `p_last`
/// at row `r` instead.
pub const COL_LAST: usize = 2;
/// 1 iff `p_idx ∈ [0, 17)` (rate XORin rows).
pub const COL_RATE_BLOCK: usize = 3;
/// 1 iff `p_idx ∈ [17, 25)` (capacity rows).
pub const COL_CAPACITY: usize = 4;
/// 1 iff `p_idx ∈ [0, 24)`.
pub const COL_RC_ACTIVE: usize = 5;
/// 1 iff `p_idx ∈ [4, 25)`.
pub const COL_SQUEEZE_ACTIVE: usize = 6;
/// 1 iff `p_idx == 25` (lane-16 trailing-`0x80` row).
pub const COL_PAD_0X80: usize = 7;
/// Low u32 half of `RC[p_idx]` on `p_rc_active` rows, 0 elsewhere.
pub const COL_RC_LO: usize = 8;
/// High u32 half of `RC[p_idx]` on `p_rc_active` rows, 0 elsewhere.
pub const COL_RC_HI: usize = 9;
/// 1 iff `p_idx ∈ [26, 29)` (extra chunk-consume rows for last-block
/// overshoot lanes).
pub const COL_EXTRA: usize = 10;

// SLOT LAYOUT
// ================================================================================================

/// First slot of the rate-XORin block (inclusive).
pub const RATE_BLOCK_BEGIN: usize = 0;
/// Length of the rate-XORin block (= Keccak-256 rate in 64-bit lanes).
pub const RATE_BLOCK_LEN: usize = 17;
/// First slot of the capacity block (inclusive).
pub const CAPACITY_BLOCK_BEGIN: usize = RATE_BLOCK_BEGIN + RATE_BLOCK_LEN;
/// Length of the capacity block (= Keccak-256 capacity in 64-bit lanes).
pub const CAPACITY_BLOCK_LEN: usize = 8;
/// Slot of the dedicated lane-16 trailing-`0x80` row.
pub const LANE_16_0X80_SLOT: usize = CAPACITY_BLOCK_BEGIN + CAPACITY_BLOCK_LEN;
/// First slot of the extra chunk-consume block (inclusive).
pub const EXTRA_BLOCK_BEGIN: usize = LANE_16_0X80_SLOT + 1;
/// Number of extra chunk-consume slots. Bounds the max per-invocation
/// overshoot: `4·num_chunks − 17·num_blocks ∈ {0,1,2,3}` since
/// `gcd(4, 17) = 1`, so three rows always suffice.
pub const EXTRA_BLOCK_LEN: usize = 3;
/// First slot of the NOP slack tail (inclusive).
pub const NOP_SLACK_BEGIN: usize = EXTRA_BLOCK_BEGIN + EXTRA_BLOCK_LEN;
/// Number of NOP slack slots.
pub const NOP_SLACK_LEN: usize = SPONGE_PERIOD - NOP_SLACK_BEGIN;

/// Number of Keccak-f\[1600] round constants the sponge provides per
/// permutation (= Keccak's 24 active rounds; the 25th cycle row in the
/// round chiplet is the dead round and carries no RC).
pub const NUM_RC: usize = 24;

// KECCAK-f[1600] ROUND CONSTANTS
// ================================================================================================

/// Standard FIPS 202 Keccak-f\[1600] round constants, indexed by round.
///
/// Provided by the sponge to the round chiplet on Memory64 at IP
/// `25 + n·3200 + r·128` for cycle `n`, round `r`. See `docs/chiplets/keccak-sponge.md`
/// (RC address algebra) and `docs/chiplets/keccak.md` (sponge contract).
pub const KECCAK_RC: [u64; NUM_RC] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

// PROGRAM
// ================================================================================================

/// Build the period-32 periodic table for the sponge AIR.
///
/// Returns a `Vec<Felt>` of length [`SPONGE_PERIOD`] for each of
/// [`NUM_PERIODIC_COLS`] columns. The order matches the `COL_*`
/// constants above.
pub fn sponge_program() -> [Vec<Felt>; NUM_PERIODIC_COLS] {
    let mut cols: [Vec<Felt>; NUM_PERIODIC_COLS] =
        core::array::from_fn(|_| vec![Felt::ZERO; SPONGE_PERIOD]);

    for slot in 0..SPONGE_PERIOD {
        cols[COL_IDX][slot] = Felt::from(slot as u32);
        cols[COL_FIRST][slot] = Felt::from((slot == 0) as u8);
        cols[COL_LAST][slot] = Felt::from((slot == SPONGE_PERIOD - 1) as u8);
        cols[COL_RATE_BLOCK][slot] = Felt::from((slot < CAPACITY_BLOCK_BEGIN) as u8);
        cols[COL_CAPACITY][slot] =
            Felt::from(((CAPACITY_BLOCK_BEGIN..LANE_16_0X80_SLOT).contains(&slot)) as u8);
        cols[COL_RC_ACTIVE][slot] = Felt::from((slot < NUM_RC) as u8);
        cols[COL_SQUEEZE_ACTIVE][slot] = Felt::from(((4..LANE_16_0X80_SLOT).contains(&slot)) as u8);
        cols[COL_PAD_0X80][slot] = Felt::from((slot == LANE_16_0X80_SLOT) as u8);
        cols[COL_EXTRA][slot] =
            Felt::from(((EXTRA_BLOCK_BEGIN..NOP_SLACK_BEGIN).contains(&slot)) as u8);

        // RC[p_idx] split into u32 halves on p_rc_active rows.
        if slot < NUM_RC {
            let rc = KECCAK_RC[slot];
            cols[COL_RC_LO][slot] = Felt::from(rc as u32);
            cols[COL_RC_HI][slot] = Felt::from((rc >> 32) as u32);
        }
    }

    cols
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periodic_columns_have_expected_lengths() {
        let cols = sponge_program();
        for col in &cols {
            assert_eq!(col.len(), SPONGE_PERIOD);
        }
    }

    #[test]
    fn p_idx_enumerates_0_to_period() {
        let cols = sponge_program();
        for (slot, value) in cols[COL_IDX].iter().enumerate().take(SPONGE_PERIOD) {
            assert_eq!(*value, Felt::from(slot as u32));
        }
    }

    #[test]
    fn row_class_flags_partition_the_period() {
        // p_rate_block, p_capacity, p_pad_0x80, p_extra, and the
        // NOP-slack implicit "off" mask must partition `[0, 32)`.
        let cols = sponge_program();
        for (slot, _) in cols[COL_IDX].iter().enumerate().take(SPONGE_PERIOD) {
            let rb = u32_at(&cols[COL_RATE_BLOCK], slot);
            let cap = u32_at(&cols[COL_CAPACITY], slot);
            let pad80 = u32_at(&cols[COL_PAD_0X80], slot);
            let extra = u32_at(&cols[COL_EXTRA], slot);
            let nop_slack = (slot >= NOP_SLACK_BEGIN) as u32;
            assert_eq!(
                rb + cap + pad80 + extra + nop_slack,
                1,
                "slot {slot} not covered exactly once",
            );
        }
    }

    #[test]
    fn p_extra_fires_on_slots_26_through_28() {
        let cols = sponge_program();
        for (slot, value) in cols[COL_EXTRA].iter().enumerate().take(SPONGE_PERIOD) {
            let expected = if (EXTRA_BLOCK_BEGIN..NOP_SLACK_BEGIN).contains(&slot) {
                Felt::ONE
            } else {
                Felt::ZERO
            };
            assert_eq!(*value, expected, "slot {slot}");
        }
    }

    #[test]
    fn p_first_fires_only_at_slot_0() {
        let cols = sponge_program();
        assert_eq!(cols[COL_FIRST][0], Felt::ONE);
        for (slot, value) in cols[COL_FIRST].iter().enumerate().take(SPONGE_PERIOD).skip(1) {
            assert_eq!(*value, Felt::ZERO, "slot {slot}");
        }
    }

    #[test]
    fn p_last_fires_only_at_last_slot() {
        let cols = sponge_program();
        for (slot, value) in cols[COL_LAST].iter().enumerate().take(SPONGE_PERIOD - 1) {
            assert_eq!(*value, Felt::ZERO, "slot {slot}");
        }
        assert_eq!(cols[COL_LAST][SPONGE_PERIOD - 1], Felt::ONE);
    }

    #[test]
    fn p_rc_active_covers_first_24_slots() {
        let cols = sponge_program();
        for (slot, value) in cols[COL_RC_ACTIVE].iter().enumerate().take(NUM_RC) {
            assert_eq!(*value, Felt::ONE, "slot {slot}");
        }
        for (slot, value) in cols[COL_RC_ACTIVE].iter().enumerate().take(SPONGE_PERIOD).skip(NUM_RC)
        {
            assert_eq!(*value, Felt::ZERO, "slot {slot}");
        }
    }

    #[test]
    fn p_squeeze_active_covers_slots_4_through_24() {
        let cols = sponge_program();
        for (slot, value) in cols[COL_SQUEEZE_ACTIVE].iter().enumerate().take(4) {
            assert_eq!(*value, Felt::ZERO, "slot {slot}");
        }
        for (slot, value) in
            cols[COL_SQUEEZE_ACTIVE].iter().enumerate().take(LANE_16_0X80_SLOT).skip(4)
        {
            assert_eq!(*value, Felt::ONE, "slot {slot}");
        }
        for (slot, value) in cols[COL_SQUEEZE_ACTIVE]
            .iter()
            .enumerate()
            .take(SPONGE_PERIOD)
            .skip(LANE_16_0X80_SLOT)
        {
            assert_eq!(*value, Felt::ZERO, "slot {slot}");
        }
    }

    #[test]
    fn p_pad_0x80_fires_only_at_slot_25() {
        let cols = sponge_program();
        for (slot, value) in cols[COL_PAD_0X80].iter().enumerate().take(SPONGE_PERIOD) {
            let expected = if slot == LANE_16_0X80_SLOT {
                Felt::ONE
            } else {
                Felt::ZERO
            };
            assert_eq!(*value, expected, "slot {slot}");
        }
    }

    #[test]
    fn rc_values_match_keccak_constants_on_active_rows() {
        let cols = sponge_program();
        for (slot, &rc) in KECCAK_RC.iter().enumerate().take(NUM_RC) {
            assert_eq!(cols[COL_RC_LO][slot], Felt::from(rc as u32));
            assert_eq!(cols[COL_RC_HI][slot], Felt::from((rc >> 32) as u32));
        }
        for (slot, value) in cols[COL_RC_LO].iter().enumerate().take(SPONGE_PERIOD).skip(NUM_RC) {
            assert_eq!(*value, Felt::ZERO, "slot {slot}");
            assert_eq!(cols[COL_RC_HI][slot], Felt::ZERO, "slot {slot}");
        }
    }

    fn u32_at(col: &[Felt], slot: usize) -> u32 {
        // The boolean flag columns hold values in {0, 1}; reading them
        // back via the canonical felt representation lets us sum across
        // mutex flags to check partition coverage without going through
        // the full field API.
        let value = col[slot];
        if value == Felt::ZERO {
            0
        } else if value == Felt::ONE {
            1
        } else {
            panic!("non-binary periodic value at slot {slot}");
        }
    }
}
