//! Hasher controller trace constants and types.
//!
//! This module defines the structure of the hasher controller trace, including:
//! - Trace selectors that determine which hash operation is being performed
//! - State layout for the Poseidon2 permutation (12 field elements: 8 rate + 4 capacity)
//!
//! The hasher chiplet supports several operations:
//! - Linear hashing (absorbing arbitrary-length inputs)
//! - 2-to-1 hashing (Merkle tree node computation)
//! - Merkle path verification
//! - Merkle root updates (for authenticated data structure modifications)

use core::ops::Range;

use miden_core::field::PrimeField64;
pub use miden_core::{Word, crypto::hash::Poseidon2 as Hasher};

use super::{Felt, ONE, ZERO};

// TYPES ALIASES
// ================================================================================================

/// Type for Hasher trace selector. These selectors are used to define which transition function
/// is to be applied at a specific row of the hasher execution trace.
pub type Selectors = [Felt; NUM_SELECTORS];

/// Type for the Hasher's state.
pub type HasherState = [Felt; STATE_WIDTH];

// CONSTANTS
// ================================================================================================

/// Number of field elements needed to represent the sponge state for the hash function.
///
/// This value is set to 12: 8 elements are reserved for rate and the remaining 4 elements are
/// reserved for capacity. This configuration enables computation of 2-to-1 hash in a single
/// permutation.
/// The sponge state is `[RATE0(4), RATE1(4), CAPACITY(4)]`.
pub const STATE_WIDTH: usize = Hasher::STATE_WIDTH;

/// Number of field elements in the capacity portion of the hasher's state.
pub const CAPACITY_LEN: usize = STATE_WIDTH - RATE_LEN;

/// The index in the hasher state where the domain is set when initializing the hasher.
///
/// The domain is stored in the second element of the capacity word.
pub const CAPACITY_DOMAIN_IDX: usize = 9;

/// Number of field elements in the rate portion of the hasher's state.
pub const RATE_LEN: usize = 8;

// The length of the output portion of the hash state.
pub const DIGEST_LEN: usize = 4;

/// The output portion of the hash state, located in the first rate word (RATE0).
pub const DIGEST_RANGE: Range<usize> = Hasher::DIGEST_RANGE;

/// Number of round steps used to complete a single permutation.
///
/// For Poseidon2, the permutation consists of 31 step transitions (1 init linear + 8 external
/// + 22 internal). These are packed into a 16-row cycle.
pub const NUM_ROUNDS: usize = miden_core::chiplets::hasher::NUM_ROUNDS;

/// Index of the last row in a permutation cycle (0-based).
pub const LAST_CYCLE_ROW: usize = HASH_CYCLE_LEN - 1;

/// Number of selector columns in the trace.
pub const NUM_SELECTORS: usize = 3;

/// The number of rows in the execution trace required to compute a permutation of Poseidon2.
///
/// The 16-row packed cycle compresses the 31 permutation steps by:
/// - Merging init linear + ext1 into one row
/// - Packing 3 internal rounds per row (7 rows for 21 rounds)
/// - Merging int22 + ext5 into one row
///
/// This gives `1 + 3 + 7 + 1 + 3 + 1 = 16` rows.
pub const HASH_CYCLE_LEN: usize = 16;

/// Row alignment for the hasher controller region inside `ChipletsAir`.
pub const CONTROLLER_TRACE_ALIGNMENT: usize = 8;

const _: () = assert!(
    CONTROLLER_TRACE_ALIGNMENT.is_multiple_of(super::bitwise::OP_CYCLE_LEN),
    "controller region alignment must keep the bitwise section on a cycle boundary"
);

/// Controller metadata columns after the selector and state columns.
pub const NUM_METADATA_COLS: usize = 5;

/// Number of columns in Hasher controller trace.
/// 3 selectors + 12 state + node_index + mrupdate_id + is_boundary + direction_bit + perm_id = 20.
pub const TRACE_WIDTH: usize = NUM_SELECTORS + STATE_WIDTH + NUM_METADATA_COLS;

/// Largest Merkle path depth accepted by MPVERIFY and MRUPDATE.
///
/// Depths above 64 require more index bits than a field element provides. At depth 64, a separate
/// constraint must still bind the path bits to the index's canonical field representation.
pub const MAX_MERKLE_DEPTH: u8 = 64;

const _: () = assert!(
    MAX_MERKLE_DEPTH > 1 && (1_u32 << 16).is_multiple_of(MAX_MERKLE_DEPTH as u32),
    "MAX_MERKLE_DEPTH must be greater than one and divide 2^16"
);

// The canonicality witness uses the final `depth - 1` path bits to reconstruct the level-1 index.
// Keep that suffix within 63 bits so its field representation cannot wrap.
const _: () = assert!(
    MAX_MERKLE_DEPTH <= 64,
    "the canonical-index witness requires the shifted index to fit in 63 bits"
);

/// Scale applied to `depth - 1` for the second Merkle-depth range check.
///
/// For a 16-bit `depth`, `(depth - 1) * MERKLE_DEPTH_RANGE_SCALE` is a 16-bit value exactly when
/// `1 <= depth <= MAX_MERKLE_DEPTH`, so the pair of checks enforces both depth bounds.
pub const MERKLE_DEPTH_RANGE_SCALE: u16 = ((1_u32 << 16) / MAX_MERKLE_DEPTH as u32) as u16;

/// Half of the largest canonical Merkle index, `(Q - 1) / 2`.
///
/// For `n = 2*x + b`, the bound `n < Q` is equivalent to `x + b <= (Q - 1) / 2`. The level-0
/// witness proves this inequality by adding a non-negative slack.
pub const MAX_MERKLE_INDEX_HALF: u64 = (Felt::ORDER_U64 - 1) / 2;

const _: () = assert!(
    2 * MAX_MERKLE_INDEX_HALF + 1 == Felt::ORDER_U64,
    "MAX_MERKLE_INDEX_HALF must be exactly (Q - 1) / 2"
);

/// Number of controller rows per permutation request (one input + one output).
pub const CONTROLLER_ROWS_PER_PERMUTATION: usize = 2;

/// Felt version of [CONTROLLER_ROWS_PER_PERMUTATION] for address arithmetic.
pub const CONTROLLER_ROWS_PER_PERM_FELT: Felt =
    Felt::new_unchecked(CONTROLLER_ROWS_PER_PERMUTATION as u64);

// --- Transition selectors -----------------------------------------------------------------------

/// Specifies a start of a new linear hash computation or absorption of new elements into an
/// executing linear hash computation. These selectors can also be used for a simple 2-to-1 hash
/// computation.
pub const LINEAR_HASH: Selectors = [ONE, ZERO, ZERO];
/// Specifies a start of Merkle path verification computation or absorption of a new path node
/// into the hasher state.
pub const MP_VERIFY: Selectors = [ONE, ZERO, ONE];

/// Specifies a start of Merkle path verification or absorption of a new path node into the hasher
/// state for the "old" node value during Merkle root update computation.
pub const MR_UPDATE_OLD: Selectors = [ONE, ONE, ZERO];

/// Specifies a start of Merkle path verification or absorption of a new path node into the hasher
/// state for the "new" node value during Merkle root update computation.
pub const MR_UPDATE_NEW: Selectors = [ONE, ONE, ONE];

/// Specifies a completion of a computation such that only the hash result (values in h0, h1, h2
/// h3) is returned.
pub const RETURN_HASH: Selectors = [ZERO, ZERO, ZERO];

/// Specifies a completion of a computation such that the entire hasher state (values in h0 through
/// h11) is returned.
pub const RETURN_STATE: Selectors = [ZERO, ZERO, ONE];

// NOTE: Selectors s0/s1/s2 are hasher-controller internal selectors.

#[cfg(test)]
mod tests {
    use miden_core::field::PrimeCharacteristicRing;

    use super::*;

    fn merkle_depth_range_values(depth: Felt) -> [Felt; 2] {
        [depth, (depth - Felt::ONE) * Felt::from_u16(MERKLE_DEPTH_RANGE_SCALE)]
    }

    fn is_u16(value: Felt) -> bool {
        value.as_canonical_u64() < 1 << 16
    }

    #[test]
    fn merkle_depth_range_checks_accept_exactly_the_supported_depths() {
        let max_depth = u64::from(MAX_MERKLE_DEPTH);
        for depth in 0..=u64::from(u16::MAX) {
            let values = merkle_depth_range_values(Felt::new_unchecked(depth));
            let accepted = values.into_iter().all(is_u16);
            assert_eq!(accepted, (1..=max_depth).contains(&depth), "depth {depth}");
        }
    }

    #[test]
    fn merkle_depth_range_checks_reject_near_modulus_values() {
        let max_depth = Felt::from_u8(MAX_MERKLE_DEPTH);
        for depth in [Felt::NEG_ONE, Felt::NEG_ONE - max_depth + Felt::ONE] {
            assert!(!merkle_depth_range_values(depth).into_iter().all(is_u16));
        }
    }
}
