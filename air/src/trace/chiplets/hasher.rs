//! Hasher controller trace constants and types.
//!
//! This module defines the structure of the hasher controller trace, including:
//! - Trace selectors that determine which hash operation is being performed
//! - State layout for Eidos compression (`block[8] || cv[4]`)
//!
//! The hasher chiplet supports several operations:
//! - Linear hashing (absorbing arbitrary-length inputs)
//! - 2-to-1 hashing (Merkle tree node computation)
//! - Merkle path verification
//! - Merkle root updates (for authenticated data structure modifications)

use core::ops::Range;

pub use miden_core::{Word, chiplets::hasher::Hasher};

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

/// Number of field elements in the hasher state.
///
/// Eidos compression interprets the state as `[block_lo(4), block_hi(4), cv(4)]`.
pub const STATE_WIDTH: usize = Hasher::STATE_WIDTH;

/// Number of field elements in one compression block.
pub const BLOCK_LEN: usize = 8;

/// Number of field elements in the chaining-value portion of the hasher's state.
pub const CV_LEN: usize = STATE_WIDTH - BLOCK_LEN;

// The length of the output portion of the hash state.
pub const DIGEST_LEN: usize = 4;

/// The output portion of the hash state, located in the final chaining-value word.
pub const DIGEST_RANGE: Range<usize> = Hasher::DIGEST_RANGE;

/// Number of transitions in one Eidos compression trace block.
pub const NUM_ROUNDS: usize = miden_core::chiplets::hasher::NUM_ROUNDS;

/// Number of selector columns in the trace.
pub const NUM_SELECTORS: usize = 3;

/// Standalone Eidos compression AIR block length.
pub const HASH_CYCLE_LEN: usize = crate::trace::eidos_compression::EIDOS_COMPRESSION_CYCLE_LEN;
pub const HASH_CYCLE_LEN_FELT: Felt = Felt::new_unchecked(HASH_CYCLE_LEN as u64);

/// Index of the last row in a standalone Eidos compression AIR block (0-based).
pub const LAST_CYCLE_ROW: usize = HASH_CYCLE_LEN - 1;
pub const LAST_CYCLE_ROW_FELT: Felt = Felt::new_unchecked(LAST_CYCLE_ROW as u64);

/// Row alignment for the hasher controller region inside `ChipletsAir`.
///
/// The following bitwise section can host 8-row AEAD stream entries. Padding the controller
/// to this boundary keeps stream rows phase-aligned.
pub const CONTROLLER_TRACE_ALIGNMENT: usize = 8;

/// Number of columns in the hasher-controller trace.
pub const TRACE_WIDTH: usize = NUM_SELECTORS + STATE_WIDTH + 7;

/// Number of controller rows per compression request.
pub const CONTROLLER_ROWS_PER_HASHER_OP: usize = 1;

/// Felt version of [CONTROLLER_ROWS_PER_HASHER_OP] for address arithmetic.
pub const CONTROLLER_ROWS_PER_HASHER_OP_FELT: Felt =
    Felt::new_unchecked(CONTROLLER_ROWS_PER_HASHER_OP as u64);

/// Largest Merkle path depth accepted by MPVERIFY and MRUPDATE.
///
/// Depths above 64 require more index bits than a field element provides.
pub const MAX_MERKLE_DEPTH: u8 = 64;

const _: () = assert!(
    MAX_MERKLE_DEPTH > 1 && (1_u32 << 16).is_multiple_of(MAX_MERKLE_DEPTH as u32),
    "MAX_MERKLE_DEPTH must be greater than one and divide 2^16"
);

/// Scale applied to `depth - 1` for the second Merkle-depth range check.
///
/// For a 16-bit `depth`, `(depth - 1) * MERKLE_DEPTH_RANGE_SCALE` is a 16-bit value exactly when
/// `1 <= depth <= MAX_MERKLE_DEPTH`, so the pair of checks enforces both depth bounds.
pub const MERKLE_DEPTH_RANGE_SCALE: u16 = ((1_u32 << 16) / MAX_MERKLE_DEPTH as u32) as u16;

// --- Transition selectors -----------------------------------------------------------------------

/// Specifies a start of a new linear hash computation or absorption of new elements into an
/// executing linear hash computation. These selectors can also be used for a simple 2-to-1 hash
/// computation.
pub const LINEAR_HASH: Selectors = [ONE, ZERO, ZERO];
/// Specifies a continuation row for an executing linear hash computation.
pub const HASH_ABSORB: Selectors = [ZERO, ZERO, ZERO];
/// Specifies a start of Merkle path verification computation or absorption of a new path node
/// into the hasher state.
pub const MP_VERIFY: Selectors = [ONE, ZERO, ONE];

/// Specifies a start of Merkle path verification or absorption of a new path node into the hasher
/// state for the "old" node value during Merkle root update computation.
pub const MR_UPDATE_OLD: Selectors = [ONE, ONE, ZERO];

/// Specifies a start of Merkle path verification or absorption of a new path node into the hasher
/// state for the "new" node value during Merkle root update computation.
pub const MR_UPDATE_NEW: Selectors = [ONE, ONE, ONE];

/// Specifies an inactive controller padding row.
pub const PADDING: Selectors = [ZERO, ONE, ZERO];

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
