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
pub const LAST_CYCLE_ROW_FELT: Felt = Felt::new_unchecked(LAST_CYCLE_ROW as u64);

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
pub const HASH_CYCLE_LEN_FELT: Felt = Felt::new_unchecked(HASH_CYCLE_LEN as u64);

/// Row alignment for the hasher controller region inside `ChipletsAir`.
pub const CONTROLLER_TRACE_ALIGNMENT: usize = 8;

/// Number of columns in Hasher controller trace.
/// 3 selectors + 12 state + node_index + mrupdate_id + is_boundary + direction_bit = 19.
pub const TRACE_WIDTH: usize = NUM_SELECTORS + STATE_WIDTH + 4;

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
