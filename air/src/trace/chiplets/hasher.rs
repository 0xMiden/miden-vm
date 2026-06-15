//! Hasher chiplet trace constants and types.
//!
//! This module defines the structure of the hasher chiplet's execution trace, including:
//! - Trace selectors that determine which hash operation is being performed
//! - State layout for BlakeG compression (`block[8] || cv[4]`)
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
/// BlakeG interprets the state as `[block_lo(4), block_hi(4), cv(4)]`.
pub const STATE_WIDTH: usize = Hasher::STATE_WIDTH;

/// Number of field elements in the chaining-value portion of the hasher's state.
pub const CAPACITY_LEN: usize = STATE_WIDTH - RATE_LEN;

/// Legacy index of the second element in the chaining-value word.
///
/// Older helpers stored domain tags in this lane. Eidos computes the full chaining word from the
/// domain and input length.
pub const CAPACITY_DOMAIN_IDX: usize = 9;

/// Number of field elements in the rate portion of the hasher's state.
pub const RATE_LEN: usize = 8;

// The length of the output portion of the hash state.
pub const DIGEST_LEN: usize = 4;

/// The output portion of the hash state, located in the final chaining-value word.
pub const DIGEST_RANGE: Range<usize> = Hasher::DIGEST_RANGE;

/// Number of transitions in one BlakeG compression trace block.
pub const NUM_ROUNDS: usize = miden_core::chiplets::hasher::NUM_ROUNDS;

/// Index of the last row in a BlakeG compression trace block (0-based).
pub const LAST_CYCLE_ROW: usize = HASH_CYCLE_LEN - 1;
pub const LAST_CYCLE_ROW_FELT: Felt = Felt::new_unchecked(LAST_CYCLE_ROW as u64);

/// Number of selector columns in the trace.
pub const NUM_SELECTORS: usize = 3;

/// Number of rows in one BlakeG compression trace block.
pub const HASH_CYCLE_LEN: usize = 64;
pub const HASH_CYCLE_LEN_FELT: Felt = Felt::new_unchecked(HASH_CYCLE_LEN as u64);

/// Row alignment for the hasher controller region inside `ChipletsAir`.
///
/// The following bitwise section currently hosts 16-row direct-AND8 stream entries. Padding the
/// controller to this boundary keeps stream rows phase-aligned.
pub const CONTROLLER_TRACE_ALIGNMENT: usize = 16;

/// Number of columns in the hasher-controller trace.
pub const TRACE_WIDTH: usize = NUM_SELECTORS + STATE_WIDTH + 4;

/// Number of controller rows per compression request (one input + one output).
pub const CONTROLLER_ROWS_PER_HASHER_OP: usize = 2;

/// Felt version of [CONTROLLER_ROWS_PER_HASHER_OP] for address arithmetic.
pub const CONTROLLER_ROWS_PER_HASHER_OP_FELT: Felt =
    Felt::new_unchecked(CONTROLLER_ROWS_PER_HASHER_OP as u64);

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
