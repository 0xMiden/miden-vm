//! Hasher chiplet trace constants and types.
//!
//! This module defines the structure of the hasher chiplet's execution trace, including:
//! - Trace selectors that determine which hash operation is being performed
//! - State layout for the RPO permutation (12 field elements: 4 capacity + 8 rate)
//! - Column ranges and indices for accessing trace data
//!
//! The hasher chiplet supports several operations:
//! - Linear hashing (absorbing arbitrary-length inputs)
//! - 2-to-1 hashing (Merkle tree node computation)
//! - Merkle path verification
//! - Merkle root updates (for authenticated data structure modifications)

use core::ops::Range;

pub use miden_core::{Word, crypto::hash::Rpo256 as Hasher};

use super::{Felt, HASH_KERNEL_VTABLE_AUX_TRACE_OFFSET, ONE, ZERO, create_range};

// TYPES ALIASES
// ================================================================================================

/// Type for Hasher trace selector. These selectors are used to define which transition function
/// is to be applied at a specific row of the hasher execution trace.
pub type Selectors = [Felt; NUM_SELECTORS];

/// Type for the Hasher's state.
pub type HasherState = [Felt; STATE_WIDTH];

// CONSTANTS
// ================================================================================================

/// Number of field element needed to represent the sponge state for the hash function.
///
/// This value is set to 12: 8 elements are reserved for rate and the remaining 4 elements are
/// reserved for capacity. This configuration enables computation of 2-to-1 hash in a single
/// permutation.
/// The sponge state is `[RATE0(4), RATE1(4), CAPACITY(4)]`.
pub const STATE_WIDTH: usize = Hasher::STATE_WIDTH;

/// The hasher state portion of the execution trace, located in columns 3..15.
pub const STATE_COL_RANGE: Range<usize> = create_range(NUM_SELECTORS, STATE_WIDTH);

/// Number of field elements in the capacity portion of the hasher's state.
pub const CAPACITY_LEN: usize = STATE_WIDTH - RATE_LEN;

/// The index in the hasher state where the domain is set when initializing the hasher.
///
/// The domain is stored in the second element of the capacity word.
/// With LE sponge state layout [RATE0, RATE1, CAP], this is at index 9 (= CAPACITY_RANGE.start +
/// 1).
pub const CAPACITY_DOMAIN_IDX: usize = 9;

/// Number of field elements in the rate portion of the hasher's state.
pub const RATE_LEN: usize = 8;

/// The rate portion of the hasher state in the execution trace, located in columns 3..11.
/// With LE sponge state layout [RATE0, RATE1, CAP], rate comes first.
pub const RATE_COL_RANGE: Range<usize> = Range {
    start: STATE_COL_RANGE.start,
    end: STATE_COL_RANGE.start + RATE_LEN,
};

/// The capacity portion of the hasher state in the execution trace, located in columns 11..15.
/// With LE sponge state layout [RATE0, RATE1, CAP], capacity comes last.
pub const CAPACITY_COL_RANGE: Range<usize> = Range {
    start: RATE_COL_RANGE.end,
    end: RATE_COL_RANGE.end + CAPACITY_LEN,
};

// The length of the output portion of the hash state.
pub const DIGEST_LEN: usize = 4;

/// The output portion of the hash state, located in the first rate word (RATE0).
pub const DIGEST_RANGE: Range<usize> = Hasher::DIGEST_RANGE;

/// Number of needed to complete a single permutation.
///
/// This value is set to 7 to target 128-bit security level with 40% security margin.
pub const NUM_ROUNDS: usize = Hasher::NUM_ROUNDS;

/// Number of selector columns in the trace.
pub const NUM_SELECTORS: usize = 3;

/// The number of rows in the execution trace required to compute a permutation of Rescue Prime
/// Optimized. This is equal to 8.
pub const HASH_CYCLE_LEN: usize = NUM_ROUNDS.next_power_of_two();

/// Number of columns in Hasher execution trace. There is one additional column for the node index.
pub const TRACE_WIDTH: usize = NUM_SELECTORS + STATE_WIDTH + 1;

// --- Transition selectors -----------------------------------------------------------------------

/// Specifies a start of a new linear hash computation or absorption of new elements into an
/// executing linear hash computation. These selectors can also be used for a simple 2-to-1 hash
/// computation.
pub const LINEAR_HASH: Selectors = [ONE, ZERO, ZERO];
/// Unique label computed as 1 plus the full chiplet selector with the bits reversed.
/// `selector = [0 | 1, 0, 0]`, `flag = rev(selector) + 1 = [0, 0, 1 | 0] + 1 = 3`
pub const LINEAR_HASH_LABEL: u8 = 0b0010 + 1;

/// Specifies a start of Merkle path verification computation or absorption of a new path node
/// into the hasher state.
pub const MP_VERIFY: Selectors = [ONE, ZERO, ONE];
/// Unique label computed as 1 plus the full chiplet selector with the bits reversed.
/// `selector = [0 | 1, 0, 1]`, `flag = rev(selector) + 1 = [1, 0, 1 | 0] + 1 = 11`
pub const MP_VERIFY_LABEL: u8 = 0b1010 + 1;

/// Specifies a start of Merkle path verification or absorption of a new path node into the hasher
/// state for the "old" node value during Merkle root update computation.
pub const MR_UPDATE_OLD: Selectors = [ONE, ONE, ZERO];
/// Unique label computed as 1 plus the full chiplet selector with the bits reversed.
/// `selector = [0 | 1, 1, 0]`, `flag = rev(selector) + 1 = [0, 1, 1 | 0] + 1 = 7`
pub const MR_UPDATE_OLD_LABEL: u8 = 0b0110 + 1;

/// Specifies a start of Merkle path verification or absorption of a new path node into the hasher
/// state for the "new" node value during Merkle root update computation.
pub const MR_UPDATE_NEW: Selectors = [ONE, ONE, ONE];
/// Unique label computed as 1 plus the full chiplet selector with the bits reversed.
/// `selector = [0 | 1, 1, 1]`, `flag = rev(selector) + 1 = [1, 1, 1 | 0] + 1 = 15`
pub const MR_UPDATE_NEW_LABEL: u8 = 0b1110 + 1;

/// Specifies a completion of a computation such that only the hash result (values in h0, h1, h2
/// h3) is returned.
pub const RETURN_HASH: Selectors = [ZERO, ZERO, ZERO];
/// Unique label computed as 1 plus the full chiplet selector with the bits reversed.
/// `selector = [0 | 0, 0, 0]`, `flag = rev(selector) + 1 = [0, 0, 0 | 0] + 1 = 1`
#[expect(clippy::identity_op)]
pub const RETURN_HASH_LABEL: u8 = 0b0000 + 1;

/// Specifies a completion of a computation such that the entire hasher state (values in h0 through
/// h11) is returned.
pub const RETURN_STATE: Selectors = [ZERO, ZERO, ONE];
/// Unique label computed as 1 plus the full chiplet selector with the bits reversed.
/// `selector = [0 | 0, 0, 1]`, `flag = rev(selector) + 1 = [1, 0, 0 | 0] + 1 = 9`
pub const RETURN_STATE_LABEL: u8 = 0b1000 + 1;

// --- Column accessors in the auxiliary trace ----------------------------------------------------

/// Index of the auxiliary trace column tracking the state of the sibling table.
pub const P1_COL_IDX: usize = HASH_KERNEL_VTABLE_AUX_TRACE_OFFSET;
