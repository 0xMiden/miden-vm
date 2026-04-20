//! Hasher chiplet trace constants and types.
//!
//! This module defines the structure of the hasher chiplet's execution trace, including:
//! - Trace selectors that determine which hash operation is being performed
//! - State layout for the Poseidon2 permutation (12 field elements: 8 rate + 4 capacity)
//! - Column ranges and indices for accessing trace data
//!
//! The hasher chiplet supports several operations:
//! - Linear hashing (absorbing arbitrary-length inputs)
//! - 2-to-1 hashing (Merkle tree node computation)
//! - Merkle path verification
//! - Merkle root updates (for authenticated data structure modifications)

use core::ops::Range;

pub use miden_core::{Word, crypto::hash::Poseidon2 as Hasher};

use super::{Felt, ONE, ZERO, create_range};

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

/// Number of round steps used to complete a single permutation.
///
/// For Poseidon2, the permutation consists of 31 step transitions (1 init linear + 8 external
/// + 22 internal). These are packed into a 16-row cycle.
pub const NUM_ROUNDS: usize = miden_core::chiplets::hasher::NUM_ROUNDS;

/// Index of the last row in a permutation cycle (0-based).
pub const LAST_CYCLE_ROW: usize = HASH_CYCLE_LEN - 1;
pub const LAST_CYCLE_ROW_FELT: Felt = Felt::new(LAST_CYCLE_ROW as u64);

/// Number of selector columns in the trace.
pub const NUM_SELECTORS: usize = 3;

/// The number of rows in the execution trace required to compute a permutation of Poseidon2.
///
/// The 16-row packed cycle compresses the 31 permutation steps by:
/// - Merging init linear + ext1 into one row
/// - Packing 3 internal rounds per row (7 rows for 21 rounds)
/// - Merging int22 + ext5 into one row Result: 1 + 3 + 7 + 1 + 3 + 1 = 16 rows.
pub const HASH_CYCLE_LEN: usize = 16;
pub const HASH_CYCLE_LEN_FELT: Felt = Felt::new(HASH_CYCLE_LEN as u64);

/// Index of the node_index column. Holds the Merkle tree node index on controller rows.
/// This column is reused to hold the permutation request multiplicity on perm segment rows.
pub const NODE_INDEX_COL_IDX: usize = NUM_SELECTORS + STATE_WIDTH;

/// Index of the mrupdate_id column (domain separator for sibling table across MRUPDATE ops).
pub const MRUPDATE_ID_COL_IDX: usize = NODE_INDEX_COL_IDX + 1;

/// Index of the is_boundary column (1 on boundary rows: first input or last output of each
/// operation, 0 otherwise).
pub const IS_BOUNDARY_COL_IDX: usize = MRUPDATE_ID_COL_IDX + 1;

/// Index of the direction_bit column. On Merkle controller rows, holds the extracted direction
/// bit from the node index. Zero on non-Merkle rows and perm segment rows.
pub const DIRECTION_BIT_COL_IDX: usize = IS_BOUNDARY_COL_IDX + 1;

/// Index of the perm_seg column (0 = controller region, 1 = permutation segment).
pub const PERM_SEG_COL_IDX: usize = DIRECTION_BIT_COL_IDX + 1;

/// Number of columns in Hasher execution trace.
/// 3 selectors + 12 state + node_index + mrupdate_id + is_boundary + direction_bit + perm_seg = 20.
pub const TRACE_WIDTH: usize = PERM_SEG_COL_IDX + 1;

/// Number of controller rows per permutation request (one input + one output).
pub const CONTROLLER_ROWS_PER_PERMUTATION: usize = 2;

/// Felt version of [CONTROLLER_ROWS_PER_PERMUTATION] for address arithmetic.
pub const CONTROLLER_ROWS_PER_PERM_FELT: Felt = Felt::new(CONTROLLER_ROWS_PER_PERMUTATION as u64);

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

// NOTE: Selectors s0/s1/s2 are unconstrained on perm segment rows.
