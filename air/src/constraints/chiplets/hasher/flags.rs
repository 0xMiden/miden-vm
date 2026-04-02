//! Hasher chiplet flag computation functions.
//!
//! This module provides functions to compute operation flags for the hasher chiplet.
//! Each flag identifies when a specific operation is active based on selector values
//! and cycle position.
//!
//! ## Unused Flags
//!
//! Some flags are defined but unused (`#[allow(dead_code)]`):
//!
//! - **`f_bp`**: BP (Begin Permutation) needs no special constraints - the round function
//!   constraints apply identically regardless of which operation started it.
//! - **`f_hout`, `f_sout`**: The combined `f_out` flag suffices for hasher constraints.
//!
//! ## Selector Encoding
//!
//! The hasher uses 3 selector columns `s[0..2]` to encode operations:
//!
//! | Operation | s0 | s1 | s2 | Cycle Position     | Description |
//! |-----------|----|----|----|--------------------|-------------|
//! | BP        | 1  | 0  | 0  | row 0              | Begin permutation |
//! | MP        | 1  | 0  | 1  | row 0              | Merkle path verify |
//! | MV        | 1  | 1  | 0  | row 0              | Merkle verify (old root) |
//! | MU        | 1  | 1  | 1  | row 0              | Merkle update (new root) |
//! | ABP       | 1  | 0  | 0  | row 31             | Absorb for linear hash |
//! | MPA       | 1  | 0  | 1  | row 31             | Merkle path absorb |
//! | MVA       | 1  | 1  | 0  | row 31             | Merkle verify absorb |
//! | MUA       | 1  | 1  | 1  | row 31             | Merkle update absorb |
//! | HOUT      | 0  | 0  | 0  | row 31             | Hash output (digest) |
//! | SOUT      | 0  | 0  | 1  | row 31             | State output (full) |
use miden_core::field::PrimeCharacteristicRing;

use crate::constraints::utils::BoolNot;

// INITIALIZATION FLAGS (row 0 of 32-row cycle)
// ================================================================================================

/// BP: Begin Permutation flag `(1,0,0)` on cycle row 0.
///
/// Initiates single permutation, 2-to-1 hash, or linear hash computation.
///
/// # Degree
/// - Periodic: 1 (cycle_row_0)
/// - Selectors: 3 (s0 * !s1 * !s2)
/// - Total: 4
#[inline]
#[allow(dead_code)]
pub fn f_bp<E>(cycle_row_0: E, s0: E, s1: E, s2: E) -> E
where
    E: PrimeCharacteristicRing,
{
    cycle_row_0 * s0 * s1.not() * s2.not()
}

/// MP: Merkle Path verification flag `(1,0,1)` on cycle row 0.
///
/// Initiates standard Merkle path verification computation.
///
/// # Degree
/// - Periodic: 1 (cycle_row_0)
/// - Selectors: 3 (s0 * !s1 * s2)
/// - Total: 4
#[inline]
pub fn f_mp<E>(cycle_row_0: E, s0: E, s1: E, s2: E) -> E
where
    E: PrimeCharacteristicRing,
{
    cycle_row_0 * s0 * s1.not() * s2
}

/// MV: Merkle Verify (old root) flag `(1,1,0)` on cycle row 0.
///
/// Begins verification for old leaf value during Merkle root update.
///
/// # Degree
/// - Periodic: 1 (cycle_row_0)
/// - Selectors: 3 (s0 * s1 * !s2)
/// - Total: 4
#[inline]
pub fn f_mv<E>(cycle_row_0: E, s0: E, s1: E, s2: E) -> E
where
    E: PrimeCharacteristicRing,
{
    cycle_row_0 * s0 * s1 * s2.not()
}

/// MU: Merkle Update (new root) flag `(1,1,1)` on cycle row 0.
///
/// Starts verification for new leaf value during Merkle root update.
///
/// # Degree
/// - Periodic: 1 (cycle_row_0)
/// - Selectors: 3 (s0 * s1 * s2)
/// - Total: 4
#[inline]
pub fn f_mu<E>(cycle_row_0: E, s0: E, s1: E, s2: E) -> E
where
    E: PrimeCharacteristicRing,
{
    cycle_row_0 * s0 * s1 * s2
}

// ================================================================================================
// ABSORPTION FLAGS (row 31 of 32-row cycle)
// ================================================================================================

/// ABP: Absorb for linear hash flag `(1,0,0)` on cycle row 31.
///
/// Absorbs next set of elements into hasher state during linear hash computation.
///
/// # Degree
/// - Periodic: 1 (cycle_row_31)
/// - Selectors: 3 (s0 * !s1 * !s2)
/// - Total: 4
#[inline]
pub fn f_abp<E>(cycle_row_31: E, s0: E, s1: E, s2: E) -> E
where
    E: PrimeCharacteristicRing,
{
    cycle_row_31 * s0 * s1.not() * s2.not()
}

/// MPA: Merkle Path Absorb flag `(1,0,1)` on cycle row 31.
///
/// Absorbs next Merkle path node during standard verification.
///
/// # Degree
/// - Periodic: 1 (cycle_row_31)
/// - Selectors: 3 (s0 * !s1 * s2)
/// - Total: 4
#[inline]
pub fn f_mpa<E>(cycle_row_31: E, s0: E, s1: E, s2: E) -> E
where
    E: PrimeCharacteristicRing,
{
    cycle_row_31 * s0 * s1.not() * s2
}

/// MVA: Merkle Verify Absorb flag `(1,1,0)` on cycle row 31.
///
/// Absorbs next node during "old" leaf verification (Merkle root update).
///
/// # Degree
/// - Periodic: 1 (cycle_row_31)
/// - Selectors: 3 (s0 * s1 * !s2)
/// - Total: 4
#[inline]
pub fn f_mva<E>(cycle_row_31: E, s0: E, s1: E, s2: E) -> E
where
    E: PrimeCharacteristicRing,
{
    cycle_row_31 * s0 * s1 * s2.not()
}

/// MUA: Merkle Update Absorb flag `(1,1,1)` on cycle row 31.
///
/// Absorbs next node during "new" leaf verification (Merkle root update).
///
/// # Degree
/// - Periodic: 1 (cycle_row_31)
/// - Selectors: 3 (s0 * s1 * s2)
/// - Total: 4
#[inline]
pub fn f_mua<E>(cycle_row_31: E, s0: E, s1: E, s2: E) -> E
where
    E: PrimeCharacteristicRing,
{
    cycle_row_31 * s0 * s1 * s2
}

// ================================================================================================
// OUTPUT FLAGS (row 31 of 32-row cycle)
// ================================================================================================

/// HOUT: Hash Output flag `(0,0,0)` on cycle row 31.
///
/// Returns the 4-element hash result (digest).
///
/// # Degree
/// - Periodic: 1 (cycle_row_31)
/// - Selectors: 3 (!s0 * !s1 * !s2)
/// - Total: 4
#[inline]
#[allow(dead_code)]
pub fn f_hout<E>(cycle_row_31: E, s0: E, s1: E, s2: E) -> E
where
    E: PrimeCharacteristicRing,
{
    cycle_row_31 * s0.not() * s1.not() * s2.not()
}

/// SOUT: State Output flag `(0,0,1)` on cycle row 31.
///
/// Returns the entire 12-element hasher state.
///
/// # Degree
/// - Periodic: 1 (cycle_row_31)
/// - Selectors: 3 (!s0 * !s1 * s2)
/// - Total: 4
#[inline]
#[allow(dead_code)]
pub fn f_sout<E>(cycle_row_31: E, s0: E, s1: E, s2: E) -> E
where
    E: PrimeCharacteristicRing,
{
    cycle_row_31 * s0.not() * s1.not() * s2
}

/// Combined output flag: `f_hout | f_sout` = `(0,0,*)` on cycle row 31.
///
/// True when any output operation is active (HOUT or SOUT).
///
/// # Degree
/// - Periodic: 1 (cycle_row_31)
/// - Selectors: 2 (!s0 * !s1)
/// - Total: 3
#[inline]
pub fn f_out<E>(cycle_row_31: E, s0: E, s1: E) -> E
where
    E: PrimeCharacteristicRing,
{
    cycle_row_31 * s0.not() * s1.not()
}

/// Lookahead output flag on cycle row 30.
///
/// True when the *next* row will be an output operation.
/// Used for selector stability constraints.
///
/// # Degree
/// - Periodic: 1 (cycle_row_30)
/// - Next selectors: 2 (!s0' * !s1')
/// - Total: 3
#[inline]
pub fn f_out_next<E>(cycle_row_30: E, s0_next: E, s1_next: E) -> E
where
    E: PrimeCharacteristicRing,
{
    cycle_row_30 * s0_next.not() * s1_next.not()
}
