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
//!
//! ## Degree Analysis
//!
//! Each flag function documents its degree contribution to help track constraint degrees.

use miden_core::field::PrimeCharacteristicRing;

// INTERNAL HELPERS
// ================================================================================================

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
    cycle_row_0 * s0 * (E::ONE - s1) * (E::ONE - s2)
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
    cycle_row_0 * s0 * (E::ONE - s1) * s2
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
    cycle_row_0 * s0 * s1 * (E::ONE - s2)
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
    cycle_row_31 * s0 * (E::ONE - s1) * (E::ONE - s2)
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
    cycle_row_31 * s0 * (E::ONE - s1) * s2
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
    cycle_row_31 * s0 * s1 * (E::ONE - s2)
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
    cycle_row_31 * (E::ONE - s0) * (E::ONE - s1) * (E::ONE - s2)
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
    cycle_row_31 * (E::ONE - s0) * (E::ONE - s1) * s2
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
    cycle_row_31 * (E::ONE - s0) * (E::ONE - s1)
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
    cycle_row_30 * (E::ONE - s0_next) * (E::ONE - s1_next)
}

// ================================================================================================
// COMPOSITE FLAGS
// ================================================================================================

/// Merkle operation active flag.
///
/// True when any Merkle operation (MP, MV, MU, MPA, MVA, MUA) is active.
/// Used for gating index shift constraints.
///
/// # Degree
/// - Depends on constituent flags, typically 4
#[inline]
pub fn f_merkle_active<E>(f_mp: E, f_mv: E, f_mu: E, f_mpa: E, f_mva: E, f_mua: E) -> E
where
    E: PrimeCharacteristicRing,
{
    f_mp + f_mv + f_mu + f_mpa + f_mva + f_mua
}

/// Merkle absorb flag (row 31 only).
///
/// True when absorbing the next node during Merkle path computation.
///
/// # Degree
/// - Depends on constituent flags, typically 4
#[inline]
pub fn f_merkle_absorb<E>(f_mpa: E, f_mva: E, f_mua: E) -> E
where
    E: PrimeCharacteristicRing,
{
    f_mpa + f_mva + f_mua
}

/// Continuation flag for hashing operations.
///
/// True when operation continues to next cycle (ABP, MPA, MVA, MUA).
/// Constrains s0' = 0 to ensure proper sequencing.
///
/// # Degree
/// - Depends on constituent flags, typically 4
#[inline]
pub fn f_continuation<E>(f_abp: E, f_mpa: E, f_mva: E, f_mua: E) -> E
where
    E: PrimeCharacteristicRing,
{
    f_abp + f_mpa + f_mva + f_mua
}
