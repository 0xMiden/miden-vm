//! Hasher chiplet flag computation functions.
//!
//! In the controller/permutation split architecture, flags are pure selector expressions
//! with no periodic column dependencies. They identify the operation type on controller rows.
//!
//! ## Controller Input Flags (s0=1)
//!
//! | Flag | s0 | s1 | s2 | Operation |
//! |------|----|----|----|--------------------|
//! | f_sponge | 1  | 0  | 0  | Sponge mode (linear hash / 2-to-1 hash / HPERM) |
//! | f_mp | 1  | 0  | 1  | Merkle path verify |
//! | f_mv | 1  | 1  | 0  | Merkle verify (old root) |
//! | f_mu | 1  | 1  | 1  | Merkle update (new root) |
//!
//! ## Controller Output Flags (s0=0, s1=0)
//!
//! | Flag   | s0 | s1 | s2 | Operation |
//! |--------|----|----|----|--------------------|
//! | f_hout | 0  | 0  | 0  | Return digest |
//! | f_sout | 0  | 0  | 1  | Return full state |
//!
//! ## Permutation Segment
//!
//! Perm segment rows are identified by `perm_seg=1`. No operation-specific flags apply
//! on perm rows.

use miden_core::field::PrimeCharacteristicRing;

// CONTROLLER INPUT FLAGS
// ================================================================================================

/// Sponge-mode input flag `(1,0,0)`.
///
/// Active on controller input rows for sponge-mode operations: linear hash (multi-batch
/// span), single 2-to-1 hash, or HPERM. In sponge mode, capacity is set once and carried
/// through across continuations (as opposed to tree mode, where capacity is zeroed at
/// every level).
///
/// # Degree: 3 (s0 * !s1 * !s2)
#[inline]
pub fn f_sponge<E: PrimeCharacteristicRing>(s0: E, s1: E, s2: E) -> E {
    s0 * (E::ONE - s1) * (E::ONE - s2)
}

/// MP: Merkle Path verification input flag `(1,0,1)`.
///
/// Active on MPVERIFY controller input rows. MPVERIFY is a read-only path check --
/// it does not interact with the sibling table.
///
/// # Degree: 3 (s0 * !s1 * s2)
#[inline]
#[allow(dead_code)]
pub fn f_mp<E: PrimeCharacteristicRing>(s0: E, s1: E, s2: E) -> E {
    s0 * (E::ONE - s1) * s2
}

/// MV: old-path leg of MRUPDATE, input flag `(1,1,0)`.
///
/// Active on MR_UPDATE_OLD controller input rows. Each MV row inserts a sibling
/// into the virtual sibling table via the hash_kernel bus.
///
/// # Degree: 3 (s0 * s1 * !s2)
#[inline]
pub fn f_mv<E: PrimeCharacteristicRing>(s0: E, s1: E, s2: E) -> E {
    s0 * s1 * (E::ONE - s2)
}

/// MU: new-path leg of MRUPDATE, input flag `(1,1,1)`.
///
/// Active on MR_UPDATE_NEW controller input rows. Each MU row removes a sibling
/// from the virtual sibling table. The table balance ensures the same siblings
/// are used for both the old and new paths.
///
/// # Degree: 3 (s0 * s1 * s2)
#[inline]
pub fn f_mu<E: PrimeCharacteristicRing>(s0: E, s1: E, s2: E) -> E {
    s0 * s1 * s2
}

// CONTROLLER OUTPUT FLAGS
// ================================================================================================

/// HOUT: Hash Output (digest return) flag `(0,0,0)`.
///
/// # Degree: 3 (!s0 * !s1 * !s2)
#[inline]
pub fn f_hout<E: PrimeCharacteristicRing>(s0: E, s1: E, s2: E) -> E {
    (E::ONE - s0) * (E::ONE - s1) * (E::ONE - s2)
}

/// SOUT: State Output (full state return) flag `(0,0,1)`.
///
/// # Degree: 3 (!s0 * !s1 * s2)
#[inline]
#[allow(dead_code)]
pub fn f_sout<E: PrimeCharacteristicRing>(s0: E, s1: E, s2: E) -> E {
    (E::ONE - s0) * (E::ONE - s1) * s2
}

// COMPOSITE FLAGS
// ================================================================================================

/// Any controller input row flag.
///
/// # Degree: 1 (s0)
#[inline]
#[allow(dead_code)]
pub fn f_input<E: PrimeCharacteristicRing>(s0: E) -> E {
    s0
}

/// Any controller output row flag.
///
/// # Degree: 2 (!s0 * !s1)
#[inline]
#[allow(dead_code)]
pub fn f_output<E: PrimeCharacteristicRing>(s0: E, s1: E) -> E {
    (E::ONE - s0) * (E::ONE - s1)
}

/// Any Merkle input row flag (MP or MV or MU).
///
/// `s0 * (s1 + s2 - s1*s2)` which equals `s0 * (1 - (1-s1)*(1-s2))`.
/// This is 1 when s0=1 and at least one of s1,s2 is 1.
///
/// # Degree: 3
#[inline]
pub fn f_merkle_input<E: PrimeCharacteristicRing>(s0: E, s1: E, s2: E) -> E {
    s0 * (s1.clone() + s2.clone() - s1 * s2)
}
