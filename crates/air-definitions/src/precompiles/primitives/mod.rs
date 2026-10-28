//! Shared low-level primitives.
//!
//! Lookup-backed building blocks used across every category (hashers,
//! transcript eval, ECC): the [`byte_pair_lut`] chiplet (8×8
//! byte-pair bitwise table + `Range16` range checks). `Range16` in
//! particular serves non-bitwise consumers too, such as the uint store's
//! 16-bit limb checks.

pub mod byte_pair_lut;
