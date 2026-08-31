//! Shared low-level primitives.
//!
//! Lookup-backed building blocks used across every category (hashers,
//! transcript eval, ECC): the [`byte_pair_lut`] chiplet (8×8
//! byte-pair bitwise table + `Range16` range checks). `Range16` in
//! particular serves non-bitwise consumers too (e.g. the uint store's
//! 16-bit limb checks); [`byte_pair_lut::require_logic64`] serves any
//! caller that commits 64-bit operands as bytes and needs their logic
//! result range-checked directly, without an intermediate chiplet.

pub mod byte_pair_lut;
