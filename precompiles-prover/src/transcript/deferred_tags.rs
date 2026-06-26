//! VM deferred tag words used by the Keccak MVP.

use miden_core::{Felt, deferred::Tag};
use miden_precompiles::Keccak256Precompile;

/// Framework-owned opaque chunk-list data tag: VM `Tag::CHUNKS`.
pub fn chunks() -> [Felt; 4] {
    Tag::CHUNKS.as_word()
}

/// Framework-owned semantic conjunction tag: VM `Tag::AND`.
pub fn and() -> [Felt; 4] {
    Tag::AND.as_word()
}

/// Keccak-256 hash assertion tag carrying the preimage byte length.
pub fn keccak_assert(len_bytes: u32) -> [Felt; 4] {
    Keccak256Precompile::assert_tag(len_bytes).as_word()
}
