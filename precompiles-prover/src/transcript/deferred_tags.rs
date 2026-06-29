//! VM deferred tag words mirrored for the Keccak MVP.
//!
//! The prover currently cannot depend on the checked-out VM crates in production because the VM has
//! moved to a newer p3 dependency line than `miden-lifted-*`. Keep these constants tiny and covered
//! by VM equality tests until the dependency stack can be aligned.

use miden_core::{Felt, ONE, ZERO};

/// Keccak-256 precompile id derived by the VM for `keccak256`.
const KECCAK256_PRECOMPILE_ID: u64 = 1_416_710_563_871_706_399;

/// Hash assertion discriminant used by VM `HashPrecompile`.
const HASH_ASSERT_DISC: u32 = 0;

/// Framework-owned opaque chunk-list data tag: VM `Tag::CHUNKS`.
pub fn chunks() -> [Felt; 4] {
    [Felt::from_u32(2), ZERO, ZERO, ZERO]
}

/// Framework-owned semantic conjunction tag: VM `Tag::AND`.
pub fn and() -> [Felt; 4] {
    [ONE, ZERO, ZERO, ZERO]
}

/// Keccak-256 hash assertion tag carrying the preimage byte length.
pub fn keccak_assert(len_bytes: u32) -> [Felt; 4] {
    [
        Felt::new(KECCAK256_PRECOMPILE_ID).expect("Keccak precompile id is canonical"),
        Felt::from_u32(HASH_ASSERT_DISC),
        Felt::from_u32(len_bytes),
        ZERO,
    ]
}
