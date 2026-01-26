//! SHA2-512 precompile for the Miden VM.
//!
//! This mirrors the Keccak256 precompile flow but targets SHA2-512. Execution-time handlers read
//! packed bytes from memory, compute the digest, extend the advice stack with the 512-bit hash, and
//! record calldata for deferred verification. Verification-time logic recomputes the digest and
//! commits to both input and output using RPO hashing.

use alloc::{vec, vec::Vec};
use core::array;

use miden_core::{
    EventName, Felt, Word, ZERO,
    field::{PrimeCharacteristicRing, PrimeField64},
    precompile::{PrecompileCommitment, PrecompileError, PrecompileRequest, PrecompileVerifier},
    utils::bytes_to_packed_u32_elements,
};
use miden_crypto::hash::rpo::Rpo256;
use miden_processor::{AdviceMutation, EventError, EventHandler, ProcessorState};
use sha2::{Digest, Sha512};

use crate::handlers::{BYTES_PER_U32, read_memory_packed_u32};

/// Event name for the SHA512 hash_bytes operation.
pub const SHA512_HASH_BYTES_EVENT_NAME: EventName =
    EventName::new("miden::core::hash::sha512::hash_bytes");

pub struct Sha512Precompile;

impl EventHandler for Sha512Precompile {
    /// SHA2-512 event handler invoked when the VM emits a hash request.
    ///
    /// Reads packed bytes from memory, computes the SHA2-512 digest, extends the advice stack with
    /// the 16 u32 limbs of the digest, and stores the raw preimage for verification.
    ///
    /// ## Input Format
    /// - **Stack**: `[event_id, ptr, len_bytes, ...]`
    /// - **Memory**: bytes packed into u32 field elements starting at `ptr`
    fn on_event(&self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        // Stack: [event_id, ptr, len_bytes, ...]
        let ptr = process.get_stack_item(1).as_canonical_u64();
        let len_bytes = process.get_stack_item(2).as_canonical_u64();

        // Read input bytes (u32-packed) from memory.
        let input_bytes = read_memory_packed_u32(process, ptr, len_bytes as usize)?;
        let preimage = Sha512Preimage::new(input_bytes);
        let digest = preimage.digest();

        Ok(vec![
            AdviceMutation::extend_stack(digest.0),
            AdviceMutation::extend_precompile_requests([preimage.into()]),
        ])
    }
}

impl PrecompileVerifier for Sha512Precompile {
    fn verify(&self, calldata: &[u8]) -> Result<PrecompileCommitment, PrecompileError> {
        let preimage = Sha512Preimage::new(calldata.to_vec());
        Ok(preimage.precompile_commitment())
    }
}

// SHA2-512 DIGEST
// ================================================================================================

/// SHA2-512 digest represented as 16 field elements (u32-packed).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Sha512FeltDigest(pub [Felt; 16]);

impl Sha512FeltDigest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 64, "digest must be 64 bytes");
        let packed: [u32; 16] = array::from_fn(|i| {
            let limbs = array::from_fn(|j| bytes[BYTES_PER_U32 * i + j]);
            u32::from_le_bytes(limbs)
        });
        Self(packed.map(Felt::from_u32))
    }

    pub fn to_commitment(&self) -> Word {
        Rpo256::hash_elements(&self.0)
    }
}

impl AsRef<[Felt]> for Sha512FeltDigest {
    fn as_ref(&self) -> &[Felt] {
        &self.0
    }
}

// SHA2-512 PREIMAGE
// ================================================================================================

/// Wrapped preimage bytes along with helpers for commitments and digest computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha512Preimage(Vec<u8>);

impl Sha512Preimage {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    pub fn as_felts(&self) -> Vec<Felt> {
        bytes_to_packed_u32_elements(self.as_ref())
    }

    pub fn input_commitment(&self) -> Word {
        Rpo256::hash_elements(&self.as_felts())
    }

    pub fn digest(&self) -> Sha512FeltDigest {
        let hash = Sha512::digest(self.as_ref());
        Sha512FeltDigest::from_bytes(&hash)
    }

    pub fn precompile_commitment(&self) -> PrecompileCommitment {
        let tag = self.precompile_tag();
        let comm = Rpo256::merge(&[self.input_commitment(), self.digest().to_commitment()]);
        PrecompileCommitment::new(tag, comm)
    }

    fn precompile_tag(&self) -> Word {
        [
            SHA512_HASH_BYTES_EVENT_NAME.to_event_id().as_felt(),
            Felt::new(self.as_ref().len() as u64),
            ZERO,
            ZERO,
        ]
        .into()
    }
}

impl AsRef<[u8]> for Sha512Preimage {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Sha512Preimage> for PrecompileRequest {
    fn from(preimage: Sha512Preimage) -> Self {
        PrecompileRequest::new(SHA512_HASH_BYTES_EVENT_NAME.to_event_id(), preimage.into_inner())
    }
}
