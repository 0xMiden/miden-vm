//! Keccak256 precompile for the Miden VM.
//!
//! This module provides both execution-time and verification-time support for Keccak256 hashing.
//!
//! ## Architecture
//!
//! ### Event Handler (Execution-Time)
//! When the VM emits a Keccak event requesting non-deterministic hash results, the processor calls
//! [`KeccakPrecompile`] which reads input data from memory, computes the hash, provides the digest
//! via the advice stack, and logs the raw preimage bytes as a precompile request.
//!
//! ### Precompile Verifier (Verification-Time)
//! During verification, the [`PrecompileVerifier`] receives the stored preimage bytes, recomputes
//! the hash, and generates a commitment `RPO(RPO(input) || RPO(digest))` that validates the
//! computation was performed correctly.
//!
//! ### Commitment Tag Format
//! Each request is tagged as `[event_id, len_bytes, 0, 0]`. The `len_bytes` field prevents
//! collisions: since bytes are packed into 32-bit limbs, we must distinguish actual data bytes
//! from padding in the final limb.
//!
//! ## Digest Representation
//! A Keccak256 digest (256 bits) is represented as 8 field elements `[h0, ..., h7]`,
//! each containing a u32 value where `hi = u32::from_le_bytes([b_{4i}, ..., b_{4i+3}])`.

use alloc::{vec, vec::Vec};
use core::array;

use miden_core::{
    EventName, Felt, Word, ZERO,
    precompile::{PrecompileCommitment, PrecompileError, PrecompileRequest, PrecompileVerifier},
};
use miden_crypto::hash::{keccak::Keccak256, rpo::Rpo256};
use miden_processor::{AdviceMutation, EventError, EventHandler, ProcessState};

use crate::handlers::{BYTES_PER_U32, bytes_to_packed_u32_felts, read_memory_packed_u32};

/// Event name for the keccak256 hash_bytes operation.
pub const KECCAK_HASH_BYTES_EVENT_NAME: EventName =
    EventName::new("miden::core::hash::keccak256::hash_bytes");

pub struct KeccakPrecompile;

impl EventHandler for KeccakPrecompile {
    /// Keccak256 event handler called by the processor when the VM emits a hash request event.
    ///
    /// Reads packed input data from memory, computes the Keccak256 hash, provides the digest via
    /// the advice stack, and stores the raw preimage for verification (see [`PrecompileVerifier`]).
    ///
    /// ## Input Format
    /// - **Stack**: `[event_id, ptr, len_bytes, ...]` where `ptr` is word-aligned (divisible by 4)
    /// - **Memory**: Input bytes packed as u32 field elements (4 bytes per element, little-endian)
    ///   from `ptr` to `ptr+ceil(len_bytes/4)`, with unused bytes in the final u32 set to zero
    ///
    /// ## Output Format
    /// - **Advice Stack**: Extended with digest `[h_0, ..., h_7]` (least significant u32 on top)
    /// - **Precompile Request**: Stores tag `[event_id, len_bytes, 0, 0]` and raw preimage bytes
    ///   for verification time
    fn on_event(&self, process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
        // Stack: [event_id, ptr, len_bytes, ...]
        let ptr = process.get_stack_item(1).as_int();
        let len_bytes = process.get_stack_item(2).as_int();

        // Read input bytes from memory using the shared helper (u32-packed, LE, zero-padded)
        let input_bytes = read_memory_packed_u32(process, ptr, len_bytes as usize)?;

        // Build preimage from bytes and compute digest
        let preimage = KeccakPreimage::new(input_bytes);
        let digest = preimage.digest();

        // Extend the stack with the digest [h_0, ..., h_7] so it can be popped in the right order
        let advice_stack_extension = AdviceMutation::extend_stack(digest.0);

        // Store the precompile data for deferred verification.
        let precompile_request_extension =
            AdviceMutation::extend_precompile_requests([preimage.into()]);

        Ok(vec![advice_stack_extension, precompile_request_extension])
    }
}

// KECCAK VERIFIER
// ================================================================================================

impl PrecompileVerifier for KeccakPrecompile {
    /// Verifier for Keccak256 precompile computations at verification time.
    ///
    /// Receives the raw preimage bytes stored during execution (see [`EventHandler::on_event`]),
    /// recomputes the Keccak256 hash, and generates a commitment `RPO(RPO(input) || RPO(digest))`
    /// with tag `[event_id, len_bytes, 0, 0]` that validates against the execution trace.
    fn verify(&self, calldata: &[u8]) -> Result<PrecompileCommitment, PrecompileError> {
        let preimage = KeccakPreimage::new(calldata.to_vec());
        Ok(preimage.precompile_commitment())
    }
}

// KECCAK DIGEST
// ================================================================================================

/// Keccak256 digest representation in the Miden VM.
///
/// Represents a 256-bit Keccak digest as 8 field elements, each containing a u32 value
/// packed in little-endian order: `[d_0, ..., d_7]` where
/// `d_0 = u32::from_le_bytes([b_0, b_1, b_2, b_3])` and so on.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct KeccakFeltDigest([Felt; 8]);

impl KeccakFeltDigest {
    /// Creates a digest from a 32-byte Keccak256 hash output.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 32, "input must be 32 bytes");
        let packed: [u32; 8] = array::from_fn(|i| {
            let limbs = array::from_fn(|j| bytes[BYTES_PER_U32 * i + j]);
            u32::from_le_bytes(limbs)
        });
        Self(packed.map(Felt::from))
    }

    /// Creates a commitment of the digest using Rpo256 over `[d_0, ..., d_7]`.
    pub fn to_commitment(&self) -> Word {
        Rpo256::hash_elements(&self.0)
    }
}

// KECCAK PREIMAGE
// ================================================================================================

/// Keccak256 preimage structure representing the raw input data to be hashed.
///
/// This structure encapsulates the raw bytes that will be passed to the Keccak256
/// hash function, providing utilities for:
/// - Converting between bytes and field element representations
/// - Computing the Keccak256 digest
/// - Generating precompile commitments for verification
/// - Handling the data packing format used by the VM
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeccakPreimage(Vec<u8>);

impl KeccakPreimage {
    /// Creates a new `KeccakPreimage` from a vector of bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Consumes the preimage and returns the inner byte vector.
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    /// Converts the preimage bytes to field elements using u32 packing.
    ///
    /// Each field element contains a u32 value representing 4 bytes in little-endian format.
    /// The last chunk is padded with zeros if the byte length is not a multiple of 4.
    ///
    /// Produces the same u32‑packed format expected by RPO hashing in MASM wrappers.
    pub fn as_felts(&self) -> Vec<Felt> {
        bytes_to_packed_u32_felts(self.as_ref())
    }

    /// Computes the RPO hash of the input data in field element format.
    ///
    /// This creates a cryptographic commitment to the input data that can be
    /// used for verification purposes. The input is first converted to field
    /// elements using the same packing format as the VM.
    pub fn input_commitment(&self) -> Word {
        Rpo256::hash_elements(&self.as_felts())
    }

    /// Computes the Keccak256 hash of the preimage bytes.
    ///
    /// Returns the digest formatted as 8 field elements, each containing a u32 value
    /// in little-endian byte order. This matches the format expected by the VM
    /// and can be directly used on the operand stack.
    pub fn digest(&self) -> KeccakFeltDigest {
        let hash_u8 = Keccak256::hash(self.as_ref());
        KeccakFeltDigest::from_bytes(&hash_u8)
    }

    /// Computes the precompile commitment: `RPO(RPO(input) || RPO(keccak_hash))` with tag
    /// `[event_id, len_bytes, 0, 0]`.
    ///
    /// Generated by the [`PrecompileVerifier`] at verification time and validated against
    /// commitments tracked during execution by the [`EventHandler`]. The double RPO hash binds
    /// input and output together, preventing tampering.
    pub fn precompile_commitment(&self) -> PrecompileCommitment {
        let tag = self.precompile_tag();
        let comm = Rpo256::merge(&[self.input_commitment(), self.digest().to_commitment()]);
        PrecompileCommitment::new(tag, comm)
    }

    /// Returns the tag used to identify the commitment to the precompile. defined as
    /// `[event_id, preimage_u8.len(), 0, 0]` where event_id is computed from the event name.
    fn precompile_tag(&self) -> Word {
        [
            KECCAK_HASH_BYTES_EVENT_NAME.to_event_id().as_felt(),
            Felt::new(self.as_ref().len() as u64),
            ZERO,
            ZERO,
        ]
        .into()
    }
}

impl From<KeccakPreimage> for PrecompileRequest {
    fn from(preimage: KeccakPreimage) -> Self {
        let event_id = KECCAK_HASH_BYTES_EVENT_NAME.to_event_id();
        PrecompileRequest::new(event_id, preimage.into_inner())
    }
}

impl AsRef<[u8]> for KeccakPreimage {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for KeccakPreimage {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl AsRef<[Felt]> for KeccakFeltDigest {
    fn as_ref(&self) -> &[Felt] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // KECCAK FELT DIGEST TESTS
    // ============================================================================================

    #[test]
    fn test_keccak_felt_digest_from_bytes() {
        // Test with a known 32-byte sequence
        let bytes: Vec<u8> = (1..=32).collect();
        let digest = KeccakFeltDigest::from_bytes(&bytes);

        // Verify each u32 is packed correctly in little-endian order
        // Each u32 is constructed from 4 consecutive bytes: byte[i] + byte[i+1]<<8 + byte[i+2]<<16
        // + byte[i+3]<<24
        let expected = [
            u32::from_le_bytes([1, 2, 3, 4]),
            u32::from_le_bytes([5, 6, 7, 8]),
            u32::from_le_bytes([9, 10, 11, 12]),
            u32::from_le_bytes([13, 14, 15, 16]),
            u32::from_le_bytes([17, 18, 19, 20]),
            u32::from_le_bytes([21, 22, 23, 24]),
            u32::from_le_bytes([25, 26, 27, 28]),
            u32::from_le_bytes([29, 30, 31, 32]),
        ]
        .map(Felt::from);

        assert_eq!(digest.0, expected);
    }

    // KECCAK PREIMAGE TESTS
    // ============================================================================================

    #[test]
    fn test_keccak_preimage_packing_cases() {
        // Table of inputs and expected u32-packed felts (little-endian)
        let cases: &[(&[u8], &[u32])] = &[
            (&[], &[]),
            (&[0x42], &[0x0000_0042]),
            (&[1, 2, 3, 4], &[0x0403_0201]),
            (&[1, 2, 3, 4, 5], &[0x0403_0201, 0x0000_0005]),
        ];

        for (input, expected_u32) in cases {
            let preimage = KeccakPreimage::new((*input).to_vec());
            let felts = preimage.as_felts();
            assert_eq!(felts.len(), expected_u32.len());
            for (felt, &u) in felts.iter().zip((*expected_u32).iter()) {
                assert_eq!(*felt, Felt::from(u));
            }

            if input.is_empty() {
                assert_eq!(preimage.input_commitment(), Word::empty());
            }
        }

        // 32-byte boundary sanity check
        let input: Vec<u8> = (1..=32).collect();
        let preimage = KeccakPreimage::new(input);
        let felts = preimage.as_felts();
        assert_eq!(felts.len(), 8);
        assert_eq!(felts[0], Felt::from(u32::from_le_bytes([1, 2, 3, 4])));
        assert_eq!(felts[7], Felt::from(u32::from_le_bytes([29, 30, 31, 32])));
    }

    #[test]
    fn test_keccak_preimage_digest_consistency() {
        // Test that digest computation is consistent with direct Keccak256
        let input = b"hello world";
        let preimage = KeccakPreimage::new(input.to_vec());

        // Compute digest using preimage
        let preimage_digest = preimage.digest();

        // Compute digest directly using Keccak256
        let direct_hash = Keccak256::hash(input);
        let direct_digest = KeccakFeltDigest::from_bytes(&direct_hash);

        assert_eq!(preimage_digest, direct_digest);
    }

    #[test]
    fn test_keccak_preimage_commitments() {
        let input = b"test input for commitments";
        let preimage = KeccakPreimage::new(input.to_vec());

        // Test input commitment
        let felts = preimage.as_felts();
        let expected_input_commitment = Rpo256::hash_elements(&felts);
        assert_eq!(preimage.input_commitment(), expected_input_commitment);

        // Test digest commitment
        let digest = preimage.digest();
        let expected_digest_commitment = Rpo256::hash_elements(digest.as_ref());
        assert_eq!(digest.to_commitment(), expected_digest_commitment);

        // Test precompile commitment (double hash)
        let expected_precompile_commitment = PrecompileCommitment::new(
            preimage.precompile_tag(),
            Rpo256::merge(&[preimage.input_commitment(), digest.to_commitment()]),
        );

        assert_eq!(preimage.precompile_commitment(), expected_precompile_commitment);
    }

    #[test]
    fn test_keccak_verifier() {
        let input = b"test verifier input";
        let preimage = KeccakPreimage::new(input.to_vec());
        let expected_commitment = preimage.precompile_commitment();

        let commitment = KeccakPrecompile.verify(input).unwrap();
        assert_eq!(commitment, expected_commitment);
    }
}
