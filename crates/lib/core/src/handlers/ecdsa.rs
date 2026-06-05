//! ECDSA signature verification advice handler for the Miden VM.
//!
//! This module provides execution-time advice support for ECDSA signature verification using the
//! secp256k1 curve with Keccak256 hashing.
//!
//! When the VM emits an ECDSA verification event requesting signature validation, the processor
//! calls [`handle_ecdsa_verify`] which reads the public key, message digest, and signature from
//! memory, performs the verification, and provides the boolean result via the advice stack.
//!
//! ## Data Format
//! - **Public Key**: 33 bytes (compressed secp256k1 point)
//! - **Message Digest**: 32 bytes (Keccak256 hash of the message)
//! - **Signature**: 65 bytes (implementation‑defined serialization used by
//!   `miden_crypto::dsa::ecdsa_k256_keccak::Signature`). When packed into u32 elements for VM
//!   memory, the final word contains 3 zero padding bytes (since 65 ≡ 1 mod 4).

use alloc::{vec, vec::Vec};

use miden_core::{
    ONE, ZERO,
    events::EventName,
    serde::{Deserializable, DeserializationError},
};
use miden_crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_processor::{ProcessorState, advice::AdviceMutation, event::EventError};

use crate::handlers::read_memory_packed_u32;

/// Qualified event name for the ECDSA signature verification event.
pub const ECDSA_VERIFY_EVENT_NAME: EventName =
    EventName::new("miden::core::crypto::dsa::ecdsa_k256_keccak::verify");

const PUBLIC_KEY_LEN_BYTES: usize = 33;
const MESSAGE_DIGEST_LEN_BYTES: usize = 32;
const SIGNATURE_LEN_BYTES: usize = 65; // r (32) + s (32) + v (1)

/// ECDSA verification event handler called by the processor when the VM emits a signature
/// verification request event.
///
/// Reads the public key, signature, and message digest from memory, performs ECDSA signature
/// verification, and provides the result via the advice stack.
///
/// ## Input Format
/// - **Stack**: `[event_id, ptr_pk, ptr_digest, ptr_sig, ...]` where all pointers are word-aligned
///   (divisible by 4)
/// - **Memory**: Data stored as packed u32 field elements (4 bytes per element, little-endian) with
///   unused bytes in the final u32 set to zero
///
/// ## Output Format
/// - **Advice Stack**: Extended with verification result (1 for valid, 0 for invalid)
pub fn handle_ecdsa_verify(process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
    // Stack: [event_id, ptr_pk, ptr_digest, ptr_sig, ...]
    let ptr_pk = process.get_stack_item(1).as_canonical_u64();
    let ptr_digest = process.get_stack_item(2).as_canonical_u64();
    let ptr_sig = process.get_stack_item(3).as_canonical_u64();

    let pk = {
        let data_type = DataType::PublicKey;
        let bytes = read_memory_packed_u32(process, ptr_pk, PUBLIC_KEY_LEN_BYTES)
            .map_err(|source| EcdsaError::ReadError { data_type, source })?;
        PublicKey::read_from_bytes(&bytes)
            .map_err(|source| EcdsaError::DeserializeError { data_type, source })?
    };

    let sig = {
        let data_type = DataType::Signature;
        let bytes = read_memory_packed_u32(process, ptr_sig, SIGNATURE_LEN_BYTES)
            .map_err(|source| EcdsaError::ReadError { data_type, source })?;
        Signature::read_from_bytes(&bytes)
            .map_err(|source| EcdsaError::DeserializeError { data_type, source })?
    };

    let digest = read_memory_packed_u32(process, ptr_digest, MESSAGE_DIGEST_LEN_BYTES)
        .map_err(|source| EcdsaError::ReadError { data_type: DataType::Digest, source })?
        .try_into()
        .expect("digest is exactly 32 bytes");

    let result = pk.verify_prehash(digest, &sig);

    Ok(vec![AdviceMutation::extend_stack([if result { ONE } else { ZERO }])])
}

// ERROR TYPES
// ================================================================================================

/// Type of data being read/processed during ECDSA verification.
#[derive(Debug, Clone, Copy)]
pub(crate) enum DataType {
    PublicKey,
    Signature,
    Digest,
}

impl core::fmt::Display for DataType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DataType::PublicKey => write!(f, "public key"),
            DataType::Signature => write!(f, "signature"),
            DataType::Digest => write!(f, "digest"),
        }
    }
}

/// Error types that can occur during ECDSA signature verification operations.
#[derive(Debug, thiserror::Error)]
pub(crate) enum EcdsaError {
    /// Failed to read data from memory.
    #[error("failed to read {data_type} from memory")]
    ReadError {
        data_type: DataType,
        #[source]
        source: crate::handlers::MemoryReadError,
    },

    /// Failed to deserialize data.
    #[error("failed to deserialize {data_type}")]
    DeserializeError {
        data_type: DataType,
        #[source]
        source: DeserializationError,
    },
}
