//! EdDSA (Ed25519) signature verification advice handler for the Miden VM.
//!
//! This advice handler mirrors the flow of the existing ECDSA integration but targets Ed25519.
//! Execution emits an event with pointers to packed bytes (public key, pre-computed challenge
//! digest `k_digest`, and signature); the host verifies the signature with `miden-crypto`
//! primitives and returns the result via the advice stack.

use alloc::{vec, vec::Vec};
use core::convert::TryInto;

use miden_core::{
    ONE, ZERO,
    events::EventName,
    serde::{Deserializable, DeserializationError},
};
use miden_crypto::dsa::eddsa_25519_sha512::{PublicKey, Signature};
use miden_processor::{ProcessorState, advice::AdviceMutation, event::EventError};

use crate::handlers::{MemoryReadError, read_memory_packed_u32};

// CONSTANTS
// ================================================================================================

/// Qualified event name for the EdDSA signature verification event.
pub const EDDSA25519_VERIFY_EVENT_NAME: EventName =
    EventName::new("miden::core::dsa::eddsa_ed25519::verify");

const PUBLIC_KEY_LEN_BYTES: usize = 32;
const K_DIGEST_LEN_BYTES: usize = 64;
const SIGNATURE_LEN_BYTES: usize = 64;

/// EdDSA (Ed25519) verification event handler called by the processor when the VM emits a
/// signature verification request event.
pub fn handle_eddsa_verify(process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
    // Stack: [event_id, pk_ptr, k_digest_ptr, sig_ptr, ...]
    let pk_ptr = process.get_stack_item(1).as_canonical_u64();
    let k_digest_ptr = process.get_stack_item(2).as_canonical_u64();
    let sig_ptr = process.get_stack_item(3).as_canonical_u64();

    let pk = {
        let data_type = DataType::PublicKey;
        let bytes = read_memory_packed_u32(process, pk_ptr, PUBLIC_KEY_LEN_BYTES)
            .map_err(|source| EddsaError::ReadError { data_type, source })?;
        PublicKey::read_from_bytes(&bytes)
            .map_err(|source| EddsaError::DeserializeError { data_type, source })?
    };

    let k_digest = {
        let data_type = DataType::KDigest;
        let bytes = read_memory_packed_u32(process, k_digest_ptr, K_DIGEST_LEN_BYTES)
            .map_err(|source| EddsaError::ReadError { data_type, source })?;
        bytes.try_into().expect("k-digest length must be exactly 64 bytes")
    };

    let signature = {
        let data_type = DataType::Signature;
        let bytes = read_memory_packed_u32(process, sig_ptr, SIGNATURE_LEN_BYTES)
            .map_err(|source| EddsaError::ReadError { data_type, source })?;
        Signature::read_from_bytes(&bytes)
            .map_err(|source| EddsaError::DeserializeError { data_type, source })?
    };

    let result = pk.verify_with_unchecked_k(k_digest, &signature).is_ok();

    Ok(vec![AdviceMutation::extend_stack([if result { ONE } else { ZERO }])])
}

// ERRORS
// ================================================================================================

#[derive(Debug, Clone, Copy)]
pub(crate) enum DataType {
    PublicKey,
    KDigest,
    Signature,
}

impl core::fmt::Display for DataType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DataType::PublicKey => write!(f, "public key"),
            DataType::KDigest => write!(f, "k-digest"),
            DataType::Signature => write!(f, "signature"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EddsaError {
    #[error("failed to read {data_type} from memory")]
    ReadError {
        data_type: DataType,
        #[source]
        source: MemoryReadError,
    },

    #[error("failed to deserialize {data_type}")]
    DeserializeError {
        data_type: DataType,
        #[source]
        source: DeserializationError,
    },
}
