//! EdDSA (Ed25519) signature verification precompile for the Miden VM.
//!
//! This precompile mirrors the flow of the existing ECDSA integration but targets Ed25519.
//! Execution emits an event with pointers to packed bytes (public key, pre-computed challenge
//! digest `k_digest`, and signature); the host verifies the signature with `miden-crypto`
//! primitives, returns the result via the advice stack, and logs the calldata for deferred
//! verification. During proof verification, the stored calldata is re-verified and committed
//! with the same hashing scheme used at execution time.

use alloc::{vec, vec::Vec};
use core::convert::TryInto;

use miden_core::{
    EventName, Felt,
    field::{PrimeCharacteristicRing, PrimeField64},
    precompile::{PrecompileCommitment, PrecompileError, PrecompileRequest, PrecompileVerifier},
    utils::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        bytes_to_packed_u32_elements,
    },
};
use miden_crypto::{
    ZERO,
    dsa::eddsa_25519_sha512::{PublicKey, Signature},
    hash::poseidon2::Poseidon2,
};
use miden_processor::{AdviceMutation, EventError, EventHandler, ProcessorState};

use crate::handlers::{MemoryReadError, read_memory_packed_u32};

// CONSTANTS
// ================================================================================================

/// Qualified event name for the EdDSA signature verification event.
pub const EDDSA25519_VERIFY_EVENT_NAME: EventName =
    EventName::new("miden::core::dsa::eddsa_ed25519::verify");

const PUBLIC_KEY_LEN_BYTES: usize = 32;
const K_DIGEST_LEN_BYTES: usize = 64;
const SIGNATURE_LEN_BYTES: usize = 64;

const PRECOMPILE_REQUEST_LEN: usize =
    PUBLIC_KEY_LEN_BYTES + K_DIGEST_LEN_BYTES + SIGNATURE_LEN_BYTES;

/// EdDSA (Ed25519) signature verification precompile handler.
pub struct EddsaPrecompile;

impl EventHandler for EddsaPrecompile {
    fn on_event(&self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
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

        let request = EddsaRequest::new(pk, k_digest, signature);
        let result = request.result();

        Ok(vec![
            AdviceMutation::extend_stack([Felt::from_bool(result)]),
            AdviceMutation::extend_precompile_requests([request.into()]),
        ])
    }
}

impl PrecompileVerifier for EddsaPrecompile {
    fn verify(&self, calldata: &[u8]) -> Result<PrecompileCommitment, PrecompileError> {
        let request = EddsaRequest::read_from_bytes(calldata)?;
        Ok(request.as_precompile_commitment())
    }
}

// REQUEST
// ================================================================================================

/// EdDSA verification request containing all data needed to re-run signature verification.
pub struct EddsaRequest {
    pk: PublicKey,
    /// Pre-computed challenge hash k = SHA-512(R || A || message), 64 bytes.
    k_digest: [u8; K_DIGEST_LEN_BYTES],
    sig: Signature,
}

impl EddsaRequest {
    pub fn new(pk: PublicKey, k_digest: [u8; K_DIGEST_LEN_BYTES], sig: Signature) -> Self {
        Self { pk, k_digest, sig }
    }

    pub fn pk(&self) -> &PublicKey {
        &self.pk
    }

    pub fn k_digest(&self) -> &[u8; K_DIGEST_LEN_BYTES] {
        &self.k_digest
    }

    pub fn sig(&self) -> &Signature {
        &self.sig
    }

    pub fn as_precompile_request(&self) -> PrecompileRequest {
        let mut calldata = Vec::with_capacity(PRECOMPILE_REQUEST_LEN);
        self.write_into(&mut calldata);
        PrecompileRequest::new(EDDSA25519_VERIFY_EVENT_NAME.to_event_id(), calldata)
    }

    pub fn result(&self) -> bool {
        self.pk.verify_with_unchecked_k(self.k_digest, &self.sig).is_ok()
    }

    pub fn as_precompile_commitment(&self) -> PrecompileCommitment {
        let result = Felt::from_bool(self.result());
        let tag = [EDDSA25519_VERIFY_EVENT_NAME.to_event_id().as_felt(), result, ZERO, ZERO].into();

        let pk_comm = {
            let felts = bytes_to_packed_u32_elements(&self.pk.to_bytes());
            Poseidon2::hash_elements(&felts)
        };
        let k_digest_comm = {
            let felts = bytes_to_packed_u32_elements(&self.k_digest);
            Poseidon2::hash_elements(&felts)
        };
        let sig_comm = {
            let felts = bytes_to_packed_u32_elements(&self.sig.to_bytes());
            Poseidon2::hash_elements(&felts)
        };

        let commitment = Poseidon2::merge(&[Poseidon2::merge(&[pk_comm, k_digest_comm]), sig_comm]);

        PrecompileCommitment::new(tag, commitment)
    }
}

impl Serializable for EddsaRequest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.pk.write_into(target);
        target.write_bytes(&self.k_digest);
        self.sig.write_into(target);
    }
}

impl Deserializable for EddsaRequest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let pk = PublicKey::read_from(source)?;
        let k_digest = source.read_array()?;
        let sig = Signature::read_from(source)?;
        Ok(Self { pk, k_digest, sig })
    }
}

impl From<EddsaRequest> for PrecompileRequest {
    fn from(request: EddsaRequest) -> Self {
        request.as_precompile_request()
    }
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
