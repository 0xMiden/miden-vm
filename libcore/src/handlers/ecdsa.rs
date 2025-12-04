//! ECDSA signature verification precompile for the Miden VM.
//!
//! This module provides both execution-time and verification-time support for ECDSA signature
//! verification using the secp256k1 curve with Keccak256 hashing.
//!
//! ## Architecture
//!
//! ### Event Handler (Execution-Time)
//! When the VM emits an ECDSA verification event requesting signature validation, the processor
//! calls [`EcdsaPrecompile`] which reads the public key, message digest, and signature from
//! memory, performs the verification, provides the boolean result via the advice stack, and logs
//! the request data for deferred verification.
//!
//! ### Precompile Verifier (Verification-Time)
//! During verification, the [`PrecompileVerifier`] receives the stored request data (public key,
//! digest, signature), re-performs the ECDSA verification, and generates a commitment
//! `Rpo256(Rpo256(Rpo256(pk) || Rpo256(digest)) || Rpo256(sig))` with a tag containing the
//! verification result that validates the computation was performed correctly. Here `pk`,
//! `digest`, and `sig` are hashed as u32‑packed field elements before being merged.
//!
//! ### Commitment Tag Format
//! Each request is tagged as `[event_id, result, 0, 0]` where `result` is 1 for valid signatures
//! and 0 for invalid ones. This allows the verifier to check that the execution-time result
//! matches the verification-time result.
//!
//! ## Data Format
//! - **Public Key**: 33 bytes (compressed secp256k1 point)
//! - **Message Digest**: 32 bytes (Keccak256 hash of the message)
//! - **Signature**: 66 bytes (implementation‑defined serialization used by
//!   `miden_crypto::dsa::ecdsa_k256_keccak::Signature`). When packed into u32 elements for VM
//!   memory, the final word contains 2 zero padding bytes (since 66 ≡ 2 mod 4).

use alloc::{vec, vec::Vec};

use miden_core::{
    EventName,
    precompile::{PrecompileCommitment, PrecompileError, PrecompileRequest, PrecompileVerifier},
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
use miden_crypto::{
    ZERO,
    dsa::ecdsa_k256_keccak::{PublicKey, Signature},
    hash::rpo::Rpo256,
};
use miden_processor::{AdviceMutation, EventError, EventHandler, ProcessState};

use crate::handlers::{bytes_to_packed_u32_felts, read_memory_packed_u32};

/// Qualified event name for the ECDSA signature verification event.
pub const ECDSA_VERIFY_EVENT_NAME: EventName =
    EventName::new("miden::core::crypto::dsa::ecdsa_k256_keccak::verify");

const PUBLIC_KEY_LEN_BYTES: usize = 33;
const MESSAGE_DIGEST_LEN_BYTES: usize = 32;
const SIGNATURE_LEN_BYTES: usize = 65; // r (32) + s (32) + v (1)

const PRECOMPILE_REQUEST_LEN: usize =
    PUBLIC_KEY_LEN_BYTES + MESSAGE_DIGEST_LEN_BYTES + SIGNATURE_LEN_BYTES;

/// ECDSA signature verification precompile handler.
pub struct EcdsaPrecompile;

impl EventHandler for EcdsaPrecompile {
    /// ECDSA verification event handler called by the processor when the VM emits a signature
    /// verification request event.
    ///
    /// Reads the public key, signature, and message digest from memory, performs ECDSA signature
    /// verification, provides the result via the advice stack, and stores the request data for
    /// verification (see [`PrecompileVerifier`]).
    ///
    /// ## Input Format
    /// - **Stack**: `[event_id, ptr_pk, ptr_digest, ptr_sig, ...]` where all pointers are
    ///   word-aligned (divisible by 4)
    /// - **Memory**: Data stored as packed u32 field elements (4 bytes per element, little-endian)
    ///   with unused bytes in the final u32 set to zero
    ///
    /// ## Output Format
    /// - **Advice Stack**: Extended with verification result (1 for valid, 0 for invalid)
    /// - **Precompile Request**: Stores tag `[event_id, result, 0, 0]` and serialized request data
    ///   (pk || digest || sig) for verification time
    fn on_event(&self, process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
        // Stack: [event_id, ptr_pk, ptr_digest, ptr_sig, ...]
        let ptr_pk = process.get_stack_item(1).as_int();
        let ptr_digest = process.get_stack_item(2).as_int();
        let ptr_sig = process.get_stack_item(3).as_int();

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

        let request = EcdsaRequest::new(pk, digest, sig);
        let result = request.result();

        Ok(vec![
            AdviceMutation::extend_stack([result.into()]),
            AdviceMutation::extend_precompile_requests([request.into()]),
        ])
    }
}

impl PrecompileVerifier for EcdsaPrecompile {
    /// Verifier for ECDSA signature verification at verification time.
    ///
    /// Receives the serialized request data (public key || digest || signature) stored during
    /// execution (see [`EventHandler::on_event`]), re-performs the ECDSA verification, and
    /// generates a commitment `RPO(RPO(RPO(pk) || RPO(digest)) || RPO(sig))` with tag
    /// `[event_id, result, 0, 0]` that validates against the execution trace. Each of `pk`,
    /// `digest`, and `sig` is first converted to u32‑packed field elements before hashing.
    fn verify(&self, calldata: &[u8]) -> Result<PrecompileCommitment, PrecompileError> {
        let request = EcdsaRequest::read_from_bytes(calldata)?;
        Ok(request.as_precompile_commitment())
    }
}

/// ECDSA signature verification request containing all data needed to verify a signature.
///
/// This structure encapsulates a complete ECDSA verification request including the public key,
/// message digest, and signature. It is used during both execution (via the event handler) and
/// verification (via the precompile verifier).
pub struct EcdsaRequest {
    /// secp256k1 public key (33 bytes, compressed)
    pk: PublicKey,
    /// Message digest (32 bytes, typically Keccak256 hash)
    digest: [u8; MESSAGE_DIGEST_LEN_BYTES],
    /// ECDSA signature (serialized by the implementation; 66 bytes in this crate)
    sig: Signature,
}

impl EcdsaRequest {
    /// Creates a new ECDSA verification request.
    ///
    /// # Arguments
    /// * `pk` - The secp256k1 public key (33 bytes, compressed)
    /// * `digest` - The message digest (32 bytes)
    /// * `sig` - The ECDSA signature
    pub fn new(pk: PublicKey, digest: [u8; MESSAGE_DIGEST_LEN_BYTES], sig: Signature) -> Self {
        Self { pk, digest, sig }
    }

    /// Returns a reference to the public key.
    pub fn pk(&self) -> &PublicKey {
        &self.pk
    }

    /// Returns a reference to the digest.
    pub fn digest(&self) -> &[u8; MESSAGE_DIGEST_LEN_BYTES] {
        &self.digest
    }

    /// Returns a reference to the signature.
    pub fn sig(&self) -> &Signature {
        &self.sig
    }

    /// Converts this request into a [`PrecompileRequest`] for deferred verification.
    ///
    /// Serializes the request data (public key || digest || signature) and wraps it in a
    /// PrecompileRequest with the ECDSA event ID.
    pub fn as_precompile_request(&self) -> PrecompileRequest {
        let mut calldata = Vec::with_capacity(PRECOMPILE_REQUEST_LEN);
        self.write_into(&mut calldata);
        PrecompileRequest::new(ECDSA_VERIFY_EVENT_NAME.to_event_id(), calldata)
    }

    /// Performs ECDSA signature verification and returns the result.
    ///
    /// Returns `true` if the signature is valid for the given public key and digest,
    /// `false` otherwise.
    pub fn result(&self) -> bool {
        self.pk.verify_prehash(self.digest, &self.sig)
    }

    /// Computes the precompile commitment for this request.
    ///
    /// The commitment is `RPO(RPO(RPO(pk) || RPO(digest)) || RPO(sig))` with tag
    /// `[event_id, result, 0, 0]`, where `result` is 1 for valid signatures and 0 for
    /// invalid ones. Each component is hashed over u32‑packed field elements.
    ///
    /// This is called by the [`PrecompileVerifier`] at verification time and must match
    /// the commitment generated during execution.
    pub fn as_precompile_commitment(&self) -> PrecompileCommitment {
        // Compute tag: [event_id, result, 0, 0]
        let result = self.result().into();
        let tag = [ECDSA_VERIFY_EVENT_NAME.to_event_id().as_felt(), result, ZERO, ZERO].into();

        // Convert serialized bytes to field elements and hash
        let pk_comm = {
            let felts = bytes_to_packed_u32_felts(&self.pk.to_bytes());
            Rpo256::hash_elements(&felts)
        };
        let digest_comm = {
            // `digest` is a 32‑byte array; hash its u32‑packed representation
            let felts = bytes_to_packed_u32_felts(&self.digest);
            Rpo256::hash_elements(&felts)
        };
        let sig_comm = {
            let felts = bytes_to_packed_u32_felts(&self.sig.to_bytes());
            Rpo256::hash_elements(&felts)
        };

        let commitment = Rpo256::merge(&[Rpo256::merge(&[pk_comm, digest_comm]), sig_comm]);

        PrecompileCommitment::new(tag, commitment)
    }
}

impl Serializable for EcdsaRequest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.pk.write_into(target);
        self.digest.write_into(target);
        self.sig.write_into(target);
    }
}

impl Deserializable for EcdsaRequest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let pk = PublicKey::read_from(source)?;
        let digest = source.read_array()?;
        let sig = Signature::read_from(source)?;
        Ok(Self { pk, digest, sig })
    }
}

impl From<EcdsaRequest> for PrecompileRequest {
    fn from(request: EcdsaRequest) -> Self {
        request.as_precompile_request()
    }
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
