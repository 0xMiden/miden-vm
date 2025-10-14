//! Precompile framework for deferred verification in the Miden VM.
//!
//! This module provides the infrastructure for executing computationally expensive operations
//! (precompiles) during VM execution while deferring their verification until proof generation.
//!
//! # Overview
//!
//! Precompiles enable the Miden VM to efficiently handle operations like cryptographic hashing
//! (e.g., Keccak256) that would be prohibitively expensive to prove directly in the VM. Instead
//! of proving every step of these computations, the VM uses a deferred verification approach.
//!
//! # Workflow
//!
//! The precompile system follows a four-stage lifecycle:
//!
//! 1. **VM Execution**: When a program calls a precompile (via an event handler), the VM:
//!    - Computes the result non-deterministically using the host
//!    - Creates a [`PrecompileCommitment`] binding inputs and outputs together
//!    - Stores a [`PrecompileRequest`] containing the raw input data for later verification
//!    - Absorbs the commitment into a running capacity (sponge state)
//!
//! 2. **Request Storage**: All precompile requests are collected and included in the execution
//!    proof alongside the final capacity word produced by the VM.
//!
//! 3. **Proof Generation**: The prover generates a STARK proof of the VM execution, including the
//!    final capacity as a public input.
//!
//! 4. **Verification**: The verifier:
//!    - Recomputes each precompile using the stored requests via [`PrecompileVerifier`]
//!    - Reconstructs the capacity using `PrecompileVerificationState`
//!    - Verifies the STARK proof with the recomputed capacity as public input
//!    - Accepts the proof only if both the STARK and the capacity match
//!
//! # Key Types
//!
//! - [`PrecompileRequest`]: Stores the event ID and raw input bytes for a precompile call
//! - [`PrecompileCommitment`]: A cryptographic commitment to both inputs and outputs, consisting of
//!   a tag (with event ID and metadata) and a commitment word
//! - [`PrecompileVerifier`]: Trait for implementing verification logic for specific precompiles
//! - [`PrecompileVerifierRegistry`]: Registry mapping event IDs to their verifier implementations
//! - `PrecompileVerificationState`: Tracks the RPO256 sponge capacity for aggregating commitments
//!
//! # Example Implementation
//!
//! See the Keccak256 precompile in `miden_stdlib::handlers::keccak256` for a complete reference
//! implementation demonstrating both execution-time event handling and verification-time
//! commitment recomputation.
//!
//! # Security Considerations
//!
//! **⚠️ Alpha Status**: This framework is under active development and subject to change. The
//! security model assumes a fixed set of precompiles supported by the network. User-defined
//! precompiles cannot be verified in the current architecture.

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec::Vec};
use core::error::Error;

use miden_crypto::{Felt, Word, hash::rpo::Rpo256};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    EventId,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// PRECOMPILE REQUEST
// ================================================================================================

/// Represents a single precompile request consisting of an event ID and byte data.
///
/// This structure encapsulates the call data for a precompile operation, storing
/// the raw bytes that will be processed by the precompile verifier when recomputing the
/// corresponding commitment.
///
/// The `EventId` corresponds to the one used by the `EventHandler` that invoked the precompile
/// during VM execution. The verifier uses this ID to select the appropriate `PrecompileVerifier`
/// to validate the `calldata`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_serde_test_macros::serde_test(winter_serde(true))
)]
pub struct PrecompileRequest {
    /// Event ID identifying the type of precompile operation
    event_id: EventId,
    /// Raw byte data representing the input of the precompile computation
    calldata: Vec<u8>,
}

impl PrecompileRequest {
    pub fn new(event_id: EventId, calldata: Vec<u8>) -> Self {
        Self { event_id, calldata }
    }

    pub fn calldata(&self) -> &[u8] {
        &self.calldata
    }

    pub fn event_id(&self) -> EventId {
        self.event_id
    }
}

impl Serializable for PrecompileRequest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.event_id.write_into(target);
        self.calldata.write_into(target);
    }
}

impl Deserializable for PrecompileRequest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let event_id = EventId::read_from(source)?;
        let calldata = Vec::<u8>::read_from(source)?;
        Ok(Self { event_id, calldata })
    }
}

// PRECOMPILE COMMITMENT
// ================================================================================================

/// A commitment to the evaluation of [`PrecompileRequest`], representing both the input and result
/// of the request.
///
/// This structure contains both the tag (which includes metadata like event ID)
/// and the commitment word that represents the verified computation result.
///
/// # Tag Structure
///
/// The tag is a 4-element word `[event_id, meta1, meta2, meta3]` where:
///
/// - **First element**: The [`EventId`] from the corresponding `EventHandler`
/// - **Remaining 3 elements**: Available for precompile-specific metadata (e.g., `len_bytes` for
///   hash functions to distinguish actual data from padding)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecompileCommitment {
    /// Tag containing metadata including the event ID in the first element. The remaining 3
    /// elements can be used for precompile-defined associated data.
    pub tag: Word,
    /// Commitment word representing the inputs and result of the request.
    pub commitment: Word,
}

impl PrecompileCommitment {
    /// Returns the concatenation of tag and commitment as field elements.
    pub fn to_elements(&self) -> [Felt; 8] {
        let words = [self.tag, self.commitment];
        Word::words_as_elements(&words).try_into().unwrap()
    }

    /// Returns the `EventId` used to identify the verifier that produced this commitment from a
    /// `PrecompileRequest`.
    pub fn event_id(&self) -> EventId {
        EventId::from_felt(self.tag[0])
    }
}

// PRECOMPILE VERIFIERS REGISTRY
// ================================================================================================

/// Registry of precompile verifiers.
///
/// This struct maintains a map of event IDs to their corresponding verifiers.
/// It is used to verify precompile requests during proof verification.
#[derive(Default, Clone)]
pub struct PrecompileVerifierRegistry {
    /// Map of event IDs to their corresponding verifiers
    verifiers: BTreeMap<EventId, Arc<dyn PrecompileVerifier>>,
}

impl PrecompileVerifierRegistry {
    /// Creates a new empty precompile verifiers registry.
    pub fn new() -> Self {
        Self { verifiers: BTreeMap::new() }
    }

    /// Registers a verifier for the specified event ID.
    pub fn register(&mut self, event_id: EventId, verifier: Arc<dyn PrecompileVerifier>) {
        self.verifiers.insert(event_id, verifier);
    }

    /// Gets a verifier for the specified event ID.
    pub fn get(&self, event_id: EventId) -> Option<&dyn PrecompileVerifier> {
        self.verifiers.get(&event_id).map(|v| v.as_ref())
    }

    /// Returns true if a verifier is registered for the specified event ID.
    pub fn contains(&self, event_id: EventId) -> bool {
        self.verifiers.contains_key(&event_id)
    }

    /// Returns the number of registered verifiers.
    pub fn len(&self) -> usize {
        self.verifiers.len()
    }

    /// Returns true if no verifiers are registered.
    pub fn is_empty(&self) -> bool {
        self.verifiers.is_empty()
    }

    /// Verifies all precompile requests and returns an aggregated commitment for deferred
    /// verification.
    ///
    /// This method iterates through all requests and verifies each one using the
    /// corresponding verifier from the registry. The commitments are then absorbed into a sponge,
    /// from which we can squeeze a digest.
    ///
    /// # Arguments
    /// * `requests` - Slice of precompile requests to verify
    ///
    /// # Errors
    /// Returns a [`PrecompileVerificationError`] if:
    /// - No verifier is registered for a request's event ID
    /// - A verifier fails to verify its request
    pub fn deferred_requests_commitment(
        &self,
        requests: &[PrecompileRequest],
    ) -> Result<Word, PrecompileVerificationError> {
        let mut state = PrecompileVerificationState::new();
        for (index, PrecompileRequest { event_id, calldata: data }) in requests.iter().enumerate() {
            let event_id = *event_id;
            let verifier = self
                .get(event_id)
                .ok_or(PrecompileVerificationError::VerifierNotFound { index, event_id })?;

            let precompile_commitment = verifier.verify(data).map_err(|error| {
                PrecompileVerificationError::PrecompileError { index, event_id, error }
            })?;
            state.absorb(precompile_commitment);
        }
        Ok(state.finalize())
    }
}

// PRECOMPILE VERIFIER TRAIT
// ================================================================================================

/// Trait for verifying precompile computations.
///
/// Each precompile type must implement this trait to enable verification of its
/// computations during proof verification. The verifier validates that the
/// computation was performed correctly and returns a precompile commitment.
///
/// # Stability
///
/// **⚠️ Alpha Status**: This trait and the broader precompile verification framework are under
/// active development. The interface and behavior may change in future releases as the framework
/// evolves. Production use should account for potential breaking changes.
pub trait PrecompileVerifier: Send + Sync {
    /// Verifies a precompile computation from the given call data.
    ///
    /// # Arguments
    /// * `calldata` - The byte data containing the inputs to evaluate the precompile.
    ///
    /// # Returns
    /// Returns a precompile commitment containing both tag and commitment word on success.
    ///
    /// # Errors
    /// Returns an error if the verification fails.
    fn verify(&self, calldata: &[u8]) -> Result<PrecompileCommitment, PrecompileError>;
}

// PRECOMPILE VERIFICATION STATE
// ================================================================================================

/// Tracks the RPO256 sponge capacity for aggregating [`PrecompileCommitment`]s.
///
/// This structure mirrors the VM's implementation of precompile commitment tracking. During
/// execution, the VM maintains only the capacity portion of an RPO256 sponge, absorbing each
/// precompile commitment as it's produced. At the end of execution, the verifier recomputes
/// this same aggregation and compares the final digest.
///
/// # Aggregation Process
///
/// - **`new()`**: Initialize capacity to `ZERO`
/// - **`absorb(comm)`**: Apply RPO256 permutation to `[capacity, tag, commitment]` and update
///   capacity to the first word of the result
/// - **`finalize()`**: Apply RPO256 permutation to `[capacity, ZERO, ZERO]` and extract the second
///   word as the final digest
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
struct PrecompileVerificationState {
    /// RPO256 sponge capacity, updated with each absorbed commitment.
    capacity: Word,
}

impl PrecompileVerificationState {
    /// Creates a new verification state with zero-initialized capacity.
    fn new() -> Self {
        Self::default()
    }

    /// Absorbs a precompile commitment by applying RPO256 to `[capacity, tag, commitment]`
    /// and saving the resulting capacity word.
    fn absorb(&mut self, commitment: PrecompileCommitment) {
        let mut state =
            Word::words_as_elements(&[self.capacity, commitment.tag, commitment.commitment])
                .try_into()
                .unwrap();
        Rpo256::apply_permutation(&mut state);
        self.capacity = Word::new(state[0..4].try_into().unwrap());
    }

    /// Finalizes by applying RPO256 to `[capacity, ZERO, ZERO]` and extracting elements the first
    /// rate word.
    ///
    /// This matches the VM's finalization where the rate portion is set to zeros for the final
    /// permutation. The zero-padded rate could be used for auxiliary metadata in future versions.
    fn finalize(self) -> Word {
        let mut state = Word::words_as_elements(&[self.capacity, Word::empty(), Word::empty()])
            .try_into()
            .unwrap();
        Rpo256::apply_permutation(&mut state);
        Word::new(state[4..8].try_into().unwrap())
    }
}

// PRECOMPILE ERROR
// ================================================================================================

/// Type alias for precompile errors.
///
/// This allows custom error types to be used by precompile verifiers while maintaining
/// a consistent interface. Similar to EventError, this provides flexibility for
/// different precompile implementations to define their own specific error types.
pub type PrecompileError = Box<dyn Error + Send + Sync + 'static>;

#[derive(Debug, thiserror::Error)]
pub enum PrecompileVerificationError {
    #[error("no verifier found for request at index {index} with event ID {event_id}")]
    VerifierNotFound { index: usize, event_id: EventId },

    #[error("verification error when verifying request at index {index}, with event ID {event_id}")]
    PrecompileError {
        index: usize,
        event_id: EventId,
        #[source]
        error: PrecompileError,
    },
}

// TESTS
// ================================================================================================

#[cfg(all(feature = "arbitrary", test))]
impl proptest::prelude::Arbitrary for PrecompileRequest {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;
        (any::<EventId>(), proptest::collection::vec(any::<u8>(), 0..=1000))
            .prop_map(|(event_id, calldata)| PrecompileRequest::new(event_id, calldata))
            .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}
