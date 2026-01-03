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
//!    - Records the commitment into a [`PrecompileTranscript`]
//!
//! 2. **Request Storage**: All precompile requests are collected and included in the execution
//!    proof.
//!
//! 3. **Proof Generation**: The prover generates a STARK proof of the VM execution. The final
//!    [`PrecompileTranscript`] state (sponge capacity) is a public input. The verifier enforces the
//!    initial (empty) and final state via variable‑length public inputs.
//!
//! 4. **Verification**: The verifier:
//!    - Recomputes each precompile commitment using the stored requests via [`PrecompileVerifier`]
//!    - Reconstructs the [`PrecompileTranscript`] by recording all commitments in order
//!    - Verifies the STARK proof with the final transcript state as public input.
//!    - Accepts the proof only if precompile verification succeeds and the STARK proof is valid
//!
//! # Key Types
//!
//! - [`PrecompileRequest`]: Stores the event ID and raw input bytes for a precompile call
//! - [`PrecompileCommitment`]: A cryptographic commitment to both inputs and outputs, consisting of
//!   a tag (with event ID and metadata) and a commitment to the request's calldata.
//! - [`PrecompileVerifier`]: Trait for implementing verification logic for specific precompiles
//! - [`PrecompileVerifierRegistry`]: Registry mapping event IDs to their verifier implementations
//! - [`PrecompileTranscript`]: A transcript (implemented via an RPO256 sponge) that creates a
//!   sequential commitment to all precompile requests.
//!
//! # Example Implementation
//!
//! See the Keccak256 precompile in `miden_core_lib::handlers::keccak256` for a complete reference
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
    EventId, EventName,
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
    miden_test_serde_macros::serde_test(binary_serde(true))
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

// PRECOMPILE TRANSCRIPT TYPES
// ================================================================================================

/// Type alias representing the precompile transcript state (sponge capacity word).
///
/// This is simply a [`Word`] used to track the evolving state of the precompile transcript sponge.
pub type PrecompileTranscriptState = Word;

/// Type alias representing the finalized transcript digest.
///
/// This is simply a [`Word`] representing the final digest of all precompile commitments.
pub type PrecompileTranscriptDigest = Word;

// PRECOMPILE COMMITMENT
// ================================================================================================

/// A commitment to the evaluation of [`PrecompileRequest`], representing both the input and result
/// of the request.
///
/// This structure contains both the tag (which includes metadata like event ID)
/// and the commitment to the input and result (calldata) of the precompile request.
///
/// # Tag Structure
///
/// The tag is a 4-element word `[event_id, meta1, meta2, meta3]` where:
///
/// - **First element**: The [`EventId`] from the corresponding `EventHandler`
/// - **Remaining 3 elements**: Available for precompile-specific metadata (e.g., `len_bytes` for
///   hash functions to distinguish actual data from padding)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecompileCommitment {
    tag: Word,
    comm: Word,
}

impl PrecompileCommitment {
    /// Creates a new precompile commitment from a `TAG` and `COMM`.
    ///
    /// - `TAG`: 4-element word where the first element encodes the [`EventId`]; the remaining
    ///   elements are available as precompile-specific metadata (e.g., `len_bytes`).
    /// - `COMM`: 4-element word containing the commitment to the calldata (or handler-specific
    ///   witness) for this precompile request.
    pub fn new(tag: Word, comm: Word) -> Self {
        Self { tag, comm }
    }

    /// Returns the `TAG` word which encodes the [`EventId`] in the first element and optional
    /// precompile-specific metadata in the remaining three elements.
    pub fn tag(&self) -> Word {
        self.tag
    }

    /// Returns the `COMM` word (calldata commitment), i.e., the commitment to the precompile's
    /// calldata (or other handler-specific witness).
    pub fn comm_calldata(&self) -> Word {
        self.comm
    }

    /// Returns the concatenation of `TAG` and `COMM` as field elements.
    pub fn to_elements(&self) -> [Felt; 8] {
        let words = [self.tag, self.comm];
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
/// This struct maintains a map of event IDs to their corresponding event names and verifiers.
/// It is used to verify precompile requests during proof verification.
#[derive(Default, Clone)]
pub struct PrecompileVerifierRegistry {
    /// Map of event IDs to their corresponding event names and verifiers
    verifiers: BTreeMap<EventId, (EventName, Arc<dyn PrecompileVerifier>)>,
}

impl PrecompileVerifierRegistry {
    /// Creates a new empty precompile verifiers registry.
    pub fn new() -> Self {
        Self { verifiers: BTreeMap::new() }
    }

    /// Returns a new registry that includes the supplied verifier in addition to existing ones.
    pub fn with_verifier(
        mut self,
        event_name: &EventName,
        verifier: Arc<dyn PrecompileVerifier>,
    ) -> Self {
        let event_id = event_name.to_event_id();
        self.verifiers.insert(event_id, (event_name.clone(), verifier));
        self
    }

    /// Merges another registry into this one, overwriting any conflicting event IDs with the other
    /// registry's verifiers.
    pub fn merge(&mut self, other: &Self) {
        for (event_id, (event_name, verifier)) in other.verifiers.iter() {
            self.verifiers.insert(*event_id, (event_name.clone(), verifier.clone()));
        }
    }

    /// Verifies all precompile requests and returns the resulting precompile transcript state after
    /// recording all commitments.
    ///
    /// # Errors
    /// Returns a [`PrecompileVerificationError`] if:
    /// - No verifier is registered for a request's event ID
    /// - A verifier fails to verify its request
    pub fn requests_transcript(
        &self,
        requests: &[PrecompileRequest],
    ) -> Result<PrecompileTranscript, PrecompileVerificationError> {
        let mut transcript = PrecompileTranscript::new();
        for (index, PrecompileRequest { event_id, calldata }) in requests.iter().enumerate() {
            let (event_name, verifier) = self.verifiers.get(event_id).ok_or(
                PrecompileVerificationError::VerifierNotFound { index, event_id: *event_id },
            )?;

            let precompile_commitment = verifier.verify(calldata).map_err(|error| {
                PrecompileVerificationError::PrecompileError {
                    index,
                    event_name: event_name.clone(),
                    error,
                }
            })?;
            transcript.record(precompile_commitment);
        }
        Ok(transcript)
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

// PRECOMPILE TRANSCRIPT
// ================================================================================================

/// Precompile transcript implemented with an RPO256 sponge.
///
/// # Structure
/// Standard RPO256 sponge: 12 elements = capacity (4 elements) + rate (8 elements)
///
/// # Operation
/// - **Record**: Each precompile commitment is recorded by absorbing it into the rate, updating the
///   capacity
/// - **State**: The evolving capacity tracks all absorbed commitments in order
/// - **Finalization**: Squeeze with zero rate to extract a transcript digest (the sequential
///   commitment)
///
/// # Implementation Note
/// We store only the 4-element capacity portion between absorptions since since the rate is always
/// overwritten when absorbing blocks that are a multiple of the rate width.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct PrecompileTranscript {
    /// The transcript state (capacity portion of the sponge).
    state: Word,
}

impl PrecompileTranscript {
    /// Creates a new sponge with zero capacity.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a transcript from an existing state (for VM operations like `log_precompile`).
    pub fn from_state(state: PrecompileTranscriptState) -> Self {
        Self { state }
    }

    /// Returns the current transcript state (capacity word).
    pub fn state(&self) -> PrecompileTranscriptState {
        self.state
    }

    /// Records a precompile commitment into the transcript, updating the state.
    pub fn record(&mut self, commitment: PrecompileCommitment) {
        let mut state =
            Word::words_as_elements(&[self.state, commitment.tag(), commitment.comm_calldata()])
                .try_into()
                .unwrap();
        Rpo256::apply_permutation(&mut state);
        self.state = Word::new(state[0..4].try_into().unwrap());
    }

    /// Finalizes the transcript to a digest (sequential commitment to all recorded requests).
    ///
    /// # Details
    /// The output is equivalent to the sequential hash of all [`PrecompileCommitment`]s, followed
    /// by two empty words. This is because
    /// - Each commitment is represented as two words, a multiple of the rate.
    /// - The initial capacity is set to the zero word since we absord full double words when
    ///   calling `record` or `finalize`.
    pub fn finalize(self) -> PrecompileTranscriptDigest {
        let mut state = Word::words_as_elements(&[self.state, Word::empty(), Word::empty()])
            .try_into()
            .unwrap();
        Rpo256::apply_permutation(&mut state);
        PrecompileTranscriptDigest::new(state[4..8].try_into().unwrap())
    }
}

// PRECOMPILE ERROR
// ================================================================================================

/// Type alias for precompile errors.
///
/// Verifiers should return informative, structured errors (e.g., using `thiserror`) so callers
/// can surface meaningful diagnostics.
pub type PrecompileError = Box<dyn Error + Send + Sync + 'static>;

#[derive(Debug, thiserror::Error)]
pub enum PrecompileVerificationError {
    #[error("no verifier found for request #{index} for event with ID: {event_id}")]
    VerifierNotFound { index: usize, event_id: EventId },

    #[error("verification error for request #{index} for event '{event_name}'")]
    PrecompileError {
        index: usize,
        event_name: EventName,
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
