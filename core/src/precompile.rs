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
//!    [`PrecompileTranscript`] state (the rolling digest of all per-call statements) is a public
//!    input. The verifier enforces the initial (empty) and final state via variable‑length public
//!    inputs.
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
//!   a tag (with event ID and metadata) and the two halves `(COMM_0, COMM_1)` of the request's
//!   calldata commitment.
//! - [`PrecompileVerifier`]: Trait for implementing verification logic for specific precompiles
//! - [`PrecompileVerifierRegistry`]: Registry mapping event IDs to their verifier implementations
//! - [`PrecompileTranscript`]: A linear hash tree over Poseidon2 that produces a rolling digest of
//!   all recorded precompile statements; the state is itself a complete digest at every step.
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

use miden_crypto::{Felt, Word, ZERO, hash::poseidon2::Poseidon2};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    events::{EventId, EventName},
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
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

    fn min_serialized_size() -> usize {
        EventId::min_serialized_size() + Vec::<u8>::min_serialized_size()
    }
}

// PRECOMPILE TRANSCRIPT TYPES
// ================================================================================================

/// Type alias representing the precompile transcript state.
///
/// The transcript is a linear hash tree: the state is the rolling digest of all per-call
/// statements absorbed so far. After every `log_precompile` call the state is itself a complete
/// digest — no separate finalization step is required.
pub type PrecompileTranscriptState = Word;

// PRECOMPILE COMMITMENT
// ================================================================================================

/// A commitment to the evaluation of [`PrecompileRequest`], representing both the input and result
/// of the request.
///
/// The commitment is a triple `(TAG, COMM_0, COMM_1)`. The transcript condenses each commitment
/// into a single statement word
/// `STMNT = Permute(COMM_0, COMM_1, TAG).rate0` (TAG enters the sponge as initial capacity, acting
/// as a domain separator), and then folds that statement into the rolling state via the 2-to-1
/// hash `state' = Permute(state, STMNT, ZERO).rate0`.
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
    comm_0: Word,
    comm_1: Word,
}

impl PrecompileCommitment {
    /// Creates a new precompile commitment from a `TAG` and the two halves `COMM_0`, `COMM_1` of
    /// the calldata commitment.
    ///
    /// - `TAG`: 4-element word where the first element encodes the [`EventId`]; the remaining
    ///   elements are available as precompile-specific metadata (e.g., `len_bytes`).
    /// - `COMM_0`, `COMM_1`: two 4-element words that together commit to the calldata (or
    ///   handler-specific witness). The transcript hashes them together with the tag as the initial
    ///   sponge capacity.
    pub fn new(tag: Word, comm_0: Word, comm_1: Word) -> Self {
        Self { tag, comm_0, comm_1 }
    }

    /// Returns the `TAG` word which encodes the [`EventId`] in the first element and optional
    /// precompile-specific metadata in the remaining three elements.
    pub fn tag(&self) -> Word {
        self.tag
    }

    /// Returns the first half of the calldata commitment, hashed into the sponge rate0 input.
    pub fn comm_0(&self) -> Word {
        self.comm_0
    }

    /// Returns the second half of the calldata commitment, hashed into the sponge rate1 input.
    pub fn comm_1(&self) -> Word {
        self.comm_1
    }

    /// Returns the concatenation of `TAG`, `COMM_0`, and `COMM_1` as field elements.
    pub fn to_elements(&self) -> [Felt; 12] {
        let words = [self.tag, self.comm_0, self.comm_1];
        Word::words_as_elements(&words).try_into().unwrap()
    }

    /// Returns the per-call statement `STMNT = Permute(COMM_0, COMM_1, TAG).rate0` that the
    /// transcript folds into its rolling state.
    pub fn statement(&self) -> Word {
        let mut state = [ZERO; Poseidon2::STATE_WIDTH];
        state[Poseidon2::RATE0_RANGE].copy_from_slice(self.comm_0.as_elements());
        state[Poseidon2::RATE1_RANGE].copy_from_slice(self.comm_1.as_elements());
        state[Poseidon2::CAPACITY_RANGE].copy_from_slice(self.tag.as_elements());
        Poseidon2::apply_permutation(&mut state);
        Word::new(state[Poseidon2::DIGEST_RANGE].try_into().unwrap())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        events::EventId,
        serde::{BudgetedReader, ByteWriter, DeserializationError, SliceReader},
    };

    #[test]
    fn precompile_request_rejects_over_budget_calldata_len() {
        let mut bytes = Vec::new();
        EventId::from_u64(0).write_into(&mut bytes);
        bytes.write_usize(2);

        let budget = bytes.len() + 1;
        let mut reader = BudgetedReader::new(SliceReader::new(&bytes), budget);
        let err = PrecompileRequest::read_from(&mut reader).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("requested 2 elements"));
    }
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

/// Precompile transcript implemented as a linear hash tree over Poseidon2.
///
/// # Structure
/// The transcript holds a single 4-element [`Word`] — the rolling state. After each `record` call,
/// the state is itself a complete digest of every commitment absorbed so far.
///
/// # Operation
/// - For each commitment, the transcript first computes the per-call statement `STMNT =
///   Permute(COMM_0, COMM_1, TAG).rate0` (TAG enters the sponge as initial capacity, acting as a
///   domain separator).
/// - It then folds the statement into the rolling state via the 2-to-1 hash `state' =
///   Permute(state, STMNT, ZERO).rate0`.
/// - The state is exposed directly as the transcript digest — no finalization step is required.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct PrecompileTranscript {
    /// The rolling transcript digest.
    state: Word,
}

impl PrecompileTranscript {
    /// Creates a new transcript with the zero word as initial state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a transcript from an existing state (for VM operations like `log_precompile`).
    pub fn from_state(state: PrecompileTranscriptState) -> Self {
        Self { state }
    }

    /// Returns the current transcript state (also the rolling digest of all recorded commitments).
    pub fn state(&self) -> PrecompileTranscriptState {
        self.state
    }

    /// Records a precompile commitment into the transcript, updating the state.
    ///
    /// Computes `STMNT = Permute(COMM_0, COMM_1, TAG).rate0` and then folds it into the rolling
    /// state via `state' = Permute(state, STMNT, ZERO).rate0`.
    pub fn record(&mut self, commitment: PrecompileCommitment) {
        let stmnt = commitment.statement();

        // Fold the statement into the rolling state: state' = Permute(state, STMNT, ZERO).rate0.
        let mut state = [ZERO; Poseidon2::STATE_WIDTH];
        state[Poseidon2::RATE0_RANGE].copy_from_slice(self.state.as_elements());
        state[Poseidon2::RATE1_RANGE].copy_from_slice(stmnt.as_elements());
        // Capacity is left as ZERO.

        Poseidon2::apply_permutation(&mut state);
        self.state = Word::new(state[Poseidon2::DIGEST_RANGE].try_into().unwrap());
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
