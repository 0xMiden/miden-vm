//! Precompile verifier trait and sealed pattern implementation.

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc};
use core::error::Error;

use miden_core::EventId;
// Import core types
pub use miden_core::precompile::{PrecompileCommitment, PrecompileRequest};
use miden_crypto::{Word, hash::rpo::Rpo256};

/// This trait is sealed and cannot be implemented for types outside this crate.
///
/// This pattern restricts implementations of PrecompileVerifier to specific types
/// within the stdlib crate, ensuring that only approved verifiers can be used.
///
/// The trait provides a common interface for verifying precompile computations
/// and generating cryptographic commitments.
pub trait PrecompileVerifier: private::Sealed {
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

// Move PrecompileVerificationError and related types to stdlib
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
        for (index, request) in requests.iter().enumerate() {
            let event_id = request.event_id();
            let verifier = self
                .get(event_id)
                .ok_or(PrecompileVerificationError::VerifierNotFound { index, event_id })?;

            let precompile_commitment = verifier.verify(request.calldata()).map_err(|error| {
                PrecompileVerificationError::PrecompileError { index, event_id, error }
            })?;
            state.absorb(precompile_commitment);
        }
        Ok(state.finalize())
    }
}

/// Tracks the RPO256 sponge capacity for aggregating [`PrecompileCommitment`]s.
///
/// This structure mirrors the VM's implementation of precompile commitment tracking. During
/// execution, the VM maintains only the capacity portion of an RPO256 sponge, absorbing each
/// precompile commitment as it's produced. At the end of execution, the verifier recomputes
/// this same aggregation and compares the final digest.
///
/// The exact shape of the commitment is described in TODO(adr1anh)
///
/// # Details:
/// This struct is a specialization of an RPO based sponge for aggregating precompile commitment.
/// - `new()`: Initialize a sponge with capacity set to `ZERO`.
/// - `absorb(comm)`: Permute the state `[self.capacity, comm.tag, comm.commitment]`, absorbing the
///   `PrecompileCommitment` into the sponge and saving the resulting capacity.
/// - `finalize()`: Permute the state `[self.capacity, ZERO, ZERO]` and extract the resulting
///   digest.
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

// MARKER TRAIT FOR SEALING
// ================================================================================================

// Private module to contain the sealed trait
mod private {
    /// This trait is sealed and cannot be implemented for types outside this crate.
    pub trait Sealed {}

    /// Implement Sealed for specific types that are allowed to implement PrecompileVerifier.
    ///
    /// Currently, only types defined within the stdlib crate are allowed to implement
    /// the PrecompileVerifier trait.
    impl Sealed for crate::handlers::keccak256::KeccakVerifier {}
}
