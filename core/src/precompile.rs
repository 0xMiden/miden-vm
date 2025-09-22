use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec::Vec};
use core::error::Error;

use miden_crypto::{Felt, Word, hash::rpo::Rpo256};
use winter_math::FieldElement;

use crate::{
    EventId,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// PRECOMPILE REQUEST
// ================================================================================================

/// Represents a single precompile request consisting of an event ID and byte data.
///
/// This structure encapsulates the call data for a precompile operation, storing
/// the raw bytes that will be processed by the precompile function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecompileRequest {
    /// Event ID identifying the type of precompile operation
    pub event_id: EventId,
    /// Raw byte data for the precompile operation
    pub data: Vec<u8>,
}

impl Serializable for PrecompileRequest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u64(self.event_id.as_felt().as_int());
        target.write_usize(self.data.len());
        target.write_bytes(&self.data);
    }
}

impl Deserializable for PrecompileRequest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let event_id = EventId::from_u64(source.read_u64()?);
        let len = source.read_usize()?;
        let data = source.read_vec(len)?;
        Ok(Self { event_id, data })
    }
}

// PRECOMPILE COMMITMENT
// ================================================================================================

/// Represents the result of a verified precompile computation.
///
/// This structure contains both the tag (which includes metadata like event ID)
/// and the commitment word that represents the verified computation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecompileCommitment {
    /// Tag containing metadata including the event ID in the first element
    pub tag: Word,
    /// Commitment word representing the verified computation result
    pub commitment: Word,
}

impl PrecompileCommitment {
    /// Returns the concatenation of tag and commitment as field elements.
    pub fn to_elements(&self) -> [Felt; 8] {
        let words = [self.tag, self.commitment];
        Word::words_as_elements(&words).try_into().unwrap()
    }
}

// PRECOMPILE VERIFIERS REGISTRY
// ================================================================================================

/// Registry of precompile verifiers.
///
/// This struct maintains a map of event IDs to their corresponding verifiers.
/// It is used to verify precompile requests during proof verification.
#[derive(Default, Clone)]
pub struct PrecompileVerifiers {
    /// Map of event IDs to their corresponding verifiers
    verifiers: BTreeMap<EventId, Arc<dyn PrecompileVerifier>>,
}

impl PrecompileVerifiers {
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

    /// Verifies all precompile requests and returns their individual commitment words.
    ///
    /// This method iterates through all requests and verifies each one using the
    /// corresponding verifier from the registry. For each request, it produces a tag
    /// word followed by a commitment word, represented as a [`PrecompileCommitment`]
    ///
    /// # Arguments
    /// * `requests` - Slice of precompile requests to verify
    ///
    /// # Errors
    /// Returns a `PrecompileVerificationError` if:
    /// - No verifier is registered for a request's event ID
    /// - A verifier fails to verify its request
    pub fn commitments(
        &self,
        requests: &[PrecompileRequest],
    ) -> Result<Vec<PrecompileCommitment>, PrecompileVerificationError> {
        let mut commitments = Vec::with_capacity(requests.len());
        for (index, PrecompileRequest { event_id, data }) in requests.iter().enumerate() {
            let event_id = *event_id;
            let verifier = self
                .get(event_id)
                .ok_or(PrecompileVerificationError::VerifierNotFound { index, event_id })?;

            let precompile_commitment = verifier.verify(data).map_err(|error| {
                PrecompileVerificationError::PrecompileError { index, event_id, error }
            })?;
            commitments.push(precompile_commitment)
        }
        Ok(commitments)
    }

    /// Accumulates precompile commitments into a final hash.
    ///
    /// # Arguments
    /// * `commitments` - Vector of commitment words from precompile requests
    ///
    /// # Returns
    /// The final accumulated commitment hash
    pub fn accumulate_commitments(commitments: &[PrecompileCommitment]) -> Word {
        let mut final_commitments = Vec::with_capacity((commitments.len() + 1) * 8);
        for commitment in commitments {
            final_commitments.extend(commitment.to_elements());
        }
        // We add 2 empty words to account for the finalization of the hash inside the VM.
        // The VM keeps track of the sponge's capacity only, so once all precompile request
        // commitments have been absorbed, the finalization requires one last permutation where
        // we set the rate portion of the state to the zeros.
        // This slot could be used to encode auxiliary metadata for the entire list of precompile
        // requests.
        final_commitments.extend([Felt::ZERO; 8]);
        Rpo256::hash_elements(&final_commitments)
    }
}

// PRECOMPILE VERIFIER TRAIT
// ================================================================================================

/// Trait for verifying precompile computations.
///
/// Each precompile type must implement this trait to enable verification of its
/// computations during proof verification. The verifier validates that the
/// computation was performed correctly and returns a precompile commitment.
pub trait PrecompileVerifier: Send + Sync {
    /// Verifies a precompile computation from the given call data.
    ///
    /// # Arguments
    /// * `data` - The byte data used for the precompile computation
    ///
    /// # Returns
    /// Returns a precompile commitment containing both tag and commitment word on success.
    ///
    /// # Errors
    /// Returns an error if the verification fails.
    fn verify(&self, data: &[u8]) -> Result<PrecompileCommitment, PrecompileError>;
}

/// Default implementation for both free functions and closures with signature
/// `fn(&[u8]) -> Result<PrecompileCommitment, PrecompileError>`
///
/// # Example
/// ```ignore
/// let verifier = |data: &[u8]| -> Result<PrecompileCommitment, PrecompileError> {
///     // Custom verification logic
///     Ok(PrecompileCommitment { tag: [0; 4].into(), commitment: [0; 4].into() })
/// };
/// ```
impl<F> PrecompileVerifier for F
where
    F: Fn(&[u8]) -> Result<PrecompileCommitment, PrecompileError> + Send + Sync + 'static,
{
    fn verify(&self, data: &[u8]) -> Result<PrecompileCommitment, PrecompileError> {
        self(data)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::SliceReader;

    #[test]
    fn test_precompile_data_serialization() {
        let event_id = EventId::from_u64(123);
        let data = vec![5, 6, 7, 8, 9];
        let original = PrecompileRequest { event_id, data };

        let mut bytes = Vec::new();
        original.write_into(&mut bytes);

        let mut reader = SliceReader::new(&bytes);
        let deserialized = PrecompileRequest::read_from(&mut reader).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_verify_empty_requests() {
        let verifiers = PrecompileVerifiers::new();
        let requests = Vec::new();

        let commitments = verifiers.commitments(&requests).unwrap();
        assert!(commitments.is_empty());
        let result = PrecompileVerifiers::accumulate_commitments(&commitments);

        // The commitment is always finalized by absorbing [Word::ZERO, Word::ZERO] to mirror
        // the VM implementation. Since no precompiles were accumulated, we just finalize the
        // hash with no prior absorbs.
        let final_chunk = [Word::empty(), Word::empty()];
        let commitment_elements = Word::words_as_elements(&final_chunk);

        let result_expected = Rpo256::hash_elements(commitment_elements);
        assert_eq!(result, result_expected);
    }
}
