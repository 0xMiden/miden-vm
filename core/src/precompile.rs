use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec::Vec};
use core::error::Error;

use miden_crypto::{Word, hash::rpo::Rpo256};

use crate::{
    EventId,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// PRECOMPILE DATA
// ================================================================================================

/// Represents a single precompile request consisting of an event ID and byte data.
///
/// This structure encapsulates the call data for a precompile operation, storing
/// the raw bytes that will be processed by the precompile function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecompileData {
    /// Event ID identifying the type of precompile operation
    pub event_id: EventId,
    /// Raw byte data for the precompile operation
    pub data: Vec<u8>,
}

impl PrecompileData {
    /// Creates a new precompile data entry.
    pub fn new(event_id: EventId, data: Vec<u8>) -> Self {
        Self { event_id, data }
    }
}

impl Serializable for PrecompileData {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u64(self.event_id.as_felt().as_int());
        target.write_usize(self.data.len());
        target.write_bytes(&self.data);
    }
}

impl Deserializable for PrecompileData {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let event_id = EventId::from_u64(source.read_u64()?);
        let len = source.read_usize()?;
        let data = source.read_vec(len)?;
        Ok(Self { event_id, data })
    }
}

// PRECOMPILE REQUESTS
// ================================================================================================

/// Container for precompile requests made during VM execution.
///
/// This struct maintains a list of all precompile requests made during execution.
/// Each request consists of an event ID and the call data required to recompute the result.
/// The requests can later be verified using a separate [`PrecompileVerifiers`] registry.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PrecompileRequests {
    /// List of precompile requests made during execution
    requests: Vec<PrecompileData>,
}

impl PrecompileRequests {
    /// Creates a new empty precompile requests container.
    pub const fn new() -> Self {
        Self { requests: Vec::new() }
    }

    /// Adds a new precompile request.
    pub fn push(&mut self, data: PrecompileData) {
        self.requests.push(data);
    }

    /// Returns the number of precompile requests.
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    /// Returns true if there are no precompile requests.
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Converts into the underlying vector of requests.
    pub fn into_requests(self) -> Vec<PrecompileData> {
        self.requests
    }

    /// Extends the precompile requests with the given iterator.
    pub fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = PrecompileData>,
    {
        self.requests.extend(iter);
    }

    /// Verifies all precompile requests and returns their individual commitment words.
    ///
    /// This method iterates through all requests and verifies each one using the
    /// corresponding verifier from the registry. For each request, it produces a commitment
    /// word followed by an empty word for metadata. The resulting vector has capacity for
    /// additional words that can be added before final hashing, which will be added by
    /// [`accumulate_commitments`] when computing the final commitment.
    ///
    /// # Arguments
    /// * `verifiers` - Registry of verifiers to use for validation
    ///
    /// # Errors
    /// Returns a `PrecompileError` if:
    /// - No verifier is registered for a request's event ID
    /// - A verifier fails to verify its request
    pub fn commitments(
        &self,
        verifiers: &PrecompileVerifiers,
    ) -> Result<Vec<Word>, VerificationError> {
        let mut commitments = Vec::with_capacity(2 * (self.len() + 1));
        for (index, PrecompileData { event_id, data }) in self.requests.iter().enumerate() {
            let verifier = verifiers
                .get(*event_id)
                .ok_or(VerificationError::VerifierNotFound { index, event_id: *event_id })?;

            // The empty word in the second slot can be used for metadata, including the precompile
            // event ID, and auxiliary information.
            let commitment = verifier.verify(&data).map_err(|error| {
                VerificationError::PrecompileError { index, event_id: *event_id, error }
            })?;
            commitments.extend([commitment, Word::empty()])
        }
        Ok(commitments)
    }

    /// Accumulates precompile commitments into a final hash.
    ///
    /// Takes a vector of commitment words, adds two empty words for finalization,
    /// and computes the final hash of all elements.
    ///
    /// # Arguments
    /// * `commitments` - Vector of commitment words from precompile requests
    ///
    /// # Returns
    /// The final accumulated commitment hash
    pub fn accumulate_commitments(commitments: Vec<Word>) -> Word {
        let mut final_commitments = commitments;
        // We add 2 empty words to account for the finalization of the hash inside the VM.
        // The VM keeps track of the sponge's capacity only, so once all precompile request
        // commitments have been absorbed, the finalization requires one last permutation where
        // we set the rate portion of the state to the zeros.
        // This slot could be used to encode auxiliary metadata for the entire list of precompile
        // requests.
        final_commitments.extend([Word::empty(), Word::empty()]);

        let commitment_data = Word::words_as_elements(&final_commitments);
        Rpo256::hash_elements(commitment_data)
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
}

// PRECOMPILE VERIFIER TRAIT
// ================================================================================================

/// Trait for verifying precompile computations.
///
/// Each precompile type must implement this trait to enable verification of its
/// computations during proof verification. The verifier validates that the
/// computation was performed correctly and returns a commitment to the computation.
pub trait PrecompileVerifier: Send + Sync {
    /// Verifies a precompile computation from the given call data.
    ///
    /// # Arguments
    /// * `data` - The byte data used for the precompile computation
    ///
    /// # Returns
    /// Returns a commitment word for this specific precompile instance on success.
    ///
    /// # Errors
    /// Returns an error if the verification fails.
    fn verify(&self, data: &[u8]) -> Result<Word, PrecompileError>;
}

/// Default implementation for both free functions and closures with signature
/// `fn(&[u8]) -> Result<Word, PrecompileError>`
impl<F> PrecompileVerifier for F
where
    F: Fn(&[u8]) -> Result<Word, PrecompileError> + Send + Sync + 'static,
{
    fn verify(&self, data: &[u8]) -> Result<Word, PrecompileError> {
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
pub enum VerificationError {
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

// SERIALIZATION
// ================================================================================================

impl Serializable for PrecompileRequests {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.requests.len());
        for request in &self.requests {
            request.write_into(target);
        }
    }
}

impl Deserializable for PrecompileRequests {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let count = source.read_usize()?;
        let mut requests = Vec::with_capacity(count);
        for _ in 0..count {
            let request = PrecompileData::read_from(source)?;
            requests.push(request);
        }
        Ok(Self { requests })
    }
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
        let original = PrecompileData::new(event_id, data);

        let mut bytes = Vec::new();
        original.write_into(&mut bytes);

        let mut reader = SliceReader::new(&bytes);
        let deserialized = PrecompileData::read_from(&mut reader).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_precompile_requests_serialization() {
        let mut requests = PrecompileRequests::new();
        requests.push(PrecompileData::new(EventId::from_u64(1), vec![1, 2]));
        requests.push(PrecompileData::new(EventId::from_u64(2), vec![3, 4, 5]));

        let mut bytes = Vec::new();
        requests.write_into(&mut bytes);

        let mut reader = SliceReader::new(&bytes);
        let deserialized = PrecompileRequests::read_from(&mut reader).unwrap();

        assert_eq!(requests, deserialized);
    }

    #[test]
    fn test_verify_empty_requests() {
        let verifiers = PrecompileVerifiers::new();
        let requests = PrecompileRequests::new();

        let commitments = requests.commitments(&verifiers).unwrap();
        assert!(commitments.is_empty());
        assert_eq!(commitments.capacity(), 2);
        let result = PrecompileRequests::accumulate_commitments(commitments);

        // The commitment is always finalized by absorbing [Word::ZERO, Word::ZERO] to mirror
        // the VM implementation. Since no precompiles were accumulated, we just finalize the
        // hash with no prior absorbs.
        let final_chunk = [Word::empty(), Word::empty()];
        let commitment_elements = Word::words_as_elements(&final_chunk);

        let result_expected = Rpo256::hash_elements(commitment_elements);
        assert_eq!(result, result_expected);
    }
}
