use alloc::{boxed::Box, vec::Vec};
use core::error::Error;

use miden_crypto::{Felt, Word};
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
/// the raw bytes that will be processed by the precompile function.
///
/// # Note:
/// The use of `EventID` here is temporary as we establish a way to identify specific verifiers.
/// If we were to allow arbitrary precompiles, we would likely need a 256-bit collision-resistant
/// identifier. If on the other hand we only allow a fixed set of verifiers, an enum descirminant
/// would be enough.
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
}

// PRECOMPILE ERROR
// ================================================================================================

/// Type alias for precompile errors.
///
/// This allows custom error types to be used by precompile verifiers while maintaining
/// a consistent interface. Similar to EventError, this provides flexibility for
/// different precompile implementations to define their own specific error types.
pub type PrecompileError = Box<dyn Error + Send + Sync + 'static>;

// PRECOMPILE VERIFIER REGISTRY (PLACEHOLDER)
// ================================================================================================

/// Placeholder for precompile verifier registry.
///
/// NOTE: The actual registry is defined in stdlib.
/// This is kept for backward compatibility during the transition.
#[derive(Default)]
pub struct PrecompileVerifierRegistry {
    /// Placeholder implementation
    _placeholder: (),
}

impl PrecompileVerifierRegistry {
    /// Creates a new empty precompile verifiers registry.
    pub fn new() -> Self {
        Self::default()
    }
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
