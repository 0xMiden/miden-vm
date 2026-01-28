use alloc::vec::Vec;
use core::ops::Deref;

use miden_crypto::{WORD_SIZE, Word, ZERO};

use super::{ByteWriter, Felt, MIN_STACK_DEPTH, OutputError, Serializable, get_num_stack_values};
use crate::utils::{ByteReader, Deserializable, DeserializationError};

// STACK OUTPUTS
// ================================================================================================

/// Defines the final state of the VM's operand stack at the end of program execution.
///
/// The first element is at position 0 (top of stack).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StackOutputs {
    elements: [Felt; MIN_STACK_DEPTH],
}

impl StackOutputs {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a new [StackOutputs] struct from the provided stack elements.
    ///
    /// # Errors
    ///  Returns an error if the number of stack elements is greater than `MIN_STACK_DEPTH` (16).
    pub fn new(values: &[Felt]) -> Result<Self, OutputError> {
        if values.len() > MIN_STACK_DEPTH {
            return Err(OutputError::OutputStackTooBig(MIN_STACK_DEPTH, values.len()));
        }

        let mut elements = [ZERO; MIN_STACK_DEPTH];
        elements[..values.len()].copy_from_slice(values);

        Ok(Self { elements })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the element located at the specified position on the stack or `None` if out of
    /// bounds.
    pub fn get_element(&self, idx: usize) -> Option<Felt> {
        self.elements.get(idx).cloned()
    }

    /// Returns the word located starting at the specified Felt position on the stack in
    /// little-endian order, or `None` if out of bounds.
    ///
    /// For example, passing in `0` returns the word at the top of the stack, and passing in `4`
    /// returns the word starting at element index `4`.
    ///
    /// Stack element N will be at position 0 of the word, N+1 at position 1, N+2 at position 2,
    /// and N+3 at position 3. `Word[0]` corresponds to the top of the stack.
    pub fn get_word(&self, idx: usize) -> Option<Word> {
        if idx > MIN_STACK_DEPTH - WORD_SIZE {
            return None;
        }

        Some(Word::from([
            self.elements[idx],
            self.elements[idx + 1],
            self.elements[idx + 2],
            self.elements[idx + 3],
        ]))
    }

    /// Returns the number of requested elements up to the maximum available in the stack outputs.
    pub fn get_num_elements(&self, num_outputs: usize) -> &[Felt] {
        let len = self.elements.len().min(num_outputs);
        &self.elements[..len]
    }

    // TESTING UTILITIES
    // --------------------------------------------------------------------------------------------

    /// Attempts to create [StackOutputs] struct from the provided stack elements represented as
    /// vector of `u64` values.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Any of the provided stack elements are invalid field elements.
    #[cfg(any(test, feature = "testing"))]
    pub fn try_from_ints<I>(iter: I) -> Result<Self, OutputError>
    where
        I: IntoIterator<Item = u64>,
    {
        use miden_crypto::field::QuotientMap;

        // Validate stack elements
        let values = iter
            .into_iter()
            .map(|v| Felt::from_canonical_checked(v).ok_or(OutputError::InvalidStackElement(v)))
            .collect::<Result<Vec<Felt>, _>>()?;

        Self::new(&values)
    }

    /// Converts the [`StackOutputs`] into the vector of `u64` values.
    #[cfg(any(test, feature = "testing"))]
    pub fn as_int_vec(&self) -> Vec<u64> {
        use miden_crypto::field::PrimeField64;

        self.elements.iter().map(|e| (*e).as_canonical_u64()).collect()
    }
}

impl Deref for StackOutputs {
    type Target = [Felt; MIN_STACK_DEPTH];

    fn deref(&self) -> &Self::Target {
        &self.elements
    }
}

impl From<[Felt; MIN_STACK_DEPTH]> for StackOutputs {
    fn from(value: [Felt; MIN_STACK_DEPTH]) -> Self {
        Self { elements: value }
    }
}

#[cfg(any(test, feature = "testing"))]
impl AsMut<[Felt]> for StackOutputs {
    /// Returns mutable access to the stack outputs, to be used for testing.
    fn as_mut(&mut self) -> &mut [Felt] {
        &mut self.elements
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for StackOutputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let num_stack_values = get_num_stack_values(self);
        target.write_u8(num_stack_values);
        target.write_many(&self.elements[..num_stack_values as usize]);
    }
}

impl Deserializable for StackOutputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_elements = source.read_u8()?;

        let elements: Vec<Felt> =
            source.read_many_iter::<Felt>(num_elements.into())?.collect::<Result<_, _>>()?;

        StackOutputs::new(&elements).map_err(|err| {
            DeserializationError::InvalidValue(format!("failed to create stack outputs: {err}",))
        })
    }
}
