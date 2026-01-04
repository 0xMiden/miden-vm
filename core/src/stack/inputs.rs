use alloc::vec::Vec;
use core::{ops::Deref, slice};

use super::{
    super::ZERO, ByteWriter, Felt, InputError, MIN_STACK_DEPTH, Serializable, get_num_stack_values,
};
use crate::{
    field::QuotientMap,
    utils::{ByteReader, Deserializable, DeserializationError},
};

// STACK INPUTS
// ================================================================================================

/// Defines the initial state of the VM's operand stack.
///
/// The values in the struct are stored in the "stack order" - i.e., the last input is at the top
/// of the stack (in position 0).
#[derive(Clone, Debug, Default)]
pub struct StackInputs {
    elements: [Felt; MIN_STACK_DEPTH],
}

impl StackInputs {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns [StackInputs] from a list of values, reversing them into a stack.
    ///
    /// # Errors
    /// Returns an error if the number of input values exceeds the allowed maximum.
    pub fn new(mut values: Vec<Felt>) -> Result<Self, InputError> {
        if values.len() > MIN_STACK_DEPTH {
            return Err(InputError::InputStackTooBig(MIN_STACK_DEPTH, values.len()));
        }
        values.reverse();
        values.resize(MIN_STACK_DEPTH, ZERO);

        Ok(Self { elements: values.try_into().unwrap() })
    }

    /// Attempts to create stack inputs from an iterator of integers.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The values do not represent a valid field element.
    /// - Number of values in the iterator exceeds the allowed maximum number of input values.
    pub fn try_from_ints<I>(iter: I) -> Result<Self, InputError>
    where
        I: IntoIterator<Item = u64>,
    {
        let values = iter
            .into_iter()
            .map(|v| Felt::from_canonical_checked(v).ok_or(InputError::InvalidStackElement(v)))
            .collect::<Result<Vec<_>, _>>()?;

        Self::new(values)
    }
}

impl Deref for StackInputs {
    type Target = [Felt; MIN_STACK_DEPTH];

    fn deref(&self) -> &Self::Target {
        &self.elements
    }
}

impl From<[Felt; MIN_STACK_DEPTH]> for StackInputs {
    fn from(value: [Felt; MIN_STACK_DEPTH]) -> Self {
        Self { elements: value }
    }
}

impl<'a> IntoIterator for &'a StackInputs {
    type Item = &'a Felt;
    type IntoIter = slice::Iter<'a, Felt>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.iter()
    }
}

impl IntoIterator for StackInputs {
    type Item = Felt;
    type IntoIter = core::array::IntoIter<Felt, 16>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for StackInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let num_stack_values = get_num_stack_values(self);
        target.write_u8(num_stack_values);
        target.write_many(&self.elements[..num_stack_values as usize]);
    }
}

impl Deserializable for StackInputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_elements = source.read_u8()?;

        let mut elements = source.read_many::<Felt>(num_elements.into())?;
        elements.reverse();

        StackInputs::new(elements).map_err(|err| {
            DeserializationError::InvalidValue(format!("failed to create stack inputs: {err}",))
        })
    }
}
