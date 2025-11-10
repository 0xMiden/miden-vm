use super::Felt;
use crate::{ONE, ZERO, errors::OperationError};

/// Asserts that the given value is a binary value (0 or 1).
#[inline(always)]
pub fn assert_binary(value: Felt) -> Result<Felt, OperationError> {
    if value != ZERO && value != ONE {
        Err(OperationError::NotBinaryValueOp(value))
    } else {
        Ok(value)
    }
}
