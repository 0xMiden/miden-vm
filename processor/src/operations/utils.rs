use super::{ExecutionError, Felt};
use crate::{ONE, ZERO};

/// Asserts that the given value is a binary value (0 or 1).
#[inline(always)]
pub fn assert_binary(value: Felt) -> Result<Felt, ExecutionError> {
    if value != ZERO && value != ONE {
        Err(ExecutionError::not_binary_value_op(value))
    } else {
        Ok(value)
    }
}
