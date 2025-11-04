use super::{ExecutionError, Felt};
use crate::{ErrorContext, ONE, ZERO, errors::OperationError};

/// Asserts that the given value is a binary value (0 or 1).
#[inline(always)]
pub fn assert_binary(value: Felt, err_ctx: &impl ErrorContext) -> Result<Felt, ExecutionError> {
    if value != ZERO && value != ONE {
        Err(ExecutionError::from_operation(
            err_ctx,
            OperationError::not_binary_value_op(value),
        ))
    } else {
        Ok(value)
    }
}
