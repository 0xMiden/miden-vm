use miden_crypto::field::PrimeField64;

use super::{
    Felt,
    errors::{InputError, OutputError},
};
use crate::utils::{ByteWriter, Serializable};

mod inputs;
pub use inputs::StackInputs;

mod outputs;
pub use outputs::StackOutputs;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Represents:
/// - Number of elements that can be initialized at the start of execution and remain populated at
///   the end of execution.
/// - Number of elements that can be accessed directly via instructions.
/// - Number of elements that remain visible to the callee when the context is switched via `call`
///   or `syscall` instructions.
/// - Number of elements below which the depth of the stack never drops.
pub const MIN_STACK_DEPTH: usize = 16;

// HELPER FUNCTIONS
// ================================================================================================

/// Get the number of non-zero stack elements.
fn get_num_stack_values(values: &[Felt; MIN_STACK_DEPTH]) -> u8 {
    let mut num_trailing_zeros = 0;
    for v in values.iter().rev() {
        if v.as_canonical_u64() == 0 {
            num_trailing_zeros += 1;
        } else {
            break;
        }
    }
    (MIN_STACK_DEPTH - num_trailing_zeros) as u8
}
