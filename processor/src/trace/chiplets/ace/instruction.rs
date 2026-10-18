//! Processor compatibility imports for the shared ACE instruction format.

pub use miden_ace::instruction::MAX_ID;
#[cfg(test)]
pub use miden_ace::instruction::{ID_BITS, Op, decode_instruction};
