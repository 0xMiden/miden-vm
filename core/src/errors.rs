use alloc::string::String;

// INPUT ERROR
// ================================================================================================

#[derive(Clone, Debug, thiserror::Error)]
pub enum InputError {
    #[error("value {0} exceeds field modulus")]
    InvalidStackElement(u64),
    #[error("number of input values on the stack cannot exceed {0}, but was {1}")]
    InputStackTooBig(usize, usize),
}

// HASH FUNCTION ERROR
// ================================================================================================

/// Error type for invalid hash function strings.
#[derive(Debug, thiserror::Error)]
#[error(
    "invalid hash function '{hash_function}'. Valid options are: blake3-256, rpo, rpx, poseidon2, keccak"
)]
pub struct InvalidHashFunctionError {
    pub hash_function: String,
}

// OUTPUT ERROR
// ================================================================================================

#[derive(Clone, Debug, thiserror::Error)]
pub enum OutputError {
    #[error("value {0} exceeds field modulus")]
    InvalidStackElement(u64),
    #[error("number of output values on the stack cannot exceed {0}, but was {1}")]
    OutputStackTooBig(usize, usize),
}

// KERNEL ERROR
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KernelError {
    #[error("kernel cannot have duplicated procedures")]
    DuplicatedProcedures,
    #[error("kernel can have at most {0} procedures, received {1}")]
    TooManyProcedures(usize, usize),
}
