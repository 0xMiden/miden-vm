// INPUT ERROR
// ================================================================================================

#[derive(Clone, Debug, thiserror::Error)]
pub enum InputError {
    #[error("value {0} exceeds field modulus")]
    InvalidStackElement(u64),
    #[error("number of input values on the stack cannot exceed {0}, but was {1}")]
    InputStackTooBig(usize, usize),
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
