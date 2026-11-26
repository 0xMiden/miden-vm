use miden_utils_diagnostics::Diagnostic;

use crate::{MemoryError, ProcessorError, operation::OperationError};

/// A failure while materializing an execution witness into an execution trace.
#[non_exhaustive]
#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum TraceGenerationError {
    #[error("trace length exceeded the maximum of {0} rows")]
    TraceLenExceeded(usize),
    #[error(
        "estimated prover memory of {estimated_bytes} bytes exceeds the budget of {budget_bytes} bytes"
    )]
    ProverMemoryExceeded { estimated_bytes: u64, budget_bytes: u64 },
    #[error("invalid execution replay: {0}")]
    InvalidReplay(&'static str),
    #[error("processor replay failed: {0}")]
    Replay(#[source] ProcessorError),
}

impl From<ProcessorError> for TraceGenerationError {
    fn from(error: ProcessorError) -> Self {
        match error {
            // The shared execution engine checks node and continuation invariants. During replay
            // those structures come from the witness, so failures belong to trace validation.
            ProcessorError::Internal(reason) => Self::InvalidReplay(reason),
            error => Self::Replay(error),
        }
    }
}

impl From<OperationError> for TraceGenerationError {
    fn from(error: OperationError) -> Self {
        Self::Replay(error.into())
    }
}

impl From<MemoryError> for TraceGenerationError {
    fn from(error: MemoryError) -> Self {
        Self::Replay(error.into())
    }
}
