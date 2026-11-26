use miden_core::deferred::{IntegrityError, PrecompileError, PreparationError};
use miden_precompiles_stark::prover::{PrecompileProvingError, SessionInputError};
use miden_processor::TraceGenerationError;
use miden_prover::ProverError;
use prost::Message;
use tonic::{Code, Status};

use crate::protocol::{ErrorCode, ErrorDetail};

pub(crate) fn status(error: ErrorCode) -> Status {
    let (code, message) = match error {
        ErrorCode::UnsupportedVersion => (Code::InvalidArgument, "unsupported protocol version"),
        ErrorCode::InvalidWitness => (Code::InvalidArgument, "invalid execution witness"),
        ErrorCode::RequestTooLarge => (Code::ResourceExhausted, "request exceeds byte limit"),
        ErrorCode::QueueFull => (Code::ResourceExhausted, "proving capacity exhausted"),
        ErrorCode::ProverLimitExceeded => {
            (Code::ResourceExhausted, "prover resource limit exceeded")
        },
        ErrorCode::DeadlineExceeded => {
            (Code::DeadlineExceeded, "proving request deadline exceeded")
        },
        ErrorCode::Cancelled => (Code::Cancelled, "proving request cancelled"),
        ErrorCode::ShuttingDown => (Code::Unavailable, "proving service is shutting down"),
        ErrorCode::ProvingFailed => (Code::Internal, "proof generation failed"),
        ErrorCode::ResponseTooLarge => {
            (Code::ResourceExhausted, "execution proof exceeds byte limit")
        },
        ErrorCode::Internal | ErrorCode::Unspecified => (Code::Internal, "proving worker failed"),
    };
    Status::with_details(code, message, ErrorDetail { code: error as i32 }.encode_to_vec().into())
}

pub(crate) fn prover_error(error: ProverError) -> Status {
    let code = match error {
        ProverError::TraceGeneration(
            TraceGenerationError::ProverMemoryExceeded { .. }
            | TraceGenerationError::TraceLenExceeded(_),
        ) => ErrorCode::ProverLimitExceeded,
        ProverError::TraceGeneration(_) => ErrorCode::InvalidWitness,
        ProverError::VmProofGeneration(_) => ErrorCode::ProvingFailed,
        ProverError::PrecompileProofGeneration(error) => match error {
            PrecompileProvingError::BatchTooLarge { .. }
            | PrecompileProvingError::MemoryEstimateOverflow
            | PrecompileProvingError::MemoryBudgetExceeded { .. } => ErrorCode::ProverLimitExceeded,
            PrecompileProvingError::Input(SessionInputError::Preparation { source, .. }) => {
                match source {
                    PreparationError::Integrity(IntegrityError::DeferredStateTooLarge {
                        ..
                    }) => ErrorCode::ProverLimitExceeded,
                    PreparationError::Precompile(error)
                        if matches!(error.root(), PrecompileError::Limit(_)) =>
                    {
                        ErrorCode::ProverLimitExceeded
                    },
                    _ => ErrorCode::InvalidWitness,
                }
            },
            PrecompileProvingError::Input(_) => ErrorCode::InvalidWitness,
            PrecompileProvingError::Prove(_) => ErrorCode::ProvingFailed,
        },
        _ => ErrorCode::Internal,
    };
    status(code)
}

#[cfg(test)]
mod tests {
    use miden_precompiles_stark::prover::ProveError;
    use miden_processor::ProcessorError;

    use super::*;

    #[test]
    fn proving_phases_preserve_service_failure_classification() {
        for (error, expected, grpc) in [
            (
                ProverError::TraceGeneration(TraceGenerationError::TraceLenExceeded(1024)),
                ErrorCode::ProverLimitExceeded,
                Code::ResourceExhausted,
            ),
            (
                ProverError::TraceGeneration(TraceGenerationError::ProverMemoryExceeded {
                    estimated_bytes: 2,
                    budget_bytes: 1,
                }),
                ErrorCode::ProverLimitExceeded,
                Code::ResourceExhausted,
            ),
            (
                ProverError::TraceGeneration(TraceGenerationError::InvalidReplay("missing row")),
                ErrorCode::InvalidWitness,
                Code::InvalidArgument,
            ),
            (
                ProverError::TraceGeneration(TraceGenerationError::Replay(
                    ProcessorError::CycleLimitExceeded(64),
                )),
                ErrorCode::InvalidWitness,
                Code::InvalidArgument,
            ),
            (
                ProverError::PrecompileProofGeneration(ProveError::MissingPreprocessed.into()),
                ErrorCode::ProvingFailed,
                Code::Internal,
            ),
        ] {
            let status = prover_error(error);
            assert_eq!(status.code(), grpc);
            assert_eq!(ErrorDetail::decode(status.details()).unwrap().code(), expected);
        }
    }
}
