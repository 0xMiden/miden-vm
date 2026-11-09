mod advice;
mod collect_trace;
mod config;
mod cycle;
#[cfg(feature = "dap")]
mod dap;
#[cfg(feature = "dap")]
mod dap_client;
#[cfg(feature = "dap")]
mod dap_types;
mod diagnostic;
pub mod event;
mod executor;
mod host;
mod query;
mod recording_host;
mod snapshot;
pub(crate) mod source;
mod state;
mod stepper;
mod trace;

#[cfg(feature = "std")]
pub use self::snapshot::ReplaySnapshotError;
pub use self::{
    advice::{
        EventMutationRecorder, clone_advice_mutation, clone_advice_mutations, read_advice_mutation,
        read_event_log, write_advice_mutation, write_event_log,
    },
    collect_trace::{CallTraceReplay, replay_call_trace},
    config::ExecutionConfig,
    cycle::{CycleInfo, NodeStart},
    diagnostic::DiagnosticExecutor,
    event::Event,
    executor::Executor,
    host::DebuggerHost,
    query::DebugQuery,
    recording_host::RecordingHost,
    snapshot::{
        MastForestRecorder, ReplaySnapshot, ReplaySnapshotEncodeError, ReplaySnapshotRecorder,
        ReplaySnapshotWrite, ReplaySnapshotWriteError,
    },
    state::DebugExecutor,
    stepper::Stepper,
    trace::ExecutionTrace,
};
#[cfg(feature = "dap")]
pub use self::{
    dap::{DapConfig, DapExecutor},
    dap_client::{DapClient, DapStopReason},
    dap_types::{DapUiFrame, DapUiState, DapVariableValue},
};

/// Resolves a future that is expected to complete on its first poll, as the futures of a
/// synchronous host do; a future that yields is a bug in the caller.
#[cfg(any(test, feature = "dap"))]
pub(crate) fn poll_immediately<T>(future: impl Future<Output = T>) -> T {
    use core::task::{Context, Poll, Waker};

    let mut future = core::pin::pin!(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("future was expected to complete immediately"),
    }
}
