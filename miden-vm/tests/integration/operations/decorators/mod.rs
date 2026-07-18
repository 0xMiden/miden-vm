// Re-export TestHost from miden_processor for use in integration tests
pub use miden_processor::{TestHost, TracingTestHost};

mod advice;
mod events;
mod trace_events;
