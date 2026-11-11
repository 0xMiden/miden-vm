pub mod config;
pub(crate) mod helpers;
pub mod instrument;
mod profiler;

#[cfg(feature = "std")]
pub use self::{config::ProfilerCliArgs, instrument::instrument_from_name};
pub use self::{
    config::ProfilerConfig,
    instrument::{
        Instrument, InstrumentRegistration, OpHistogramGlobal, OpHistogramProc, OutputResult,
        OutputWriter,
    },
    profiler::Profiler,
};
