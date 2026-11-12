//! Every distinct kind of profiling data collection is an [`Instrument`] implementation that
//! lives in a submodule.
//!
//! Each instrument is uniquely identified by its [`Instrument::name`].

use alloc::{boxed::Box, string::String};

use miden_core::operations::Operation;

use crate::CycleInfo;

mod op_histogram_global;
mod op_histogram_proc;

pub use op_histogram_global::OpHistogramGlobal;
pub use op_histogram_proc::OpHistogramProc;

/// The functionality required for an instrument to be plugged in to `Profiler`.
pub trait Instrument {
    /// The human readable name of this instrument used in CLI arguments and user output
    fn name(&self) -> &'static str;
    /// To be called each vm cycle an `Operation` is executed.
    ///
    /// `proc` is the name of the most recent live procedure, or `None` when the operation cannot
    /// be attributed to a procedure. For example, it is `None` while executing a program without
    /// assembly operation metadata.
    fn on_operation_execution_cycle(&mut self, op: Operation, proc: Option<&str>);
    /// To be called before each vm cycle with what the cycle is about to execute, resolved to
    /// source.
    ///
    /// Unlike [`Self::on_operation_execution_cycle`], this runs before the cycle executes and
    /// for control-flow cycles too, so a cycle that fails is reported like any other. Instruments
    /// that do not need the source view keep the default, which does nothing.
    fn on_cycle(&mut self, _cycle: &CycleInfo<'_>) {}
    /// Write this instrumentation's collected output as a report to `writer`
    fn write_report_to(&self, writer: &mut dyn OutputWriter) -> OutputResult<()>;
}

pub type OutputError = Box<dyn core::error::Error + 'static>;
pub type OutputResult<T> = Result<T, OutputError>;

pub trait OutputWriter {
    fn write_all(&mut self, buf: &[u8]) -> OutputResult<()>;
    fn write_fmt(&mut self, args: core::fmt::Arguments<'_>) -> OutputResult<()>;
}

#[cfg(feature = "std")]
impl<T: std::io::Write> OutputWriter for T {
    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> OutputResult<()> {
        std::io::Write::write_all(self, buf).map_err(|err| Box::new(err) as Box<_>)
    }

    #[inline]
    fn write_fmt(&mut self, args: core::fmt::Arguments<'_>) -> OutputResult<()> {
        std::io::Write::write_fmt(self, args).map_err(|err| Box::new(err) as Box<_>)
    }
}

#[cfg(not(feature = "std"))]
impl OutputWriter for alloc::vec::Vec<u8> {
    fn write_all(&mut self, buf: &[u8]) -> OutputResult<()> {
        self.extend_from_slice(buf);
        Ok(())
    }

    fn write_fmt(&mut self, args: core::fmt::Arguments<'_>) -> OutputResult<()> {
        use alloc::string::ToString;
        let formatted = args.to_string();
        self.extend_from_slice(formatted.as_bytes());
        Ok(())
    }
}

/// An instrument name that is not supported by the debugger.
#[derive(Debug, thiserror::Error)]
#[error("unknown profiling instrument '{0}'")]
pub struct InstrumentError(pub String);

/// Construct one of the debugger's built-in profiling instruments.
#[cfg(feature = "std")]
pub fn instrument_from_name(name: &str) -> Result<Box<dyn Instrument>, InstrumentError> {
    match name {
        OpHistogramGlobal::NAME => Ok(Box::new(OpHistogramGlobal::default())),
        OpHistogramProc::NAME => Ok(Box::new(OpHistogramProc::default())),
        _ => Err(InstrumentError(name.into())),
    }
}
