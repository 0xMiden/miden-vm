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
    ///
    /// This should be the same name as the corresponding `InstrumentRegistration::NAME` constant
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

/// Represents the information needed to construct an [Instrument] dynamically
pub trait InstrumentRegistration: Sized + Instrument + 'static {
    /// The human readable name of this instrument used in CLI arguments and user output
    const NAME: &'static str;

    /// Create an instance of this instrument with the provided configuration
    fn build(config: &super::ProfilerConfig) -> Result<Self, InstrumentError>;
}

#[derive(Debug, thiserror::Error)]
pub enum InstrumentError {
    /// The given instrument name is not registered to any known instrument
    #[error("unknown profiling instrument '{0}'")]
    Undefined(String),
    /// We failed to construct the named instrument
    #[error("failed to construct instrument '{name}': {reason}")]
    Build { name: String, reason: String },
}

/// Get an instance of instrument `name`, if one has been registered by that name.
///
/// Returns `Err` if no such instrument is registered, or the instrument constructor returned an
/// error
#[cfg(feature = "std")]
pub fn instrument_from_name(
    name: &str,
    config: &super::ProfilerConfig,
) -> Result<Box<dyn Instrument>, InstrumentError> {
    use alloc::string::ToString;

    for instrument in inventory::iter::<InstrumentRegistrationInfo>() {
        if instrument.name == name {
            return (instrument.builder)(config);
        }
    }
    Err(InstrumentError::Undefined(name.to_string()))
}

#[cfg(feature = "std")]
#[doc(hidden)]
pub struct InstrumentRegistrationInfo {
    name: &'static str,
    builder: fn(&super::ProfilerConfig) -> Result<Box<dyn Instrument>, InstrumentError>,
}

#[cfg(feature = "std")]
impl InstrumentRegistrationInfo {
    pub const fn new<T: InstrumentRegistration>() -> Self {
        let name = <T as InstrumentRegistration>::NAME;
        Self {
            name,
            builder: build_instrument::<T>,
        }
    }
}

#[cfg(feature = "std")]
#[macro_export]
macro_rules! register_instrument {
    ($t:ty) => {
        inventory::submit!($crate::profiling::instrument::InstrumentRegistrationInfo::new::<$t>());
    };
}

#[cfg(feature = "std")]
inventory::collect!(InstrumentRegistrationInfo);

#[cfg(feature = "std")]
#[inline]
fn build_instrument<T: InstrumentRegistration>(
    config: &super::ProfilerConfig,
) -> Result<Box<dyn Instrument>, InstrumentError> {
    <T as InstrumentRegistration>::build(config).map(|inst| Box::new(inst) as Box<dyn Instrument>)
}
