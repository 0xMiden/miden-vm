use miden_core::operations::Operation;

use super::{Instrument, InstrumentRegistration};
use crate::profiling::{OutputResult, OutputWriter, helpers::op_histogram::OpHistogram};

/// An [`Instrument`] to create global operation histograms.
///
/// The global histogram aggregates across all procedures over the entire runtime.
///
/// At each cycle, it records the current operation and produces a histogram of executed operations
/// weighted by cycles per operation. If `opX` takes 4 cycles and was executed twice, its count
/// will be 8.
#[derive(Default)]
pub struct OpHistogramGlobal {
    hist: OpHistogram,
}

impl InstrumentRegistration for OpHistogramGlobal {
    const NAME: &'static str = "op-histogram-global";

    fn build(_config: &crate::profiling::ProfilerConfig) -> Result<Self, super::InstrumentError> {
        Ok(Self::default())
    }
}

#[cfg(feature = "std")]
crate::register_instrument!(OpHistogramGlobal);

impl Instrument for OpHistogramGlobal {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn on_operation_execution_cycle(&mut self, op: Operation, _proc: Option<&str>) {
        // The global histogram aggregates over all procedures, ignoring `proc`.
        self.hist.record(op);
    }

    fn write_report_to(&self, writer: &mut dyn OutputWriter) -> OutputResult<()> {
        writer.write_all(self.hist.report().as_bytes())
    }
}

#[cfg(test)]
mod tests;
