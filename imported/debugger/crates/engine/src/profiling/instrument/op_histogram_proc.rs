use alloc::{borrow::ToOwned, string::String, vec::Vec};

#[cfg(feature = "std")]
type Map<K, V> = std::collections::HashMap<K, V>;
#[cfg(not(feature = "std"))]
type Map<K, V> = alloc::collections::BTreeMap<K, V>;

use miden_core::operations::Operation;

use super::{Instrument, InstrumentRegistration};
use crate::profiling::{OutputResult, OutputWriter, helpers::op_histogram::OpHistogram};

/// Map key under which operations that cannot be attributed to a procedure are collected. The
/// angle brackets cannot occur in a MASM identifier, so this never collides with a procedure name
const UNKNOWN_PROCEDURE: &str = "<unknown>";

/// An [`Instrument`] to create per-procedure operation histograms.
///
/// At each cycle, it records the current operation into the histogram of the most recent live
/// procedure. Operations that cannot be attributed to a procedure are collected into a separate
/// histogram, reported under [`UNKNOWN_PROCEDURE`].
///
/// The report contains one section per procedure, sorted by the number of cycles spent
/// in that procedure (highest first).
#[derive(Default)]
pub struct OpHistogramProc {
    histograms: Map<String, OpHistogram>,
}

impl InstrumentRegistration for OpHistogramProc {
    const NAME: &'static str = "op-histogram-proc";

    fn build(_config: &crate::profiling::ProfilerConfig) -> Result<Self, super::InstrumentError> {
        Ok(Self::default())
    }
}

#[cfg(feature = "std")]
crate::register_instrument!(OpHistogramProc);

impl Instrument for OpHistogramProc {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn on_operation_execution_cycle(&mut self, op: Operation, proc: Option<&str>) {
        let key = proc.unwrap_or(UNKNOWN_PROCEDURE);
        // Look up by borrow first so the key is only cloned when a new procedure is seen.
        match self.histograms.get_mut(key) {
            Some(hist) => hist.record(op),
            None => {
                let mut hist = OpHistogram::default();
                hist.record(op);
                self.histograms.insert(key.to_owned(), hist);
            }
        }
    }

    fn write_report_to(&self, writer: &mut dyn OutputWriter) -> OutputResult<()> {
        let mut entries: Vec<(&str, &OpHistogram)> =
            self.histograms.iter().map(|(name, hist)| (name.as_str(), hist)).collect();
        // Print the histogram with the highest total cycle count first, break ties by procedure
        // name for a stable order.
        entries
            .sort_by(|a, b| b.1.total_cycles().cmp(&a.1.total_cycles()).then_with(|| a.0.cmp(b.0)));

        for (name, hist) in entries {
            writeln!(writer, "procedure: {name}")?;
            writer.write_all(hist.report().as_bytes())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
