use alloc::{boxed::Box, vec::Vec};

use miden_core::operations::Operation;

use crate::{
    CycleInfo,
    profiling::{OutputResult, OutputWriter, ProfilerConfig, instrument::Instrument},
};

/// Holds the loaded [`Instrument`]s and dispatches event handlers to them.
///
/// The default is a no-op `Profiler`.
#[derive(Default)]
pub struct Profiler {
    instruments: Vec<Box<dyn Instrument>>,
    #[cfg(feature = "std")]
    reports_dir: Option<std::path::PathBuf>,
}

impl Profiler {
    pub fn from_config(config: ProfilerConfig) -> Self {
        Self {
            instruments: config.instruments,
            #[cfg(feature = "std")]
            reports_dir: config.reports_dir,
        }
    }

    /// Records the op with every active instrument, otherwise it's a no-op.
    pub fn on_operation_execution_cycle(&mut self, op: Operation, proc: Option<&str>) {
        for instrument in &mut self.instruments {
            instrument.on_operation_execution_cycle(op, proc);
        }
    }

    /// Describes the cycle about to execute to every active instrument, otherwise it's a no-op.
    pub fn on_cycle(&mut self, cycle: &CycleInfo<'_>) {
        for instrument in &mut self.instruments {
            instrument.on_cycle(cycle);
        }
    }

    /// Writes every instrument's report to the configured reports output directory.
    ///
    /// Failure to write a report should not abort execution, therefore this function always
    /// succeeds. If any errors occur they are logged.
    #[cfg(feature = "std")]
    pub fn write_reports(&self) {
        if self.instruments.is_empty() {
            return;
        }

        let Some(ref reports_dir) = self.reports_dir else {
            log::warn!("cannot write profiler reports: no reports directory configured");
            return;
        };

        if let Err(e) = std::fs::create_dir_all(reports_dir) {
            log::error!(
                "failed to create profiler reports directory {}: {e}",
                reports_dir.display()
            );
            return;
        }

        for instrument in &self.instruments {
            let name = instrument.name();
            let path = reports_dir.join(name);
            let mut file = match std::fs::File::create(&path) {
                Ok(file) => file,
                Err(e) => {
                    log::error!(
                        "failed to create profiler output file for `{name}` at {}: {e}",
                        path.display()
                    );
                    continue;
                }
            };
            if let Err(e) = instrument.write_report_to(&mut file) {
                log::error!("failed to write `{name}` report to {}: {e}", path.display());
            }
        }
    }

    /// Writes every instrument's report to the given output writer.
    pub fn write_reports_to(&self, writer: &mut dyn OutputWriter) -> OutputResult<()> {
        if self.instruments.is_empty() {
            return Ok(());
        }

        for instrument in &self.instruments {
            instrument.write_report_to(writer)?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests;
