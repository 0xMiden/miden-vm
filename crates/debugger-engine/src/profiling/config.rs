use alloc::{boxed::Box, vec::Vec};
#[cfg(feature = "std")]
use std::path::PathBuf;

#[cfg(feature = "std")]
use miden_assembly_syntax::diagnostics::Report;

use crate::profiling::instrument::Instrument;

/// Profiler options parsed from the command line.
#[cfg(feature = "std")]
#[derive(Default, Clone, Debug, clap::Args)]
pub struct ProfilerCliArgs {
    /// Enables profiling and sets the output dir for reports. Profiling
    /// instruments need to be enabled separately.
    #[arg(long = "profiling-reports-dir", value_name = "DIRECTORY")]
    pub reports_dir: Option<PathBuf>,
    #[arg(
        long = "profiling-instruments",
        value_name = "VALUE",
        value_delimiter = ','
    )]
    pub instruments: Vec<alloc::string::String>,
}

#[derive(Default)]
pub struct ProfilerConfig {
    /// The active instrumentations.
    pub instruments: Vec<Box<dyn Instrument>>,
    /// The directory where profiling reports are written.
    #[cfg(feature = "std")]
    pub reports_dir: Option<PathBuf>,
}

#[cfg(feature = "std")]
impl TryFrom<ProfilerCliArgs> for ProfilerConfig {
    type Error = Report;

    fn try_from(mut args: ProfilerCliArgs) -> Result<Self, Self::Error> {
        use crate::profiling::instrument_from_name;

        let mut config = ProfilerConfig::default();

        if let Some(ref path) = args.reports_dir
            && path.exists()
            && !path.is_dir()
        {
            return Err(Report::msg(format!(
                "invalid profiling reports directory '{}': not a directory",
                path.display()
            )));
        }

        if args.reports_dir.is_some() && args.instruments.is_empty() {
            return Err(Report::msg(
                "profiling requires at least one instrument set with --profiling-instruments",
            ));
        }

        if args.reports_dir.is_none() && !args.instruments.is_empty() {
            return Err(Report::msg(
                "profiling instruments require --profiling-reports-dir to be set",
            ));
        }

        config.reports_dir = args.reports_dir;

        args.instruments.sort();
        args.instruments.dedup();
        for name in &args.instruments {
            let instrument = instrument_from_name(name, &config).map_err(Report::msg)?;
            config.instruments.push(instrument);
        }

        Ok(config)
    }
}

impl core::fmt::Debug for ProfilerConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let instrument_names: Vec<&'static str> =
            self.instruments.iter().map(|i| i.name()).collect();
        let mut builder = f.debug_struct("ProfilerConfig");
        builder.field("instruments", &instrument_names);
        #[cfg(feature = "std")]
        {
            builder.field("reports_dir", &self.reports_dir);
        }
        builder.finish()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests;
