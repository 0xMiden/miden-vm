#[cfg(feature = "repl")]
use std::boxed::Box;

mod commands;
pub(crate) mod engine;
#[cfg(feature = "python")]
mod python;
mod script;
#[cfg(feature = "repl")]
mod session;

#[cfg(feature = "repl")]
use log::LevelFilter;
#[cfg(feature = "repl")]
use miden_assembly_syntax::diagnostics::{IntoDiagnostic, Report};

pub use self::script::run_commands;
#[cfg(feature = "repl")]
use self::session::ReplSession;
#[cfg(feature = "repl")]
use crate::config::DebuggerConfig;

/// Run the REPL debugger with the given configuration.
#[cfg(feature = "repl")]
pub fn run(config: Box<DebuggerConfig>, logger: Box<dyn log::Log>) -> Result<(), Report> {
    run_with_log_level(config, logger, LevelFilter::Trace)
}

/// Run the REPL debugger with the given configuration and log level filter.
#[cfg(feature = "repl")]
pub fn run_with_log_level(
    config: Box<DebuggerConfig>,
    logger: Box<dyn log::Log>,
    max_level: LevelFilter,
) -> Result<(), Report> {
    // Install the logger; propagate any failure as a diagnostic so the
    // session doesn't silently start with a half-installed logger.
    crate::logger::DebugLogger::install_with_max_level(logger, max_level).into_diagnostic()?;

    let mut session = ReplSession::new(config)?;
    session.run()
}
