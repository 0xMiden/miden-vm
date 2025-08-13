use clap::Parser;
use miden_assembly::diagnostics::Report;
#[cfg(feature = "tracing-forest")]
use tracing_forest::ForestLayer;
#[cfg(not(feature = "tracing-forest"))]
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::{EnvFilter, prelude::*};

mod cli;
mod repl;
mod tools;

pub(crate) mod utils;

/// Root CLI struct
#[derive(Parser, Debug)]
#[command(
    name = "miden-vm",
    about = "The Miden virtual machine",
    version,
    rename_all = "kebab-case"
)]
pub struct Cli {
    #[command(subcommand)]
    action: Actions,
}

/// CLI actions
#[derive(Debug, Parser)]
pub enum Actions {
    Analyze(tools::Analyze),
    Compile(cli::CompileCmd),
    Bundle(cli::BundleCmd),
    Debug(cli::DebugCmd),
    Events(cli::EventsCmd),
    Prove(cli::ProveCmd),
    Run(cli::RunCmd),
    Verify(cli::VerifyCmd),
    #[cfg(feature = "std")]
    Repl(cli::ReplCmd),
}

/// CLI entry point
impl Cli {
    pub fn execute(&self) -> Result<(), Report> {
        match &self.action {
            Actions::Analyze(analyze) => analyze.execute(),
            Actions::Compile(compile) => compile.execute(),
            Actions::Bundle(compile) => compile.execute(),
            Actions::Debug(debug) => debug.execute(),
            Actions::Events(events) => events.execute(),
            Actions::Prove(prove) => prove.execute(),
            Actions::Run(run) => run.execute(),
            Actions::Verify(verify) => verify.execute(),
            #[cfg(feature = "std")]
            Actions::Repl(repl) => repl.execute(),
        }
    }
}

/// Executable entry point
pub fn main() -> Result<(), Report> {
    // read command-line args
    let cli = Cli::parse();

    initialize_diagnostics();

    // configure logging
    // if logging level is not specified, set level to "warn"
    if std::env::var("MIDEN_LOG").is_err() {
        unsafe { std::env::set_var("MIDEN_LOG", "warn") };
    }
    let registry =
        tracing_subscriber::registry::Registry::default().with(EnvFilter::from_env("MIDEN_LOG"));

    #[cfg(feature = "tracing-forest")]
    registry.with(ForestLayer::default()).init();

    #[cfg(not(feature = "tracing-forest"))]
    {
        let format = tracing_subscriber::fmt::layer()
            .with_level(false)
            .with_target(false)
            .with_thread_names(false)
            .with_span_events(FmtSpan::CLOSE)
            .with_ansi(false)
            .compact();

        registry.with(format).init();
    }

    // execute cli action
    cli.execute()
}

fn initialize_diagnostics() {
    use miden_assembly::diagnostics::reporting::{self, ReportHandlerOpts};

    #[cfg(feature = "std")]
    {
        let result = reporting::set_hook(Box::new(|_| Box::new(ReportHandlerOpts::new().build())));
        if result.is_ok() {
            reporting::set_panic_hook();
        }
    }

    #[cfg(not(feature = "std"))]
    {
        let _ = reporting::set_hook(Box::new(|_| Box::new(ReportHandlerOpts::new().build())));
    }
}
