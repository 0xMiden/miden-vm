use std::ffi::OsString;

use clap::{FromArgMatches, Parser, Subcommand};
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
#[command(multicall(true))]
pub struct MidenVmCli {
    #[command(subcommand)]
    behavior: Behavior,
}

impl From<MidenVmCli> for Cli {
    fn from(value: MidenVmCli) -> Self {
        match value.behavior {
            Behavior::MidenVm { cli } => cli,
            Behavior::External(args) => Cli::parse_from(args).set_external(),
        }
    }
}

#[derive(Debug, Subcommand)]
#[command(rename_all = "kebab-case")]
enum Behavior {
    /// The Miden VM CLI.
    MidenVm {
        #[command(flatten)]
        cli: Cli,
    },

    /// Used when the Miden VM CLI is called under a different name, like
    /// when it is called from [Midenup](https://github.com/0xMiden/midenup).
    /// Vec<OsString> holds the "raw" arguments passed to the command line,
    /// analogous to `argv`.
    #[command(external_subcommand)]
    External(Vec<OsString>),
}

#[derive(Parser, Debug)]
#[command(name = "miden-client")]
pub struct Cli {
    #[command(subcommand)]
    action: Actions,

    /// Indicates whether the vm's CLI is being called directly, or externally
    /// under an alias (like in the case of
    /// [Midenup](https://github.com/0xMiden/midenup).
    #[arg(skip)]
    #[allow(unused)]
    external: bool,
}

/// CLI actions
#[derive(Debug, Parser)]
pub enum Actions {
    Analyze(tools::Analyze),
    Compile(cli::CompileCmd),
    Bundle(cli::BundleCmd),
    Debug(cli::DebugCmd),
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
            Actions::Prove(prove) => prove.execute(),
            Actions::Run(run) => run.execute(),
            Actions::Verify(verify) => verify.execute(),
            #[cfg(feature = "std")]
            Actions::Repl(repl) => repl.execute(),
        }
    }

    fn set_external(mut self) -> Self {
        self.external = true;
        self
    }
}

/// Executable entry point
pub fn main() -> Result<(), Report> {
    // read command-line args
    let cli = <MidenVmCli as clap::CommandFactory>::command();
    let matches = cli.get_matches();
    let parsed = MidenVmCli::from_arg_matches(&matches).unwrap_or_else(|err| err.exit());
    let cli: Cli = parsed.into();

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

// TESTS
// ================================================================================================
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    /// Check that the VM recognizes when it is being called under an alias.
    fn test_mutlicall() {
        // Direct call
        let miden_vm_command =
            MidenVmCli::try_parse_from(["miden-vm", "repl"]).expect("failed to parse commands");

        assert!(matches!(
            miden_vm_command.behavior,
            Behavior::MidenVm { cli: Cli { external: false, .. } }
        ));

        let cli: Cli = miden_vm_command.into();
        assert!(matches!(cli, Cli { external: false, .. }));

        // External call

        // This recreates how the vm would be called from midenup
        let external =
            MidenVmCli::try_parse_from(["miden vm", "repl"]).expect("failed to parse commands");

        assert!(matches!(external.behavior, Behavior::External(_)));

        let cli: Cli = external.into();
        assert!(matches!(cli, Cli { external: true, .. }));
    }
}
