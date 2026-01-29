use std::ffi::{OsStr, OsString};

use clap::{FromArgMatches, Parser, Subcommand};
use miden_assembly::diagnostics::Report;
#[cfg(feature = "tracing-forest")]
use tracing_forest::ForestLayer;
#[cfg(not(feature = "tracing-forest"))]
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::{EnvFilter, prelude::*};

mod cli;

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

impl TryFrom<MidenVmCli> for Cli {
    type Error = Report;

    fn try_from(value: MidenVmCli) -> Result<Self, Self::Error> {
        match value.behavior {
            Behavior::MidenVm { cli } => Ok(cli),
            Behavior::External(args) => {
                let used_alias = args.first();
                let is_known_alias = used_alias
                    .map(|command_name| command_name.as_os_str() == OsStr::new("miden vm"))
                    // Edge case where the CLI is called under no name.
                    .unwrap_or(false);

                if !is_known_alias {
                    let error_message = used_alias
                        .map(|command_name| {
                            format!(
                                "Called the CLI with an unknown alias '{}'",
                                command_name.clone().into_string().unwrap_or("".to_string())
                            )
                        })
                        .unwrap_or(String::from("Called the CLI under an empty alias"));

                    return Err(Report::msg(error_message));
                }

                Ok(Cli::parse_from(args).set_external())
            },
        }
    }
}

/// Wrapper subcommand used by [MidenVmCli]'s multicall functionality to
/// distinguish when the executable is being called under an alias.
/// executable name. This is not intended to be visible via the CLI interface.
#[derive(Debug, Subcommand)]
#[command(rename_all = "kebab-case")]
enum Behavior {
    /// The Miden VM CLI.
    MidenVm {
        #[command(flatten)]
        cli: Cli,
    },

    /// This variant will be matched when the CLI is called under an alias, like
    /// when it is called from [Midenup](https://github.com/0xMiden/midenup).
    /// Vec<OsString> holds the "raw" arguments passed to the command line,
    /// analogous to `argv`.
    #[command(external_subcommand)]
    External(Vec<OsString>),
}

#[derive(Parser, Debug)]
#[command(name = "miden-vm")]
pub struct Cli {
    #[command(subcommand)]
    action: Actions,

    /// Indicates whether the vm's CLI is being called directly, or externally
    /// under an alias (like in the case of
    /// [Midenup](https://github.com/0xMiden/midenup).
    #[arg(skip)]
    external: bool,
}

/// CLI actions
#[derive(Debug, Parser)]
pub enum Actions {
    Compile(cli::CompileCmd),
    Bundle(cli::BundleCmd),
    Prove(cli::ProveCmd),
    Run(cli::RunCmd),
    Verify(cli::VerifyCmd),
}

/// CLI entry point
impl Cli {
    pub fn execute(&self) -> Result<(), Report> {
        match &self.action {
            Actions::Compile(compile) => compile.execute(),
            Actions::Bundle(compile) => compile.execute(),
            Actions::Prove(prove) => prove.execute(),
            Actions::Run(run) => run.execute(),
            Actions::Verify(verify) => verify.execute(),
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
    let cli: Cli = parsed.try_into()?;

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
    fn test_multicall() {
        // Direct call
        let miden_vm_command = MidenVmCli::try_parse_from(["miden-vm", "run", "my_file.masm"])
            .expect("failed to parse commands");

        assert!(matches!(
            miden_vm_command.behavior,
            Behavior::MidenVm { cli: Cli { external: false, .. } }
        ));

        let cli: Cli = miden_vm_command.try_into().expect("Failed to turn MidenVmCli into Cli.");
        assert!(matches!(cli, Cli { external: false, .. }));

        // External call

        // This recreates how the vm would be called from midenup
        let external = MidenVmCli::try_parse_from(["miden vm", "run", "my_file.masm"])
            .expect("failed to parse commands");

        assert!(matches!(external.behavior, Behavior::External(_)));

        let cli: Cli = external.try_into().expect("Failed to turn MidenVmCli into Cli.");
        assert!(matches!(cli, Cli { external: true, .. }));
    }
}
