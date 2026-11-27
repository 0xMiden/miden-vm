extern crate alloc;

use std::{
    ffi::{OsStr, OsString},
    path::PathBuf,
    process::ExitCode,
};

use clap::{Args, FromArgMatches, Parser, Subcommand};
use miden_assembly::diagnostics::Report;
#[cfg(feature = "tracing-forest")]
use tracing_forest::ForestLayer;
#[cfg(not(feature = "tracing-forest"))]
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::{EnvFilter, prelude::*};

mod cli;

use cli::ProofMode;

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
            Behavior::MidenVm { cli } => Ok(*cli),
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
                                command_name.to_string_lossy()
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
        cli: Box<Cli>,
    },

    /// This variant will be matched when the CLI is called under an alias, like
    /// when it is called from [Midenup](https://github.com/0xMiden/midenup).
    /// Vec<OsString> holds the "raw" arguments passed to the command line,
    /// analogous to `argv`.
    #[command(external_subcommand)]
    External(Vec<OsString>),
}

#[derive(Parser, Debug)]
#[command(name = "miden-vm", version)]
pub struct Cli {
    #[command(subcommand)]
    action: Actions,

    #[command(flatten)]
    parameters: ParameterArgs,

    /// Indicates whether the vm's CLI is being called directly, or externally
    /// under an alias (like in the case of
    /// [Midenup](https://github.com/0xMiden/midenup).
    #[arg(skip)]
    external: bool,
}

#[derive(Args, Debug)]
struct ParameterArgs {
    /// Load reusable settings from PATH (defaults to ./miden-vm.toml when present).
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Override a configuration setting, e.g. --set resources.max-prover-memory=8GiB.
    #[arg(long = "set", value_name = "KEY=VALUE")]
    settings: Vec<String>,
}

// Clap propagates a global argument from the deepest subcommand that supplied it. For a
// repeatable option this would discard earlier --set arguments. Parse the two positions
// independently and join their assignments in command-line order.
#[derive(Args, Debug)]
struct Invocation<T: Args> {
    #[command(flatten)]
    parameters: ParameterArgs,
    #[command(flatten)]
    command: T,
}

impl<T: Args> Invocation<T> {
    fn execute(
        self,
        mut leading: ParameterArgs,
        run: impl FnOnce(&T, &cli::config::Settings) -> Result<(), Report>,
    ) -> Result<(), Report> {
        if leading.config.is_some() && self.parameters.config.is_some() {
            return Err(Report::msg("--config may only be supplied once"));
        }
        let path = self.parameters.config.or(leading.config);
        leading.settings.extend(self.parameters.settings);
        let settings = cli::config::Settings::load(path.as_deref(), &leading.settings)?;
        run(&self.command, &settings)
    }
}

#[derive(Debug, Subcommand)]
enum Actions {
    Compile(Invocation<cli::CompileCmd>),
    Bundle(Invocation<cli::BundleCmd>),
    /// Prove the VM execution and export a witness for any precompile work
    ///
    /// The witness contains raw precompile inputs and can reveal private advice. Use
    /// prove-complete to generate a precompile STARK. With no precompile work, either command
    /// produces a complete proof.
    Prove(Invocation<cli::ProveCmd>),
    /// Generate a complete proof, including a STARK for any precompile work
    ProveComplete(Invocation<cli::ProveCmd>),
    Run(Invocation<cli::RunCmd>),
    /// Verify a complete or deferred execution proof and report its status
    Verify(Invocation<cli::VerifyCmd>),
    /// Verify a complete execution proof, including any precompile STARK
    VerifyComplete(Invocation<cli::VerifyCmd>),
    /// Verify a partial execution proof that carries a deferred precompile witness
    ///
    /// Verifies the VM STARK, checks the witness against the authenticated precompile root,
    /// and evaluates the witness natively. Reports the outstanding precompile root on success.
    VerifyPartial(Invocation<cli::VerifyCmd>),
}

impl Cli {
    pub fn execute(self) -> Result<(), Report> {
        match self.action {
            Actions::Compile(cmd) => cmd.execute(self.parameters, |cmd, _| cmd.execute()),
            Actions::Bundle(cmd) => cmd.execute(self.parameters, cli::BundleCmd::execute),
            Actions::Prove(cmd) => cmd.execute(self.parameters, |cmd, settings| {
                cmd.execute(settings, ProofMode::Deferred)
            }),
            Actions::ProveComplete(cmd) => cmd.execute(self.parameters, |cmd, settings| {
                cmd.execute(settings, ProofMode::Complete)
            }),
            Actions::Run(cmd) => cmd.execute(self.parameters, cli::RunCmd::execute),
            Actions::Verify(cmd) => {
                cmd.execute(self.parameters, |cmd, settings| cmd.execute(settings, None))
            },
            Actions::VerifyComplete(cmd) => cmd.execute(self.parameters, |cmd, settings| {
                cmd.execute(settings, Some(ProofMode::Complete))
            }),
            Actions::VerifyPartial(cmd) => cmd.execute(self.parameters, |cmd, settings| {
                cmd.execute(settings, Some(ProofMode::Deferred))
            }),
        }
    }

    fn set_external(mut self) -> Self {
        self.external = true;
        self
    }
}

/// Executable entry point
pub fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprint!("{error:?}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<(), Report> {
    // read command-line args
    let cli = <MidenVmCli as clap::CommandFactory>::command();
    let matches = cli.get_matches();
    let parsed = MidenVmCli::from_arg_matches(&matches).unwrap_or_else(|err| err.exit());
    let cli: Cli = parsed.try_into()?;

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

// TESTS
// ================================================================================================
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parameters_on_either_side_of_the_subcommand_work_in_both_entry_points() {
        let cwd = tempfile::tempdir().unwrap();
        let file = cwd.path().join("ci.toml");
        std::fs::write(&file, "[display]\nnum-outputs = 8").unwrap();
        for argv0 in ["miden-vm", "miden vm"] {
            let cli: Cli = MidenVmCli::try_parse_from([
                argv0,
                "--config",
                file.to_str().unwrap(),
                "--set",
                "execution.expected-cycles=128",
                "prove-complete",
                "unused.masm",
                "--set",
                "display.num-outputs=4",
            ])
            .unwrap()
            .try_into()
            .unwrap();
            let Actions::ProveComplete(cmd) = cli.action else {
                panic!("expected prove-complete")
            };
            cmd.execute(cli.parameters, |_, settings| {
                assert_eq!(settings.execution.expected_cycles(), 128);
                assert_eq!(settings.num_outputs, 4);
                Ok(())
            })
            .unwrap();
        }
    }

    #[test]
    /// Check that the VM recognizes when it is being called under an alias.
    fn test_multicall() {
        // Direct call
        let miden_vm_command = MidenVmCli::try_parse_from(["miden-vm", "run", "my_file.masm"])
            .expect("failed to parse commands");

        assert!(matches!(
            miden_vm_command.behavior,
            Behavior::MidenVm { ref cli } if !cli.external
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
