use std::env;

use clap::Parser;
#[cfg(feature = "flamegraph")]
use clap::Subcommand;
use miden_assembly_syntax::diagnostics::{IntoDiagnostic, Report, WrapErr};
use miden_debug::DebuggerConfig;
#[cfg(feature = "flamegraph")]
use miden_debug::flamegraph::FlamegraphArgs;
#[cfg(feature = "repl")]
use miden_debug::run_repl_with_log_level as run_repl;
#[cfg(feature = "tui")]
use miden_debug::run_replay_and_log_level;
#[cfg(feature = "tui")]
use miden_debug::run_with_log_level as run;
#[cfg(all(feature = "dap", feature = "tui"))]
use miden_debug::{State, run_with_state_and_log_level as run_with_state};

#[derive(Parser)]
#[command(author, version, about = "The interactive Miden debugger")]
#[command(args_conflicts_with_subcommands = true)]
struct Cli {
    #[cfg(feature = "flamegraph")]
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    config: DebuggerConfig,
}

#[cfg(feature = "flamegraph")]
#[derive(Subcommand)]
enum Commands {
    /// Generate a flame graph SVG from program execution cycle counts
    Flamegraph(FlamegraphArgs),
}

pub fn main() -> Result<(), Report> {
    setup_diagnostics();

    // Initialize logger, but do not install it, leave that up to the command handler
    let mut builder = env_logger::Builder::from_env("MIDENC_TRACE");
    builder.format_indent(Some(2));
    // miden-core's deserializer logs advisory errors on every untrusted
    // package load, even successful ones; real failures surface as errors in
    // their own right. Keep the default output clean, but let an explicit
    // MIDENC_TRACE spec re-enable the module.
    if env::var("MIDENC_TRACE").is_err() {
        builder.filter_module("miden_core::mast::serialization", log::LevelFilter::Off);
    }
    if let Ok(precision) = env::var("MIDENC_TRACE_TIMING") {
        match precision.as_str() {
            "s" => builder.format_timestamp_secs(),
            "ms" => builder.format_timestamp_millis(),
            "us" => builder.format_timestamp_micros(),
            "ns" => builder.format_timestamp_nanos(),
            other => {
                return Err(Report::msg(format!(
                    "invalid MIDENC_TRACE_TIMING precision, expected one of [s, ms, us, ns], got \
                     '{other}'"
                )));
            }
        };
    } else {
        builder.format_timestamp(None);
    }

    let logger = builder.build();
    let log_level = logger.filter();
    let logger = Box::new(logger);
    let cli = Cli::parse();

    #[cfg(feature = "flamegraph")]
    if let Some(command) = cli.command {
        return match command {
            Commands::Flamegraph(args) => {
                log::set_boxed_logger(logger)
                    .map_err(|err| Report::msg(format!("failed to install logger: {err}")))?;
                log::set_max_level(log_level);
                miden_debug::flamegraph::run(args)
            }
        };
    }

    run_debugger(Box::new(cli.config), logger, log_level)
}

fn run_debugger(
    mut config: Box<DebuggerConfig>,
    _logger: Box<dyn log::Log>,
    _log_level: log::LevelFilter,
) -> Result<(), Report> {
    if config.working_dir.is_none() {
        let cwd = env::current_dir()
            .into_diagnostic()
            .wrap_err("could not read current working directory")?;

        config.working_dir = Some(cwd);
    }

    #[cfg(feature = "tui")]
    if let Some(snapshot_path) = config.replay.clone() {
        return run_replay_and_log_level(&snapshot_path, _logger, _log_level);
    }

    #[cfg(all(feature = "dap", feature = "tui"))]
    if let Some(addr) = config.dap_connect.as_ref() {
        let state = State::new_for_dap(addr)?;
        return run_with_state(state, _logger, _log_level);
    }

    #[cfg(feature = "dap")]
    if config.start_debug_adapter.is_some() {
        log::set_boxed_logger(_logger).ok();
        log::set_max_level(_log_level);
        return miden_debug::run_dap_server(config);
    }

    #[cfg(feature = "script")]
    if let Some(commands) = config.commands.clone() {
        // Batch mode: install the logger directly (no interactive frontend),
        // then run the command script to completion and exit.
        log::set_boxed_logger(_logger).ok();
        log::set_max_level(_log_level);
        return miden_debug::run_commands(config, &commands);
    }

    #[cfg(feature = "repl")]
    if config.repl {
        return run_repl(config, _logger, _log_level);
    }

    #[cfg(not(feature = "repl"))]
    if config.repl {
        return Err(Report::msg(
            "this build does not include the REPL; rebuild with `--features repl`",
        ));
    }

    #[cfg(not(feature = "script"))]
    if config.commands.is_some() {
        return Err(Report::msg(
            "this build does not include command scripting; rebuild with `--features script`",
        ));
    }

    #[cfg(feature = "tui")]
    return run(config, _logger, _log_level);

    #[cfg(not(feature = "tui"))]
    Err(Report::msg(
        "no UI feature enabled: build with --features tui or --features repl",
    ))
}

fn setup_diagnostics() {
    use miden_assembly_syntax::diagnostics::reporting::{self, ReportHandlerOpts};

    let result = reporting::set_hook(Box::new(|_| Box::new(ReportHandlerOpts::new().build())));
    if result.is_ok() {
        reporting::set_panic_hook();
    }
}
