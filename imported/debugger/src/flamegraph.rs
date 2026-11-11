use std::{
    collections::{BTreeMap, VecDeque},
    fs::File,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_assembly::{DefaultSourceManager, SourceManager};
use miden_assembly_syntax::diagnostics::{IntoDiagnostic, Report, WrapErr};
use miden_debug_engine::LinkLibrary;
use miden_processor::ExecutionError;

use crate::{
    config::{ColorChoice, DebuggerConfig},
    debug::CallFrame,
    exec::{DebugExecutor, ExecutionConfig, Executor, ReplaySnapshot},
    input::InputFile,
};

/// Folded stack samples keyed by semicolon-separated stack paths.
pub type Samples = BTreeMap<String, usize>;

/// A collected VM cycle profile that can be rendered as folded stacks or an SVG flamegraph.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FlamegraphProfile {
    samples: Samples,
    total_cycles: usize,
}

/// The output format selected by [`FlamegraphProfile::write_to_path`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlamegraphOutput {
    Svg,
    FoldedStacks,
}

impl FlamegraphProfile {
    /// Execute `executor` to completion, sampling its logical source stack for every VM cycle.
    /// Inferred and inline frames retain their labels; frame events provide the fallback when
    /// source metadata is unavailable.
    pub fn collect(executor: &mut DebugExecutor) -> Result<Self, ExecutionError> {
        let mut profile = Self::default();

        loop {
            if executor.stopped {
                break;
            }

            let previous_cycle = executor.cycle;
            match executor.step() {
                Ok(_) if executor.cycle > previous_cycle => {
                    let cycle_delta = executor.cycle - previous_cycle;
                    let frames = executor.callstack.logical_frames("");
                    profile
                        .record_stack(frames.iter().map(|frame| frame.display_name()), cycle_delta);
                }
                Ok(_) => {
                    if executor.stopped {
                        break;
                    }
                }
                Err(err) => return Err(err),
            }
        }

        Ok(profile)
    }

    /// Replay a recorded execution and collect its cycle-weighted call stacks.
    pub fn collect_replay(snapshot: ReplaySnapshot) -> Result<Self, ExecutionError> {
        let ReplaySnapshot {
            package,
            stack_inputs,
            advice_inputs,
            options,
            mast_forests,
            event_log,
        } = snapshot;
        let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
        let executor = Executor::from_config(ExecutionConfig {
            inputs: stack_inputs,
            advice_inputs,
            options,
        });
        let mut debug_executor = executor.into_debug_with_replay(
            package,
            source_manager,
            mast_forests,
            VecDeque::from(event_log),
        );
        Self::collect(&mut debug_executor)
    }

    /// Record `cycles` against a call stack from the debugger engine.
    pub fn record_call_stack(&mut self, frames: &[CallFrame], cycles: usize) {
        let path = build_stack_path(frames);
        self.record_stack_path(path, cycles);
    }

    /// Record `cycles` against a stack of frame names.
    ///
    /// Frame names are sanitized for folded stack output, then joined with `;`.
    pub fn record_stack<I, S>(&mut self, frames: I, cycles: usize)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let path = build_stack_path_from_names(frames);
        self.record_stack_path(path, cycles);
    }

    /// Record `cycles` against an already formatted folded-stack path.
    pub fn record_stack_path(&mut self, stack_path: impl Into<String>, cycles: usize) {
        if cycles == 0 {
            return;
        }

        self.total_cycles += cycles;
        *self.samples.entry(stack_path.into()).or_default() += cycles;
    }

    pub fn samples(&self) -> &Samples {
        &self.samples
    }

    pub fn total_cycles(&self) -> usize {
        self.total_cycles
    }

    pub fn unique_stack_paths(&self) -> usize {
        self.samples.len()
    }

    /// Write this profile as an SVG when `path` ends in `.svg`, otherwise as folded stack text.
    pub fn write_to_path(&self, path: impl AsRef<Path>) -> Result<FlamegraphOutput, Report> {
        let path = path.as_ref();
        if is_svg_path(path) {
            self.write_svg(path)?;
            Ok(FlamegraphOutput::Svg)
        } else {
            self.write_folded_stacks(path)?;
            Ok(FlamegraphOutput::FoldedStacks)
        }
    }

    /// Write this profile in folded stack format.
    pub fn write_folded_stacks(&self, path: impl AsRef<Path>) -> Result<(), Report> {
        write_folded_stacks(&self.samples, path.as_ref())
    }

    /// Render this profile as an SVG flamegraph.
    pub fn write_svg(&self, path: impl AsRef<Path>) -> Result<(), Report> {
        generate_svg(&self.samples, path.as_ref())
    }
}

#[derive(clap::Args, Debug)]
#[command(group(
    clap::ArgGroup::new("execution")
        .required(true)
        .args(["input", "replay"])
))]
pub struct FlamegraphArgs {
    /// Specify the path to a Miden program file to execute.
    #[arg(value_name = "FILE")]
    pub input: Option<InputFile>,
    /// Replay a recorded transaction snapshot instead of executing a raw program.
    #[arg(long, value_name = "FILE")]
    pub replay: Option<PathBuf>,
    /// Write the generated flame graph SVG or folded stack text to this path.
    #[arg(short, long, default_value = "flamegraph.svg")]
    pub output: PathBuf,
    /// Specify the path to a file containing program inputs.
    #[arg(long, value_name = "FILE")]
    pub inputs: Option<ExecutionConfig>,
    /// Arguments to encode for the selected program entrypoint.
    #[arg(last(true), value_name = "ARGV")]
    pub args: Vec<String>,
    /// The working directory for execution.
    #[arg(long, value_name = "DIR", help_heading = "Execution")]
    pub working_dir: Option<PathBuf>,
    /// The path to the root directory of the current Miden toolchain.
    #[arg(
        long,
        value_name = "DIR",
        env = "MIDEN_SYSROOT",
        help_heading = "Linker"
    )]
    pub sysroot: Option<PathBuf>,
    /// Specify the function to call as the entrypoint for the program.
    #[arg(long, help_heading = "Execution")]
    pub entrypoint: Option<String>,
    /// Specify one or more search paths for link libraries requested via `-l`.
    #[arg(
        long = "search-path",
        short = 'L',
        value_name = "PATH",
        help_heading = "Linker"
    )]
    pub search_path: Vec<PathBuf>,
    /// Load the compiled library package NAME.
    ///
    /// KIND currently supports only `masp` (the default). The optional LINKAGE is either `static`
    /// or `dynamic` and defaults to `dynamic`.
    #[arg(
        long = "link-library",
        short = 'l',
        value_name = "[KIND[:LINKAGE]=]NAME",
        value_delimiter = ',',
        next_line_help(true),
        help_heading = "Linker"
    )]
    pub link_libraries: Vec<LinkLibrary>,
}

impl FlamegraphArgs {
    fn into_debugger_config(self) -> DebuggerConfig {
        DebuggerConfig {
            input: self.input,
            inputs: self.inputs,
            args: self.args,
            working_dir: self.working_dir,
            sysroot: self.sysroot,
            color: ColorChoice::Auto,
            entrypoint: self.entrypoint,
            #[cfg(all(feature = "dap", feature = "tui"))]
            dap_connect: None,
            #[cfg(feature = "dap")]
            start_debug_adapter: None,
            source_path_prefixes: Vec::new(),
            search_path: self.search_path,
            link_libraries: self.link_libraries,
            repl: false,
            commands: None,
            #[cfg(feature = "tui")]
            replay: None,
            #[cfg(feature = "python")]
            no_user_python_init: true,
            profiler_cli_args: Default::default(), // disable profiling
        }
    }
}

pub fn run(args: FlamegraphArgs) -> Result<(), Report> {
    let output = args.output.clone();
    let replay = args.replay.clone();
    if let Some(replay) = replay {
        let snapshot = ReplaySnapshot::read_from_file(&replay)
            .map_err(|err| Report::msg(format!("failed to read {}: {err}", replay.display())))?;
        let profile = FlamegraphProfile::collect_replay(snapshot)
            .map_err(|err| Report::msg(format!("replay execution failed: {err}")))?;
        report_and_write_profile(&profile, &output)?;
        return Ok(());
    }

    let mut config = args.into_debugger_config();
    ensure_working_dir(&mut config)?;

    let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
    let mut executor =
        crate::program_loader::load_debug_executor(&config, source_manager, "flamegraph")?.executor;

    let profile = match FlamegraphProfile::collect(&mut executor) {
        Ok(profile) => profile,
        Err(err) => {
            return Err(Report::msg(format!(
                "program execution failed at cycle {}: {err}",
                executor.cycle
            )));
        }
    };

    report_and_write_profile(&profile, &output)?;

    Ok(())
}

fn report_and_write_profile(profile: &FlamegraphProfile, output: &Path) -> Result<(), Report> {
    eprintln!(
        "Executed {} cycles across {} unique stack paths",
        profile.total_cycles(),
        profile.unique_stack_paths()
    );
    profile.write_to_path(output)?;
    Ok(())
}

fn ensure_working_dir(config: &mut DebuggerConfig) -> Result<(), Report> {
    if config.working_dir.is_none() {
        let cwd = std::env::current_dir()
            .into_diagnostic()
            .wrap_err("could not read current working directory")?;
        config.working_dir = Some(cwd);
    }

    Ok(())
}

fn build_stack_path(frames: &[CallFrame]) -> String {
    build_stack_path_from_names(frames.iter().filter_map(|frame| frame.procedure("")))
}

fn build_stack_path_from_names<I, S>(frames: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut path = String::new();
    for frame in frames {
        append_frame(&mut path, frame.as_ref());
    }

    if path.is_empty() {
        "[unknown]".to_string()
    } else {
        path
    }
}

fn append_frame(path: &mut String, name: &str) {
    if !path.is_empty() {
        path.push(';');
    }
    append_sanitized_frame(path, name);
}

fn append_sanitized_frame(path: &mut String, name: &str) {
    for ch in name.chars() {
        match ch {
            ';' => path.push(':'),
            '\n' | '\r' => path.push(' '),
            _ => path.push(ch),
        }
    }
}

fn is_svg_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("svg"))
}

fn write_folded_stacks(samples: &Samples, path: &Path) -> Result<(), Report> {
    let file = File::create(path).into_diagnostic()?;
    let mut writer = BufWriter::new(file);
    for (stack, count) in samples {
        writeln!(writer, "{stack} {count}").into_diagnostic()?;
    }
    writer.flush().into_diagnostic()?;

    eprintln!("Wrote folded stacks to {}", path.display());
    Ok(())
}

fn generate_svg(samples: &Samples, path: &Path) -> Result<(), Report> {
    let input = samples
        .iter()
        .map(|(stack, count)| format!("{stack} {count}"))
        .collect::<Vec<_>>()
        .join("\n");

    let mut opts = inferno::flamegraph::Options::default();
    opts.title = "Miden VM Flame Graph (cycles)".to_string();
    opts.count_name = "cycles".to_string();

    let file = File::create(path).into_diagnostic()?;
    let mut writer = BufWriter::new(file);
    inferno::flamegraph::from_reader(&mut opts, input.as_bytes(), &mut writer).into_diagnostic()?;
    writer.flush().into_diagnostic()?;

    eprintln!("Wrote flame graph to {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests;
