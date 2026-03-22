use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::Parser;
use miden_assembly_syntax_cst::parse_text;

#[derive(Debug, Parser)]
#[command(name = "miden-format", version, about = "Format Miden Assembly source files")]
struct Cli {
    /// Check whether the input is already formatted.
    #[arg(long)]
    check: bool,

    /// Read the source from stdin instead of from filesystem paths.
    #[arg(long, conflicts_with = "paths")]
    stdin: bool,

    /// Logical path to associate with stdin input for diagnostics.
    #[arg(long, requires = "stdin")]
    stdin_filepath: Option<PathBuf>,

    /// Paths to Miden Assembly source files.
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("either at least one path or --stdin must be provided")]
    MissingInput,
    #[error("failed to read source from '{path}': {source}")]
    ReadFile {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to read source from stdin: {0}")]
    ReadStdin(#[source] io::Error),
    #[error("formatting is not implemented yet; parser and lexer scaffolding are in place")]
    FormattingUnavailable,
    #[error("syntax errors were found in the provided inputs")]
    SyntaxErrors,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<(), CliError> {
    let cli = Cli::parse();
    let inputs = collect_inputs(&cli)?;

    let mut has_syntax_errors = false;
    for (path, source) in &inputs {
        let parse = parse_text(source);
        if parse.has_errors() {
            has_syntax_errors = true;
            for diagnostic in parse.diagnostics() {
                let span = diagnostic.span();
                eprintln!(
                    "{}:{}..{}: {}",
                    path.display(),
                    span.start,
                    span.end,
                    diagnostic.message()
                );
            }
        }
    }

    if has_syntax_errors {
        return Err(CliError::SyntaxErrors);
    }

    let _ = cli.check;
    Err(CliError::FormattingUnavailable)
}

fn collect_inputs(cli: &Cli) -> Result<Vec<(PathBuf, String)>, CliError> {
    if cli.stdin {
        let path = cli.stdin_filepath.clone().unwrap_or_else(|| PathBuf::from("<stdin>"));
        let mut source = String::new();
        io::stdin().read_to_string(&mut source).map_err(CliError::ReadStdin)?;
        return Ok(vec![(path, source)]);
    }

    if cli.paths.is_empty() {
        return Err(CliError::MissingInput);
    }

    cli.paths.iter().map(|path| read_file(path)).collect::<Result<Vec<_>, _>>()
}

fn read_file(path: &Path) -> Result<(PathBuf, String), CliError> {
    let source = fs::read_to_string(path)
        .map_err(|source| CliError::ReadFile { path: path.display().to_string(), source })?;
    Ok((path.to_path_buf(), source))
}
