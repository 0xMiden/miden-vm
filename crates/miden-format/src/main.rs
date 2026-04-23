mod formatter;

use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use clap::Parser;
use miden_assembly_syntax_cst::{
    Report,
    diagnostics::{miette::MietteDiagnostic, reporting::PrintDiagnostic},
    parse_source_file,
};
use miden_debug_types::{
    DefaultSourceManager, SourceFile, SourceLanguage, SourceManager, SourceManagerError,
    SourceManagerExt, Uri,
};

use self::formatter::format_syntax;

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
    #[error("failed to write formatted source to '{path}': {source}")]
    WriteFile {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to read source from stdin: {0}")]
    ReadStdin(#[source] io::Error),
    #[error("syntax errors were found in the provided inputs")]
    SyntaxErrors,
    #[error("the following inputs are not formatted:\n{0}")]
    CheckFailed(String),
    #[error(transparent)]
    SourceManagerError(#[from] SourceManagerError),
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
    miden_assembly_syntax_cst::diagnostics::reporting::set_panic_hook();

    let cli = Cli::parse();
    let source_manager = Arc::new(DefaultSourceManager::default());
    let inputs = collect_inputs(&cli, &source_manager)?;

    let mut has_syntax_errors = false;
    let mut formatted_inputs = Vec::with_capacity(inputs.len());
    for input in inputs {
        let mut parse = parse_source_file(input.clone());
        if parse.has_errors() {
            has_syntax_errors = true;
            for diagnostic in parse.take_diagnostics() {
                eprintln!(
                    "{}",
                    PrintDiagnostic::new(report_parse_diagnostic(input.clone(), diagnostic))
                );
            }
            continue;
        }

        formatted_inputs.push((input, format_syntax(&parse.syntax())));
    }

    if has_syntax_errors {
        return Err(CliError::SyntaxErrors);
    }

    if cli.check {
        let mut mismatches = Vec::new();
        for (source, formatted) in &formatted_inputs {
            if source.as_str() != formatted {
                mismatches.push(source.uri());
            }
        }

        if mismatches.is_empty() {
            return Ok(());
        }

        for path in &mismatches {
            eprintln!("would reformat {path}");
        }

        return Err(CliError::CheckFailed(mismatches.iter().map(ToString::to_string).fold(
            String::new(),
            |mut acc, item| {
                acc.push('\n');
                acc.push_str(&item);
                acc
            },
        )));
    }

    if cli.stdin {
        if let Some((_, formatted)) = formatted_inputs.into_iter().next() {
            print!("{formatted}");
        }
        return Ok(());
    }

    for (source, formatted) in formatted_inputs {
        if source.as_str() == formatted {
            continue;
        }

        let path = Path::new(source.uri().path());
        fs::write(path, formatted).map_err(|err| CliError::WriteFile {
            path: source.uri().path().to_string(),
            source: err,
        })?;
    }

    Ok(())
}

fn report_parse_diagnostic(source: Arc<SourceFile>, diagnostic: MietteDiagnostic) -> Report {
    Report::from(diagnostic).with_source_code(source)
}

fn collect_inputs(
    cli: &Cli,
    source_manager: &dyn SourceManager,
) -> Result<Vec<Arc<SourceFile>>, CliError> {
    let mut inputs = vec![];

    if cli.stdin {
        let path = cli.stdin_filepath.clone().unwrap_or_else(|| PathBuf::from("<stdin>"));
        let mut source = String::new();
        io::stdin().read_to_string(&mut source).map_err(CliError::ReadStdin)?;
        let source = source_manager.load(SourceLanguage::Masm, Uri::from(path.as_path()), source);
        inputs.push(source);
        return Ok(inputs);
    }

    if cli.paths.is_empty() {
        return Err(CliError::MissingInput);
    }

    inputs.reserve_exact(cli.paths.len());
    for path in cli.paths.iter() {
        let source = source_manager.load_file(path)?;
        inputs.push(source);
    }

    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_diagnostics_include_source_context() {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let source = source_manager.load(
            SourceLanguage::Masm,
            Uri::from(Path::new("snippet.masm")),
            "begin".to_string(),
        );

        let mut parse = parse_source_file(source.clone());
        assert!(parse.has_errors());

        let diagnostic =
            parse.take_diagnostics().into_iter().next().expect("expected syntax diagnostic");
        let rendered = format!(
            "{}",
            PrintDiagnostic::new_without_color(report_parse_diagnostic(source, diagnostic))
        );

        assert!(rendered.contains("snippet.masm"));
        assert!(rendered.contains("begin"));
    }
}
