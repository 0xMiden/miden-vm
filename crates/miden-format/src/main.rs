mod config;
mod formatter;

use std::{
    fs,
    io::{self, Read, Write},
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

use self::{config::Config, formatter::format_syntax};

#[derive(Debug)]
struct Input {
    source: Arc<SourceFile>,
    path: Option<PathBuf>,
}

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

    /// Set formatter options from the command line
    #[arg(long)]
    config: Option<Config>,

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
    #[error("failed to write formatted source to '{path}': not a valid file path")]
    InvalidSourceUri { path: String },
    #[error("failed to read source from stdin: {0}")]
    ReadStdin(#[source] io::Error),
    #[error("failed to write formatted source to stdout: {0}")]
    WriteStdout(#[source] io::Error),
    #[error("syntax errors were found in the provided inputs")]
    SyntaxErrors,
    #[error("the following inputs are not formatted:\n{0}")]
    CheckFailed(String),
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error(transparent)]
    SourceManagerError(#[from] SourceManagerError),
    #[error(transparent)]
    WalkDir(#[from] walkdir::Error),
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

    let config = if let Ok(cwd) = std::env::current_dir() {
        let path = cwd.join("miden-format.toml");
        if path.try_exists().ok().is_some_and(|exists| exists) {
            let mut config = Config::load(path)?;
            if let Some(cli_config) = cli.config.as_ref() {
                config.merge(cli_config);
            }
            config
        } else {
            cli.config.clone().unwrap_or_default()
        }
    } else {
        cli.config.clone().unwrap_or_default()
    };

    let inputs = collect_inputs(&cli, &source_manager)?;

    let mut has_syntax_errors = false;
    let mut formatted_inputs = Vec::with_capacity(inputs.len());
    for input in inputs {
        let source = input.source.clone();
        let mut parse = parse_source_file(source.clone());
        if parse.has_errors() {
            has_syntax_errors = true;
            for diagnostic in parse.take_diagnostics() {
                eprintln!(
                    "{}",
                    PrintDiagnostic::new(report_parse_diagnostic(source.clone(), diagnostic))
                );
            }
            continue;
        }

        formatted_inputs.push((input, format_syntax(&config, &parse.syntax())));
    }

    if has_syntax_errors {
        return Err(CliError::SyntaxErrors);
    }

    if cli.check {
        let mut mismatches = Vec::new();
        for (input, formatted) in &formatted_inputs {
            let source = &input.source;
            if source.as_str() != formatted {
                mismatches.push(source.uri());
            }
        }

        if mismatches.is_empty() {
            return Ok(());
        }

        return Err(CliError::CheckFailed(
            mismatches.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n"),
        ));
    }

    if cli.stdin {
        if let Some((_, formatted)) = formatted_inputs.into_iter().next() {
            let mut stdout = io::stdout().lock();
            write_formatted_stdout(&formatted, &mut stdout)?;
        }
        return Ok(());
    }

    for (input, formatted) in formatted_inputs {
        let source = &input.source;
        if source.as_str() == formatted {
            continue;
        }

        let path = output_path_for_input(&input)?;
        replace_file_atomically(path, formatted.as_bytes()).map_err(|err| CliError::WriteFile {
            path: path.display().to_string(),
            source: err,
        })?;
    }

    Ok(())
}

fn replace_file_atomically(path: &Path, contents: &[u8]) -> io::Result<()> {
    replace_file_atomically_with(path, |file| file.write_all(contents))
}

fn write_formatted_stdout(formatted: &str, writer: &mut impl Write) -> Result<(), CliError> {
    handle_stdout_result(writer.write_all(formatted.as_bytes()))?;
    handle_stdout_result(writer.flush())
}

fn handle_stdout_result(result: io::Result<()>) -> Result<(), CliError> {
    match result {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(err) => Err(CliError::WriteStdout(err)),
    }
}

fn replace_file_atomically_with(
    path: &Path,
    write_contents: impl FnOnce(&mut fs::File) -> io::Result<()>,
) -> io::Result<()> {
    let path = atomic_replace_target(path)?;
    let path = path.as_path();
    ensure_existing_target_is_writable(path)?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "cannot replace path without file name")
    })?;
    let file_name = file_name.to_string_lossy();
    let temp_path =
        parent.join(format!(".{file_name}.tmp-{}-{}", std::process::id(), unique_temp_suffix()));

    let mut temp_file = create_temp_file_for_atomic_replace(&temp_path, path)?;

    if let Err(err) = write_contents(&mut temp_file) {
        drop(temp_file);
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }

    if let Err(err) = temp_file.sync_all() {
        drop(temp_file);
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    drop(temp_file);
    if let Err(err) = replace_path_atomically(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }

    Ok(())
}

#[cfg(not(windows))]
fn replace_path_atomically(temp_path: &Path, path: &Path) -> io::Result<()> {
    fs::rename(temp_path, path)
}

#[cfg(windows)]
fn replace_path_atomically(temp_path: &Path, path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let temp_path = temp_path.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<_>>();
    let path = path.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(
            temp_path.as_ptr(),
            path.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn atomic_replace_target(path: &Path) -> io::Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => fs::canonicalize(path),
        Ok(_) => Ok(path.to_path_buf()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(path.to_path_buf()),
        Err(error) => Err(error),
    }
}

fn ensure_existing_target_is_writable(path: &Path) -> io::Result<()> {
    match fs::OpenOptions::new().write(true).open(path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn create_temp_file_for_atomic_replace(
    temp_path: &Path,
    target_path: &Path,
) -> io::Result<fs::File> {
    let existing_permissions = match fs::metadata(target_path) {
        Ok(metadata) => Some(metadata.permissions()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        options.mode(
            existing_permissions
                .as_ref()
                .map_or(0o600, |permissions| permissions.mode() & 0o777),
        );
    }

    let file = options.open(temp_path)?;
    if let Some(permissions) = existing_permissions
        && let Err(err) = fs::set_permissions(temp_path, permissions)
    {
        drop(file);
        let _ = fs::remove_file(temp_path);
        return Err(err);
    }

    Ok(file)
}

fn output_path_for_input(input: &Input) -> Result<&Path, CliError> {
    input
        .path
        .as_deref()
        .ok_or_else(|| CliError::InvalidSourceUri { path: input.source.uri().to_string() })
}

fn unique_temp_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

fn report_parse_diagnostic(source: Arc<SourceFile>, diagnostic: MietteDiagnostic) -> Report {
    Report::from(diagnostic).with_source_code(source)
}

fn collect_inputs(cli: &Cli, source_manager: &dyn SourceManager) -> Result<Vec<Input>, CliError> {
    let mut inputs = Vec::with_capacity(cli.paths.len());

    if cli.stdin {
        let path = cli.stdin_filepath.clone().unwrap_or_else(|| PathBuf::from("<stdin>"));
        let mut source = String::new();
        io::stdin().read_to_string(&mut source).map_err(CliError::ReadStdin)?;
        let source = source_manager.load(SourceLanguage::Masm, Uri::from(path.as_path()), source);
        inputs.push(Input { source, path: None });
        return Ok(inputs);
    }

    if cli.paths.is_empty() {
        return Err(CliError::MissingInput);
    }

    for path in cli.paths.iter() {
        if path.is_dir() {
            let walker = walkdir::WalkDir::new(path);
            for entry in walker {
                let entry = entry?;
                // We only care about files
                if !entry.file_type().is_file() {
                    continue;
                }
                // We only care about .masm files specifically
                if entry.path().extension().is_none_or(|ext| !ext.eq_ignore_ascii_case("masm")) {
                    continue;
                }
                let path = entry.path().to_path_buf();
                let source = source_manager.load_file(&path)?;
                inputs.push(Input { source, path: Some(path) });
            }
        } else {
            let source = source_manager.load_file(path)?;
            inputs.push(Input { source, path: Some(path.clone()) });
        }
    }

    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use std::{io::ErrorKind, path::Path};

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

    struct FailingWriter {
        kind: ErrorKind,
    }

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(self.kind, "injected stdout failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FlushFailingWriter {
        kind: ErrorKind,
        output: Vec<u8>,
    }

    impl Write for FlushFailingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(self.kind, "injected stdout flush failure"))
        }
    }

    #[test]
    fn stdout_writer_accepts_broken_pipe() {
        let mut writer = FailingWriter { kind: ErrorKind::BrokenPipe };

        write_formatted_stdout("begin\nend\n", &mut writer)
            .expect("broken pipe should be accepted for stdout");
    }

    #[test]
    fn stdout_writer_reports_non_broken_pipe_errors() {
        let mut writer = FailingWriter { kind: ErrorKind::WriteZero };

        let err = write_formatted_stdout("begin\nend\n", &mut writer)
            .expect_err("non-broken-pipe stdout errors should be reported");

        assert!(matches!(
            err,
            CliError::WriteStdout(source) if source.kind() == ErrorKind::WriteZero
        ));
    }

    #[test]
    fn stdout_writer_accepts_broken_pipe_on_flush() {
        let mut writer = FlushFailingWriter {
            kind: ErrorKind::BrokenPipe,
            output: Vec::new(),
        };

        write_formatted_stdout("begin\nend\n", &mut writer)
            .expect("broken pipe should be accepted during stdout flush");

        assert_eq!(writer.output, b"begin\nend\n");
    }

    #[test]
    fn stdout_writer_reports_non_broken_pipe_flush_errors() {
        let mut writer = FlushFailingWriter {
            kind: ErrorKind::WriteZero,
            output: Vec::new(),
        };

        let err = write_formatted_stdout("begin\nend\n", &mut writer)
            .expect_err("non-broken-pipe stdout flush errors should be reported");

        assert!(matches!(
            err,
            CliError::WriteStdout(source) if source.kind() == ErrorKind::WriteZero
        ));
        assert_eq!(writer.output, b"begin\nend\n");
    }

    #[test]
    fn stdout_writer_writes_formatted_source() {
        let mut output = Vec::new();

        write_formatted_stdout("begin\nend\n", &mut output)
            .expect("stdout writer should accept writable output");

        assert_eq!(output, b"begin\nend\n");
    }

    #[test]
    fn atomic_replacement_preserves_original_on_write_failure() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("source.masm");
        fs::write(&path, "begin\n    push.1\nend\n").expect("failed to write source");

        let error = replace_file_atomically_with(&path, |file| {
            file.write_all(b"partial replacement")?;
            Err(io::Error::new(ErrorKind::WriteZero, "injected write failure"))
        })
        .expect_err("expected injected write failure");

        assert_eq!(error.kind(), ErrorKind::WriteZero);
        let contents = fs::read_to_string(&path).expect("failed to read source after failure");
        assert_eq!(contents, "begin\n    push.1\nend\n");
    }

    #[test]
    fn atomic_replacement_overwrites_existing_file() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("source.masm");
        fs::write(&path, "begin\n    push.1\nend\n").expect("failed to write source");

        replace_file_atomically(&path, b"begin\n    push.2\nend\n")
            .expect("failed to replace existing source");

        let contents = fs::read_to_string(&path).expect("failed to read source after replace");
        assert_eq!(contents, "begin\n    push.2\nend\n");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replacement_rejects_read_only_existing_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("source.masm");
        fs::write(&path, "begin\n    push.1\nend\n").expect("failed to write source");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444))
            .expect("failed to make source read-only");

        let error = replace_file_atomically(&path, b"begin\n    push.2\nend\n")
            .expect_err("expected read-only source write to fail");

        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        let contents = fs::read_to_string(&path).expect("failed to read source after failure");
        assert_eq!(contents, "begin\n    push.1\nend\n");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("failed to restore source permissions");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replacement_follows_symlinked_source() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let target = dir.path().join("target.masm");
        let link = dir.path().join("source.masm");
        fs::write(&target, "begin\n    push.1\nend\n").expect("failed to write target");
        symlink(&target, &link).expect("failed to create source symlink");

        replace_file_atomically(&link, b"begin\n    push.2\nend\n")
            .expect("failed to replace symlinked source target");

        assert!(
            fs::symlink_metadata(&link)
                .expect("failed to stat source symlink")
                .file_type()
                .is_symlink()
        );
        let contents = fs::read_to_string(&target).expect("failed to read target after replace");
        assert_eq!(contents, "begin\n    push.2\nend\n");
    }

    #[test]
    fn output_path_uses_original_path_instead_of_source_uri_round_trip() {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let source = source_manager.load(
            SourceLanguage::Masm,
            Uri::new("file:///source-uri.masm"),
            "begin\nend\n".to_string(),
        );
        let path = PathBuf::from("original-path.masm");
        let input = Input { source, path: Some(path.clone()) };

        assert_eq!(output_path_for_input(&input).unwrap(), path.as_path());
    }
}
