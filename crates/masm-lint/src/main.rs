//! CLI linter for Miden Assembly (MASM).

mod render;

use std::{collections::HashSet, path::PathBuf, sync::Arc};

use clap::Parser;
use masm_analysis::lint::{
    LibraryRoot, LintPathAnalysisInput, UnresolvedDependencyReport, analyze_paths,
};
use miden_debug_types::DefaultSourceManager;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "masm-lint",
    version,
    about = "Static analysis linter for Miden Assembly (MASM) files"
)]
struct Cli {
    /// MASM source files or directories to lint
    #[arg(required = true, value_name = "INPUT")]
    inputs: Vec<PathBuf>,

    /// Register an additional library root: `<namespace>=<path>`
    #[arg(long = "library", value_parser = parse_library_spec)]
    libraries: Vec<LibraryRoot>,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

    /// Group advice warnings by root-cause origin instead of listing each sink separately
    #[arg(long)]
    group_by_origin: bool,
}

fn main() {
    let cli = Cli::parse();

    if cli.no_color {
        yansi::disable();
    }

    std::process::exit(run(cli));
}

// ── Driver ────────────────────────────────────────────────────────────────────

/// Run the linter. Returns an exit code: 0 = clean, 1 = warnings, 2 = hard error.
fn run(cli: Cli) -> i32 {
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("masm-lint: cannot determine working directory: {e}");
            return 2;
        },
    };

    // Share one source manager with the analysis facade so rendered spans
    // resolve across all loaded modules.
    let sources: Arc<DefaultSourceManager> = Arc::new(DefaultSourceManager::default());
    let report = match analyze_paths(LintPathAnalysisInput {
        inputs: cli.inputs,
        libraries: cli.libraries,
        cwd,
        sources: sources.clone(),
        group_by_origin: cli.group_by_origin,
    }) {
        Ok(Some(report)) => report,
        Ok(None) => {
            eprintln!("masm-lint: no .masm files found in the given inputs");
            return 0;
        },
        Err(error) => {
            eprintln!("masm-lint: {error}");
            return 2;
        },
    };

    for error in &report.load_errors {
        eprintln!("masm-lint: failed to load {}: {}", error.path.display(), error.message);
    }

    if let Some(unresolved) = &report.unresolved_dependencies {
        emit_unresolved_dependency_errors(unresolved);
    }

    // Render.
    for diag in &report.diagnostics {
        render::render_diagnostic(diag, sources.as_ref());
    }

    // Summary to stderr (cargo/clippy style).
    emit_summary(report.warning_count(), report.error_count())
}

/// Emit a cargo/clippy-style summary and return the exit code.
fn emit_summary(warning_count: usize, error_count: usize) -> i32 {
    use yansi::Paint as _;

    match (error_count, warning_count) {
        (0, 0) => {
            eprintln!("masm-lint: no issues found");
            0
        },
        (0, w) => {
            eprintln!("{}: masm-lint generated {w} warning(s)", "warning".yellow().bold(),);
            1
        },
        (e, 0) => {
            eprintln!("{}: masm-lint found {e} error(s)", "error".red().bold(),);
            2
        },
        (e, w) => {
            eprintln!(
                "{}: masm-lint found {e} error(s); {w} warning(s) emitted",
                "error".red().bold(),
            );
            2
        },
    }
}

// ── Unresolved dependencies ───────────────────────────────────────────────────

/// Emit errors about modules that could not be resolved, with guidance on
/// how to configure the missing library roots.
fn emit_unresolved_dependency_errors(unresolved: &UnresolvedDependencyReport) {
    use yansi::Paint as _;

    let rendered_modules = unresolved
        .modules
        .iter()
        .map(|m| m.path.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    eprintln!(
        "{}: unable to resolve {} referenced module(s): {rendered_modules}",
        "error".red().bold(),
        unresolved.modules.len(),
    );

    let rendered_roots = unresolved
        .configured_roots
        .iter()
        .map(format_library_root)
        .collect::<Vec<_>>()
        .join(", ");
    eprintln!("  {} configured library roots: {rendered_roots}", "=".cyan().bold(),);
    eprintln!(
        "  {} signature mismatch checks are skipped when dependencies are unresolved",
        "=".cyan().bold(),
    );

    let mut seen_configured: HashSet<String> = HashSet::new();
    let mut seen_unconfigured: HashSet<String> = HashSet::new();
    for module in &unresolved.modules {
        if let Some(ns) = module.configured_namespace.as_deref() {
            if seen_configured.insert(ns.to_string()) {
                eprintln!(
                    "  {} namespace `{ns}` is configured, but some referenced modules were not found under its roots",
                    "=".cyan().bold(),
                );
            }
        } else if seen_unconfigured.insert(module.path.clone()) {
            eprintln!(
                "  {} add `--library <namespace>=<path>` for module `{}`",
                "help".cyan().bold(),
                module.path,
            );
        }
    }
    eprintln!();
}

/// Render a [`LibraryRoot`] for human-readable output.
fn format_library_root(root: &LibraryRoot) -> String {
    if root.namespace.is_empty() {
        format!("<default>={}", root.path.display())
    } else {
        format!("{}={}", root.namespace, root.path.display())
    }
}

// ── Argument parsing ──────────────────────────────────────────────────────────

/// Parse a `<namespace>=<path>` library spec from the command line.
fn parse_library_spec(spec: &str) -> Result<LibraryRoot, String> {
    let (ns, path) = spec
        .split_once('=')
        .ok_or_else(|| "library spec must be <namespace>=<path>".to_string())?;
    if ns.is_empty() {
        return Err("library namespace cannot be empty".to_string());
    }
    if path.is_empty() {
        return Err("library path cannot be empty".to_string());
    }
    let root = LibraryRoot::new(ns, PathBuf::from(path));
    if root.namespace == "miden::core" {
        Ok(LibraryRoot::trusted_stdlib(root.namespace, root.path))
    } else {
        Ok(root)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
