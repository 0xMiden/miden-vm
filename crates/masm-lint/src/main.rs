//! CLI linter for Miden Assembly (MASM).

mod render;

use std::{
    collections::{BTreeSet, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::Parser;
use masm_analysis::lint::{LibraryRoot, SymbolPath, Workspace, diagnostics_from_workspace};
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

    // Validate library root paths before doing anything else.
    for root in &cli.libraries {
        if !root.path.exists() {
            eprintln!(
                "masm-lint: library root path does not exist: {} (for namespace `{}`)",
                root.path.display(),
                root.namespace
            );
            return 2;
        }
    }

    // Collect .masm files from all inputs, canonicalized and deduplicated.
    let mut masm_files: BTreeSet<PathBuf> = BTreeSet::new();
    for input in &cli.inputs {
        let abs = normalize_cli_path(input, &cwd);
        if abs.is_dir() {
            collect_masm_files(&abs, &mut masm_files);
        } else if abs.is_file() {
            masm_files.insert(abs);
        } else {
            eprintln!("masm-lint: input path does not exist: {}", input.display());
            return 2;
        }
    }

    if masm_files.is_empty() {
        eprintln!("masm-lint: no .masm files found in the given inputs");
        return 0;
    }

    // Build library roots: user-supplied + CWD as the default root.
    let mut roots = normalize_library_roots(&cli.libraries, &cwd);
    roots.push(LibraryRoot::new("", normalize_cli_path(&cwd, &cwd)));

    // Build workspace using a shared source manager so spans resolve correctly
    // across modules.
    let sources: Arc<DefaultSourceManager> = Arc::new(DefaultSourceManager::default());
    let mut workspace = Workspace::with_source_manager(roots, sources.clone());
    let mut error_count: usize = 0;

    for file in &masm_files {
        if let Err(e) = workspace.load_entry(file) {
            eprintln!("masm-lint: failed to load {}: {e}", file.display());
            error_count += 1;
        }
    }

    workspace.load_dependencies();
    let unresolved = workspace.unresolved_module_paths();

    let include_signature_mismatches = unresolved.is_empty();
    if !include_signature_mismatches {
        error_count += unresolved.len();
        emit_unresolved_dependency_errors(&unresolved, &workspace);
    }

    let diagnostics = diagnostics_from_workspace(
        &workspace,
        sources.clone(),
        include_signature_mismatches,
        cli.group_by_origin,
    );

    let warning_count = diagnostics.len();

    // Render.
    for diag in &diagnostics {
        render::render_diagnostic(diag, sources.as_ref());
    }

    // Summary to stderr (cargo/clippy style).
    emit_summary(warning_count, error_count)
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
fn emit_unresolved_dependency_errors(unresolved: &[SymbolPath], workspace: &Workspace) {
    use yansi::Paint as _;

    let rendered_modules =
        unresolved.iter().map(|m| m.as_str().to_string()).collect::<Vec<_>>().join(", ");
    eprintln!(
        "{}: unable to resolve {} referenced module(s): {rendered_modules}",
        "error".red().bold(),
        unresolved.len(),
    );

    let rendered_roots =
        workspace.roots().iter().map(format_library_root).collect::<Vec<_>>().join(", ");
    eprintln!("  {} configured library roots: {rendered_roots}", "=".cyan().bold(),);
    eprintln!(
        "  {} signature mismatch checks are skipped when dependencies are unresolved",
        "=".cyan().bold(),
    );

    let mut seen_configured: HashSet<String> = HashSet::new();
    let mut seen_unconfigured: HashSet<String> = HashSet::new();
    for module in unresolved {
        if let Some(ns) = configured_namespace_for_module(module, workspace.roots()) {
            if seen_configured.insert(ns.to_string()) {
                eprintln!(
                    "  {} namespace `{ns}` is configured, but some referenced modules were not found under its roots",
                    "=".cyan().bold(),
                );
            }
        } else if seen_unconfigured.insert(module.as_str().to_string()) {
            eprintln!(
                "  {} add `--library <namespace>=<path>` for module `{}`",
                "help".cyan().bold(),
                module.as_str(),
            );
        }
    }
    eprintln!();
}

/// Return the longest configured namespace that matches `module`.
fn configured_namespace_for_module<'a>(
    module: &SymbolPath,
    roots: &'a [LibraryRoot],
) -> Option<&'a str> {
    roots
        .iter()
        .filter(|root| !root.namespace.is_empty())
        .filter(|root| root.matches_module_path(module.as_str()))
        .map(|root| root.namespace.as_str())
        .max_by_key(|ns| ns.len())
}

// ── Filesystem helpers ────────────────────────────────────────────────────────

/// Recursively collect `.masm` files under `dir`.
fn collect_masm_files(dir: &Path, out: &mut BTreeSet<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_masm_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("masm") {
            if let Ok(canonical) = std::fs::canonicalize(&path) {
                out.insert(canonical);
            } else {
                out.insert(path);
            }
        }
    }
}

/// Normalize a CLI path: resolve to absolute and canonicalize if possible.
fn normalize_cli_path(path: &Path, cwd: &Path) -> PathBuf {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    std::fs::canonicalize(&abs).unwrap_or(abs)
}

/// Normalize user-supplied library roots to absolute, canonicalized paths.
fn normalize_library_roots(roots: &[LibraryRoot], cwd: &Path) -> Vec<LibraryRoot> {
    roots
        .iter()
        .map(|root| {
            let path = normalize_cli_path(&root.path, cwd);
            if root.trusted_stdlib {
                LibraryRoot::trusted_stdlib(root.namespace.as_str(), path)
            } else {
                LibraryRoot::new(root.namespace.as_str(), path)
            }
        })
        .collect()
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
