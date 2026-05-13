//! Public facade for the `masm-lint` CLI.
//!
//! Keep this surface narrow: it defines what the lint binary consumes from the
//! vendored analysis/decompiler crates.

use std::{collections::HashSet, path::PathBuf, sync::Arc};

pub use masm_decompiler::LibraryRoot;
use masm_decompiler::{SymbolPath, Workspace};
use miden_debug_types::{DefaultSourceManager, SourceManager, SourceSpan};

use crate::{
    AnalysisSnapshot, SignatureMismatch,
    lint_policy::filtered_advice_diagnostics,
    signature_mismatch_message,
    unconstrained_advice::{
        AdviceDiagnostic, AdviceRootCauseGroup, group_advice_diagnostics_by_origin,
    },
};

/// A unified lint diagnostic ready for rendering.
#[derive(Debug)]
pub struct LintDiagnostic {
    /// Human-readable warning message.
    pub message: String,
    /// Primary source span.
    pub span: SourceSpan,
    /// Additional explanatory note rendered after the snippets.
    pub note: String,
    /// Related source locations, such as advice origins.
    pub related: Vec<RelatedSpan>,
}

/// A related source location with an explanatory message.
#[derive(Debug)]
pub struct RelatedSpan {
    /// Source span of the related location.
    pub span: SourceSpan,
    /// Human-readable explanation.
    pub message: String,
}

/// Inputs needed to run the lint analysis pipeline.
pub struct LintAnalysisInput {
    /// Entry MASM files to load into the workspace.
    pub entry_files: Vec<PathBuf>,
    /// Library roots used to resolve imported modules.
    pub roots: Vec<LibraryRoot>,
    /// Source manager shared with diagnostic rendering.
    pub sources: Arc<DefaultSourceManager>,
    /// Group advice warnings by origin instead of emitting sink-level warnings.
    pub group_by_origin: bool,
}

/// Results of running the lint analysis pipeline.
pub struct LintAnalysisReport {
    /// Lint warnings ready for rendering.
    pub diagnostics: Vec<LintDiagnostic>,
    /// Entry files that failed to load.
    pub load_errors: Vec<LintLoadError>,
    /// Referenced modules that could not be resolved.
    pub unresolved_dependencies: Option<UnresolvedDependencyReport>,
}

impl LintAnalysisReport {
    /// Number of warning diagnostics in this report.
    pub fn warning_count(&self) -> usize {
        self.diagnostics.len()
    }

    /// Number of hard errors in this report.
    pub fn error_count(&self) -> usize {
        self.load_errors.len()
            + self.unresolved_dependencies.as_ref().map_or(0, |report| report.modules.len())
    }
}

/// Failure to load an entry MASM file.
pub struct LintLoadError {
    /// Entry file path.
    pub path: PathBuf,
    /// Loader error rendered without source coloring.
    pub message: String,
}

/// Unresolved dependency information for CLI diagnostics.
pub struct UnresolvedDependencyReport {
    /// Unresolved module paths.
    pub modules: Vec<UnresolvedModule>,
    /// Library roots configured for the analysis run.
    pub configured_roots: Vec<LibraryRoot>,
}

/// A referenced module that could not be resolved.
pub struct UnresolvedModule {
    /// Fully-qualified module path.
    pub path: String,
    /// Configured namespace that should contain this module, if any.
    pub configured_namespace: Option<String>,
}

/// Load the requested entry files, resolve dependencies, and return lint diagnostics.
pub fn analyze_entries(input: LintAnalysisInput) -> LintAnalysisReport {
    let mut workspace = Workspace::with_source_manager(input.roots, input.sources.clone());
    let mut load_errors = Vec::new();

    for file in &input.entry_files {
        if let Err(e) = workspace.load_entry(file) {
            load_errors.push(LintLoadError {
                path: file.clone(),
                message: e.to_string(),
            });
        }
    }

    workspace.load_dependencies();
    let unresolved_paths = workspace.unresolved_module_paths();
    let include_signature_mismatches = unresolved_paths.is_empty();
    let unresolved_dependencies = unresolved_dependency_report(&workspace, unresolved_paths);
    let diagnostics = diagnostics_from_workspace(
        &workspace,
        input.sources,
        include_signature_mismatches,
        input.group_by_origin,
    );

    LintAnalysisReport {
        diagnostics,
        load_errors,
        unresolved_dependencies,
    }
}

/// Analyze a workspace and return sorted lint diagnostics.
fn diagnostics_from_workspace(
    workspace: &Workspace,
    sources: Arc<DefaultSourceManager>,
    include_signature_mismatches: bool,
    group_by_origin: bool,
) -> Vec<LintDiagnostic> {
    let snapshot =
        AnalysisSnapshot::from_workspace(workspace, sources.clone(), include_signature_mismatches);
    let advice_diagnostics =
        filtered_advice_diagnostics(&snapshot.advice_diagnostics, sources.as_ref());
    let mut diagnostics = Vec::new();

    if include_signature_mismatches {
        diagnostics
            .extend(snapshot.signature_mismatches.iter().filter_map(signature_mismatch_to_lint));
    }

    if group_by_origin {
        diagnostics.extend(
            group_advice_diagnostics_by_origin(&advice_diagnostics)
                .iter()
                .map(root_cause_group_to_lint),
        );
    } else {
        diagnostics.extend(
            advice_diagnostics
                .values()
                .flat_map(|advice_diags| advice_diags.iter().map(advice_diagnostic_to_lint)),
        );
    }

    sort_diagnostics(&mut diagnostics, sources.as_ref());
    diagnostics
}

fn unresolved_dependency_report(
    workspace: &Workspace,
    unresolved_paths: Vec<SymbolPath>,
) -> Option<UnresolvedDependencyReport> {
    if unresolved_paths.is_empty() {
        return None;
    }

    let modules = unresolved_paths
        .into_iter()
        .map(|path| UnresolvedModule {
            configured_namespace: configured_namespace_for_module(&path, workspace.roots())
                .map(str::to_string),
            path: path.as_str().to_string(),
        })
        .collect();

    Some(UnresolvedDependencyReport {
        modules,
        configured_roots: workspace.roots().to_vec(),
    })
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

/// Convert a [`SignatureMismatch`] into a [`LintDiagnostic`].
fn signature_mismatch_to_lint(m: &SignatureMismatch) -> Option<LintDiagnostic> {
    let message = signature_mismatch_message(m);
    if message.is_empty() {
        return None;
    }
    let procedure = SymbolPath::new(&m.proc_name);
    Some(LintDiagnostic {
        message,
        span: m.span,
        note: format!("in procedure `{}`", procedure.as_str()),
        related: Vec::new(),
    })
}

/// Convert an [`AdviceDiagnostic`] into a [`LintDiagnostic`], attaching
/// advice origin spans as related locations.
fn advice_diagnostic_to_lint(ad: &AdviceDiagnostic) -> LintDiagnostic {
    let related = ad
        .origins
        .iter()
        .map(|&origin_span| RelatedSpan {
            span: origin_span,
            message: "unconstrained advice introduced here".to_string(),
        })
        .collect();

    LintDiagnostic {
        message: ad.message.clone(),
        span: ad.span,
        note: format!("in procedure `{}`", ad.procedure.as_str()),
        related,
    }
}

/// Convert a root-cause group into a grouped [`LintDiagnostic`].
fn root_cause_group_to_lint(group: &AdviceRootCauseGroup) -> LintDiagnostic {
    let related = group
        .diagnostics
        .iter()
        .map(|diag| RelatedSpan {
            span: diag.span,
            message: format!("{} (in procedure `{}`)", diag.message, diag.procedure.as_str()),
        })
        .collect();

    LintDiagnostic {
        message: group.summary_message(),
        span: group.origin,
        note: grouped_procedure_note(&group.diagnostics),
        related,
    }
}

fn grouped_procedure_note(diagnostics: &[AdviceDiagnostic]) -> String {
    let mut procedures = diagnostics
        .iter()
        .map(|diag| diag.procedure.as_str().to_string())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    procedures.sort();

    match procedures.as_slice() {
        [] => "root cause group has no downstream procedures".to_string(),
        [procedure] => format!("root cause fan-out stays within procedure `{procedure}`"),
        [first, second] => {
            format!("root cause fan-out reaches procedures `{first}` and `{second}`")
        },
        [first, second, rest @ ..] => format!(
            "root cause fan-out reaches procedures `{first}`, `{second}`, and {} more",
            rest.len()
        ),
    }
}

/// Sort diagnostics by (uri, line, col) of their primary span.
fn sort_diagnostics(diagnostics: &mut [LintDiagnostic], sources: &dyn SourceManager) {
    diagnostics.sort_by(|a, b| {
        let key_a = sort_key(a.span, sources);
        let key_b = sort_key(b.span, sources);
        key_a.cmp(&key_b)
    });
}

/// Produce a sortable key `(file_uri, line, col)` for a span.
fn sort_key(span: SourceSpan, sources: &dyn SourceManager) -> (String, usize, usize) {
    sources
        .file_line_col(span)
        .ok()
        .map(|flc| (flc.uri.as_str().to_owned(), flc.line.to_usize(), flc.column.to_usize()))
        .unwrap_or_default()
}
