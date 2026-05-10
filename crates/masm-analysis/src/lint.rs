//! Public facade for the `masm-lint` CLI.
//!
//! Keep this surface narrow: it defines what the lint binary consumes from the
//! vendored analysis/decompiler crates.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

pub use masm_decompiler::{LibraryRoot, SymbolPath, Workspace};
use miden_debug_types::{DefaultSourceManager, SourceManager, SourceSpan};

use crate::{
    AnalysisSnapshot, SignatureMismatch, signature_mismatch_message,
    signature_mismatches_from_snapshot,
    unconstrained_advice::{
        AdviceDiagnostic, AdviceRootCauseGroup, group_advice_diagnostics_by_origin,
    },
};

const ALLOW_UNCONSTRAINED_ADVICE_MARKER: &str = "masm-lint: allow unconstrained-advice";

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

/// Analyze a workspace and return sorted lint diagnostics.
pub fn diagnostics_from_workspace(
    workspace: &Workspace,
    sources: Arc<DefaultSourceManager>,
    include_signature_mismatches: bool,
    group_by_origin: bool,
) -> Vec<LintDiagnostic> {
    let snapshot = AnalysisSnapshot::from_workspace(workspace);
    let advice_diagnostics =
        filtered_advice_diagnostics(&snapshot.advice_diagnostics, sources.as_ref());
    let mut diagnostics = Vec::new();

    if include_signature_mismatches {
        for program in workspace.modules() {
            let module = program.module();
            let mismatches =
                signature_mismatches_from_snapshot(module, sources.clone(), &snapshot.signatures);
            diagnostics.extend(mismatches.iter().filter_map(signature_mismatch_to_lint));
        }
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

fn filtered_advice_diagnostics(
    diagnostics: &HashMap<SymbolPath, Vec<AdviceDiagnostic>>,
    sources: &dyn SourceManager,
) -> HashMap<SymbolPath, Vec<AdviceDiagnostic>> {
    diagnostics
        .iter()
        .filter_map(|(procedure, advice_diags)| {
            let retained = advice_diags
                .iter()
                .filter_map(|diag| filter_advice_diagnostic(diag, sources))
                .collect::<Vec<_>>();
            (!retained.is_empty()).then(|| (procedure.clone(), retained))
        })
        .collect()
}

fn filter_advice_diagnostic(
    diag: &AdviceDiagnostic,
    sources: &dyn SourceManager,
) -> Option<AdviceDiagnostic> {
    if line_has_allow_marker(diag.span, sources) {
        return None;
    }

    let origins = diag
        .origins
        .iter()
        .copied()
        .filter(|&origin_span| !line_has_allow_marker(origin_span, sources))
        .collect::<Vec<_>>();

    if !diag.origins.is_empty() && origins.is_empty() {
        return None;
    }

    let mut diag = diag.clone();
    diag.origins = origins;
    Some(diag)
}

fn line_has_allow_marker(span: SourceSpan, sources: &dyn SourceManager) -> bool {
    let Ok(file_line_col) = sources.file_line_col(span) else {
        return false;
    };
    let Ok(source_file) = sources.get(span.source_id()) else {
        return false;
    };
    let Some(line_idx) = file_line_col.line.to_usize().checked_sub(1) else {
        return false;
    };

    let first_line = line_idx.saturating_sub(1);
    source_file
        .as_str()
        .lines()
        .skip(first_line)
        .take(line_idx - first_line + 1)
        .any(|line| line.contains(ALLOW_UNCONSTRAINED_ADVICE_MARKER))
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
