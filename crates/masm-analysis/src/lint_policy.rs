//! Lint-facing diagnostic policy helpers.

use std::collections::HashMap;

use masm_decompiler::SymbolPath;
use miden_debug_types::{SourceManager, SourceSpan};

use crate::unconstrained_advice::AdviceDiagnostic;

const ALLOW_UNCONSTRAINED_ADVICE_MARKER: &str = "masm-lint: allow unconstrained-advice";

/// Remove advice diagnostics suppressed by source allow markers.
pub(crate) fn filtered_advice_diagnostics(
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
