use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use midenc_dialect_hir::analyses::{AdviceTaintAnalysis, AdviceTaintOriginKind};
use midenc_frontend_masm::SkippedProcedure;
use midenc_hir::{
    SourceSpan,
    diagnostics::{SourceManager, Uri},
};

pub fn findings(
    analysis: &AdviceTaintAnalysis,
    sources: &dyn SourceManager,
    root: &Path,
    verbose: bool,
) -> usize {
    let sinks = analysis.diagnostic_findings(sources);
    let count =
        sinks.len() + analysis.exit_findings().len() + analysis.external_call_findings().len();
    if verbose {
        for report in analysis.reports(sources) {
            eprintln!("{report:?}");
        }
        return count;
    }

    for finding in sinks {
        eprintln!(
            "{}: {} [sink {}; origin {}]",
            location(sources, finding.sink_span, root),
            finding.diagnostic(sources).message(),
            finding.sink,
            location(sources, finding.advice_span, root),
        );
    }
    for finding in analysis.external_call_findings() {
        eprintln!(
            "{}: {} [origin {}]",
            location(sources, finding.call_span, root),
            finding.diagnostic(sources).message(),
            location(sources, finding.advice_span, root),
        );
    }

    let mut returns =
        BTreeMap::<(String, String, &str), (BTreeSet<usize>, BTreeSet<String>)>::new();
    for finding in analysis.exit_findings() {
        // Lifted function/return operations can have synthetic spans. Use the origin's
        // file to keep same-named functions in different modules in separate groups.
        let function_location = source_location(sources, finding.function_span, root)
            .or_else(|| source_location(sources, finding.return_span, root))
            .unwrap_or_else(|| {
                sources
                    .file_line_col(finding.advice_span)
                    .map(|location| relative_path(&location.uri, root))
                    .unwrap_or_else(|_| "<unknown>".to_string())
            });
        let subject = match finding.origin.kind {
            AdviceTaintOriginKind::Advice => "unconstrained advice",
            AdviceTaintOriginKind::ExternalCall => "unconstrained external call results",
        };
        let (results, origins) = returns
            .entry((function_location, finding.function.to_string(), subject))
            .or_default();
        results.insert(finding.result_index);
        origins.insert(location(sources, finding.advice_span, root));
    }
    for ((location, function, subject), (results, origins)) in returns {
        let results = results.iter().map(usize::to_string).collect::<Vec<_>>().join(", ");
        let origins = origins.into_iter().collect::<Vec<_>>().join(", ");
        eprintln!(
            "{location}: return advisory: '{function}' returns {subject} in results [{results}] [origins {origins}]"
        );
    }
    count
}

pub fn coverage(skipped: &[SkippedProcedure]) {
    if skipped.is_empty() {
        eprintln!("Coverage full: no procedures skipped");
        return;
    }
    let mut causes = BTreeMap::<&str, usize>::new();
    let mut dependent = 0;
    for procedure in skipped {
        let reason = procedure.reason.as_str();
        if reason.starts_with("depends on skipped procedure") {
            dependent += 1;
            continue;
        }
        let cause = if reason.starts_with("declared signature")
            || reason.starts_with("if branches")
            || reason.starts_with("while body")
        {
            "stack/signature inference"
        } else if reason.contains("lint analysis limit")
            || reason.contains("lint analysis signature limit")
        {
            "analysis size limits"
        } else if reason.starts_with("invalid ") {
            "lifter validation"
        } else if reason.contains("not supported") || reason.contains("unsupported") {
            "unsupported constructs"
        } else if reason.contains("cycle") {
            "call graph cycles"
        } else {
            "other"
        };
        *causes.entry(cause).or_default() += 1;
    }
    eprintln!(
        "Coverage partial: {} procedures skipped ({} root failures, {dependent} dependent callers)",
        skipped.len(),
        skipped.len() - dependent,
    );
    let causes = causes
        .iter()
        .map(|(cause, count)| format!("{cause}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    eprintln!("Skipped root causes: {causes}");
}

fn location(sources: &dyn SourceManager, span: SourceSpan, root: &Path) -> String {
    source_location(sources, span, root).unwrap_or_else(|| "<unknown>".to_string())
}

fn source_location(sources: &dyn SourceManager, span: SourceSpan, root: &Path) -> Option<String> {
    let location = sources.file_line_col(span).ok()?;
    let path = relative_path(&location.uri, root);
    Some(format!("{path}:{}:{}", location.line, location.column))
}

fn relative_path(uri: &Uri, root: &Path) -> String {
    let Some(path) = uri.to_path() else {
        return uri.to_string();
    };
    path.strip_prefix(root).unwrap_or(&path).display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_uris_and_plain_paths_are_relative_to_the_manifest() {
        for uri in ["file:///project/asm/mod.masm", "/project/asm/mod.masm"] {
            assert_eq!(relative_path(&Uri::from(uri), Path::new("/project/asm")), "mod.masm");
        }
        assert_eq!(
            relative_path(&Uri::from("https://example.com/mod.masm"), Path::new("/project/asm")),
            "https://example.com/mod.masm"
        );
    }
}
