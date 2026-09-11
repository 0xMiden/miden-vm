//! Root-cause-oriented grouping helpers for unconstrained-advice diagnostics.

use std::collections::HashMap;

use miden_debug_types::SourceSpan;

use super::AdviceDiagnostic;
use crate::SymbolPath;

/// One origin-centric view over downstream unconstrained-advice diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdviceRootCauseGroup {
    /// The origin span where unconstrained advice entered the program.
    pub origin: SourceSpan,
    /// All sink diagnostics that are reachable from `origin`.
    pub diagnostics: Vec<AdviceDiagnostic>,
}

impl AdviceRootCauseGroup {
    /// Return the number of downstream sinks reachable from this origin.
    pub(crate) fn sink_count(&self) -> usize {
        self.diagnostics.len()
    }

    /// Return a human-readable summary line for origin-centric UIs.
    pub fn summary_message(&self) -> String {
        let sink_count = self.sink_count();
        format!("unconstrained advice introduced here reaches {sink_count} downstream sink(s)")
    }
}

/// Group flat advice diagnostics by each distinct origin span they mention.
///
/// Diagnostics with multiple possible origins appear once in every matching
/// root-cause group. Diagnostics without resolved origins are skipped because
/// there is no root-cause location to anchor them to in grouped UIs.
pub fn group_advice_diagnostics_by_origin(
    diagnostics: &HashMap<SymbolPath, Vec<AdviceDiagnostic>>,
) -> Vec<AdviceRootCauseGroup> {
    let mut grouped = HashMap::<SourceSpan, Vec<AdviceDiagnostic>>::new();

    for diagnostic in diagnostics.values().flat_map(|proc_diags| proc_diags.iter()) {
        let mut origins = diagnostic.origins.clone();
        origins.sort_by_key(|span| source_span_sort_key(*span));
        origins.dedup();

        for origin in origins {
            grouped.entry(origin).or_default().push(diagnostic.clone());
        }
    }

    let mut groups = grouped
        .into_iter()
        .map(|(origin, mut diagnostics)| {
            diagnostics.sort_by(|left, right| {
                left.procedure
                    .as_str()
                    .cmp(right.procedure.as_str())
                    .then_with(|| {
                        source_span_sort_key(left.span).cmp(&source_span_sort_key(right.span))
                    })
                    .then_with(|| left.message.cmp(&right.message))
            });
            AdviceRootCauseGroup { origin, diagnostics }
        })
        .collect::<Vec<_>>();

    groups.sort_by(|left, right| {
        right.sink_count().cmp(&left.sink_count()).then_with(|| {
            source_span_sort_key(left.origin).cmp(&source_span_sort_key(right.origin))
        })
    });
    groups
}

fn source_span_sort_key(span: SourceSpan) -> (u32, u32, u32) {
    (span.source_id().to_u32(), span.start().to_u32(), span.end().to_u32())
}
