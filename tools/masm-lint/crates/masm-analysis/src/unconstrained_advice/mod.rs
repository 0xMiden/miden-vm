//! Interprocedural analysis for unconstrained advice reaching U32 and non-zero sinks.

mod address;
mod call_transfer;
mod domain;
mod effect;
mod env;
mod expr;
mod grouping;
mod inter;
mod intrinsic_transfer;
mod local_transfer;
mod loop_transfer;
mod merkle;
mod nonzero;
mod provenance;
mod shared;
mod sink;
mod summary;
mod u32;
mod u32_domain;
mod walker;

pub use grouping::{AdviceRootCauseGroup, group_advice_diagnostics_by_origin};
pub use summary::AdviceDiagnostic;
use summary::AdviceDiagnosticsMap;

use crate::prepared::PreparedAnalysis;

/// Run advice-related diagnostics.
pub(super) fn analyze(prepared: &PreparedAnalysis) -> AdviceDiagnosticsMap {
    inter::infer_unconstrained_advice(prepared).1
}
