//! Public facade for the `masm-lint` CLI.
//!
//! Keep this surface narrow: it defines what the lint binary consumes from the
//! vendored analysis/decompiler crates.

pub use masm_decompiler::{LibraryRoot, SymbolPath, Workspace};

pub use crate::{
    AnalysisSnapshot, SignatureMismatch, signature_mismatch_message,
    signature_mismatches_from_snapshot,
    unconstrained_advice::{
        AdviceDiagnostic, AdviceRootCauseGroup, group_advice_diagnostics_by_origin,
    },
};
