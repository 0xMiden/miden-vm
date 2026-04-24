//! Summary and diagnostic types for unconstrained-advice analysis.

use std::collections::HashMap;

use miden_debug_types::SourceSpan;

use super::{domain::AdviceFact, u32_domain::U32Validity};
use crate::SymbolPath;

/// Summary of unconstrained-advice flow for one procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdviceSummary {
    /// Per-output unconstrained-advice provenance.
    pub outputs: Vec<AdviceFact>,
    /// Per-output `u32` validity.
    pub(crate) u32_outputs: Vec<U32Validity>,
    /// Exact input-position forwarding for each output, when known.
    pub(crate) forwarded_inputs: Vec<Option<usize>>,
    /// Per-input `u32` postconditions guaranteed after the call returns.
    pub(crate) u32_inputs: Vec<U32Validity>,
    /// Whether this summary is opaque.
    pub unknown: bool,
}

impl AdviceSummary {
    /// Create a known summary.
    pub fn new(outputs: Vec<AdviceFact>) -> Self {
        let output_count = outputs.len();
        Self {
            outputs,
            u32_outputs: vec![U32Validity::Unknown; output_count],
            forwarded_inputs: vec![None; output_count],
            u32_inputs: Vec::new(),
            unknown: false,
        }
    }

    /// Create a known summary with explicit exact-forwarding metadata.
    pub(crate) fn with_forwarding(
        outputs: Vec<AdviceFact>,
        u32_outputs: Vec<U32Validity>,
        forwarded_inputs: Vec<Option<usize>>,
        u32_inputs: Vec<U32Validity>,
    ) -> Self {
        debug_assert_eq!(outputs.len(), u32_outputs.len());
        debug_assert_eq!(outputs.len(), forwarded_inputs.len());
        Self {
            outputs,
            u32_outputs,
            forwarded_inputs,
            u32_inputs,
            unknown: false,
        }
    }

    /// Create an opaque summary with explicit output arity.
    pub fn unknown_with_arity(outputs: usize) -> Self {
        Self {
            outputs: vec![AdviceFact::bottom(); outputs],
            u32_outputs: vec![U32Validity::Unknown; outputs],
            forwarded_inputs: vec![None; outputs],
            u32_inputs: Vec::new(),
            unknown: true,
        }
    }

    /// Return an opaque summary without arity information.
    pub fn unknown() -> Self {
        Self::unknown_with_arity(0)
    }

    /// Return true if the summary is opaque.
    pub fn is_unknown(&self) -> bool {
        self.unknown
    }

    /// Return the per-output `u32` validity.
    pub(crate) fn u32_outputs(&self) -> &[U32Validity] {
        &self.u32_outputs
    }

    /// Return the exact-forwarding metadata for each output.
    pub(crate) fn forwarded_inputs(&self) -> &[Option<usize>] {
        &self.forwarded_inputs
    }

    /// Return the per-input `u32` postconditions.
    pub(crate) fn u32_inputs(&self) -> &[U32Validity] {
        &self.u32_inputs
    }

    /// Return the number of summarized outputs.
    pub(crate) fn output_count(&self) -> usize {
        self.outputs.len()
    }
}

impl Default for AdviceSummary {
    fn default() -> Self {
        Self::unknown()
    }
}

/// Kind of sink that triggered an advice warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdviceSinkKind {
    /// A U32-producing or U32-requiring expression.
    U32Expression,
    /// A U32 intrinsic statement.
    U32Intrinsic,
    /// An operand to `div`/`inv` that must be proven non-zero.
    NonZeroOperand,
    /// A call argument whose callee expects `U32`.
    CallArgument,
    /// A memory address operand (mem_load, mem_store, adv_pipe, mem_stream).
    MemoryAddress,
    /// A Merkle tree root operand (mtree_get, mtree_set, mtree_verify).
    MerkleRoot,
}

/// Refinement for call-argument diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallArgumentRequirement {
    /// The callee expects a `U32` argument.
    U32,
    /// The callee expects a proven non-zero argument.
    NonZero,
}

/// Diagnostic emitted by unconstrained-advice analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdviceDiagnostic {
    /// Procedure in which the diagnostic was emitted.
    pub procedure: SymbolPath,
    /// Source span associated with the sink.
    pub span: SourceSpan,
    /// Concrete advice source spans that may reach this sink.
    pub origins: Vec<SourceSpan>,
    /// Human-readable message.
    pub message: String,
    /// Optional callee for call-argument diagnostics.
    pub callee: Option<SymbolPath>,
    /// Optional argument index for call-argument diagnostics.
    pub arg_index: Option<usize>,
    /// Optional refinement for call-argument diagnostics.
    pub call_requirement: Option<CallArgumentRequirement>,
    /// Kind of sink that triggered the diagnostic.
    pub sink: AdviceSinkKind,
}

impl AdviceDiagnostic {
    /// Create a new diagnostic with the given sink kind and message.
    pub fn new(
        procedure: SymbolPath,
        span: SourceSpan,
        sink: AdviceSinkKind,
        message: impl Into<String>,
    ) -> Self {
        Self {
            procedure,
            span,
            origins: Vec::new(),
            message: message.into(),
            callee: None,
            arg_index: None,
            call_requirement: None,
            sink,
        }
    }
}

/// Map of advice summaries by procedure.
pub type AdviceSummaryMap = HashMap<SymbolPath, AdviceSummary>;

/// Map of advice diagnostics by procedure.
pub type AdviceDiagnosticsMap = HashMap<SymbolPath, Vec<AdviceDiagnostic>>;
