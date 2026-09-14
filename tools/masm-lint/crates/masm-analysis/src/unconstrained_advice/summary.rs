//! Summary and diagnostic types for unconstrained-advice analysis.

use std::collections::{BTreeSet, HashMap};

use miden_debug_types::SourceSpan;

use super::{domain::AdviceFact, u32_domain::U32Validity};
use crate::SymbolPath;

/// Provenance portion of an advice summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AdviceProvenanceSummary {
    /// Per-output unconstrained-advice provenance.
    outputs: Vec<AdviceFact>,
    /// Exact input-position forwarding for each output, when known.
    forwarded_inputs: Vec<Option<usize>>,
}

impl AdviceProvenanceSummary {
    /// Create a provenance summary for procedure outputs.
    fn new(outputs: Vec<AdviceFact>, forwarded_inputs: Vec<Option<usize>>) -> Self {
        debug_assert_eq!(outputs.len(), forwarded_inputs.len());
        Self { outputs, forwarded_inputs }
    }
}

/// U32-validity portion of an advice summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AdviceU32Summary {
    /// Per-output `u32` validity.
    outputs: Vec<U32Validity>,
    /// Per-input `u32` postconditions guaranteed after the call returns.
    inputs: Vec<U32Validity>,
}

impl AdviceU32Summary {
    /// Create a U32 summary for procedure inputs and outputs.
    fn new(outputs: Vec<U32Validity>, inputs: Vec<U32Validity>) -> Self {
        Self { outputs, inputs }
    }
}

/// Non-zero precondition portion of an advice summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AdviceNonZeroSummary {
    /// Input positions that may reach a divisor or `inv` input without a local proof.
    required_inputs: BTreeSet<usize>,
    /// Whether this summary is opaque.
    unknown: bool,
}

impl AdviceNonZeroSummary {
    /// Create a known non-zero summary with no required inputs.
    fn empty() -> Self {
        Self {
            required_inputs: BTreeSet::new(),
            unknown: false,
        }
    }

    /// Create an opaque non-zero summary.
    fn unknown() -> Self {
        Self {
            required_inputs: BTreeSet::new(),
            unknown: true,
        }
    }

    /// Create a known non-zero summary from required input positions.
    fn new(required_inputs: BTreeSet<usize>) -> Self {
        Self { required_inputs, unknown: false }
    }
}

/// Typed summary carrier for advice-related capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AdviceSummary {
    /// Provenance facts owned by the provenance capability.
    provenance: AdviceProvenanceSummary,
    /// U32 facts owned by the U32 capability.
    u32: AdviceU32Summary,
    /// Non-zero precondition facts owned by the non-zero capability.
    nonzero: AdviceNonZeroSummary,
    /// Whether this summary is opaque.
    unknown: bool,
}

impl AdviceSummary {
    /// Create a known summary.
    pub(super) fn new(outputs: Vec<AdviceFact>) -> Self {
        let output_count = outputs.len();
        Self {
            provenance: AdviceProvenanceSummary::new(outputs, vec![None; output_count]),
            u32: AdviceU32Summary::new(vec![U32Validity::Unknown; output_count], Vec::new()),
            nonzero: AdviceNonZeroSummary::empty(),
            unknown: false,
        }
    }

    /// Create a known summary with explicit exact-forwarding metadata.
    pub(super) fn with_forwarding(
        outputs: Vec<AdviceFact>,
        u32_outputs: Vec<U32Validity>,
        forwarded_inputs: Vec<Option<usize>>,
        u32_inputs: Vec<U32Validity>,
    ) -> Self {
        debug_assert_eq!(outputs.len(), u32_outputs.len());
        debug_assert_eq!(outputs.len(), forwarded_inputs.len());
        Self {
            provenance: AdviceProvenanceSummary::new(outputs, forwarded_inputs),
            u32: AdviceU32Summary::new(u32_outputs, u32_inputs),
            nonzero: AdviceNonZeroSummary::empty(),
            unknown: false,
        }
    }

    /// Create an opaque summary with explicit output arity.
    pub(super) fn unknown_with_arity(outputs: usize) -> Self {
        Self {
            provenance: AdviceProvenanceSummary::new(
                vec![AdviceFact::bottom(); outputs],
                vec![None; outputs],
            ),
            u32: AdviceU32Summary::new(vec![U32Validity::Unknown; outputs], Vec::new()),
            nonzero: AdviceNonZeroSummary::unknown(),
            unknown: true,
        }
    }

    /// Return an opaque summary without arity information.
    pub(super) fn unknown() -> Self {
        Self::unknown_with_arity(0)
    }

    /// Return true if the summary is opaque.
    pub(super) fn is_unknown(&self) -> bool {
        self.unknown
    }

    /// Return the per-output `u32` validity.
    pub(super) fn u32_outputs(&self) -> &[U32Validity] {
        &self.u32.outputs
    }

    /// Return the exact-forwarding metadata for each output.
    pub(super) fn forwarded_inputs(&self) -> &[Option<usize>] {
        &self.provenance.forwarded_inputs
    }

    /// Return the per-input `u32` postconditions.
    pub(super) fn u32_inputs(&self) -> &[U32Validity] {
        &self.u32.inputs
    }

    /// Return the per-output provenance facts.
    pub(super) fn output_facts(&self) -> &[AdviceFact] {
        &self.provenance.outputs
    }

    /// Return the number of summarized outputs.
    pub(super) fn output_count(&self) -> usize {
        self.provenance.outputs.len()
    }

    /// Set non-zero precondition summary facts.
    pub(super) fn set_nonzero_requirements(&mut self, required_inputs: BTreeSet<usize>) {
        self.nonzero = AdviceNonZeroSummary::new(required_inputs);
    }

    /// Mark the non-zero summary as opaque.
    pub(super) fn set_nonzero_unknown(&mut self) {
        self.nonzero = AdviceNonZeroSummary::unknown();
    }

    /// Return true if the non-zero summary is opaque.
    pub(super) fn nonzero_is_unknown(&self) -> bool {
        self.nonzero.unknown
    }

    /// Return input positions required by non-zero preconditions.
    pub(super) fn nonzero_required_inputs(&self) -> &BTreeSet<usize> {
        &self.nonzero.required_inputs
    }
}

impl Default for AdviceSummary {
    fn default() -> Self {
        Self::unknown()
    }
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
}

impl AdviceDiagnostic {
    /// Create a new diagnostic with the given message.
    pub(super) fn new(procedure: SymbolPath, span: SourceSpan, message: impl Into<String>) -> Self {
        Self {
            procedure,
            span,
            origins: Vec::new(),
            message: message.into(),
        }
    }
}

/// Procedure-local context for building advice diagnostics.
#[derive(Debug, Clone)]
pub(super) struct AdviceDiagnosticContext {
    procedure: SymbolPath,
}

impl AdviceDiagnosticContext {
    /// Create a diagnostic context for one procedure.
    pub(super) fn new(procedure: SymbolPath) -> Self {
        Self { procedure }
    }

    /// Create a diagnostic whose related source spans are derived from an advice fact.
    pub(super) fn diagnostic_for_fact(
        &self,
        span: SourceSpan,
        message: impl Into<String>,
        fact: &AdviceFact,
    ) -> AdviceDiagnostic {
        diagnostic_from_fact(self.procedure.clone(), span, message, fact)
    }
}

/// Create a diagnostic whose related source spans are derived from an advice fact.
pub(super) fn diagnostic_from_fact(
    procedure: SymbolPath,
    span: SourceSpan,
    message: impl Into<String>,
    fact: &AdviceFact,
) -> AdviceDiagnostic {
    let mut diagnostic = AdviceDiagnostic::new(procedure, span, message);
    diagnostic.origins = fact.source_spans.iter().copied().collect();
    diagnostic
}

/// Map of advice summaries by procedure.
pub(super) type AdviceSummaryMap = HashMap<SymbolPath, AdviceSummary>;

/// Map of advice diagnostics by procedure.
pub(super) type AdviceDiagnosticsMap = HashMap<SymbolPath, Vec<AdviceDiagnostic>>;
