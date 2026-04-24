//! Procedure type summaries and diagnostics.

use std::collections::HashMap;

use miden_assembly_syntax::debuginfo::SourceSpan;

use super::domain::{InferredType, TypeRequirement};
use crate::symbol::path::SymbolPath;

/// Type summary inferred for a single procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeSummary {
    /// Required input types by call-argument position.
    ///
    /// Position `0` corresponds to the top-of-stack argument (first popped).
    pub inputs: Vec<TypeRequirement>,
    /// Guaranteed output types by call-result position.
    ///
    /// Position `0` corresponds to the first pushed result (deepest of the
    /// new return values on the stack).
    pub outputs: Vec<InferredType>,
    /// Maps each output position to the input position it traces back to
    /// as an unmodified copy, or `None` if the output is computed.
    ///
    /// When `output_input_map[i] == Some(j)`, the value at output position
    /// `i` is the same value that was passed as input `j`. This enables
    /// callers to infer the output type from their own argument types
    /// rather than using the callee's conservative fixed type.
    pub output_input_map: Vec<Option<usize>>,
    /// Indicates the summary is opaque and should not be used for mismatch checks.
    pub opaque: bool,
}

impl TypeSummary {
    /// Create a known summary.
    pub fn new(inputs: Vec<TypeRequirement>, outputs: Vec<InferredType>) -> Self {
        let output_count = outputs.len();
        Self {
            inputs,
            outputs,
            output_input_map: vec![None; output_count],
            opaque: false,
        }
    }

    /// Create a known summary with an explicit output-to-input map.
    pub fn new_with_map(
        inputs: Vec<TypeRequirement>,
        outputs: Vec<InferredType>,
        output_input_map: Vec<Option<usize>>,
    ) -> Self {
        debug_assert_eq!(
            output_input_map.len(),
            outputs.len(),
            "output_input_map length must match outputs length"
        );
        Self {
            inputs,
            outputs,
            output_input_map,
            opaque: false,
        }
    }

    /// Create an opaque summary with explicit input/output arity.
    pub fn opaque_with_arity(inputs: usize, outputs: usize) -> Self {
        Self {
            inputs: vec![TypeRequirement::Felt; inputs],
            outputs: vec![InferredType::Felt; outputs],
            output_input_map: vec![None; outputs],
            opaque: true,
        }
    }

    /// Create a fully opaque summary without arity information.
    pub fn opaque() -> Self {
        Self::opaque_with_arity(0, 0)
    }

    /// Returns true if this summary is opaque.
    pub const fn is_opaque(&self) -> bool {
        self.opaque
    }
}

impl Default for TypeSummary {
    fn default() -> Self {
        Self::opaque()
    }
}

/// Diagnostic emitted by type analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeDiagnostic {
    /// Procedure in which the diagnostic was emitted.
    pub procedure: SymbolPath,
    /// Source span associated with the mismatch (where the violation occurs).
    pub span: SourceSpan,
    /// Human-readable message.
    pub message: String,
    /// Optional callee (for call-argument diagnostics).
    pub callee: Option<SymbolPath>,
    /// Optional argument index (for call-argument diagnostics).
    pub arg_index: Option<usize>,
    /// Expected type requirement.
    pub expected: Option<TypeRequirement>,
    /// Actual inferred type.
    pub actual: Option<InferredType>,
    /// Optional source span pointing to the origin of the type mismatch.
    ///
    /// For example, the Felt arithmetic operation whose output feeds a U32
    /// call site, or the public procedure input that lacks validation.
    pub source_span: Option<SourceSpan>,
    /// Optional human-readable explanation of why the source causes the mismatch.
    ///
    /// For example, "Felt addition can produce values outside the u32 range"
    /// or "public procedure input must be validated as U32".
    pub source_description: Option<String>,
}

impl TypeDiagnostic {
    /// Create a new diagnostic with the given message.
    pub fn new(procedure: SymbolPath, span: SourceSpan, message: impl Into<String>) -> Self {
        Self {
            procedure,
            span,
            message: message.into(),
            callee: None,
            arg_index: None,
            expected: None,
            actual: None,
            source_span: None,
            source_description: None,
        }
    }
}

/// Map of inferred type summaries by procedure.
pub type TypeSummaryMap = HashMap<SymbolPath, TypeSummary>;

/// Map of diagnostics by procedure.
pub type TypeDiagnosticsMap = HashMap<SymbolPath, Vec<TypeDiagnostic>>;
