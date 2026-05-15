//! Procedure type summaries.

use std::collections::HashMap;

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
    pub(crate) fn new(inputs: Vec<TypeRequirement>, outputs: Vec<InferredType>) -> Self {
        let output_count = outputs.len();
        Self {
            inputs,
            outputs,
            output_input_map: vec![None; output_count],
            opaque: false,
        }
    }

    /// Create a known summary with an explicit output-to-input map.
    pub(crate) fn new_with_map(
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
    pub(crate) fn opaque_with_arity(inputs: usize, outputs: usize) -> Self {
        Self {
            inputs: vec![TypeRequirement::Felt; inputs],
            outputs: vec![InferredType::Felt; outputs],
            output_input_map: vec![None; outputs],
            opaque: true,
        }
    }

    /// Create a fully opaque summary without arity information.
    pub(crate) fn opaque() -> Self {
        Self::opaque_with_arity(0, 0)
    }

    /// Returns true if this summary is opaque.
    pub(crate) const fn is_opaque(&self) -> bool {
        self.opaque
    }
}

impl Default for TypeSummary {
    fn default() -> Self {
        Self::opaque()
    }
}

/// Map of inferred type summaries by procedure.
pub type TypeSummaryMap = HashMap<SymbolPath, TypeSummary>;
