use alloc::vec::Vec;

use super::{AdviceMap, DebugInfo, MastForest, MastForestError, serialization};
use crate::serde::{BudgetedReader, DeserializationError, SliceReader};

/// A [`MastForest`] deserialized from untrusted input that has not yet been validated.
///
/// This type wraps a serialized-backed, decoded MAST representation that has not had its node
/// hashes verified. Before using the forest, callers must call [`validate()`](Self::validate) to
/// materialize and verify structural integrity and node hashes.
///
/// # Usage
///
/// ```ignore
/// // Deserialize from untrusted bytes
/// let untrusted = UntrustedMastForest::read_from_bytes(&bytes)?;
///
/// // Validate structure and hashes
/// let forest = untrusted.validate()?;
///
/// // Now safe to use
/// let root = forest.procedure_roots()[0];
/// ```
///
/// # Security
///
/// This type exists to provide type-level safety for untrusted deserialization. The validation
/// performed by [`validate()`](Self::validate) includes:
///
/// 1. **Structural validation**: Checks that basic block batch invariants are satisfied and
///    procedure names reference valid roots.
/// 2. **Topological ordering**: Verifies that all node references point to nodes that appear
///    earlier in the forest (no forward references).
/// 3. **Hash recomputation**: Recomputes the digest for every node and verifies it matches the
///    stored digest.
#[derive(Debug, Clone)]
pub struct UntrustedMastForest {
    pub(super) bytes: Vec<u8>,
    pub(super) layout: serialization::ForestLayout,
    pub(super) advice_map: AdviceMap,
    pub(super) debug_info: DebugInfo,
    pub(super) remaining_allocation_budget: Option<usize>,
}

/// Options for reading an [`UntrustedMastForest`] from bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UntrustedMastForestReadOptions {
    wire_byte_budget: Option<usize>,
    validation_allocation_budget: Option<usize>,
}

impl UntrustedMastForestReadOptions {
    /// Creates options that use the default untrusted budgets.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum number of serialized bytes consumed while parsing wire data.
    pub fn with_wire_byte_budget(mut self, budget: usize) -> Self {
        self.wire_byte_budget = Some(budget);
        self
    }

    /// Sets the maximum helper allocation budget used during validation.
    pub fn with_validation_allocation_budget(mut self, budget: usize) -> Self {
        self.validation_allocation_budget = Some(budget);
        self
    }

    fn wire_byte_budget(self, bytes_len: usize) -> usize {
        self.wire_byte_budget.unwrap_or(bytes_len)
    }

    fn validation_allocation_budget(self, bytes_len: usize) -> usize {
        self.validation_allocation_budget
            .unwrap_or_else(|| serialization::default_untrusted_allocation_budget(bytes_len))
    }
}

impl UntrustedMastForest {
    /// Validates the forest by checking structural invariants and recomputing all node hashes.
    ///
    /// This method performs a complete validation of the deserialized forest:
    ///
    /// 1. If wire node hashes are present, recomputes all non-external node hashes and requires
    ///    them to match the serialized digests.
    /// 2. If the payload is hashless, uses the digests rebuilt during materialization.
    /// 3. Validates structural invariants, topological ordering, and procedure-name roots.
    ///
    /// # Returns
    ///
    /// - `Ok(MastForest)` if validation succeeds
    /// - `Err(MastForestError)` with details about the first validation failure
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Deferred materialization from serialized form fails ([`MastForestError::Deserialization`])
    /// - Any basic block has invalid batch structure ([`MastForestError::InvalidBatchPadding`])
    /// - Any procedure name references a non-root digest
    ///   ([`MastForestError::InvalidProcedureNameDigest`])
    /// - Any node references a child that appears later in the forest
    ///   ([`MastForestError::ForwardReference`])
    /// - Any non-external wire digest does not match the recomputed digest
    ///   ([`MastForestError::HashMismatch`])
    /// - External digest slots are not sorted lexicographically on the wire
    ///   ([`MastForestError::ExternalDigestsNotSorted`])
    /// - Any node's digest cannot be recomputed because structural validation fails first
    ///
    /// Security convention:
    /// - Hashless payloads rebuild non-external digests from structure during materialization.
    /// - If wire node hashes are present, validation recomputes them and requires them to match.
    /// - External node digests are marshaled as opaque values and are not semantically resolved
    ///   here.
    pub fn validate(self) -> Result<MastForest, MastForestError> {
        let is_hashless = self.layout.is_hashless();
        if let Some(violation) =
            serialization::external_digest_order_violation(&self.bytes, &self.layout)
                .map_err(MastForestError::Deserialization)?
        {
            return Err(MastForestError::ExternalDigestsNotSorted {
                previous_slot: violation.previous_slot,
                slot: violation.slot,
                previous: violation.previous,
                current: violation.current,
            });
        }

        let forest = self.into_materialized().map_err(MastForestError::Deserialization)?;

        // Step 1: Validate over-specified wire hashes instead of silently rewriting them.
        if !is_hashless {
            forest.validate_node_hashes()?;
        }

        // Step 2: Validate the recomputed forest.
        forest.validate()?;

        Ok(forest)
    }

    /// Deserializes an [`UntrustedMastForest`] from bytes.
    ///
    /// This method uses a [`BudgetedReader`] plus a bounded validation-allocation budget derived
    /// from the input size to protect against denial-of-service attacks from malicious input.
    /// The default validation budget includes room for the retained serialized copy used by the
    /// deferred-validation path, in addition to stripped/hashless helper allocations. Concretely,
    /// the default is `bytes.len()` for parsing and `bytes.len() * 7` for validation allocations.
    /// That `* 7` factor is a coarse convenience bound, not an exact peak-memory formula.
    ///
    /// For explicit parsing and validation limits, use
    /// [`read_from_bytes_with_options`](Self::read_from_bytes_with_options).
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Read from untrusted source
    /// let untrusted = UntrustedMastForest::read_from_bytes(&bytes)?;
    ///
    /// // Validate before use
    /// let forest = untrusted.validate()?;
    /// ```
    pub fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        Self::read_from_bytes_with_options(bytes, UntrustedMastForestReadOptions::default())
    }

    /// Deserializes an [`UntrustedMastForest`] from bytes with explicit options.
    ///
    /// The wire byte budget limits wire-driven parsing and collection pre-sizing. The validation
    /// allocation budget caps tracked stripped/hashless helper allocations such as digest slot
    /// tables, empty debug-info scaffolding, and rebuilt digest tables.
    pub fn read_from_bytes_with_options(
        bytes: &[u8],
        options: UntrustedMastForestReadOptions,
    ) -> Result<Self, DeserializationError> {
        let mut reader =
            BudgetedReader::new(SliceReader::new(bytes), options.wire_byte_budget(bytes.len()));
        serialization::read_untrusted_with_flags_and_allocation_budget(
            &mut reader,
            options.validation_allocation_budget(bytes.len()),
        )
        .map(|(forest, _flags)| forest)
    }
}
