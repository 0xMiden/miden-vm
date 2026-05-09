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
    /// - Any node's digest cannot be recomputed because structural validation fails first
    ///
    /// Security convention:
    /// - Hashless payloads rebuild non-external digests from structure during materialization.
    /// - If wire node hashes are present, validation recomputes them and requires them to match.
    /// - External node digests are marshaled as opaque values and are not semantically resolved
    ///   here.
    pub fn validate(self) -> Result<MastForest, MastForestError> {
        let is_hashless = self.layout.is_hashless();
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
    /// [`read_from_bytes_with_budgets`](Self::read_from_bytes_with_budgets).
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
        Self::read_from_bytes_with_budgets(
            bytes,
            bytes.len(),
            serialization::default_untrusted_allocation_budget(bytes.len()),
        )
    }

    /// Deserializes an [`UntrustedMastForest`] from bytes and returns the raw wire flags.
    ///
    /// This enables callers to inspect serializer intent flags (e.g., HASHLESS) without affecting
    /// the untrusted deserialization path.
    pub fn read_from_bytes_with_flags(bytes: &[u8]) -> Result<(Self, u8), DeserializationError> {
        Self::read_from_bytes_with_budgets_and_flags(
            bytes,
            bytes.len(),
            serialization::default_untrusted_allocation_budget(bytes.len()),
        )
    }

    /// Deserializes an [`UntrustedMastForest`] from bytes with a byte budget.
    ///
    /// This method uses a [`BudgetedReader`] to limit memory consumption during deserialization,
    /// protecting against denial-of-service attacks from malicious input that claims to contain
    /// an excessive number of elements.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The serialized forest bytes
    /// * `budget` - Maximum bytes to consume while parsing the wire payload and pre-sizing
    ///   wire-driven collections via [`BudgetedReader`]
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Read from untrusted source with an explicit parsing budget
    /// let untrusted = UntrustedMastForest::read_from_bytes_with_budget(&bytes, bytes.len())?;
    ///
    /// // Validate before use
    /// let forest = untrusted.validate()?;
    /// ```
    ///
    /// # Security
    ///
    /// The budget limits:
    /// - Pre-allocation sizes when deserializing collections (via `max_alloc`)
    /// - Total bytes consumed during deserialization
    ///
    /// This prevents attacks where malicious input claims an unrealistic number of elements
    /// (e.g., `len = 2^60`), causing excessive memory allocation before any data is read.
    ///
    /// To also cap stripped/hashless validation helper allocations, use
    /// [`read_from_bytes_with_budgets`](Self::read_from_bytes_with_budgets).
    pub fn read_from_bytes_with_budget(
        bytes: &[u8],
        budget: usize,
    ) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), budget);
        serialization::read_untrusted_with_flags(&mut reader).map(|(forest, _flags)| forest)
    }

    /// Deserializes an [`UntrustedMastForest`] from bytes with a byte budget and returns flags.
    pub fn read_from_bytes_with_budget_and_flags(
        bytes: &[u8],
        budget: usize,
    ) -> Result<(Self, u8), DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), budget);
        serialization::read_untrusted_with_flags(&mut reader)
    }

    /// Deserializes an [`UntrustedMastForest`] from bytes with separate parsing and validation
    /// budgets.
    ///
    /// `parsing_budget` limits wire-driven parsing and collection pre-sizing. `validation_budget`
    /// additionally caps tracked stripped/hashless helper allocations such as digest slot tables,
    /// empty debug-info scaffolding, and rebuilt digest tables.
    pub fn read_from_bytes_with_budgets(
        bytes: &[u8],
        parsing_budget: usize,
        validation_budget: usize,
    ) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), parsing_budget);
        serialization::read_untrusted_with_flags_and_allocation_budget(
            &mut reader,
            validation_budget,
        )
        .map(|(forest, _flags)| forest)
    }

    /// Deserializes an [`UntrustedMastForest`] from bytes with separate parsing and validation
    /// budgets and returns flags.
    pub fn read_from_bytes_with_budgets_and_flags(
        bytes: &[u8],
        parsing_budget: usize,
        validation_budget: usize,
    ) -> Result<(Self, u8), DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), parsing_budget);
        serialization::read_untrusted_with_flags_and_allocation_budget(
            &mut reader,
            validation_budget,
        )
    }
}
