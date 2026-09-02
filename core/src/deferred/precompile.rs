//! Trait and selector contract for precompiles in the deferred framework.
//!
//! A [`Precompile`] owns a registered selector and supplies the semantics the framework cannot
//! know: which tags are valid, what their bodies mean, and how nodes evaluate to canonical form.
//! The framework owns routing but does not derive consensus selectors from names.

use alloc::vec::Vec;

use super::{DeferredContext, Node, NodeType, Payload, PrecompileError};
use crate::Felt;

/// Constructs a selector in a test-only portion of the delegated miden-vm range.
///
/// These selectors never appear in production code or the protocol registry. Centralized
/// construction keeps test fixtures explicit and avoids scattered numeric literals.
#[cfg(test)]
pub(crate) const fn test_precompile_selector(discriminant: u8) -> Felt {
    assert!(discriminant >= 1, "test selector discriminants start at one");
    Felt::new_unchecked((0x0001_ffff_u64 << 8) | discriminant as u64)
}

// PRECOMPILE TRAIT
// ================================================================================================

/// Semantic module installed in a [`PrecompileRegistry`](crate::deferred::PrecompileRegistry).
///
/// Each precompile owns one stable selector and interprets that selector's two local tag
/// parameters.
pub trait Precompile: Send + Sync {
    /// Human-readable name used for diagnostics only.
    fn name(&self) -> &'static str;

    /// Registered numeric selector for this precompile.
    ///
    /// The registry rejects framework ids, invalid selector encodings, and selectors assigned to
    /// other VM constructions. Implementations must obtain an explicit allocation from the shared
    /// selector registry.
    fn id(&self) -> Felt;

    /// Canonical constants this precompile wants registered before execution.
    ///
    /// State initialization loads every installed precompile's init nodes into one bootstrap set,
    /// then evaluates each init node to ensure the set resolves under the installed registry. The
    /// default contributes no constants.
    fn init(&self) -> Vec<Node> {
        Vec::new()
    }

    /// Declares the body shape for recognized local tag arguments.
    ///
    /// Returning `None` rejects the tag. The registry has already matched the precompile id, so
    /// this only interprets the tag's local arguments.
    fn decode(&self, args: [Felt; 2]) -> Option<NodeType>;

    /// Evaluates one owned node to its canonical form.
    ///
    /// The registry has already matched the tag id; implementors receive only local `args` and a
    /// payload whose outer shape passed [`Self::decode`]. Use [`DeferredContext`] to evaluate
    /// registered child digests (digests present in the state's node store) or to register helper
    /// nodes referenced by a compound canonical.
    ///
    /// Common conventions:
    /// - canonical values return themselves after validating payload contents;
    /// - producing ops evaluate structural children and return the resulting canonical node;
    /// - predicates return [`Node::TRUE`] on success and [`PrecompileError::AssertionFailed`] on
    ///   mismatch;
    /// - multi-chunk data nodes usually evaluate to a single-chunk value.
    fn evaluate(
        &self,
        args: [Felt; 2],
        payload: &Payload,
        context: &mut DeferredContext<'_>,
    ) -> Result<Node, PrecompileError>;
}
