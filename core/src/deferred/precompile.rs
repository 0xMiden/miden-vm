//! Trait and frame contract for precompiles in the deferred framework.
//!
//! A [`Precompile`] owns a registered domain tag and supplies the semantics the framework cannot
//! know: which parameter tuples are valid, what their payloads mean, and how nodes evaluate to
//! canonical form.
//! The framework owns routing but does not derive consensus domain tags from names.

use alloc::vec::Vec;

use miden_crypto::hash::eidos::DomainTag;
#[cfg(test)]
use miden_crypto::hash::eidos::{DomainVersion, namespace};

use super::{DeferredContext, Node, NodeType, Payload, PrecompileError};

/// Constructs a tag in a test-only portion of the ecosystem namespace.
///
/// These test tags never appear in production code or the protocol registry. Centralized
/// construction keeps test fixtures explicit and avoids scattered numeric literals.
#[cfg(test)]
pub(crate) const fn test_precompile_domain_tag(discriminant: u8) -> DomainTag {
    assert!(discriminant >= 1, "test tag discriminants start at one");
    DomainTag::new(namespace::MIDEN_ECOSYSTEM, u16::MAX, DomainVersion::numbered(discriminant))
}

// PRECOMPILE TRAIT
// ================================================================================================

/// Semantic module installed in a [`PrecompileRegistry`](crate::deferred::PrecompileRegistry).
///
/// Each precompile owns one stable domain and interprets the frame's three parameters.
pub trait Precompile: Send + Sync {
    /// Human-readable name used for diagnostics only.
    fn name(&self) -> &'static str;

    /// Registered Eidos domain tag for this precompile.
    ///
    /// The registry rejects framework ids, invalid domain-tag encodings, and tags assigned to
    /// other VM constructions. Implementations must obtain an explicit allocation from the shared
    /// domain registry.
    fn domain(&self) -> DomainTag;

    /// Canonical constants this precompile wants registered before execution.
    ///
    /// State initialization loads every installed precompile's init nodes into one bootstrap set,
    /// then evaluates each init node to ensure the set resolves under the installed registry. The
    /// default contributes no constants.
    fn init(&self) -> Vec<Node> {
        Vec::new()
    }

    /// Declares the body shape for a recognized parameter tuple.
    ///
    /// Returning `None` rejects the frame. The registry has already matched the domain tag, so this
    /// only interprets the frame's domain-defined parameters.
    fn decode(&self, params: [u32; 3]) -> Option<NodeType>;

    /// Applies payload checks beyond the declared [`NodeType`] before insertion.
    ///
    /// This is called after [`Self::decode`] accepts `params` and the payload matches the returned
    /// outer shape. [`NodeType::Data`] and [`NodeType::PairList`] guarantee only non-emptiness, not
    /// arity. Implementors must reject every unsupported fixed or parameter-dependent arity here
    /// or in [`Self::evaluate`]. The default performs no additional checks.
    fn validate_payload(&self, _params: [u32; 3], _payload: &Payload) -> bool {
        true
    }

    /// Evaluates one owned node to its canonical form.
    ///
    /// The registry has already matched the domain; implementors receive only local `params` and a
    /// payload whose outer shape passed [`Self::decode`] and whose additional checks passed
    /// [`Self::validate_payload`]. Use [`DeferredContext`] to evaluate registered child digests
    /// (digests present in the state's node store) or to register helper nodes referenced by a
    /// compound canonical.
    ///
    /// Common conventions:
    /// - canonical values return themselves after validating payload contents;
    /// - producing ops evaluate structural children and return the resulting canonical node;
    /// - predicates return [`Node::TRUE`] on success and [`PrecompileError::AssertionFailed`] on
    ///   mismatch;
    /// - multi-chunk data nodes usually evaluate to a single-chunk value.
    fn evaluate(
        &self,
        params: [u32; 3],
        payload: &Payload,
        context: &mut DeferredContext<'_>,
    ) -> Result<Node, PrecompileError>;
}
