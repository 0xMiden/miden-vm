//! Trait and id scheme for deferred precompiles.
//!
//! A [`Precompile`] owns a stable slice of tag space and supplies the semantics the framework
//! cannot know: which tags are valid, what their bodies mean, and how nodes evaluate to canonical
//! form. The framework owns only id derivation and routing.

use alloc::{format, vec::Vec};

use super::{DeferredContext, Node, NodeType, Payload, PrecompileError};
use crate::{Felt, utils::hash_string_to_word};

// PRECOMPILE TRAIT
// ================================================================================================

/// Semantic module installed in a [`PrecompileRegistry`](crate::deferred::PrecompileRegistry).
///
/// Each precompile owns one stable id and interprets that id's three local tag felts.
pub trait Precompile: Send + Sync {
    /// Stable name hashed into the precompile id; renaming changes every tag this precompile owns.
    fn name(&self) -> &'static str;

    /// Stable tag id for this precompile.
    ///
    /// The registry validates this against [`precompile_id`] and rejects framework-reserved ids,
    /// turning id drift into a setup-time failure.
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
    fn decode(&self, args: [Felt; 3]) -> Option<NodeType>;

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
    /// - unary payload `params` are literal node data, not child digests or tag arguments;
    /// - predicates return [`Node::TRUE`] on success and [`PrecompileError::AssertionFailed`] on
    ///   mismatch;
    /// - multi-chunk data nodes usually evaluate to a single-chunk value.
    fn evaluate(
        &self,
        args: [Felt; 3],
        payload: &Payload,
        context: &mut DeferredContext<'_>,
    ) -> Result<Node, PrecompileError>;
}

// PRECOMPILE ID DERIVATION
// ================================================================================================

/// Keeps precompile ids in a namespace separate from event ids even when names overlap.
const PRECOMPILE_ID_DOMSEP: &str = "miden-deferred-precompile/v1";

/// Derives the canonical id a registry expects for a precompile name.
///
/// The domain and length prefixes make the id stable, unambiguous, and disjoint from event ids.
/// [`PrecompileRegistry::with_precompile`](crate::deferred::PrecompileRegistry::with_precompile)
/// uses this to catch accidental id drift at setup time.
pub fn precompile_id(name: &str) -> Felt {
    let domain_separated = format!("{PRECOMPILE_ID_DOMSEP}:{}:{name}", name.len());
    hash_string_to_word(domain_separated.as_str())[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_derivation_is_stable_unique_and_domain_separated() {
        assert_eq!(precompile_id("foo"), precompile_id("foo"));
        assert_ne!(precompile_id("foo"), precompile_id("bar"));

        // Precompile ids and event ids share the hash_string_to_word helper but live in separate
        // namespaces: the precompile path domain-separates (domsep + length prefix), so the same
        // name must derive a different felt on each path.
        let name = "my_precompile";
        assert_ne!(precompile_id(name), crate::events::EventId::from_name(name).as_felt());
    }
}
