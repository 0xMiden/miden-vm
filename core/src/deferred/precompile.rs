//! Multi-precompile registry substrate.
//!
//! A [`Precompile`] is a self-contained semantic module (e.g. a hash, signature, or field
//! precompile) that claims a slice of the tag space identified by a stable [`Felt`] id. The
//! [`crate::deferred::PrecompileRegistry`] dispatches each [`Tag`](crate::deferred::Tag) to the
//! right precompile by its [`Tag::id`](crate::deferred::Tag), hands the precompile-local
//! [`Tag::args`](crate::deferred::Tag) felts to it, and forwards `decode` / `reduce`.
//!
//! Tag layout: `Tag { id, args: [Felt; 3] }`. Only `id` is framework-owned (validated against
//! [`precompile_id`]; `ZERO` is reserved for the framework's TRUE / AND nodes, so a precompile
//! may not derive id `ZERO`). The three `args` felts are entirely the precompile's to interpret:
//! each precompile decides which of them are meaningful and what they mean.

use alloc::{format, vec::Vec};

use super::{Node, NodeType, Payload, PrecompileError, WitnessBuilder};
use crate::{Felt, utils::hash_string_to_word};

// PRECOMPILE TRAIT
// ================================================================================================

/// A single semantic module of a [`PrecompileRegistry`](crate::deferred::PrecompileRegistry).
///
/// A precompile owns a slice of the tag space identified by its [`Tag::id`](crate::deferred::Tag),
/// and interprets its three immediate felts however it likes.
pub trait Precompile: Send + Sync {
    /// Hashed into the precompile id. Renaming breaks decoding for existing programs.
    fn name(&self) -> &'static str;

    /// Pinned id (the [`Tag::id`](crate::deferred::Tag) of every tag belonging to this
    /// precompile). Implementors return the precomputed value;
    /// [`PrecompileRegistry::with_precompile`](crate::deferred::PrecompileRegistry::with_precompile)
    /// validates it equals [`precompile_id`] (and is not the framework-reserved `ZERO`),
    /// panicking on drift. No default — the value/derivation bridge is the validator's hook.
    fn id(&self) -> Felt;

    /// Canonical constant leaves this precompile contributes at registry-init time (e.g. `ZERO`,
    /// `ONE`, a generator).
    /// [`PrecompileRegistry::init`](crate::deferred::PrecompileRegistry::init) collects these,
    /// interns them, and errors on a cross-precompile digest collision. Default: contributes
    /// nothing.
    fn init(&self) -> Vec<Node> {
        Vec::new()
    }

    /// Decode the precompile-local immediate felts (`tag.args`) to the tag's [`NodeType`].
    /// Returning `None` rejects the tag; the registry wraps that into the framework error,
    /// tagged with this precompile's name. `tag.id` has already been matched to this precompile
    /// by the registry, so `decode` only inspects the felts it cares about.
    fn decode(&self, args: [Felt; 3]) -> Option<NodeType>;

    /// Reduce a node owned by this precompile to its canonical form, given the node's immediate
    /// felts and body. The registry has already routed by `tag.id`, so an implementor never
    /// re-checks the id; it typically classifies `args[0]` with the same helper `decode` uses
    /// (`decode` having succeeded means that classification cannot fail here), then walks the
    /// `payload`. To emit a node, rebuild the tag as `Tag::new(self.id(), args)`.
    ///
    /// `payload` is a [`Payload`](super::Payload): use `payload.join_children()?` to pull
    /// the two child digests of an op/predicate, `payload.as_felts()?` for a value leaf, or
    /// `payload.as_chunks()?` for bulk data (the `?` surfaces a wrong-shape body as a
    /// [`PrecompileError`]). Call `witness.resolve(d)` on each child digest to get the canonical
    /// child back, and `witness.intern(child)` to mint a freshly-computed child (compound
    /// canonicals).
    ///
    /// Canonical-form conventions (per-precompile intent — not enforced by the framework, which
    /// only requires the result to be a valid `Node`):
    /// - **Already-canonical input**: when the input node is its own canonical (e.g. a validated
    ///   value leaf, or a compound canonical that some other reduce produced via `witness.intern`),
    ///   return a clone of it. "Canonical" is a per-precompile property of the `(tag, payload)`
    ///   pair — there is no framework-level tag-equality check for it.
    /// - **Producing op**: resolve the children, combine, return a new node with the canonical tag
    ///   (minting compound-canonical children via `witness.intern`).
    /// - **Predicate**: resolve the operands, check the predicate, return [`Node::TRUE`] on success
    ///   or [`PrecompileError::AssertionFailed`] on mismatch. The framework detects a predicate
    ///   result post-reduce via [`Node::is_true_node`](super::Node::is_true_node) and skips the
    ///   advice-stack push for it.
    /// - **Chunk body**: typically reduces to a digest-leaf expression.
    ///
    /// Payload-validity checks (e.g. "leaf limbs must be u32-canonical") live here — they fire
    /// when the node is used, keeping `decode` to tag inspection only.
    fn reduce(
        &self,
        args: [Felt; 3],
        payload: &Payload,
        witness: &mut WitnessBuilder<'_>,
    ) -> Result<Node, PrecompileError>;
}

// PRECOMPILE ID DERIVATION
// ================================================================================================

/// Domain separator pinned to the v1 framework hashing convention. Prefixed onto the name before
/// hashing so precompile ids occupy a namespace disjoint from event ids (which hash the bare
/// name): an event handler and a precompile that happen to share a name still derive different
/// felts. Bump iff the *derivation* changes (different hash, different input layout).
const PRECOMPILE_ID_DOMSEP: &str = "miden-deferred-precompile/v1";

/// Derive a precompile's canonical id from its `name`.
///
/// Hashes `"<domsep>:<name.len()>:<name>"` through [`hash_string_to_word`] — the same Blake3 →
/// first-felt helper [`EventId::from_name`](crate::events::EventId::from_name) uses — so the id
/// shares the event-id crypto while living in a separate namespace. The `name.len()` prefix keeps
/// the `domsep`/`name` boundary unambiguous. Used by
/// [`PrecompileRegistry::with_precompile`](crate::deferred::PrecompileRegistry::with_precompile)
/// to validate each precompile's declared [`Precompile::id`].
pub fn precompile_id(p: &dyn Precompile) -> Felt {
    derive(p.name())
}

fn derive(name: &str) -> Felt {
    let domain_separated = format!("{PRECOMPILE_ID_DOMSEP}:{}:{name}", name.len());
    hash_string_to_word(domain_separated.as_str())[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_deterministic() {
        assert_eq!(derive("foo"), derive("foo"));
    }

    #[test]
    fn id_changes_with_name() {
        assert_ne!(derive("foo"), derive("bar"));
    }

    #[test]
    fn differs_from_event_id_derivation() {
        // Precompile ids and event ids share the hash_string_to_word helper but live in separate
        // namespaces: the precompile path domain-separates (domsep + length prefix), so the same
        // name must derive a different felt on each path.
        let name = "my_precompile";
        assert_ne!(derive(name), crate::events::EventId::from_name(name).as_felt());
    }
}
