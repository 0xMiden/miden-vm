//! Multi-precompile registry substrate.
//!
//! A [`Precompile`] is a self-contained semantic module (e.g. a hash, signature, or field
//! precompile) that claims a slice of the tag space identified by a stable [`Felt`] id. The
//! [`crate::deferred::PrecompileRegistry`] dispatches each [`Tag`](crate::deferred::Tag) to the
//! right precompile by its [`Tag::id`](crate::deferred::Tag), hands the precompile-local
//! [`Tag::imm`](crate::deferred::Tag) felts to it, and forwards `decode` / `reduce`.
//!
//! Tag layout: `Tag { id, imm: [Felt; 3] }`. Only `id` is framework-owned (validated against
//! [`precompile_id`]; `ZERO` is reserved for the framework's TRUE / AND nodes, so a precompile
//! may not derive id `ZERO`). The three `imm` felts are *entirely* the precompile's to
//! interpret — the framework imposes no structure, no reserved felt, no zeroing convention.

use alloc::vec::Vec;

use miden_crypto::hash::blake::Blake3_256;

use super::{Node, NodeType, Payload, PrecompileError, WitnessBuilder};
use crate::Felt;

// PRECOMPILE TRAIT
// ================================================================================================

/// A single semantic module of a [`PrecompileRegistry`](crate::deferred::PrecompileRegistry).
///
/// A precompile owns a slice of the tag space identified by its [`Tag::id`](crate::deferred::Tag).
/// The framework imposes *nothing* on the three immediate felts: each precompile decides which
/// of them are meaningful and what they mean.
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

    /// Decode the precompile-local immediate felts (`tag.imm`) to the tag's [`NodeType`].
    /// Returning `None` rejects the tag; the registry wraps that into the framework error,
    /// tagged with this precompile's name. `tag.id` has already been matched to this precompile
    /// by the registry, so `decode` only inspects the felts it cares about — there is no
    /// framework-mandated reserved felt.
    fn decode(&self, imm: [Felt; 3]) -> Option<NodeType>;

    /// Reduce a node owned by this precompile to its canonical form, given the node's immediate
    /// felts and body. The registry has already routed by `tag.id`, so an implementor never
    /// re-checks the id; it typically classifies `imm[0]` with the same helper `decode` uses
    /// (`decode` having succeeded means that classification cannot fail here), then walks the
    /// `payload`. To emit a node, rebuild the tag as `Tag::new(self.id(), imm)`.
    ///
    /// `payload` is a [`Payload`](super::Payload): use `payload.binary_op_children()?` to pull
    /// the two child digests of an op/predicate, `payload.as_felts()?` for a value leaf, or
    /// `payload.as_chunks()?` for bulk data (the `?` surfaces a wrong-shape body as a
    /// [`PrecompileError`]). Call `witness.resolve(d)` on each child digest to get the canonical
    /// child back, and `witness.intern(child)` to mint a freshly-computed child (compound
    /// canonicals).
    ///
    /// Canonical-form conventions (per-precompile intent — not enforced by the framework, which
    /// only requires the result to be a valid `Node`):
    /// - **Self-evaluating leaf**: return the node rebuilt from `(Tag::new(self.id(), imm),
    ///   payload)`, optionally first validating the payload.
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
        imm: [Felt; 3],
        payload: &Payload,
        witness: &mut WitnessBuilder<'_>,
    ) -> Result<Node, PrecompileError>;
}

// PRECOMPILE ID DERIVATION
// ================================================================================================

/// Domain separator pinned to the v1 framework hashing convention. Bump iff the *derivation*
/// changes (different hash, different input layout).
const PRECOMPILE_ID_DOMSEP: &[u8] = b"miden-deferred-precompile/v1";

/// Derive a precompile's canonical id from its `name`.
///
/// The name is hashed with Blake3; the first 8 bytes of the digest are interpreted as a
/// little-endian `u64` and reduced modulo the Goldilocks prime — giving ~32 bits of
/// birthday-collision resistance, comfortably sufficient for the handful of precompiles a
/// registry is expected to host. Used by
/// [`PrecompileRegistry::with_precompile`](crate::deferred::PrecompileRegistry::with_precompile)
/// to validate each precompile's declared [`Precompile::id`].
pub fn precompile_id(p: &dyn Precompile) -> Felt {
    derive(p.name())
}

fn derive(name: &str) -> Felt {
    // Length-prefix the name so it is domain-separated from the digest tail.
    let mut buf = Vec::with_capacity(PRECOMPILE_ID_DOMSEP.len() + 4 + name.len());
    buf.extend_from_slice(PRECOMPILE_ID_DOMSEP);
    buf.extend_from_slice(&(name.len() as u32).to_le_bytes());
    buf.extend_from_slice(name.as_bytes());
    let digest = Blake3_256::hash(&buf);
    let raw = u64::from_le_bytes(digest.as_bytes()[..8].try_into().expect("8 bytes"));
    Felt::new_unchecked(raw % Felt::ORDER)
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
    fn id_lies_in_field() {
        // `new_unchecked` is sound only if the value < Felt::ORDER.
        assert!(derive("anything").as_canonical_u64() < Felt::ORDER);
    }
}
