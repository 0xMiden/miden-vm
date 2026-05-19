//! Multi-precompile registry substrate.
//!
//! A [`Precompile`] is a self-contained semantic module (e.g. a hash, signature, or field
//! precompile) that claims a slice of the tag space identified by a stable [`Felt`] id. The
//! [`crate::deferred::Precompiles`] registry dispatches each [`Tag`](crate::deferred::Tag) to
//! the right precompile by its [`Tag::id`](crate::deferred::Tag), hands the precompile-local
//! [`Tag::imm`](crate::deferred::Tag) felts to it, and forwards `decode` / `reduce`.
//!
//! Tag layout (locked for v1) — `Tag { id, imm: [node_disc, imm, reserved] }`:
//!
//! - `id` — the precompile's pinned id; validated against [`precompile_id`]. `ZERO` is reserved for
//!   the framework (the TRUE / AND nodes); a precompile may not derive id `ZERO`.
//! - `imm[0]` (`node_disc`) — precompile-local discriminant index (small integer).
//! - `imm[1]` — precompile-local immediate (e.g. `n_bytes` for chunk precompiles); `ZERO` if
//!   unused.
//! - `imm[2]` — reserved; conventionally `ZERO` in v1. The precompile owns this check.

use alloc::vec::Vec;

use blake3::Hasher;

use super::{Node, PrecompileError, TagInfo, WitnessBuilder};
use crate::Felt;

// PRECOMPILE TRAIT
// ================================================================================================

/// A single semantic module of a [`Precompiles`](crate::deferred::Precompiles) registry.
///
/// Precompiles own a small enum of node-kinds and (optionally) one immediate per tag. They are
/// stitched together into a [`crate::deferred::Precompiles`] registry, which dispatches by
/// [`Tag::id`](crate::deferred::Tag).
pub trait Precompile: core::fmt::Debug + Send + Sync {
    /// Hashed into the precompile id. Renaming breaks decoding for existing programs.
    fn name(&self) -> &'static str;

    /// Pinned id (the [`Tag::id`](crate::deferred::Tag) of every tag belonging to this
    /// precompile). Implementors return the precomputed value;
    /// [`crate::deferred::Precompiles::new`] validates it equals [`precompile_id`] (and is not
    /// the framework-reserved `ZERO`), erroring on drift. No default — the value/derivation
    /// bridge is the validator's hook.
    fn id(&self) -> Felt;

    /// Canonical constant leaves this precompile contributes at registry-init time (e.g. `ZERO`,
    /// `ONE`, a generator). [`crate::deferred::Precompiles::init`] collects these, interns them,
    /// and errors on a cross-precompile digest collision. Default: contributes nothing.
    fn init(&self) -> Vec<Node> {
        Vec::new()
    }

    /// Decode the precompile-local immediate felts (`tag.imm`, i.e. `[node_disc, imm, reserved]`)
    /// to a [`TagInfo`]. Returning `None` rejects the tag; the [`crate::deferred::Precompiles`]
    /// registry wraps that into the framework error, tagged with this precompile's name. The
    /// precompile owns validation of all three felts, including rejecting a non-`ZERO` reserved
    /// felt. `tag.id` has already been matched to this precompile by the registry.
    fn decode(&self, imm: [Felt; 3]) -> Option<TagInfo>;

    /// Reduce a node owned by this precompile to its canonical form. The precompile picks the
    /// child digests off `node.payload` and calls `witness.resolve(d)` on each to get the
    /// corresponding canonical-form child node back. If the canonical form references *new*
    /// child digests (e.g. a producing op on a compound canonical), it calls
    /// `witness.intern(child)` to mint them.So from what I'm seeing pa pa pa pa pa pa pa pa I would
    /// say let's not impose anything in the pre compile framework about immediate being zero or
    /// whatever. It's completely free for the the implementer to choose how they do this. a
    /// precompile makes sense but I would say yes okay so decode takes I think actually I would I I
    /// would like the reduce function in precompile trait to not take node but instead something
    /// like just basically just the immediate with so basically something where reduce takes
    /// basically the immediate so the three felts and whatever it contains. So I'm not sure how we
    /// would modify node for this, but maybe I think we would want to wrap something like a
    /// precompile node inside of a node and the node contains like the ID and then the rest is a
    /// precompile node with the payload and stuff I don't like the term precompiles. I would say
    /// like pre-compile registry is probably a nicer one. I think also when it comes to compiles, I
    /// think what really what the only thing we want I think we want a default one and then just
    /// use the with da ta ta the builder format we only want that that should simplify things a lot
    /// ba ba ba ba. Yeah so basically I think reduce can take like I think if I understand things
    /// correctly, we can take the immediate and the payload and then let it decode the payload. we
    /// probably don't need a separate separate precomilep node and node type because we have the
    /// not the payload the payload which is the thing which is either a chunk like a a chunk or
    /// eight felts. I think what we also want to do is that for all of the implementations of
    /// precompiles we want to remove all of the checks in the decoding as well as those which are
    /// duplicated inside of the reduce, like there's a lot of unnecessary checks and stuff that
    /// could just be handled by a single function. So like we have this discriminant, right? We get
    /// the discriminant from the I from the immediates. And so when decoding the immediates then we
    /// get a thing. And so then we can just pass through the R and it removes a lot of boilerplate
    /// checking Yeah, I see this for example in I mean there's many places, right?
    ///
    /// Output type must match `decode(node.tag.imm).evaluates_to`:
    /// - **Self-evaluating leaf** (`evaluates_to == node.tag`): return a clone of the node,
    ///   optionally first validating the payload (e.g. limb canonicality).
    /// - **Producing op** (`evaluates_to == some_canonical_tag`): resolve the children and combine
    ///   them, returning a new node with the canonical tag. Compound canonicals (those whose
    ///   payload contains by-digest children) mint those children via `witness.intern`.
    /// - **Predicate** (`evaluates_to == TRUE_TAG`): resolve the operands, check the predicate, and
    ///   return [`super::true_node`] on success or [`PrecompileError::AssertionFailed`] on
    ///   mismatch.
    /// - **Chunk body**: typically reduces to a digest-leaf expression so a chunk-as-child appears
    ///   to parent ops as a normal expression after canonicalisation.
    ///
    /// Precompile-defined payload-validity checks (e.g. "leaf limbs must be u32-canonical") live
    /// here — they fire when the node is actually used, keeping `decode` to tag inspection only.
    ///
    /// `node` is borrowed (not consumed) so the framework can intern it by-move after this call
    /// returns — saving a chunk-sized clone on every reduction.
    fn reduce(
        &self,
        node: &Node,
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
/// registry is expected to host. Used by [`crate::deferred::Precompiles::new`] to validate each
/// precompile's declared [`Precompile::id`].
pub fn precompile_id(p: &dyn Precompile) -> Felt {
    derive(p.name())
}

fn derive(name: &str) -> Felt {
    let mut hasher = Hasher::new();
    hasher.update(PRECOMPILE_ID_DOMSEP);
    // Length-prefix the name so it is domain-separated from the digest tail.
    hasher.update(&(name.len() as u32).to_le_bytes());
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
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
