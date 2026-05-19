//! Multi-precompile composite-schema substrate.
//!
//! A [`Precompile`] is a self-contained semantic module (e.g. a hash, signature, or field
//! app) that claims a slice of the 4-felt tag space identified by a stable [`Felt`] id. The
//! [`crate::deferred::PrecompileSchema`] composite dispatches each tag to the right precompile
//! by `tag[0]`, hands the remaining bits to it as a [`PrecompileTag`], and forwards
//! `decode` / `reduce`.
//!
//! Tag layout (locked for v1):
//!
//! ```text
//! [precompile_id, node_disc, imm, ZERO]
//! ```
//!
//! - `precompile_id` (felt 0) — the precompile's pinned id; validated against [`precompile_id`].
//! - `node_disc` (felt 1) — precompile-local discriminant index (small integer).
//! - `imm` (felt 2) — precompile-local immediate (e.g. `n_bytes` for chunk apps); `ZERO` if unused.
//! - `tag[3]` — reserved; must be `ZERO` in v1.

use alloc::vec::Vec;

use blake3::Hasher;

use super::{Node, ReduceCtx, SchemaError, TagInfo};
use crate::Felt;

// PRECOMPILE TAG
// ================================================================================================

/// The 3 felts after `tag[0]` (the precompile id): `[tag[1], tag[2], tag[3]]`. Opaque to the
/// framework — each precompile decodes its own layout (typically `[node_disc, imm, reserved]`,
/// rejecting a non-`ZERO` reserved felt itself, since the composite no longer enforces it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecompileTag(pub [Felt; 3]);

// PRECOMPILE TRAIT
// ================================================================================================

/// A single semantic module of a composite schema.
///
/// Precompiles own a small enum of node-kinds and (optionally) one immediate per tag. They are
/// stitched together into a [`crate::deferred::PrecompileSchema`] which implements the
/// framework's [`super::Schema`] trait.
pub trait Precompile: core::fmt::Debug + Send + Sync {
    /// Hashed into the precompile id. Renaming breaks the schema for existing programs.
    fn name(&self) -> &'static str;

    /// Hashed into the precompile id. Bump on incompatible decode/reduce changes.
    fn version(&self) -> u32;

    /// Pinned id (the first felt of every tag belonging to this precompile). Implementors
    /// return the precomputed value; [`crate::deferred::PrecompileSchema::new`] validates it
    /// equals [`precompile_id`], panicking on drift. No default — the value/derivation bridge
    /// is the validator's hook.
    fn id(&self) -> Felt;

    /// Canonical constant leaves this precompile contributes at schema-init time (e.g. `ZERO`,
    /// `ONE`, a generator). [`crate::deferred::PrecompileSchema::init`] collects these, interns
    /// them, and errors on a cross-precompile digest collision. Default: contributes nothing.
    fn init(&self) -> Vec<Node> {
        Vec::new()
    }

    /// Decode the precompile-local sub-tag to its [`TagInfo`]. Returning
    /// `Err(SchemaError::InvalidNode)` rejects the tag. The precompile owns validation of all
    /// three felts, including rejecting a non-`ZERO` reserved felt.
    fn decode(&self, sub: PrecompileTag) -> Result<TagInfo, SchemaError>;

    /// Reduce a node owned by this precompile to canonical form. Same contract as
    /// [`super::Schema::reduce`] — see its docs for the leaf / op / predicate / chunk variants.
    fn reduce(&self, node: &Node, ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError>;
}

// PRECOMPILE ID DERIVATION
// ================================================================================================

/// Domain separator pinned to the v1 framework hashing convention. Bump iff the *derivation*
/// changes (different hash, different input layout). Per-precompile evolution is handled by the
/// `version` method.
const APP_ID_DOMSEP: &[u8] = b"miden-deferred-app/v1";

/// Derive a precompile's canonical id from `(name, version)`.
///
/// Inputs are hashed with Blake3; the first 8 bytes of the digest are interpreted as a
/// little-endian `u64` and reduced modulo the Goldilocks prime — giving ~32 bits of
/// birthday-collision resistance, comfortably sufficient for the handful of precompiles a
/// composite schema is expected to host. Used by [`crate::deferred::PrecompileSchema::new`] to
/// validate each precompile's declared [`Precompile::id`].
pub fn precompile_id(p: &dyn Precompile) -> Felt {
    derive(p.name(), p.version())
}

fn derive(name: &str, version: u32) -> Felt {
    let mut hasher = Hasher::new();
    hasher.update(APP_ID_DOMSEP);
    // Length-prefix the name so it is domain-separated from the version suffix.
    hasher.update(&(name.len() as u32).to_le_bytes());
    hasher.update(name.as_bytes());
    hasher.update(&version.to_le_bytes());
    let digest = hasher.finalize();
    let raw = u64::from_le_bytes(digest.as_bytes()[..8].try_into().expect("8 bytes"));
    Felt::new_unchecked(raw % Felt::ORDER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_deterministic() {
        assert_eq!(derive("foo", 1), derive("foo", 1));
    }

    #[test]
    fn id_changes_with_name_and_version() {
        let base = derive("foo", 1);
        assert_ne!(base, derive("bar", 1));
        assert_ne!(base, derive("foo", 2));
    }

    #[test]
    fn id_lies_in_field() {
        // `new_unchecked` is sound only if the value < Felt::ORDER.
        assert!(derive("anything", 0).as_canonical_u64() < Felt::ORDER);
    }
}
