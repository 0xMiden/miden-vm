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

use blake3::Hasher;

use super::{DeferredState, Node, ReduceCtx, SchemaError, TagInfo};
use crate::Felt;

// PRECOMPILE TAG
// ================================================================================================

/// The precompile-local portion of a tag — the slice [`crate::deferred::PrecompileSchema`] hands
/// to a precompile after stripping the leading id. Precompiles never see `tag[0]` or the
/// reserved `tag[3]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecompileTag {
    /// Precompile-local discriminant index. Maps to the precompile's internal node-kind enum.
    pub node_disc: Felt,
    /// Precompile-local immediate. Precompiles without an immediate ignore this and require `ZERO`.
    pub imm: Felt,
}

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

    /// Discriminant names hashed into the precompile id.
    ///
    /// Transitional: removed at step 4, when [`precompile_id`] drops to hashing only
    /// `(name, version)`.
    fn discriminants(&self) -> &'static [&'static str];

    /// Pinned id (the first felt of every tag belonging to this precompile). Implementors
    /// return the precomputed value; [`crate::deferred::PrecompileSchema::new`] validates it
    /// equals [`precompile_id`], panicking on drift. No default — the value/derivation bridge
    /// is the validator's hook.
    fn id(&self) -> Felt;

    /// Pre-register canonical constants this precompile provides (e.g. `ZERO`, `ONE`,
    /// generator). Called by [`crate::deferred::PrecompileSchema::boot`]. Default is a no-op.
    fn init(&self, _state: &mut DeferredState) {}

    /// Decode the precompile-local tag to its [`TagInfo`]. Returning
    /// `Err(SchemaError::InvalidNode)` rejects the tag.
    fn decode(&self, local: PrecompileTag) -> Result<TagInfo, SchemaError>;

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

/// Derive a precompile's canonical id from its metadata.
///
/// Inputs are hashed with Blake3; the first 8 bytes of the digest are interpreted as a
/// little-endian `u64` and reduced modulo the Goldilocks prime — giving ~32 bits of
/// birthday-collision resistance, comfortably sufficient for the handful of precompiles a
/// composite schema is expected to host. Used by [`crate::deferred::PrecompileSchema::new`] to
/// validate each precompile's declared [`Precompile::id`].
pub fn precompile_id(p: &dyn Precompile) -> Felt {
    derive_app_id(p.name(), p.version(), &[], p.discriminants())
}

/// Internal byte-exact derivation shared by [`precompile_id`]. The `params` slice is currently
/// always empty (no precompile mixes parameter bytes); kept as an argument so the hashed byte
/// layout is unchanged from the pre-refactor `app_id_from`.
fn derive_app_id(name: &str, version: u32, params: &[u8], discriminants: &[&str]) -> Felt {
    let mut hasher = Hasher::new();
    hasher.update(APP_ID_DOMSEP);
    hash_bytes(&mut hasher, name.as_bytes());
    hasher.update(&version.to_le_bytes());
    hash_bytes(&mut hasher, params);
    hasher.update(&(discriminants.len() as u32).to_le_bytes());
    for d in discriminants {
        hash_bytes(&mut hasher, d.as_bytes());
    }
    let digest = hasher.finalize();
    let raw = u64::from_le_bytes(digest.as_bytes()[..8].try_into().expect("8 bytes"));
    Felt::new_unchecked(raw % Felt::ORDER)
}

fn hash_bytes(hasher: &mut Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u32).to_le_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_id_is_deterministic() {
        let a = derive_app_id("foo", 1, b"params", &["x", "y"]);
        let b = derive_app_id("foo", 1, b"params", &["x", "y"]);
        assert_eq!(a, b);
    }

    #[test]
    fn app_id_changes_with_each_input() {
        let base = derive_app_id("foo", 1, b"params", &["x", "y"]);
        assert_ne!(base, derive_app_id("bar", 1, b"params", &["x", "y"]));
        assert_ne!(base, derive_app_id("foo", 2, b"params", &["x", "y"]));
        assert_ne!(base, derive_app_id("foo", 1, b"params2", &["x", "y"]));
        assert_ne!(base, derive_app_id("foo", 1, b"params", &["x"]));
        assert_ne!(base, derive_app_id("foo", 1, b"params", &["x", "z"]));
    }

    #[test]
    fn app_id_lies_in_field() {
        // `new_unchecked` is sound only if the value < Felt::ORDER.
        let id = derive_app_id("anything", 0, &[], &[]);
        assert!(id.as_canonical_u64() < Felt::ORDER);
    }
}
