//! Multi-app composite-schema substrate.
//!
//! An [`App`] is a self-contained semantic module (e.g. `Uint256`, future curve / hash apps)
//! that claims a slice of the 4-felt tag space identified by a stable [`Felt`] `app_id`. The
//! [`PrecompileSchema`] composite dispatches each tag to the right app by `tag[0]`, hands the
//! remaining bits to the app as an [`AppTag`], and forwards `decode` / `reduce`.
//!
//! Tag layout (locked for v1):
//!
//! ```text
//! [app_id, node_disc, imm, ZERO]
//! ```
//!
//! - `app_id` (felt 0) — derived via [`app_id_from`] from app metadata.
//! - `node_disc` (felt 1) — app-local discriminant index (small integer).
//! - `imm` (felt 2) — app-local immediate (e.g. `n_bytes` for chunk apps); `ZERO` if unused.
//! - `tag[3]` — reserved; must be `ZERO` in v1.

use blake3::Hasher;

use super::{ChildResolver, DeferredState, Node, SchemaError, TagInfo};
use crate::Felt;

mod composite;
pub use composite::PrecompileSchema;

mod uint256;
pub use uint256::Uint256;

// APP TAG
// ================================================================================================

/// The app-local portion of a tag — the slice [`PrecompileSchema`] hands to an app after
/// stripping the leading `app_id`. Apps never see `tag[0]` or the reserved `tag[3]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppTag {
    /// App-local discriminant index. Maps to the app's internal node-kind enum.
    pub node_disc: Felt,
    /// App-local immediate. Apps without an immediate ignore this and require `ZERO`.
    pub imm: Felt,
}

// APP TRAIT
// ================================================================================================

/// A single semantic module of a composite schema.
///
/// Apps own a small enum of node-kinds and (optionally) one immediate per tag. They are stitched
/// together into a [`PrecompileSchema`] which implements the framework's
/// [`super::Schema`] trait.
pub trait App: core::fmt::Debug + Send + Sync {
    /// Stable identifier (the first felt of every tag belonging to this app). Derived once from
    /// the app's metadata via [`app_id_from`]; implementations typically memoise the result.
    fn id(&self) -> Felt;

    /// Pre-register canonical constants this app provides (e.g. `ZERO`, `ONE`, generator).
    /// Called by [`PrecompileSchema::boot`]. Default is a no-op for apps without constants.
    fn init(&self, _state: &mut DeferredState) {}

    /// Decode the app-local tag to its [`TagInfo`]. Returning `Err(SchemaError::InvalidNode)`
    /// rejects the tag.
    fn decode(&self, local: AppTag) -> Result<TagInfo, SchemaError>;

    /// Reduce a node owned by this app to canonical form. Same contract as
    /// [`super::Schema::reduce`] — see its docs for the leaf / op / predicate / chunk variants.
    fn reduce(&self, node: &Node, children: &mut dyn ChildResolver) -> Result<Node, SchemaError>;
}

// APP ID DERIVATION
// ================================================================================================

/// Domain separator pinned to the v1 framework hashing convention. Bump iff the *derivation*
/// changes (different hash, different input layout). Per-app evolution is handled by the
/// `version` parameter of [`app_id_from`].
const APP_ID_DOMSEP: &[u8] = b"miden-deferred-app/v1";

/// Derive an app's `app_id` from its metadata.
///
/// Inputs are hashed with Blake3; the first 8 bytes of the digest are interpreted as a
/// little-endian `u64` and reduced modulo the Goldilocks prime — giving ~32 bits of
/// birthday-collision resistance, which is comfortably sufficient for the handful of apps a
/// composite schema is expected to host. The hash mixes:
///
/// - [`APP_ID_DOMSEP`]
/// - `name` — UTF-8 string, length-prefixed.
/// - `version` — `u32`, little-endian; bump on incompatible discriminant changes within an app.
/// - `params` — opaque parameter bytes (e.g. a prime modulus or curve descriptor).
/// - `discriminants` — list of discriminant names, length-prefixed and individually
///   length-prefixed; renaming a discriminant changes the id.
pub fn app_id_from(name: &str, version: u32, params: &[u8], discriminants: &[&str]) -> Felt {
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
        let a = app_id_from("foo", 1, b"params", &["x", "y"]);
        let b = app_id_from("foo", 1, b"params", &["x", "y"]);
        assert_eq!(a, b);
    }

    #[test]
    fn app_id_changes_with_each_input() {
        let base = app_id_from("foo", 1, b"params", &["x", "y"]);
        assert_ne!(base, app_id_from("bar", 1, b"params", &["x", "y"]));
        assert_ne!(base, app_id_from("foo", 2, b"params", &["x", "y"]));
        assert_ne!(base, app_id_from("foo", 1, b"params2", &["x", "y"]));
        assert_ne!(base, app_id_from("foo", 1, b"params", &["x"]));
        assert_ne!(base, app_id_from("foo", 1, b"params", &["x", "z"]));
    }

    #[test]
    fn app_id_lies_in_field() {
        // `new_unchecked` is sound only if the value < Felt::ORDER.
        let id = app_id_from("anything", 0, &[], &[]);
        assert!(id.as_canonical_u64() < Felt::ORDER);
    }
}
