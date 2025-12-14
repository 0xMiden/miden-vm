use alloc::vec::Vec;

use miden_crypto::hash::blake::{Blake3_256, Blake3Digest};

use crate::{
    LookupByIdx, Word,
    mast::{DecoratorId, MastForest, MastForestError, MastNodeId},
};

// MAST NODE EQUALITY
// ================================================================================================

pub type DecoratorFingerprint = Blake3Digest<32>;

/// Represents the hash used to test for equality between [`crate::mast::MastNode`]s.
///
/// The decorator root will be `None` if and only if there are no decorators attached to the node,
/// and all children have no decorator roots (meaning that there are no decorators in all the
/// descendants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MastNodeFingerprint {
    mast_root: Word,
    decorator_root: Option<DecoratorFingerprint>,
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl MastNodeFingerprint {
    /// Creates a new [`MastNodeFingerprint`] from the given MAST root with an empty decorator root.
    pub fn new(mast_root: Word) -> Self {
        Self { mast_root, decorator_root: None }
    }

    /// Creates a new [`MastNodeFingerprint`] from the given MAST root and the given
    /// [`DecoratorFingerprint`].
    pub fn with_decorator_root(mast_root: Word, decorator_root: DecoratorFingerprint) -> Self {
        Self {
            mast_root,
            decorator_root: Some(decorator_root),
        }
    }
}

// ------------------------------------------------------------------------------------------------
/// Accessors
impl MastNodeFingerprint {
    pub fn mast_root(&self) -> &Word {
        &self.mast_root
    }
}

pub fn fingerprint_from_parts(
    forest: &MastForest,
    hash_by_node_id: &impl LookupByIdx<MastNodeId, MastNodeFingerprint>,
    before_enter_ids: &[DecoratorId],
    after_exit_ids: &[DecoratorId],
    children_ids: &[MastNodeId],
    node_digest: Word,
) -> Result<MastNodeFingerprint, MastForestError> {
    let pre_decorator_hash_bytes: Vec<[u8; 32]> =
        before_enter_ids.iter().map(|&id| forest[id].fingerprint().as_bytes()).collect();
    let post_decorator_hash_bytes: Vec<[u8; 32]> =
        after_exit_ids.iter().map(|&id| forest[id].fingerprint().as_bytes()).collect();

    let children_decorator_roots: Vec<[u8; 32]> = {
        let mut roots = Vec::new();
        for child_id in children_ids {
            if let Some(child_fingerprint) = hash_by_node_id.get(*child_id) {
                if let Some(decorator_root) = child_fingerprint.decorator_root {
                    roots.push(decorator_root.as_bytes());
                }
            } else {
                return Err(MastForestError::ChildFingerprintMissing(*child_id));
            }
        }
        roots
    };

    // Reminder: the `MastNodeFingerprint`'s decorator root will be `None` if and only if there are
    // no decorators attached to the node, and all children have no decorator roots (meaning
    // that there are no decorators in all the descendants).
    if pre_decorator_hash_bytes.is_empty()
        && post_decorator_hash_bytes.is_empty()
        && children_decorator_roots.is_empty()
    {
        Ok(MastNodeFingerprint::new(node_digest))
    } else {
        let decorator_bytes_iter = pre_decorator_hash_bytes
            .iter()
            .map(|bytes| bytes.as_slice())
            .chain(post_decorator_hash_bytes.iter().map(|bytes| bytes.as_slice()))
            .chain(children_decorator_roots.iter().map(|bytes| bytes.as_slice()));

        let decorator_root = Blake3_256::hash_iter(decorator_bytes_iter);
        Ok(MastNodeFingerprint::with_decorator_root(node_digest, decorator_root))
    }
}

// TESTS
// ================================================================================================
