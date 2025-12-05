use alloc::vec::Vec;

use miden_crypto::hash::{
    Digest,
    blake::{Blake3_256, Blake3Digest},
};

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
    let pre_decorator_hash_bytes =
        before_enter_ids.iter().flat_map(|&id| forest[id].fingerprint().as_bytes());
    let post_decorator_hash_bytes =
        after_exit_ids.iter().flat_map(|&id| forest[id].fingerprint().as_bytes());

    let children_decorator_roots = children_ids
        .iter()
        .filter_map(|child_id| {
            hash_by_node_id
                .get(*child_id)
                .ok_or(MastForestError::ChildFingerprintMissing(*child_id))
                .map(|child_fingerprint| child_fingerprint.decorator_root)
                .transpose()
        })
        .collect::<Result<Vec<DecoratorFingerprint>, MastForestError>>()?;

    // Reminder: the `MastNodeFingerprint`'s decorator root will be `None` if and only if there are
    // no decorators attached to the node, and all children have no decorator roots (meaning
    // that there are no decorators in all the descendants).
    if pre_decorator_hash_bytes.clone().next().is_none()
        && post_decorator_hash_bytes.clone().next().is_none()
        && children_decorator_roots.is_empty()
    {
        Ok(MastNodeFingerprint::new(node_digest))
    } else {
        let decorator_bytes_to_hash: Vec<u8> = pre_decorator_hash_bytes
            .chain(post_decorator_hash_bytes)
            .chain(
                children_decorator_roots
                    .into_iter()
                    .flat_map(|decorator_root| decorator_root.as_bytes()),
            )
            .collect();

        let decorator_root = Blake3_256::hash(&decorator_bytes_to_hash);
        Ok(MastNodeFingerprint::with_decorator_root(node_digest, decorator_root))
    }
}

// TESTS
// ================================================================================================
