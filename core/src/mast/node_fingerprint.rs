use alloc::vec::Vec;

use crate::{
    Word,
    crypto::hash::{Blake3_256, Blake3Digest},
    mast::{MastForestError, MastNodeId},
    utils::LookupByIdx,
};

// MAST NODE EQUALITY
// ================================================================================================

pub type MetadataFingerprint = Blake3Digest<32>;

/// Represents the hash used to test for equality between [`crate::mast::MastNode`]s.
///
/// The metadata root is `None` if the node and all descendants have no metadata that should affect
/// deduplication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MastNodeFingerprint {
    mast_root: Word,
    metadata_root: Option<MetadataFingerprint>,
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl MastNodeFingerprint {
    /// Creates a new [`MastNodeFingerprint`] from the given MAST root with an empty metadata root.
    pub fn new(mast_root: Word) -> Self {
        Self { mast_root, metadata_root: None }
    }

    /// Creates a new [`MastNodeFingerprint`] from the given MAST root and the given
    /// [`MetadataFingerprint`].
    pub fn with_metadata_root(mast_root: Word, metadata_root: MetadataFingerprint) -> Self {
        Self {
            mast_root,
            metadata_root: Some(metadata_root),
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
    hash_by_node_id: &impl LookupByIdx<MastNodeId, MastNodeFingerprint>,
    children_ids: &[MastNodeId],
    node_digest: Word,
) -> Result<MastNodeFingerprint, MastForestError> {
    let children_metadata_roots: Vec<[u8; 32]> = {
        let mut roots = Vec::new();
        for child_id in children_ids {
            if let Some(child_fingerprint) = hash_by_node_id.get(*child_id) {
                if let Some(metadata_root) = child_fingerprint.metadata_root {
                    roots.push(*metadata_root.as_bytes());
                }
            } else {
                return Err(MastForestError::ChildFingerprintMissing(*child_id));
            }
        }
        roots
    };

    if children_metadata_roots.is_empty() {
        Ok(MastNodeFingerprint::new(node_digest))
    } else {
        let metadata_bytes_iter = children_metadata_roots.iter().map(<[u8; 32]>::as_slice);

        let metadata_root = Blake3_256::hash_iter(metadata_bytes_iter);
        Ok(MastNodeFingerprint::with_metadata_root(node_digest, metadata_root))
    }
}

// TESTS
// ================================================================================================
