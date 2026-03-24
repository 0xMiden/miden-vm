use alloc::vec::Vec;

use super::{MastNodeEntry, MastNodeInfo};
use crate::{Word, mast::MastNodeId, serde::DeserializationError};

/// Read-only view over serialization-oriented MAST node metadata.
///
/// This trait lives alongside [`super::SerializedMastForest`] because its surface is defined in
/// terms of serialized-equivalent node entries and digests, even though both
/// [`super::SerializedMastForest`] and in-memory [`crate::mast::MastForest`] implement it.
pub trait MastForestView {
    /// Returns the number of nodes in the forest.
    fn node_count(&self) -> usize;

    /// Returns fixed-width structural metadata for a node at the specified index.
    fn node_entry_at(&self, index: usize) -> Result<MastNodeEntry, DeserializationError>;

    /// Returns the digest of the node at the specified index.
    fn node_digest_at(&self, index: usize) -> Result<Word, DeserializationError>;

    /// Returns serialized-equivalent metadata for a node at the specified index.
    fn node_info_at(&self, index: usize) -> Result<MastNodeInfo, DeserializationError> {
        Ok(MastNodeInfo::from_entry(
            self.node_entry_at(index)?,
            self.node_digest_at(index)?,
        ))
    }

    /// Returns the number of procedure roots in the forest.
    fn procedure_root_count(&self) -> usize;

    /// Returns the procedure root id at the specified index.
    fn procedure_root_at(&self, index: usize) -> Result<MastNodeId, DeserializationError>;

    /// Returns true when the forest contains no nodes.
    fn is_empty(&self) -> bool {
        self.node_count() == 0
    }

    /// Returns true when `index` is a valid node index.
    fn has_node(&self, index: usize) -> bool {
        index < self.node_count()
    }

    /// Returns all node infos in index order.
    fn all_node_infos(&self) -> Result<Vec<MastNodeInfo>, DeserializationError> {
        (0..self.node_count()).map(|index| self.node_info_at(index)).collect()
    }

    /// Returns all procedure roots in index order.
    fn procedure_roots(&self) -> Result<Vec<MastNodeId>, DeserializationError> {
        (0..self.procedure_root_count())
            .map(|index| self.procedure_root_at(index))
            .collect()
    }
}
