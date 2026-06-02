use alloc::{boxed::Box, vec::Vec};
use core::{
    fmt,
    ops::{Deref, DerefMut},
};

use crate::{
    Word,
    merkle::{
        NodeIndex,
        smt::{InnerNode, Map, SmtLeaf, large::subtree::Subtree},
    },
};

mod error;
pub use error::{StorageError, StorageResult};

#[cfg(feature = "rocksdb")]
mod rocksdb;
#[cfg(feature = "rocksdb")]
pub use rocksdb::{RocksDbConfig, RocksDbSnapshotStorage, RocksDbStorage};

mod memory;
pub use memory::{MemoryStorage, MemoryStorageSnapshot};

mod updates;
pub use updates::{StorageUpdateParts, StorageUpdates, SubtreeUpdate};

pub type BoxedFallibleLeafIterator<'a> =
    Box<dyn Iterator<Item = StorageResult<(u64, SmtLeaf)>> + 'a>;

// SMT STORAGE READER
// ================================================================================================

/// Read-only operations for the Sparse Merkle Tree storage backend.
///
/// This trait outlines the operations required to retrieve the components of an SMT: leaves and
/// deeper subtrees. Implementations of this trait can provide various storage solutions, like
/// in-memory maps or persistent databases (e.g., RocksDB).
///
/// All methods are expected to handle potential storage errors by returning a
/// `Result<_, StorageError>`.
///
/// Implementations used as [`SmtStorage::Reader`] must be point-in-time snapshots. This is required
/// because `LargeSmt::reader()` copies the in-memory portion of the tree and pairs it with the
/// returned storage reader.
pub trait SmtStorageReader: 'static + fmt::Debug + Send + Sync {
    /// Retrieves the total number of leaf nodes currently stored.
    ///
    /// # Errors
    /// Returns `StorageError` if the storage read operation fails.
    fn leaf_count(&self) -> StorageResult<usize>;

    /// Retrieves the total number of unique key-value entries across all leaf nodes.
    ///
    /// # Errors
    /// Returns `StorageError` if the storage read operation fails.
    fn entry_count(&self) -> StorageResult<usize>;

    /// Retrieves a single SMT leaf node by its logical `index`.
    /// Returns `Ok(None)` if no leaf exists at the given `index`.
    fn get_leaf(&self, index: u64) -> StorageResult<Option<SmtLeaf>>;

    /// Retrieves multiple SMT leaf nodes by their logical `indices`.
    ///
    /// The returned `Vec` will have the same length as the input `indices` slice.
    /// For each `index` in the input, the corresponding element in the output `Vec`
    /// will be `Some(SmtLeaf)` if found, or `None` if not found.
    fn get_leaves(&self, indices: &[u64]) -> StorageResult<Vec<Option<SmtLeaf>>>;

    /// Returns true if the storage has any leaves.
    ///
    /// # Errors
    /// Returns `StorageError` if the storage read operation fails.
    fn has_leaves(&self) -> StorageResult<bool>;

    /// Retrieves a single SMT Subtree by its root `NodeIndex`.
    ///
    /// Subtrees typically represent deeper, compacted parts of the SMT.
    /// Returns `Ok(None)` if no subtree is found for the given `index`.
    fn get_subtree(&self, index: NodeIndex) -> StorageResult<Option<Subtree>>;

    /// Retrieves multiple Subtrees by their root `NodeIndex` values.
    ///
    /// The returned `Vec` will have the same length as the input `indices` slice.
    /// For each `index` in the input, the corresponding element in the output `Vec`
    /// will be `Some(Subtree)` if found, or `None` if not found.
    fn get_subtrees(&self, indices: &[NodeIndex]) -> StorageResult<Vec<Option<Subtree>>>;

    /// Retrieves a single leaf and multiple subtrees in one call.
    ///
    /// The default implementation delegates to [`Self::get_leaf`] and [`Self::get_subtree`].
    /// Backends can override this with a more-optimized implementation if one is available. This
    /// default implementation does not employ parallelism, and hence may be slower than separately
    /// issuing [`Self::get_leaf`] and [`Self::get_subtrees`] for large numbers of subtrees.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Backend`] if the backing storage cannot be accessed during the query.
    fn get_leaf_and_subtrees(
        &self,
        leaf_index: u64,
        subtree_indices: &[NodeIndex],
    ) -> StorageResult<(Option<SmtLeaf>, Vec<Option<Subtree>>)> {
        let leaf = self.get_leaf(leaf_index)?;

        // We explicitly do NOT want to delegate to `get_subtrees` here as it can be a very heavy
        // hammer. We instead use the simplest solution that has no potential for unpredictable
        // performance, even if it is slower for large numbers of subtrees.
        let subtrees = subtree_indices
            .iter()
            .map(|&idx| self.get_subtree(idx))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((leaf, subtrees))
    }

    /// Retrieves a single inner node from within a Subtree.
    ///
    /// This method is intended for accessing nodes at depths greater than the in-memory horizon.
    /// Returns `Ok(None)` if the containing Subtree or the specific inner node is not found.
    fn get_inner_node(&self, index: NodeIndex) -> StorageResult<Option<InnerNode>>;

    /// Returns an iterator over all `(logical_index, SmtLeaf)` pairs currently in storage.
    ///
    /// The returned iterator is fallible: each item is a
    /// [`crate::merkle::smt::StorageResult`] so backends can report per-element read or
    /// deserialization failures encountered after iterator creation.
    ///
    /// The order of iteration is not guaranteed unless specified by the implementation.
    fn iter_leaves(&self) -> StorageResult<BoxedFallibleLeafIterator<'_>>;

    /// Returns an iterator over all `Subtree` instances currently in storage.
    ///
    /// The returned iterator is fallible: each item is a
    /// [`crate::merkle::smt::StorageResult`] so backends can report per-element read or
    /// deserialization failures encountered after iterator creation.
    ///
    /// The order of iteration is not guaranteed unless specified by the implementation.
    fn iter_subtrees(&self)
    -> StorageResult<Box<dyn Iterator<Item = StorageResult<Subtree>> + '_>>;

    /// Retrieves roots of all top level subtrees for efficient startup reconstruction.
    ///
    /// Returns a vector of `(node_index_value, Word)` tuples representing the roots of nodes at
    /// `IN_MEMORY_DEPTH` (the in-memory/storage boundary). These roots enable fast reconstruction
    /// of the upper tree without loading entire subtrees.
    ///
    /// The hash cache is automatically maintained by subtree operations - no manual cache
    /// management is required.
    fn get_top_subtree_roots(&self) -> StorageResult<Vec<(u64, Word)>>;
}

impl<T: SmtStorageReader + ?Sized> SmtStorageReader for Box<T> {
    #[inline]
    fn leaf_count(&self) -> StorageResult<usize> {
        self.deref().leaf_count()
    }

    #[inline]
    fn entry_count(&self) -> StorageResult<usize> {
        self.deref().entry_count()
    }

    #[inline]
    fn get_leaf(&self, index: u64) -> StorageResult<Option<SmtLeaf>> {
        self.deref().get_leaf(index)
    }

    #[inline]
    fn get_leaves(&self, indices: &[u64]) -> StorageResult<Vec<Option<SmtLeaf>>> {
        self.deref().get_leaves(indices)
    }

    #[inline]
    fn has_leaves(&self) -> StorageResult<bool> {
        self.deref().has_leaves()
    }

    #[inline]
    fn get_subtree(&self, index: NodeIndex) -> StorageResult<Option<Subtree>> {
        self.deref().get_subtree(index)
    }

    #[inline]
    fn get_subtrees(&self, indices: &[NodeIndex]) -> StorageResult<Vec<Option<Subtree>>> {
        self.deref().get_subtrees(indices)
    }

    #[inline]
    fn get_leaf_and_subtrees(
        &self,
        leaf_index: u64,
        subtree_indices: &[NodeIndex],
    ) -> StorageResult<(Option<SmtLeaf>, Vec<Option<Subtree>>)> {
        self.deref().get_leaf_and_subtrees(leaf_index, subtree_indices)
    }

    #[inline]
    fn get_inner_node(&self, index: NodeIndex) -> StorageResult<Option<InnerNode>> {
        self.deref().get_inner_node(index)
    }

    #[inline]
    fn iter_leaves(&self) -> StorageResult<BoxedFallibleLeafIterator<'_>> {
        self.deref().iter_leaves()
    }

    #[inline]
    fn iter_subtrees(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = StorageResult<Subtree>> + '_>> {
        self.deref().iter_subtrees()
    }

    #[inline]
    fn get_top_subtree_roots(&self) -> StorageResult<Vec<(u64, Word)>> {
        self.deref().get_top_subtree_roots()
    }
}

// SMT STORAGE
// ================================================================================================

/// Sparse Merkle Tree storage backend with full read and write capabilities.
///
/// This trait extends [`SmtStorageReader`] with the mutation operations required to persist changes
/// to the SMT.
///
/// All methods are expected to handle potential storage errors by returning a
/// `Result<_, StorageError>`.
pub trait SmtStorage: SmtStorageReader {
    /// The read-only view type returned by [`Self::reader`].
    type Reader: SmtStorageReader;

    /// Returns a read-only snapshot of this storage at its current committed state.
    ///
    /// The returned value is used to construct a read-only `LargeSmt` (via
    /// [`super::LargeSmt::reader`]) from a writable one. Implementations are responsible for
    /// ensuring that the returned reader remains consistent with `self` at the time of the call.
    ///
    /// Implementations must return a point-in-time snapshot. Later writes through `self` must not
    /// affect the returned reader. Holding the reader must not block writes in any way.
    fn reader(&self) -> StorageResult<Self::Reader>;

    /// Inserts a key-value pair into the SMT leaf at the specified logical `index`.
    ///
    /// - If the leaf at `index` does not exist, it may be created.
    /// - If the `key` already exists in the leaf at `index`, its `value` is updated.
    /// - Returns the previous `Word` value associated with the `key` at `index`, if any.
    ///
    /// Implementations are responsible for updating overall leaf and entry counts if necessary.
    ///
    /// Note: This only updates the leaf. Callers are responsible for recomputing and
    /// persisting the corresponding inner nodes.
    ///
    /// # Errors
    /// Returns `StorageError` if the storage operation fails (e.g., backend database error,
    /// insufficient space, serialization failures).
    fn insert_value(&mut self, index: u64, key: Word, value: Word) -> StorageResult<Option<Word>>;

    /// Removes a key-value pair from the SMT leaf at the specified logical `index`.
    ///
    /// - If the `key` is found in the leaf at `index`, it is removed, and the old `Word` value is
    ///   returned.
    /// - If the leaf at `index` does not exist, or if the `key` is not found within it, `Ok(None)`
    ///   is returned.
    /// - If removing the entry causes the leaf to become empty, the behavior regarding the leaf
    ///   node itself (e.g., whether it's removed from storage) is implementation-dependent, but
    ///   counts should be updated.
    ///
    /// Implementations are responsible for updating overall leaf and entry counts if necessary.
    ///
    /// Note: This only updates the leaf. Callers are responsible for recomputing and
    /// persisting the corresponding inner nodes.
    ///
    /// # Errors
    /// Returns `StorageError` if the storage operation fails (e.g., backend database error,
    /// write permission issues, serialization failures).
    fn remove_value(&mut self, index: u64, key: Word) -> StorageResult<Option<Word>>;

    /// Sets or updates multiple SMT leaf nodes in storage.
    ///
    /// For each entry in the `leaves` map, if a leaf at the given index already exists,
    /// it should be overwritten with the new `SmtLeaf` data.
    /// If it does not exist, a new leaf is stored.
    ///
    /// Note: This only updates the leaves. Callers are responsible for recomputing and
    /// persisting the corresponding inner nodes.
    ///
    /// # Errors
    /// Returns `StorageError` if any storage operation fails during the batch update.
    fn set_leaves(&mut self, leaves: Map<u64, SmtLeaf>) -> StorageResult<()>;

    /// Removes a single SMT leaf node entirely from storage by its logical `index`.
    ///
    /// Note: This only removes the leaf. Callers are responsible for recomputing and
    /// persisting the corresponding inner nodes.
    ///
    /// Returns the `SmtLeaf` that was removed, or `Ok(None)` if no leaf existed at `index`.
    /// Implementations should ensure that removing a leaf also correctly updates
    /// the overall leaf and entry counts.
    fn remove_leaf(&mut self, index: u64) -> StorageResult<Option<SmtLeaf>>;

    /// Sets or updates a single SMT Subtree in storage, identified by its root `NodeIndex`.
    ///
    /// If a subtree with the same root `NodeIndex` already exists, it is overwritten.
    fn set_subtree(&mut self, subtree: &Subtree) -> StorageResult<()>;

    /// Sets or updates multiple SMT Subtrees in storage.
    ///
    /// For each `Subtree` in the `subtrees` vector, if a subtree with the same root `NodeIndex`
    /// already exists, it is overwritten.
    fn set_subtrees(&mut self, subtrees: Vec<Subtree>) -> StorageResult<()>;

    /// Removes a single SMT Subtree from storage, identified by its root `NodeIndex`.
    ///
    /// Returns `Ok(())` on successful removal or if the subtree did not exist.
    fn remove_subtree(&mut self, index: NodeIndex) -> StorageResult<()>;

    /// Sets or updates a single inner node (non-leaf node) within a Subtree.
    ///
    /// - If the target Subtree does not exist, it might need to be created by the implementation.
    /// - Returns the `InnerNode` that was previously at this `index`, if any.
    fn set_inner_node(
        &mut self,
        index: NodeIndex,
        node: InnerNode,
    ) -> StorageResult<Option<InnerNode>>;

    /// Removes a single inner node (non-leaf node) from within a Subtree.
    ///
    /// - If the Subtree becomes empty after removing the node, the Subtree itself might be removed
    ///   by the storage implementation.
    /// - Returns the `InnerNode` that was removed, if any.
    fn remove_inner_node(&mut self, index: NodeIndex) -> StorageResult<Option<InnerNode>>;

    /// Applies a batch of `StorageUpdates` atomically to the storage backend.
    ///
    /// This is the primary method for persisting changes to the SMT. Implementations must ensure
    /// that all updates within the `StorageUpdates` struct (leaf changes, subtree changes,
    /// new root hash, and count deltas) are applied as a single, indivisible operation.
    /// If any part of the update fails, the entire transaction should be rolled back, leaving
    /// the storage in its previous state.
    fn apply(&mut self, updates: StorageUpdates) -> StorageResult<()>;
}

impl<T: SmtStorage + ?Sized> SmtStorage for Box<T> {
    type Reader = T::Reader;

    #[inline]
    fn reader(&self) -> StorageResult<Self::Reader> {
        self.deref().reader()
    }

    #[inline]
    fn insert_value(&mut self, index: u64, key: Word, value: Word) -> StorageResult<Option<Word>> {
        self.deref_mut().insert_value(index, key, value)
    }

    #[inline]
    fn remove_value(&mut self, index: u64, key: Word) -> StorageResult<Option<Word>> {
        self.deref_mut().remove_value(index, key)
    }

    #[inline]
    fn set_leaves(&mut self, leaves: Map<u64, SmtLeaf>) -> StorageResult<()> {
        self.deref_mut().set_leaves(leaves)
    }

    #[inline]
    fn remove_leaf(&mut self, index: u64) -> StorageResult<Option<SmtLeaf>> {
        self.deref_mut().remove_leaf(index)
    }

    #[inline]
    fn set_subtree(&mut self, subtree: &Subtree) -> StorageResult<()> {
        self.deref_mut().set_subtree(subtree)
    }

    #[inline]
    fn set_subtrees(&mut self, subtrees: Vec<Subtree>) -> StorageResult<()> {
        self.deref_mut().set_subtrees(subtrees)
    }

    #[inline]
    fn remove_subtree(&mut self, index: NodeIndex) -> StorageResult<()> {
        self.deref_mut().remove_subtree(index)
    }

    #[inline]
    fn set_inner_node(
        &mut self,
        index: NodeIndex,
        node: InnerNode,
    ) -> StorageResult<Option<InnerNode>> {
        self.deref_mut().set_inner_node(index, node)
    }

    #[inline]
    fn remove_inner_node(&mut self, index: NodeIndex) -> StorageResult<Option<InnerNode>> {
        self.deref_mut().remove_inner_node(index)
    }

    #[inline]
    fn apply(&mut self, updates: StorageUpdates) -> StorageResult<()> {
        self.deref_mut().apply(updates)
    }
}
