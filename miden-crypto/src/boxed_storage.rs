//! Adapter used only by the `miden-crypto` executable benchmark.
//!
//! The executable chooses memory or RocksDB storage at runtime. This wrapper erases the concrete
//! storage type while preserving the associated reader type needed by `SmtStorage`.

use miden_crypto::{
    Map, Word,
    merkle::smt::{InnerNode, SmtLeaf, SmtStorage, SmtStorageReader, StorageError, StorageUpdates},
};

pub(crate) type BoxedSmtStorage = Box<dyn SmtStorage<Reader = Box<dyn SmtStorageReader>>>;

#[derive(Debug)]
pub(crate) struct BoxedStorage<T>(pub(crate) T);

impl<T: SmtStorageReader> SmtStorageReader for BoxedStorage<T> {
    fn leaf_count(&self) -> Result<usize, StorageError> {
        self.0.leaf_count()
    }
    fn entry_count(&self) -> Result<usize, StorageError> {
        self.0.entry_count()
    }
    fn get_leaf(&self, index: u64) -> Result<Option<SmtLeaf>, StorageError> {
        self.0.get_leaf(index)
    }
    fn get_leaves(&self, indices: &[u64]) -> Result<Vec<Option<SmtLeaf>>, StorageError> {
        self.0.get_leaves(indices)
    }
    fn has_leaves(&self) -> Result<bool, StorageError> {
        self.0.has_leaves()
    }
    fn get_subtree(
        &self,
        index: miden_crypto::merkle::NodeIndex,
    ) -> Result<Option<miden_crypto::merkle::smt::Subtree>, StorageError> {
        self.0.get_subtree(index)
    }
    fn get_subtrees(
        &self,
        indices: &[miden_crypto::merkle::NodeIndex],
    ) -> Result<Vec<Option<miden_crypto::merkle::smt::Subtree>>, StorageError> {
        self.0.get_subtrees(indices)
    }
    fn get_leaf_and_subtrees(
        &self,
        leaf_index: u64,
        subtree_indices: &[miden_crypto::merkle::NodeIndex],
    ) -> Result<(Option<SmtLeaf>, Vec<Option<miden_crypto::merkle::smt::Subtree>>), StorageError>
    {
        self.0.get_leaf_and_subtrees(leaf_index, subtree_indices)
    }
    fn get_inner_node(
        &self,
        index: miden_crypto::merkle::NodeIndex,
    ) -> Result<Option<InnerNode>, StorageError> {
        self.0.get_inner_node(index)
    }
    fn iter_leaves(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Result<(u64, SmtLeaf), StorageError>> + '_>, StorageError>
    {
        self.0.iter_leaves()
    }
    fn iter_subtrees(
        &self,
    ) -> Result<
        Box<dyn Iterator<Item = Result<miden_crypto::merkle::smt::Subtree, StorageError>> + '_>,
        StorageError,
    > {
        self.0.iter_subtrees()
    }
    fn get_top_subtree_roots(&self) -> Result<Vec<(u64, Word)>, StorageError> {
        self.0.get_top_subtree_roots()
    }
}

impl<T: SmtStorage> SmtStorage for BoxedStorage<T> {
    type Reader = Box<dyn SmtStorageReader>;

    fn reader(&self) -> Result<Self::Reader, StorageError> {
        Ok(Box::new(BoxedStorage(self.0.reader()?)))
    }
    fn insert_value(
        &mut self,
        index: u64,
        key: Word,
        value: Word,
    ) -> Result<Option<Word>, StorageError> {
        self.0.insert_value(index, key, value)
    }
    fn remove_value(&mut self, index: u64, key: Word) -> Result<Option<Word>, StorageError> {
        self.0.remove_value(index, key)
    }
    fn set_leaves(&mut self, leaves: Map<u64, SmtLeaf>) -> Result<(), StorageError> {
        self.0.set_leaves(leaves)
    }
    fn remove_leaf(&mut self, index: u64) -> Result<Option<SmtLeaf>, StorageError> {
        self.0.remove_leaf(index)
    }
    fn set_subtree(
        &mut self,
        subtree: &miden_crypto::merkle::smt::Subtree,
    ) -> Result<(), StorageError> {
        self.0.set_subtree(subtree)
    }
    fn set_subtrees(
        &mut self,
        subtrees: Vec<miden_crypto::merkle::smt::Subtree>,
    ) -> Result<(), StorageError> {
        self.0.set_subtrees(subtrees)
    }
    fn remove_subtree(
        &mut self,
        index: miden_crypto::merkle::NodeIndex,
    ) -> Result<(), StorageError> {
        self.0.remove_subtree(index)
    }
    fn set_inner_node(
        &mut self,
        index: miden_crypto::merkle::NodeIndex,
        node: InnerNode,
    ) -> Result<Option<InnerNode>, StorageError> {
        self.0.set_inner_node(index, node)
    }
    fn remove_inner_node(
        &mut self,
        index: miden_crypto::merkle::NodeIndex,
    ) -> Result<Option<InnerNode>, StorageError> {
        self.0.remove_inner_node(index)
    }
    fn apply(&mut self, updates: StorageUpdates) -> Result<(), StorageError> {
        self.0.apply(updates)
    }
}
