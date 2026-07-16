//! This module contains the definition of the [`ForestOperation`] type that encapsulates the
//! possible modifications made to a tree, as well as the concept of a [`SmtUpdateBatch`] of
//! operations to be performed on a single tree in the forest. This is then extended to
//! [`SmtForestUpdateBatch`], which defines a batch of operations across multiple trees.

use alloc::vec::Vec;

use crate::{EMPTY_WORD, Map, Set, Word, merkle::smt::large_forest::root::LineageId};

// FOREST OPERATION
// ================================================================================================

/// The operations that can be performed on an arbitrary leaf in a tree in a forest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SmtForestOperation {
    /// An insertion of `value` under `key` into the tree.
    ///
    /// If `key` already exists in the tree, the associated value will be replaced with `value`
    /// instead.
    Insert { key: Word, value: Word },

    /// The removal of the `key` and its associated value from the tree.
    Remove { key: Word },
}
impl SmtForestOperation {
    /// Insert the provided `value` into a tree under the provided `key`.
    pub fn insert(key: Word, value: Word) -> Self {
        Self::Insert { key, value }
    }

    /// Remove the provided `key` and its associated value from a tree.
    pub fn remove(key: Word) -> Self {
        Self::Remove { key }
    }

    /// Retrieves the key from the operation.
    pub fn key(&self) -> Word {
        match self {
            SmtForestOperation::Insert { key, .. } => *key,
            SmtForestOperation::Remove { key } => *key,
        }
    }
}

impl From<SmtForestOperation> for (Word, Word) {
    fn from(value: SmtForestOperation) -> Self {
        match value {
            SmtForestOperation::Insert { key, value } => (key, value),
            SmtForestOperation::Remove { key } => (key, EMPTY_WORD),
        }
    }
}

// TREE BATCH
// ================================================================================================

/// A batch of operations that can be performed on an arbitrary tree in a forest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtUpdateBatch {
    /// The operations to be performed on a tree.
    operations: Vec<SmtForestOperation>,
}
impl SmtUpdateBatch {
    /// Creates an empty batch of operations.
    pub fn empty() -> Self {
        Self { operations: vec![] }
    }

    /// Creates a batch containing the provided `operations`.
    pub fn new(operations: impl Iterator<Item = SmtForestOperation>) -> Self {
        Self {
            operations: operations.collect::<Vec<_>>(),
        }
    }

    /// Adds the provided `operations` to the batch.
    pub fn add_operations(&mut self, operations: impl Iterator<Item = SmtForestOperation>) {
        self.operations.extend(operations);
    }

    /// Adds the [`SmtForestOperation::Insert`] operation for the provided `key` and `value` pair to
    /// the batch.
    pub fn add_insert(&mut self, key: Word, value: Word) {
        self.operations.push(SmtForestOperation::insert(key, value));
    }

    /// Adds the [`SmtForestOperation::Remove`] operation for the provided `key` to the batch.
    pub fn add_remove(&mut self, key: Word) {
        self.operations.push(SmtForestOperation::remove(key));
    }

    /// Consumes the batch as a vector of operations, containing the last operation for any given
    /// `key` in the case that multiple operations per key are encountered.
    ///
    /// This vector is guaranteed to be sorted by the key on which an operation is performed.
    pub fn consume(self) -> Vec<SmtForestOperation> {
        // As we want to keep the LAST operation for each key, rather than the first, we filter in
        // reverse.
        let mut seen_keys: Set<Word> = Set::new();
        let mut ops = self
            .operations
            .into_iter()
            .rev()
            .filter(|o| seen_keys.insert(o.key()))
            .collect::<Vec<_>>();
        ops.sort_by_key(SmtForestOperation::key);
        ops
    }
}

impl IntoIterator for SmtUpdateBatch {
    type Item = SmtForestOperation;
    type IntoIter = alloc::vec::IntoIter<Self::Item>;

    /// Consumes the batch as an iterator yielding operations while respecting the guarantees given
    /// by [`Self::consume`].
    ///
    /// The iteration order is unspecified.
    fn into_iter(self) -> Self::IntoIter {
        self.consume().into_iter()
    }
}

impl From<SmtUpdateBatch> for Vec<(Word, Word)> {
    fn from(value: SmtUpdateBatch) -> Self {
        value
            .consume()
            .into_iter()
            .map(|op| match op {
                SmtForestOperation::Insert { key, value } => (key, value),
                SmtForestOperation::Remove { key } => (key, EMPTY_WORD),
            })
            .collect()
    }
}

impl<I> From<I> for SmtUpdateBatch
where
    I: Iterator<Item = (Word, Word)>,
{
    fn from(value: I) -> Self {
        Self::new(value.map(|(k, v)| {
            if v.is_empty() {
                SmtForestOperation::Remove { key: k }
            } else {
                SmtForestOperation::Insert { key: k, value: v }
            }
        }))
    }
}

impl Default for SmtUpdateBatch {
    fn default() -> Self {
        Self::empty()
    }
}

// FOREST BATCH
// ================================================================================================

/// A batch of operations that can be performed on an arbitrary forest, consisting of operations
/// associated with specified trees in that forest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtForestUpdateBatch {
    /// The operations associated with each targeted lineage in the forest.
    operations: Map<LineageId, SmtUpdateBatch>,
}

impl SmtForestUpdateBatch {
    /// Creates a new, empty, batch of operations.
    pub fn empty() -> Self {
        Self { operations: Map::new() }
    }

    /// Adds the provided `operations` to be performed on the tree with the specified `lineage`.
    pub fn add_operations(
        &mut self,
        lineage: LineageId,
        operations: impl Iterator<Item = SmtForestOperation>,
    ) {
        let batch = self.operations.entry(lineage).or_insert_with(SmtUpdateBatch::empty);
        batch.add_operations(operations);
    }

    /// Gets the batch of operations for the tree with the specified `lineage` for inspection and/or
    /// modification.
    ///
    /// It is assumed that calling this means that the caller wants to insert operations into the
    /// associated batch, so a batch will be created even if one was not previously present.
    pub fn operations(&mut self, lineage: LineageId) -> &mut SmtUpdateBatch {
        self.operations.entry(lineage).or_insert_with(SmtUpdateBatch::empty)
    }

    /// Gets an iterator over the lineages
    pub fn lineages(&self) -> impl Iterator<Item = &LineageId> {
        self.operations.keys()
    }

    /// Consumes the batch as a map of batches, with each individual batch guaranteed to be in
    /// sorted order and contain only the last operation in the batch for any given key.
    pub fn consume(self) -> Map<LineageId, Vec<SmtForestOperation>> {
        self.operations.into_iter().map(|(k, v)| (k, v.consume())).collect()
    }
}

impl IntoIterator for SmtForestUpdateBatch {
    type Item = (LineageId, Vec<SmtForestOperation>);
    type IntoIter = crate::MapIntoIter<LineageId, Vec<SmtForestOperation>>;

    /// Consumes the batch as an iterator yielding pairs of `(lineage, operations)` while respecting
    /// the guarantees given by [`Self::consume`].
    ///
    /// The iteration order is unspecified.
    fn into_iter(self) -> Self::IntoIter {
        self.consume().into_iter()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod test {
    use itertools::Itertools;

    use super::*;
    use crate::rand::test_utils::ContinuousRng;

    #[test]
    fn tree_batch() {
        let mut rng = ContinuousRng::new([0x12; 32]);

        // We start by creating an empty tree batch.
        let mut batch = SmtUpdateBatch::empty();

        // Let's make three operations on different keys...
        let o1_key: Word = rng.value();
        let o1_value: Word = rng.value();
        let o2_key: Word = rng.value();
        let o3_key: Word = rng.value();
        let o3_value: Word = rng.value();

        let o1 = SmtForestOperation::insert(o1_key, o1_value);
        let o2 = SmtForestOperation::remove(o2_key);
        let o3 = SmtForestOperation::insert(o3_key, o3_value);

        // ... and stick them in the batch in various ways
        batch.add_operations(vec![o1.clone()].into_iter());
        batch.add_remove(o2_key);
        batch.add_insert(o3_key, o3_value);

        // We save a copy of the batch for later as we have more testing to do.
        let batch_tmp = batch.clone();

        // If we then consume the batch, we should have the operations ordered by their key.
        let ops = batch.consume();
        assert!(ops.is_sorted_by_key(SmtForestOperation::key));

        // Let's now make two additional operations with keys that overlay with keys from the first
        // three...
        let o4_key = o2_key;
        let o4_value: Word = rng.value();
        let o5_key = o1_key;

        let o4 = SmtForestOperation::insert(o4_key, o4_value);
        let o5 = SmtForestOperation::remove(o5_key);

        // ... and also stick them into the batch.
        let mut batch = batch_tmp;
        batch.add_operations(vec![o4.clone(), o5.clone()].into_iter());

        // Now if we consume the batch we should have three operations, and they should be the last
        // operation for each key.
        let ops = batch.consume();

        assert_eq!(ops.len(), 3);
        assert!(ops.is_sorted_by_key(SmtForestOperation::key));

        assert!(ops.contains(&o3));
        assert!(ops.contains(&o4));
        assert!(!ops.contains(&o2));
        assert!(ops.contains(&o5));
        assert!(!ops.contains(&o1));
    }

    #[test]
    fn forest_batch() {
        let mut rng = ContinuousRng::new([0x13; 32]);

        // We can start by creating an empty forest batch.
        let mut batch = SmtForestUpdateBatch::empty();

        // Let's start by adding a few operations to a tree.
        let t1_lineage: LineageId = rng.value();
        let t1_o1 = SmtForestOperation::insert(rng.value(), rng.value());
        let t1_o2 = SmtForestOperation::remove(rng.value());
        batch.add_operations(t1_lineage, vec![t1_o1, t1_o2].into_iter());

        // We can also add them differently.
        let t2_lineage: LineageId = rng.value();
        let t2_o1 = SmtForestOperation::remove(rng.value());
        let t2_o2 = SmtForestOperation::insert(rng.value(), rng.value());
        batch.operations(t2_lineage).add_operations(vec![t2_o1, t2_o2].into_iter());

        // When we consume the batch, each per-tree batch should be unique by key and sorted.
        let ops = batch.consume();
        assert_eq!(ops.len(), 2);

        let t1_ops = ops.get(&t1_lineage).unwrap();
        assert!(t1_ops.is_sorted_by_key(SmtForestOperation::key));
        assert_eq!(t1_ops.iter().unique_by(|o| o.key()).count(), 2);

        let t2_ops = ops.get(&t2_lineage).unwrap();
        assert!(t2_ops.is_sorted_by_key(SmtForestOperation::key));
        assert_eq!(t2_ops.iter().unique_by(|o| o.key()).count(), 2);
    }
}
