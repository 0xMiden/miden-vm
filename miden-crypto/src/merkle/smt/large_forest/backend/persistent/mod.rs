//! A persistent backend for the SMT forest built with inspiration from LargeSMT's existing
//! persistent backend.
//!
//! # Performance Considerations
//!
//! Most operations in this backend need to perform disk I/O to the backing database. The
//! implementation does its best to mask this latency through parallelism, but some methods (e.g.
//! [`PersistentBackend::open`]) don't have work that can be parallelized in this way.
//!
//! To take advantage of data locality on disk, batches built using keys that share high-order bits
//! (e.g. from within the same lineage) are going to exhibit better read and write performance. Such
//! locality will also result in reductions to peak memory residency.
//!
//! ## Memory Residency
//!
//! As this backend does not store much data permanently in memory, the memory usage behavior is
//! quite spiky. Peak memory usage will be seen during a query or update operation, but all the
//! memory of that peak is released back to the system by the time the query has completed.
//!
//! Peak memory usage is proportional to:
//!
//! - The number of mutated leaves in a batch.
//! - The number of unique subtrees across which these leaves fall.
//! - The number of distinct subtrees altered by these mutations.
//!
//! This means that extremely large batches, or batches that are scattered across a significant
//! number of subtrees, will see higher peak residency than batches with good locality
//! characteristics.

pub mod config;
mod internal;
mod iterator;
mod keys;
mod property_tests;
mod tests;
mod tree_metadata;

use alloc::{string::ToString, sync::Arc, vec::Vec};
use core::ffi::c_int;
use std::{collections::HashMap, iter::once, mem};

use miden_serde_utils::{Deserializable, DeserializationError, Serializable};
use num::Integer;
use rayon::prelude::*;
use rocksdb as db;

use super::{BackendError, Result};
use crate::{
    EMPTY_WORD, Map, Word,
    merkle::{
        EmptySubtreeRoots, MerkleError, NodeIndex, SparseMerklePath,
        smt::{
            Backend, InnerNode, LeafIndex, LineageId, NodeMutation, NodeMutations, SMT_DEPTH,
            SmtForestUpdateBatch, SmtLeaf, SmtLeafError, SmtProof, SmtUpdateBatch,
            StorageUpdateParts, StorageUpdates, Subtree, SubtreeError, TreeEntry, TreeWithRoot,
            VersionId,
            full::concurrent::{
                MutatedSubtreeLeaves, SUBTREE_DEPTH, SubtreeLeaf, SubtreeLeavesIter,
                fetch_sibling_pair, process_sorted_pairs_to_leaves,
            },
            large::{StorageError, SubtreeUpdate},
            large_forest::{
                backend::persistent::{
                    config::Config,
                    internal::merge_batches,
                    iterator::PersistentBackendEntriesIterator,
                    keys::{LeafKey, SubtreeKey},
                    tree_metadata::TreeMetadata,
                },
                utils::MutationSet,
            },
        },
    },
};

// TYPE ALIASES
// ================================================================================================

/// The type of the underlying RocksDB database in use by this backend.
type DB = db::DB;

/// The type of a write batch in the database associated with a transaction.
type WriteBatch = db::WriteBatch;

// CONSTANTS / COLUMN FAMILY NAMES
// ================================================================================================

const LEAVES_CF: &str = "v1/leaves";
const METADATA_CF: &str = "v1/metadata";

const SUBTREE_00_CF: &str = "v1/st00";
const SUBTREE_08_CF: &str = "v1/st08";
const SUBTREE_16_CF: &str = "v1/st16";
const SUBTREE_24_CF: &str = "v1/st24";
const SUBTREE_32_CF: &str = "v1/st32";
const SUBTREE_40_CF: &str = "v1/st40";
const SUBTREE_48_CF: &str = "v1/st48";
const SUBTREE_56_CF: &str = "v1/st56";

const SUBTREE_CFS: [&str; 8] = [
    SUBTREE_00_CF,
    SUBTREE_08_CF,
    SUBTREE_16_CF,
    SUBTREE_24_CF,
    SUBTREE_32_CF,
    SUBTREE_40_CF,
    SUBTREE_48_CF,
    SUBTREE_56_CF,
];

// CONSTANTS / DATABASE CONFIGURATION
// ================================================================================================

/// The maximum size of the write buffer for the metadata column family (currently 8 MiB).
const MAX_METADATA_CF_WRITE_BUFFER_SIZE_BYTES: usize = 8 << 20;

/// The maximum size of the write buffer for the leaves column family (currently 128 MiB).
const MAX_LEAVES_CF_WRITE_BUFFER_SIZE_BYTES: usize = 128 << 20;

/// The maximum size of the write buffer for the subtree column families (currently 128 MiB).
const MAX_SUBTREE_CF_WRITE_BUFFER_SIZE_BYTES: usize = 128 << 20;

/// The maximum number of write buffers to maintain per column family.
const MAX_WRITE_BUFFER_COUNT: c_int = 3;

/// The minimum number of write buffers to merge when flushing.
const MIN_WRITE_BUFFERS_TO_MERGE: c_int = 1;

/// The maximum number of write buffers to retain in memory when flushing.
const MAX_WRITE_BUFFERS_TO_RETAIN: i64 = 0;

/// The compression mode to be used for all column families where compression is enabled.
///
/// This is chosen as it has fast decompression performance, and also does not require the
/// introduction of any additional dependencies into this project.
const COMPRESSION_MODE: db::DBCompressionType = db::DBCompressionType::Lz4;

/// Trigger compaction of L0 files when there are this many or more.
const L0_FILE_COMPACTION_TRIGGER: c_int = 8;

/// The minimum number of lineages in a batch where it is worth spawning additional threads to
/// combine their batches in parallel.
const MIN_LINEAGES_IN_BATCH_TO_PARALLELIZE: usize = 5;

/// The minimum number of items per rayon chunk when parallelizing deserialization and extraction.
const CHUNKING_UNIT: usize = 100;

// PERSISTENT BACKEND
// ================================================================================================

/// The persistent backend for the SMT forest, providing durable storage for the latest tree in each
/// lineage in the forest.
#[derive(Debug)]
pub struct PersistentBackend {
    /// The underlying database.
    ///
    /// # Layout
    ///
    /// The data on each tree is stored across a series of RocksDB column families, along with
    /// additional metadata. The layout is fixed (for the moment), and has the following column
    /// families.
    ///
    /// - [`LEAVES_CF`]: Stores the [`SmtLeaf`] data, keyed by a [`LeafKey`] instance.
    /// - [`METADATA_CF`]: Stores a [`TreeMetadata`] instance for each tree, keyed by
    ///   [`LineageId`]. This acts like a mirror of the in-memory `lineages` data, which exists to
    ///   speed up common queries.
    /// - `SUBTREE_XX_CF`: Stores the [`Subtree`]s with their root at level `XX` in the backend,
    ///   keyed on the [`SubtreeKey`].
    db: Arc<DB>,

    /// An in-memory cache of the tree metadata enabling the more rapid servicing of certain kinds
    /// of queries.
    ///
    /// Care must be taken that this is _always_ kept in sync with the on-disk copy in the
    /// [`METADATA_CF`] column.
    lineages: HashMap<LineageId, TreeMetadata>,

    /// Whether writes should be synchronously flushed to disk.
    ///
    /// Setting this to true will result in reduced throughput but may result in higher durability
    /// in the presence of crashes.
    sync_writes: bool,
}

// CONSTRUCTION
// ================================================================================================

/// This block contains functions for the construction of the persistent backend.
impl PersistentBackend {
    /// Constructs an instance of the persistent backend, either opening or creating the data store
    /// at the location specified in the `config`.
    ///
    /// # Errors
    ///
    /// - [`BackendError::CorruptedData`] if data corruption is encountered when loading the forest
    ///   from disk.
    /// - [`BackendError::Internal`] if the backend cannot be started up properly.
    pub fn load(config: Config) -> Result<Self> {
        let db = Arc::new(Self::build_db_with_options(&config)?);
        let lineages = Self::read_all_metadata(db.clone())?;
        let sync_writes = config.sync_writes;

        Ok(Self { db, lineages, sync_writes })
    }
}

// BACKEND TRAIT
// ================================================================================================

impl Backend for PersistentBackend {
    /// Returns an opening for the specified `key` in the SMT with the specified `lineage`.
    ///
    /// # Errors
    ///
    /// - [`BackendError::UnknownLineage`] if the provided `lineage` is not known by the backend.
    /// - [`BackendError::Internal`] if the backing database cannot be accessed for some reason.
    fn open(&self, lineage: LineageId, key: Word) -> Result<SmtProof> {
        // We fail early if we don't know about the lineage in question, as querying further could
        // cause very strange behavior.
        if !self.lineages.contains_key(&lineage) {
            return Err(BackendError::UnknownLineage(lineage));
        }

        // We get our leaf first.
        let leaf = self
            .load_leaf_for(lineage, key)?
            .unwrap_or_else(|| SmtLeaf::new_empty(LeafIndex::from(key)));

        // We then have to load both the corresponding leaf, and the siblings for its path out of
        // storage.
        let leaf_index: NodeIndex = LeafIndex::from(key).into();

        // We calculate the roots of the subtrees in order to know their keys for loading. As an
        // opening only ever needs to retrieve 8 subtrees we just do this sequentially.
        let subtree_roots = (0..SMT_DEPTH / SUBTREE_DEPTH)
            .scan(leaf_index.parent(), |cursor, _| {
                let subtree_root = Subtree::find_subtree_root(*cursor);
                *cursor = subtree_root.parent();
                Some(subtree_root)
            })
            .collect::<Vec<_>>();

        // Doing this as a separate step exhibits better performance than loading these subtrees
        // inline in the path creation. This appears to be due to better pipelining and
        // branch-predictor behavior.
        let mut subtree_cache = HashMap::<NodeIndex, Subtree>::new();
        for root in subtree_roots {
            let maybe_tree = self.load_subtree(SubtreeKey { lineage, index: root })?;
            subtree_cache.insert(root, maybe_tree.unwrap_or_else(|| Subtree::new(root)));
        }

        let merkle_path = self.compute_path(leaf_index, &subtree_cache);

        // This is safe to do unchecked as we ensure that the path is valid by construction.
        Ok(SmtProof::new_unchecked(merkle_path, leaf))
    }

    /// Returns the leaf stored at `leaf_index` in the SMT with the specified `lineage`.
    ///
    /// If no leaf is explicitly stored at the given index, an empty leaf for that index is
    /// returned.
    ///
    /// # Errors
    ///
    /// - [`BackendError::UnknownLineage`] if the provided `lineage` is not known by the backend.
    /// - [`BackendError::Internal`] if the backing database cannot be accessed for some reason.
    fn get_leaf(&self, lineage: LineageId, leaf_index: LeafIndex<SMT_DEPTH>) -> Result<SmtLeaf> {
        if !self.lineages.contains_key(&lineage) {
            return Err(BackendError::UnknownLineage(lineage));
        }

        let key = LeafKey { lineage, index: leaf_index.position() };
        Ok(self.load_leaf_raw(&key)?.unwrap_or_else(|| SmtLeaf::new_empty(leaf_index)))
    }

    /// Returns the value associated with the provided `key` in the specified `lineage`, or [`None`]
    /// if no such value exists.
    ///
    /// # Errors
    ///
    /// - [`BackendError::UnknownLineage`] if the provided `lineage` is not known by the backend.
    /// - [`BackendError::Internal`] if the backing database cannot be accessed for some reason.
    fn get(&self, lineage: LineageId, key: Word) -> Result<Option<Word>> {
        // We fail early if we don't know about the lineage in question, as querying further could
        // cause very strange behavior.
        if !self.lineages.contains_key(&lineage) {
            return Err(BackendError::UnknownLineage(lineage));
        }

        // We cannot read individual key-value pairs out of storage, so we have to read the leaf
        // that contains the key we care about.
        let leaf = self.load_leaf_for(lineage, key)?;
        Ok(leaf.and_then(|l| {
            let val = l.get_value(&key);
            val.and_then(|e| if e.is_empty() { None } else { Some(e) })
        }))
    }

    /// Returns the version of the tree with the specified `lineage`.
    ///
    /// # Errors
    ///
    /// - [`BackendError::UnknownLineage`] If the provided `lineage` is one not known by this
    ///   backend.
    fn version(&self, lineage: LineageId) -> Result<VersionId> {
        let metadata = self.lineages.get(&lineage).ok_or(BackendError::UnknownLineage(lineage))?;
        Ok(metadata.version)
    }

    /// Returns an iterator over all the lineages that the backend knows about.
    ///
    /// # Errors
    ///
    /// - This implementation does not return any errors.
    fn lineages(&self) -> Result<impl Iterator<Item = LineageId>> {
        Ok(self.lineages.keys().copied())
    }

    /// Returns an iterator over all the trees that the backend knows about.
    ///
    /// The iteration order is unspecified.
    ///
    /// # Errors
    ///
    /// - This implementation does not return any errors.
    fn trees(&self) -> Result<impl Iterator<Item = TreeWithRoot>> {
        Ok(self
            .lineages
            .iter()
            .map(|(l, m)| TreeWithRoot::new(*l, m.version, m.root_value)))
    }

    /// Returns the number of entries in the tree with the provided `lineage`.
    ///
    /// # Errors
    ///
    /// - [`BackendError::UnknownLineage`] if the provided `lineage` is not known by the backend.
    fn entry_count(&self, lineage: LineageId) -> Result<usize> {
        let metadata = self.lineages.get(&lineage).ok_or(BackendError::UnknownLineage(lineage))?;
        Ok(metadata.entry_count.try_into().expect("Count of entries should fit into usize"))
    }

    /// Returns an iterator that yields the populated (key-value) entries for the specified
    /// `lineage`.
    ///
    /// This iterator yields entries in an arbitrary order, and never yields entries for which the
    /// value is the empty word.
    ///
    /// # Errors
    ///
    /// - [`BackendError::UnknownLineage`] if the provided `lineage` is not one known by this
    ///   backend.
    fn entries(&self, lineage: LineageId) -> Result<impl Iterator<Item = Result<TreeEntry>>> {
        if !self.lineages.contains_key(&lineage) {
            return Err(BackendError::UnknownLineage(lineage));
        }

        let lineage_bytes = lineage.to_bytes();

        // In order to improve iteration performance significantly, we iterate with a prefix. As
        // leaves are keyed on `LeafKey`, which begins with the bytes of the lineage, we can use the
        // lineage as our prefix. That means that the iterator should only yield values whose key
        // begins with the prefix with a high likelihood.
        let pfx_iterator = self.db.prefix_iterator_cf(self.cf(LEAVES_CF)?, lineage_bytes);

        // Data ownership concerns mean we cannot use this iterator directly even if we could change
        // its type, so we delegate to our custom entries iterator impl.
        Ok(PersistentBackendEntriesIterator::new(lineage, pfx_iterator))
    }

    /// Adds the provided `lineage` to the forest with the provided `version` and sets the
    /// associated tree to have the value created by applying `updates` to the empty tree, returning
    /// the root of this new tree.
    ///
    /// # Errors
    ///
    /// - [`BackendError::DuplicateLineage`] if the provided `lineage` already exists in the
    ///   backend.
    /// - [`BackendError::Internal`] if the database cannot be accessed at any point.
    /// - [`BackendError::Merkle`] if an error occurs with the merkle tree semantics.
    fn add_lineage(
        &mut self,
        lineage: LineageId,
        version: VersionId,
        updates: SmtUpdateBatch,
    ) -> Result<TreeWithRoot> {
        // We start by checking if the lineage already exists, as we are expected by contract to
        // error if it is a duplicate.
        if self.lineages.contains_key(&lineage) {
            return Err(BackendError::DuplicateLineage(lineage));
        }

        // We now build our new tree metadata, which begins as a fully-empty tree with the default
        // root, no leaves, and no entries.
        let new_lineage_meta = TreeMetadata {
            version,
            root_value: *EmptySubtreeRoots::entry(SMT_DEPTH, 0),
            entry_count: 0,
        };

        // We add and update the tree all in one go in the backend, using a single batch to ensure
        // internal consistency.
        let batch = WriteBatch::default();

        // We perform the update. If this fails due to an error, the batch will get dropped at the
        // end of the scope, and any staged mutations will be forgotten without being applied.
        let (batch, reversion_set, tree_metadata) = self.update_tree_in_write_batch(
            batch,
            lineage,
            new_lineage_meta,
            version,
            updates.into(),
        )?;

        // Upon returning successfully, we need to update the metadata on disk as part of this
        // operation.
        let batch = self.write_metadata(batch, lineage, &tree_metadata)?;

        // Only when the batch has been successfully written to disk do we write to the in-memory
        // metadata, ensuring that the state remains consistent.
        let new_root = tree_metadata.root_value;
        self.finalize_update(batch, once((lineage, tree_metadata, reversion_set)))?;

        // Finally we just return the necessary metadata.
        Ok(TreeWithRoot::new(lineage, version, new_root))
    }

    /// Performs the provided `updates` on the tree with the specified `lineage`, returning the
    /// mutation set that will revert the changes made to the tree.
    ///
    /// At most one new root is added to the backend for the entire batch.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the database cannot be accessed at any point.
    /// - [`BackendError::Merkle`] if an error occurs with the merkle tree semantics.
    /// - [`BackendError::UnknownLineage`] if the provided `lineage` is not known by this backend.
    fn update_tree(
        &mut self,
        lineage: LineageId,
        new_version: VersionId,
        updates: SmtUpdateBatch,
    ) -> Result<MutationSet> {
        // We check our lineage existence at the start just as a sanity check.
        let tree_metadata = self
            .lineages
            .get(&lineage)
            .ok_or(BackendError::UnknownLineage(lineage))?
            .clone();

        // All the work needs to happen atomically, so we construct a new write batch in which we
        // stage our operations.
        let batch = WriteBatch::default();

        // We perform the update. If this fails with an error, the write batch will be dropped
        // during error unwind, and any staged mutations will be forgotten about without being
        // applied.
        let (batch, reversion_set, tree_metadata) = self.update_tree_in_write_batch(
            batch,
            lineage,
            tree_metadata,
            new_version,
            updates.into(),
        )?;

        // At this point the batch contains the updates to the tree, but we still need to handle
        // updating the metadata.
        let batch = self.write_metadata(batch, lineage, &tree_metadata)?;

        // Writing the batch may fail, so we only write to the in-memory metadata once it is
        // successful to ensure the in-memory state cache remains consistent with the database.
        let mut res = self.finalize_update(batch, once((lineage, tree_metadata, reversion_set)))?;
        let Some((_, reversion_set)) = res.pop() else {
            unreachable!("finalize_update did not return the same number of output elements")
        };

        // We then just return the reversion set for the operations in question.
        Ok(reversion_set)
    }

    /// Adds multiple new `lineages` to the tree, creating an empty tree for each and applying the
    /// provided modifications to it, with the result being given the specified `version`.
    ///
    /// If the provide batch of modifications is empty for any given lineage, then the **empty tree
    /// will be added** as the first version in that lineage.
    ///
    /// # Errors
    ///
    /// - [`BackendError::DuplicateLineage`] if any of the provided lineages already exists in the
    ///   backend.
    /// - [`BackendError::Internal`] if the database cannot be accessed at any point.
    /// - [`BackendError::Merkle`] if an error occurs with the merkle tree semantics.
    fn add_lineages(
        &mut self,
        version: VersionId,
        lineages: SmtForestUpdateBatch,
    ) -> Result<Vec<(LineageId, TreeWithRoot)>> {
        // We start by checking that none of the lineages already exist, as we are expected by
        // contract to error if any is a duplicate.
        let updates = lineages
            .into_iter()
            .map(|(lineage, ops)| {
                if self.lineages.contains_key(&lineage) {
                    return Err(BackendError::DuplicateLineage(lineage));
                }
                Ok((lineage, ops))
            })
            .collect::<Result<Vec<_>>>()?;
        let lineage_count = updates.len();

        // If we have no lineages, then we can exit early.
        if updates.is_empty() {
            return Ok(Vec::new());
        }

        // Build the initial metadata and set up empty write batches for each new lineage
        let updates_with_batch = updates
            .into_iter()
            .map(|(lineage, ops)| {
                let new_meta = TreeMetadata {
                    version,
                    root_value: *EmptySubtreeRoots::entry(SMT_DEPTH, 0),
                    entry_count: 0,
                };
                let batch = WriteBatch::default();
                (lineage, ops, new_meta, batch)
            })
            .collect::<Vec<_>>();

        // Process lineages in parallel, updating each tree in its own write batch
        let lineage_data = updates_with_batch
            .into_par_iter()
            .map(|(lineage, ops, new_meta, batch)| {
                let ops = ops.into_iter().map(|op| op.into()).collect();
                let (batch, reversion, tree_data) =
                    self.update_tree_in_write_batch(batch, lineage, new_meta, version, ops)?;
                let batch = self.write_metadata(batch, lineage, &tree_data)?;
                let root = tree_data.root_value;

                Ok((batch, (lineage, tree_data, reversion), (lineage, root)))
            })
            .collect::<Result<Vec<_>>>()?;
        let (batches, mutation_sets, roots): (Vec<_>, Vec<_>, Vec<_>) =
            lineage_data.into_iter().fold(
                (
                    Vec::with_capacity(lineage_count),
                    Vec::with_capacity(lineage_count),
                    Vec::with_capacity(lineage_count),
                ),
                |(mut bs, mut ms, mut rs), (b, m, r)| {
                    bs.push(b);
                    ms.push(m);
                    rs.push(r);
                    (bs, ms, rs)
                },
            );

        // Merge all the write batches into one atomic batch
        let final_batch = if lineage_count > MIN_LINEAGES_IN_BATCH_TO_PARALLELIZE {
            batches
                .into_par_iter()
                .fold(WriteBatch::new, |l, r| merge_batches(l, &r))
                .reduce(WriteBatch::new, |l, r| merge_batches(l, &r))
        } else {
            batches.into_iter().fold(WriteBatch::new(), |l, r| merge_batches(l, &r))
        };

        // Atomically write to disk and update in-memory cache.
        self.finalize_update(final_batch, mutation_sets.into_iter())?;

        // Build the return value from the captured roots.
        let results = roots
            .into_iter()
            .map(|(lineage, root)| (lineage, TreeWithRoot::new(lineage, version, root)))
            .collect();

        Ok(results)
    }

    /// Performs the provided `updates` on the entire forest, returning the mutation sets that would
    /// reverse the changes to each lineage in the forest.
    ///
    /// The order of application of these mutations is unspecified, but is guaranteed to produce no
    /// more than one new root for each operated-upon lineage. All operations are performed as part
    /// of one atomic update, leaving the data on disk in a consistent state even if failures occur.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the database cannot be accessed at any point.
    /// - [`BackendError::Merkle`] if an error occurs with the merkle tree semantics.
    /// - [`BackendError::UnknownLineage`] if the provided `lineage` is not known by this backend.
    fn update_forest(
        &mut self,
        new_version: VersionId,
        updates: SmtForestUpdateBatch,
    ) -> Result<Vec<(LineageId, MutationSet)>> {
        // We first have to check our precondition that all lineages are valid, returning an error
        // as required by our contract if any lineage is unknown to the backend.
        let updates = updates
            .into_iter()
            .map(|(lineage, ops)| {
                if !self.lineages.contains_key(&lineage) {
                    return Err(BackendError::UnknownLineage(lineage));
                }

                Ok((lineage, ops))
            })
            .collect::<Result<Vec<_>>>()?;
        let lineage_count = updates.len();
        let updates = updates
            .into_iter()
            .map(|(lineage, ops)| {
                (lineage, ops, self.lineages.get(&lineage).expect("Known to exist").clone())
            })
            .collect::<Vec<_>>();

        // We want to update all trees as part of an atomic update to the backing database, but we
        // also want to do this in parallel. As we cannot share a transaction directly, we instead
        // share a write-batch per tree.
        let updates_with_batch = updates
            .into_iter()
            .map(|(lineage, ops, tree_data)| {
                let batch = WriteBatch::default();
                (lineage, ops, tree_data, batch)
            })
            .collect::<Vec<_>>();

        // Now we can simply issue the work in parallel.
        let lineage_data = updates_with_batch
            .into_par_iter()
            .map(|(lineage, ops, tree_data, batch)| {
                let ops = ops.into_iter().map(|op| op.into()).collect();
                let (batch, reversion, tree_data) =
                    self.update_tree_in_write_batch(batch, lineage, tree_data, new_version, ops)?;
                let batch = self.write_metadata(batch, lineage, &tree_data)?;

                Ok((batch, (lineage, tree_data, reversion)))
            })
            .collect::<Result<Vec<_>>>()?;
        let (batches, mutation_sets): (Vec<_>, Vec<_>) = lineage_data.into_iter().unzip();

        // We construct our final WriteBatch in parallel if we have enough of them, otherwise we
        // just do it in serial.
        let final_batch = if lineage_count > MIN_LINEAGES_IN_BATCH_TO_PARALLELIZE {
            batches
                .into_par_iter()
                .fold(WriteBatch::new, |l, r| merge_batches(l, &r))
                .reduce(WriteBatch::new, |l, r| merge_batches(l, &r))
        } else {
            batches.into_iter().fold(WriteBatch::new(), |l, r| merge_batches(l, &r))
        };

        // Only at this point do we write to the in-memory metadata, ensuring that the state remains
        // consistent.
        let result = self.finalize_update(final_batch, mutation_sets.into_iter())?;

        Ok(result)
    }
}

// INTERNAL / UTILITY
// ================================================================================================

/// This block contains methods for internal use only that provide useful functionality for the
/// implementation of the backend.
impl PersistentBackend {
    /// Computes the merkle path for the provided `lineage` beginning at the provided `leaf_index`
    /// using the pre-loaded `subtrees`.
    fn compute_path(
        &self,
        mut leaf_index: NodeIndex,
        subtrees: &HashMap<NodeIndex, Subtree>,
    ) -> SparseMerklePath {
        let mut path = Vec::with_capacity(SMT_DEPTH as usize);

        while leaf_index.depth() > 0 {
            let is_right = leaf_index.is_position_odd();
            leaf_index = leaf_index.parent();

            let root = Subtree::find_subtree_root(leaf_index);
            let subtree = &subtrees[&root]; // Known to exist by construction.
            let InnerNode { left, right } =
                subtree.get_inner_node(leaf_index).unwrap_or_else(|| {
                    EmptySubtreeRoots::get_inner_node(SMT_DEPTH, leaf_index.depth())
                });

            path.push(if is_right { left } else { right });
        }

        SparseMerklePath::from_sized_iter(path).expect("Always succeeds by construction")
    }

    /// Performs `updates` on the tree in the specified lineage, assigning the new tree the
    /// provided `new_version`.
    ///
    /// All operations in this method take place within the context of the provided `batch`. This
    /// method will only stage operations using the transaction associated with that batch, and is
    /// guaranteed to not commit those changes.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the backend fails to read to or write from storage.
    /// - [`BackendError::Merkle`] if an error occurs with the merkle tree semantics in the backend.
    fn update_tree_in_write_batch(
        &self,
        batch: WriteBatch,
        lineage: LineageId,
        mut tree_metadata: TreeMetadata,
        new_version: VersionId,
        mut updates: Vec<(Word, Word)>,
    ) -> Result<(WriteBatch, MutationSet, TreeMetadata)> {
        // We start by ensuring that our updates are sorted, as this is necessary for the efficiency
        // of various other operations.
        updates.sort_by_key(|(k, _)| LeafIndex::from(*k).position());

        // We then have to load the leaves that correspond to these pairs from storage. If the tree
        // is known to be empty (entry_count == 0), we skip the disk read entirely as all leaves
        // are guaranteed to not exist. This is primarily an optimization for the case of adding
        // new trees.
        let leaf_map = if tree_metadata.entry_count == 0 {
            HashMap::new()
        } else {
            self.get_leaves_for_keys(lineage, &updates.iter().map(|(k, _)| *k).collect::<Vec<_>>())?
        };

        // We then process the leaves in parallel to determine the mutations that we need to apply
        // to the full tree.
        let LeafMutations {
            mut leaves,
            leaf_updates,
            leaf_count_delta,
            entry_count_delta,
            reversion_pairs,
        } = self.sorted_pairs_to_mutated_leaves(updates, &leaf_map)?;

        // If we have no mutations to perform, we return early for performance and to satisfy the
        // contract required of `add_lineage`.
        if leaves.is_empty() {
            // As a result, our mutation set is empty.
            return Ok((
                batch,
                MutationSet {
                    old_root: tree_metadata.root_value,
                    node_mutations: NodeMutations::default(),
                    new_pairs: Map::default(),
                    new_root: tree_metadata.root_value,
                },
                tree_metadata,
            ));
        }

        // We can then preallocate capacity for the subtree updates.
        let mut subtree_updates: Vec<SubtreeUpdate> = Vec::with_capacity(leaves.len());
        let mut global_node_reversions = Map::new();

        // We process each depth level in reverse, stepping by the subtree depth. This is due to the
        // dependency order of updates.
        for subtree_root_depth in
            (0..=SMT_DEPTH - SUBTREE_DEPTH).step_by(SUBTREE_DEPTH as usize).rev()
        {
            let subtree_count = leaves.len();

            let (mut subtree_roots, modified_subtrees, node_reversions) = leaves
                .into_par_iter()
                .map(|subtree_leaves| {
                    self.process_subtree_for_depth(lineage, subtree_leaves, subtree_root_depth)
                })
                .fold(
                    || {
                        Ok((
                            Vec::with_capacity(subtree_count),
                            Vec::with_capacity(subtree_count),
                            Map::new(),
                        ))
                    },
                    |result, processed_tree| match (result, processed_tree) {
                        (Ok((mut roots, mut subtrees, mut node_reversions)), Ok(tree)) => {
                            roots.push(tree.subtree_root);
                            node_reversions.extend(tree.reversion_nodes);
                            if let Some(action) = tree.storage_action {
                                subtrees.push(action);
                            }

                            Ok((roots, subtrees, node_reversions))
                        },
                        (Err(e), _) | (_, Err(e)) => Err(e),
                    },
                )
                .reduce(
                    || Ok((Vec::new(), Vec::new(), Map::new())),
                    |data1, data2| match (data1, data2) {
                        (
                            Ok((mut roots1, mut trees1, mut reversions1)),
                            Ok((roots2, trees2, reversions2)),
                        ) => {
                            roots1.extend(roots2);
                            trees1.extend(trees2);
                            reversions1.extend(reversions2);
                            Ok((roots1, trees1, reversions1))
                        },
                        (Err(e), _) | (_, Err(e)) => Err(e),
                    },
                )?;

            subtree_updates.extend(modified_subtrees);
            global_node_reversions.extend(node_reversions);
            leaves = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();

            debug_assert!(!leaves.is_empty());
        }

        // Next we have to build the storage updates.
        let mut leaf_update_map = leaf_map;

        for (idx, mutated_leaf) in leaf_updates {
            let leaf_opt = match mutated_leaf {
                SmtLeaf::Empty(_) => None, // Delete from storage
                _ => Some(mutated_leaf),
            };
            leaf_update_map.insert(idx, leaf_opt);
        }

        let updates = StorageUpdates::from_parts(
            leaf_update_map,
            subtree_updates,
            leaf_count_delta,
            entry_count_delta,
        );

        // And we apply the updates to the lineage in the storage under the current transaction.
        let batch = self.apply_updates_to_lineage(batch, lineage, updates)?;

        // And then compute the new root.
        let root_after_modification = leaves[0][0].hash;

        // We then write the node metadata into a copy
        let root_before_modification = tree_metadata.root_value;
        tree_metadata.entry_count = tree_metadata.entry_count.saturating_add_signed(
            entry_count_delta.try_into().expect("Delta should always fit into i64"),
        );
        tree_metadata.root_value = root_after_modification;
        tree_metadata.version = new_version;

        let mutation_set = MutationSet {
            old_root: root_after_modification,
            node_mutations: global_node_reversions,
            new_pairs: reversion_pairs.into_iter().collect(),
            new_root: root_before_modification,
        };

        Ok((batch, mutation_set, tree_metadata))
    }

    /// Applies the `updates` to the specified `lineage` in the context of the provided `batch`.
    ///
    /// It will stage operations into the provided `batch` before returning it.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the backend cannot be written to.
    fn apply_updates_to_lineage(
        &self,
        mut batch: WriteBatch,
        lineage: LineageId,
        updates: StorageUpdates,
    ) -> Result<WriteBatch> {
        let leaves_cf = self.cf(LEAVES_CF)?;

        let StorageUpdateParts { leaf_updates, subtree_updates, .. } = updates.into_parts();

        // These are simple enough that it does not make sense to do it in parallel.
        for (k, v) in leaf_updates {
            let key_bytes = LeafKey { lineage, index: k }.to_bytes();
            match v {
                Some(leaf) => batch.put_cf(leaves_cf, key_bytes, leaf.to_bytes()),
                None => batch.delete_cf(leaves_cf, key_bytes),
            }
        }

        // These do more work, so we issue all of them in parallel.
        let update_data = subtree_updates
            .into_par_iter()
            .map(|update| {
                let (index, maybe_bytes) = match update {
                    SubtreeUpdate::Store { index, subtree } => {
                        let bytes = subtree.to_vec();
                        (index, Some(bytes))
                    },
                    SubtreeUpdate::Delete { index } => (index, None),
                };

                let key = SubtreeKey { lineage, index };
                let key_bytes = key.to_bytes();
                let cf = self.subtree_cf(index)?;
                Ok((cf, key_bytes, maybe_bytes))
            })
            .collect::<Result<Vec<_>>>()?;

        // We then add all the changes to the transaction in serial for now.
        for (cf, k, mv) in update_data {
            match mv {
                None => batch.delete_cf(cf, k),
                Some(bytes) => batch.put_cf(cf, k, bytes),
            }
        }

        Ok(batch)
    }

    /// Processes the provided set of `subtree_leaves` in the subtree at depth `subtree_root_depth`
    /// and returns the updated subtree data.
    ///
    /// # Panics
    ///
    /// - If loading the subtree from disk fails.
    /// - If the load succeeds but no subtrees have actually been loaded despite being requested.
    /// - If the function cannot retrieve an inner node that is scheduled for removal from the
    ///   subtree.
    fn process_subtree_for_depth(
        &self,
        lineage: LineageId,
        subtree_leaves: Vec<SubtreeLeaf>,
        subtree_root_depth: u8,
    ) -> Result<ProcessedSubtree> {
        debug_assert!(subtree_leaves.is_sorted(), "Subtree leaves were not sorted");
        debug_assert!(!subtree_leaves.is_empty(), "Subtree leaves were empty");

        let subtree_root_index =
            NodeIndex::new_unchecked(subtree_root_depth, subtree_leaves[0].col >> SUBTREE_DEPTH);

        // We now unconditionally load the subtree from storage as all subtrees are stored on disk.
        let mut subtree = self
            .load_subtree(SubtreeKey { lineage, index: subtree_root_index })?
            .unwrap_or_else(|| Subtree::new(subtree_root_index));

        // We then build the mutations for the subtree.
        let (mutations, root) =
            self.build_subtree_mutations(subtree_leaves, subtree_root_depth, &subtree)?;

        // We are always acting on from-storage subtrees, so we can next apply the mutations to the
        // subtree in question and determine what we do to the storage. We also gather our reversion
        // operations at the same time.
        let mut node_reversion_mutations = NodeMutations::new();
        let modified = !mutations.is_empty();

        for (index, mutation) in mutations {
            match mutation {
                NodeMutation::Removal => {
                    // If we are removing something we know structurally that it had to exist
                    // before. The reversion is simply then to add it back.
                    node_reversion_mutations.insert(
                        index,
                        NodeMutation::Addition(subtree.get_inner_node(index).expect(
                            "Removals imply the existence of a value at that index being removed",
                        )),
                    );
                    subtree.remove_inner_node(index);
                },
                NodeMutation::Addition(node) => {
                    // For an addition, we can either be adding something anew or overwriting an
                    // existing value. If there was no previous value, then our reversion is to
                    // remove the node entirely, while if there was we have to add it back.
                    node_reversion_mutations.insert(
                        index,
                        subtree
                            .get_inner_node(index)
                            .map(NodeMutation::Addition)
                            .unwrap_or_else(|| NodeMutation::Removal),
                    );

                    subtree.insert_inner_node(index, node);
                },
            }
        }

        let update = if !modified {
            None
        } else if !subtree.is_empty() {
            Some(SubtreeUpdate::Store { index: subtree_root_index, subtree })
        } else {
            Some(SubtreeUpdate::Delete { index: subtree_root_index })
        };

        Ok(ProcessedSubtree {
            subtree_root: root,
            storage_action: update,
            reversion_nodes: node_reversion_mutations,
        })
    }

    /// Builds the set of subtree mutations based on the provided `leaves` and root_depth` in the
    /// specified `subtree`.
    fn build_subtree_mutations(
        &self,
        mut leaves: Vec<SubtreeLeaf>,
        root_depth: u8,
        subtree: &Subtree,
    ) -> Result<(NodeMutations, SubtreeLeaf)> {
        let bottom_depth = root_depth + SUBTREE_DEPTH;

        debug_assert!(bottom_depth <= SMT_DEPTH);
        debug_assert!(Integer::is_multiple_of(&bottom_depth, &SUBTREE_DEPTH));
        debug_assert!(leaves.len() <= usize::pow(2, SUBTREE_DEPTH as u32));

        let mut node_mutations: NodeMutations = Default::default();
        let mut next_leaves: Vec<SubtreeLeaf> = Vec::with_capacity(leaves.len() / 2);

        for current_depth in (root_depth..bottom_depth).rev() {
            debug_assert!(current_depth <= bottom_depth);

            let next_depth = current_depth + 1;
            let mut iter = leaves.drain(..).peekable();

            while let Some(first_leaf) = iter.next() {
                // This constructs a valid index because next_depth will never exceed the depth of
                // the tree.
                let parent_index = NodeIndex::new_unchecked(next_depth, first_leaf.col).parent();
                let parent_node = subtree.get_inner_node(parent_index).unwrap_or_else(|| {
                    EmptySubtreeRoots::get_inner_node(SMT_DEPTH, parent_index.depth())
                });

                let combined_node = fetch_sibling_pair(&mut iter, first_leaf, parent_node);
                let combined_hash = combined_node.hash();

                let &empty_hash = EmptySubtreeRoots::entry(SMT_DEPTH, current_depth);

                // Add the parent node even if it is empty for proper upward updates
                next_leaves.push(SubtreeLeaf {
                    col: parent_index.position(),
                    hash: combined_hash,
                });

                node_mutations.insert(
                    parent_index,
                    if combined_hash != empty_hash {
                        NodeMutation::Addition(combined_node)
                    } else {
                        NodeMutation::Removal
                    },
                );
            }
            drop(iter);
            leaves = mem::take(&mut next_leaves);
        }

        debug_assert_eq!(leaves.len(), 1);
        let root_leaf = leaves.pop().unwrap();
        Ok((node_mutations, root_leaf))
    }

    /// Loads the subtree specified by `tree_key`, returning it if present in the backing DB or
    /// returning [`None`] if it is not.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the underlying database cannot be accessed.
    fn load_subtree(&self, tree_key: SubtreeKey) -> Result<Option<Subtree>> {
        let cf = self.subtree_cf(tree_key.index)?;
        let key_bytes = tree_key.to_bytes();
        let result = match self.db.get_cf(cf, key_bytes) {
            Ok(Some(bytes)) => Some(Subtree::from_vec(tree_key.index, &bytes)?),
            Ok(None) => None,
            Err(e) => return Err(e.into()),
        };

        Ok(result)
    }

    /// Converts the provided key-value `pairs` and current leaf values into the necessary updates
    /// to be performed on the stored tree.
    ///
    /// The provided `pairs` must be sorted, else undefined behavior may result.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Merkle`] if something goes wrong with the merkle tree semantics.
    /// - [`BackendError::Internal`] if construction would cause any given SMT leaf to exceed its
    ///   maximum number of entries.
    ///
    /// # Panics
    ///
    /// - If a leaf was changed during the processing, but is empty when constructing the leaf and
    ///   entry deltas.
    /// - If the provided `pairs` vector is not sorted, but only with debug assertions enabled.
    fn sorted_pairs_to_mutated_leaves(
        &self,
        pairs: Vec<(Word, Word)>,
        leaf_map: &HashMap<u64, Option<SmtLeaf>>,
    ) -> Result<LeafMutations> {
        debug_assert!(
            pairs.is_sorted_by_key(|(key, _)| LeafIndex::from(*key).position()),
            "The provided pairs vector is not sorted but is required to be"
        );

        let mut reversion_pairs = HashMap::new();
        let mut leaf_count_delta = 0isize;
        let mut entry_count_delta = 0isize;

        // We rely on existing functionality here, but pass in our own closure to provide the
        // forest-specific logic.
        let accumulator = process_sorted_pairs_to_leaves(pairs, |leaf_pairs| {
            let leaf_index = LeafIndex::from(leaf_pairs[0].0);

            let maybe_old_leaf = leaf_map.get(&leaf_index.position()).and_then(Option::as_ref);
            let old_entry_count = maybe_old_leaf.map(|leaf| leaf.num_entries()).unwrap_or_default();

            // Whenever we change a value in the current leaf, we have to store the _old_ version of
            // that value in our reversion pairs.
            let mut new_leaf = maybe_old_leaf
                .cloned()
                .unwrap_or_else(|| SmtLeaf::new_empty(leaf_pairs[0].0.into()));

            let mut leaf_changed = false;

            for (key, value) in leaf_pairs {
                // The old value for the key comes from the old corresponding leaf, or if no such
                // leaf existed all of its values were implicitly zero.
                let old_value_for_key = maybe_old_leaf
                    .and_then(|old_leaf| old_leaf.get_value(&key))
                    .unwrap_or(Word::empty());

                if value != old_value_for_key {
                    new_leaf = self
                        .construct_prospective_leaf(new_leaf, &key, &value)
                        .map_err(|e| MerkleError::InternalError(e.to_string()))?;
                    reversion_pairs.insert(key, old_value_for_key);
                    leaf_changed = true;
                }
            }

            if leaf_changed {
                let new_entry_count = new_leaf.entries().len();
                match (&new_leaf, maybe_old_leaf) {
                    (SmtLeaf::Empty(_), Some(_)) => {
                        leaf_count_delta -= 1;
                        entry_count_delta -= old_entry_count as isize;
                    },
                    (SmtLeaf::Empty(_), None) => {
                        unreachable!("Leaf was empty but leaf_changed=true");
                    },
                    (_, None) => {
                        leaf_count_delta += 1;
                        entry_count_delta += new_entry_count as isize;
                    },
                    (_, Some(_)) => {
                        entry_count_delta += new_entry_count as isize - old_entry_count as isize;
                    },
                }

                Ok(Some(new_leaf))
            } else {
                Ok(None)
            }
        })?;

        Ok(LeafMutations {
            leaves: accumulator.leaves,
            leaf_updates: accumulator.nodes,
            leaf_count_delta,
            entry_count_delta,
            reversion_pairs,
        })
    }

    /// Updates a prospective `leaf` by modifying it based on the provided `key` and `value`.
    ///
    /// # Errors
    ///
    /// - [`SmtLeafError::TooManyLeafEntries`] if an attempt is made to insert `key` and `value`
    ///   into the `leaf` but the insertion would cause the leaf exceed the maximum number of leaf
    ///   entries.
    fn construct_prospective_leaf(
        &self,
        mut leaf: SmtLeaf,
        key: &Word,
        value: &Word,
    ) -> core::result::Result<SmtLeaf, SmtLeafError> {
        debug_assert_eq!(leaf.index(), LeafIndex::from(*key));

        match leaf {
            SmtLeaf::Empty(_) => Ok(SmtLeaf::new_single(*key, *value)),
            _ => {
                if *value != EMPTY_WORD {
                    leaf.insert(*key, *value)?;
                } else {
                    leaf.remove(*key);
                }

                Ok(leaf)
            },
        }
    }

    /// Gets the leaves from disk in the provided `lineage` that contain all the provided `keys`.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if it is unable to load the necessary data from the disk.
    fn get_leaves_for_keys(
        &self,
        lineage: LineageId,
        keys: &[Word],
    ) -> Result<HashMap<u64, Option<SmtLeaf>>> {
        // We have to get all the leaf indices, accounting for the fact that multiple keys may map
        // to any given leaf.
        let mut leaf_indices =
            keys.iter().map(|k| LeafIndex::from(*k).position()).collect::<Vec<_>>();
        leaf_indices.par_sort_unstable();
        leaf_indices.dedup();

        let leaves = self.load_leaves(lineage, &leaf_indices)?;

        Ok(leaf_indices.into_iter().zip(leaves).collect())
    }

    /// Loads the concrete leaves from disk corresponding to the provided `indices` in the provided
    /// `lineage`.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the data cannot be loaded from the database.
    fn load_leaves(&self, lineage: LineageId, indices: &[u64]) -> Result<Vec<Option<SmtLeaf>>> {
        let keys = indices
            .iter()
            .map(|index| LeafKey { lineage, index: *index })
            .collect::<Vec<_>>();

        self.load_leaves_direct(keys.iter())
    }

    /// Loads the concrete leaves from disk corresponding to the provided `keys`.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the data cannot be loaded from the database.
    fn load_leaves_direct<'b>(
        &self,
        keys: impl Iterator<Item = &'b LeafKey>,
    ) -> Result<Vec<Option<SmtLeaf>>> {
        let bytes = keys.map(|k| k.to_bytes()).collect::<Vec<_>>();
        self.load_leaves_raw(bytes.iter())
    }

    /// Loads the concrete leaves from disk corresponding to the provided `keys`.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the data cannot be loaded from the database.
    #[inline(always)]
    fn load_leaves_raw<'b>(
        &self,
        key_bytes: impl Iterator<Item = &'b Vec<u8>>,
    ) -> Result<Vec<Option<SmtLeaf>>> {
        let col = self.cf(LEAVES_CF)?;
        let leaves = self.db.multi_get_cf(key_bytes.map(|k| (col, k.as_slice())));

        leaves
            .into_par_iter()
            .with_min_len(CHUNKING_UNIT)
            .map(|result| match result {
                Ok(Some(bytes)) => {
                    Ok(Some(SmtLeaf::read_from_bytes_with_budget(&bytes, bytes.len())?))
                },
                Ok(None) => Ok(None),
                Err(e) => Err(e.into()),
            })
            .collect()
    }

    /// Gets the leaf with the provided `key` from disk, or returns [`None`] if it is not stored.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the database cannot be successfully queried.
    #[inline(always)]
    fn load_leaf_raw(&self, key: &LeafKey) -> Result<Option<SmtLeaf>> {
        let col = self.cf(LEAVES_CF)?;
        let key_bytes = key.to_bytes();
        let leaf_bytes = self.db.get_cf(col, key_bytes)?;
        let leaf = match leaf_bytes {
            Some(bytes) => Some(SmtLeaf::read_from_bytes_with_budget(&bytes, bytes.len())?),
            None => None,
        };

        Ok(leaf)
    }

    /// Gets the leaf from disk in the provided `lineage` that would contain `key`.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the database cannot be successfully queried.
    fn load_leaf_for(&self, lineage: LineageId, key: Word) -> Result<Option<SmtLeaf>> {
        let key = LeafKey {
            lineage,
            index: LeafIndex::from(key).position(),
        };
        self.load_leaf_raw(&key)
    }

    /// Gets the column family corresponding to the subtree with root index `index`.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the database cannot be accessed to get the column family.
    #[inline(always)]
    fn subtree_cf(&self, index: NodeIndex) -> Result<&db::ColumnFamily> {
        self.subtree_cf_depth(index.depth())
    }

    /// Gets the column family corresponding to the subtree with root index `index`.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the database cannot be accessed to get the column family.
    #[inline(always)]
    fn subtree_cf_depth(&self, depth: u8) -> Result<&db::ColumnFamily> {
        let cf_name = subtree_cf_name(depth);
        self.cf(cf_name)
    }

    /// Gets the column family with the specified name.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the database cannot be accessed to get the column family.
    #[inline(always)]
    fn cf(&self, name: &str) -> Result<&db::ColumnFamily> {
        self.db.cf_handle(name).ok_or_else(|| {
            BackendError::internal_from_message(format!("Could not load column with name {name}"))
        })
    }

    /// Writes the provided `batch` into the database as part of one atomic operation.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if writing to the database fails for any reason.
    fn write(&self, batch: WriteBatch) -> Result<()> {
        let mut write_opts = db::WriteOptions::default();
        write_opts.set_sync(self.sync_writes);
        self.db.write_opt(batch, &write_opts)?;

        Ok(())
    }

    /// Forces the underlying database to perform a sync to disk, and thus ensure that all data is
    /// persisted.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the flush to disk fails for any reason.
    fn sync(&self) -> Result<()> {
        let mut flush_opts = db::FlushOptions::default();
        flush_opts.set_wait(true);

        // Flush all the subtree column families.
        for name in SUBTREE_CFS {
            self.db.flush_cf_opt(self.cf(name)?, &flush_opts)?;
        }

        // Flush the leaves and metadata column families.
        for name in [LEAVES_CF, METADATA_CF] {
            self.db.flush_cf_opt(self.cf(name)?, &flush_opts)?;
        }

        // Flush the WAL.
        self.db.flush_wal(true)?;

        Ok(())
    }
}

// INTERNAL / STARTUP
// ================================================================================================

/// This impl block contains internal functionality to do with starting up the backend and
/// performing its initialization work.
impl PersistentBackend {
    /// Sets up the basic configuration for the underlying RocksDB database.
    fn build_db_with_options(config: &Config) -> Result<DB> {
        let mut db_opts = db::Options::default();

        // We start by initially setting up the base options for the whole database.
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.increase_parallelism(rayon::current_num_threads() as _);
        db_opts.set_max_open_files(config.max_open_files as _);
        db_opts.set_max_background_jobs(rayon::current_num_threads() as _);
        db_opts.set_max_total_wal_size(config.max_wal_size);

        // We want to share a block cache across all column families.
        let cache = db::Cache::new_lru_cache(config.cache_size_bytes);

        // Now we set up our basic options for all column families.
        let mut cf_opts = db::BlockBasedOptions::default();
        cf_opts.set_block_cache(&cache);
        cf_opts.set_bloom_filter(config.bloom_filter_bits, false);
        cf_opts.set_whole_key_filtering(true); // Better for point lookups.
        cf_opts.set_pin_l0_filter_and_index_blocks_in_cache(true); // Improves performance.

        // From this, we can set up the configuration for each of our column families. We start with
        // the one for metadata.
        let metadata_cf_opts = Self::build_cf_opts(
            config,
            &cf_opts,
            MAX_METADATA_CF_WRITE_BUFFER_SIZE_BYTES,
            db::DBCompressionType::None,
        );

        // We can also create the configuration for our leaves column family.
        let leaves_cf_opts = Self::build_cf_opts(
            config,
            &cf_opts,
            MAX_LEAVES_CF_WRITE_BUFFER_SIZE_BYTES,
            COMPRESSION_MODE,
        );

        // Finally we create them for each of our subtree CFs.
        let subtree_cfs = SUBTREE_CFS.into_iter().map(|name| {
            db::ColumnFamilyDescriptor::new(
                name,
                Self::build_cf_opts(
                    config,
                    &cf_opts,
                    MAX_SUBTREE_CF_WRITE_BUFFER_SIZE_BYTES,
                    COMPRESSION_MODE,
                ),
            )
        });

        // With the column-specific configuration made, we can then simply create our database
        // options
        let mut columns = vec![
            db::ColumnFamilyDescriptor::new(METADATA_CF, metadata_cf_opts),
            db::ColumnFamilyDescriptor::new(LEAVES_CF, leaves_cf_opts),
        ];
        columns.extend(subtree_cfs);

        Ok(DB::open_cf_descriptors(&db_opts, config.path.clone(), columns)?)
    }

    /// Unifies the building of options for column families where most parameters are shared,
    /// customizing only the `max_write_buffer_size` and `compression_mode`.
    fn build_cf_opts(
        config: &Config,
        base: &db::BlockBasedOptions,
        max_write_buffer_size: usize,
        compression_mode: db::DBCompressionType,
    ) -> db::Options {
        let mut cf_opts = db::Options::default();
        cf_opts.set_block_based_table_factory(base);
        cf_opts.set_write_buffer_size(max_write_buffer_size);
        cf_opts.set_max_write_buffer_number(MAX_WRITE_BUFFER_COUNT);
        cf_opts.set_min_write_buffer_number_to_merge(MIN_WRITE_BUFFERS_TO_MERGE);
        cf_opts.set_max_write_buffer_size_to_maintain(MAX_WRITE_BUFFERS_TO_RETAIN);
        cf_opts.set_compaction_style(db::DBCompactionStyle::Level);
        cf_opts.set_target_file_size_base(config.target_file_size);
        cf_opts.set_compression_type(compression_mode);
        cf_opts.set_level_zero_file_num_compaction_trigger(L0_FILE_COMPACTION_TRIGGER);

        cf_opts
    }

    /// Stages the provided `metadata` to be written to the provided `lineage` on disk within the
    /// provided `batch`, staging the changes encapsulated by `batch` in the underlying DB.
    ///
    /// It stages its write operations into the provided `batch` before returning it.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the underlying database cannot be accessed for reading or
    ///   staging.
    fn write_metadata(
        &self,
        mut batch: WriteBatch,
        lineage: LineageId,
        tree_metadata: &TreeMetadata,
    ) -> Result<WriteBatch> {
        let metadata = self.cf(METADATA_CF)?;
        let metadata_key = lineage.to_bytes();
        let metadata_value = tree_metadata.to_bytes();
        batch.put_cf(metadata, &metadata_key, &metadata_value);
        Ok(batch)
    }

    /// Finalizes the update by committing the provided `batch` to disk and updating the in-memory
    /// cache with the provided `metadata`.
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the underlying database cannot be written to.
    fn finalize_update(
        &mut self,
        batch: WriteBatch,
        metadata: impl Iterator<Item = (LineageId, TreeMetadata, MutationSet)>,
    ) -> Result<Vec<(LineageId, MutationSet)>> {
        // We first write the full atomic update to disk. If it errors, we bail.
        self.write(batch)?;

        // If it hasn't errored, we can now safely update the in-memory metadata cache.
        Ok(metadata
            .map(|(l, d, r)| {
                self.lineages.insert(l, d);
                (l, r)
            })
            .collect())
    }

    /// Reads all the lineages and their corresponding metadata out of the on-disk storage as part
    /// of the startup work.
    ///
    /// # Errors
    ///
    /// - [`BackendError::CorruptedData`] if data corruption is discovered.
    /// - [`BackendError::Internal`] if the metadata cannot be read from disk.
    fn read_all_metadata(db: Arc<DB>) -> Result<HashMap<LineageId, TreeMetadata>> {
        let cf = db.cf_handle(METADATA_CF).ok_or_else(|| {
            BackendError::CorruptedData(format!("{METADATA_CF} column not found"))
        })?;
        let db_iter = db.iterator_cf(&cf, db::IteratorMode::Start);

        db_iter
            .map(|bytes| {
                let (key_bytes, value_bytes) = bytes?;
                let lineage = LineageId::read_from_bytes(&key_bytes)?;
                let metadata = TreeMetadata::read_from_bytes(&value_bytes)?;

                Ok((lineage, metadata))
            })
            .collect::<Result<_>>()
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

/// We implement drop in order to force a sync to disk as the program shuts down, ensuring that all
/// data is correctly persisted.
impl Drop for PersistentBackend {
    /// Forces the database to be synced to disk on drop.
    ///
    /// # Panics
    ///
    /// - If the sync cannot be performed, indicating that data on disk may be in a corrupt state.
    fn drop(&mut self) {
        if let Err(e) = self.sync() {
            if std::thread::panicking() {
                std::eprintln!("Failed to flush database on shutdown during panic: {e}")
            } else {
                panic!("Failed to flush database on shutdown: {e}")
            }
        }
    }
}

// PROCESSED_SUBTREE
// ================================================================================================

/// The results of processing a subtree in a full tree.
#[derive(Clone, Debug)]
struct ProcessedSubtree {
    /// The computed root of the subtree as a leaf of its containing subtree.
    pub subtree_root: SubtreeLeaf,

    /// The storage update instruction for the subtree.
    pub storage_action: Option<SubtreeUpdate>,

    /// The operations that need to be performed to revert the changes to the subtree.
    pub reversion_nodes: HashMap<NodeIndex, NodeMutation>,
}

// LEAF MUTATIONS
// ================================================================================================

/// A container for the data necessary to perform mutations on the in-memory tree, computed based on
/// a list of key-value pairs representing the changes to the leaves.
#[derive(Clone, Debug, Eq, PartialEq)]
struct LeafMutations {
    /// The leaves, organized into groups to allow building subtrees in parallel.
    pub leaves: MutatedSubtreeLeaves,

    /// The leaves, mapping leaf index to the corresponding _new_ node, organized for performing
    /// storage updates.
    pub leaf_updates: HashMap<u64, SmtLeaf>,

    /// The change in the number of leaves in the tree.
    pub leaf_count_delta: isize,

    /// The change in the number of entries in the tree.
    pub entry_count_delta: isize,

    /// A key-value mapping of leaves that would need to be inserted in order to **reverse** the
    /// changes specified by `self`.
    pub reversion_pairs: HashMap<Word, Word>,
}

// ERRORS
// ================================================================================================

/// We forward all errors in deserialization as data corruption errors.
impl From<DeserializationError> for BackendError {
    fn from(e: DeserializationError) -> Self {
        Self::CorruptedData(e.to_string())
    }
}

/// We generically forward all errors to do with the DB implementation out of the interface of the
/// [`Backend`] as internal errors.
impl From<db::Error> for BackendError {
    fn from(e: db::Error) -> Self {
        BackendError::internal_from(e)
    }
}

/// We generically forward IO errors as fatal errors out of the interface of the [`Backend`] as
/// internal errors.
impl From<std::io::Error> for BackendError {
    fn from(e: std::io::Error) -> Self {
        BackendError::internal_from(e)
    }
}

/// We generically forward storage backend errors out of the interface for the [`Backend`] as
/// data corruption errors.
impl From<StorageError> for BackendError {
    fn from(e: StorageError) -> Self {
        BackendError::CorruptedData(e.to_string())
    }
}

/// All errors to do with subtrees are fatal.
impl From<SubtreeError> for BackendError {
    fn from(e: SubtreeError) -> Self {
        Self::internal_from(e)
    }
}

// HELPERS
// ================================================================================================

/// Gets the subtree column family name corresponding to the provided depth.
///
/// # Panics
///
/// - If `depth` is not a valid subtree depth in this backend.
#[inline(always)]
fn subtree_cf_name(depth: u8) -> &'static str {
    match depth {
        0 => SUBTREE_00_CF,
        8 => SUBTREE_08_CF,
        16 => SUBTREE_16_CF,
        24 => SUBTREE_24_CF,
        32 => SUBTREE_32_CF,
        40 => SUBTREE_40_CF,
        48 => SUBTREE_48_CF,
        56 => SUBTREE_56_CF,
        _ => panic!("Unsupported subtree depth {depth}"),
    }
}
