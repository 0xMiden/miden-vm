use alloc::{boxed::Box, vec::Vec};
use core::fmt;
use std::{mem::ManuallyDrop, path::PathBuf, sync::Arc};

use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DB, DBCompactionStyle, DBCompressionType,
    DBIteratorWithThreadMode, FlushOptions, IteratorMode, Options, ReadOptions, WriteBatch,
    WriteBufferManager, WriteOptions,
};

use super::{
    SmtStorage, SmtStorageReader, StorageError, StorageResult, StorageUpdateParts, StorageUpdates,
    SubtreeUpdate,
};
use crate::{
    EMPTY_WORD, Word,
    merkle::{
        NodeIndex,
        smt::{
            InnerNode, Map, SmtLeaf,
            large::{IN_MEMORY_DEPTH, LargeSmt, subtree::Subtree},
        },
    },
    utils::{Deserializable, Serializable},
};

const DEFAULT_CACHE_SIZE: usize = 1 << 30;
const DEFAULT_MAX_OPEN_FILES: i32 = 512;
const DEFAULT_BLOCK_SIZE: usize = 16 << 10;
const DEFAULT_MAX_TOTAL_WAL_SIZE: u64 = 512 * 1024 * 1024;
const DEFAULT_BOTTOMMOST_ZSTD_MAX_TRAIN_BYTES: i32 = 1 << 20;
const DEFAULT_BLOOM_FILTER_BITS_PER_KEY: f64 = 10.0;

/// The name of the RocksDB column family used for storing SMT leaves.
const LEAVES_CF: &str = "leaves";
/// The names of the RocksDB column families used for storing SMT subtrees (deep nodes).
const SUBTREE_16_CF: &str = "st16";
const SUBTREE_24_CF: &str = "st24";
const SUBTREE_32_CF: &str = "st32";
const SUBTREE_40_CF: &str = "st40";
const SUBTREE_48_CF: &str = "st48";
const SUBTREE_56_CF: &str = "st56";

/// The name of the RocksDB column family used for storing metadata (e.g., counts).
const METADATA_CF: &str = "metadata";
/// The name of the RocksDB column family used for storing in-memory-depth hashes for fast tree
/// rebuilding.
const IN_MEM_DEPTH_CF: &str = "in_mem_depth";

/// The key used in the `METADATA_CF` column family to store the total count of non-empty leaves.
const LEAF_COUNT_KEY: &[u8] = b"leaf_count";
/// The key used in the `METADATA_CF` column family to store the total count of key-value entries.
const ENTRY_COUNT_KEY: &[u8] = b"entry_count";

// ROCKSDB STORAGE
// ================================================================================================

/// A RocksDB-backed persistent storage implementation for a Sparse Merkle Tree (SMT).
///
/// Implements the `SmtStorage` trait, providing durable storage for SMT components
/// including leaves, subtrees (for deeper parts of the tree), and metadata like the SMT root
/// and counts. It leverages RocksDB column families to organize data:
/// - `LEAVES_CF` ("leaves"): Stores `SmtLeaf` data, keyed by their logical u64 index.
/// - `SUBTREE_16_CF` ("st16"): Stores serialized `Subtree` data at depth 16, keyed by their root
///   `NodeIndex`.
/// - `SUBTREE_24_CF` ("st24"): Stores serialized `Subtree` data at depth 24, keyed by their root
///   `NodeIndex`.
/// - `SUBTREE_32_CF` ("st32"): Stores serialized `Subtree` data at depth 32, keyed by their root
///   `NodeIndex`.
/// - `SUBTREE_40_CF` ("st40"): Stores serialized `Subtree` data at depth 40, keyed by their root
///   `NodeIndex`.
/// - `SUBTREE_48_CF` ("st48"): Stores serialized `Subtree` data at depth 48, keyed by their root
///   `NodeIndex`.
/// - `SUBTREE_56_CF` ("st56"): Stores serialized `Subtree` data at depth 56, keyed by their root
///   `NodeIndex`.
/// - `METADATA_CF` ("metadata"): Stores overall SMT metadata such as the current root hash, total
///   leaf count, and total entry count.
#[derive(Debug, Clone)]
pub struct RocksDbStorage {
    db: Arc<DB>,
    durability_mode: RocksDbDurabilityMode,
}

impl RocksDbStorage {
    /// Opens or creates a RocksDB database at the specified `path` and configures it for SMT
    /// storage.
    ///
    /// This method sets up the necessary column families (`leaves`, `subtrees`, `metadata`)
    /// and applies various RocksDB options for performance, such as caching, bloom filters,
    /// and compaction strategies tailored for SMT workloads.
    ///
    /// The default profile uses:
    /// - a 1 GiB block cache shared by this database's column families
    /// - up to 512 open files
    /// - 16 KiB block-based table blocks with cached index/filter blocks
    /// - 128 MiB write buffers with up to 3 memtables per write-heavy column family
    /// - LZ4 compression for active data and ZSTD for bottommost files
    ///
    /// # Errors
    /// Returns `StorageError::Backend` if the database cannot be opened or configured,
    /// for example, due to path issues, permissions, or RocksDB internal errors.
    pub fn open(config: RocksDbConfig) -> StorageResult<Self> {
        let tuning_options = &config.tuning_options;

        // Base DB options
        let mut db_opts = Options::default();
        // Create DB if it doesn't exist
        db_opts.create_if_missing(true);
        // Auto-create missing column families
        db_opts.create_missing_column_families(true);
        // Tune compaction threads to match CPU cores
        db_opts.increase_parallelism(rayon::current_num_threads() as i32);
        // Limit the number of open file handles
        db_opts.set_max_open_files(config.max_open_files);
        // Parallelize flush/compaction up to CPU count
        db_opts.set_max_background_jobs(rayon::current_num_threads() as i32);
        // Maximum WAL size
        db_opts.set_max_total_wal_size(tuning_options.max_total_wal_size);

        // Cache and optional write-buffer manager are shared across this DB's column families.
        let cache = Cache::new_lru_cache(config.cache_size);
        let write_buffer_manager = config.write_buffer_manager(&cache);

        // Common table options for bloom filtering and cache
        let mut table_opts = BlockBasedOptions::default();
        configure_block_table_options(
            &mut table_opts,
            &cache,
            tuning_options,
            tuning_options.bloom_filter_bits_per_key.leaves,
        );

        // Column family for leaves
        let mut leaves_opts = Options::default();
        leaves_opts.set_block_based_table_factory(&table_opts);
        configure_smt_cf_options(&mut leaves_opts);
        if let Some(wbm) = write_buffer_manager.as_ref() {
            db_opts.set_write_buffer_manager(wbm);
            leaves_opts.set_write_buffer_manager(wbm);
        }

        // Helper to build subtree CF options with the tuned block-table profile
        #[expect(clippy::items_after_statements)]
        fn subtree_cf(
            cache: &Cache,
            tuning_options: &RocksDbTuningOptions,
            bloom_filter_bits: f64,
            write_buffer_manager: Option<&WriteBufferManager>,
        ) -> Options {
            let mut table_opts = BlockBasedOptions::default();
            configure_block_table_options(
                &mut table_opts,
                cache,
                tuning_options,
                bloom_filter_bits,
            );

            let mut opts = Options::default();
            opts.set_block_based_table_factory(&table_opts);
            configure_smt_cf_options(&mut opts);
            if let Some(wbm) = write_buffer_manager {
                opts.set_write_buffer_manager(wbm);
            }
            opts
        }

        // In-memory-depth cache column family (uses its own bloom filter setting)
        let mut in_mem_depth_table_opts = BlockBasedOptions::default();
        configure_block_table_options(
            &mut in_mem_depth_table_opts,
            &cache,
            tuning_options,
            tuning_options.bloom_filter_bits_per_key.in_mem_depth,
        );

        let mut in_mem_depth_opts = Options::default();
        in_mem_depth_opts.set_compression_type(DBCompressionType::Lz4);
        in_mem_depth_opts.set_bottommost_compression_type(DBCompressionType::Zstd);
        // Enable the bottommost compression setting; selecting ZSTD alone is not enough.
        in_mem_depth_opts
            .set_bottommost_zstd_max_train_bytes(DEFAULT_BOTTOMMOST_ZSTD_MAX_TRAIN_BYTES, true);
        in_mem_depth_opts.set_block_based_table_factory(&in_mem_depth_table_opts);
        if let Some(wbm) = write_buffer_manager.as_ref() {
            in_mem_depth_opts.set_write_buffer_manager(wbm);
        }

        // Metadata CF with no compression
        let mut metadata_opts = Options::default();
        metadata_opts.set_compression_type(DBCompressionType::None);
        if let Some(wbm) = write_buffer_manager.as_ref() {
            metadata_opts.set_write_buffer_manager(wbm);
        }

        let bloom = &tuning_options.bloom_filter_bits_per_key;

        // Define column families with tailored options
        let cfs = vec![
            ColumnFamilyDescriptor::new(LEAVES_CF, leaves_opts),
            ColumnFamilyDescriptor::new(
                SUBTREE_16_CF,
                subtree_cf(&cache, tuning_options, bloom.subtree_16, write_buffer_manager.as_ref()),
            ),
            ColumnFamilyDescriptor::new(
                SUBTREE_24_CF,
                subtree_cf(&cache, tuning_options, bloom.subtree_24, write_buffer_manager.as_ref()),
            ),
            ColumnFamilyDescriptor::new(
                SUBTREE_32_CF,
                subtree_cf(&cache, tuning_options, bloom.subtree_32, write_buffer_manager.as_ref()),
            ),
            ColumnFamilyDescriptor::new(
                SUBTREE_40_CF,
                subtree_cf(&cache, tuning_options, bloom.subtree_40, write_buffer_manager.as_ref()),
            ),
            ColumnFamilyDescriptor::new(
                SUBTREE_48_CF,
                subtree_cf(&cache, tuning_options, bloom.subtree_48, write_buffer_manager.as_ref()),
            ),
            ColumnFamilyDescriptor::new(
                SUBTREE_56_CF,
                subtree_cf(&cache, tuning_options, bloom.subtree_56, write_buffer_manager.as_ref()),
            ),
            ColumnFamilyDescriptor::new(METADATA_CF, metadata_opts),
            ColumnFamilyDescriptor::new(IN_MEM_DEPTH_CF, in_mem_depth_opts),
        ];

        // Open the database with our tuned CFs
        let db = DB::open_cf_descriptors(&db_opts, config.path, cfs)?;

        Ok(Self {
            db: Arc::new(db),
            durability_mode: config.durability_mode,
        })
    }

    /// Syncs the RocksDB database to disk.
    ///
    /// This ensures that all data is persisted to disk.
    ///
    /// # Errors
    /// - Returns `StorageError::Backend` if the flush operation fails.
    fn sync(&self) -> StorageResult<()> {
        let mut fopts = FlushOptions::default();
        fopts.set_wait(true);

        for name in [
            LEAVES_CF,
            SUBTREE_16_CF,
            SUBTREE_24_CF,
            SUBTREE_32_CF,
            SUBTREE_40_CF,
            SUBTREE_48_CF,
            SUBTREE_56_CF,
            METADATA_CF,
            IN_MEM_DEPTH_CF,
        ] {
            let cf = self.cf_handle(name)?;
            self.db.flush_cf_opt(cf, &fopts)?;
        }

        self.db.flush_wal(true)?;
        Ok(())
    }

    fn write_options(&self) -> WriteOptions {
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(self.should_sync_writes());
        write_opts
    }

    fn write_batch(&self, batch: WriteBatch) -> StorageResult<()> {
        self.db.write_opt(batch, &self.write_options())?;
        Ok(())
    }

    fn should_sync_writes(&self) -> bool {
        self.durability_mode == RocksDbDurabilityMode::Sync
    }

    /// Converts an index (u64) into a fixed-size byte array for use as a RocksDB key.
    #[inline(always)]
    fn index_db_key(index: u64) -> [u8; 8] {
        index.to_be_bytes()
    }

    /// Converts a `NodeIndex` (for a subtree root) into a `KeyBytes` for use as a RocksDB key.
    /// The `KeyBytes` is a wrapper around a 8-byte value with a variable-length prefix.
    #[inline(always)]
    fn subtree_db_key(index: NodeIndex) -> KeyBytes {
        let keep = match index.depth() {
            16 => 2,
            24 => 3,
            32 => 4,
            40 => 5,
            48 => 6,
            56 => 7,
            d => panic!("unsupported depth {d}"),
        };
        KeyBytes::new(index.position(), keep)
    }

    /// Retrieves a handle to a RocksDB column family by its name.
    ///
    /// # Errors
    /// Returns `StorageError::Backend` if the column family with the given `name` does not
    /// exist.
    fn cf_handle(&self, name: &str) -> StorageResult<&rocksdb::ColumnFamily> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| StorageError::Unsupported(format!("unknown column family `{name}`")))
    }

    /* helper: CF handle from NodeIndex ------------------------------------- */
    #[inline(always)]
    fn subtree_cf(&self, index: NodeIndex) -> &rocksdb::ColumnFamily {
        let name = cf_for_depth(index.depth());
        self.cf_handle(name).expect("CF handle missing")
    }
}

impl SmtStorageReader for RocksDbStorage {
    /// Retrieves the total count of non-empty leaves from the `METADATA_CF` column family.
    /// Returns 0 if the count is not found.
    ///
    /// # Errors
    /// - `StorageError::Backend`: If the metadata column family is missing or a RocksDB error
    ///   occurs.
    /// - `StorageError::BadValueLen`: If the retrieved count bytes are invalid.
    fn leaf_count(&self) -> StorageResult<usize> {
        let cf = self.cf_handle(METADATA_CF)?;
        self.db.get_cf(cf, LEAF_COUNT_KEY)?.map_or(Ok(0), |bytes| {
            let arr: [u8; 8] =
                bytes.as_slice().try_into().map_err(|_| StorageError::BadValueLen {
                    what: "leaf count",
                    expected: 8,
                    found: bytes.len(),
                })?;
            Ok(usize::from_be_bytes(arr))
        })
    }

    /// Retrieves the total count of key-value entries from the `METADATA_CF` column family.
    /// Returns 0 if the count is not found.
    ///
    /// # Errors
    /// - `StorageError::Backend`: If the metadata column family is missing or a RocksDB error
    ///   occurs.
    /// - `StorageError::BadValueLen`: If the retrieved count bytes are invalid.
    fn entry_count(&self) -> StorageResult<usize> {
        let cf = self.cf_handle(METADATA_CF)?;
        self.db.get_cf(cf, ENTRY_COUNT_KEY)?.map_or(Ok(0), |bytes| {
            let arr: [u8; 8] =
                bytes.as_slice().try_into().map_err(|_| StorageError::BadValueLen {
                    what: "entry count",
                    expected: 8,
                    found: bytes.len(),
                })?;
            Ok(usize::from_be_bytes(arr))
        })
    }

    /// Retrieves a single SMT leaf node by its logical `index` from the `LEAVES_CF` column family.
    ///
    /// # Errors
    /// - `StorageError::Backend`: If the leaves column family is missing or a RocksDB error occurs.
    /// - `StorageError::DeserializationError`: If the retrieved leaf data is corrupt.
    fn get_leaf(&self, index: u64) -> StorageResult<Option<SmtLeaf>> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let key = Self::index_db_key(index);
        match self.db.get_cf(cf, key)? {
            Some(bytes) => {
                let leaf = SmtLeaf::read_from_bytes_with_budget(&bytes, bytes.len())?;
                Ok(Some(leaf))
            },
            None => Ok(None),
        }
    }

    /// Retrieves multiple SMT leaf nodes by their logical `indices` using RocksDB's `multi_get_cf`.
    ///
    /// # Errors
    /// - `StorageError::Backend`: If the leaves column family is missing or a RocksDB error occurs.
    /// - `StorageError::DeserializationError`: If any retrieved leaf data is corrupt.
    fn get_leaves(&self, indices: &[u64]) -> StorageResult<Vec<Option<SmtLeaf>>> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let db_keys: Vec<[u8; 8]> = indices.iter().map(|&idx| Self::index_db_key(idx)).collect();
        let results = self.db.multi_get_cf(db_keys.iter().map(|k| (cf, k.as_ref())));

        results
            .into_iter()
            .map(|result| match result {
                Ok(Some(bytes)) => {
                    Ok(Some(SmtLeaf::read_from_bytes_with_budget(&bytes, bytes.len())?))
                },
                Ok(None) => Ok(None),
                Err(e) => Err(e.into()),
            })
            .collect()
    }

    /// Returns true if the storage has any leaves.
    ///
    /// # Errors
    /// Returns `StorageError` if the storage read operation fails.
    fn has_leaves(&self) -> StorageResult<bool> {
        Ok(self.leaf_count()? > 0)
    }

    /// Batch-retrieves multiple subtrees from RocksDB by their node indices.
    ///
    /// This method groups requests by subtree depth into column family buckets,
    /// then performs parallel `multi_get` operations to efficiently retrieve
    /// all subtrees. Results are deserialized and placed in the same order as
    /// the input indices.
    ///
    /// Note: Retrieval is performed in parallel. If multiple errors occur (e.g.,
    /// deserialization or backend errors), only the first one encountered is returned.
    /// Other errors will be discarded.
    ///
    /// # Parameters
    /// - `indices`: A slice of subtree root indices to retrieve.
    ///
    /// # Returns
    /// - A `Vec<Option<Subtree>>` where each index corresponds to the original input.
    /// - `Ok(...)` if all fetches succeed.
    /// - `Err(StorageError)` if any RocksDB access or deserialization fails.
    fn get_subtree(&self, index: NodeIndex) -> StorageResult<Option<Subtree>> {
        let cf = self.subtree_cf(index);
        let key = Self::subtree_db_key(index);
        match self.db.get_cf(cf, key)? {
            Some(bytes) => {
                let subtree = Subtree::from_vec(index, &bytes)?;
                Ok(Some(subtree))
            },
            None => Ok(None),
        }
    }

    /// Batch-retrieves multiple subtrees from RocksDB by their node indices.
    ///
    /// This method groups requests by subtree depth into column family buckets,
    /// then performs parallel `multi_get` operations to efficiently retrieve
    /// all subtrees. Results are deserialized and placed in the same order as
    /// the input indices.
    ///
    /// # Parameters
    /// - `indices`: A slice of subtree root indices to retrieve.
    ///
    /// # Returns
    /// - A `Vec<Option<Subtree>>` where each index corresponds to the original input.
    /// - `Ok(...)` if all fetches succeed.
    /// - `Err(StorageError)` if any RocksDB access or deserialization fails.
    fn get_subtrees(&self, indices: &[NodeIndex]) -> StorageResult<Vec<Option<Subtree>>> {
        use p3_maybe_rayon::prelude::*;

        let mut depth_buckets: [Vec<(usize, NodeIndex)>; 6] = Default::default();

        for (original_index, &node_index) in indices.iter().enumerate() {
            let depth = node_index.depth();
            let bucket_index = match depth {
                56 => 0,
                48 => 1,
                40 => 2,
                32 => 3,
                24 => 4,
                16 => 5,
                _ => {
                    return Err(StorageError::Unsupported(format!(
                        "unsupported subtree depth {depth}"
                    )));
                },
            };
            depth_buckets[bucket_index].push((original_index, node_index));
        }
        let mut results = vec![None; indices.len()];

        // Process depth buckets in parallel
        let bucket_results: StorageResult<Vec<_>> = depth_buckets
            .into_par_iter()
            .enumerate()
            .filter(|(_, bucket)| !bucket.is_empty())
            .map(|(bucket_index, bucket)| -> StorageResult<Vec<(usize, Option<Subtree>)>> {
                let depth = LargeSmt::<RocksDbStorage>::SUBTREE_DEPTHS[bucket_index];
                let cf = self.cf_handle(cf_for_depth(depth))?;
                let keys: Vec<_> =
                    bucket.iter().map(|(_, idx)| Self::subtree_db_key(*idx)).collect();

                let db_results = self.db.multi_get_cf(keys.iter().map(|k| (cf, k.as_ref())));

                // Process results for this bucket
                bucket
                    .into_iter()
                    .zip(db_results)
                    .map(|((original_index, node_index), db_result)| {
                        let subtree = match db_result {
                            Ok(Some(bytes)) => Some(Subtree::from_vec(node_index, &bytes)?),
                            Ok(None) => None,
                            Err(e) => return Err(e.into()),
                        };
                        Ok((original_index, subtree))
                    })
                    .collect()
            })
            .collect();

        // Flatten results and place them in correct positions
        for bucket_result in bucket_results? {
            for (original_index, subtree) in bucket_result {
                results[original_index] = subtree;
            }
        }

        Ok(results)
    }

    /// Retrieves a single inner node (non-leaf node) from within a Subtree.
    ///
    /// This method is intended for accessing nodes at depths greater than or equal to
    /// `IN_MEMORY_DEPTH`. It first finds the appropriate Subtree containing the `index`, then
    /// delegates to `Subtree::get_inner_node()`.
    ///
    /// # Errors
    /// - `StorageError::Backend`: If `index.depth() < IN_MEMORY_DEPTH`, or if RocksDB errors occur.
    /// - `StorageError::Value`: If the containing Subtree data is corrupt.
    fn get_inner_node(&self, index: NodeIndex) -> StorageResult<Option<InnerNode>> {
        if index.depth() < IN_MEMORY_DEPTH {
            return Err(StorageError::Unsupported(
                "Cannot get inner node from upper part of the tree".into(),
            ));
        }
        let subtree_root_index = Subtree::find_subtree_root(index);
        Ok(self
            .get_subtree(subtree_root_index)?
            .and_then(|subtree| subtree.get_inner_node(index)))
    }

    /// Returns an iterator over all (logical u64 index, `SmtLeaf`) pairs in the `LEAVES_CF`.
    ///
    /// The iterator uses a RocksDB snapshot for consistency and iterates in lexicographical
    /// order of the keys (leaf indices). Errors during iteration (e.g., deserialization issues)
    /// are returned as iterator items.
    ///
    /// # Errors
    /// - `StorageError::Backend`: If the leaves column family is missing or a RocksDB error occurs
    ///   during iterator creation.
    fn iter_leaves(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = StorageResult<(u64, SmtLeaf)>> + '_>> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let mut read_opts = ReadOptions::default();
        read_opts.set_total_order_seek(true);
        let db_iter = self.db.iterator_cf_opt(cf, read_opts, IteratorMode::Start);

        Ok(Box::new(RocksDbDirectLeafIterator { iter: db_iter }))
    }

    /// Returns an iterator over all `Subtree` instances across all subtree column families.
    ///
    /// The iterator uses a RocksDB snapshot and iterates in lexicographical order of keys
    /// (subtree root NodeIndex) across all depth column families (24, 32, 40, 48, 56).
    /// Errors during iteration (e.g., deserialization issues) are returned as iterator items.
    ///
    /// # Errors
    /// - `StorageError::Backend`: If any subtree column family is missing or a RocksDB error occurs
    ///   during iterator creation.
    fn iter_subtrees(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = StorageResult<Subtree>> + '_>> {
        // All subtree column family names in order
        const SUBTREE_CFS: [&str; 6] = [
            SUBTREE_16_CF,
            SUBTREE_24_CF,
            SUBTREE_32_CF,
            SUBTREE_40_CF,
            SUBTREE_48_CF,
            SUBTREE_56_CF,
        ];

        let mut cf_handles = Vec::new();
        for cf_name in SUBTREE_CFS {
            cf_handles.push(self.cf_handle(cf_name)?);
        }

        Ok(Box::new(RocksDbSubtreeIterator::new(&self.db, cf_handles)))
    }

    /// Retrieves roots of all top level subtrees for efficient startup reconstruction.
    ///
    /// # Errors
    /// - `StorageError::Backend`: If the in-memory-depth column family is missing or a RocksDB
    ///   error occurs.
    /// - `StorageError::Value`: If any hash bytes are corrupt.
    fn get_top_subtree_roots(&self) -> StorageResult<Vec<(u64, Word)>> {
        let cf = self.cf_handle(IN_MEM_DEPTH_CF)?;
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        let mut hashes = Vec::new();

        for item in iter {
            let (key_bytes, value_bytes) = item?;

            let index = index_from_key_bytes(&key_bytes)?;
            let hash = Word::read_from_bytes_with_budget(&value_bytes, value_bytes.len())?;

            hashes.push((index, hash));
        }

        Ok(hashes)
    }
}

impl SmtStorage for RocksDbStorage {
    type Reader = RocksDbSnapshotStorage;

    /// Returns a detached read-only snapshot of the current RocksDB-backed storage.
    fn reader(&self) -> StorageResult<Self::Reader> {
        Ok(RocksDbSnapshotStorage::new(Arc::clone(&self.db)))
    }

    /// Inserts a key-value pair into the SMT leaf at the specified logical `index`.
    ///
    /// This operation involves:
    /// 1. Retrieving the current leaf (if any) at `index`.
    /// 2. Inserting the new key-value pair into the leaf.
    /// 3. Updating the leaf and entry counts in the metadata column family.
    /// 4. Writing all changes (leaf data, counts) to RocksDB in a single batch.
    ///
    /// Note: This only updates the leaf. Callers are responsible for recomputing and
    /// persisting the corresponding inner nodes.
    ///
    /// # Errors
    /// - `StorageError::Backend`: If column families are missing or a RocksDB error occurs.
    /// - `StorageError::DeserializationError`: If existing leaf data is corrupt.
    fn insert_value(&mut self, index: u64, key: Word, value: Word) -> StorageResult<Option<Word>> {
        debug_assert_ne!(value, EMPTY_WORD);

        let mut batch = WriteBatch::default();

        // Fetch initial counts.
        let mut current_leaf_count = self.leaf_count()?;
        let mut current_entry_count = self.entry_count()?;

        let leaves_cf = self.cf_handle(LEAVES_CF)?;
        let db_key = Self::index_db_key(index);

        let maybe_leaf = self.get_leaf(index)?;

        let value_to_return: Option<Word> = match maybe_leaf {
            Some(mut existing_leaf) => {
                let old_value = existing_leaf.insert(key, value).expect("Failed to insert value");
                // Determine if the overall SMT entry_count needs to change.
                // entry_count increases if:
                //   1. The key was not present in this leaf before (`old_value` is `None`).
                //   2. The key was present but held `EMPTY_WORD` (`old_value` is
                //      `Some(EMPTY_WORD)`).
                if old_value.is_none_or(|old_v| old_v == EMPTY_WORD) {
                    current_entry_count += 1;
                }
                // current_leaf_count does not change because the leaf itself already existed.
                batch.put_cf(leaves_cf, db_key, existing_leaf.to_bytes());
                old_value
            },
            None => {
                // Leaf at `index` does not exist, so create a new one.
                let new_leaf = SmtLeaf::Single((key, value));
                // A new leaf is created.
                current_leaf_count += 1;
                // This new leaf contains one new SMT entry.
                current_entry_count += 1;
                batch.put_cf(leaves_cf, db_key, new_leaf.to_bytes());
                // No previous value, as the leaf (and thus the key in it) was new.
                None
            },
        };

        // Add updated metadata counts to the batch.
        let metadata_cf = self.cf_handle(METADATA_CF)?;
        batch.put_cf(metadata_cf, LEAF_COUNT_KEY, current_leaf_count.to_be_bytes());
        batch.put_cf(metadata_cf, ENTRY_COUNT_KEY, current_entry_count.to_be_bytes());

        // Atomically write all changes (leaf data and metadata counts).
        self.write_batch(batch)?;

        Ok(value_to_return)
    }

    /// Removes a key-value pair from the SMT leaf at the specified logical `index`.
    ///
    /// This operation involves:
    /// 1. Retrieving the leaf at `index`.
    /// 2. Removing the `key` from the leaf. If the leaf becomes empty, it's deleted from RocksDB.
    /// 3. Updating the leaf and entry counts in the metadata column family.
    /// 4. Writing all changes (leaf data/deletion, counts) to RocksDB in a single batch.
    ///
    /// Returns `Ok(None)` if the leaf at `index` does not exist or the `key` is not found.
    ///
    /// Note: This only updates the leaf. Callers are responsible for recomputing and
    /// persisting the corresponding inner nodes.
    ///
    /// # Errors
    /// - `StorageError::Backend`: If column families are missing or a RocksDB error occurs.
    /// - `StorageError::DeserializationError`: If existing leaf data is corrupt.
    fn remove_value(&mut self, index: u64, key: Word) -> StorageResult<Option<Word>> {
        let Some(mut leaf) = self.get_leaf(index)? else {
            return Ok(None);
        };

        let mut batch = WriteBatch::default();
        let cf = self.cf_handle(LEAVES_CF)?;
        let metadata_cf = self.cf_handle(METADATA_CF)?;
        let db_key = Self::index_db_key(index);
        let mut entry_count = self.entry_count()?;
        let mut leaf_count = self.leaf_count()?;

        let (current_value, is_empty) = leaf.remove(key);
        if let Some(current_value) = current_value
            && current_value != EMPTY_WORD
        {
            entry_count -= 1;
        }
        if is_empty {
            leaf_count -= 1;
            batch.delete_cf(cf, db_key);
        } else {
            batch.put_cf(cf, db_key, leaf.to_bytes());
        }
        batch.put_cf(metadata_cf, LEAF_COUNT_KEY, leaf_count.to_be_bytes());
        batch.put_cf(metadata_cf, ENTRY_COUNT_KEY, entry_count.to_be_bytes());
        self.write_batch(batch)?;
        Ok(current_value)
    }

    /// Sets or updates multiple SMT leaf nodes in the `LEAVES_CF` column family.
    ///
    /// This method performs a batch write to RocksDB. It also updates the global
    /// leaf and entry counts in the `METADATA_CF` based on the provided `leaves` map,
    /// overwriting any previous counts.
    ///
    /// Note: This method assumes the provided `leaves` map represents the entirety
    /// of leaves to be stored or that counts are being explicitly reset.
    /// Note: This only updates the leaves. Callers are responsible for recomputing and
    /// persisting the corresponding inner nodes.
    ///
    /// # Errors
    /// - `StorageError::Backend`: If column families are missing or a RocksDB error occurs.
    fn set_leaves(&mut self, leaves: Map<u64, SmtLeaf>) -> StorageResult<()> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let leaf_count: usize = leaves.len();
        let entry_count: usize = leaves.values().map(|leaf| leaf.entries().len()).sum();
        let mut batch = WriteBatch::default();
        for (idx, leaf) in leaves {
            let key = Self::index_db_key(idx);
            let value = leaf.to_bytes();
            batch.put_cf(cf, key, &value);
        }
        let metadata_cf = self.cf_handle(METADATA_CF)?;
        batch.put_cf(metadata_cf, LEAF_COUNT_KEY, leaf_count.to_be_bytes());
        batch.put_cf(metadata_cf, ENTRY_COUNT_KEY, entry_count.to_be_bytes());
        self.write_batch(batch)?;
        Ok(())
    }

    /// Removes a single SMT leaf node by its logical `index` from the `LEAVES_CF` column family.
    ///
    /// Important: This method currently *does not* update the global leaf and entry counts
    /// in the metadata. Callers are responsible for managing these counts separately
    /// if using this method directly, or preferably use `apply` or `remove_value` which handle
    /// counts.
    ///
    /// Note: This only removes the leaf. Callers are responsible for recomputing and
    /// persisting the corresponding inner nodes.
    ///
    /// # Errors
    /// - `StorageError::Backend`: If the leaves column family is missing or a RocksDB error occurs.
    /// - `StorageError::DeserializationError`: If the retrieved (to be returned) leaf data is
    ///   corrupt.
    fn remove_leaf(&mut self, index: u64) -> StorageResult<Option<SmtLeaf>> {
        let key = Self::index_db_key(index);
        let cf = self.cf_handle(LEAVES_CF)?;
        let old_bytes = self.db.get_cf(cf, key)?;
        let mut batch = WriteBatch::default();
        batch.delete_cf(cf, key);
        self.write_batch(batch)?;
        Ok(old_bytes.map(|bytes| {
            SmtLeaf::read_from_bytes_with_budget(&bytes, bytes.len())
                .expect("failed to deserialize leaf")
        }))
    }

    /// Stores a single subtree in RocksDB and optionally updates the in-memory-depth root cache.
    ///
    /// The subtree is serialized and written to its corresponding column family.
    /// If it’s an in-memory-depth subtree, the root node’s hash is also stored in the
    /// dedicated `IN_MEM_DEPTH_CF` cache to support top-level reconstruction.
    ///
    /// # Parameters
    /// - `subtree`: A reference to the subtree to be stored.
    ///
    /// # Errors
    /// - Returns `StorageError` if column family lookup, serialization, or the write operation
    ///   fails.
    fn set_subtree(&mut self, subtree: &Subtree) -> StorageResult<()> {
        let subtrees_cf = self.subtree_cf(subtree.root_index());
        let mut batch = WriteBatch::default();

        let key = Self::subtree_db_key(subtree.root_index());
        let value = subtree.to_vec();
        batch.put_cf(subtrees_cf, key, value);

        // Also update in-memory-depth hash cache if this is an in-memory-depth subtree
        if subtree.root_index().depth() == IN_MEMORY_DEPTH {
            let root_hash = subtree
                .get_inner_node(subtree.root_index())
                .ok_or_else(|| StorageError::Unsupported("Subtree root node not found".into()))?
                .hash();

            let in_mem_depth_cf = self.cf_handle(IN_MEM_DEPTH_CF)?;
            let hash_key = Self::index_db_key(subtree.root_index().position());
            batch.put_cf(in_mem_depth_cf, hash_key, root_hash.to_bytes());
        }

        self.write_batch(batch)?;
        Ok(())
    }

    /// Bulk-writes subtrees to storage.
    ///
    /// This method writes a vector of serialized `Subtree` objects directly to their
    /// corresponding RocksDB column families based on their root index.
    ///
    /// Uses default write options to keep WAL enabled. Disabling WAL would make writes
    /// non-crash-safe: data in the memtable is lost on unexpected termination, causing root
    /// mismatch on restart (see miden-node#1558).
    ///
    /// # Parameters
    /// - `subtrees`: A vector of `Subtree` objects to be serialized and persisted.
    ///
    /// # Errors
    /// - Returns `StorageError::Backend` if any column family lookup or RocksDB write fails.
    fn set_subtrees(&mut self, subtrees: Vec<Subtree>) -> StorageResult<()> {
        let in_mem_depth_cf = self.cf_handle(IN_MEM_DEPTH_CF)?;
        let mut batch = WriteBatch::default();

        for subtree in subtrees {
            let subtrees_cf = self.subtree_cf(subtree.root_index());
            let key = Self::subtree_db_key(subtree.root_index());
            let value = subtree.to_vec();
            batch.put_cf(subtrees_cf, key, value);

            if subtree.root_index().depth() == IN_MEMORY_DEPTH
                && let Some(root_node) = subtree.get_inner_node(subtree.root_index())
            {
                let hash_key = Self::index_db_key(subtree.root_index().position());
                batch.put_cf(in_mem_depth_cf, hash_key, root_node.hash().to_bytes());
            }
        }

        self.write_batch(batch)?;
        Ok(())
    }

    /// Removes a single SMT Subtree from storage, identified by its root `NodeIndex`.
    ///
    /// # Errors
    /// - `StorageError::Backend`: If the subtrees column family is missing or a RocksDB error
    ///   occurs.
    fn remove_subtree(&mut self, index: NodeIndex) -> StorageResult<()> {
        let subtrees_cf = self.subtree_cf(index);
        let mut batch = WriteBatch::default();

        let key = Self::subtree_db_key(index);
        batch.delete_cf(subtrees_cf, key);

        // Also remove in-memory-depth hash cache if this is an in-memory-depth subtree
        if index.depth() == IN_MEMORY_DEPTH {
            let in_mem_depth_cf = self.cf_handle(IN_MEM_DEPTH_CF)?;
            let hash_key = Self::index_db_key(index.position());
            batch.delete_cf(in_mem_depth_cf, hash_key);
        }

        self.write_batch(batch)?;
        Ok(())
    }

    /// Sets or updates a single inner node (non-leaf node) within a Subtree.
    ///
    /// This method is intended for `index.depth() >= IN_MEMORY_DEPTH`.
    /// If the target Subtree does not exist, it is created. The `node` is then
    /// inserted into the Subtree, and the modified Subtree is written back to storage.
    ///
    /// # Errors
    /// - `StorageError::Backend`: If `index.depth() < IN_MEMORY_DEPTH`, or if RocksDB errors occur.
    /// - `StorageError::Value`: If existing Subtree data is corrupt.
    fn set_inner_node(
        &mut self,
        index: NodeIndex,
        node: InnerNode,
    ) -> StorageResult<Option<InnerNode>> {
        if index.depth() < IN_MEMORY_DEPTH {
            return Err(StorageError::Unsupported(
                "Cannot set inner node in upper part of the tree".into(),
            ));
        }

        let subtree_root_index = Subtree::find_subtree_root(index);
        let mut subtree = self
            .get_subtree(subtree_root_index)?
            .unwrap_or_else(|| Subtree::new(subtree_root_index));
        let old_node = subtree.insert_inner_node(index, node);
        self.set_subtree(&subtree)?;
        Ok(old_node)
    }

    /// Removes a single inner node (non-leaf node) from within a Subtree.
    ///
    /// This method is intended for `index.depth() >= IN_MEMORY_DEPTH`.
    /// If the Subtree becomes empty after removing the node, the Subtree itself
    /// is removed from storage.
    ///
    /// # Errors
    /// - `StorageError::Backend`: If `index.depth() < IN_MEMORY_DEPTH`, or if RocksDB errors occur.
    /// - `StorageError::Value`: If existing Subtree data is corrupt.
    fn remove_inner_node(&mut self, index: NodeIndex) -> StorageResult<Option<InnerNode>> {
        if index.depth() < IN_MEMORY_DEPTH {
            return Err(StorageError::Unsupported(
                "Cannot remove inner node from upper part of the tree".into(),
            ));
        }

        let subtree_root_index = Subtree::find_subtree_root(index);
        self.get_subtree(subtree_root_index)
            .and_then(|maybe_subtree| match maybe_subtree {
                Some(mut subtree) => {
                    let old_node = subtree.remove_inner_node(index);
                    let db_operation_result = if subtree.is_empty() {
                        self.remove_subtree(subtree_root_index)
                    } else {
                        self.set_subtree(&subtree)
                    };
                    db_operation_result.map(|_| old_node)
                },
                None => Ok(None),
            })
    }

    /// Applies a batch of `StorageUpdates` atomically to the RocksDB backend.
    ///
    /// This is the primary method for persisting changes to the SMT. It constructs a single
    /// RocksDB `WriteBatch` containing all specified changes:
    /// - Leaf updates/deletions in `LEAVES_CF`.
    /// - Subtree updates/deletions in `SUBTREE_24_CF`, `SUBTREE_32_CF`, `SUBTREE_40_CF`,
    ///   `SUBTREE_48_CF`, `SUBTREE_56_CF`.
    /// - Updates to leaf and entry counts in `METADATA_CF` based on `leaf_count_delta` and
    ///   `entry_count_delta`.
    ///
    /// All operations in the batch are applied atomically by RocksDB.
    ///
    /// # Errors
    /// - `StorageError::Backend`: If any column family is missing or a RocksDB write error occurs.
    fn apply(&mut self, updates: StorageUpdates) -> StorageResult<()> {
        use p3_maybe_rayon::prelude::*;

        let mut batch = WriteBatch::default();

        let leaves_cf = self.cf_handle(LEAVES_CF)?;
        let metadata_cf = self.cf_handle(METADATA_CF)?;
        let in_mem_depth_cf = self.cf_handle(IN_MEM_DEPTH_CF)?;

        let StorageUpdateParts {
            leaf_updates,
            subtree_updates,
            leaf_count_delta,
            entry_count_delta,
        } = updates.into_parts();

        // Process leaf updates
        for (index, maybe_leaf) in leaf_updates {
            let key = Self::index_db_key(index);
            match maybe_leaf {
                Some(leaf) => batch.put_cf(leaves_cf, key, leaf.to_bytes()),
                None => batch.delete_cf(leaves_cf, key),
            }
        }

        // Helper for in-memory-depth operations
        let is_in_mem_depth = |index: NodeIndex| index.depth() == IN_MEMORY_DEPTH;

        // Parallel preparation of subtree operations
        let subtree_ops: StorageResult<Vec<_>> = subtree_updates
            .into_par_iter()
            .map(|update| -> StorageResult<_> {
                let (index, maybe_bytes, in_mem_depth_op) = match update {
                    SubtreeUpdate::Store { index, subtree } => {
                        let bytes = subtree.to_vec();
                        let in_mem_depth_op = is_in_mem_depth(index)
                            .then(|| subtree.get_inner_node(index))
                            .flatten()
                            .map(|root_node| {
                                let hash_key = Self::index_db_key(index.position());
                                (hash_key, Some(root_node.hash().to_bytes()))
                            });
                        (index, Some(bytes), in_mem_depth_op)
                    },
                    SubtreeUpdate::Delete { index } => {
                        let in_mem_depth_op = is_in_mem_depth(index).then(|| {
                            let hash_key = Self::index_db_key(index.position());
                            (hash_key, None)
                        });
                        (index, None, in_mem_depth_op)
                    },
                };

                let key = Self::subtree_db_key(index);
                let subtrees_cf = self.subtree_cf(index);

                Ok((subtrees_cf, key, maybe_bytes, in_mem_depth_op))
            })
            .collect();

        // Sequential batch building
        for (subtrees_cf, key, maybe_bytes, in_mem_depth_op) in subtree_ops? {
            match maybe_bytes {
                Some(bytes) => batch.put_cf(subtrees_cf, key, bytes),
                None => batch.delete_cf(subtrees_cf, key),
            }

            if let Some((hash_key, maybe_hash_bytes)) = in_mem_depth_op {
                match maybe_hash_bytes {
                    Some(hash_bytes) => batch.put_cf(in_mem_depth_cf, hash_key, hash_bytes),
                    None => batch.delete_cf(in_mem_depth_cf, hash_key),
                }
            }
        }

        if leaf_count_delta != 0 || entry_count_delta != 0 {
            let current_leaf_count = self.leaf_count()?;
            let current_entry_count = self.entry_count()?;

            let new_leaf_count = current_leaf_count.saturating_add_signed(leaf_count_delta);
            let new_entry_count = current_entry_count.saturating_add_signed(entry_count_delta);

            batch.put_cf(metadata_cf, LEAF_COUNT_KEY, new_leaf_count.to_be_bytes());
            batch.put_cf(metadata_cf, ENTRY_COUNT_KEY, new_entry_count.to_be_bytes());
        }

        self.write_batch(batch)?;

        Ok(())
    }
}

/// Syncs the RocksDB database to disk before dropping the storage.
///
/// This ensures that all data is persisted to disk before the storage is dropped.
///
/// # Panics
/// - If the RocksDB sync operation fails.
impl Drop for RocksDbStorage {
    fn drop(&mut self) {
        if let Err(e) = self.sync() {
            panic!("failed to flush RocksDB on drop: {e}");
        }
    }
}

// ITERATORS
// --------------------------------------------------------------------------------------------

/// An iterator over leaves directly from RocksDB.
///
/// Wraps a `DBIteratorWithThreadMode` and handles deserialization of keys to `u64` (leaf index)
/// and values to `SmtLeaf`.
struct RocksDbDirectLeafIterator<'a> {
    iter: DBIteratorWithThreadMode<'a, DB>,
}

impl Iterator for RocksDbDirectLeafIterator<'_> {
    type Item = StorageResult<(u64, SmtLeaf)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|result| {
            result.map_err(StorageError::from).and_then(|(key_bytes, value_bytes)| {
                let leaf_idx = index_from_key_bytes(&key_bytes)?;
                let leaf = SmtLeaf::read_from_bytes_with_budget(&value_bytes, value_bytes.len())?;
                Ok((leaf_idx, leaf))
            })
        })
    }
}

/// An iterator over subtrees from multiple RocksDB column families.
///
/// Iterates through all subtree column families (24, 32, 40, 48, 56) sequentially.
/// When one column family is exhausted, it moves to the next one.
struct RocksDbSubtreeIterator<'a> {
    db: &'a DB,
    cf_handles: Vec<&'a rocksdb::ColumnFamily>,
    current_cf_index: usize,
    current_iter: Option<DBIteratorWithThreadMode<'a, DB>>,
}

impl<'a> RocksDbSubtreeIterator<'a> {
    fn new(db: &'a DB, cf_handles: Vec<&'a rocksdb::ColumnFamily>) -> Self {
        let mut iterator = Self {
            db,
            cf_handles,
            current_cf_index: 0,
            current_iter: None,
        };
        iterator.advance_to_next_cf();
        iterator
    }

    fn advance_to_next_cf(&mut self) {
        if self.current_cf_index < self.cf_handles.len() {
            let cf = self.cf_handles[self.current_cf_index];
            let mut read_opts = ReadOptions::default();
            read_opts.set_total_order_seek(true);
            self.current_iter = Some(self.db.iterator_cf_opt(cf, read_opts, IteratorMode::Start));
        } else {
            self.current_iter = None;
        }
    }

    fn next_from_iter(
        iter: &mut DBIteratorWithThreadMode<DB>,
        cf_index: usize,
    ) -> Option<StorageResult<Subtree>> {
        iter.next().map(|result| {
            result.map_err(StorageError::from).and_then(|(key_bytes, value_bytes)| {
                let depth = IN_MEMORY_DEPTH + (cf_index * 8) as u8;

                let node_idx = subtree_root_from_key_bytes(&key_bytes, depth)?;
                let value_vec = value_bytes.into_vec();
                Ok(Subtree::from_vec(node_idx, &value_vec)?)
            })
        })
    }
}

impl Iterator for RocksDbSubtreeIterator<'_> {
    type Item = StorageResult<Subtree>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let iter = self.current_iter.as_mut()?;

            // Try to get the next valid subtree from current iterator
            if let Some(result) = Self::next_from_iter(iter, self.current_cf_index) {
                return Some(result);
            }

            // Current CF exhausted, advance to next
            self.current_cf_index += 1;
            self.advance_to_next_cf();

            // If no more CFs, we're done
            self.current_iter.as_ref()?;
        }
    }
}

fn configure_smt_cf_options(opts: &mut Options) {
    // 128 MB memtable
    opts.set_write_buffer_size(128 << 20);
    // Allow up to 3 memtables
    opts.set_max_write_buffer_number(3);
    opts.set_min_write_buffer_number_to_merge(1);
    // Do not retain flushed memtables in memory
    opts.set_max_write_buffer_size_to_maintain(0);
    // Use level-based compaction
    opts.set_compaction_style(DBCompactionStyle::Level);
    // 512 MB target file size
    opts.set_target_file_size_base(512 << 20);
    opts.set_target_file_size_multiplier(2);
    // LZ4 compression for active files, ZSTD for bottommost files
    opts.set_compression_type(DBCompressionType::Lz4);
    opts.set_bottommost_compression_type(DBCompressionType::Zstd);
    // Enable the bottommost compression setting; selecting ZSTD alone is not enough.
    opts.set_bottommost_zstd_max_train_bytes(DEFAULT_BOTTOMMOST_ZSTD_MAX_TRAIN_BYTES, true);
    // Set level-based compaction parameters
    opts.set_level_zero_file_num_compaction_trigger(8);
}

fn configure_block_table_options(
    table_opts: &mut BlockBasedOptions,
    cache: &Cache,
    tuning_options: &RocksDbTuningOptions,
    bloom_bits_per_key: f64,
) {
    // Keep all block-based column families on the same cache and metadata policy.
    table_opts.set_block_cache(cache);
    table_opts.set_cache_index_and_filter_blocks(true);
    table_opts.set_bloom_filter(bloom_bits_per_key, false);
    table_opts.set_block_size(tuning_options.block_size);
    table_opts.set_whole_key_filtering(true);
    table_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
}

// ROCKSDB CONFIGURATION
// --------------------------------------------------------------------------------------------

/// Configuration for RocksDB storage used by the Sparse Merkle Tree implementation.
///
/// This struct contains the essential configuration parameters needed to initialize
/// and optimize RocksDB for SMT storage operations. It provides sensible defaults
/// while allowing customization for specific performance requirements.
#[derive(Debug, Clone, PartialEq)]
pub struct RocksDbConfig {
    /// The filesystem path where the RocksDB database will be stored.
    ///
    /// This should be a directory path that the application has read/write permissions for.
    /// The database will create multiple files in this directory to store data, logs, and
    /// metadata.
    pub(crate) path: PathBuf,

    /// The size of the RocksDB block cache in bytes.
    ///
    /// This cache stores frequently accessed data blocks in memory to improve read performance.
    /// Larger cache sizes generally improve read performance but consume more memory.
    /// Default: 1GB (1 << 30 bytes)
    pub(crate) cache_size: usize,

    /// The maximum number of files that RocksDB can have open simultaneously.
    ///
    /// This setting affects both memory usage and the number of file descriptors used by the
    /// process. Higher values may improve performance for databases with many SST files but
    /// increase resource usage. Default: 512 files
    pub(crate) max_open_files: i32,

    /// Optional per-DB write-buffer manager shared by this DB's column families.
    pub(crate) write_buffer_manager: Option<RocksDbWriteBufferManagerBudget>,

    /// Tunable RocksDB profile values.
    pub(crate) tuning_options: RocksDbTuningOptions,

    /// Write durability mode for RocksDB write operations.
    pub(crate) durability_mode: RocksDbDurabilityMode,
}

impl RocksDbConfig {
    /// Creates a new RocksDbConfig with the given database path and default settings.
    ///
    /// # Arguments
    /// * `path` - The filesystem path where the RocksDB database will be stored. This can be any
    ///   type that converts into a `PathBuf`.
    ///
    /// # Default Settings
    /// * `cache_size`: 1GB (1,073,741,824 bytes)
    /// * `max_open_files`: 512
    /// * `write_buffer_manager`: disabled
    /// * `tuning_options`: [`RocksDbTuningOptions::default()`]
    /// * `durability_mode`: [`RocksDbDurabilityMode::Relaxed`]
    ///
    /// # Examples
    /// ```
    /// use miden_crypto::merkle::smt::RocksDbConfig;
    ///
    /// let config = RocksDbConfig::new("/path/to/database");
    /// ```
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            path: path.into(),
            cache_size: DEFAULT_CACHE_SIZE,
            max_open_files: DEFAULT_MAX_OPEN_FILES,
            write_buffer_manager: None,
            tuning_options: RocksDbTuningOptions::default(),
            durability_mode: RocksDbDurabilityMode::default(),
        }
    }

    /// Sets the block cache size for RocksDB.
    ///
    /// The block cache stores frequently accessed data blocks in memory to improve read
    /// performance. Larger cache sizes generally improve read performance but consume more
    /// memory.
    ///
    /// # Arguments
    /// * `size` - The cache size in bytes.
    ///
    /// # Examples
    /// ```
    /// use miden_crypto::merkle::smt::RocksDbConfig;
    ///
    /// let config = RocksDbConfig::new("/path/to/database")
    ///     .with_cache_size(2 * 1024 * 1024 * 1024); // 2GB cache
    /// ```
    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.cache_size = size;
        self
    }

    /// Sets the RocksDB memory budget for this database instance.
    ///
    /// This controls the block cache size and optional write-buffer manager created by
    /// [`RocksDbStorage::open`] for one DB and its column families. It is not a process-wide
    /// budget across multiple RocksDB instances.
    #[must_use]
    pub fn with_memory_budget(mut self, memory_budget: RocksDbMemoryBudget) -> Self {
        let RocksDbMemoryBudget { block_cache_size, write_buffer_manager } = memory_budget;
        self.cache_size = block_cache_size;
        self.write_buffer_manager = write_buffer_manager;
        self
    }

    /// Sets the maximum number of files that RocksDB can have open simultaneously.
    ///
    /// This setting affects both memory usage and the number of file descriptors used by the
    /// process. Higher values may improve performance for databases with many SST files but
    /// increase resource usage.
    ///
    /// # Arguments
    /// * `count` - The maximum number of open files. Must be positive.
    ///
    /// # Examples
    /// ```
    /// use miden_crypto::merkle::smt::RocksDbConfig;
    ///
    /// let config = RocksDbConfig::new("/path/to/database")
    ///     .with_max_open_files(1024); // Allow up to 1024 open files
    /// ```
    pub fn with_max_open_files(mut self, count: i32) -> Self {
        self.max_open_files = count;
        self
    }

    /// Sets the RocksDB tuning options.
    #[must_use]
    pub fn with_tuning_options(mut self, tuning_options: RocksDbTuningOptions) -> Self {
        self.tuning_options = tuning_options;
        self
    }

    /// Sets the RocksDB write durability mode.
    ///
    /// The default is [`RocksDbDurabilityMode::Relaxed`], matching RocksDB's default non-sync
    /// writes.
    #[must_use]
    pub fn with_durability_mode(mut self, durability_mode: RocksDbDurabilityMode) -> Self {
        self.durability_mode = durability_mode;
        self
    }

    fn write_buffer_manager(&self, cache: &Cache) -> Option<WriteBufferManager> {
        self.write_buffer_manager.as_ref().map(|budget| {
            if budget.charge_to_block_cache {
                WriteBufferManager::new_write_buffer_manager_with_cache(
                    budget.buffer_size,
                    budget.allow_stall,
                    cache.clone(),
                )
            } else {
                WriteBufferManager::new_write_buffer_manager(budget.buffer_size, budget.allow_stall)
            }
        })
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub enum RocksDbDurabilityMode {
    #[default]
    Relaxed,
    Sync,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RocksDbMemoryBudget {
    /// Block cache size for one RocksDB instance.
    pub block_cache_size: usize,
    /// Optional write-buffer manager for one RocksDB instance.
    pub write_buffer_manager: Option<RocksDbWriteBufferManagerBudget>,
}

impl Default for RocksDbMemoryBudget {
    fn default() -> Self {
        Self {
            block_cache_size: DEFAULT_CACHE_SIZE,
            write_buffer_manager: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RocksDbWriteBufferManagerBudget {
    pub buffer_size: usize,
    pub allow_stall: bool,
    pub charge_to_block_cache: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RocksDbTuningOptions {
    pub block_size: usize,
    pub max_total_wal_size: u64,
    pub bloom_filter_bits_per_key: RocksDbBloomFilterBitsPerKey,
}

impl Default for RocksDbTuningOptions {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE,
            max_total_wal_size: DEFAULT_MAX_TOTAL_WAL_SIZE,
            bloom_filter_bits_per_key: RocksDbBloomFilterBitsPerKey::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RocksDbBloomFilterBitsPerKey {
    pub leaves: f64,
    pub in_mem_depth: f64,
    pub subtree_16: f64,
    pub subtree_24: f64,
    pub subtree_32: f64,
    pub subtree_40: f64,
    pub subtree_48: f64,
    pub subtree_56: f64,
}

impl Default for RocksDbBloomFilterBitsPerKey {
    fn default() -> Self {
        Self {
            leaves: DEFAULT_BLOOM_FILTER_BITS_PER_KEY,
            in_mem_depth: DEFAULT_BLOOM_FILTER_BITS_PER_KEY,
            subtree_16: DEFAULT_BLOOM_FILTER_BITS_PER_KEY,
            subtree_24: DEFAULT_BLOOM_FILTER_BITS_PER_KEY,
            subtree_32: DEFAULT_BLOOM_FILTER_BITS_PER_KEY,
            subtree_40: DEFAULT_BLOOM_FILTER_BITS_PER_KEY,
            subtree_48: DEFAULT_BLOOM_FILTER_BITS_PER_KEY,
            subtree_56: DEFAULT_BLOOM_FILTER_BITS_PER_KEY,
        }
    }
}

// SUBTREE DB KEY
// --------------------------------------------------------------------------------------------

/// Compact key wrapper for variable-length subtree prefixes.
///
/// * `bytes` always holds the big-endian 8-byte value.
/// * `len` is how many leading bytes are significant (3-7).
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub(crate) struct KeyBytes {
    bytes: [u8; 8],
    len: u8,
}

impl KeyBytes {
    #[inline(always)]
    pub fn new(value: u64, keep: usize) -> Self {
        debug_assert!((2..=7).contains(&keep));
        let bytes = value.to_be_bytes();
        debug_assert!(bytes[..8 - keep].iter().all(|&b| b == 0));
        Self { bytes, len: keep as u8 }
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[8 - self.len as usize..]
    }
}

impl AsRef<[u8]> for KeyBytes {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

// HELPERS
// --------------------------------------------------------------------------------------------

/// Deserializes an index (u64) from a RocksDB key byte slice.
/// Expects `key_bytes` to be exactly 8 bytes long.
///
/// # Errors
/// - `StorageError::BadKeyLen`: If `key_bytes` is not 8 bytes long or conversion fails.
fn index_from_key_bytes(key_bytes: &[u8]) -> StorageResult<u64> {
    if key_bytes.len() != 8 {
        return Err(StorageError::BadKeyLen { expected: 8, found: key_bytes.len() });
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(key_bytes);
    Ok(u64::from_be_bytes(arr))
}

fn read_count(what: &'static str, bytes: &[u8]) -> StorageResult<usize> {
    let arr: [u8; 8] = bytes.try_into().map_err(|_| StorageError::BadValueLen {
        what,
        expected: 8,
        found: bytes.len(),
    })?;
    Ok(usize::from_be_bytes(arr))
}

fn collect_to_subtree_roots(
    iter: DBIteratorWithThreadMode<'_, DB>,
) -> StorageResult<Vec<(u64, Word)>> {
    let mut hashes = Vec::new();

    for item in iter {
        let (key_bytes, value_bytes) = item?;

        let index = index_from_key_bytes(&key_bytes)?;
        let hash = Word::read_from_bytes_with_budget(&value_bytes, value_bytes.len())?;

        hashes.push((index, hash));
    }

    Ok(hashes)
}

/// Reconstructs a `NodeIndex` from the variable-length subtree key stored in RocksDB.
///
/// * `key_bytes` is the big-endian tail of the 64-bit value:
///   - depth 56 → 7 bytes
///   - depth 48 → 6 bytes
///   - depth 40 → 5 bytes
///   - depth 32 → 4 bytes
///   - depth 24 → 3 bytes
///   - depth 16 → 2 bytes
///
/// # Errors
/// * `StorageError::Unsupported` -  `depth` is not one of 24/32/40/48/56.
/// * `StorageError::DeserializationError` - `key_bytes.len()` does not match the length required by
///   `depth`.
#[inline(always)]
fn subtree_root_from_key_bytes(key_bytes: &[u8], depth: u8) -> StorageResult<NodeIndex> {
    let expected = match depth {
        16 => 2,
        24 => 3,
        32 => 4,
        40 => 5,
        48 => 6,
        56 => 7,
        d => return Err(StorageError::Unsupported(format!("unsupported subtree depth {d}"))),
    };

    if key_bytes.len() != expected {
        return Err(StorageError::BadSubtreeKeyLen { depth, expected, found: key_bytes.len() });
    }
    let mut buf = [0u8; 8];
    buf[8 - expected..].copy_from_slice(key_bytes);
    let value = u64::from_be_bytes(buf);
    Ok(NodeIndex::new_unchecked(depth, value))
}

/// Helper that maps an SMT depth to its column family.
#[inline(always)]
fn cf_for_depth(depth: u8) -> &'static str {
    match depth {
        16 => SUBTREE_16_CF,
        24 => SUBTREE_24_CF,
        32 => SUBTREE_32_CF,
        40 => SUBTREE_40_CF,
        48 => SUBTREE_48_CF,
        56 => SUBTREE_56_CF,
        _ => panic!("unsupported subtree depth: {depth}"),
    }
}

impl From<rocksdb::Error> for StorageError {
    fn from(e: rocksdb::Error) -> Self {
        StorageError::Backend(Box::new(e))
    }
}

// ROCKSDB SNAPSHOT STORAGE
// ================================================================================================

/// Read-only, cloneable SMT storage backed by a native RocksDB point-in-time snapshot.
#[derive(Clone)]
pub struct RocksDbSnapshotStorage {
    inner: Arc<RocksDbSnapshotInner>,
}

impl fmt::Debug for RocksDbSnapshotStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RocksDbSnapshotStorage").finish_non_exhaustive()
    }
}

/// Owns a RocksDB snapshot together with the database it borrows from.
///
/// `rocksdb::Snapshot<'a>` borrows the database used to create it. This type stores an `Arc<DB>`
/// beside the snapshot and releases the snapshot before the `Arc` is dropped, so the borrowed
/// database remains alive for the full lifetime of the snapshot.
struct RocksDbSnapshotInner {
    snapshot: ManuallyDrop<rocksdb::Snapshot<'static>>,
    db: Arc<DB>,
}

impl RocksDbSnapshotInner {
    fn new(db: Arc<DB>) -> Self {
        let snapshot = db.snapshot();
        // SAFETY: The snapshot internally stores a reference to the same `DB` allocation owned by
        // `db`. `RocksDbSnapshotInner` keeps that `Arc<DB>` alive and its `Drop` implementation
        // manually releases the snapshot before the `Arc<DB>` field is dropped.
        let snapshot = unsafe {
            core::mem::transmute::<rocksdb::Snapshot<'_>, rocksdb::Snapshot<'static>>(snapshot)
        };
        Self {
            snapshot: ManuallyDrop::new(snapshot),
            db,
        }
    }
}

impl Drop for RocksDbSnapshotInner {
    fn drop(&mut self) {
        // SAFETY: `snapshot` was placed in `ManuallyDrop` only to control field drop order. It is
        // dropped exactly once here, before `db` is dropped by Rust's normal field cleanup.
        unsafe {
            ManuallyDrop::drop(&mut self.snapshot);
        }
    }
}

impl RocksDbSnapshotStorage {
    /// Creates a snapshot-backed storage reader from a shared RocksDB handle.
    pub fn new(db: Arc<DB>) -> Self {
        Self {
            inner: Arc::new(RocksDbSnapshotInner::new(db)),
        }
    }

    /// Retrieves a handle to a RocksDB column family by its name.
    fn cf_handle(&self, name: &str) -> StorageResult<&rocksdb::ColumnFamily> {
        self.inner
            .db
            .cf_handle(name)
            .ok_or_else(|| StorageError::Unsupported(format!("unknown column family `{name}`")))
    }

    #[inline(always)]
    fn subtree_cf(&self, index: NodeIndex) -> &rocksdb::ColumnFamily {
        let name = cf_for_depth(index.depth());
        self.cf_handle(name).expect("CF handle missing")
    }
}

impl SmtStorageReader for RocksDbSnapshotStorage {
    /// Retrieves the total count of non-empty leaves from the snapshot.
    fn leaf_count(&self) -> StorageResult<usize> {
        let cf = self.cf_handle(METADATA_CF)?;
        self.inner
            .snapshot
            .get_cf(cf, LEAF_COUNT_KEY)?
            .map_or(Ok(0), |bytes| read_count("leaf count", &bytes))
    }

    /// Retrieves the total count of key-value entries from the snapshot.
    fn entry_count(&self) -> StorageResult<usize> {
        let cf = self.cf_handle(METADATA_CF)?;
        self.inner
            .snapshot
            .get_cf(cf, ENTRY_COUNT_KEY)?
            .map_or(Ok(0), |bytes| read_count("entry count", &bytes))
    }

    /// Retrieves a single SMT leaf node by its logical `index` from the snapshot.
    fn get_leaf(&self, index: u64) -> StorageResult<Option<SmtLeaf>> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let key = RocksDbStorage::index_db_key(index);
        match self.inner.snapshot.get_cf(cf, key)? {
            Some(bytes) => {
                let leaf = SmtLeaf::read_from_bytes_with_budget(&bytes, bytes.len())?;
                Ok(Some(leaf))
            },
            None => Ok(None),
        }
    }

    /// Retrieves multiple SMT leaf nodes by their logical `indices` from the snapshot.
    fn get_leaves(&self, indices: &[u64]) -> StorageResult<Vec<Option<SmtLeaf>>> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let db_keys: Vec<[u8; 8]> =
            indices.iter().map(|&idx| RocksDbStorage::index_db_key(idx)).collect();
        let results = self.inner.snapshot.multi_get_cf(db_keys.iter().map(|k| (cf, k.as_ref())));

        results
            .into_iter()
            .map(|result| match result {
                Ok(Some(bytes)) => {
                    Ok(Some(SmtLeaf::read_from_bytes_with_budget(&bytes, bytes.len())?))
                },
                Ok(None) => Ok(None),
                Err(e) => Err(e.into()),
            })
            .collect()
    }

    /// Returns true if the snapshot has any leaves.
    fn has_leaves(&self) -> StorageResult<bool> {
        Ok(self.leaf_count()? > 0)
    }

    /// Retrieves a single SMT Subtree by its root `NodeIndex` from the snapshot.
    fn get_subtree(&self, index: NodeIndex) -> StorageResult<Option<Subtree>> {
        let cf = self.subtree_cf(index);
        let key = RocksDbStorage::subtree_db_key(index);
        match self.inner.snapshot.get_cf(cf, key)? {
            Some(bytes) => {
                let subtree = Subtree::from_vec(index, &bytes)?;
                Ok(Some(subtree))
            },
            None => Ok(None),
        }
    }

    /// Retrieves multiple subtrees from the snapshot.
    fn get_subtrees(&self, indices: &[NodeIndex]) -> StorageResult<Vec<Option<Subtree>>> {
        use p3_maybe_rayon::prelude::*;

        let mut depth_buckets: [Vec<(usize, NodeIndex)>; 6] = Default::default();

        for (original_index, &node_index) in indices.iter().enumerate() {
            let depth = node_index.depth();
            let bucket_index = match depth {
                56 => 0,
                48 => 1,
                40 => 2,
                32 => 3,
                24 => 4,
                16 => 5,
                _ => {
                    return Err(StorageError::Unsupported(format!(
                        "unsupported subtree depth {depth}"
                    )));
                },
            };
            depth_buckets[bucket_index].push((original_index, node_index));
        }
        let mut results = vec![None; indices.len()];

        let bucket_results: StorageResult<Vec<_>> = depth_buckets
            .into_par_iter()
            .enumerate()
            .filter(|(_, bucket)| !bucket.is_empty())
            .map(|(bucket_index, bucket)| -> StorageResult<Vec<(usize, Option<Subtree>)>> {
                let depth = LargeSmt::<RocksDbStorage>::SUBTREE_DEPTHS[bucket_index];
                let cf = self.cf_handle(cf_for_depth(depth))?;
                let keys: Vec<_> =
                    bucket.iter().map(|(_, idx)| RocksDbStorage::subtree_db_key(*idx)).collect();

                let db_results =
                    self.inner.snapshot.multi_get_cf(keys.iter().map(|k| (cf, k.as_ref())));

                bucket
                    .into_iter()
                    .zip(db_results)
                    .map(|((original_index, node_index), db_result)| {
                        let subtree = match db_result {
                            Ok(Some(bytes)) => Some(Subtree::from_vec(node_index, &bytes)?),
                            Ok(None) => None,
                            Err(e) => return Err(e.into()),
                        };
                        Ok((original_index, subtree))
                    })
                    .collect()
            })
            .collect();

        for bucket_result in bucket_results? {
            for (original_index, subtree) in bucket_result {
                results[original_index] = subtree;
            }
        }

        Ok(results)
    }

    /// Retrieves a single inner node from within a snapshot subtree.
    fn get_inner_node(&self, index: NodeIndex) -> StorageResult<Option<InnerNode>> {
        if index.depth() < IN_MEMORY_DEPTH {
            return Err(StorageError::Unsupported(
                "Cannot get inner node from upper part of the tree".into(),
            ));
        }
        let subtree_root_index = Subtree::find_subtree_root(index);
        Ok(self
            .get_subtree(subtree_root_index)?
            .and_then(|subtree| subtree.get_inner_node(index)))
    }

    /// Returns an iterator over all leaves in this snapshot.
    fn iter_leaves(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = StorageResult<(u64, SmtLeaf)>> + '_>> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let mut read_opts = ReadOptions::default();
        read_opts.set_total_order_seek(true);
        let db_iter = self.inner.snapshot.iterator_cf_opt(cf, read_opts, IteratorMode::Start);

        Ok(Box::new(RocksDbDirectLeafIterator { iter: db_iter }))
    }

    /// Returns an iterator over all subtrees in this snapshot.
    fn iter_subtrees(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = StorageResult<Subtree>> + '_>> {
        const SUBTREE_CFS: [&str; 6] = [
            SUBTREE_16_CF,
            SUBTREE_24_CF,
            SUBTREE_32_CF,
            SUBTREE_40_CF,
            SUBTREE_48_CF,
            SUBTREE_56_CF,
        ];

        let mut cf_handles = Vec::new();
        for cf_name in SUBTREE_CFS {
            cf_handles.push(self.cf_handle(cf_name)?);
        }

        Ok(Box::new(RocksDbSnapshotSubtreeIterator::new(&self.inner.snapshot, cf_handles)))
    }

    /// Retrieves roots of all top level subtrees for efficient startup reconstruction.
    fn get_top_subtree_roots(&self) -> StorageResult<Vec<(u64, Word)>> {
        let cf = self.cf_handle(IN_MEM_DEPTH_CF)?;
        let iter = self.inner.snapshot.iterator_cf(cf, IteratorMode::Start);
        collect_to_subtree_roots(iter)
    }
}

/// An iterator over subtrees from multiple RocksDB column families in a single snapshot.
struct RocksDbSnapshotSubtreeIterator<'a> {
    snapshot: &'a rocksdb::Snapshot<'static>,
    cf_handles: Vec<&'a rocksdb::ColumnFamily>,
    current_cf_index: usize,
    current_iter: Option<DBIteratorWithThreadMode<'a, DB>>,
}

impl<'a> RocksDbSnapshotSubtreeIterator<'a> {
    fn new(
        snapshot: &'a rocksdb::Snapshot<'static>,
        cf_handles: Vec<&'a rocksdb::ColumnFamily>,
    ) -> Self {
        let mut iterator = Self {
            snapshot,
            cf_handles,
            current_cf_index: 0,
            current_iter: None,
        };
        iterator.advance_to_next_cf();
        iterator
    }

    fn advance_to_next_cf(&mut self) {
        if self.current_cf_index < self.cf_handles.len() {
            let cf = self.cf_handles[self.current_cf_index];
            let mut read_opts = ReadOptions::default();
            read_opts.set_total_order_seek(true);
            self.current_iter =
                Some(self.snapshot.iterator_cf_opt(cf, read_opts, IteratorMode::Start));
        } else {
            self.current_iter = None;
        }
    }
}

impl Iterator for RocksDbSnapshotSubtreeIterator<'_> {
    type Item = StorageResult<Subtree>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let iter = self.current_iter.as_mut()?;

            if let Some(result) =
                RocksDbSubtreeIterator::next_from_iter(iter, self.current_cf_index)
            {
                return Some(result);
            }

            self.current_cf_index += 1;
            self.advance_to_next_cf();

            self.current_iter.as_ref()?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config = RocksDbConfig::new(dir.path());

        assert_eq!(config.cache_size, DEFAULT_CACHE_SIZE);
        assert_eq!(config.max_open_files, DEFAULT_MAX_OPEN_FILES);
        assert_eq!(config.durability_mode, RocksDbDurabilityMode::Relaxed);
        assert_eq!(config.write_buffer_manager, None);
        assert_eq!(config.tuning_options, RocksDbTuningOptions::default());
    }

    #[test]
    fn config_defaults_to_relaxed_durability() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(RocksDbConfig::new(dir.path()).durability_mode, RocksDbDurabilityMode::Relaxed);
    }

    #[test]
    fn config_builders_update_independent_knobs() {
        let dir = tempfile::tempdir().unwrap();
        let memory_budget = RocksDbMemoryBudget {
            block_cache_size: 512 << 20,
            write_buffer_manager: Some(RocksDbWriteBufferManagerBudget {
                buffer_size: 64 << 20,
                allow_stall: true,
                charge_to_block_cache: true,
            }),
        };
        let tuning_options = RocksDbTuningOptions {
            block_size: 8 << 10,
            max_total_wal_size: 2 << 30,
            bloom_filter_bits_per_key: RocksDbBloomFilterBitsPerKey {
                leaves: 11.0,
                in_mem_depth: 12.0,
                subtree_16: 9.0,
                subtree_24: 13.0,
                subtree_32: 14.0,
                subtree_40: 15.0,
                subtree_48: 16.0,
                subtree_56: 17.0,
            },
        };

        let config = RocksDbConfig::new(dir.path())
            .with_memory_budget(memory_budget)
            .with_max_open_files(1024)
            .with_tuning_options(tuning_options.clone())
            .with_durability_mode(RocksDbDurabilityMode::Sync);

        assert_eq!(
            config,
            RocksDbConfig {
                path: dir.path().to_path_buf(),
                cache_size: 512 << 20,
                max_open_files: 1024,
                write_buffer_manager: memory_budget.write_buffer_manager,
                tuning_options,
                durability_mode: RocksDbDurabilityMode::Sync,
            }
        );
    }
}
