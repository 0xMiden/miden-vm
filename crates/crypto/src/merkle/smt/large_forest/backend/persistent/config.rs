//! Contains the configuration for the persistent backend.

use std::{ffi::c_double, fs, path::PathBuf};

use super::Result;
use crate::merkle::smt::BackendError;

// CONSTANTS
// ================================================================================================

/// The default size for the database cache in bytes (2 GiB).
const DEFAULT_CACHE_SIZE_BYTES: usize = 2 << 30;

/// The default maximum number of files that the database engine can have open at one time.
const DEFAULT_MAX_OPEN_FILES: usize = 1 << 9;

/// The default maximum size of the write-ahead log in bytes (1 GiB).
const DEFAULT_MAX_TOTAL_WAL_SIZE_BYTES: u64 = 1 << 30;

/// The default number of bits in the RocksDB bloom filter to use per key.
const DEFAULT_BLOOM_FILTER_BITS_PER_KEY: c_double = 10.0;

/// The default target file size for the files that make up the database (512 MiB).
const DEFAULT_TARGET_FILE_SIZE: u64 = 512 << 20;

/// The default setting for synchronous writes (`false`).
///
/// When `false`, writes are buffered and not immediately flushed to disk.
const DEFAULT_SYNC_WRITES: bool = false;

// CONFIG TYPE
// ================================================================================================

/// The basic configuration for the persistent backend.
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// The path at which the database can be found.
    ///
    /// This should be a directory path that the application has read/write permissions for. The
    /// database will create multiple files in this directory as part of its operation.
    pub(super) path: PathBuf,

    /// The maximum size of the backend's block cache in bytes.
    ///
    /// This cache stores blocks that the database accesses frequently in memory to improve read
    /// performance. Larger cache sizes improve read performance but consume more memory.
    ///
    /// Defaults to [`DEFAULT_CACHE_SIZE_BYTES`].
    pub(super) cache_size_bytes: usize,

    /// The maximum number of file handles that the database engine can keep open at one time.
    ///
    /// This setting affects both memory usage and the number of FDs used by the process. Higher
    /// values can improve performance for large databases, but can increase resource usage.
    ///
    /// Defaults to [`DEFAULT_MAX_OPEN_FILES`].
    pub(super) max_open_files: usize,

    /// The maximum size of the write-ahead log in bytes.
    ///
    /// This setting affects the amount of data that can be buffered in the WAL before it has to be
    /// flushed to disk, and hence the maximum amount of memory it can use.
    ///
    /// Defaults to [`DEFAULT_MAX_TOTAL_WAL_SIZE_BYTES`].
    pub(super) max_wal_size: u64,

    /// The number of bits in the RocksDB bloom filter to use per key.
    ///
    /// This setting balances between the amount of work to look up a key and the size of the bloom
    /// filter. If the bloom filter gets too large, it gets too complex to query and hence slows
    /// things down. If the bits per key are insufficiently distinguishing, then the performance
    /// improvement from the bloom filter can become negligible.
    ///
    /// Defaults to [`DEFAULT_BLOOM_FILTER_BITS_PER_KEY`].
    pub(super) bloom_filter_bits: c_double,

    /// The target size for the files that make up the database.
    ///
    /// This directly determines how large any individual file can get on disk as part of the
    /// Database, and hence has an impact on file handle churn as the database performs operations.
    ///
    /// Defaults to [`DEFAULT_TARGET_FILE_SIZE`].
    pub(super) target_file_size: u64,

    /// Whether each write should be synchronously flushed to disk.
    ///
    /// When `true`, every write is synchronously flushed to disk, providing stronger durability
    /// guarantees but with reduced write performance. When `false` (the default), writes are
    /// buffered and only flushed to disk when the buffers become full.
    ///
    /// Defaults to [`DEFAULT_SYNC_WRITES`].
    pub(super) sync_writes: bool,
}

impl Config {
    /// Constructs a new configuration object with the provided database `path` and default
    /// settings.
    ///
    /// The provided `path` must be in a location writable by the backend, and will be created by
    /// the database if it does not exist.
    ///
    /// The defaults are as follows:
    ///
    /// - `cache_size_bytes`: 2 GiB
    /// - `max_open_files`: 512
    /// - `max_wal_size`: 1 GiB
    /// - `sync_writes`: `false`
    ///
    /// # Errors
    ///
    /// - [`BackendError::Internal`] if the provided `path` is not accessible to the backend, or is
    ///   not a directory.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();

        if fs::exists(&path)? {
            // The provided path must be a directory or a symlink to one, and it must be
            // RW-accessible by us if it does exist.
            let path_data = fs::metadata(&path)?;
            if !path_data.is_dir() {
                return Err(BackendError::internal_from_message(format!(
                    "The path {} exists and is not a folder",
                    path.to_string_lossy()
                )));
            }
            if path_data.permissions().readonly() {
                return Err(BackendError::internal_from_message(format!(
                    "The path {} is not writable",
                    path.to_string_lossy()
                )));
            }
        }

        Ok(Self {
            path,
            cache_size_bytes: DEFAULT_CACHE_SIZE_BYTES,
            max_open_files: DEFAULT_MAX_OPEN_FILES,
            max_wal_size: DEFAULT_MAX_TOTAL_WAL_SIZE_BYTES,
            bloom_filter_bits: DEFAULT_BLOOM_FILTER_BITS_PER_KEY,
            target_file_size: DEFAULT_TARGET_FILE_SIZE,
            sync_writes: DEFAULT_SYNC_WRITES,
        })
    }
}

// BUILDER FUNCTIONS
// ================================================================================================

/// This block contains the functions for building an appropriate configuration for the backend.
impl Config {
    /// Sets the cache size in bytes for the database cache.
    ///
    /// The block cache stores frequently-accessed data block in memory to improve read performance.
    /// Larger cache sizes generally improve read performance but consume more memory.
    ///
    /// Defaults to `2 * 1024 * 1024 * 1024` bytes, or 2 GiB.
    pub fn with_cache_size_bytes(mut self, cache_size_bytes: usize) -> Self {
        self.cache_size_bytes = cache_size_bytes;
        self
    }

    /// Sets the maximum number of files that the backend can have open simultaneously.
    ///
    /// This affects both memory usage of the backend and the number of file descriptors used by the
    /// process. Higher values improve performances for large databases, but increase resource
    /// usage.
    ///
    /// Defaults to 512 files.
    pub fn with_max_open_files(mut self, max_open_files: usize) -> Self {
        self.max_open_files = max_open_files;
        self
    }

    /// Sets the maximum size of the write-ahead log in the backend.
    ///
    /// This setting affects the amount of data that can be buffered in the WAL before it has to be
    /// flushed to disk, and hence the maximum amount of memory it can use.
    ///
    /// Defaults to 1 GiB.
    pub fn with_max_wal_size(mut self, max_wal_size: u64) -> Self {
        self.max_wal_size = max_wal_size;
        self
    }

    /// The number of bits in the RocksDB bloom filter to use per key.
    ///
    /// This setting balances between the amount of work to look up a key and the size of the bloom
    /// filter. If the bloom filter gets too large, it gets too complex to query and hence slows
    /// things down. If the bits per key are insufficiently distinguishing, then the performance
    /// improvement from the bloom filter can become negligible.
    ///
    /// Defaults to 10.0.
    pub fn with_bloom_filter_bits(mut self, bloom_filter_bits: f64) -> Self {
        self.bloom_filter_bits = c_double::from(bloom_filter_bits);
        self
    }

    /// Sets the target size for the files that make up the database.
    ///
    /// This directly determines how large any individual file can get on disk as part of the
    /// Database, and hence has an impact on file handle churn as the database performs operations.
    ///
    /// Defaults to 512 MiB.
    pub fn with_target_file_size(mut self, target_file_size: u64) -> Self {
        self.target_file_size = target_file_size;
        self
    }

    /// Sets whether writes should be synchronously flushed to disk.
    ///
    /// When `true`, every write is synchronously flushed to disk, providing stronger durability
    /// guarantees but with reduced write performance. When `false` (the default), writes are
    /// buffered only flushed to disk when the buffer becomes full.
    ///
    /// Defaults to `false`.
    pub fn with_sync_writes(mut self, sync_writes: bool) -> Self {
        self.sync_writes = sync_writes;
        self
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod test {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn new() -> Result<()> {
        let tempdir = tempdir()?;
        let config = Config::new(tempdir.path())?;

        assert_eq!(config.cache_size_bytes, DEFAULT_CACHE_SIZE_BYTES);
        assert_eq!(config.max_open_files, DEFAULT_MAX_OPEN_FILES);
        assert_eq!(config.max_wal_size, DEFAULT_MAX_TOTAL_WAL_SIZE_BYTES);
        assert_eq!(config.bloom_filter_bits, DEFAULT_BLOOM_FILTER_BITS_PER_KEY);
        assert_eq!(config.target_file_size, DEFAULT_TARGET_FILE_SIZE);
        assert_eq!(config.sync_writes, DEFAULT_SYNC_WRITES);

        Ok(())
    }

    #[test]
    fn with_cache_size_bytes() -> Result<()> {
        let tempdir = tempdir()?;
        let config = Config::new(tempdir.path())?;
        let config = config.with_cache_size_bytes(1024);

        assert_eq!(config.cache_size_bytes, 1024);

        Ok(())
    }

    #[test]
    fn with_max_open_files() -> Result<()> {
        let tempdir = tempdir()?;
        let config = Config::new(tempdir.path())?;
        let config = config.with_max_open_files(63);

        assert_eq!(config.max_open_files, 63);

        Ok(())
    }

    #[test]
    fn with_max_wal_size() -> Result<()> {
        let tempdir = tempdir()?;
        let config = Config::new(tempdir.path())?;
        let config = config.with_max_wal_size(2 << 30);

        assert_eq!(config.max_wal_size, 2 << 30);

        Ok(())
    }

    #[test]
    fn with_bloom_filter_bits() -> Result<()> {
        let tempdir = tempdir()?;
        let config = Config::new(tempdir.path())?;
        let config = config.with_bloom_filter_bits(21.0);

        assert_eq!(config.bloom_filter_bits, 21.0);

        Ok(())
    }

    #[test]
    fn with_target_file_size() -> Result<()> {
        let tempdir = tempdir()?;
        let config = Config::new(tempdir.path())?;
        let config = config.with_target_file_size(256 << 20);

        assert_eq!(config.target_file_size, 256 << 20);

        Ok(())
    }

    #[test]
    fn with_sync_writes() -> Result<()> {
        let tempdir = tempdir()?;
        let config = Config::new(tempdir.path())?;
        let config = config.with_sync_writes(true);

        assert!(config.sync_writes);

        Ok(())
    }
}
