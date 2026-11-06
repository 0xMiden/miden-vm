//! Hash-construction compatibility for RocksDB-backed SMTs.

use rocksdb::{DB, IteratorMode, Options, WriteOptions};

use super::{EmptySubtreeRoots, SMT_DEPTH, StorageError, StorageResult};
use crate::utils::Serializable;

/// The default column family holds the hash marker independently of each backend's data layout.
pub(super) const HASH_SCHEME_KEY: &[u8] = b"miden-smt/hash-scheme";

/// Checks the empty SMT root used to identify the hash construction, or records it for a new store.
pub(super) fn ensure_hash_scheme(db: &DB) -> StorageResult<()> {
    let expected = EmptySubtreeRoots::entry(SMT_DEPTH, 0).to_bytes();
    if let Some(stored) = db.get(HASH_SCHEME_KEY)? {
        return if stored == expected {
            Ok(())
        } else {
            Err(StorageError::IncompatibleHashScheme)
        };
    }

    // Check records directly: absent or zero counts do not rule out cached subtree hashes.
    for name in DB::list_cf(&Options::default(), db.path())? {
        let cf = db
            .cf_handle(&name)
            .ok_or_else(|| StorageError::Unsupported(format!("unknown column family `{name}`")))?;
        if db.iterator_cf(cf, IteratorMode::Start).next().transpose()?.is_some() {
            return Err(StorageError::IncompatibleHashScheme);
        }
    }

    // Persist the marker before exposing the store, including in relaxed durability mode.
    let mut options = WriteOptions::default();
    options.set_sync(true);
    db.put_opt(HASH_SCHEME_KEY, expected, &options)?;
    Ok(())
}
