use alloc::{sync::Arc, vec::Vec};
use core::mem::ManuallyDrop;
use std::collections::HashMap;

use miden_serde_utils::{Deserializable, Serializable};
use rocksdb as db;

use super::{
    super::{BackendError, Result},
    LEAVES_CF,
    iterator::PersistentBackendEntriesIterator,
    keys::{LeafKey, SubtreeKey},
    subtree_cf_name,
    tree_metadata::TreeMetadata,
};
use crate::{
    Word,
    merkle::{
        EmptySubtreeRoots, NodeIndex, SparseMerklePath,
        smt::{
            BackendReader, InnerNode, LeafIndex, LineageId, SMT_DEPTH, SmtLeaf, SmtProof, Subtree,
            TreeEntry, TreeWithRoot, VersionId, full::concurrent::SUBTREE_DEPTH,
        },
    },
};

// PERSISTENT BACKEND SNAPSHOT INNER
// ================================================================================================

/// Inner state shared by all clones of a [`PersistentBackendReader`].
///
/// Pairs a RocksDB point-in-time snapshot with the `Arc<DB>` that owns the database, so that
/// the database is guaranteed to outlive the snapshot.
///
/// # Safety
///
/// `snapshot` contains an internal pointer into the `DB` allocation. `db` must not be dropped
/// (i.e. its refcount must not reach zero) while `snapshot` is live. The `Drop` impl enforces
/// this by explicitly dropping `snapshot` before the `Arc<DB>` field is automatically decremented.
pub(super) struct SnapshotInner {
    /// The RocksDB snapshot providing the consistent read view.
    ///
    /// The `'static` lifetime is a sound lie: the real lifetime is tied to `db`. The `Drop` impl
    /// guarantees we drop this before `db`.
    snapshot: ManuallyDrop<db::Snapshot<'static>>,
    /// Keeps the database alive for at least as long as `snapshot`.
    db: Arc<db::DB>,
    /// Point-in-time view of the lineage metadata, shared with the backend via copy-on-write.
    lineages: Arc<HashMap<LineageId, TreeMetadata>>,
}

impl Drop for SnapshotInner {
    fn drop(&mut self) {
        // SAFETY: Drop the snapshot before the Arc<DB> refcount is decremented.
        unsafe {
            ManuallyDrop::drop(&mut self.snapshot);
        }
    }
}

impl core::fmt::Debug for SnapshotInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SnapshotInner").finish_non_exhaustive()
    }
}

// PERSISTENT BACKEND READER
// ================================================================================================

/// A read-only, point-in-time snapshot of a [`PersistentBackend`](super::PersistentBackend).
///
/// This type intentionally implements only [`BackendReader`], not
/// [`Backend`](crate::merkle::smt::Backend). It is returned by
/// [`Backend::reader`](crate::merkle::smt::Backend::reader) for
/// [`PersistentBackend`](super::PersistentBackend) to provide read-only access to a consistent
/// snapshot of the backend state without exposing any mutation capabilities.
///
/// All reads go through a RocksDB snapshot, so the view is frozen at the instant
/// [`Backend::reader`](crate::merkle::smt::Backend::reader) was called; concurrent writes to the
/// underlying database are invisible to this reader.
///
/// Cloning is O(1): both the snapshot and the lineage metadata are owned by the inner `Arc`.
#[derive(Clone, Debug)]
pub struct PersistentBackendReader {
    inner: Arc<SnapshotInner>,
}

impl PersistentBackendReader {
    pub(super) fn new(
        db: Arc<db::DB>,
        snapshot: db::Snapshot<'static>,
        lineages: Arc<HashMap<LineageId, TreeMetadata>>,
    ) -> Self {
        Self {
            inner: Arc::new(SnapshotInner {
                snapshot: ManuallyDrop::new(snapshot),
                db,
                lineages,
            }),
        }
    }

    fn load_subtree(&self, tree_key: &SubtreeKey) -> Result<Option<Subtree>> {
        let cf = self.subtree_cf(tree_key.index)?;
        let key_bytes = tree_key.to_bytes();
        let result = match self.inner.snapshot.get_cf(cf, key_bytes) {
            Ok(Some(bytes)) => Some(Subtree::from_vec(tree_key.index, &bytes)?),
            Ok(None) => None,
            Err(e) => return Err(e.into()),
        };
        Ok(result)
    }

    fn load_leaf_raw(&self, key: &LeafKey) -> Result<Option<SmtLeaf>> {
        let col = self.cf(LEAVES_CF)?;
        let key_bytes = key.to_bytes();
        let leaf_bytes = self.inner.snapshot.get_cf(col, key_bytes)?;
        Ok(match leaf_bytes {
            Some(bytes) => Some(SmtLeaf::read_from_bytes_with_budget(&bytes, bytes.len())?),
            None => None,
        })
    }

    fn load_leaf_for(&self, lineage: LineageId, key: Word) -> Result<Option<SmtLeaf>> {
        let key = LeafKey {
            lineage,
            index: LeafIndex::from(key).position(),
        };
        self.load_leaf_raw(&key)
    }

    #[inline(always)]
    fn subtree_cf(&self, index: NodeIndex) -> Result<&db::ColumnFamily> {
        self.subtree_cf_depth(index.depth())
    }

    #[inline(always)]
    fn subtree_cf_depth(&self, depth: u8) -> Result<&db::ColumnFamily> {
        let cf_name = subtree_cf_name(depth);
        self.cf(cf_name)
    }

    #[inline(always)]
    fn cf(&self, name: &str) -> Result<&db::ColumnFamily> {
        self.inner.db.cf_handle(name).ok_or_else(|| {
            BackendError::internal_from_message(format!("Could not load column with name {name}"))
        })
    }
}

impl BackendReader for PersistentBackendReader {
    fn open(&self, lineage: LineageId, key: Word) -> Result<SmtProof> {
        open_proof(
            &self.inner.lineages,
            lineage,
            key,
            |l, k| self.load_leaf_for(l, k),
            |k| self.load_subtree(&k),
        )
    }

    fn get_leaf(&self, lineage: LineageId, leaf_index: LeafIndex<SMT_DEPTH>) -> Result<SmtLeaf> {
        if !self.inner.lineages.contains_key(&lineage) {
            return Err(BackendError::UnknownLineage(lineage));
        }
        let key = LeafKey { lineage, index: leaf_index.position() };
        Ok(self.load_leaf_raw(&key)?.unwrap_or_else(|| SmtLeaf::new_empty(leaf_index)))
    }

    fn get(&self, lineage: LineageId, key: Word) -> Result<Option<Word>> {
        if !self.inner.lineages.contains_key(&lineage) {
            return Err(BackendError::UnknownLineage(lineage));
        }
        let leaf = self.load_leaf_for(lineage, key)?;
        Ok(leaf.and_then(|l| {
            let val = l.get_value(&key);
            val.filter(|&e| !e.is_empty())
        }))
    }

    fn version(&self, lineage: LineageId) -> Result<VersionId> {
        let metadata =
            self.inner.lineages.get(&lineage).ok_or(BackendError::UnknownLineage(lineage))?;
        Ok(metadata.version)
    }

    fn lineages(&self) -> Result<impl Iterator<Item = LineageId>> {
        Ok(self.inner.lineages.keys().copied())
    }

    fn trees(&self) -> Result<impl Iterator<Item = TreeWithRoot>> {
        Ok(self
            .inner
            .lineages
            .iter()
            .map(|(l, m)| TreeWithRoot::new(*l, m.version, m.root_value)))
    }

    fn entry_count(&self, lineage: LineageId) -> Result<usize> {
        let metadata =
            self.inner.lineages.get(&lineage).ok_or(BackendError::UnknownLineage(lineage))?;
        Ok(metadata.entry_count.try_into().expect("Count of entries should fit into usize"))
    }

    fn entries(&self, lineage: LineageId) -> Result<impl Iterator<Item = Result<TreeEntry>>> {
        if !self.inner.lineages.contains_key(&lineage) {
            return Err(BackendError::UnknownLineage(lineage));
        }
        let lineage_bytes = lineage.to_bytes();
        let cf = self.cf(LEAVES_CF)?;
        let mut read_opts = db::ReadOptions::default();
        read_opts.set_prefix_same_as_start(true);
        let pfx_iterator = self.inner.snapshot.iterator_cf_opt(
            cf,
            read_opts,
            db::IteratorMode::From(&lineage_bytes, db::Direction::Forward),
        );
        Ok(PersistentBackendEntriesIterator::new(lineage, pfx_iterator))
    }
}

// HELPERS
// ================================================================================================

fn compute_merkle_path(
    mut leaf_index: NodeIndex,
    subtrees: &HashMap<NodeIndex, Subtree>,
) -> SparseMerklePath {
    let mut path = Vec::with_capacity(SMT_DEPTH as usize);

    while leaf_index.depth() > 0 {
        let is_right = leaf_index.is_position_odd();
        leaf_index = leaf_index.parent();

        let root = Subtree::find_subtree_root(leaf_index);
        let subtree = &subtrees[&root];
        let InnerNode { left, right } = subtree
            .get_inner_node(leaf_index)
            .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, leaf_index.depth()));

        path.push(if is_right { left } else { right });
    }

    SparseMerklePath::from_sized_iter(path).expect("Always succeeds by construction")
}

pub(super) fn open_proof(
    lineages: &HashMap<LineageId, TreeMetadata>,
    lineage: LineageId,
    key: Word,
    load_leaf: impl Fn(LineageId, Word) -> Result<Option<SmtLeaf>>,
    load_subtree: impl Fn(SubtreeKey) -> Result<Option<Subtree>>,
) -> Result<SmtProof> {
    if !lineages.contains_key(&lineage) {
        return Err(BackendError::UnknownLineage(lineage));
    }

    let leaf = load_leaf(lineage, key)?.unwrap_or_else(|| SmtLeaf::new_empty(LeafIndex::from(key)));
    let leaf_index: NodeIndex = LeafIndex::from(key).into();

    // An opening needs exactly one subtree per level; collect their roots up front so we can
    // load them all before constructing the path.
    let subtree_roots = (0..SMT_DEPTH / SUBTREE_DEPTH)
        .scan(leaf_index.parent(), |cursor, _| {
            let subtree_root = Subtree::find_subtree_root(*cursor);
            *cursor = subtree_root.parent();
            Some(subtree_root)
        })
        .collect::<Vec<_>>();

    // Loading subtrees as a separate step (rather than inline during path construction)
    // exhibits better performance due to improved pipelining and branch-predictor behavior.
    let mut subtree_cache = HashMap::<NodeIndex, Subtree>::new();
    for root in subtree_roots {
        let maybe_tree = load_subtree(SubtreeKey { lineage, index: root })?;
        subtree_cache.insert(root, maybe_tree.unwrap_or_else(|| Subtree::new(root)));
    }

    let merkle_path = compute_merkle_path(leaf_index, &subtree_cache);
    Ok(SmtProof::new_unchecked(merkle_path, leaf))
}
