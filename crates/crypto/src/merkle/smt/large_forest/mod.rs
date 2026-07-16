//! A high-performance sparse merkle tree forest with pluggable backends.
//!
//! # Semantic Layout
//!
//! Much like the `SparseMerkleTree`, the forest stores its trees at depth [`SMT_DEPTH`] and then
//! relies on the compact leaf optimization to uniquely store the 256-bit elements that it contains.
//! This is done to both reduce the size of a merkle path, and to reduce the computational work
//! necessary to perform queries into the trees.
//!
//! It also has the benefit of significantly reducing the memory usage for the forest. Even in cases
//! where it relies on a persistent backend, the other peripheral structures are able to be smaller
//! and thus use less memory.
//!
//! # Backends
//!
//! The forest is implemented to rely on the API and contract conformance of an arbitrary
//! [`Backend`] implementation. These backends provide the storage for full trees in the forest, and
//! are the main extension point for the way the forest functions.
//!
//! The [`InMemoryBackend`] provides simple, in-memory storage for the full trees in the forest. It
//! is _primarily_ intended to be used for testing purposes, but should nevertheless be correct and
//! functional for production use-cases if no persistence is required.
//!
//! The [`PersistentBackend`] provides persistent on-disk storage for the full trees in the forest,
//! and is intended to maintain good performance in scenarios where persistence is key or where the
//! forest would grow too large to fit into memory.
//!
//! While any given [`Backend`] may choose to share data between lineages, this behavior is not
//! guaranteed, and must not be relied upon.
//!
//! ## Performance
//!
//! Each [`Backend`] provides the same set of functionality to the forest, but may exhibit
//! significant variance in their performance characteristics. As a result, **any performance
//! analysis of the forest should be done in conjunction with a specific backend**.
//!
//! Nevertheless, we can provide some basic guidelines for getting good performance from this
//! structure:
//!
//! 1. **Batch Operations:** Wherever possible, perform queries and/or updates using batching
//!    operations on the forest. These provide scope for taking advantage of parallelism as much as
//!    possible, and can mask potential I/O latency.
//! 2. **Grouping:** If you have lots of data to apply to the tree, batching operations so that they
//!    share prefixes in the trees in question will yield improved performance by requiring fewer
//!    subtrees to be accessed.
//!
//! Take care to read the documentation of the specific [`Backend`] that you are planning to use in
//! order to understand its performance, potential gotchas, and other such details.
//!
//! # Storing Trees and Versions
//!
//! An SMT forest conceptually performs two roles. Firstly, it acts as a collection that is able to
//! store **multiple, unrelated trees**. Secondly, it is a container for **multiple versions of a
//! given tree**. In order to make it tractable to implement a performant forest with pluggable
//! backends, this type makes an explicit delineation between these use-cases in both the API and
//! the implementation.
//!
//! ## Lineages
//!
//! We term a set of trees, where each tree is derived from changing the previous version, to be a
//! **lineage** of trees. A single lineage contains the information necessary to reconstruct any
//! previous version of the tree, within the bounds of the history that the forest stores.
//!
//! Users must take care to ensure that each lineage identifier is unique, as reuse of these
//! identifiers can result in data corruption and hence queries that return incorrect results.
//!
//! # Tree Identification
//!
//! It is possible for a tree with identical leaves (and hence an identical root) to exist in
//! multiple lineages in the forest. As lineages are stored separately, there needs to be a way to
//! specify the precise instance of a given tree.
//!
//! Trees are thus identified using the [`TreeId`], which combines the **lineage** in which the tree
//! exists with the **version** in that lineage.
//!
//! ## Potential Gotchas
//!
//! The separation of the forest into lineages of trees has a few impacts that a client of the
//! forest must understand:
//!
//! - When using a [`Backend`] that offers data persistence, **only the state of the current version
//!   of each lineage is persisted**, while **the historical data is not persisted**. This is part
//!   of the way the forest is structured, and does not depend on the choice of backend.
//! - It is always going to be more expensive to query a given lineage at **an older point** in its
//!   history than it is to query at a newer point.
//! - Querying **the latest tree in a lineage will take the least time**.
//!
//! # Batch Operations
//!
//! The [`LargeSmtForest::update_tree`] and [`LargeSmtForest::update_forest`] methods are what is
//! known as **batch operations**. In other words, they are performed in one go and only produce a
//! one-stage update to the forest, rather than a sequence of updates.
//!
//! These methods should be used wherever possible (especially preferring `update_forest` over a
//! sequence of `update_tree` calls) as this will allow the forest and its backend to exploit as
//! much parallelism as possible in the updates.
//!
//! # Examples
//!
//! The following section contains usage examples for the forest. They rely on the included
//! [`InMemoryBackend`] for simplicity, but will work with any conformant [`Backend`]
//! implementation. Each example is designed to build upon the last.
//!
//! ## Constructing a Forest
//!
//! A new forest can be constructed by calling either [`LargeSmtForest::new`], which will use a
//! default [`Config`], or by explicitly providing the config in [`LargeSmtForest::with_config`].
//!
//! ```
//! use miden_crypto::merkle::smt::{ForestInMemoryBackend, LargeSmtForest};
//! # use miden_crypto::merkle::smt::LargeSmtForestError;
//! #
//! # fn main() -> Result<(), LargeSmtForestError> {
//!
//! let backend = ForestInMemoryBackend::new();
//! let forest = LargeSmtForest::new(backend)?;
//! #
//! # Ok(())
//! # }
//! ```
//!
//! Upon startup, the forest has to read the lineages it knows from the provided storage. If it
//! cannot get this information, it cannot start up properly and the constructor may return an
//! error.
//!
//! ## Adding a Lineage
//!
//! Each tree in the forest belongs to a _lineage_, identified by a [`LineageId`]. In order to work
//! with a lineage in the forest, that lineage first has to be added to it! Adding a lineage can
//! either add the empty tree, or specify a set of modifications on the empty tree to create a
//! starting state.
//!
//! ```
//! # use miden_crypto::merkle::smt::LargeSmtForestError;
//! # use miden_crypto::merkle::smt::{ForestInMemoryBackend, LargeSmtForest};
//! use miden_crypto::{
//!     Word,
//!     merkle::smt::{LineageId, SmtUpdateBatch},
//! };
//!
//! # fn main() -> Result<(), LargeSmtForestError> {
//! # let backend = ForestInMemoryBackend::new();
//! # let mut forest = LargeSmtForest::new(backend)?;
//! #
//! // We can just make some arbitrary values here for demonstration.
//! let key_1 = Word::parse("0x42").unwrap();
//! let value_1 = Word::parse("0x80").unwrap();
//! let key_2 = Word::parse("0xAB").unwrap();
//! let value_2 = Word::parse("0xCD").unwrap();
//!
//! // Operations are most cleanly specified using a builder.
//! let mut operations = SmtUpdateBatch::empty();
//! operations.add_insert(key_1, value_1);
//! operations.add_insert(key_2, value_2);
//!
//! // To add a new lineage we also need to give it a lineage ID, and a version.
//! let lineage = LineageId::new([0x42; 32]);
//! let version_1 = 1;
//!
//! // Now we can add the lineage to the forest!
//! assert!(forest.add_lineage(lineage, version_1, operations).is_ok());
//! #
//! # Ok(())
//! # }
//! ```
//!
//! ## Modifying a Lineage
//!
//! A forest is not all that useful if we cannot update it! Modifying a lineage is much like adding
//! a new one, in that we specify operations to be performed on the latest tree in that lineage.
//!
//! ```
//! # use miden_crypto::merkle::smt::LargeSmtForestError;
//! # use miden_crypto::{
//! #     Word,
//! #     merkle::smt::{ForestInMemoryBackend, LargeSmtForest, LineageId, SmtUpdateBatch},
//! # };
//! #
//! # fn main() -> Result<(), LargeSmtForestError> {
//! # let backend = ForestInMemoryBackend::new();
//! # let mut forest = LargeSmtForest::new(backend)?;
//! #
//! # // We can just make some arbitrary values here for demonstration.
//! # let key_1 = Word::parse("0x42").unwrap();
//! # let value_1 = Word::parse("0x80").unwrap();
//! # let key_2 = Word::parse("0xAB").unwrap();
//! # let value_2 = Word::parse("0xCD").unwrap();
//! #
//! # // Operations are most cleanly specified using a builder.
//! # let mut operations = SmtUpdateBatch::empty();
//! # operations.add_insert(key_1, value_1);
//! # operations.add_insert(key_2, value_2);
//! #
//! # // To add a new lineage we also need to give it a lineage ID, and a version.
//! # let lineage = LineageId::new([0x42; 32]);
//! # let version_1 = 1;
//! #
//! # // Now we can add the lineage to the forest!
//! # forest.add_lineage(lineage, version_1, operations)?;
//! #
//! // Let's make another arbitrary value.
//! let key_3 = Word::parse("0x67").unwrap();
//! let value_3 = Word::parse("0x96").unwrap();
//!
//! // And build a batch of operations again.
//! let mut operations = SmtUpdateBatch::empty();
//! operations.add_insert(key_3, value_3);
//! operations.add_remove(key_1);
//!
//! // Now we can simply update the tree all in one go with our changes.
//! let version_2 = version_1 + 1;
//! assert!(forest.update_tree(lineage, version_2, operations).is_ok());
//! #
//! # Ok(())
//! # }
//! ```
//!
//! Multiple lineages can be modified at once using the [`LargeSmtForest::update_forest`] method,
//! which works very similarly to the [`LargeSmtForest::update_tree`] method shown above.
//!
//! ## Querying a Lineage
//!
//! Modification is just one part of the puzzle, however. It is just as important to be able to get
//! data _out_ of the forest too!
//!
//! ```
//! # use miden_crypto::merkle::smt::LargeSmtForestError;
//! # use miden_crypto::{
//! #     Word,
//! #     merkle::smt::{ForestInMemoryBackend, LargeSmtForest, LineageId, SmtUpdateBatch},
//! # };
//! use miden_crypto::merkle::smt::{TreeEntry, TreeId};
//!
//! # fn main() -> Result<(), LargeSmtForestError> {
//! # let backend = ForestInMemoryBackend::new();
//! # let mut forest = LargeSmtForest::new(backend)?;
//! #
//! # // We can just make some arbitrary values here for demonstration.
//! # let key_1 = Word::parse("0x42").unwrap();
//! # let value_1 = Word::parse("0x80").unwrap();
//! # let key_2 = Word::parse("0xAB").unwrap();
//! # let value_2 = Word::parse("0xCD").unwrap();
//! #
//! # // Operations are most cleanly specified using a builder.
//! # let mut operations = SmtUpdateBatch::empty();
//! # operations.add_insert(key_1, value_1);
//! # operations.add_insert(key_2, value_2);
//! #
//! # // To add a new lineage we also need to give it a lineage ID, and a version.
//! # let lineage = LineageId::new([0x42; 32]);
//! # let version_1 = 1;
//! #
//! # // Now we can add the lineage to the forest!
//! # forest.add_lineage(lineage, version_1, operations)?;
//! #
//! # // Let's make another arbitrary value.
//! # let key_3 = Word::parse("0x67").unwrap();
//! # let value_3 = Word::parse("0x96").unwrap();
//! #
//! # // And build a batch of operations again.
//! # let mut operations = SmtUpdateBatch::empty();
//! # operations.add_insert(key_3, value_3);
//! # operations.add_remove(key_1);
//! #
//! # // Now we can simply update the tree all in one go with our changes.
//! # let version_2 = version_1 + 1;
//! # forest.update_tree(lineage, version_2, operations)?;
//! #
//! // As discussed above, trees are identified by a combination of their lineage and version.
//! let old_tree = TreeId::new(lineage, version_1);
//! let current_tree = TreeId::new(lineage, version_2);
//!
//! // The first really useful query is `open`, which gets the opening for the specified key. We can
//! // get openings for the current tree AND the historical trees.
//! assert!(forest.open(old_tree, key_1).is_ok());
//! assert!(forest.open(current_tree, key_3).is_ok());
//!
//! // We can also just `get` the value associated with a key, which returns `None` if the key is
//! // not populated.
//! assert_eq!(forest.get(old_tree, key_1)?, Some(value_1));
//! assert_eq!(forest.get(current_tree, key_3)?, Some(value_3));
//! assert!(forest.get(current_tree, key_1)?.is_none());
//!
//! // We can also get an iterator over all the entries in the tree.
//! let entries_old = forest.entries(old_tree)?.collect::<Result<Vec<_>, _>>()?;
//! let entries_current = forest.entries(current_tree)?.collect::<Result<Vec<_>, _>>()?;
//! assert!(entries_old.contains(&TreeEntry { key: key_1, value: value_1 }));
//! assert!(entries_old.contains(&TreeEntry { key: key_2, value: value_2 }));
//! assert!(!entries_old.contains(&TreeEntry { key: key_3, value: value_3 }));
//! assert!(!entries_current.contains(&TreeEntry { key: key_1, value: value_1 }));
//! assert!(entries_current.contains(&TreeEntry { key: key_2, value: value_2 }));
//! assert!(entries_current.contains(&TreeEntry { key: key_3, value: value_3 }));
//! #
//! # Ok(())
//! # }
//! ```
//!
//! There are many other kinds of queries of course, so taking a look at the methods available on
//! [`LargeSmtForest`] is a good starting point.

mod backend;
mod config;
mod error;
mod history;
mod iterator;
mod lineage;
mod operation;
mod property_tests;
mod root;
mod test_utils;
mod tests;
mod utils;

use alloc::vec::Vec;
use core::num::NonZeroU8;

pub use backend::{
    Backend, BackendError, BackendReader,
    memory::{InMemoryBackend, InMemoryBackendSnapshot},
};
#[cfg(feature = "persistent-forest")]
pub use backend::{
    persistent::config::Config as PersistentBackendConfig,
    persistent::{PersistentBackend, PersistentBackendReader},
};
pub use config::{Config, DEFAULT_MAX_HISTORY_VERSIONS, MIN_HISTORY_VERSIONS};
pub use error::{LargeSmtForestError, Result};
pub use operation::{SmtForestOperation, SmtForestUpdateBatch, SmtUpdateBatch};
pub use root::{LineageId, RootInfo, TreeEntry, TreeId, TreeWithRoot, VersionId};
pub use utils::{
    AppliedLineageMutation, LineageMutation, LineageMutationKind, SmtForestMutationSet,
};

use crate::{
    EMPTY_WORD, Map, Set, Word,
    merkle::{
        NodeIndex, SparseMerklePath,
        smt::{
            LeafIndex, SMT_DEPTH, SmtLeaf, SmtProof,
            large_forest::{
                history::{History, HistoryView},
                iterator::EntriesIterator,
                lineage::LineageData,
                root::{RootValue, UniqueRoot},
            },
        },
    },
};

// SPARSE MERKLE TREE FOREST
// ================================================================================================

/// A high-performance forest of sparse merkle trees with pluggable storage backends.
///
/// See the module documentation for more information.
#[derive(Clone, Debug)]
pub struct LargeSmtForest<B: BackendReader> {
    /// The configuration for how the forest functions.
    config: Config,

    /// The backend for storing the full trees that exist as part of the forest.
    ///
    /// It makes no guarantees as to where the tree data is stored, and **must not be exposed** in
    /// the API of the forest to ensure that internal invariants are maintained.
    backend: B,

    /// The container for the in-memory data associated with each lineage in the forest.
    ///
    /// It must contain an entry for every tree lineage in the forest.
    lineage_data: Map<LineageId, LineageData>,

    /// A set tracking which lineages have histories containing actual deltas in order to speed up
    /// querying.
    ///
    /// It must always be maintained as a strict subset of `lineage_data.keys()`.
    non_empty_histories: Set<LineageId>,
}

// CONSTRUCTION AND BASIC QUERIES
// ================================================================================================

/// These functions deal with the creation of new forest instances, and hence rely on the ability to
/// query the backend to do so.
///
/// # Performance
///
/// All the methods in this impl block require access to the underlying [`Backend`] instance to
/// return results. This means that their performance will depend heavily on the specific instance
/// with which the forest was constructed.
///
/// Where anything more specific can be said about performance, the method documentation will
/// contain more detail.
impl<B: BackendReader> LargeSmtForest<B> {
    /// Constructs a new forest backed by the provided `backend` using the default [`Config`] for
    /// the forest's behavior.
    ///
    /// This constructor will treat whatever state is contained within the provided `backend` as the
    /// starting state for the forest. This means that, if you pass a newly-initialized storage, the
    /// forest will start in an empty state. Similarly, if you pass a `backend` that already
    /// contains some data (loaded from disk, for example), then the forest will start in that state
    /// instead.
    ///
    /// # Performance
    ///
    /// For performance notes on this method, see [`Self::with_config`] instead.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Other`] if the forest cannot be started up correctly using the
    ///   provided `backend`.
    pub fn new(backend: B) -> Result<Self> {
        Self::with_config(backend, Config::default())
    }

    /// Constructs a new forest backed by the provided `backend` and configuring behavior using the
    /// provided `config`.
    ///
    /// This constructor will treat whatever state is contained within the provided `backend` as the
    /// starting state for the forest. This means that, if you pass a newly-initialized storage, the
    /// forest will start in an empty state. Similarly, if you pass a `backend` that already
    /// contains some data (loaded from disk, for example), then the forest will start in that state
    /// instead.
    ///
    /// # Performance
    ///
    /// This method is required to load the basic tree metadata from the backend during forest
    /// construction. This metadata should be stored separately, and hence this method should take a
    /// relatively small amount of time.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Fatal`] if the forest cannot be started up correctly using the
    ///   provided `backend`.
    pub fn with_config(backend: B, config: Config) -> Result<Self> {
        // The lineages at initialization time are whichever ones the backend knows about. To that
        // end, we read from the backend and construct the starting state for each known lineage.
        let lineage_data = backend
            .trees()?
            .map(|t| {
                let data = LineageData {
                    history: History::empty(config.max_history_versions()),
                    latest_version: t.version(),
                    latest_root: t.root(),
                };
                (t.lineage(), data)
            })
            .collect::<Map<LineageId, LineageData>>();

        // As no backend is able to preserve history, we can unconditionally initialize the tracking
        // for non-empty histories as empty.
        let non_empty_histories = Set::default();

        Ok(Self {
            config,
            backend,
            lineage_data,
            non_empty_histories,
        })
    }
}

/// These methods provide the ability to perform basic operations on the forest without the need to
/// query the backend.
///
/// # Performance
///
/// All of these methods can be performed fully in-memory, and hence their performance is
/// predictable on a given machine regardless of the choice of [`Backend`] instance being used by
/// the forest.
impl<B: BackendReader> LargeSmtForest<B> {
    /// Returns an iterator that yields all the (uniquely identified) roots that the forest knows
    /// about, including those from historical versions.
    ///
    /// The iteration order of these roots is unspecified.
    pub fn roots(&self) -> impl Iterator<Item = UniqueRoot> {
        // As the history container does not deal in roots with domains, we have to attach the
        // corresponding domain to each root, and do this as lazily as possible to avoid
        // materializing more things than we need to.
        self.lineage_data
            .iter()
            .flat_map(|(l, d)| d.roots().map(|r| UniqueRoot::new(*l, r)))
    }

    /// Gets the latest version of the tree for the provided `lineage`, if that lineage is in the
    /// forest, or returns [`None`] otherwise.
    pub fn latest_version(&self, lineage: LineageId) -> Option<VersionId> {
        self.lineage_data.get(&lineage).map(|d| d.latest_version)
    }

    /// Returns an iterator that yields the root values for trees within the specified `lineage`, or
    /// [`None`] if the lineage is not known.
    ///
    /// The iteration order of the roots is guaranteed to move backward in time as the iterator
    /// advances, with earlier items being roots from versions closer to the present. The current
    /// root of the lineage will thus always be the first item yielded by the iterator.
    pub fn lineage_roots(&self, lineage: LineageId) -> Option<impl Iterator<Item = RootValue>> {
        self.lineage_data.get(&lineage).map(LineageData::roots)
    }

    /// Gets the value root of the newest tree in the provided `lineage`, if that lineage is in the
    /// forest, or returns [`None`] otherwise.
    pub fn latest_root(&self, lineage: LineageId) -> Option<RootValue> {
        self.lineage_data.get(&lineage).map(|d| d.latest_root)
    }

    /// Returns the number of trees in the forest that have unique identity.
    ///
    /// This is **not** the number of unique tree lineages in the forest, as it includes all
    /// historical trees as well. For that, see [`Self::lineage_count`].
    pub fn tree_count(&self) -> usize {
        self.roots().count()
    }

    /// Returns the number of unique tree lineages in the forest.
    ///
    /// This is **not** the number of unique trees in the forest, as it does not include all
    /// versions in each lineage. For that, see [`Self::tree_count`].
    pub fn lineage_count(&self) -> usize {
        self.lineage_data.len()
    }

    /// Returns data describing what information the forest knows about the provided `root`.
    pub fn root_info(&self, root: TreeId) -> RootInfo {
        let Some(d) = self.lineage_data.get(&root.lineage()) else {
            return RootInfo::Missing;
        };

        if d.latest_version == root.version() {
            return RootInfo::LatestVersion(d.latest_root);
        }

        if root.version() > d.latest_version {
            return RootInfo::Missing;
        }

        match d.history.root_for_version(root.version()) {
            Ok(r) => RootInfo::HistoricalVersion(r),
            Err(_) => RootInfo::Missing,
        }
    }

    /// Removes all tree versions in the forest that are older than the provided `version`, but
    /// always retains the latest tree in each lineage.
    pub fn truncate(&mut self, version: VersionId) {
        let mut newly_empty = Set::default();

        self.non_empty_histories.iter().for_each(|l| {
            if let Some(d) = self.lineage_data.get_mut(l)
                && d.truncate(version)
            {
                newly_empty.insert(*l);
            }
        });

        for l in &newly_empty {
            self.non_empty_histories.remove(l);
        }
    }
}

// QUERIES
// ================================================================================================

/// These methods pertain to non-mutating queries about the data stored in the forest. They differ
/// from the simple queries in the previous block by requiring access to the backend to function.
///
/// # Performance
///
/// All the methods in this impl block require access to the underlying [`Backend`] instance to
/// return results. This means that their performance will depend heavily on the specific instance
/// with which the forest was constructed.
///
/// Where anything more specific can be said about performance, the method documentation will
/// contain more detail.
impl<B: BackendReader> LargeSmtForest<B> {
    /// Returns an opening for the specified `key` in the specified `tree`, regardless of whether
    /// the `tree` has a value associated with `key` or not.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Fatal`] if the backend fails to operate properly during the query.
    /// - [`LargeSmtForestError::UnknownLineage`] if the provided `tree` specifies a lineage that is
    ///   not one known by the forest.
    /// - [`LargeSmtForestError::UnknownTree`] if the provided `tree` refers to a tree that is not a
    ///   member of the forest.
    /// - [`LargeSmtForestError::Merkle`] if there is insufficient data in the specified `tree` to
    ///   provide an opening for `key`.
    pub fn open(&self, tree: TreeId, key: Word) -> Result<SmtProof> {
        // We want to return an error if the lineage is unknown to comply with the stated contract
        // for the function.
        let lineage_data = self
            .lineage_data
            .get(&tree.lineage())
            .ok_or(LargeSmtForestError::UnknownLineage(tree.lineage()))?;

        // We then check if the version exists in the forest. We do this before fetching the full
        // tree as to do so otherwise would represent a possible denial-of-service vector.
        if tree.version() > lineage_data.latest_version {
            // Here the tree is newer than we know about, and so we should error.
            return Err(LargeSmtForestError::UnknownTree(tree));
        }

        if tree.version() == lineage_data.latest_version {
            // In this case we can service the opening directly from the backend as the query is for
            // the latest version of the tree.
            return self.backend.open(tree.lineage(), key).map_err(Into::into);
        }

        let Ok(view) = lineage_data.history.get_view_at(tree.version()) else {
            // In this case, either the version in `tree` is newer than the latest we know about, so
            // we can't provide an opening, or it is not serviceable by the history. In either case,
            // the specified tree is unknown to the forest.
            return Err(LargeSmtForestError::UnknownTree(tree));
        };

        // We start by computing the relevant leaf index and getting the opening from the full
        // tree to do our (potentially) most-expensive work up front.
        let leaf_index = LeafIndex::from(key);
        let opening = self
            .backend
            .open(tree.lineage(), key)
            .map_err(Into::<LargeSmtForestError>::into)?;

        // Pre-collect the changed keys relevant to the target leaf and its deepest sibling
        // in a single pass over the history delta, avoiding repeated full scans.
        let sibling_leaf_index =
            LeafIndex::new_max_depth(NodeIndex::from(leaf_index).sibling().position());
        let mut target_leaf_changes = Vec::new();
        let mut sibling_leaf_changes = Vec::new();
        for (k, v) in view.changed_keys() {
            let key_leaf = LeafIndex::from(k);
            if key_leaf == leaf_index {
                target_leaf_changes.push((k, v));
            } else if key_leaf == sibling_leaf_index {
                sibling_leaf_changes.push((k, v));
            }
        }

        // We compute the new leaf and new path by applying any reversions from the history on
        // top of the current state.
        let new_leaf = Self::merge_leaves(opening.leaf(), view, &target_leaf_changes)?;
        let new_path = Self::merge_paths(
            &self.backend,
            tree.lineage(),
            leaf_index,
            opening.path(),
            view,
            &sibling_leaf_changes,
        )?;

        // Finally we can compose our combined opening.
        Ok(SmtProof::new(new_path, new_leaf)?)
    }

    /// Returns the value associated with the provided `key` in the specified `tree`, or [`None`] if
    /// there is no non-default value corresponding to the provided `key` in that tree.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Fatal`] if the backend fails to operate properly during the query.
    /// - [`LargeSmtForestError::UnknownLineage`] if the provided `tree` specifies a lineage that is
    ///   not one known by the forest.
    /// - [`LargeSmtForestError::UnknownTree`] if the provided `tree` refers to a tree that is not a
    ///   member of the forest.
    pub fn get(&self, tree: TreeId, key: Word) -> Result<Option<Word>> {
        // We want to return an error if the lineage is unknown to comply with the stated contract
        // for the function.
        let lineage_data = self
            .lineage_data
            .get(&tree.lineage())
            .ok_or(LargeSmtForestError::UnknownLineage(tree.lineage()))?;

        if tree.version() > lineage_data.latest_version {
            // Here the tree is newer than we know about, and so we should error.
            return Err(LargeSmtForestError::UnknownTree(tree));
        }

        if tree.version() == lineage_data.latest_version {
            // In this case we can service the opening directly from the backend as the query is for
            // the latest version of the tree.
            return self.backend.get(tree.lineage(), key).map_err(Into::into);
        }

        let Ok(view) = lineage_data.history.get_view_at(tree.version()) else {
            // In this case, either the version in `tree` is newer than the latest we know about, so
            // we can't provide an opening, or it is not serviceable by the history. In either case,
            // the specified tree is unknown to the forest.
            return Err(LargeSmtForestError::UnknownTree(tree));
        };

        // We prioritize the value in the history if one exists, falling back to the full tree
        // if none does. We don't use `or` here because we don't want to query the backend
        // unless we have to, and we can't use `or_else` due to lack of support for `Result`.
        let result = if let Some(value) = view.value(&key) {
            // If the history value is an empty word, the value was unset in the historical tree
            // version, so we have to conform to our interface by returning `None` here.
            if value == EMPTY_WORD { None } else { Some(value) }
        } else {
            self.backend.get(tree.lineage(), key)?
        };

        // We can just return that directly.
        Ok(result)
    }

    /// Returns the number of populated entries in the specified `tree`.
    ///
    /// # Performance
    ///
    /// This method should always return its result in constant time. The exact performance profile
    /// to do this is dependent on the backend for the most recent tree, but for historical trees
    /// will be the same regardless of the backend in use.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Fatal`] if the backend fails to operate properly during the query.
    /// - [`LargeSmtForestError::UnknownLineage`] if the provided `tree` specifies a lineage that is
    ///   not one known by the forest.
    /// - [`LargeSmtForestError::UnknownTree`] if the provided `tree` refers to a tree that is not a
    ///   member of the forest.
    pub fn entry_count(&self, tree: TreeId) -> Result<usize> {
        // We start by yielding an error if we cannot get the lineage data for the specified tree.
        let Some(lineage_data) = self.lineage_data.get(&tree.lineage()) else {
            return Err(LargeSmtForestError::UnknownLineage(tree.lineage()));
        };

        if tree.version() > lineage_data.latest_version {
            // Here the tree is newer than we know about, and so we should error.
            return Err(LargeSmtForestError::UnknownTree(tree));
        }

        if tree.version() == lineage_data.latest_version {
            // We can fast-path the current tree using the backend.
            return Ok(self.backend.entry_count(tree.lineage())?);
        }

        let Ok(view) = lineage_data.history.get_view_at(tree.version()) else {
            // If neither of these are the case, we do not know the version and so fail out.
            return Err(LargeSmtForestError::UnknownTree(tree));
        };

        Ok(view.entry_count())
    }

    /// Returns an iterator that yields the entries in the specified `tree`.
    ///
    /// - If any error occurs during iteration, this is signaled to the user by the iterator
    ///   yielding `Some(Err(...))`. The user should stop on first error, as the iterator will be in
    ///   an inconsistent state afterward.
    /// - `None` is returned if the true end of the iterator is reached successfully, or at any
    ///   point after an error has been yielded.
    ///
    /// # Performance
    ///
    /// The performance of the iterator depends both on the choice of backend _and_ the type of tree
    /// that is queried for. We cannot give exact performance figures, but in general querying over
    /// **the current tree** in a lineage will be faster than querying over **a historical tree** in
    /// a lineage.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Fatal`] if the backend fails to operate properly during the query.
    /// - [`LargeSmtForestError::UnknownLineage`] if the provided `tree` specifies a lineage that is
    ///   not one known by the forest.
    /// - [`LargeSmtForestError::UnknownTree`] if the provided `tree` refers to a tree that is not a
    ///   member of the forest.
    pub fn entries(&self, tree: TreeId) -> Result<impl Iterator<Item = Result<TreeEntry>>> {
        // We start by yielding an error if we cannot get the lineage data for the specified tree.
        let Some(lineage_data) = self.lineage_data.get(&tree.lineage()) else {
            return Err(LargeSmtForestError::UnknownLineage(tree.lineage()));
        };

        if tree.version() > lineage_data.latest_version {
            // Here the tree is newer than we know about, and so we should error.
            return Err(LargeSmtForestError::UnknownTree(tree));
        }

        if tree.version() == lineage_data.latest_version {
            // If we match the current version, we can construct the simple iterator variant.
            return Ok(EntriesIterator::new_without_history(self.backend.entries(tree.lineage())?));
        }

        let Ok(view) = lineage_data.history.get_view_at(tree.version()) else {
            // If neither of these are the case, we do not know the version and so fail out.
            return Err(LargeSmtForestError::UnknownTree(tree));
        };

        // If we can serve it from the history we need to instead construct the complex version.
        Ok(EntriesIterator::new_with_history(self.backend.entries(tree.lineage())?, view))
    }
}

// SINGLE-TREE MODIFIERS
// ================================================================================================

/// These methods pertain to modifications that can be made to a single tree in the forest. They
/// exploit parallelism within the single target tree wherever possible.
///
/// # Performance
///
/// All the methods in this impl block require access to the underlying [`Backend`] instance to
/// return results. This means that their performance will depend heavily on the specific instance
/// with which the forest was constructed.
///
/// Where anything more specific can be said about performance, the method documentation will
/// contain more detail.
impl<B: Backend> LargeSmtForest<B> {
    /// Adds a new `lineage` to the forest, creating an empty tree and modifying it as specified by
    /// `updates`, with the result taking the provided `new_version`.
    ///
    /// This is the one-phase convenience API. It is equivalent to ensuring that the lineage
    /// does not exist and then calling [`Self::compute_tree_mutations`] followed immediately
    /// by [`Self::apply_mutations`]. Use the two-phase API directly when the proposed root
    /// commitment must be inspected before committing the backend changes.
    ///
    /// If the provided `updates` batch is empty, then the **empty tree will be added** as the first
    /// version in the lineage.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::DuplicateLineage`] if the provided `lineage` is the same as an
    ///   already-known lineage.
    /// - [`LargeSmtForestError::Fatal`] if the backend fails while computing or applying the
    ///   mutation.
    /// - [`LargeSmtForestError::Merkle`] if the provided `updates` cannot be applied to the empty
    ///   tree.
    pub fn add_lineage(
        &mut self,
        lineage: LineageId,
        new_version: VersionId,
        updates: SmtUpdateBatch,
    ) -> Result<TreeWithRoot> {
        let mutations = self.compute_add_lineage_mutations(lineage, new_version, updates)?;
        let mut roots = self.apply_mutations(mutations)?;
        Ok(roots.pop().expect("single lineage mutation returns one root"))
    }

    /// Computes the mutations required to add a new `lineage`, without applying them.
    ///
    /// This is the first phase of [`Self::add_lineage`]. It computes the proposed new root for the
    /// lineage and the backend-specific data needed to commit the update later via
    /// [`Self::apply_mutations`]. Reverse mutations needed for history are returned by the backend
    /// during the apply phase.
    ///
    /// The forest and backend are not modified by this method. Callers can inspect the returned
    /// mutation set before committing it, which is useful when root commitments must be published,
    /// checked, or combined with other data before the backend write occurs.
    ///
    /// If the provided `updates` batch is empty, then the **empty tree will be added** as the first
    /// version in the lineage.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::DuplicateLineage`] if the provided `lineage` is the same as an
    ///   already-known lineage.
    /// - [`LargeSmtForestError::Fatal`] if the backend fails while computing the mutation.
    /// - [`LargeSmtForestError::Merkle`] if the provided `updates` cannot be applied to the empty
    ///   tree.
    ///
    /// # Applying the Result
    ///
    /// The returned mutation set is valid only while the lineage remains at the same latest
    /// version and root. [`Self::apply_mutations`] rejects stale mutation sets if the lineage has
    /// changed since this method was called.
    fn compute_add_lineage_mutations(
        &self,
        lineage: LineageId,
        new_version: VersionId,
        updates: SmtUpdateBatch,
    ) -> Result<SmtForestMutationSet<B>> {
        if self.lineage_data.contains_key(&lineage) {
            return Err(LargeSmtForestError::DuplicateLineage(lineage));
        }

        self.compute_tree_mutations(lineage, new_version, updates)
    }

    /// Performs the provided `updates` on the latest tree in the specified `lineage`, adding a
    /// single new root to the forest (corresponding to `new_version`) for the entire batch, and
    /// returning the data for the new root of the tree.
    ///
    /// This is the one-phase convenience API. It is equivalent to ensuring that the lineage exists
    /// then calling [`Self::compute_tree_mutations`] followed immediately by
    /// [`Self::apply_mutations`]. Use the two-phase API directly when the proposed root commitment
    /// must be inspected before committing the backend changes.
    ///
    /// If applying the provided `operations` results in no changes to the tree, then the root data
    /// will be returned unchanged and no new tree will be allocated. It will retain its original
    /// version, and not be returned with `new_version`.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::BadVersion`] if `new_version` is not newer than the latest version
    ///   for the provided `lineage`.
    /// - [`LargeSmtForestError::Fatal`] if the backend fails while computing or applying the
    ///   mutation.
    /// - [`LargeSmtForestError::Merkle`] if the provided `updates` cannot be applied to the latest
    ///   tree.
    /// - [`LargeSmtForestError::UnknownLineage`] if `lineage` is not known by the forest.
    pub fn update_tree(
        &mut self,
        lineage: LineageId,
        new_version: VersionId,
        updates: SmtUpdateBatch,
    ) -> Result<TreeWithRoot> {
        let mutations = self.compute_update_tree_mutations(lineage, new_version, updates)?;
        let mut roots = self.apply_mutations(mutations)?;
        Ok(roots.pop().expect("single lineage mutation returns one root"))
    }

    /// Computes the mutations required to update the latest tree in `lineage`, without applying
    /// them.
    ///
    /// This is the first phase of [`Self::update_tree`]. It computes the proposed new root for the
    /// lineage and the backend-specific data needed to commit the update later via
    /// [`Self::apply_mutations`]. Reverse mutations needed for history are returned by the backend
    /// during the apply phase.
    ///
    /// The forest and backend are not modified by this method. Callers can inspect the returned
    /// mutation set before committing it, which is useful when root commitments must be published,
    /// checked, or combined with other data before the backend write occurs.
    ///
    /// If applying `updates` would not change the tree, the returned mutation set represents a
    /// no-op. Applying it will not advance the lineage version or allocate a new tree version, and
    /// [`SmtForestMutationSet::roots`] will report the current latest version/root.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::UnknownLineage`] if `lineage` is not known by the forest.
    /// - [`LargeSmtForestError::BadVersion`] if `new_version` is not newer than the latest version
    ///   for `lineage`.
    /// - [`LargeSmtForestError::Fatal`] if the backend fails while computing prepared data.
    /// - [`LargeSmtForestError::Merkle`] if the provided `updates` cannot be applied to the latest
    ///   tree.
    ///
    /// # Applying the Result
    ///
    /// The returned mutation set is valid only while the lineage remains at the same latest
    /// version and root. [`Self::apply_mutations`] rejects stale mutation sets if the lineage has
    /// changed since this method was called.
    fn compute_update_tree_mutations(
        &self,
        lineage: LineageId,
        new_version: VersionId,
        updates: SmtUpdateBatch,
    ) -> Result<SmtForestMutationSet<B>> {
        let Some(lineage_data) = self.lineage_data.get(&lineage) else {
            return Err(LargeSmtForestError::UnknownLineage(lineage));
        };

        if lineage_data.latest_version >= new_version {
            return Err(LargeSmtForestError::BadVersion {
                provided: new_version,
                latest: lineage_data.latest_version,
            });
        }

        self.compute_tree_mutations(lineage, new_version, updates)
    }

    /// Computes the mutations required to mutate one lineage, without applying them.
    ///
    /// If the lineage is already present it is updated, while unknown lineages are added from the
    /// empty tree.
    ///
    /// The forest and backend are not modified by this method. Callers can inspect the returned
    /// mutation set, especially via [`SmtForestMutationSet::roots`] or
    /// [`SmtForestMutationSet::lineage_mutations`], before deciding whether to commit it.
    ///
    /// If the provided `updates` batch is empty, the returned mutation set still represents adding
    /// the empty tree as the first version of the lineage.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::DuplicateLineage`] if `lineage` is already known by the forest.
    /// - [`LargeSmtForestError::Fatal`] if the backend fails while computing prepared data.
    /// - [`LargeSmtForestError::Merkle`] if the provided `updates` cannot be applied to the empty
    ///   tree.
    ///
    /// # Applying the Result
    ///
    /// The returned mutation set is valid only for the forest state against which it was computed.
    /// [`Self::apply_mutations`] rejects stale mutation sets if the lineage has changed since this
    /// method was called.
    pub fn compute_tree_mutations(
        &self,
        lineage: LineageId,
        new_version: VersionId,
        updates: SmtUpdateBatch,
    ) -> Result<SmtForestMutationSet<B>> {
        if let Some(lineage_data) = self.lineage_data.get(&lineage)
            && lineage_data.latest_version >= new_version
        {
            return Err(LargeSmtForestError::BadVersion {
                provided: new_version,
                latest: lineage_data.latest_version,
            });
        }

        let mut batch = SmtForestUpdateBatch::empty();
        batch.operations(lineage).add_operations(updates.into_iter());
        let (entries, prepared) = self.backend.compute_mutations(new_version, batch)?;
        Ok(SmtForestMutationSet::new(entries, prepared))
    }
}

// MULTI-TREE MODIFIERS
// ================================================================================================

/// These methods pertain to modifications that can be made to multiple trees in the forest at once.
/// They exploit parallelism both between trees and within trees wherever possible.
///
/// # Performance
///
/// All the methods in this impl block require access to the underlying [`Backend`] instance to
/// return results. This means that their performance will depend heavily on the specific instance
/// with which the forest was constructed.
///
/// Where anything more specific can be said about performance, the method documentation will
/// contain more detail.
impl<B: Backend> LargeSmtForest<B> {
    /// Adds multiple new `lineages` to the forest, creating an empty tree for each and applying the
    /// provided modifications to it, with the result being given the specified `version`.
    ///
    /// This is the one-phase convenience API. It is equivalent to make sure that none of the
    /// lineages exists and then calling [`Self::compute_forest_mutations`] followed immediately
    /// by [`Self::apply_mutations`]. Use the two-phase API directly when the proposed root
    /// commitments must be inspected before committing the backend changes.
    ///
    /// If the provided batch of modifications is empty for any given lineage, then the **empty tree
    /// will be added** as the first version in that lineage.
    ///
    /// # Performance
    ///
    /// This method is intended to be a reliable choice if the caller needs to add more than one
    /// new lineage at once. At _worst_, its performance should be no slower than repeating
    /// [`Self::add_lineage`] in a loop, but in some cases it may be significantly more performant.
    ///
    /// The exact scope of any speed-up is determined by the backend in use, so it is worth reading
    /// the documentation for the backend's [`Backend::compute_mutations`] method.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::DuplicateLineage`] if any of the provided lineages share an ID with
    ///   an already-known lineage.
    /// - [`LargeSmtForestError::Fatal`] if the backend fails while computing or applying the
    ///   mutations.
    /// - [`LargeSmtForestError::Merkle`] if any provided updates cannot be applied to an empty
    ///   tree.
    pub fn add_lineages(
        &mut self,
        version: VersionId,
        lineages: SmtForestUpdateBatch,
    ) -> Result<Vec<TreeWithRoot>> {
        let mutations = self.compute_add_lineages_mutations(version, lineages)?;
        self.apply_mutations(mutations)
    }

    /// Computes mutations that would add multiple new lineages without applying them.
    ///
    /// This is the first phase of [`Self::add_lineages`]. It returns a [`SmtForestMutationSet`]
    /// containing one proposed result per lineage in `lineages`, plus backend-specific prepared
    /// data that can later be committed with [`Self::apply_mutations`].
    ///
    /// The forest and backend are not modified by this method. Callers can inspect the returned
    /// roots before committing the batch. This is useful when a higher-level transaction must know
    /// all new root commitments before the forest backend is updated.
    ///
    /// Empty per-lineage operation batches still produce new empty lineages in the mutation set.
    ///
    /// # Performance
    ///
    /// Backends may compute the per-lineage mutations in parallel and may prepare a batched apply
    /// representation. This method should generally be preferred over repeated
    /// [`Self::compute_add_lineage_mutations`] calls when adding multiple lineages.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::DuplicateLineage`] if any provided lineage is already known by the
    ///   forest.
    /// - [`LargeSmtForestError::Fatal`] if the backend fails while computing prepared data.
    /// - [`LargeSmtForestError::Merkle`] if any provided updates cannot be applied to an empty
    ///   tree.
    fn compute_add_lineages_mutations(
        &self,
        version: VersionId,
        lineages: SmtForestUpdateBatch,
    ) -> Result<SmtForestMutationSet<B>> {
        for lineage in lineages.lineages() {
            if self.lineage_data.contains_key(lineage) {
                return Err(LargeSmtForestError::DuplicateLineage(*lineage));
            }
        }

        let (entries, prepared) = self.backend.compute_mutations(version, lineages)?;
        Ok(SmtForestMutationSet::new(entries, prepared))
    }

    /// Performs the provided `updates` on the forest, adding at most one new root with version
    /// `new_version` for each targeted lineage and returning the resulting root data.
    ///
    /// This is the one-phase convenience API. It is equivalent to checking that all of the lineages
    /// exist then calling [`Self::compute_forest_mutations`] followed immediately by
    /// [`Self::apply_mutations`]. Use the two-phase API directly when the proposed root
    /// commitments must be inspected before committing the backend changes.
    ///
    /// If applying the associated batch to any given lineage in the forest results in no changes to
    /// that tree, the initial root for that lineage will be returned and no new tree will be
    /// allocated.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::UnknownLineage`] if any lineage in the batch of modifications is
    ///   one that is not known by the forest.
    /// - [`LargeSmtForestError::Fatal`] if the backend fails while computing or applying the
    ///   mutations.
    /// - [`LargeSmtForestError::BadVersion`] if `new_version` is not newer than the latest version
    ///   for any targeted lineage.
    /// - [`LargeSmtForestError::Merkle`] if any provided updates cannot be applied to the relevant
    ///   latest tree.
    pub fn update_forest(
        &mut self,
        new_version: VersionId,
        updates: SmtForestUpdateBatch,
    ) -> Result<Vec<TreeWithRoot>> {
        let mutations = self.compute_update_forest_mutations(new_version, updates)?;
        self.apply_mutations(mutations)
    }

    /// Computes mutations that would update multiple existing lineages without applying them.
    ///
    /// This is the first phase of [`Self::update_forest`]. It returns an [`SmtForestMutationSet`]
    /// containing one proposed result per lineage in `updates`, plus backend-specific prepared data
    /// that can later be committed with [`Self::apply_mutations`].
    ///
    /// The forest and backend are not modified by this method. Callers can inspect all proposed
    /// root commitments before committing the batch. This is useful when the forest update is only
    /// one part of a larger transaction or when root commitments must be signed, checked, or stored
    /// elsewhere before the backend write occurs.
    ///
    /// If a per-lineage update would not change the tree, the corresponding mutation is a no-op.
    /// Applying the mutation set will not advance that lineage's version or allocate a new tree
    /// version for it.
    ///
    /// # Performance
    ///
    /// Backends may compute per-lineage mutations in parallel and may prepare a batched apply
    /// representation. This method should generally be preferred over repeated
    /// [`Self::compute_update_tree_mutations`] calls when updating multiple lineages.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::UnknownLineage`] if any targeted lineage is not known by the
    ///   forest.
    /// - [`LargeSmtForestError::BadVersion`] if `new_version` is not newer than the latest version
    ///   for any targeted lineage.
    /// - [`LargeSmtForestError::Fatal`] if the backend fails while computing prepared data.
    /// - [`LargeSmtForestError::Merkle`] if any provided updates cannot be applied to the relevant
    ///   latest tree.
    fn compute_update_forest_mutations(
        &self,
        new_version: VersionId,
        updates: SmtForestUpdateBatch,
    ) -> Result<SmtForestMutationSet<B>> {
        updates
            .lineages()
            .map(|lineage| {
                let Some(lineage_data) = self.lineage_data.get(lineage) else {
                    return Err(LargeSmtForestError::UnknownLineage(*lineage));
                };

                if lineage_data.latest_version < new_version {
                    Ok(())
                } else {
                    Err(LargeSmtForestError::BadVersion {
                        provided: new_version,
                        latest: lineage_data.latest_version,
                    })
                }
            })
            .collect::<Result<Vec<_>>>()?;

        self.compute_forest_mutations(new_version, updates)
    }

    /// Computes mutations that would add or update multiple lineages without applying them.
    ///
    /// Lineages that are already present are updated, while unknown lineages are added from the
    /// empty tree.
    ///
    /// The forest and backend are not modified by this method. Callers can inspect all proposed
    /// root commitments before committing the batch. This is useful when the forest update is only
    /// one part of a larger transaction or when root commitments must be signed, checked, or stored
    /// elsewhere before the backend write occurs.
    ///
    /// If a per-lineage update would not change the tree, the corresponding mutation is a no-op.
    /// Applying the mutation set will not advance that lineage's version or allocate a new tree
    /// version for it.
    ///
    /// # Performance
    ///
    /// Backends may compute the per-lineage mutations in parallel and may prepare a batched apply
    /// representation. This method should generally be preferred over repeated
    /// [`Self::compute_tree_mutations`] calls when updating multiple lineages.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Fatal`] if the backend fails while computing or applying the
    ///   mutations.
    /// - [`LargeSmtForestError::BadVersion`] if `new_version` is not newer than the latest version
    ///   for any targeted lineage that is already present.
    /// - [`LargeSmtForestError::Merkle`] if any provided updates cannot be applied to the relevant
    ///   latest tree.
    pub fn compute_forest_mutations(
        &self,
        new_version: VersionId,
        updates: SmtForestUpdateBatch,
    ) -> Result<SmtForestMutationSet<B>> {
        updates
            .lineages()
            .map(|lineage| {
                let Some(lineage_data) = self.lineage_data.get(lineage) else {
                    return Ok(());
                };

                if lineage_data.latest_version < new_version {
                    Ok(())
                } else {
                    Err(LargeSmtForestError::BadVersion {
                        provided: new_version,
                        latest: lineage_data.latest_version,
                    })
                }
            })
            .collect::<Result<Vec<_>>>()?;

        let (entries, prepared) = self.backend.compute_mutations(new_version, updates)?;
        Ok(SmtForestMutationSet::new(entries, prepared))
    }

    /// Applies mutations previously computed by one of the forest compute methods.
    ///
    /// This is the second phase of the two-phase update API. It consumes an
    /// [`SmtForestMutationSet`] returned by one of:
    ///
    /// - [`Self::compute_tree_mutations`], or
    /// - [`Self::compute_forest_mutations`].
    ///
    /// The backend validates that the mutation set is still applicable before committing anything.
    /// For update mutations, the latest version and root of every affected lineage must still match
    /// the version/root captured during the compute phase. For new-lineage mutations, the lineage
    /// must still be absent. These checks prevent stale mutation sets from being applied after
    /// intervening forest changes.
    ///
    /// If backend validation succeeds, the opaque backend-prepared data is committed first. Only
    /// after the backend apply succeeds does the forest update its in-memory lineage metadata and
    /// history. This ordering keeps the forest consistent if the backend reports an error.
    ///
    /// The returned roots match [`SmtForestMutationSet::roots`] for the applied mutation set. No-op
    /// update mutations return the existing latest version/root for their lineages.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::DuplicateLineage`] if a mutation set attempts to add a lineage that
    ///   is now already known.
    /// - [`LargeSmtForestError::UnknownLineage`] if a mutation set attempts to update a lineage
    ///   that is no longer known.
    /// - [`LargeSmtForestError::BadVersion`] if an update mutation was computed against a version
    ///   that is no longer the latest version.
    /// - [`LargeSmtForestError::Merkle`] if an update mutation was computed against a root that is
    ///   no longer the latest root.
    /// - [`LargeSmtForestError::Fatal`] if the backend fails while applying its prepared data.
    pub fn apply_mutations(
        &mut self,
        mutations: SmtForestMutationSet<B>,
    ) -> Result<Vec<TreeWithRoot>> {
        let (entries, prepared) = mutations.into_parts();

        let applied_entries = self.backend.apply_mutations(prepared)?;

        assert_eq!(
            entries.len(),
            applied_entries.len(),
            "backend returned an unexpected number of applied mutations"
        );
        let mut roots = Vec::with_capacity(applied_entries.len());
        for (entry, applied) in entries.into_iter().zip(applied_entries) {
            assert_eq!(entry.lineage(), applied.lineage());
            assert_eq!(entry.old_version(), applied.old_version());
            assert_eq!(entry.new_version(), applied.new_version());
            assert_eq!(entry.old_root(), applied.old_root());
            assert_eq!(entry.new_root(), applied.new_root());
            assert_eq!(entry.kind(), applied.kind());

            let root = applied.result();
            match entry.kind() {
                LineageMutationKind::AddLineage => {
                    let lineage_data = LineageData {
                        history: History::empty(self.config.max_history_versions()),
                        latest_version: root.version(),
                        latest_root: root.root(),
                    };
                    self.lineage_data.insert(entry.lineage(), lineage_data);
                },
                LineageMutationKind::UpdateTree => {
                    if entry.old_root() != entry.new_root() {
                        let lineage_data = self
                            .lineage_data
                            .get_mut(&entry.lineage())
                            .expect("Lineage has been checked to be present");

                        let old_version =
                            entry.old_version().expect("update mutations have old versions");
                        let old_entry_count = applied.old_entry_count();
                        lineage_data
                            .history
                            .add_version_from_mutation_set(
                                old_version,
                                applied.into_reverse(),
                                old_entry_count,
                            )
                            .unwrap_or_else(|_| {
                                panic!("Unable to add valid version {old_version} to history")
                            });

                        self.non_empty_histories.insert(entry.lineage());
                        lineage_data.latest_root = entry.new_root();
                        lineage_data.latest_version = entry.new_version();
                    }
                },
            }
            roots.push(root);
        }

        Ok(roots)
    }
}

// INTERNAL UTILITY FUNCTIONS
// ================================================================================================

/// This block contains internal functions that exist to de-duplicate or modularize functionality
/// within the forest. These should not be exposed.
impl<B: BackendReader> LargeSmtForest<B> {
    /// Applies the history delta given by `history_view` on top of the provided `full_tree_leaf` to
    /// produce the correct leaf for a historical opening.
    ///
    /// `leaf_changes` must contain exactly the entries from the history's changed keys that belong
    /// to the same leaf index as `full_tree_leaf`. Providing pre-filtered changes avoids repeated
    /// full scans of the history delta.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::SmtLeafError`] if the combined leaf cannot be computed correctly
    fn merge_leaves(
        full_tree_leaf: &SmtLeaf,
        history_view: HistoryView,
        leaf_changes: &[(Word, Word)],
    ) -> Result<SmtLeaf> {
        // We apply the historical delta on top of the existing entries to perform the reversion
        // back to the previous state.
        let mut leaf_entries = Map::new();
        for (k, v) in full_tree_leaf.to_entries() {
            // If the history removes the pair, then we skip adding it to our output leaf entries.
            if history_view.is_key_removed(k) {
                continue;
            }

            leaf_entries.insert(*k, *v);
        }

        // The delta may have added items that we do not have (due to later removals), so we have to
        // add those back, but only the ones for the leaf we care about. The caller has already
        // filtered `leaf_changes` to only contain entries for this leaf.
        leaf_entries.extend(leaf_changes.iter().filter(|(_, v)| !v.is_empty()).copied());

        // At this point we should not see any entries with empty values, so in debug builds let's
        // sanity check this.
        debug_assert!(
            leaf_entries.iter().all(|(_, v)| !v.is_empty()),
            "Leaf entries should not contain entries with empty values"
        );

        // We sort the entries to ensure a consistent ordering, as the map above is a HashMap
        // which does not guarantee iteration order.
        let mut entries = leaf_entries.into_iter().collect::<Vec<_>>();
        entries.sort_by_key(|(key, value)| (*key, *value));
        Ok(SmtLeaf::new(entries, full_tree_leaf.index())?)
    }

    /// Applies any historical changes contained in `history_view` on top of the merkle path
    /// obtained from the full tree to produce the correct path for a historical opening.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::Merkle`] if the merkle path cannot be created properly.
    fn merge_paths(
        backend: &B,
        lineage: LineageId,
        leaf_index: LeafIndex<SMT_DEPTH>,
        full_tree_path: &SparseMerklePath,
        history_view: HistoryView,
        sibling_leaf_changes: &[(Word, Word)],
    ) -> Result<SparseMerklePath> {
        let mut path_elems = [EMPTY_WORD; SMT_DEPTH as usize];
        let mut current_node_ix = NodeIndex::from(leaf_index);
        for depth in (1..=SMT_DEPTH).rev() {
            // This is the sibling node of the currently-tracked node. In other words, it is the
            // node that needs to become part of the path.
            let path_node_ix = current_node_ix.sibling();

            if let Some(historical_value) = history_view.node_value(&path_node_ix) {
                // If there is a historical value we need to use it, and so we write it to the
                // correct slot in the path elements array.
                path_elems[depth as usize - 1] = *historical_value;
            } else if path_node_ix.depth() == SMT_DEPTH {
                // The caller has already collected the sibling leaf's changed keys, so we can
                // check for changes without scanning the full delta again.
                if !sibling_leaf_changes.is_empty() {
                    let sibling_leaf_index = LeafIndex::new_max_depth(path_node_ix.position());
                    let sibling_leaf = backend.get_leaf(lineage, sibling_leaf_index)?;
                    let sibling_leaf =
                        Self::merge_leaves(&sibling_leaf, history_view, sibling_leaf_changes)?;
                    path_elems[depth as usize - 1] = sibling_leaf.hash();
                } else {
                    let bounded_depth = NonZeroU8::new(depth).expect("depth ∈ 1 ..= SMT_DEPTH]");
                    path_elems[depth as usize - 1] = full_tree_path.at_depth(bounded_depth)?;
                }
            } else {
                // If there isn't a historical value, we should delegate to the corresponding
                // element in the path from the full-tree opening.
                let bounded_depth = NonZeroU8::new(depth).expect("depth ∈ 1 ..= SMT_DEPTH]");
                path_elems[depth as usize - 1] = full_tree_path.at_depth(bounded_depth)?
            }

            // We then need to move upward in the tree of the nodes we know.
            current_node_ix = current_node_ix.parent();
        }

        // Now that we have filled in our `path_elems` we can use the construction of a sparse
        // merkle path from a sized iterator, and thus not compute the mask ourselves. We
        // reverse the iterator to make it go from deepest to shallowest as required.
        Ok(SparseMerklePath::from_sized_iter(path_elems.into_iter().rev())?)
    }
}

impl<B: Backend> LargeSmtForest<B> {
    /// Returns a read-only `LargeSmtForest` backed by a reader view of this forest's backend.
    ///
    /// The new forest shares the same config, lineage data, and history as `self`, and its backend
    /// is a point-in-time snapshot produced by [`Backend::reader`]. The returned forest's backend
    /// type is `B::Reader: BackendReader`, so it cannot be used for mutations.
    pub fn reader(&self) -> Result<LargeSmtForest<B::Reader>> {
        Ok(LargeSmtForest {
            config: self.config.clone(),
            backend: self.backend.reader()?,
            lineage_data: self.lineage_data.clone(),
            non_empty_histories: self.non_empty_histories.clone(),
        })
    }
}

// TESTING FUNCTIONALITY
// ================================================================================================

/// This block contains functions that are exclusively for testing, providing some extra tools to
/// inspect the internal state of the forest that are unsafe to make part of the forest's public
/// API.
#[cfg(test)]
impl<B: BackendReader> LargeSmtForest<B> {
    /// Gets an immutable reference to the underlying backend of the forest.
    pub fn get_backend(&self) -> &B {
        &self.backend
    }

    /// Gets a mutable reference to the underlying backend of the forest.
    pub fn get_backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Gets an immutable reference to the underlying configuration object for the forest.
    pub fn get_config(&self) -> &Config {
        &self.config
    }

    /// Gets the history container corresponding to the provided `lineage`.
    ///
    /// # Panics
    ///
    /// - If the `lineage` is not one that the tree knows about.
    pub fn get_history(&self, lineage: LineageId) -> &History {
        self.lineage_data
            .get(&lineage)
            .map(|d| &d.history)
            .unwrap_or_else(|| panic!("Lineage {lineage} had no data"))
    }

    /// Gets an immutable reference to the set tracking the lineages that have non-empty histories.
    pub fn get_non_empty_histories(&self) -> &Set<LineageId> {
        &self.non_empty_histories
    }
}
