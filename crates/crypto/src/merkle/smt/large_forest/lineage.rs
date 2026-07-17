//! This module contains the data types used by the forest to store and manage the lineages that it
//! knows about.

use core::iter::once;

use crate::merkle::smt::{
    VersionId,
    large_forest::{history::History, root::RootValue},
};

// LINEAGE DATA
// ================================================================================================

/// The data that the forest stores in memory for each lineage of trees.
#[derive(Clone, Debug)]
pub(super) struct LineageData {
    /// The history of changes made to the lineage, representing a contiguous set of historical
    /// trees in the lineage up to the configured maximum number of versions.
    pub history: History,

    /// The version of the latest tree in the lineage.
    pub latest_version: VersionId,

    /// The value of the root for the latest tree in the lineage.
    pub latest_root: RootValue,
}

impl LineageData {
    /// Gets an iterator that yields all roots in the lineage.
    ///
    /// The iteration order of the roots is guaranteed to move backward in time, with earlier items
    /// in the iterator being roots from versions closer to the present. The current root of the
    /// lineage will always be the first item that the iterator yields.
    pub(super) fn roots(&self) -> impl Iterator<Item = RootValue> {
        once(self.latest_root).chain(self.history.roots())
    }

    /// Truncates the information on this tree to the provided `version`, returning `true` if the
    /// history is empty after truncation, and `false` otherwise.
    ///
    /// If the latest version in the lineage is older than the specified `version`, this latest
    /// version is always retained. In other words, the method cannot prune a lineage from the
    /// forest entirely.
    pub(super) fn truncate(&mut self, version: VersionId) -> bool {
        if version >= self.latest_version {
            // Truncation in the history is defined such that it never removes a version that could
            // possibly serve as the latest delta for a newer version. This is because it cannot
            // safely know if a version `v` is between the latest delta `d` and the current version
            // `c`, as it has no knowledge of the current version.
            //
            // Thus, if we have a version `v` such that `d <= v < c`, we need to retain the
            // reversion delta `d` in the history to correctly service queries for `v`. If, however,
            // we have `d < c <= v` we need to explicitly remove the last delta as well.
            //
            // To that end, we handle the latter case first, by explicitly calling
            // `History::clear()`.
            self.history.clear();
            true
        } else {
            // The other case is `v < c`, which is handled simply by the truncation mechanism in the
            // history as we want. In other words, it retains the necessary delta, and so we can
            // just call it here.
            self.history.truncate(version);
            false
        }
    }
}
