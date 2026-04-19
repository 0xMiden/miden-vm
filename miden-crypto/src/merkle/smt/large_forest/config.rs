//! This module contains the configuration structure for the forest.

// CONSTANTS
// ================================================================================================

/// The default number of historical versions of each tree to keep.
pub const DEFAULT_MAX_HISTORY_VERSIONS: usize = 10;

/// The minimum number of historical versions per lineage that the forest can store.
pub const MIN_HISTORY_VERSIONS: usize = 1;

// CONFIG
// ================================================================================================

/// The configuration for the forest's behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// The maximum number of historical versions that the forest will keep for any given lineage.
    max_historical_versions: usize,
}

/// This block contains the accessors for the configuration options.
impl Config {
    /// The maximum number of historical versions that the forest will keep for any given lineage.
    ///
    /// If this field is set to `n`, the forest will implicitly store `n + 1` versions of a given
    /// lineage once the latest version in that lineage is accounted for.
    ///
    /// Defaults to [`DEFAULT_MAX_HISTORY_VERSIONS`].
    pub fn max_history_versions(&self) -> usize {
        self.max_historical_versions
    }
}

// BUILDERS
// ================================================================================================

/// This impl block contains the builder functions for the configuration options.
impl Config {
    /// Sets the maximum number of historical versions that the forest will store for any given
    /// lineage, clamping to [`MIN_HISTORY_VERSIONS`] on the low end.
    ///
    /// If this field is set to `n`, the forest will implicitly store `n + 1` versions of a given
    /// lineage once the latest version in that lineage is accounted for.
    ///
    /// This defaults to [`DEFAULT_MAX_HISTORY_VERSIONS`].
    pub fn with_max_history_versions(mut self, max_historical_versions: usize) -> Self {
        self.max_historical_versions = if max_historical_versions < MIN_HISTORY_VERSIONS {
            MIN_HISTORY_VERSIONS
        } else {
            max_historical_versions
        };
        self
    }
}

// TRAIT IMPLS
// ================================================================================================

/// Please see individual methods on [`Config`] for the default value of each configuration option.
impl Default for Config {
    fn default() -> Self {
        let max_historical_versions = DEFAULT_MAX_HISTORY_VERSIONS;
        Self { max_historical_versions }
    }
}
