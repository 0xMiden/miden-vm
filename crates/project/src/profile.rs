use core::borrow::Borrow;

use miden_assembly_syntax::debuginfo::Spanned;

use crate::*;

/// Represents configuration options for a specific build profile, e.g. `release`
#[derive(Debug, Clone)]
pub struct Profile {
    /// The name of this profile, e.g. `release`
    name: Span<Arc<str>>,
    /// Whether to emit debugging information for this profile
    debug: bool,
    /// Whether or not to trim file paths in debug information, making them relative to the current
    /// working directory.
    trim_paths: bool,
    /// Custom metadata associated with this profile
    ///
    /// This is intended for third-party/downstream tooling which need to support per-profile config.
    metadata: Metadata,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            name: Span::unknown("dev".to_string().into_boxed_str().into()),
            debug: true,
            trim_paths: false,
            metadata: Default::default(),
        }
    }
}

/// Constructors
impl Profile {
    /// Create a new profile called `name`, with all configuration options set to their defaults.
    pub fn new(name: Span<Arc<str>>) -> Self {
        Self { name, ..Default::default() }
    }

    /// Create a profile called `name`, with all configuration options inherited from `parent`
    ///
    /// NOTE: Any changes made to `parent` after this new profile is created are _not_ automatically
    /// inherited - the "inheritance" here is simply used to initialize the options this profile
    /// starts with.
    pub fn inherit(name: Span<Arc<str>>, parent: &Self) -> Self {
        Self { name, ..parent.clone() }
    }

    /// Get the default `release` profile
    pub fn release() -> Self {
        Self {
            name: Span::unknown("release".to_string().into_boxed_str().into()),
            debug: false,
            trim_paths: true,
            metadata: Default::default(),
        }
    }

    /// Merge configuration from `other` into `self`.
    ///
    /// This has the effect of overriding any options in `self` which have different values in
    /// `other`.
    pub fn merge(&mut self, other: &Self) {
        let Self { name: _, debug, trim_paths, metadata } = self;

        *debug = other.debug;
        *trim_paths = other.trim_paths;
        for (k, v) in metadata.iter_mut() {
            if let Some(v2) = other.metadata.get(k) {
                match &mut **v {
                    Value::Table(table) => {
                        if let Value::Table(table2) = v2.inner() {
                            table.extend(table2.iter().map(|(k, v)| (k.clone(), v.clone())));
                        } else {
                            *v = v2.clone();
                        }
                    },
                    _ => {
                        *v = v2.clone();
                    },
                }
            }
        }
    }
}

/// Mutations
impl Profile {
    /// Enable emission of debug information under this profile
    pub fn enable_debug_info(&mut self, yes: bool) -> &mut Self {
        self.debug = yes;
        self
    }

    /// Enable trimmming of file paths in debug info under this profile
    pub fn enable_trim_paths(&mut self, yes: bool) -> &mut Self {
        self.trim_paths = yes;
        self
    }
}

/// Accessors
impl Profile {
    /// Get the name of this profile
    pub fn name(&self) -> &Arc<str> {
        &self.name
    }

    /// Returns true if this profile is configured so that we should emit debug information.
    pub const fn should_emit_debug_info(&self) -> bool {
        self.debug
    }

    /// Returns true if this profile is configured so that we should trim file paths in debug
    /// information to be relative to the current working directory.
    pub const fn should_trim_paths(&self) -> bool {
        self.debug
    }

    /// Returns true if `key` is defined in the custom metadata associated with this profile.
    #[inline]
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        Q: ?Sized + Ord,
        Span<Arc<str>>: Borrow<Q> + Ord,
    {
        self.metadata.contains_key(key)
    }

    /// Returns the value associated with `key` in the custom metadata associated with this profile.
    ///
    /// Returns `None` if no value is found for `key`.
    #[inline]
    pub fn get<Q>(&self, key: &Q) -> Option<&Span<Value>>
    where
        Q: ?Sized + Ord,
        Span<Arc<str>>: Borrow<Q> + Ord,
    {
        self.metadata.get(key)
    }
}

impl Extend<(Span<Arc<str>>, Span<Value>)> for Profile {
    fn extend<T: IntoIterator<Item = (Span<Arc<str>>, Span<Value>)>>(&mut self, iter: T) {
        self.metadata.extend(iter);
    }
}

impl Spanned for Profile {
    fn span(&self) -> SourceSpan {
        self.name.span()
    }
}
