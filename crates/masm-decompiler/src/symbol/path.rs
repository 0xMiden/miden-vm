use std::{borrow::Borrow, fmt};

use miden_assembly_syntax::ast::Module;

/// A typed wrapper for fully-qualified symbol paths.
///
/// Symbol paths follow the format `module::submodule::name` and represent
/// the fully-qualified identifier for a procedure, constant, or module.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SymbolPath(String);

impl SymbolPath {
    /// Create a new SymbolPath from a string.
    ///
    /// Any leading `::` separators are stripped to normalize paths.
    pub fn new(path: impl Into<String>) -> Self {
        Self(normalize_path(path.into()))
    }

    /// Build a fully-qualified path for an item in a module.
    pub fn from_module_and_name(module: &Module, name: &str) -> Self {
        let mut buf = module.path().to_path_buf();
        buf.push(name);
        Self::new(buf.to_string())
    }

    /// Build a fully-qualified path for an item in a module path string.
    pub fn from_module_path_and_name(module_path: &str, name: &str) -> Self {
        if module_path.is_empty() {
            Self::new(name)
        } else {
            Self::new(format!("{module_path}::{name}"))
        }
    }

    /// Get the path as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the last segment of the path (the symbol name).
    ///
    /// For path `miden::core::crypto::sha256::hash`, returns `"hash"`.
    pub fn name(&self) -> &str {
        self.0.rsplit("::").next().unwrap_or(&self.0)
    }

    /// Get the module path (everything before the last segment).
    ///
    /// For path `miden::core::crypto::sha256::hash`, returns `Some("miden::core::crypto::sha256")`.
    pub fn module_path(&self) -> Option<&str> {
        self.0.rsplit_once("::").map(|(prefix, _)| prefix)
    }

    /// Iterate over path segments.
    ///
    /// For path `miden::core::crypto::sha256::hash`, yields `[
    ///   "miden", "core", "crypto", "sha256", "hash"
    /// ]`.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split("::").filter(|s| !s.is_empty())
    }

    /// Check if this path ends with the given suffix.
    pub fn ends_with(&self, suffix: &str) -> bool {
        self.0.ends_with(suffix)
    }

    /// Convert into the inner String.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for SymbolPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for SymbolPath {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SymbolPath {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl AsRef<str> for SymbolPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for SymbolPath {
    fn borrow(&self) -> &str {
        &self.0
    }
}

fn normalize_path(mut path: String) -> String {
    while let Some(stripped) = path.strip_prefix("::") {
        path = stripped.to_string();
    }
    path
}
