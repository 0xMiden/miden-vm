use crate::{TomlSpan, *};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct LibTarget {
    /// The kind of library target this is.
    ///
    /// Defaults to `library`
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub kind: Option<TomlSpan<Arc<str>>>,
    /// The optional namespace override for modules parsed from this target
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub namespace: Option<TomlSpan<Arc<str>>>,
    /// The relative path from the project manifest to the root source file for this target
    pub path: TomlSpan<Arc<str>>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct BinTarget {
    /// An optional name for this target.
    ///
    /// If unspecified, the effective target name defaults to the package name.
    ///
    /// All binary target names must be unique in a project.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub name: Option<TomlSpan<Arc<str>>>,
    /// The relative path from the project manifest to the root source file for this target
    pub path: TomlSpan<Arc<str>>,
}
