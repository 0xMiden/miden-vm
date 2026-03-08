use crate::{ast::parsing::SetSourceId, *};

/// Represents build target configuration
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct Target {
    pub kind: TargetType,
    /// An optional name for this target.
    ///
    /// If unspecified, the name is derived from `namespace`.
    ///
    /// All names must be unique in a project.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub name: Option<Span<Arc<str>>>,
    /// The optional namespace override for modules parsed from this target
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub namespace: Option<Span<Arc<str>>>,
    /// The relative path from the project manifest to the root source file for this target
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub path: Option<Span<Uri>>,
    /// The set of other targets in the same project which are required to build this one
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub requires: Vec<Span<Arc<str>>>,
}

impl Target {
    /// Get the name of this target
    pub fn name(&self) -> Option<Span<Arc<str>>> {
        self.name.clone().or_else(|| self.namespace.clone())
    }

    /// Get the relative path from the project manifest to the root source file for this target
    pub fn path(&self) -> Uri {
        self.path.as_ref().map(|p| p.inner().clone()).unwrap_or(Uri::new("mod.masm"))
    }
}

impl SetSourceId for Target {
    fn set_source_id(&mut self, source_id: SourceId) {
        if let Some(ns) = self.namespace.as_mut() {
            ns.set_source_id(source_id);
        }

        if let Some(path) = self.path.as_mut() {
            path.set_source_id(source_id);
        }
    }
}
