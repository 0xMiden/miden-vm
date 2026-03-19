use crate::{ast::parsing::SetSourceId, *};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct LibTarget {
    /// The kind of library target this is.
    ///
    /// Defaults to `library`
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub kind: Option<Span<TargetType>>,
    /// The optional namespace override for modules parsed from this target
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub namespace: Option<Span<Arc<str>>>,
    /// The relative path from the project manifest to the root source file for this target
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub path: Option<Span<Uri>>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct BinTarget {
    /// An optional name for this target.
    ///
    /// If unspecified, the name defaults to `$exec`.
    ///
    /// All binary target names must be unique in a project.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub name: Option<Span<Arc<str>>>,
    /// The relative path from the project manifest to the root source file for this target
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub path: Option<Span<Uri>>,
}

impl SetSourceId for LibTarget {
    fn set_source_id(&mut self, source_id: SourceId) {
        if let Some(kind) = self.kind.as_mut() {
            kind.set_source_id(source_id);
        }

        if let Some(ns) = self.namespace.as_mut() {
            ns.set_source_id(source_id);
        }

        if let Some(path) = self.path.as_mut() {
            path.set_source_id(source_id);
        }
    }
}

impl SetSourceId for BinTarget {
    fn set_source_id(&mut self, source_id: SourceId) {
        if let Some(ns) = self.name.as_mut() {
            ns.set_source_id(source_id);
        }

        if let Some(path) = self.path.as_mut() {
            path.set_source_id(source_id);
        }
    }
}
