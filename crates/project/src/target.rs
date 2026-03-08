use miden_assembly_syntax::Path;

use crate::*;

/// Represents build target configuration
#[derive(Debug, Clone)]
pub struct Target {
    pub ty: TargetType,
    /// The effective name of this target
    ///
    /// If unspecified in the project file, the name is the same as `namespace`
    ///
    /// The name must be unique within a project
    pub name: Span<Arc<str>>,
    /// The namespace root for this target
    pub namespace: Span<Arc<Path>>,
    /// The path from the project manifest to the root source file for this target
    pub path: Span<Uri>,
    /// The set of other targets in the same project which are required to build this one
    pub requires: Vec<Span<Arc<str>>>,
}
