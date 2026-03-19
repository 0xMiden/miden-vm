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
    ///
    /// If not provided, it is expected that source modules will be provided to the assembler
    /// through other means. For example, `midenc` will compile Rust code to MASM, and then provide
    /// the MASM modules to an instantiated assembler when assembling this project.
    pub path: Option<Span<Uri>>,
}
