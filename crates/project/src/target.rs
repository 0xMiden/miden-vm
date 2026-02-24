use miden_assembly_syntax::Path;

use crate::*;

/// Represents build target configuration
#[derive(Debug, Clone)]
pub struct Target {
    pub ty: TargetType,
    /// The namespace root for this target
    pub namespace: Span<Arc<Path>>,
    /// The path from the project manifest to the root source file for this target
    pub path: Span<Uri>,
}
