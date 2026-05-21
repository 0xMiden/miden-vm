use alloc::string::{String, ToString};

use miden_assembly_syntax::Path;

use crate::*;

/// Represents build target configuration
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// The path can be to a source file written in any language, e.g. for MASM it might refer to
    /// `mod.masm`, while for Rust it might refer to `src/lib.rs` - as long as an appropriate
    /// source provider is registered with the assembler.
    pub path: Span<Uri>,
}

impl Target {
    /// Construct a new executable target named `name` and given source `uri`
    pub fn executable(name: impl Into<Arc<str>>, uri: Uri) -> Self {
        Self::new(TargetType::Executable, name.into(), Path::exec_path(), uri)
    }

    /// Construct a new library target named `name` with the given `namespace` and source `uri`
    pub fn library(namespace: impl Into<Arc<Path>>, uri: Uri) -> Self {
        let namespace = namespace.into();
        let name: Arc<str> = namespace.as_str().into();
        Self::new(TargetType::Library, name, namespace, uri)
    }

    /// Construct a new target of type `ty`, with the given `name`, `namespace` and source `uri`
    pub fn new(
        ty: TargetType,
        name: impl Into<Arc<str>>,
        namespace: impl Into<Arc<Path>>,
        uri: Uri,
    ) -> Self {
        Self {
            ty,
            name: Span::unknown(name.into()),
            namespace: Span::unknown(namespace.into()),
            path: Span::unknown(uri),
        }
    }

    /// Returns true if this target is an executable target
    pub const fn is_executable(&self) -> bool {
        matches!(self.ty, TargetType::Executable)
    }

    /// Returns true if this target is a non-executable target
    pub const fn is_library(&self) -> bool {
        !self.is_executable()
    }

    /// Returns true if this target is a kernel target
    pub const fn is_kernel(&self) -> bool {
        matches!(self.ty, TargetType::Kernel)
    }

    /// Append the selected target fields that affect package artifact reuse to `out`.
    pub fn append_build_provenance_projection(&self, out: &mut String) {
        let Self { ty, name, namespace, path } = self;

        out.push_str("target:kind:");
        out.push_str(ty.to_string().as_str());
        out.push('\n');
        out.push_str("target:name:");
        out.push_str(name.inner().as_ref());
        out.push('\n');
        out.push_str("target:namespace:");
        out.push_str(namespace.inner().as_str());
        out.push('\n');
        out.push_str("target:path:");
        out.push_str(path.inner().as_str());
        out.push('\n');
    }
}
