use alloc::string::{String, ToString};

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

impl Target {
    /// Construct a new virtual executable target named `name`
    pub fn executable(name: impl Into<Arc<str>>) -> Self {
        Self::r#virtual(TargetType::Executable, name.into(), Path::exec_path())
    }

    /// Construct a new virtual library target named `name` with namespace `namespace`
    pub fn library(namespace: impl Into<Arc<Path>>) -> Self {
        let namespace = namespace.into();
        let name: Arc<str> = namespace.as_str().into();
        Self::r#virtual(TargetType::Library, name, namespace)
    }

    /// Construct a new virtual target of type `ty`, with the given `name` and `namespace`
    pub fn r#virtual(
        ty: TargetType,
        name: impl Into<Arc<str>>,
        namespace: impl Into<Arc<Path>>,
    ) -> Self {
        Self {
            ty,
            name: Span::unknown(name.into()),
            namespace: Span::unknown(namespace.into()),
            path: None,
        }
    }

    /// Construct this [Target] with the given root module [Uri].
    pub fn with_path(mut self, path: impl Into<Uri>) -> Self {
        self.path = Some(Span::unknown(path.into()));
        self
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
        match path.as_ref() {
            Some(path) => out.push_str(path.inner().path()),
            None => out.push_str("<virtual>"),
        }
        out.push('\n');
    }
}
