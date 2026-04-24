//! Unified symbol resolution for Miden assembly.

use std::sync::Arc;

use miden_assembly_syntax::{
    Path,
    ast::{InvocationTarget, LocalSymbolResolver, Module, SymbolResolution, SymbolResolutionError},
    debuginfo::{SourceManager, SourceSpan, Span, Spanned},
};

use crate::{frontend::Workspace, symbol::path::SymbolPath};

/// Result type alias for symbol resolution operations.
///
/// The error is boxed to keep `Result` sizes small, since `ResolutionError`
/// variants can be large (176+ bytes).
pub type ResolutionResult<T> = Result<T, Box<ResolutionError>>;

/// Error returned when symbol resolution fails.
#[derive(Debug, Clone)]
pub enum ResolutionError {
    /// The module context required for resolution is missing in the workspace.
    ModuleNotLoaded { module: SymbolPath },
    /// The symbol/path could not be resolved in the given module context.
    SymbolResolution {
        module: SymbolPath,
        reference: String,
        source: SymbolResolutionError,
    },
    /// The symbol resolved to a non-path target (e.g. MAST root digest).
    NonPathResolution { module: SymbolPath, reference: String },
    /// The reference resolved, but does not refer to a constant definition.
    NonConstantSymbol {
        module: SymbolPath,
        reference: String,
        resolved: SymbolPath,
    },
}

impl std::fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolutionError::ModuleNotLoaded { module } => {
                write!(f, "module `{module}` is not loaded in the workspace")
            },
            ResolutionError::SymbolResolution { module, reference, .. } => {
                write!(f, "failed to resolve `{reference}` in module `{module}`")
            },
            ResolutionError::NonPathResolution { module, reference } => {
                write!(f, "symbol `{reference}` in module `{module}` resolved to a non-path target")
            },
            ResolutionError::NonConstantSymbol { module, reference, resolved } => write!(
                f,
                "reference `{reference}` in module `{module}` resolved to `{resolved}`, which is not a constant"
            ),
        }
    }
}

impl std::error::Error for ResolutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ResolutionError::SymbolResolution { source, .. } => Some(source),
            ResolutionError::ModuleNotLoaded { .. }
            | ResolutionError::NonPathResolution { .. }
            | ResolutionError::NonConstantSymbol { .. } => None,
        }
    }
}

// -----------------------------------------------------------------------------
// Module-level resolution
// -----------------------------------------------------------------------------

/// Resolve an invocation target to its fully-qualified symbol path.
///
/// This is the single source of truth for symbol resolution across the codebase.
pub fn resolve_target(
    module: &Module,
    source_manager: Arc<dyn SourceManager>,
    target: &InvocationTarget,
) -> ResolutionResult<Option<SymbolPath>> {
    create_resolver(module, source_manager).resolve_target(target)
}

/// Resolve a simple symbol name to its fully-qualified path.
///
/// Handles local definitions and imported procedures via `use` statements.
pub fn resolve_symbol(
    module: &Module,
    source_manager: Arc<dyn SourceManager>,
    name: &str,
) -> ResolutionResult<SymbolPath> {
    create_resolver(module, source_manager).resolve_symbol(name)
}

/// Resolve a qualified path (e.g., `base_field::square`) to its fully-qualified path.
///
/// Handles:
/// - Module aliases from `use` statements
/// - Absolute paths (starting with `::`)
/// - Relative paths within the module hierarchy
pub fn resolve_path(
    module: &Module,
    source_manager: Arc<dyn SourceManager>,
    path_str: &str,
) -> ResolutionResult<SymbolPath> {
    create_resolver(module, source_manager).resolve_path(path_str)
}

/// Create a resolver that can be reused for multiple resolutions within the same module.
///
/// This is more efficient when resolving many symbols from the same module.
pub fn create_resolver(
    module: &Module,
    source_manager: Arc<dyn SourceManager>,
) -> SymbolResolver<'_> {
    SymbolResolver {
        module,
        resolver: LocalSymbolResolver::new(module, source_manager)
            .expect("loaded MASM module should have a valid local symbol resolver"),
    }
}

/// A reusable symbol resolver for a specific module.
///
/// More efficient than calling `resolve_target` repeatedly, as it caches
/// the `LocalSymbolResolver`.
pub struct SymbolResolver<'a> {
    module: &'a Module,
    resolver: LocalSymbolResolver,
}

impl std::fmt::Debug for SymbolResolver<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymbolResolver")
            .field("module_path", &self.module.path())
            .finish_non_exhaustive()
    }
}

impl<'a> SymbolResolver<'a> {
    /// Resolve an invocation target to its fully-qualified path.
    pub fn resolve_target(
        &self,
        target: &InvocationTarget,
    ) -> ResolutionResult<Option<SymbolPath>> {
        match target {
            InvocationTarget::MastRoot(_) => Ok(None),
            InvocationTarget::Symbol(ident) => resolve_symbol_span_to_option(
                self.module,
                &self.resolver,
                Span::new(ident.span(), ident.as_str()),
            ),
            InvocationTarget::Path(path) => {
                resolve_path_span_to_option(self.module, &self.resolver, path.as_deref())
            },
        }
    }

    /// Resolve a simple symbol name.
    pub fn resolve_symbol(&self, name: &str) -> ResolutionResult<SymbolPath> {
        resolve_symbol_span(self.module, &self.resolver, Span::new(SourceSpan::UNKNOWN, name))
    }

    /// Resolve a qualified path.
    pub fn resolve_path(&self, path_str: &str) -> ResolutionResult<SymbolPath> {
        let path = Path::new(path_str);
        resolve_path_span(self.module, &self.resolver, Span::new(SourceSpan::UNKNOWN, path))
    }

    /// Get the underlying module.
    pub fn module(&self) -> &'a Module {
        self.module
    }
}

// -----------------------------------------------------------------------------
// Workspace-level resolution
// -----------------------------------------------------------------------------

/// Workspace-level symbol resolution trait.
///
/// Implementations should use the provided module path to resolve symbols using
/// the module's import context.
pub trait WorkspaceSymbolResolver {
    fn resolve_target(
        &self,
        module: &SymbolPath,
        target: &InvocationTarget,
    ) -> ResolutionResult<Option<SymbolPath>>;
    fn resolve_symbol(&self, module: &SymbolPath, name: &str) -> ResolutionResult<SymbolPath>;
    fn resolve_path(&self, module: &SymbolPath, path: &str) -> ResolutionResult<SymbolPath>;
}

impl WorkspaceSymbolResolver for Workspace {
    fn resolve_target(
        &self,
        module: &SymbolPath,
        target: &InvocationTarget,
    ) -> ResolutionResult<Option<SymbolPath>> {
        let program = self
            .lookup_module(module)
            .ok_or_else(|| Box::new(ResolutionError::ModuleNotLoaded { module: module.clone() }))?;
        let resolver = create_resolver(program.module(), self.source_manager());
        resolver.resolve_target(target)
    }

    fn resolve_symbol(&self, module: &SymbolPath, name: &str) -> ResolutionResult<SymbolPath> {
        let program = self
            .lookup_module(module)
            .ok_or_else(|| Box::new(ResolutionError::ModuleNotLoaded { module: module.clone() }))?;
        let resolver = create_resolver(program.module(), self.source_manager());
        resolver.resolve_symbol(name)
    }

    fn resolve_path(&self, module: &SymbolPath, path: &str) -> ResolutionResult<SymbolPath> {
        let program = self
            .lookup_module(module)
            .ok_or_else(|| Box::new(ResolutionError::ModuleNotLoaded { module: module.clone() }))?;
        let resolver = create_resolver(program.module(), self.source_manager());
        resolver.resolve_path(path)
    }
}

/// Resolve a symbol and require that it refers to a constant definition.
pub fn resolve_constant_symbol(
    workspace: &Workspace,
    module: &SymbolPath,
    name: &str,
) -> ResolutionResult<SymbolPath> {
    let resolved = workspace.resolve_symbol(module, name)?;
    ensure_constant_target(workspace, module, name.to_string(), resolved)
}

/// Resolve a qualified path and require that it refers to a constant definition.
pub fn resolve_constant_path(
    workspace: &Workspace,
    module: &SymbolPath,
    path: &str,
) -> ResolutionResult<SymbolPath> {
    let resolved = workspace.resolve_path(module, path)?;
    ensure_constant_target(workspace, module, path.to_string(), resolved)
}

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------

fn resolve_symbol_span(
    module: &Module,
    resolver: &LocalSymbolResolver,
    name: Span<&str>,
) -> ResolutionResult<SymbolPath> {
    let resolution = resolver.resolve(name).map_err(|source| {
        Box::new(ResolutionError::SymbolResolution {
            module: SymbolPath::new(module.path().to_string()),
            reference: (*name.inner()).to_string(),
            source,
        })
    })?;
    resolution_to_path(module, resolution).ok_or_else(|| {
        Box::new(ResolutionError::NonPathResolution {
            module: SymbolPath::new(module.path().to_string()),
            reference: (*name.inner()).to_string(),
        })
    })
}

fn resolve_symbol_span_to_option(
    module: &Module,
    resolver: &LocalSymbolResolver,
    name: Span<&str>,
) -> ResolutionResult<Option<SymbolPath>> {
    let resolution = resolver.resolve(name).map_err(|source| {
        Box::new(ResolutionError::SymbolResolution {
            module: SymbolPath::new(module.path().to_string()),
            reference: (*name.inner()).to_string(),
            source,
        })
    })?;
    Ok(resolution_to_path(module, resolution))
}

fn resolve_path_span(
    module: &Module,
    resolver: &LocalSymbolResolver,
    path: Span<&Path>,
) -> ResolutionResult<SymbolPath> {
    if path.inner().is_absolute() {
        return Ok(SymbolPath::new(path.as_str()));
    }

    let resolution = match resolver.resolve_path(path) {
        Ok(resolution) => resolution,
        Err(source) if is_unresolved_qualified_external(path, &source) => {
            return Ok(SymbolPath::new(path.as_str()));
        },
        Err(source) => {
            return Err(Box::new(ResolutionError::SymbolResolution {
                module: SymbolPath::new(module.path().to_string()),
                reference: path.as_str().to_string(),
                source,
            }));
        },
    };
    resolution_to_path(module, resolution).ok_or_else(|| {
        Box::new(ResolutionError::NonPathResolution {
            module: SymbolPath::new(module.path().to_string()),
            reference: path.as_str().to_string(),
        })
    })
}

fn resolve_path_span_to_option(
    module: &Module,
    resolver: &LocalSymbolResolver,
    path: Span<&Path>,
) -> ResolutionResult<Option<SymbolPath>> {
    if path.inner().is_absolute() {
        return Ok(Some(SymbolPath::new(path.as_str())));
    }

    let resolution = match resolver.resolve_path(path) {
        Ok(resolution) => resolution,
        Err(source) if is_unresolved_qualified_external(path, &source) => {
            return Ok(Some(SymbolPath::new(path.as_str())));
        },
        Err(source) => {
            return Err(Box::new(ResolutionError::SymbolResolution {
                module: SymbolPath::new(module.path().to_string()),
                reference: path.as_str().to_string(),
                source,
            }));
        },
    };
    Ok(resolution_to_path(module, resolution))
}

/// Returns true when `path` is an explicit multi-segment external path (e.g. `foo::bar`) that
/// does not rely on local imports and therefore can be used as-is.
fn is_unresolved_qualified_external(path: Span<&Path>, source: &SymbolResolutionError) -> bool {
    matches!(source, SymbolResolutionError::UndefinedSymbol { .. })
        && !path.inner().is_absolute()
        && path.inner().as_ident().is_none()
}

/// Ensure that a resolved path refers to a constant definition in the current workspace.
fn ensure_constant_target(
    workspace: &Workspace,
    module: &SymbolPath,
    reference: String,
    resolved: SymbolPath,
) -> ResolutionResult<SymbolPath> {
    if workspace.lookup_constant_entry(&resolved).is_some() {
        return Ok(resolved);
    }

    if let Some(module_path) = resolved.module_path() {
        let module_path = SymbolPath::new(module_path);
        if workspace.lookup_module(&module_path).is_none() {
            return Err(Box::new(ResolutionError::ModuleNotLoaded { module: module_path }));
        }
    }

    Err(Box::new(ResolutionError::NonConstantSymbol {
        module: module.clone(),
        reference,
        resolved,
    }))
}

/// Convert a `SymbolResolution` to a `SymbolPath`.
fn resolution_to_path(module: &Module, resolution: SymbolResolution) -> Option<SymbolPath> {
    match resolution {
        SymbolResolution::Local(idx) => {
            let item = module.get(idx.into_inner())?;
            Some(SymbolPath::from_module_and_name(module, item.name().as_str()))
        },
        SymbolResolution::External(path) => Some(SymbolPath::new(path.as_str())),
        SymbolResolution::Module { path, .. } => Some(SymbolPath::new(path.as_str())),
        SymbolResolution::Exact { path, .. } => Some(SymbolPath::new(path.as_str())),
        SymbolResolution::MastRoot(_) => None,
    }
}
