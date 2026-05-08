//! Unified symbol resolution for Miden assembly.

use std::sync::Arc;

use miden_assembly_syntax::{
    Path,
    ast::{InvocationTarget, LocalSymbolResolver, Module, SymbolResolution, SymbolResolutionError},
    debuginfo::{SourceManager, Span, Spanned},
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
        }
    }
}

impl std::error::Error for ResolutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ResolutionError::SymbolResolution { source, .. } => Some(source),
            ResolutionError::ModuleNotLoaded { .. } | ResolutionError::NonPathResolution { .. } => {
                None
            },
        }
    }
}

// -----------------------------------------------------------------------------
// Module-level resolution
// -----------------------------------------------------------------------------

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
    pub(crate) fn resolve_target(
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
}

// -----------------------------------------------------------------------------
// Workspace-level resolution
// -----------------------------------------------------------------------------

/// Workspace-level symbol resolution trait.
///
/// Implementations should use the provided module path to resolve symbols using
/// the module's import context.
pub(crate) trait WorkspaceSymbolResolver {
    fn resolve_target(
        &self,
        module: &SymbolPath,
        target: &InvocationTarget,
    ) -> ResolutionResult<Option<SymbolPath>>;
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
}

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------

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
