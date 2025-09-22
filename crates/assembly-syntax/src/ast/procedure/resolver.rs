use alloc::{collections::BTreeMap, vec::Vec};

use miden_debug_types::{SourceSpan, Span, Spanned};

use super::{ProcedureIndex, ProcedureName, QualifiedProcedureName};
use crate::{LibraryPath, Word, ast::Ident};

// RESOLVED PROCEDURE
// ================================================================================================

/// Represents the result of resolving a [ProcedureName] in the context of a module.
#[derive(Debug, Clone)]
pub enum ResolvedProcedure {
    /// The name was resolved to a procedure definition in the same module at the given index
    Local(Span<ProcedureIndex>),
    /// The name was resolved to a procedure exported from another module
    External(QualifiedProcedureName),
    /// The name was resolved to a procedure with a known MAST root
    MastRoot(Word),
}

impl Spanned for ResolvedProcedure {
    fn span(&self) -> SourceSpan {
        match self {
            ResolvedProcedure::Local(p) => p.span(),
            ResolvedProcedure::External(p) => p.span(),
            ResolvedProcedure::MastRoot(_) => SourceSpan::default(),
        }
    }
}

// LOCAL NAME RESOLVER
// ================================================================================================

/// A lookup table for procedure names in the context of some module
pub struct LocalNameResolver {
    imports: BTreeMap<Ident, Span<LibraryPath>>,
    resolved: BTreeMap<ProcedureName, ProcedureIndex>,
    resolutions: Vec<ResolvedProcedure>,
}

impl LocalNameResolver {
    /// Try to resolve `name` as a procedure
    pub fn resolve(&self, name: &ProcedureName) -> Option<ResolvedProcedure> {
        self.resolved
            .get(name)
            .copied()
            .map(|index| self.resolutions[index.as_usize()].clone())
    }

    /// Try to resolve `name` to an imported module, returning the [LibraryPath] of that module.
    pub fn resolve_import(&self, name: &Ident) -> Option<Span<&LibraryPath>> {
        self.imports.get(name).map(|spanned| spanned.as_ref())
    }

    /// Get the name of the procedure at `index`
    ///
    /// This is guaranteed to resolve if `index` is valid, and will panic if not.
    pub fn get_name(&self, index: ProcedureIndex) -> &ProcedureName {
        self.resolved
            .iter()
            .find_map(|(k, v)| if v == &index { Some(k) } else { None })
            .expect("invalid procedure index")
    }

    /// Extend the set of imports this resolver knows about.
    pub fn with_imports<I>(mut self, imports: I) -> Self
    where
        I: IntoIterator<Item = (Ident, Span<LibraryPath>)>,
    {
        self.imports.extend(imports);
        self
    }
}

impl FromIterator<(ProcedureName, ResolvedProcedure)> for LocalNameResolver {
    /// Construct a [LocalNameResolver] from an iterator of resolved names.
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = (ProcedureName, ResolvedProcedure)>,
    {
        let mut resolver = Self {
            imports: Default::default(),
            resolved: Default::default(),
            resolutions: Default::default(),
        };
        for (name, resolution) in iter {
            let index = ProcedureIndex::new(resolver.resolutions.len());
            resolver.resolutions.push(resolution);
            resolver.resolved.insert(name, index);
        }
        resolver
    }
}
