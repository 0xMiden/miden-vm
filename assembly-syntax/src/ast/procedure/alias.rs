use alloc::string::String;
use core::fmt;

use miden_debug_types::{SourceSpan, Span, Spanned};

use super::{ProcedureName, QualifiedProcedureName};
use crate::{
    Word,
    ast::{DocString, InvocationTarget},
};

// PROCEDURE ALIAS
// ================================================================================================

/// Represents a procedure that acts like it is locally-defined, but delegates to an externally-
/// defined procedure.
///
/// These procedure "aliases" do not have a concrete representation in the module, but are instead
/// resolved during compilation to refer directly to the aliased procedure, regardless of whether
/// the caller is in the current module, or in another module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedureAlias {
    /// The documentation attached to this procedure
    docs: Option<DocString>,
    /// The name of this procedure
    name: ProcedureName,
    /// The underlying procedure being aliased.
    ///
    /// Alias targets are context-sensitive, depending on how they were defined and what stage of
    /// compilation we're in. See [AliasTarget] for semantics of each target type, but they closely
    /// correspond to [InvocationTarget].
    target: AliasTarget,
}

impl ProcedureAlias {
    /// Creates a new procedure alias called `name`, which resolves to `target`.
    pub fn new(name: ProcedureName, target: AliasTarget) -> Self {
        Self { docs: None, name, target }
    }

    /// Adds documentation to this procedure alias.
    pub fn with_docs(mut self, docs: Option<Span<String>>) -> Self {
        self.docs = docs.map(DocString::new);
        self
    }

    /// Returns the documentation associated with this declaration.
    pub fn docs(&self) -> Option<Span<&str>> {
        self.docs.as_ref().map(|docstring| docstring.as_spanned_str())
    }

    /// Returns the name of this alias within its containing module.
    ///
    /// If the procedure is simply re-exported with the same name, this will be equivalent to
    /// `self.target().name`
    #[inline]
    pub fn name(&self) -> &ProcedureName {
        &self.name
    }

    /// Returns the target of this procedure alias
    #[inline]
    pub fn target(&self) -> &AliasTarget {
        &self.target
    }

    /// Returns a mutable reference to the target of this procedure alias
    #[inline]
    pub fn target_mut(&mut self) -> &mut AliasTarget {
        &mut self.target
    }

    /// Returns true if this procedure uses an absolute target path
    #[inline]
    pub fn is_absolute(&self) -> bool {
        matches!(self.target, AliasTarget::MastRoot(_) | AliasTarget::AbsoluteProcedurePath(_))
    }

    /// Returns true if this alias uses a different name than the target procedure
    #[inline]
    pub fn is_renamed(&self) -> bool {
        match self.target() {
            AliasTarget::MastRoot(_) => true,
            AliasTarget::ProcedurePath(fqn) | AliasTarget::AbsoluteProcedurePath(fqn) => {
                fqn.name != self.name
            },
        }
    }
}

impl Spanned for ProcedureAlias {
    fn span(&self) -> SourceSpan {
        self.target.span()
    }
}

impl crate::prettier::PrettyPrint for ProcedureAlias {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let mut doc = self
            .docs
            .as_ref()
            .map(|docstring| docstring.render())
            .unwrap_or(Document::Empty);

        doc += const_text("pub proc ");
        doc += match &self.target {
            target @ AliasTarget::MastRoot(_) => display(format_args!("{}->{}", target, self.name)),
            target => {
                let prefix = if self.is_absolute() { "::" } else { "" };
                if self.is_renamed() {
                    display(format_args!("{}{}->{}", prefix, target, &self.name))
                } else {
                    display(format_args!("{prefix}{target}"))
                }
            },
        };
        doc
    }
}

/// A fully-qualified external procedure that is the target of a procedure alias
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasTarget {
    /// An alias of the procedure whose root is the given digest
    ///
    /// Corresponds to [`InvocationTarget::MastRoot`]
    MastRoot(Span<Word>),
    /// An alias of `name`, imported from `module`
    ///
    /// Corresponds to [`InvocationTarget::ProcedurePath`]
    ProcedurePath(QualifiedProcedureName),
    /// An alias of a procedure with the given absolute, fully-qualified path
    ///
    /// Corresponds to [InvocationTarget::AbsoluteProcedurePath]
    AbsoluteProcedurePath(QualifiedProcedureName),
}

impl Spanned for AliasTarget {
    fn span(&self) -> SourceSpan {
        match self {
            Self::MastRoot(spanned) => spanned.span(),
            Self::ProcedurePath(spanned) | Self::AbsoluteProcedurePath(spanned) => spanned.span(),
        }
    }
}

impl From<Span<Word>> for AliasTarget {
    fn from(digest: Span<Word>) -> Self {
        Self::MastRoot(digest)
    }
}

impl TryFrom<InvocationTarget> for AliasTarget {
    type Error = InvocationTarget;

    fn try_from(target: InvocationTarget) -> Result<Self, Self::Error> {
        let span = target.span();
        match target {
            InvocationTarget::MastRoot(digest) => Ok(Self::MastRoot(digest)),
            InvocationTarget::ProcedurePath { name, module } => {
                let ns = crate::LibraryNamespace::from_ident_unchecked(module);
                let module = crate::LibraryPath::new_from_components(ns, []);
                Ok(Self::ProcedurePath(QualifiedProcedureName { span, module, name }))
            },
            InvocationTarget::AbsoluteProcedurePath { name, path: module } => {
                Ok(Self::AbsoluteProcedurePath(QualifiedProcedureName { span, module, name }))
            },
            target @ InvocationTarget::ProcedureName(_) => Err(target),
        }
    }
}

impl From<&AliasTarget> for InvocationTarget {
    fn from(target: &AliasTarget) -> Self {
        match target {
            AliasTarget::MastRoot(digest) => Self::MastRoot(*digest),
            AliasTarget::ProcedurePath(fqn) => {
                let name = fqn.name.clone();
                let module = fqn.module.last_component().to_ident();
                Self::ProcedurePath { name, module }
            },
            AliasTarget::AbsoluteProcedurePath(fqn) => Self::AbsoluteProcedurePath {
                name: fqn.name.clone(),
                path: fqn.module.clone(),
            },
        }
    }
}
impl From<AliasTarget> for InvocationTarget {
    fn from(target: AliasTarget) -> Self {
        match target {
            AliasTarget::MastRoot(digest) => Self::MastRoot(digest),
            AliasTarget::ProcedurePath(fqn) => {
                let name = fqn.name;
                let module = fqn.module.last_component().to_ident();
                Self::ProcedurePath { name, module }
            },
            AliasTarget::AbsoluteProcedurePath(fqn) => {
                Self::AbsoluteProcedurePath { name: fqn.name, path: fqn.module }
            },
        }
    }
}

impl crate::prettier::PrettyPrint for AliasTarget {
    fn render(&self) -> crate::prettier::Document {
        use miden_core::utils::DisplayHex;

        use crate::prettier::*;

        match self {
            Self::MastRoot(digest) => display(DisplayHex(digest.as_bytes().as_slice())),
            Self::ProcedurePath(fqn) => display(fqn),
            Self::AbsoluteProcedurePath(fqn) => display(format_args!("::{fqn}")),
        }
    }
}

impl fmt::Display for AliasTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use crate::prettier::PrettyPrint;

        self.pretty_print(f)
    }
}
