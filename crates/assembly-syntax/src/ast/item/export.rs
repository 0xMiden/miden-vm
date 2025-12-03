use alloc::string::String;

use crate::{
    ast::{
        Alias, AttributeSet, Constant, FunctionType, Ident, Invoke, Procedure, TypeDecl, Visibility,
    },
    debuginfo::{SourceSpan, Span, Spanned},
};

// EXPORT
// ================================================================================================

/// Represents an exportable item from a [crate::ast::Module].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Export {
    /// A locally-defined procedure.
    Procedure(Procedure),
    /// A locally-defined constant.
    Constant(Constant),
    /// A locally-defined type.
    Type(TypeDecl),
    /// An alias for an externally-defined item, i.e. a re-exported import.
    Alias(Alias),
}

impl Export {
    /// Adds documentation to this export.
    pub fn with_docs(self, docs: Option<Span<String>>) -> Self {
        match self {
            Self::Procedure(item) => Self::Procedure(item.with_docs(docs)),
            Self::Constant(item) => Self::Constant(item.with_docs(docs)),
            Self::Type(item) => Self::Type(item.with_docs(docs)),
            Self::Alias(item) => Self::Alias(item.with_docs(docs)),
        }
    }

    /// Returns the name of the exported procedure.
    pub fn name(&self) -> &Ident {
        match self {
            Self::Procedure(item) => item.name().as_ref(),
            Self::Constant(item) => &item.name,
            Self::Type(item) => item.name(),
            Self::Alias(item) => item.name(),
        }
    }

    /// Returns the documentation for this item.
    pub fn docs(&self) -> Option<&str> {
        match self {
            Self::Procedure(item) => item.docs().map(|spanned| spanned.into_inner()),
            Self::Constant(item) => item.docs().map(|spanned| spanned.into_inner()),
            Self::Type(item) => item.docs().map(|spanned| spanned.into_inner()),
            Self::Alias(item) => item.docs().map(|spanned| spanned.into_inner()),
        }
    }

    /// Returns the attributes for this item, if it is a procedure.
    pub fn attributes(&self) -> Option<&AttributeSet> {
        match self {
            Self::Procedure(proc) => Some(proc.attributes()),
            Self::Constant(_) | Self::Type(_) | Self::Alias(_) => None,
        }
    }

    /// Returns the visibility of this item (e.g. public or private).
    ///
    /// See [Visibility] for more details on what visibilities are supported.
    pub fn visibility(&self) -> Visibility {
        match self {
            Self::Procedure(item) => item.visibility(),
            Self::Constant(item) => item.visibility,
            Self::Type(item) => item.visibility(),
            Self::Alias(_) => Visibility::Public,
        }
    }

    /// Returns a reference to the type signature of this item, if it is a procedure, and known.
    pub fn signature(&self) -> Option<&FunctionType> {
        match self {
            Self::Procedure(item) => item.signature(),
            Self::Constant(_) | Self::Type(_) | Self::Alias(_) => None,
        }
    }

    /// Returns the number of automatically-allocated words of memory this item requires
    /// for the storage of temporaries/local variables.
    ///
    /// NOTE: This is only applicable for procedure items - the value 0 will be returned if this
    /// is a non-procedure item, or if the type of item is not yet known.
    pub fn num_locals(&self) -> usize {
        match self {
            Self::Procedure(proc) => proc.num_locals() as usize,
            Self::Constant(_) | Self::Type(_) | Self::Alias(_) => 0,
        }
    }

    /// Returns true if this procedure is the program entrypoint.
    pub fn is_main(&self) -> bool {
        self.name().as_str() == Ident::MAIN
    }

    /// Unwraps this [Export] as a [Procedure], or panic.
    #[track_caller]
    pub fn unwrap_procedure(&self) -> &Procedure {
        match self {
            Self::Procedure(item) => item,
            Self::Constant(_) => panic!("attempted to unwrap constant as procedure definition"),
            Self::Type(_) => panic!("attempted to unwrap type as procedure definition"),
            Self::Alias(_) => panic!("attempted to unwrap alias as procedure definition"),
        }
    }

    /// Get an iterator over the set of other procedures invoked from this procedure.
    ///
    /// NOTE: This only applies to [Procedure]s, other types currently return an empty
    /// iterator whenever called.
    pub fn invoked<'a, 'b: 'a>(&'b self) -> impl Iterator<Item = &'a Invoke> + 'a {
        use crate::ast::procedure::InvokedIter;

        match self {
            Self::Procedure(item) if item.invoked.is_empty() => InvokedIter::Empty,
            Self::Procedure(item) => InvokedIter::NonEmpty(item.invoked.iter()),
            Self::Constant(_) | Self::Type(_) | Self::Alias(_) => InvokedIter::Empty,
        }
    }
}

impl crate::prettier::PrettyPrint for Export {
    fn render(&self) -> crate::prettier::Document {
        match self {
            Self::Procedure(item) => item.render(),
            Self::Constant(item) => item.render(),
            Self::Type(item) => item.render(),
            Self::Alias(item) => item.render(),
        }
    }
}

impl Spanned for Export {
    fn span(&self) -> SourceSpan {
        match self {
            Self::Procedure(spanned) => spanned.span(),
            Self::Constant(spanned) => spanned.span(),
            Self::Type(spanned) => spanned.span(),
            Self::Alias(spanned) => spanned.span(),
        }
    }
}
